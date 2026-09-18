"""Weirvern control-panel TUI (Textual).

What it does: install/start/stop/restart services, watch live health, read logs,
edit thresholds, and see anomalies — without touching the shell.

Design decisions worth knowing:
  * Collection runs in a Textual *worker thread* and results are posted back as
    messages. Blocking the event loop to query ClickHouse would freeze the UI
    exactly when the database is slow, which is when an operator most needs it
    responsive.
  * Every panel renders its own failure ("database unreachable") rather than
    raising: a control panel must survive the thing it controls being down.
  * Destructive actions (volume removal) require typed confirmation.
"""
from __future__ import annotations

import logging
from pathlib import Path

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, VerticalScroll
from textual.message import Message
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    RichLog,
    Select,
    Static,
    TabbedContent,
    TabPane,
)

from weirvern.admin import config_io
from weirvern.admin.runtime import (
    NAMESPACE,
    WORKLOADS,
    detect_capabilities,
    find_project_dir,
    get_backend,
)
from weirvern.admin.status import collect_health, recent_anomalies, top_talkers

logger = logging.getLogger(__name__)

# Workload display order: data store first, then the two sensors, then the
# consumer. Kept as a name list derived from runtime.WORKLOADS so the TUI cannot
# drift from the workloads the backend actually knows about.
SERVICE_ORDER = [name for name, _kind in WORKLOADS]

def _host_label(addr: str) -> str:
    """Address for a table cell: `spyro.home (192.168.2.42)`.

    THE FULL SOURCE IP IS ALWAYS PRESENT. An earlier version shortened it to the
    last octet (`spyro (42)`) to save width, which was wrong: the IP is the fact,
    not the decoration. An operator correlating an anomaly with a firewall rule,
    a DHCP lease, or another log needs the whole address, and a name alone is not
    a substitute — DNS can be stale, and a PTR record can map several addresses to
    one name. The name is the convenience; the address is what you act on.

    Falls back to the bare address for every failure path, including the default
    `private` reverse-DNS mode declining to resolve a public address.
    """
    if not addr:
        return ""
    try:
        from weirvern.admin import revdns
        name = revdns.lookup(addr)
    except Exception:  # noqa: BLE001
        return addr
    if not name or name == addr:
        return addr
    return f"{name} ({addr})"


def _condense(text: str, limit: int = 90) -> str:
    """Shorten a driver/connection error for a one-line display.

    Raw urllib3 messages are hundreds of characters of URL and query_id noise
    ("Max retries exceeded with url: /?query_id=ead..."), which crowds out the
    part an operator needs: which host and why. Keep the host and the cause.
    """
    if not text:
        return ""
    # Collapse whitespace, then drop the noisy tail.
    text = " ".join(text.split())
    for noise in ("Max retries exceeded with url:", "?query_id="):
        idx = text.find(noise)
        if idx != -1:
            text = text[:idx].rstrip(" ,:") + " (unreachable)"
            break
    text = text.replace("Error HTTPConnectionPool", "HTTPConnectionPool")
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


EDITABLE_KEYS = [
    "BASE_THRESHOLD",
    "MIN_AGREEMENT",
    "DETECT_INTERVAL_S",
    "RETRAIN_EVERY_H",
    "PUSHOVER_ENABLED",
    "PUSHOVER_COOLDOWN_S",
    "PUSHOVER_MAX_PER_HOUR",
    "ZEEK_IFACE",
]


class HealthUpdated(Message):
    """Posted from the collection worker with a fresh snapshot."""

    def __init__(self, services, probes, anomalies, talkers, caps, error: str = "") -> None:
        self.services = services
        self.probes = probes
        self.anomalies = anomalies
        self.talkers = talkers
        self.caps = caps
        self.error = error
        super().__init__()


class WeirvernTUI(App):
    """The control panel."""

    CSS = """
    Screen { layout: vertical; }
    #statusbar { height: 3; padding: 0 1; background: $panel; }
    #services { height: auto; max-height: 8; }
    .panel-title { text-style: bold; padding: 0 1; }
    DataTable { height: auto; max-height: 14; }
    #logs { height: 1fr; border: round $primary; }
    #config-list { height: 1fr; }
    #action-row { height: 3; padding: 0 1; }
    Button { margin: 0 1 0 0; }
    .hint { color: $text-muted; padding: 0 1; }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("r", "refresh", "Refresh"),
        Binding("s", "start_all", "Start"),
        Binding("x", "stop_all", "Stop"),
        Binding("R", "restart_all", "Restart"),
        Binding("a", "apply", "Apply"),
        Binding("l", "load_logs", "Logs"),
    ]

    def __init__(self, project_dir: Path | str | None = None, refresh_s: int = 5) -> None:
        super().__init__()
        # Default to discovery so `WeirvernTUI()` works from anywhere, and so a
        # workstation with no cluster is usable without arguments.
        self.project_dir = find_project_dir(project_dir)
        self.refresh_s = max(2, refresh_s)
        self.caps = detect_capabilities(self.project_dir)
        self.backend = get_backend(self.project_dir, self.caps)
        self._timer: object | None = None

    # -- layout ------------------------------------------------------------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with TabbedContent(initial="tab-overview"):
            with TabPane("Overview", id="tab-overview"):
                yield Static(id="statusbar")
                yield Static("Workloads", classes="panel-title")
                yield DataTable(id="services", zebra_stripes=True)
                yield Static("Health", classes="panel-title")
                yield DataTable(id="health", zebra_stripes=True)
                with Horizontal(id="action-row"):
                    yield Button("Start all", id="btn-start", variant="success")
                    yield Button("Stop all", id="btn-stop", variant="warning")
                    yield Button("Restart", id="btn-restart", variant="primary")
                    yield Button("Apply", id="btn-apply", variant="default")
                    yield Button("Refresh", id="btn-refresh")

            with TabPane("Anomalies", id="tab-anomalies"):
                yield Static("Recent anomalies (score >= 0.5)", classes="panel-title")
                yield DataTable(id="anomalies", zebra_stripes=True)
                yield Static("Top talkers (24h)", classes="panel-title")
                yield DataTable(id="talkers", zebra_stripes=True)

            with TabPane("Logs", id="tab-logs"):
                with Horizontal(id="action-row"):
                    yield Select(
                        [(s, s) for s in SERVICE_ORDER] + [("all", "all")],
                        value="weirvern-worker", id="log-service", allow_blank=False,
                    )
                    yield Button("Load", id="btn-logs")
                yield RichLog(id="logs", highlight=True, markup=False, wrap=True)

            with TabPane("Config", id="tab-config"):
                yield Static(
                    "Edit a value below and press Save. Secrets are masked. "
                    "Changes are backed up and require a worker restart.",
                    classes="hint",
                )
                yield DataTable(id="config-list", zebra_stripes=True)
                with Horizontal(id="action-row"):
                    yield Select(
                        [(k, k) for k in EDITABLE_KEYS],
                        prompt="key to edit", id="config-key", allow_blank=True,
                    )
                    yield Input(placeholder="new value", id="config-value")
                    yield Button("Save", id="btn-save", variant="success")
                    yield Button("Validate", id="btn-validate")

            with TabPane("Help", id="tab-help"):
                yield VerticalScroll(Static(id="help-text"))

        yield Footer()

    def on_mount(self) -> None:
        self.title = "Weirvern"
        self.sub_title = str(self.project_dir)
        self._setup_tables()
        self.query_one("#help-text", Static).update(self._help_markdown())
        self._refresh()
        self._timer = self.set_interval(self.refresh_s, self._refresh_tick)

    def _setup_tables(self) -> None:
        svc = self.query_one("#services", DataTable)
        svc.add_columns("", "Service", "State", "Health")

        health = self.query_one("#health", DataTable)
        health.add_columns("", "Check", "Detail")

        anom = self.query_one("#anomalies", DataTable)
        # The Source column holds a reverse-DNS label like
        # `spyro.home (192.168.2.42)` -- about 26 characters. Textual auto-sizes
        # columns to their content, so the full label fits without an explicit
        # width; no truncation is needed and the IP is never dropped to save space.
        anom.add_columns("Detected", "Source", "Score", "Severity", "Detectors")

        talk = self.query_one("#talkers", DataTable)
        talk.add_columns("Source", "Bytes", "Flows", "Destinations")

        cfg = self.query_one("#config-list", DataTable)
        cfg.add_columns("Key", "Value", "Notes")

    # -- data collection (threaded) ----------------------------------------
    def _refresh(self) -> None:
        self._collect()

    def _refresh_tick(self) -> None:
        self._collect()

    @work(thread=True, exclusive=True)
    def _collect(self) -> None:
        """Gather everything off the UI thread, then post one message."""
        services, probes, anomalies, talkers = [], [], [], []
        error = ""

        try:
            services = self.backend.ps()
        except Exception as exc:  # noqa: BLE001
            error = f"services: {exc}"

        try:
            from weirvern.admin.cli import admin_client
            from weirvern.config import get_settings

            settings = get_settings()
            # `admin_client` opens a port-forward when the configured host is
            # cluster-internal. Without it the TUI reported "Could not connect to
            # ClickHouse at http://clickhouse:8123" while every workload showed
            # healthy, because a workstation cannot resolve a cluster DNS name.
            with admin_client(settings) as client:
                report = collect_health(client, settings)
                probes = report.probes
                if not error:
                    anomalies = recent_anomalies(client)
                    talkers = top_talkers(client)
        except Exception as exc:  # noqa: BLE001
            if not error:
                error = _condense(str(exc), 160)

        self.post_message(HealthUpdated(services, probes, anomalies, talkers, self.caps, error))

    @on(HealthUpdated)
    def _render(self, msg: HealthUpdated) -> None:
        # Status bar
        bar = self.query_one("#statusbar", Static)
        if msg.error:
            bar.update(f"[red]✗ {_condense(msg.error)}[/red]")
        else:
            ok = sum(1 for p in msg.probes if p.ok)
            total = len(msg.probes)
            colour = "green" if ok == total and total else "yellow"
            if msg.caps.cluster_available:
                runtime = f"kubernetes ({NAMESPACE})"
            else:
                runtime = f"no cluster ({_condense(msg.caps.reason, 40)})"
            bar.update(f"[{colour}]✓ {ok}/{total} checks passing[/{colour}]   "
                       f"[dim]runtime: {runtime}   refresh: {self.refresh_s}s   "
                       f"press ? for help[/dim]")

        # Workloads
        table = self.query_one("#services", DataTable)
        table.clear()
        order = {name: i for i, name in enumerate(SERVICE_ORDER)}
        for s in sorted(msg.services, key=lambda x: order.get(x.name, 99)):
            colour = {"running": "green", "suspended": "yellow"}.get(s.state, "red")
            table.add_row(f"[{colour}]{s.dot}[/{colour}]", s.name,
                          s.state, s.detail or s.health or "-")
        if not msg.services:
            # An empty table looks like a bug; say what is actually true.
            if msg.caps.cluster_available:
                table.add_row("[dim]·[/dim]", "(nothing deployed)", "not applied",
                              "[dim]press A to apply the manifests[/dim]")
            else:
                table.add_row("[dim]·[/dim]", "(unavailable)", "no runtime",
                              f"[dim]{_condense(msg.caps.reason, 30)}[/dim]")

        # Health probes
        htable = self.query_one("#health", DataTable)
        htable.clear()
        for p in msg.probes:
            mark = "[green]✓[/green]" if p.ok else "[red]✗[/red]"
            htable.add_row(mark, p.name, p.detail)
        if not msg.probes:
            # Distinguish "database down" from "nothing to report".
            htable.add_row("[red]✗[/red]", "clickhouse",
                           f"[red]{_condense(msg.error or 'not reachable', 60)}[/red]")
            htable.add_row("[dim]·[/dim]", "pipeline", "[dim]not probed (no database)[/dim]")

        # Anomalies
        atable = self.query_one("#anomalies", DataTable)
        atable.clear()
        for row in msg.anomalies:
            detected, src, score, severity, detectors = row
            colour = {"critical": "red", "high": "yellow"}.get(severity, "dim")
            atable.add_row(str(detected), _host_label(str(src)), f"{score:.3f}",
                           f"[{colour}]{severity}[/{colour}]", str(detectors)[:40])
        if not msg.anomalies and not msg.error:
            atable.add_row("-", "(none recorded)", "-", "-", "-")

        # Talkers
        ttable = self.query_one("#talkers", DataTable)
        ttable.clear()
        for row in msg.talkers:
            src, b, flows, dsts = row
            ttable.add_row(_host_label(str(src)), _bytes(int(b or 0)),
                           str(flows), str(dsts))

        self._render_config()

    def _render_config(self) -> None:
        table = self.query_one("#config-list", DataTable)
        table.clear()
        env = config_io.EnvFile.load(self.project_dir / ".env")
        for key in env.keys():  # noqa: SIM118 - EnvFile is not a dict
            val = env.get(key) or ""
            shown = config_io.mask(val) if config_io.is_secret(key) else val
            table.add_row(key, shown or "(unset)",
                          "[dim]secret[/dim]" if config_io.is_secret(key) else "")

    def _help_markdown(self) -> str:
        return (
            "[b]Keys[/b]\n"
            "  q  quit          r  refresh        s  start all\n"
            "  x  stop all      R  restart all    a  apply manifests\n"
            "  l  load logs\n\n"
            "[b]Tabs[/b]\n"
            "  Overview  — workloads, health probes, live state\n"
            "  Anomalies — recent detections and top talkers\n"
            "  Logs      — tail a workload's output\n"
            "  Config    — inspect and edit .env (secrets masked)\n\n"
            "[b]What the lifecycle keys do on Kubernetes[/b]\n"
            "  s  start    scale the workloads back up (removes a Zeek suspension)\n"
            "  x  stop     scale to zero. The Zeek DaemonSet cannot be scaled to\n"
            "              zero, so it is suspended — packet capture stops and the\n"
            "              workload reports 'suspended' rather than 'stopped'.\n"
            "  R  restart  kubectl rollout restart (there is no pod restart verb)\n"
            "  a  apply    kubectl apply -k k8s/ — deploys and updates the stack\n\n"
            "[b]Typical first run[/b]\n"
            "  1. On the node: kubectl label node <node> weirvern.io/sensor-node=true\n"
            "  2. Config tab: set ZEEK_IFACE to the mirror/NIC\n"
            "  3. Overview: Apply, then Start all\n"
            "  4. Watch Health until ingest_freshness turns green\n"
            "  5. Anomalies tab: confirm detections appear\n\n"
            "[b]No cluster connected?[/b]\n"
            "  The panel still reads ClickHouse and edits .env. Workload control\n"
            "  needs kubectl pointing at a cluster — see README.md.\n"
        )

    # -- actions -----------------------------------------------------------
    def action_refresh(self) -> None:
        self.notify("Refreshing…", timeout=2)
        self._refresh()

    def _run_backend(self, label: str, fn) -> None:
        self.notify(f"{label}…", timeout=3)
        self._do_backend(label, fn)

    @work(thread=True)
    def _do_backend(self, label: str, fn) -> None:
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            self.call_from_thread(self.notify, f"{label} failed: {exc}", severity="error", timeout=6)
            return
        if result.ok:
            self.call_from_thread(self.notify, f"{label}: ok", timeout=3)
        else:
            tail = (result.text or "")[-300:]
            self.call_from_thread(self.notify, f"{label} failed: {tail}", severity="error", timeout=8)
        self.call_from_thread(self._refresh)

    def action_start_all(self) -> None:
        self._run_backend("start", lambda: self.backend.start())

    def action_stop_all(self) -> None:
        self._run_backend("stop", lambda: self.backend.stop())

    def action_restart_all(self) -> None:
        self._run_backend("restart", lambda: self.backend.restart())

    def action_apply(self) -> None:
        """Apply the manifests. This is the deploy action on Kubernetes — the
        equivalent of what `up -d` did on a single host."""
        self._run_backend("apply", lambda: self.backend.apply())

    def action_load_logs(self) -> None:
        self._load_logs()

    def _load_logs(self) -> None:
        try:
            choice = self.query_one("#log-service", Select).value
        except Exception:  # noqa: BLE001
            choice = "weirvern-worker"
        service = "" if choice in (Select.BLANK, "all") else str(choice)
        self._fetch_logs(service)

    @work(thread=True)
    def _fetch_logs(self, service: str) -> None:
        try:
            text = self.backend.logs(service, tail=self.app_log_tail())
        except Exception as exc:  # noqa: BLE001
            text = f"log fetch failed: {exc}"
        log = self.query_one("#logs", RichLog)
        lines = text.splitlines()[-400:] or ["(no output)"]
        self.call_from_thread(log.clear)
        for line in lines:
            self.call_from_thread(log.write, line)

    def app_log_tail(self) -> int:
        return 200

    @on(Button.Pressed, "#btn-start")
    def _b_start(self) -> None:
        self.action_start_all()

    @on(Button.Pressed, "#btn-stop")
    def _b_stop(self) -> None:
        self.action_stop_all()

    @on(Button.Pressed, "#btn-restart")
    def _on_restart(self) -> None:
        self.action_restart_all()

    @on(Button.Pressed, "#btn-apply")
    def _on_apply(self) -> None:
        self.action_apply()

    @on(Button.Pressed, "#btn-refresh")
    def _b_refresh(self) -> None:
        self.action_refresh()

    @on(Button.Pressed, "#btn-logs")
    def _b_logs(self) -> None:
        self._load_logs()

    @on(Button.Pressed, "#btn-save")
    def _b_save(self) -> None:
        key = self.query_one("#config-key", Select).value
        value = self.query_one("#config-value", Input).value
        if key in (Select.BLANK, None) or not str(key):
            self.notify("pick a key first", severity="warning")
            return
        if value == "":
            self.notify("value is empty (use the CLI to unset)", severity="warning")
            return
        env = config_io.EnvFile.load(self.project_dir / ".env")
        env.backup(".bak")
        env.set(str(key), value)
        env.save()
        self.notify(f"{key} saved — restart the worker to apply", timeout=5)
        self.query_one("#config-value", Input).value = ""
        self._refresh()

    @on(Button.Pressed, "#btn-validate")
    def _b_validate(self) -> None:
        from weirvern.admin.cli import _validate_env  # local import: CLI owns validation rules

        env = config_io.EnvFile.load(self.project_dir / ".env")
        import io
        from contextlib import redirect_stdout

        buf = io.StringIO()
        with redirect_stdout(buf):
            code = _validate_env(env)
        text = buf.getvalue().strip() or ("valid" if code == 0 else "invalid")
        # Strip ANSI for the notification.
        import re as _re
        text = _re.sub(r"\x1b\[[0-9;]*m", "", text)
        self.notify(text[:180], severity="information" if code == 0 else "error", timeout=8)


def _bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f}PB"


def run_tui(project_dir: str | Path, refresh_s: int = 5) -> int:
    app = WeirvernTUI(Path(project_dir), refresh_s=refresh_s)
    app.run()
    return 0
