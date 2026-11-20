"""Weirvern configuration — environment-driven, validated at import time.

Lesson v14–v19: magic numbers were scattered through the detection script and
thresholds changed version over version. All knobs live here, overridable via
environment variables, documented in `.env.example`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# ── WHERE THE TAP PUBLISHES ITS OWN STATE (measured 2026-11-17) ────────────────────────────────
#
# The tap runs where the privilege is (the Zeek pod's sidecar on the hub, the agent container on a
# weirling), and the process that reports health runs somewhere else (the GUI pod, or the worker
# for the CLI). Neither can see the other's /tmp, and the tap has no database client -- by design,
# a capture process must keep capturing when ClickHouse is away.
#
# So the state is a small file on a hostPath that all three mount. It is the only evidence a human
# has that capture is ALIVE rather than merely configured: every other health probe can read green
# while the tap is dead, because flows simply stop arriving and "no flows" looks exactly like "a
# quiet network" (the failure this module's siblings spent the week fixing).
DEFAULT_TAP_STATE_PATH = "/var/lib/weirvern/tap/state.json"


def tap_state_path() -> str:
    """Where the tap writes its state and every reader looks for it.

    A function, not a constant, so the path is read at CALL time: tests point it at a tmp dir, and
    a container can override it without the value being frozen at import.
    """
    return (os.environ.get("WEIRVERN_TAP_STATE") or "").strip() or DEFAULT_TAP_STATE_PATH


def _int_env(name: str, default: int) -> int:
    """Read a positive int from the environment, tolerating junk.

    A cap is an operational safety limit, not a correctness-critical value, so a
    malformed one must not take the control plane down -- it falls back to the default
    and the value is visible via `weirvern disk`.
    """
    raw = (os.environ.get(name) or "").strip()
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default




# THE SCORE THE DECISION ACTUALLY COMPARES. `ensemble.detect_flows` fuses the per-model scores into
# one number and thresholds THAT, so a calibrator fitted only on the individual detectors calibrates a
# value nothing alerts on. The fused score is recorded into the calibration population under this
# reserved name and fitted like any other, and the decision reads its threshold back. It lives in
# config because both modules that need it already import config, and neither imports the other.
FUSED_MODEL = "__fused__"


def _env_int(name: str, default: int) -> int:
    raw = _clean_env(os.environ.get(name))
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from None


def _env_float(name: str, default: float) -> float:
    raw = _clean_env(os.environ.get(name))
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError:
        raise ValueError(f"{name} must be a number, got {raw!r}") from None


def _env_str(name: str, default: str = "") -> str:
    raw = _clean_env(os.environ.get(name))
    return default if raw is None else raw


def _clean_env(raw: str | None) -> str | None:
    """Strip an inline trailing comment and surrounding whitespace.

    The `.env.example` template ships values with trailing comments (e.g.
    `DETECT_INTERVAL_S=300          # sweep cadence`), so a parser that did not
    strip them would fail on its own shipped template — verified failure:
    DETECT_INTERVAL_S parsed as "300          # sweep cadence (seconds)" and
    raised on int().

    A `#` inside quotes is preserved (it is part of the value).
    """
    if raw is None:
        return None
    raw = raw.strip()
    if not raw:
        return raw
    if raw[0] in {'"', "'"}:
        quote = raw[0]
        end = raw.find(quote, 1)
        return (raw[1:end] if end != -1 else raw[1:]).strip()
    marker = raw.find(" #")
    if marker == -1:
        marker = raw.find("\t#")
    if marker != -1:
        raw = raw[:marker]
    return raw.strip()


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _clean_env(os.environ.get(name))
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_mode(name: str, default: str = "loch") -> str:
    """Read the sensor mode, normalised through the mode module.

    Normalised here rather than validated: an unknown value is RETURNED AS TYPED so the
    status output can report exactly what is configured and that it is unrecognised.
    Silently coercing it to "loch" would hide a typo and quietly change the sensor's
    behaviour, which is the opposite of what someone setting this wants.
    """
    raw = _clean_env(os.environ.get(name))
    if raw is None or raw.strip() == "":
        return default
    from weirvern.admin.mode import normalise

    return normalise(raw)


@dataclass(frozen=True)
class Settings:
    # ClickHouse
    clickhouse_host: str = field(default_factory=lambda: os.environ.get("CLICKHOUSE_HOST", "clickhouse"))
    clickhouse_port: int = field(default_factory=lambda: _env_int("CLICKHOUSE_PORT", 8123))
    clickhouse_db: str = field(default_factory=lambda: os.environ.get("CLICKHOUSE_DB", "weirvern"))
    clickhouse_user: str = field(default_factory=lambda: os.environ.get("CLICKHOUSE_USER", "default"))
    clickhouse_password: str = field(default_factory=lambda: os.environ.get("CLICKHOUSE_PASSWORD", ""))

    # ── RETENTION (derived from free disk, not fixed) ─────────────────────────────────────────
    #
    # 'auto' (the default) derives the window from the disk that holds this database and the
    # ingest rate the managed tables have ACTUALLY observed -- see weirvern.retention. An
    # explicit day count (7-365) overrides it, and is refused above the measured budget.
    #
    # `DATA_RETENTION_RATIO` is the share of FREE space the tables may occupy: 40% by default,
    # never more than 70%, because ClickHouse needs room for merges. Both are ConfigMap keys,
    # so the schema Job and every worker start read the operator's choice through Settings.
    data_retention_days: str = field(
        default_factory=lambda: _env_str("DATA_RETENTION_DAYS", "auto"))
    data_retention_ratio: int = field(
        default_factory=lambda: _env_int("DATA_RETENTION_RATIO", 40))

    # Detection loop
    detect_interval_s: int = field(default_factory=lambda: _env_int("DETECT_INTERVAL_S", 300))
    retrain_every_h: int = field(default_factory=lambda: _env_int("RETRAIN_EVERY_H", 6))
    retrain_window_h: int = field(default_factory=lambda: _env_int("RETRAIN_WINDOW_H", 72))
    base_threshold: float = field(default_factory=lambda: _env_float("BASE_THRESHOLD", 0.35))
    min_agreement: float = field(default_factory=lambda: _env_float("MIN_AGREEMENT", 0.33))
    # The corroboration bar: a detector scoring at/above this counts as a STRONG signal,
    # and high/critical severity requires two-or-more (or one plus a structural signature).
    #
    # WIRED, not decorative. This was a module constant in ensemble.py that the GUI and
    # the ConfigMap advertised as editable and VALIDATED on apply -- so changing it wrote
    # a perfectly valid ConfigMap key that no code ever read. The edit validated, the
    # worker restarted, and the behaviour was identical: the exact silent no-op this
    # setting is supposed to be the opposite of. It now reads from the environment like
    # its neighbours, and detect_flows uses the value for both the strong-model count and
    # the signature gate.
    strong_signal: float = field(default_factory=lambda: _env_float("STRONG_SIGNAL", 0.85))

    # ── ML SHADOW/calibration ────────────────────────────────────────────────────────────────
    # Shadow passes write candidate/calibration tables only; they never alter alerts or severity.
    # The calibration target is a false-alarm fraction for the alert tail, not an accuracy claim.
    ml_shadow: bool = field(default_factory=lambda: _env_bool("ML_SHADOW", True))

    # The host-hour's daily episode budget. The threshold is derived from it (budget divided
    # by host-hours) rather than tuned by hand, so the number of pages is a decision the
    # operator made rather than one the distribution made for them. Shadow only until the
    # scorecard has measured a replay at this budget.
    host_hour_alerts_per_day: int = field(
        default_factory=lambda: _env_int("HOST_HOUR_ALERTS_PER_DAY", 20))
    ml_target_far: float = field(default_factory=lambda: _env_float("ML_TARGET_FAR", 0.01))
    # Eligibility gate: a detector whose measured FAR exceeds target * multiple cannot set the
    # fused score. ON by default because the operator asked for the production decision layer;
    # ML_ELIGIBILITY=false is the kill switch. A missing/empty calibration leaves every model
    # eligible (the gate cannot invent a quarantine from no evidence).
    ml_eligibility: bool = field(default_factory=lambda: _env_bool("ML_ELIGIBILITY", True))
    # MODELS REMOVED FROM THE FUSION, BY NAME, COMMA SEPARATED. This is a second rail beside
    # eligibility, because the two exclusions fail differently. Eligibility bars a model whose
    # measured false-alarm rate is out of budget, and a structural signature is DELIBERATELY
    # allowed to override it, since the barred model may be the only one that saw the scan.
    # A fusion exclusion is different in kind: the model is removed because it makes the fused
    # score unmeasurable, so nothing should restore it. Measured on 4,770 host-windows: the
    # Gradient Boosting student sits on a point mass at 0.99 covering 3.04% of windows and equals
    # the fused maximum on 69.6% of them, so `max` fusion inherits its quantization and a
    # conformal threshold returns 0.99 for every target from 1% to 0.2%, which stops the alert
    # budget from controlling the alert count at all. Empty string restores the old fusion.
    ml_fusion_exclude: str = field(
        default_factory=lambda: _env_str("ML_FUSION_EXCLUDE", "Gradient Boosting"))
    # WHEN ON, the alert bar is the calibrated threshold for the fused score rather than
    # `base_threshold` reduced per window. The point of a conformal calibrator is that the
    # threshold IS the chosen alerts-per-day, and an adaptive reduction applied on top of it
    # silently spends a budget nobody chose. Off restores the previous decision exactly.
    ml_calibrated_threshold: bool = field(
        default_factory=lambda: _env_bool("ML_CALIBRATED_THRESHOLD", True))
    ml_eligibility_multiple: float = field(
        default_factory=lambda: _env_float("ML_ELIGIBILITY_MULTIPLE", 3.0)
    )
    # Episode/budget layer: consecutive windows for the same host are one incident. Only
    # high/critical episodes may page, and only `episode_page_budget` per host per 24h.
    episode_gap_minutes: int = field(default_factory=lambda: _env_int("EPISODE_GAP_MINUTES", 30))
    # How far back the episode builder reads anomalies. It must cover the whole life of an open
    # incident, not just the display window: keying on a sliding 24-hour start is what created a
    # new episode row every five minutes.
    episode_lookback_h: int = field(default_factory=lambda: _env_int("EPISODE_LOOKBACK_H", 720))
    episode_page_budget: int = field(default_factory=lambda: _env_int("EPISODE_PAGE_BUDGET", 2))
    episode_page_min_severity: str = field(
        default_factory=lambda: os.environ.get("EPISODE_PAGE_MIN_SEVERITY", "high")
    )
    ml_calibration_days: int = field(default_factory=lambda: _env_int("ML_CALIBRATION_DAYS", 7))
    # ── MISSING-DATA HANDLING (default OFF) ───────────────────────────────────────────────────
    #
    # ON: a feature whose source was not measured is None (NULL) rather than 0, Isolation
    # Forest and Gradient Boosting impute the TRAINING-TIME median per feature and add one
    # `<feature>__missing` indicator, DBSCAN takes its distance over observed dimensions only
    # (or abstains below the coverage floor), and calibration excludes windows below the floor.
    #
    # OFF: every behaviour above is skipped and the score path is exactly the one that
    # existed before this flag. Flipping it changes EVERY score in production and invalidates
    # models trained on the old vector, which is why the default is OFF: the artifacts are
    # refused at load (their recorded mode disagrees) and each detector retrains on its next
    # cadence; until that retrain and a fresh calibration, the existing holdout lock keeps
    # them out of the fused score.
    ml_missing_features: bool = field(
        default_factory=lambda: _env_bool("ML_MISSING_FEATURES", False))
    # The share of a detector's vector that must be measured before the window is scored or
    # used in calibration. See models/missing.DEFAULT_MIN_COVERAGE for why 0.15.
    ml_min_feature_coverage: float = field(
        default_factory=lambda: _env_float("ML_MIN_FEATURE_COVERAGE", 0.15))
    # Warm-up gate for a new deployment. The models can learn only after the local network
    # has produced enough distinct windows/hosts; until then the detection rows still land in
    # the console, but they do not page. This is the cold-start contract: no universal
    # "normal" is assumed, and an empty network is not a quiet network.
    ml_warmup_hours: int = field(default_factory=lambda: _env_int("ML_WARMUP_HOURS", 24))
    ml_warmup_min_windows: int = field(
        default_factory=lambda: _env_int("ML_WARMUP_MIN_WINDOWS", 12)
    )
    ml_warmup_min_hosts: int = field(default_factory=lambda: _env_int("ML_WARMUP_MIN_HOSTS", 1))


    # Data input (goflow2 JSONL sink)
    tail_file: str = field(default_factory=lambda: os.environ.get("TAIL_FILE", "/data/flows.jsonl"))
    # ONE COLLECTOR PER NIC (2026-11-18): each writes its own file on the one port 2055, bound to
    # a different loopback address. "eth1=/data/flows.jsonl,eth2=/data/flows-eth2.jsonl" makes the
    # file the attribution; empty keeps the single-file behaviour and an empty interface name.
    tail_files: str = field(default_factory=lambda: os.environ.get("TAIL_FILES", ""))

    # Addresses the sensor refuses to LEARN from: scanners, synthetic test ranges, noisy hosts.
    # Comma-separated CIDRs. Applied at the row layer so the traffic is counted rather than
    # vanishing, which keeps the evidence available for a manual look.
    exclude_cidrs: str = field(
        default_factory=lambda: os.environ.get("WEIRVERN_EXCLUDE_CIDRS", "")
    )
    # Addresses dropped at the CAPTURE socket instead. Empty by default, and separate from the
    # above on purpose: this destroys the record before it exists, so it must be chosen
    # deliberately rather than inherited from a list added for ingest.
    capture_exclude_cidrs: str = field(
        default_factory=lambda: os.environ.get("WEIRVERN_CAPTURE_EXCLUDE_CIDRS", "")
    )

    # Zeek packet-level logs (optional second sensor). Empty = NetFlow only.
    zeek_log_dir: str = field(default_factory=lambda: os.environ.get("ZEEK_LOG_DIR", ""))

    # The capture and management interfaces, by NAME, as the sensor node sees them.
    # Kept in the settings so the running worker can report a mismatch: a capture
    # interface that is also the default route is the configuration that produces a
    # capture full of broadcast noise and nothing else.
    zeek_iface: str = field(default_factory=lambda: os.environ.get("ZEEK_IFACE", ""))
    # ZEEK_IFACES lets the capture sensor sniff SEVERAL ports (operator, 2026-10-19: "Zeek must be
    # configured to leverage multiple nic"). Empty means "just zeek_iface". CAPTURE_IFACE is the
    # one port the siphon intercept borrows for in-path relay; it may be one of the Zeek ports or
    # a different one, and it is the only port that is ever poisoned.
    zeek_ifaces: str = field(default_factory=lambda: os.environ.get("ZEEK_IFACES", ""))
    capture_iface: str = field(default_factory=lambda: os.environ.get("CAPTURE_IFACE", ""))
    # HUMAN NAMES FOR INTERFACES, so an alert can say "Servers" or "DMZ" instead of only a CIDR
    # (operator, 2026-10-19). Format: `eth1=Servers,eth2=DMZ`; empty means no names. Read by the
    # console's anomaly location resolver; it is a label, never an addressing decision.
    interface_networks: str = field(
        default_factory=lambda: os.environ.get("INTERFACE_NETWORKS", "")
    )
    mgmt_iface: str = field(default_factory=lambda: os.environ.get("MGMT_IFACE", ""))

    # What this sensor calls itself in sensor-keyed rows and the gate's state row
    # (worker._sensor_name). THE DOOR EXISTS NOW (review round 2026-10-15): the worker read
    # `getattr(settings, "sensor_name", "")` for a field this class never defined, so the
    # documented "a deployment that wants to call itself something" switch was unreachable
    # -- only NODE_NAME/hostname ever applied, and SENSOR_ID (which the heartbeat honors
    # and fleet.py validates) was invisible to the gate's rows. The field reads SENSOR_ID,
    # so every reader of the identity now agrees on it.
    sensor_name: str = field(
        default_factory=lambda: (os.environ.get("SENSOR_ID") or "").strip()
    )

    # HOW the sensor gets its packets: "loch" (passive promisc/SPAN capture) or "siphon"
    # (in-path ARP intercept). Normalised through the mode module so a mechanism word
    # like "intercept" typed into a config file still resolves, and so an unknown value
    # is preserved for reporting rather than silently defaulting to something else.
    #
    # Note this is read, not enforced, here: the mode gates container capabilities and
    # sysctls, which are decided in the manifests. Reading it lets the running worker
    # report the mode and its blast radius in status output.
    sensor_mode: str = field(
        default_factory=lambda: _env_mode("SENSOR_MODE")
    )

    # Siphon mode only: comma-separated addresses (or CIDRs) to intercept, or "*" for
    # every host on the capture segment. Empty means nothing is intercepted even if the
    # mode says siphon, so enabling the mode cannot by itself divert traffic — the
    # targets are a separate, explicit decision.
    intercept_targets: str = field(
        default_factory=lambda: os.environ.get("INTERCEPT_TARGETS", "")
    )

    # ── WHICH FLOW EXPORTERS TO BELIEVE ───────────────────────────────────────────────────────
    #
    # Comma-separated addresses or CIDRs. EMPTY MEANS ACCEPT ANYTHING, which is the default
    # because a collector that silently drops a legitimate exporter on first boot is worse than
    # one that takes whatever arrives — an operator adding an allow-list before seeing what
    # actually sends flows would have no way to write it.
    #
    # WHY THIS EXISTS. The collector runs with hostNetwork so it can bind 2055/6343 on the node's
    # own interfaces (an exporter was observed sending to the container port rather than the
    # NodePort, and the packets vanished with nothing logged). That also means ANY device that can
    # reach the node can send flows: NetFlow is unauthenticated UDP with no source verification in
    # the protocol, the NetworkPolicy deliberately exempts this collector, and goflow2 has no
    # accept-list. So a host on the segment can inject flows attributed to any address it chooses,
    # and those flows feed the anomaly models and the charts a threat-hunt team reads.
    #
    # SET THIS ONCE YOU KNOW YOUR EXPORTERS: `SET` reports the addresses it has seen. Turning it on
    # converts "any device may write to my detection data" into "these devices may".
    flow_exporter_allow: str = field(
        default_factory=lambda: os.environ.get("WEIRVERN_FLOW_EXPORTER_ALLOW", "")
    )

    # Alerting
    # ── Sluice Gate: operator-controlled blocking ──────────────────────────────────────────
    #
    # SLUICE_ENABLED is the MASTER SWITCH and defaults to OFF, deliberately. A monitoring appliance
    # that blocks traffic the moment it is installed would surprise an operator who wanted to look
    # before touching; the gate is opened by a decision, not by an install.
    sluice_enabled: bool = field(default_factory=lambda: _env_bool("SLUICE_ENABLED", False))
    # WHICH INTERFACE enforcement attaches to. Empty means "use the capture interface", which is the
    # right answer for an in-path deployment; it can never be the management interface (the gate
    # refuses at authoring time), because blocking there locks the operator out of the appliance.
    # THE DOMAIN-BLOCKING SWITCH (the operator, 2026-10-16: "in sluice gate add a section to
    # enable or disable Domain Blocking"). ON by default: it gates only the domain-rule half of
    # enforcement, and an operator who made a domain rule in block mode asked for it. Off, those
    # rules stay recorded and alerting while address rules keep working -- see
    # sluice.enforcement_pass.
    # How often imported DNS lists are re-fetched (hours). Exposed 2026-10-16 with the
    # blocklist work: the lists moved into the operator's hands, and the cadence moved with them.
    blocklist_sync_hours: int = field(
        default_factory=lambda: _env_int("BLOCKLIST_SYNC_HOURS", 24))
    sluice_block_domains: bool = field(
        default_factory=lambda: _env_bool("SLUICE_BLOCK_DOMAINS", True))
    sluice_iface: str = field(default_factory=lambda: os.environ.get("SLUICE_IFACE", ""))
    # PER-NIC PLANS for this sensor. Empty keeps the legacy single plan (SENSOR_MODE +
    # CAPTURE_IFACE + SLUICE_IFACE); a non-empty document is authoritative, so a plan set with
    # no siphon NICs does not silently fall back to the old global mode.
    intercept_plans: str = field(
        default_factory=lambda: os.environ.get("INTERCEPT_PLANS", ""))
    # The criticality policy: whether detections may block on their own, and how aggressively. The
    # default is OFF even when the gate is enabled -- auto-blocking on ML output is a decision an
    # operator makes deliberately, having seen what the ensemble calls high severity on their own
    # network.
    sluice_criticality: str = field(
        default_factory=lambda: os.environ.get("SLUICE_CRITICALITY", "off").strip().lower()
    )
    # The longest a derived block may last, as a CEILING on the policy's own TTL. An operator who
    # distrusts automated blocking can set this to a minute and keep the convenience.
    sluice_max_block_s: int = field(default_factory=lambda: _env_int("SLUICE_MAX_BLOCK_S", 3600))
    # How often the gate is re-armed. Every pass re-evaluates expiry, so this is also the interval
    # within which a lapsed rule stops being enforced. Short is cheap: compiling a ruleset is
    # milliseconds.
    sluice_interval_s: int = field(default_factory=lambda: _env_int("SLUICE_INTERVAL_S", 60))
    # THE OPERATOR'S OWN AUTO-BLOCK THRESHOLD. When > 0, ANY detection whose fused score is at
    # or above this value is blocked on the gate's own pass -- "if it scores this high, stop it"
    # -- independent of the severity policy above (which stays the finer instrument: severity
    # AND confidence floors). 0.0 disables it, so the default deployment blocks nothing unless
    # the operator asks. A NUMBER rather than another severity level, because a fleet's notion
    # of "high" moves with its own thresholds while a score the operator picked does not.
    sluice_auto_score: float = field(default_factory=lambda: _env_float("SLUICE_AUTO_SCORE", 0.0))
    # WHAT THIS PROCESS IS FOR. "full" is the hub: ingest, detect, train, and enforce. "gate" is a
    # WEIRLING that has an enforcement ability of its own -- same image, same rule store, same
    # checks; it enforces and derives nothing (the hub is the single writer of rules, and a second
    # writer would mint a second rule for one detection, so revoking one would keep blocking on the
    # other). The point of a role rather than a second program: the hub's gate path and a
    # weirling's gate path cannot drift, because they are the same code.
    role: str = field(default_factory=lambda: os.environ.get("WEIRVERN_ROLE", "full"))
    # CHANNEL NETFLOW: whether the IN-LINE channel's crossing traffic is summarised into flow
    # records -- 'off' (default), 'upstream' or 'downstream' naming WHICH PORT the probe samples.
    # Either port sees every frame crossing the box, so one is enough; sampling both would count
    # each conversation twice. The probe exports to this deployment's OWN collector (goflow2),
    # which writes the same flows.jsonl the ingester tails -- so the records land in the same
    # `flows` table the Netflow tab and the models already read. Only meaningful while the
    # channel is verified active; the worker starts and stops the probe on that condition.
    # FLOW RECORDS FROM THE OTHER IN-LINE SOURCE. A live siphon intercept relays the segment's
    # traffic through this box, so the interface the relay crosses can be metered exactly the way
    # the channel's ports are -- same tap, same summariser, same collector, same `flows` table.
    # Off by default, and it only ever runs while the intercept is VERIFIED live: records from a
    # configured-but-dead intercept would be records of nothing, landing in the same table the
    # volume baselines train on.
    siphon_netflow: bool = field(
        default_factory=lambda: _env_bool("SIPHON_NETFLOW", False)
    )
    # PASSIVE OR ACTIVE NETFLOW (operator, 2026-10-19). Passive means an external router
    # exports NetFlow to this sensor's collector -- the historical path. Active means the
    # sensor summarises its own capture: the live siphon relay while intercepting, or the
    # mirrored interface in loch mode. `auto` preserves the pre-setting behaviour (siphon
    # auto-taps; otherwise only SIPHON_NETFLOW can start a probe).
    netflow_mode: str = field(
        default_factory=lambda: os.environ.get("NETFLOW_MODE", "auto").strip().lower()
    )
    # The port an ACTIVE loch probe samples. Empty resolves to ZEEK_IFACE. In siphon mode
    # the probe follows CAPTURE_IFACE, because that is the port the relay crosses.
    netflow_iface: str = field(
        default_factory=lambda: os.environ.get("NETFLOW_IFACE", "").strip()
    )
    channel_netflow: str = field(
        default_factory=lambda: os.environ.get("CHANNEL_NETFLOW", "off").strip().lower()
    )
    # CHANNEL: the two ports of an IN-LINE weirling -- upstream toward the network, downstream
    # toward the protected device -- joined into one bridge. A live channel is a VERIFIED
    # enforcement path for the Sluice Gate that needs no siphon interception and no forged
    # ARP: the gate's rules hit traffic that physically traverses this host. The checks the
    # gate performs before claiming it are in admin/channel.py; empty = no channel.
    channel_upstream: str = field(default_factory=lambda: os.environ.get("CHANNEL_UPSTREAM", ""))
    channel_downstream: str = field(default_factory=lambda: os.environ.get("CHANNEL_DOWNSTREAM", ""))

    pushover_enabled: bool = field(default_factory=lambda: _env_bool("PUSHOVER_ENABLED", False))
    pushover_user_key: str = field(default_factory=lambda: os.environ.get("PUSHOVER_USER_KEY", ""))
    pushover_api_token: str = field(default_factory=lambda: os.environ.get("PUSHOVER_API_TOKEN", ""))
    pushover_cooldown_s: int = field(default_factory=lambda: _env_int("PUSHOVER_COOLDOWN_S", 1800))
    pushover_max_per_hour: int = field(default_factory=lambda: _env_int("PUSHOVER_MAX_PER_HOUR", 20))

    # ── Active asset scanner (Nmap + Nuclei) ──────────────────────────────────────────────────
    # This is a separate process (weirvern.scanner), not the worker. It is OFF by default for the
    # same reason Sluice is: an appliance that starts probing the LAN because it was installed is
    # a surprise. The scope comes from the enabled weirlings' declared CIDR segments; with none,
    # the scanner idles rather than guessing that the whole RFC1918 space belongs to it.
    scan_enabled: bool = field(default_factory=lambda: _env_bool("SCAN_ENABLED", False))
    scan_interval_s: int = field(default_factory=lambda: _env_int("SCAN_INTERVAL_S", 60))
    # THE LOOP IS CHEAP; THE SWEEP IS NOT. A passive pass is one ClickHouse read of recent flows
    # and catches any host that has spoken. An active `nmap -sn` sweep sends ARP/ICMP probes to
    # every address in the declared networks, so it runs on its own, slower schedule. At 60s a
    # two-/24 scope was ~30k probes/hour for zero new assets; 300s is the default, and an
    # operator can raise it without slowing passive detection.
    scan_discovery_s: int = field(default_factory=lambda: _env_int("SCAN_DISCOVERY_S", 300))
    # THE CHANGE LEDGER NEEDS A SECOND LOOK. Discovery only finds new hosts, and pending-only
    # scanning never revisits an existing host, so a service can open and stay invisible forever.
    # Rescan completed hosts on this slower clock; the cap is scan_max_hosts per pass.
    scan_rescan_s: int = field(default_factory=lambda: _env_int("SCAN_RESCAN_S", 3600))
    # A manual job's lease. The scanner renews it only by finishing the job; a pod that dies
    # mid-scan leaves the row claimable after this many seconds (the scan is idempotent).
    scan_job_lease_s: int = field(default_factory=lambda: _env_int("SCAN_JOB_LEASE_S", 900))
    scan_passive_minutes: int = field(default_factory=lambda: _env_int("SCAN_PASSIVE_MINUTES", 10))
    scan_bootstrap: bool = field(default_factory=lambda: _env_bool("SCAN_BOOTSTRAP", False))
    scan_ports: str = field(
        default_factory=lambda: os.environ.get("SCAN_PORTS", "1-1024,3000,5000,8000-9000,9090,9443")
    )
    scan_timeout_s: int = field(default_factory=lambda: _env_int("SCAN_TIMEOUT_S", 600))
    scan_max_hosts: int = field(default_factory=lambda: _env_int("SCAN_MAX_HOSTS", 16))
    # Nuclei is OFF for now. The active-inventory layer is Nmap + NSE: it is portable to any
    # network, has no template-update lifecycle, and cannot run a community template that turns
    # out to be destructive. Keep the code path for a future reviewed exposure layer, but do not
    # require the binary or the template download in the default image.
    scan_nuclei_enabled: bool = field(
        default_factory=lambda: _env_bool("SCAN_NUCLEI_ENABLED", False)
    )
    scan_nuclei_severity: str = field(
        default_factory=lambda: os.environ.get("SCAN_NUCLEI_SEVERITY", "critical,high,medium")
    )
    scan_nuclei_templates: str = field(
        default_factory=lambda: os.environ.get("SCAN_NUCLEI_TEMPLATES", "")
    )
    # ── SAFETY AND SIZE OF THE NUCLEI PASS ────────────────────────────────────────────────
    # The template ecosystem includes destructive checks. A network CVE tagged `dos` (SLP,
    # CVE-2019-5544) is a live example: it sends a heap-overflow payload, not a read-only probe.
    # A vulnerability scanner on a home network must never run those by accident, so dangerous
    # tags are excluded explicitly rather than trusting the template repository's default ignore
    # file (which can change between releases).
    scan_nuclei_exclude_tags: str = field(
        default_factory=lambda: os.environ.get(
            "SCAN_NUCLEI_EXCLUDE_TAGS", "dos,intrusive,fuzz,brute-force,headless,code"
        )
    )
    # An optional allowlist. Empty means "all non-excluded templates"; a comma-separated tag
    # list can narrow a deployment to cve,exposure,misconfig without forking the image.
    scan_nuclei_tags: str = field(default_factory=lambda: os.environ.get("SCAN_NUCLEI_TAGS", ""))
    scan_nuclei_exclude_ids: str = field(
        default_factory=lambda: os.environ.get("SCAN_NUCLEI_EXCLUDE_IDS", "")
    )
    # MEASURED: default concurrency with 10k templates peaked near 2 GiB on the test box. These
    # defaults keep the scanner within its 4 GiB limit and shorten the tail of slow hosts.
    scan_nuclei_concurrency: int = field(
        default_factory=lambda: _env_int("SCAN_NUCLEI_CONCURRENCY", 25)
    )
    scan_nuclei_bulk_size: int = field(
        default_factory=lambda: _env_int("SCAN_NUCLEI_BULK_SIZE", 25)
    )
    scan_nuclei_rate_limit: int = field(
        default_factory=lambda: _env_int("SCAN_NUCLEI_RATE_LIMIT", 150)
    )
    scan_nuclei_timeout_s: int = field(
        default_factory=lambda: _env_int("SCAN_NUCLEI_TIMEOUT_S", 10)
    )
    scan_nuclei_retries: int = field(
        default_factory=lambda: _env_int("SCAN_NUCLEI_RETRIES", 1)
    )
    scan_nuclei_max_host_error: int = field(
        default_factory=lambda: _env_int("SCAN_NUCLEI_MAX_HOST_ERROR", 5)
    )
    scan_nuclei_response_size: int = field(
        default_factory=lambda: _env_int("SCAN_NUCLEI_RESPONSE_SIZE", 1_048_576)
    )
    # Interactsh sends callbacks to a third-party OAST service. This scanner is a LAN appliance;
    # keep it outbound-free unless an operator explicitly wants OAST.
    scan_nuclei_no_interactsh: bool = field(
        default_factory=lambda: _env_bool("SCAN_NUCLEI_NO_INTERACTSH", True)
    )
    scan_nmap_binary: str = field(default_factory=lambda: os.environ.get("SCAN_NMAP_BINARY", "nmap"))
    scan_nuclei_binary: str = field(
        default_factory=lambda: os.environ.get("SCAN_NUCLEI_BINARY", "nuclei")
    )


    # Models
    model_dir: str = field(default_factory=lambda: os.environ.get("MODEL_DIR", "/models"))

    # How often the worker publishes the sensor's observed state. Independent of
    # detect_interval_s: the heartbeat must be frequent for staleness to mean anything
    # (status.HEARTBEAT_STALE_S is 45s), while detection is deliberately slow. Sharing one
    # interval would make a healthy sensor look dead between detection cycles.
    heartbeat_interval_s: int = field(
        default_factory=lambda: _int_env("HEARTBEAT_INTERVAL_S", 15)
    )

    # ── Disk caps ───────────────────────────────────────────────────────────
    # Byte ceilings for the components that grow without bound. Zeek rotates by TIME
    # and never deletes, so nothing bounded its log directory until these existed:
    # measured 87 rotated files / ~7 MB per hour on a 40 GB disk.
    #
    # Read by the prune CronJob and `weirvern prune`. Declared here so they are
    # discoverable -- a cap that only appears in a manifest is one operators never set,
    # and an unset cap is indistinguishable from a healthy disk until it is full.
    #
    # 0 means "no cap" and is reported as unset rather than as within budget.
    zeek_max_mb: int = field(default_factory=lambda: _int_env("ZEEK_MAX_MB", 0))
    netflow_max_mb: int = field(default_factory=lambda: _int_env("NETFLOW_MAX_MB", 0))
    ml_max_mb: int = field(default_factory=lambda: _int_env("ML_MAX_MB", 0))

    # ------------------------------------------------------------------
    @property
    def http_url(self) -> str:
        return f"http://{self.clickhouse_host}:{self.clickhouse_port}"

    def validate(self) -> None:
        """Fail fast on obviously bad config (lesson: silent misconfig cost weeks)."""
        if not 0.0 < self.base_threshold <= 1.0:
            raise ValueError(f"BASE_THRESHOLD must be in (0, 1], got {self.base_threshold}")
        if not 0.0 < self.min_agreement <= 1.0:
            raise ValueError(f"MIN_AGREEMENT must be in (0, 1], got {self.min_agreement}")
        if not 0.0 < self.strong_signal <= 1.0:
            raise ValueError(f"STRONG_SIGNAL must be in (0, 1], got {self.strong_signal}")
        if self.ml_eligibility_multiple <= 0:
            raise ValueError(
                f"ML_ELIGIBILITY_MULTIPLE must be > 0, got {self.ml_eligibility_multiple}"
            )
        if self.episode_gap_minutes < 1:
            raise ValueError(
                f"EPISODE_GAP_MINUTES must be >= 1, got {self.episode_gap_minutes}"
            )
        if self.episode_lookback_h < 1:
            raise ValueError(
                f"EPISODE_LOOKBACK_H must be >= 1, got {self.episode_lookback_h}"
            )
        if self.episode_page_budget < 0:
            raise ValueError(
                f"EPISODE_PAGE_BUDGET must be >= 0, got {self.episode_page_budget}"
            )
        if self.episode_page_min_severity not in ("low", "medium", "high", "critical"):
            raise ValueError(
                "EPISODE_PAGE_MIN_SEVERITY must be low, medium, high or critical, got "
                f"{self.episode_page_min_severity!r}"
            )
        if self.ml_calibration_days < 1:
            raise ValueError(
                f"ML_CALIBRATION_DAYS must be >= 1, got {self.ml_calibration_days}"
            )
        if not 0.0 <= self.ml_min_feature_coverage <= 1.0:
            raise ValueError(
                "ML_MIN_FEATURE_COVERAGE must be between 0 and 1, got "
                f"{self.ml_min_feature_coverage}"
            )
        if self.ml_warmup_hours < 0:
            raise ValueError(
                f"ML_WARMUP_HOURS must be >= 0, got {self.ml_warmup_hours}"
            )
        if self.ml_warmup_min_windows < 1:
            raise ValueError(
                f"ML_WARMUP_MIN_WINDOWS must be >= 1, got {self.ml_warmup_min_windows}"
            )
        if self.ml_warmup_min_hosts < 1:
            raise ValueError(
                f"ML_WARMUP_MIN_HOSTS must be >= 1, got {self.ml_warmup_min_hosts}"
            )
        if self.detect_interval_s < 10:
            raise ValueError("DETECT_INTERVAL_S must be >= 10")
        if self.retrain_every_h < 1:
            raise ValueError("RETRAIN_EVERY_H must be >= 1")
        if self.role not in ("full", "gate"):
            raise ValueError(
                f"WEIRVERN_ROLE must be 'full' or 'gate', got {self.role!r}: a typo here would "
                "start the hub pipeline on a sensor box, or a gate with no detection behind it"
            )
        if self.pushover_enabled and (
            not self.pushover_user_key or not self.pushover_api_token
        ):
            raise ValueError(
                "PUSHOVER_ENABLED=1 requires PUSHOVER_USER_KEY and PUSHOVER_API_TOKEN"
            )

    # ------------------------------------------------------------------
    def model_path(self, kind: str) -> str:
        """Versioned artifact path. Lesson: v14 deployed while v19 sat on disk —
        versioned filenames + persisted state make the *running* version obvious."""
        return str(Path(self.model_dir) / f"{kind}_v1.pkl")


@dataclass(frozen=True)
class ModelConfig:
    """Hyper-parameters for the ensemble, versioned with the code."""

    contamination: float = 0.06
    if_n_samples: int = 80_000
    if_extremes: int = 5_000  # top-N extremes per metric to force into training
    dbscan_eps: float = 0.6
    dbscan_min_samples: int = 5
    dbscan_n_samples: int = 5_000
    # ── CROSS-SECTIONAL DETECTORS (kNN distance and LOF) ────────────────────────────────────────
    #
    # Both ask the same question of the same 19-column vector: does this host-window look unlike
    # the population of host-windows? They are SEPARATE detectors -- separate artifacts, reference
    # sets, calibrations and eligibility rows -- and these are the parameters the bake-off used,
    # not values searched here (`docs/research/cross-sectional-detector-2026-11-20.md` §3.4).
    #
    # `knn_k` = 10 and `lof_neighbors` = 20 are the report's values. `*_n_samples` is the ROW cap
    # on the reference (production's old dbscan_n_samples), applied with a deterministic
    # `ORDER BY sipHash64(src_addr, window_start) LIMIT n`; there is NO host sampling, because a
    # 1-in-5 host cut left 5 of 24 hosts and a cross-sectional model cannot work from five.
    knn_k: int = 10
    knn_n_samples: int = 5_000
    lof_neighbors: int = 20
    lof_n_samples: int = 5_000
    gb_max_samples: int = 50_000
    test_size: float = 0.2
    random_state: int = 42
    baseline_min_obs: int = 10

    # Ensemble weights — used only when fusion_mode == "mean" (legacy A/B mode).
    # "max" (default) ignores them; see fuse_scores() for why.
    weight_if: float = 1.0
    weight_gb: float = 0.75
    weight_dbscan: float = 0.65
    # THE TWO CROSS-SECTIONAL DETECTORS CARRY THE NEUTRAL WEIGHT, EXPLICITLY.
    #
    # The shipped fusion mode is "max", which does not read weights at all (see fuse_scores); these
    # exist so mean-mode A/B carries a stated number rather than an implicit 1.0 from the unknown-
    # name fallback. 1.0 is the neutral value on purpose: the bake-off measured these as NEW
    # independent evidence, and an unmeasured down-weight would rebalance the ensemble by accident
    # -- the exact failure the operator asked to avoid. If a future measurement says they deserve
    # less, that is a tuning change with its own before/after distribution.
    weight_knn: float = 1.0
    weight_lof: float = 1.0
    weight_baseline: float = 1.3   # when baseline exists
    weight_baseline_missing: float = 0.5

    # "max" = strongest-detector signal (default, recommended);
    # "mean" = legacy weighted average retained for comparison.
    fusion_mode: str = "max"

    # Statistically thin windows (few flows) have unreliable per-window
    # statistics; scores are damped proportionally (see
    # ensemble.detection_confidence_factor for the measured rationale).
    min_flows_for_full_confidence: int = 10
    # ── A MULTIPLIER FLOOR, NOT AN ABSOLUTE SCORE (audit F186) ──────────────────────────────────
    #
    # This shipped as 0.35 -- the same value as `base_threshold` -- which made the relationship
    # between the two invisible. They are different KINDS of number: this multiplies a score capped
    # at `ensemble.MAX_FUSED_SCORE` (0.99), while `base_threshold` is an absolute score the result
    # has to clear. So the reachable maximum for a thin window is 0.99 * this, and if that lands
    # under the bar the window is UNALERTABLE whatever the detectors report.
    #
    # 0.35 gave 0.99 * 0.35 = 0.3465 against a bar of 0.35 -- short by 0.0035. MEASURED: 23 of 23
    # live near misses scored exactly 0.3465 across six unrelated hosts, and 566 of 567 windows in a
    # 6-hour span (99.8%, carrying 99.98% of the bytes) were thin enough to be capped there.
    #
    # 0.36 is the smallest value that clears the bar with margin (0.99 * 0.36 = 0.3564) and it keeps
    # the measured false-positive case suppressed: a 3-flow window with a raw 0.96 still lands at
    # 0.3456, below the bar. `ensemble.assert_thin_floor_is_reachable` enforces the relationship at
    # runtime so these two cannot drift apart in silence again.
    thin_window_floor: float = 0.36

    # SOC-2: the near-miss band, as a FRACTION of the threshold this host faced. A window
    # scoring at or above threshold * this value (and below the threshold) is recorded as a
    # near miss rather than thrown away. 0.85 puts the floor at e.g. 0.60 against a 0.70
    # bar -- wide enough to see a host drifting up, narrow enough that ordinary traffic
    # does not fill the table. Setting it to 1.0 disables banding entirely (nothing is
    # strictly below and at/above the threshold).
    near_miss_band: float = 0.85

    # ── MISSING-DATA HANDLING (default OFF; see models/missing.py) ───────────────────────────
    # These mirror `Settings.ml_missing_features` / `ml_min_feature_coverage`; the worker
    # copies the operator's settings into this object so the detectors and the ensemble read
    # ONE authority. Left as plain defaults here so a test can construct a detector directly.
    missing_features: bool = False
    min_feature_coverage: float = 0.15

    # Structural port-scan signature (diversity metrics) — lets a lone strong
    # specialist escalate when the window itself is direct scan evidence.
    port_scan_min_ports: int = 50
    port_scan_min_entropy: float = 4.0

    # ── Agreement gate (see ensemble.detection_sweep) ────────────────────────
    # A detection whose fused score is high (>= 0.6) is allowed a lower agreement
    # bar, because its score already carries the evidence. This margin shapes that
    # relaxation. Both knobs are internal derivations rather than operator
    # tunables, which is why neither is in .env.example.
    #
    # A SUBTRACTIVE margin, not a multiplier: the original hardcoded pair was
    # exactly 0.33 (low score) and 0.25 (high score), i.e. a 0.08 offset. A
    # multiplier of 0.75 against the 0.33 default yields 0.2475, which would have
    # silently shifted every high-scoring detection's agreement bar by 0.0025 on
    # the default path. The offset reproduces the original exactly and still
    # tracks MIN_AGREEMENT upward.
    #
    # min_agreement_margin: subtracted from MIN_AGREEMENT for the high-score tier
    #   (0.08 with the default MIN_AGREEMENT of 0.33 gives exactly 0.25).
    # min_agreement_floor: the subtraction can never push the bar below this, so a
    #   badly chosen MIN_AGREEMENT cannot disable the gate entirely.
    #
    # AND THE SOLO FLOOR, the review round of 2026-10-15: the ensemble additionally never
    # admits ONE detector's share of the agreement (1/n) at any tier unless a lone strong
    # specialist is corroborated by a direct structural signature -- measured, the old
    # top-tier bar (0.25 with four detectors) sat exactly ON that share, so `agreement <
    # min_agreement` could never fire there and one detector's word alerted alone.
    # MIN_AGREEMENT governs ABOVE that floor; values at or below 1/n have no further effect.
    min_agreement_margin: float = 0.08
    min_agreement_floor: float = 0.20

    # ── Training hygiene: do not learn the attack ────────────────────────────
    # Detectors train on the last RETRAIN_WINDOW_H of traffic, which INCLUDES any
    # ongoing incident. Isolation Forest's contamination=0.06 expects ~6% of
    # training samples to be outliers, so a sustained attack lasting days becomes
    # part of the learned "normal" -- a model poisoned by the very traffic it is
    # supposed to catch, with no metric able to show it.
    #
    # With this enabled, host-windows ALREADY FLAGGED at high/critical severity
    # (in netflow_anomalies, over the same window) are excluded from the next
    # training pass. That is the minimum defence and a deliberate one: it uses
    # the system's own prior detections as evidence about which rows not to trust,
    # so it can only be as wrong as the detector that flagged them -- which is
    # strictly better than trusting everything unconditionally.
    #
    # NOT the full answer: a slow attack that never crosses the severity bar still
    # trains in, and a frozen benign-baseline model (champion/challenger, alerting
    # when the two disagree) is the stronger design recorded in the audit backlog.
    exclude_flagged_from_training: bool = True

    # Score normalization parameters
    z_activation_k: float = 0.4
    z_activation_shift: float = 2.5

    @property
    def weights(self) -> dict[str, float]:
        """Base weights keyed by detector name (baseline adjusted at runtime).

        `weight_baseline_missing` is deliberately NOT here: it is not a base weight, it is the
        baseline detector's weight in the case where NO baseline exists for the host, and only
        `ensemble.detection_sweep` knows which case applies. It is applied there, where
        `has_baseline` is known. Putting a value here would make the mapping look complete while
        the runtime branch silently overrode it for exactly the case the field names.
        """
        return {
            "isolation_forest": self.weight_if,
            "gradient_boosting": self.weight_gb,
            "dbscan": self.weight_dbscan,
            "knn": self.weight_knn,
            "lof": self.weight_lof,
            "adaptive_baseline": self.weight_baseline,
        }


def _load_env_file() -> None:
    """Load a local `.env` into os.environ, WITHOUT overriding real env vars.

    THE BUG THIS FIXES: `weirvern install` GENERATES `.env` from `.env.example`,
    and `config`/`tune` read and write it — but nothing ever loaded it into the
    environment, and every Settings field reads os.environ at construction. So
    `.env` had no effect on any runtime setting: editing CLICKHOUSE_USER or
    PUSHOVER_ENABLED appeared to work and silently did nothing.

    It surfaced on a live box where `.env` said CLICKHOUSE_USER=default while the
    cluster had been reconfigured to a named user, so `weirvern status` reported
    an authentication failure that the `.env` file made impossible to fix.

    Precedence: real environment variables WIN. That ordering matters in
    Kubernetes, where the ConfigMap and Secret are injected as environment
    variables and must not be shadowed by a stale `.env` that happened to be
    copied into the image. This only fills in values that are not already set.

    Deliberately no python-dotenv dependency: the format needed here is
    KEY=value with optional `export`, comments and surrounding quotes, which is a
    dozen lines and avoids adding a runtime dependency to the worker image.
    """
    import os
    from pathlib import Path

    candidates: list[Path] = []
    explicit = os.environ.get("WEIRVERN_ENV_FILE")
    if explicit:
        candidates.append(Path(explicit))
    else:
        # WEIRVERN_HOME, then the current directory. Both are checked because the
        # CLI is often run from the project root while the worker runs from an
        # installed package location.
        home = os.environ.get("WEIRVERN_HOME")
        if home:
            candidates.append(Path(home) / ".env")
        candidates.append(Path.cwd() / ".env")

    for path in candidates:
        try:
            text = path.read_text()
        except (FileNotFoundError, NotADirectoryError, PermissionError):
            continue
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.startswith("export "):
                line = line[len("export "):]
            key, _, value = line.partition("=")
            key = key.strip()
            if not key:
                continue
            # Strip an inline comment, but only when it follows whitespace, so a
            # value like `abc#def` is preserved. .env.example ships
            # `PUSHOVER_ENABLED=0             # 1 = real pushes`, which would
            # otherwise be parsed as a value with the comment attached.
            value = value.strip()
            for quote in ('"', "'"):
                if value.startswith(quote) and value.endswith(quote) and len(value) > 1:
                    value = value[1:-1]
                    break
            else:
                hash_idx = value.find(" #")
                if hash_idx != -1:
                    value = value[:hash_idx].rstrip()
            # Real environment wins -- see the docstring.
            os.environ.setdefault(key, value)
        return  # first readable file wins; do not merge several


def get_settings() -> Settings:
    """Validated settings singleton (call once; cheap enough to call per-test)."""
    _load_env_file()
    s = Settings()
    s.validate()
    return s
