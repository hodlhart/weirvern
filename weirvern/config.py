"""Weirvern configuration — environment-driven, validated at import time.

Lesson v14–v19: magic numbers were scattered through the detection script and
thresholds changed version over version. All knobs live here, overridable via
environment variables, documented in `.env.example`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


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

    # Data input (goflow2 JSONL sink)
    tail_file: str = field(default_factory=lambda: os.environ.get("TAIL_FILE", "/data/flows.jsonl"))

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
    gb_max_samples: int = 50_000
    test_size: float = 0.2
    random_state: int = 42
    baseline_min_obs: int = 10

    # Ensemble weights — used only when fusion_mode == "mean" (legacy A/B mode).
    # "max" (default) ignores them; see fuse_scores() for why.
    weight_if: float = 1.0
    weight_gb: float = 0.75
    weight_dbscan: float = 0.65
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
