"""Write the cluster's configuration, and read back what actually landed.

WHY THIS EXISTS. The CLI's config commands write the local `.env` file.
The cluster reads the `weirvern-env` ConfigMap. Nothing in `k8s/*.yaml` reads `.env` and the
Containerfile ships none, so `.env` writes have been a no-op against a deployed cluster
for as long as they have existed. This module replaces the broken path rather than porting it.

The read side already existed: `cli._cluster_config()`. This is the write side.

HOW THE WRITE REACHES THE CLUSTER. The GUI pod has no `kubectl` binary and no ServiceAccount
token (`automountServiceAccountToken: false`), so it cannot shell out. Options were: mount a
kubeconfig, ship kubectl, or call the Kubernetes API directly. The API is chosen because it is the
only one that needs no credential to be copied into the image and no binary to be added -- the
in-cluster token, once the ServiceAccount is granted, is enough.

EVERY WRITE IS VERIFIED BY READ-BACK. A successful HTTP PATCH is not evidence the ConfigMap
changed: the API server validates the REQUEST, not the resulting state, and a merge-patch that
matches nothing returns 200 with the original content. So after writing, this reads the ConfigMap
back and compares. A write that did not take is reported as a failure, because a config UI that
says "saved" over a change that did not land is worse than one that errors.
"""

from __future__ import annotations

import contextlib
import datetime
import json
import logging
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

NAMESPACE = "weirvern"
CONFIGMAP = "weirvern-env"

# ── GUI-WRITE PROVENANCE (audit F016) ────────────────────────────────────────────────────────────
#
# CONFIRMED BY RUNNING IT: a GUI write to this ConfigMap is undone by the next `kubectl apply -k`,
# because the ConfigMap is owned by a manifest and an apply is entitled to restore it. Measured: a
# GUI write of DETECT_INTERVAL_S=240 landed and even rolled the worker, and the next apply put it
# back to 300.
#
# The value of these two annotations is that the conflict becomes VISIBLE. Before them, a settings
# view could only show the current value, which looks identical whether an operator chose it or a
# deploy just overwrote their choice. With them, the view can say "you set this on the 23rd; a
# deploy may have reverted it", which is a thing an operator can act on.
GUI_WRITE_ANNOTATION = "weirvern.io/gui-written-keys"
GUI_WRITE_LEGEND = "weirvern.io/gui-written-keys-note"

# The paths the in-cluster client needs. Standard, and present in every pod that mounts a token.
_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"
_CA_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
_API_HOST = "https://kubernetes.default.svc"

# Keys a GUI session may change. AN ALLOW-LIST, not a deny-list: the ConfigMap holds the whole
# deployment's configuration, and an unknown key should be refused by default rather than
# permitted until someone remembers to forbid it.
#
# `SENSOR_MODE` is here because it was asked for, but see `apply_plan` -- it is treated specially
# because it is the one setting whose change touches live traffic.
EDITABLE_KEYS: tuple[str, ...] = (
    "BASE_THRESHOLD",
    "MIN_AGREEMENT",
    "STRONG_SIGNAL",
    "DETECT_INTERVAL_S",
    "RETRAIN_EVERY_H",
    "RETRAIN_WINDOW_H",
    "PUSHOVER_ENABLED",
    "PUSHOVER_COOLDOWN_S",
    "PUSHOVER_MAX_PER_HOUR",
    "ZEEK_IFACE",
    "ZEEK_IFACES",
    "CAPTURE_IFACE",
    "INTERFACE_NETWORKS",
    "MGMT_IFACE",
    "WEIRVERN_REVERSE_DNS",
    "INTERCEPT_TARGETS",
    "INTERCEPT_SEGMENT",
    "INTERCEPT_ADDR",
    "INTERCEPT_GATEWAY",
    "INTERCEPT_PLANS",
    "CHANNEL_UPSTREAM",
    "CHANNEL_DOWNSTREAM",
    # The channel's flow selection: whether the in-line traffic is summarised into NetFlow.
    "CHANNEL_NETFLOW",
    "SIPHON_NETFLOW",
    "NETFLOW_MODE",
    "NETFLOW_IFACE",
    # THE GATE'S OWN KEYS. The Sluice Gate is a product surface (its own tab, its own proof), and
    # operating it previously meant a ConfigMap patch and a worker restart -- the opposite of the
    # operator's standing request that everything be clickable. All five are read by the WORKER,
    # so each restarts it (see _RESTART_FOR), and the two numeric ones carry bounds here so the
    # control and the validator cannot disagree.
    "BLOCKLIST_SYNC_HOURS",
    "SLUICE_ENABLED",
    "SLUICE_BLOCK_DOMAINS",
    "SLUICE_IFACE",
    "SLUICE_CRITICALITY",
    "SLUICE_AUTO_SCORE",
    "SLUICE_MAX_BLOCK_S",
    "SLUICE_INTERVAL_S",
    "SENSOR_MODE",
    "WEIRVERN_EXCLUDE_CIDRS",
    "WEIRVERN_CAPTURE_EXCLUDE_CIDRS",
)

# ROW KEY -> CONFIGMAP KEY, for the entries where lower-casing is not enough.
#
# The GUI's settings rows are named after Settings attributes (exclude_cidrs), while the cluster's
# ConfigMap uses WEIRVERN_-prefixed names (WEIRVERN_EXCLUDE_CIDRS). Four keys differ by more than
# case, so a blanket .upper() cannot recover them -- and without this table those four rows would
# render read-only with no way to tell why.
ROW_TO_CONFIGMAP: dict[str, str] = {
    "exclude_cidrs": "WEIRVERN_EXCLUDE_CIDRS",
    "capture_exclude_cidrs": "WEIRVERN_CAPTURE_EXCLUDE_CIDRS",
    "reverse_dns": "WEIRVERN_REVERSE_DNS",
    # `strong_signal` has no settings ROW, because STRONG_SIGNAL is a constant in the detector
    # rather than a Settings attribute. Mapped anyway so an apply of that name validates instead
    # of being rejected as uneditable.
    "strong_signal": "STRONG_SIGNAL",
}


def apply_semantics(key: str) -> str:
    """How a change to this key takes effect, in one sentence for the settings row's badge.

    DERIVED FROM _RESTART_FOR, never hand-written: the badge and the apply path read the SAME
    table, so a row can never promise "no restart" while the writer restarts something (BF-5;
    research: pfSense's runtime-vs-boot tunables -- the one place OPNsense states this, and the
    alternative is a documented trap). Every row applies WITH APPLY -- this console has no
    live-on-save settings; what differs is what the apply restarts."""
    _targets, blast = _RESTART_FOR.get(str(key).strip().upper(), ((), ""))
    return "applies with Apply \u2014 " + blast if blast else "applies with Apply"


def to_configmap_key(row_key: str) -> str:
    """The ConfigMap key an apply would write for a settings row key."""
    k = (row_key or "").strip()
    return ROW_TO_CONFIGMAP.get(k.lower(), k.upper())


def to_row_key(configmap_key: str) -> str:
    """The settings row key that edits a given ConfigMap key (the inverse of the above)."""
    k = (configmap_key or "").strip()
    for row, cm in ROW_TO_CONFIGMAP.items():
        if cm == k:
            return row
    return k.lower()


# Which workloads must restart for a key to take effect. A ConfigMap env var is read at process
# start, so a change is inert until the reader restarts -- and WHICH reader matters: restarting
# the worker for a Zeek interface change does nothing, and the operator would be told it applied.
#
# A KEY CAN NEED MORE THAN ONE RESTART, so each entry is a TUPLE of targets. The siphon keys
# are the reason: SENSOR_MODE must reach the capture DaemonSet (which states the mode and, in
# the siphon overlay, runs the sysctl init container) AND the worker (which supervises the
# intercept -- see admin/siphon_supervisor.py). Restarting only one of the two was the WEIR-1
# shape: the config said "siphon" while nothing in the cluster ran an intercept.
#
# "zeek" is the capture DaemonSet, which is the one that touches the wire. Restarting it has a
# brief capture gap, which is why the UI states it before applying.
_RESTART_FOR: dict[str, tuple[tuple[str, ...], str]] = {
    "SENSOR_MODE": (("ds/zeek", "deploy/weirvern-worker"),
                    "restarts the capture sensor (brief capture gap) and the worker, which "
                    "starts or stops the supervised intercept"),
    "ZEEK_IFACE": (("ds/zeek", "deploy/weirvern-worker"),
                   "restarts the capture sensor (brief capture gap) and the worker, whose "
                   "intercept relays on this interface"),
    "ZEEK_IFACES": (("ds/zeek",), "restarts the capture sensor (brief capture gap)"),
    "CAPTURE_IFACE": (("ds/zeek", "deploy/weirvern-worker"),
                      "restarts the capture sensor (its forwarding init uses this port) and "
                      "the worker, whose intercept relays on this interface"),
    "INTERFACE_NETWORKS": (("deploy/weirvern-gui",), "restarts the console so anomaly locations "
                            "re-read the interface names"),
    "MGMT_IFACE": (("ds/zeek",), "restarts the capture sensor (brief capture gap)"),
    # The LEGACY intercept fields are read by the WORKER's supervisor, not by the sensor, so
    # restarting ds/zeek for them applied nothing. INTERCEPT_PLANS is different in one respect:
    # the siphon forwarding init ALSO reads it (to open the path on every siphon NIC), so a plan
    # change must restart the sensor as well as the worker.
    "INTERCEPT_TARGETS": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "INTERCEPT_SEGMENT": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "INTERCEPT_ADDR": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "INTERCEPT_GATEWAY": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "INTERCEPT_PLANS": (("ds/zeek", "deploy/weirvern-worker"),
                        "restarts the capture sensor (its forwarding init opens every siphon "
                        "NIC in the plan) and the worker, which supervises one intercept per "
                        "interface"),
    # The channel keys are read by the WORKER (it verifies the wiring from the kernel and
    # enforces on the bridge); the capture sensor only ever sees the bridge through ZEEK_IFACE.
    "CHANNEL_UPSTREAM": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "CHANNEL_DOWNSTREAM": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "SIPHON_NETFLOW": (("deploy/weirvern-worker",), "restarts the detection worker, which "
                       "runs the flow probe"),
    "NETFLOW_MODE": (("deploy/weirvern-worker",), "restarts the detection worker, which "
                      "starts or stops sensor-generated flow capture"),
    "NETFLOW_IFACE": (("deploy/weirvern-worker",), "restarts the detection worker, which "
                       "samples this port for active flow capture"),
    "CHANNEL_NETFLOW": (("deploy/weirvern-worker",), "restarts the detection worker, which "
                        "starts or stops the flow probe"),
    # The sluice keys are read by the WORKER: it resolves the enforcement interface, compiles the
    # rules and runs the pass. Restarting it also re-establishes the kernel state immediately
    # rather than waiting for the gate's own interval.
    "SLUICE_ENABLED": (("deploy/weirvern-worker",), "restarts the detection worker, which disarms "
                       "or compiles the gate immediately"),
    "SLUICE_BLOCK_DOMAINS": (("deploy/weirvern-worker",), "restarts the detection worker, which "
                             "recompiles the gate without (or with) its domain sets"),
    "BLOCKLIST_SYNC_HOURS": (("deploy/weirvern-worker",), "restarts the detection worker, which "
                             "re-reads the blocklist sync cadence"),
    "SLUICE_IFACE": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "SLUICE_CRITICALITY": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "SLUICE_AUTO_SCORE": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "SLUICE_MAX_BLOCK_S": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "SLUICE_INTERVAL_S": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "BASE_THRESHOLD": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "MIN_AGREEMENT": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "STRONG_SIGNAL": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "DETECT_INTERVAL_S": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "RETRAIN_EVERY_H": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "RETRAIN_WINDOW_H": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "PUSHOVER_ENABLED": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "PUSHOVER_COOLDOWN_S": (("deploy/weirvern-worker",), "restarts the detection worker"),
    "PUSHOVER_MAX_PER_HOUR": (("deploy/weirvern-worker",), "restarts the detection worker"),
    # REVERSE DNS IS READ BY THE GUI, NOT THE WORKER. `revdns.lookup` runs inside the GUI
    # process (`web_api._hostname` resolves every displayed address); the worker never imports
    # it. The earlier mapping restarted the worker -- measured live: after setting 'all' the
    # ConfigMap held it, the WORKER saw 'all', and the GUI pod still answered 'private',
    # because nothing restarted the process that does the lookups. The change was inert in
    # exactly the place the tabs need it.
    "WEIRVERN_REVERSE_DNS": (("deploy/weirvern-gui",),
                             "restarts the web UI (it resolves the names the views display)"),
    # The worker installs the ingest filter at startup; Zeek reads the capture list at
    # startup too, so BOTH restart for a change to either to take effect.
    "WEIRVERN_EXCLUDE_CIDRS": (("deploy/weirvern-worker",),
                               "restarts the detection worker"),
    "WEIRVERN_CAPTURE_EXCLUDE_CIDRS": (("ds/zeek",),
                                       "restarts the capture sensor (brief capture gap)"),
}


class ConfigError(Exception):
    """A write that could not be performed, or was performed and did not take.

    A plain Exception, NOT a dataclass: `@dataclass` on an Exception subclass generates an
    `__init__(self)` taking no arguments, so every `raise ConfigError("why")` would fail with
    "Expected 0 positional arguments" -- at the moment it tries to report a problem.
    """


class NotFoundError(ConfigError):
    """The ConfigMap does not exist. Distinct from other failures ON PURPOSE.

    The account store is created on first startup rather than shipped as a manifest, so
    "this ConfigMap is not there yet" is a normal state that means "go ahead and create it".
    Every other read failure means "you cannot see the state", and treating those the same
    would let a transient failure overwrite live accounts with a fresh document.
    """


@dataclass
class Proposal:
    """One proposed change, with what it will cost."""

    key: str
    current: str
    proposed: str
    restarts: tuple[str, ...] = ()
    blast: str = ""
    warning: str = ""


@dataclass
class Plan:
    """What a set of changes would do, computed WITHOUT touching anything.

    The UI shows this and asks for confirmation, so the blast radius is stated before the change
    rather than discovered after.
    """

    proposals: list[Proposal] = field(default_factory=list)
    rejected: list[tuple[str, str]] = field(default_factory=list)

    @property
    def restart_targets(self) -> list[str]:
        out: list[str] = []
        for p in self.proposals:
            for target in p.restarts:
                if target and target not in out:
                    out.append(target)
        return out


# Values that would make the sensor dangerous or useless, with the reason. A config UI is a new
# way to reach a setting that previously required reading the docs, so the check that the docs
# provided has to live here instead.
_GUARDS: dict[str, tuple[str, ...]] = {
    "RETRAIN_EVERY_H": ("detection falls behind a changing traffic mix",),
    "DETECT_INTERVAL_S": ("alerts are delayed by up to this interval",),
}

# NUMERIC bounds for every editable numeric key: (low, high, what, step). `validate()` enforces
# the bounds; the Settings tab uses `step` for its number inputs. ONE definition, so the control
# the operator manipulates and the rule the write path enforces cannot disagree.
NUMERIC_RANGES: dict[str, tuple[float, float, str, float]] = {
    "BASE_THRESHOLD": (0.0, 1.0, "a score fraction", 0.01),
    "MIN_AGREEMENT": (0.0, 1.0, "a fraction of models", 0.01),
    "STRONG_SIGNAL": (0.0, 1.0, "a score fraction", 0.01),
    "DETECT_INTERVAL_S": (30, 86400, "seconds", 1),
    "RETRAIN_EVERY_H": (1, 720, "hours", 1),
    "RETRAIN_WINDOW_H": (1, 8760, "hours", 1),
    "PUSHOVER_COOLDOWN_S": (0, 86400, "seconds", 1),
    "PUSHOVER_MAX_PER_HOUR": (0, 1000, "alerts per hour", 1),
    # A block may last an hour by default and a week at most -- the same ceiling the Sluice tab's
    # own rule form offers (10080 minutes). The re-check interval may not go below 5s (the pass
    # would hammer the rule store) nor above an hour (rules would expire unnoticed for that long).
    "BLOCKLIST_SYNC_HOURS": (1, 168, "hours", 1),
    "SLUICE_MAX_BLOCK_S": (60, 604800, "seconds", 60),
    "SLUICE_INTERVAL_S": (5, 3600, "seconds", 5),
    # 0 disables the threshold entirely (the default); anything above it blocks detections at
    # or above that fused score. The step is 0.05 -- finer than the ensemble's own confidence
    # granularity, and coarse enough that the control does not invite false precision.
    "SLUICE_AUTO_SCORE": (0.0, 1.0, "a score fraction (0 disables)", 0.05),
}

# HOW THE SETTINGS TAB RENDERS EACH EDITABLE KEY: its natural control, so an operator CHOOSES a
# value instead of typing one and cannot type a value the write path will reject.
#
# EVERY editable key has an explicit entry, ON PURPOSE (a test enforces it): without one, a new
# editable key would silently fall back to a raw text box -- which is the "setup should be easy"
# failure this registry exists to remove. `text` is a deliberate choice for the genuinely
# free-text keys (interface names, addresses, CIDR lists), not a fallback.
SETTING_CONTROLS: dict[str, dict] = {
    **{k: {"control": "number", "min": lo, "max": hi, "step": step, "unit": what}
       for k, (lo, hi, what, step) in NUMERIC_RANGES.items()},
    "PUSHOVER_ENABLED": {"control": "toggle"},
    "SENSOR_MODE": {"control": "select", "options": ["loch", "siphon"]},
    "WEIRVERN_REVERSE_DNS": {"control": "select", "options": ["private", "all", "off"]},
    "ZEEK_IFACE": {"control": "text"},
    "ZEEK_IFACES": {"control": "text"},
    "CAPTURE_IFACE": {"control": "text"},
    "INTERFACE_NETWORKS": {"control": "text"},
    "MGMT_IFACE": {"control": "text"},
    "INTERCEPT_TARGETS": {"control": "text"},
    "INTERCEPT_SEGMENT": {"control": "text"},
    "INTERCEPT_ADDR": {"control": "text"},
    "INTERCEPT_GATEWAY": {"control": "text"},
    "INTERCEPT_PLANS": {"control": "text"},
    "CHANNEL_UPSTREAM": {"control": "text"},
    "CHANNEL_DOWNSTREAM": {"control": "text"},
    # A CHECKBOX, NOT A THREE-WAY SELECT (operator, 2026-10-17: "I need a check box for
    # enabling netflow"). The fine print -- which port the probe samples -- is a distinction
    # without a difference (either port sees every frame crossing the box); off/on is the
    # real decision. The staged values stay in the validator's vocabulary ("upstream"/"off"),
    # so nothing downstream learns a new spelling.
    "CHANNEL_NETFLOW": {"control": "toggle", "on_value": "upstream", "off_value": "off"},
    "SLUICE_ENABLED": {"control": "toggle"},
    # Step is part of the spec (browsers round float inputs without one); bounds mirror
    # NUMERIC_RANGES, which the validator enforces -- a control that can offer a value the
    # server refuses is a trap.
    "BLOCKLIST_SYNC_HOURS": {"control": "number", "step": 1, "min": 1, "max": 168},
    # The domain-rule half of the gate: off, blocking domain rules record and alert only.
    "SLUICE_BLOCK_DOMAINS": {"control": "toggle"},
    # A switch, and only meaningful in siphon mode: it turns the intercept itself into a flow
    # source (see the tooltip for the one-path rule).
    "SIPHON_NETFLOW": {"control": "toggle"},
    "NETFLOW_MODE": {"control": "select", "options": ["auto", "passive", "active"]},
    "NETFLOW_IFACE": {"control": "text"},
    # Empty resolves automatically (channel bridge, else capture port), so it stays free text --
    # a closed set of interface names does not exist across deployments.
    "SLUICE_IFACE": {"control": "text"},
    "SLUICE_CRITICALITY": {"control": "select",
                           "options": ["off", "high", "medium", "strict"]},
    # NOTE: SLUICE_AUTO_SCORE has no entry here ON PURPOSE. It is in NUMERIC_RANGES, and that
    # table is expanded into `{control: number, min, max, step, unit}` just below -- an explicit
    # `{"control": "number"}` would OVERRIDE the generated spec and drop the step (floats then
    # round to integers in some browsers) and the bounds the UI relies on.
    "WEIRVERN_EXCLUDE_CIDRS": {"control": "text"},
    "WEIRVERN_CAPTURE_EXCLUDE_CIDRS": {"control": "text"},
}


def validate(key: str, value: str) -> str:
    """Check one proposed value, returning a warning ("" when there is nothing to say).

    Raises ConfigError for a value that cannot be accepted at all. The distinction matters: a
    warning is shown and may be confirmed, a rejection cannot be.
    """
    from weirvern.admin import mode as mode_mod

    key = key.strip().upper()
    raw = (value or "").strip()

    if key not in EDITABLE_KEYS:
        raise ConfigError(
            f"'{key}' is not editable from the GUI. Editable keys are: "
            f"{', '.join(sorted(EDITABLE_KEYS))}"
        )

    if key == "SENSOR_MODE":
        normalised = mode_mod.normalise(raw)
        if normalised not in ("loch", "siphon"):
            raise ConfigError(f"'{raw}' is not a sensor mode; expected 'loch' or 'siphon'")
        return ("in-path interception puts this host in the traffic path. Enabling it without "
                "forwarding working takes the segment down — the mode gate is checked at apply.")

    if key in ("CHANNEL_UPSTREAM", "CHANNEL_DOWNSTREAM"):
        # The two ends of a channel must be DIFFERENT ports; everything else about the wiring
        # (bridge membership, carrier, bridge-nf) is reported from the kernel by the gate itself
        # (admin/channel.py), so this refuses only the value that can never be right.
        import os as _os  # noqa: PLC0415

        other = "CHANNEL_DOWNSTREAM" if key == "CHANNEL_UPSTREAM" else "CHANNEL_UPSTREAM"
        if raw and raw == (_os.environ.get(other) or "").strip():
            raise ConfigError(
                f"{key}={raw} names the same port as {other}; the two ends of a channel must "
                f"be different interfaces."
            )
        if raw == "lo":
            raise ConfigError("'lo' is the loopback interface; a channel needs two real ports.")
        return (
            "a channel needs BOTH ports set (CHANNEL_UPSTREAM and CHANNEL_DOWNSTREAM); until "
            "they are, the channel stays inactive and the Sluice Gate keeps reporting why. "
            "Wire the two ports in line, join them into one bridge, and keep bridge-nf enabled."
        )

    if key == "CHANNEL_NETFLOW":
        if raw.lower() not in ("off", "upstream", "downstream", ""):
            raise ConfigError(
                f"{key} must be off, upstream or downstream; got '{raw}'. The value names which "
                f"channel port the flow probe samples; either port sees every frame crossing "
                f"the box, so one is enough."
            )
        if raw.lower() not in ("off", ""):
            return ("the probe records only while the channel is verified active, and its "
                    "records land in the same Netflow tab and model features as the router's "
                    "export -- the box's own crossing traffic, summarised.")
        return ""

    if key == "NETFLOW_MODE":
        wanted = raw.lower()
        if wanted not in ("auto", "passive", "active"):
            raise ConfigError(
                f"NETFLOW_MODE must be auto, passive or active; got '{raw}'. Passive leaves "
                f"collection to a router exporter; active makes this sensor summarise its own "
                f"capture."
            )
        return ""

    if key == "NETFLOW_IFACE":
        if raw and not raw.startswith(("eth", "en", "bond", "wl")):
            return f"'{raw}' does not look like a network interface name"
        return ""

    if key == "ZEEK_IFACE" or key == "MGMT_IFACE":
        if raw and raw == _other_iface(key):
            # Measured fact: pointing the capture interface at the management port produces a
            # capture full of broadcast noise that LOOKS like a busy network, and Zeek's own logs
            # stay healthy. It is the single most expensive misconfiguration available here.
            raise ConfigError(
                f"{key}={raw} is the same interface as the other role. A sensor must not capture "
                f"on its management interface: the capture fills with broadcast noise and reads "
                f"as a busy network."
            )
        if raw and not raw.startswith(("eth", "en", "bond", "wl")):
            return f"'{raw}' does not look like a network interface name"
        return ""

    numeric = NUMERIC_RANGES
    if key in numeric:
        lo, hi, what, _step = numeric[key]
        try:
            number = float(raw)
        except ValueError:
            raise ConfigError(f"{key} must be a number ({what}), not '{raw}'") from None
        if number < lo or number > hi:
            raise ConfigError(f"{key} must be between {lo} and {hi} ({what}); got {raw}")
        if key in ("RETRAIN_EVERY_H", "RETRAIN_WINDOW_H") and number < 1:
            return "a sub-hour retrain interval will keep the detectors permanently busy"
        if key == "SLUICE_INTERVAL_S" and number < 15:
            return ("a re-check interval under 15s reads the rule store that often; 30-60s is "
                    "usually enough to make a filed block feel immediate")
        if key == "SLUICE_AUTO_SCORE" and number > 0:
            return ("any detection scoring at or above this value is BLOCKED on the sensor's "
                    "gate for up to SLUICE_MAX_BLOCK_S, while the gate is enabled and a "
                    "verified enforcement path is live. Start high (0.9) and watch the rules "
                    "the gate files before lowering it; 0 turns it off.")
        return ""

    if key in ("PUSHOVER_ENABLED", "SLUICE_ENABLED"):
        if raw.lower() not in ("true", "false", "1", "0", "yes", "no", ""):
            raise ConfigError(f"{key} must be true or false, not '{raw}'")
        if key == "SIPHON_NETFLOW" and raw.lower() in ("true", "1", "yes"):
            return ("the sensor's own interface is metered while a siphon intercept is VERIFIED "
                    "live, and the records land in the same `flows` table the channel and any "
                    "exporter feed. It never runs on a configured-but-dead intercept, it yields to "
                    "CHANNEL_NETFLOW on a box doing both -- two taps would count every "
                    "conversation twice -- and it costs nothing while no intercept is up.")
        if key == "SLUICE_ENABLED" and raw.lower() in ("true", "1", "yes"):
            return ("while this is on, live block rules are compiled into the kernel on the "
                    "sensor. Every rule is TTL-bounded and the gate fails OPEN; turning this off "
                    "disarms it and removes any table a previous run left behind.")
        return ""

    if key == "SLUICE_IFACE":
        import os as _os  # noqa: PLC0415

        if raw and raw == (_os.environ.get("MGMT_IFACE") or "").strip():
            raise ConfigError(
                f"{key}={raw} is the management interface. The gate refuses to arm there -- "
                f"blocking on the management path would cut off SSH and the cluster API -- so "
                f"this would be accepted, restarted for, and then refused where nobody sees it."
            )
        return ("empty (the default) resolves automatically: the channel's bridge when one is "
                "verified active, otherwise the capture interface.")

    if key == "SLUICE_CRITICALITY":
        from weirvern.sluice import CRITICALITY_POLICIES  # noqa: PLC0415

        if raw.lower() not in CRITICALITY_POLICIES:
            raise ConfigError(
                f"{key} must be one of {', '.join(sorted(CRITICALITY_POLICIES))}; got '{raw}'. "
                f"The policy decides which of the ensemble's own detections may block."
            )
        if raw.lower() != "off":
            return ("detections matching this policy will BLOCK the offending address on the "
                    "sensor for the policy's own TTL (15-30 minutes), only while the gate is "
                    "enabled. Weaker detections are refused by the policy's own floors.")
        return ""

    if key in ("WEIRVERN_EXCLUDE_CIDRS", "WEIRVERN_CAPTURE_EXCLUDE_CIDRS"):
        # VALIDATED HERE, at the point of write, using the SAME parser the ingester uses. A value
        # that reaches the worker and fails to parse does not degrade gracefully: the worker
        # REFUSES TO START, so a typo in this field is an outage rather than a no-op. Catching it
        # before it is written is the difference between a refused form and a dead sensor.
        from weirvern import exclude as exclude_mod

        try:
            nets = exclude_mod.parse_cidrs(raw)
        except ValueError as exc:
            raise ConfigError(str(exc)) from None
        if key == "WEIRVERN_CAPTURE_EXCLUDE_CIDRS":
            v6 = [n for n in nets if n.version != 4]
            if v6:
                raise ConfigError(
                    f"the capture filter does not support IPv6 ({', '.join(str(n) for n in v6)}). "
                    f"A v4-shaped BPF term for a v6 network matches nothing and yields an "
                    f"empty-but-healthy capture. Use {exclude_mod.EXCLUDE_ENV} for IPv6."
                )
            if nets:
                # Stated before it is applied, because this one cannot be undone for traffic that
                # has already passed.
                return ("dropped at the capture socket: Zeek will not record this traffic at all, "
                        "so it cannot be reviewed later. Use the ingest list if you may want the "
                        "evidence.")
            return ""
        if nets:
            return (f"{len(nets)} network(s) excluded from learning. The traffic still reaches the "
                    f"sensor and is counted, not stored — use the capture list for traffic that "
                    f"should never be recorded.")
        return ""

    if key == "WEIRVERN_REVERSE_DNS":
        if raw.lower() not in ("private", "all", "off", ""):
            raise ConfigError(
                f"{key} must be private, all or off; got '{raw}'. 'all' resolves PUBLIC addresses "
                f"too, which sends every destination this sensor sees to a DNS resolver — that is "
                f"derived traffic intelligence leaving the network, so it is explicit."
            )
        if raw.lower() == "all":
            return ("'all' resolves public addresses, which sends every external destination in "
                    "your flow data to a DNS resolver. That leaks what this network talks to.")
        return ""

    _ = _GUARDS.get(key)
    return ""


def _other_iface(key: str) -> str:
    """The value of the OTHER interface role, read from the environment.

    Read live rather than passed in, so the check cannot be defeated by a caller that supplies a
    stale pair -- the GUI sends one key at a time and would otherwise never know the other's value.
    """
    import os

    return os.environ.get("MGMT_IFACE" if key == "ZEEK_IFACE" else "ZEEK_IFACE", "") or ""


def receipt_items(changes: dict[str, str], landed: dict[str, str] | None,
                  after: dict[str, str] | None = None, error: str = "") -> list[dict]:
    """The per-item receipt for a settings write: one record per requested key.

    WHY PER ITEM. The apply response used to say only "saved" -- one batch result for what was
    really N separate intentions. When a write half-landed, the operator could not tell WHICH
    value failed or why; the staged-settings research names exactly this (a result that cannot
    be audited) as a reason operators stop trusting Apply buttons. One record per key, each
    carrying the value, the verdict and (on failure) the reason.

    WHOSE VERDICT. `ok` is NOT "the call returned" -- it is what a READ-BACK shows: the value
    in `after` (a fresh read, used on the refusal path) or in `landed` (the apply's own
    read-back result). No read-back source at all -> not ok, never assumed.
    """
    items: list[dict] = []
    for key, value in changes.items():
        want = (value or "").strip()
        source = after if after is not None else landed
        got = None if source is None else source.get(to_configmap_key(key), "")
        ok = source is not None and got == want
        items.append({
            "key": key,
            "value": want,
            "ok": ok,
            "error": "" if ok else (error or "the read-back does not show this value"),
        })
    return items


def plan(changes: dict[str, str], current: dict[str, str]) -> Plan:
    """Compute what a set of changes would do. Touches nothing.

    Raises ConfigError if any single change is unacceptable, so a multi-key apply is all-or-nothing
    -- a partial apply would leave the deployment in a state nobody chose.
    """
    out = Plan()
    for key, value in changes.items():
        # A ROW key arrives here from the GUI (exclude_cidrs); the ConfigMap and validate() speak
        # CONFIGMAP keys (WEIRVERN_EXCLUDE_CIDRS). Translate at the boundary, because four keys
        # differ by more than case and validate() rejects anything not in EDITABLE_KEYS.
        key = to_configmap_key(key)
        warning = validate(key, value)
        was = current.get(key, "")
        targets: tuple[str, ...]
        targets, blast = _RESTART_FOR.get(key, ((), ""))
        out.proposals.append(Proposal(
            key=key,
            current=was,
            proposed=(value or "").strip(),
            restarts=tuple(targets),
            blast=blast,
            warning=warning,
        ))
    return out


# -- the cluster client -------------------------------------------------------------------


class ClusterConfig:
    """Reads and writes the ConfigMap over the Kubernetes API, in-cluster.

    Uses the mounted ServiceAccount token rather than shelling out to kubectl: the GUI image has
    no kubectl, and adding one to a container that only needs to serve HTTP is a larger change
    than calling the API it would call anyway.
    """

    def __init__(self, namespace: str = NAMESPACE, configmap: str = CONFIGMAP,
                 token_path: str = _TOKEN_PATH, ca_path: str = _CA_PATH,
                 api_host: str = _API_HOST, timeout: int = 20) -> None:
        self.namespace = namespace
        self.configmap = configmap
        self.token_path = token_path
        self.ca_path = ca_path
        self.api_host = api_host
        self.timeout = timeout

    # -- credentials --------------------------------------------------------

    def token(self) -> str:
        try:
            with open(self.token_path, encoding="utf-8") as fh:
                return fh.read().strip()
        except OSError as exc:
            raise ConfigError(
                f"no ServiceAccount token at {self.token_path}. The GUI pod needs "
                f"serviceAccountName: weirvern-operator and a mounted token to change the "
                f"configuration."
            ) from exc

    def _ssl_context(self) -> ssl.SSLContext | None:
        import os

        if os.path.exists(self.ca_path):
            return ssl.create_default_context(cafile=self.ca_path)
        return None

    def _request(self, method: str, body: dict | None = None) -> dict:
        url = (f"{self.api_host}/api/v1/namespaces/{self.namespace}"
               f"/configmaps/{self.configmap}")
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token()}")
        req.add_header("Accept", "application/json")
        if data is not None:
            # A merge patch is the right type here: it changes only the keys sent, so a concurrent
            # edit to another key is not clobbered. A JSON patch would need the full document and
            # an update PUT replaces every field.
            req.add_header("Content-Type", "application/merge-patch+json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=self._ssl_context()) as resp:
                raw = resp.read().decode()
        except urllib.error.HTTPError as exc:
            detail = ""
            with contextlib.suppress(Exception):
                detail = exc.read().decode()[:400]
            if exc.code == 404:
                raise NotFoundError(
                    f"{self.configmap!r} does not exist in {self.namespace}"
                ) from exc
            if exc.code == 403:
                raise ConfigError(
                    f"the cluster refused the write (403). The GUI's ServiceAccount needs "
                    f"patch permission on configmaps in {self.namespace}."
                ) from exc
            raise ConfigError(f"the cluster rejected the request ({exc.code}): {detail}") from exc
        except urllib.error.URLError as exc:
            raise ConfigError(f"could not reach the cluster API: {exc.reason}") from exc
        try:
            return json.loads(raw) if raw else {}
        except ValueError:
            raise ConfigError("the cluster returned something that is not JSON") from None

    # -- read ---------------------------------------------------------------

    def read(self) -> dict[str, str]:
        """The ConfigMap's data, as a flat dict. {} when unreadable."""
        return dict(self._request("GET").get("data") or {})

    # -- write --------------------------------------------------------------

    def patch_data(self, data: dict[str, str]) -> None:
        """Merge-patch `data` keys into this ConfigMap, WITHOUT the read-back `apply` does.

        Used by the account store, which reloads its own in-memory cache from what it wrote
        and needs the merge semantics (`apply` is for the settings ConfigMap, where the
        read-back is the point). Same credential, same URL: `self.configmap` is whatever this
        client was constructed for.
        """
        self._request("PATCH", {"data": data})

    def get_json(self, path: str) -> dict:
        """GET one in-cluster API path with this client's credentials.

        NOT the ConfigMap read: this exists for the reads the deployment performs about
        ITSELF -- currently the sensor-capability probe, which must see the DaemonSet's
        real capabilities rather than this process's. Same token, same CA, same host;
        only the path differs. Raises ConfigError on any failure, so callers that gate on
        the answer can treat an error as "unknown".
        """
        return self.api_json("GET", path)

    def api_json(self, method: str, path: str, body: dict | None = None) -> dict:
        """One JSON API call against `path`, with this client's credentials.

        THE READ/WRITE TRANSPORT FOR EVERYTHING THAT IS NOT THE SETTINGS CONFIGMAP. The
        Sonar survey job is created, polled and deleted through this (jobs are RBAC the
        operator Role already grants); the sensor-capability probe reads through it too.
        A 404 raises NotFoundError and a 403 raises ConfigError with the permission named,
        because both are operator-fixable and a bare "HTTP error" is not.
        """
        url = f"{self.api_host}{path}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", f"Bearer {self.token()}")
        req.add_header("Accept", "application/json")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=self._ssl_context()) as resp:
                raw = resp.read().decode()
        except urllib.error.HTTPError as exc:
            detail = ""
            with contextlib.suppress(Exception):
                detail = exc.read().decode()[:300]
            if exc.code == 404:
                raise NotFoundError(f"{path!r} was not found in {self.namespace}") from exc
            if exc.code == 403:
                raise ConfigError(
                    f"the cluster refused {method} {path} (403). The GUI's ServiceAccount "
                    f"lacks the permission this operation needs in {self.namespace}."
                ) from exc
            raise ConfigError(
                f"the cluster rejected {method} {path} ({exc.code}): {detail}") from exc
        except urllib.error.URLError as exc:
            raise ConfigError(f"could not reach the cluster API: {exc.reason}") from exc
        try:
            return json.loads(raw) if raw else {}
        except ValueError:
            raise ConfigError("the cluster returned something that is not JSON") from None

    def api_text(self, method: str, path: str) -> str:
        """One API call whose response is plain text (a pod log). Raises ConfigError."""
        url = f"{self.api_host}{path}"
        req = urllib.request.Request(url, method=method)
        req.add_header("Authorization", f"Bearer {self.token()}")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=self._ssl_context()) as resp:
                return resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            detail = ""
            with contextlib.suppress(Exception):
                detail = exc.read().decode()[:300]
            raise ConfigError(
                f"the cluster rejected {method} {path} ({exc.code}): {detail}") from exc
        except urllib.error.URLError as exc:
            raise ConfigError(f"could not reach the cluster API: {exc.reason}") from exc

    def create(self, data: dict[str, str]) -> None:
        """Create this ConfigMap. Raises ConfigError when it already exists.

        THE FIRST WRITE TO A NAMESPACE THAT HAS NONE. The account store is created by the GUI
        on first startup rather than shipped as a manifest: a placeholder manifest would be
        re-applied with empty values on every `kubectl apply -k`, silently wiping live
        accounts -- the same failure mode the Secret has a note about in kustomization.yaml.
        """
        url = f"{self.api_host}/api/v1/namespaces/{self.namespace}/configmaps"
        body = json.dumps({
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": self.configmap, "namespace": self.namespace},
            "data": data,
        }).encode()
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Authorization", f"Bearer {self.token()}")
        req.add_header("Accept", "application/json")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=self._ssl_context()):
                return
        except urllib.error.HTTPError as exc:
            detail = ""
            with contextlib.suppress(Exception):
                detail = exc.read().decode()[:300]
            if exc.code == 409:
                raise ConfigError(f"the ConfigMap {self.configmap!r} already exists") from exc
            if exc.code == 403:
                raise ConfigError(
                    f"the cluster refused creating {self.configmap!r} (403). The GUI's "
                    f"ServiceAccount needs create permission on configmaps in {self.namespace}."
                ) from exc
            raise ConfigError(
                f"the cluster rejected creating {self.configmap!r} ({exc.code}): {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            raise ConfigError(f"could not reach the cluster API: {exc.reason}") from exc

    def apply(self, changes: dict[str, str], *, reason: str = "",
              by: str = "") -> dict[str, str]:
        """Merge the changes in, then READ BACK and prove they landed.

        BF-9: `reason`/`by` ride into the per-key provenance record when given -- the write
        trail answers who changed this and why, next to the value and the time.

        THE READ-BACK IS THE POINT. A merge-patch that matches nothing returns 200 with the
        original content, so a successful call is not evidence the configuration changed. This
        compares the result against what was asked for and raises when they differ, because a
        settings UI that reports success over a change that did not take is worse than one that
        errors.

        ── AND IT RECORDS THAT IT WROTE, BECAUSE `apply -k` WILL REVERT THIS (audit F016) ────────

        CONFIRMED BY RUNNING IT against the live cluster: a GUI write of DETECT_INTERVAL_S=240
        landed (the response even rolled the worker), and the very next `kubectl apply -k k8s/`
        put it back to 300. The GUI was reporting success over a change with the lifetime of a
        deploy, and the operator had no way to know.

        This is not a bug in the write path -- it is what `kubectl apply` DOES to a ConfigMap that
        a manifest owns. The field IS the manifest's, so an apply is entitled to reset it. Fighting
        that (a second ConfigMap, an overlay generator, admission webhooks) would trade a silent
        revert for a much larger machine, and the deployment's own `kustomization.yaml` already
        chooses the opposite trade for the account store: it does NOT ship a manifest for data the
        product writes, precisely so an apply cannot wipe it.

        So the honest fix is to make the conflict LEGIBLE rather than pretend it does not exist:
        every key the GUI writes is recorded in an annotation with its value and timestamp, so a
        later read can tell "this is the manifest's value" from "an operator changed this, and a
        deploy may have reverted it". The settings view surfaces that, and this method's return
        says which keys are at risk.
        """
        want = {to_configmap_key(k): (v or "").strip() for k, v in changes.items()}
        stamp = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        # US-10: the PREVIOUS landed value, read BEFORE this write. A revert needs the version
        # this write replaced -- the annotation only ever held the newest one. An unreadable
        # configmap degrades to "no previous recorded" (the revert then says so), never to a
        # guessed value.
        before: dict = {}
        try:
            before = self.read()
        except Exception:  # noqa: BLE001
            before = {}

        # Read the existing provenance so this write ADDS to it rather than replacing it: an
        # operator who changed two keys on two days must not lose the first record.
        prior = self.configmap_annotation(GUI_WRITE_ANNOTATION)
        records: dict[str, dict[str, str]] = {}
        if prior:
            with contextlib.suppress(ValueError, TypeError):
                parsed = json.loads(prior)
                if isinstance(parsed, dict):
                    records = parsed
        # Only record keys whose value actually DIFFERS from the last write, so a no-op save does
        # not make every key look operator-modified.
        for key, value in want.items():
            previous = (records.get(key) or {}).get("value")
            if previous == value:
                records[key]["at"] = stamp
                continue
            record = {"value": value, "at": stamp}
            if by:
                record["by"] = by
            if reason:
                record["reason"] = reason
            # US-10: the version this write replaced (the ConfigMap's own prior value), so the
            # settings row can offer a revert that lands somewhere real.
            if before:
                record["prev_value"] = before.get(key, "")
                if isinstance(records.get(key), dict) and records[key].get("at"):
                    record["prev_at"] = records[key]["at"]
            records[key] = record

        self._request("PATCH", {"data": want, "metadata": {"annotations": {
            GUI_WRITE_ANNOTATION: json.dumps(records, sort_keys=True),
            GUI_WRITE_LEGEND: (
                "Keys listed here were set through the Weirvern GUI, not by k8s/*.yaml. "
                "`kubectl apply -k` RESTORES THE MANIFEST'S VALUE and will revert any of them that "
                "a manifest also defines. Re-apply the GUI setting after a deploy, or move it into "
                "k8s/20-configmap-env.yaml to make it permanent."
            ),
        }}})

        landed = self.read()
        missing = {k: (v, landed.get(k)) for k, v in want.items() if landed.get(k) != v}
        if missing:
            raise ConfigError(
                "the write did not take. The cluster accepted the request but the ConfigMap "
                f"still reports different values: {missing}"
            )
        return landed

    def configmap_annotation(self, name: str) -> str:
        """One annotation's value on this ConfigMap, or '' if it is absent."""
        try:
            meta = self._request("GET", None).get("metadata") or {}
        except ConfigError:
            return ""
        return str((meta.get("annotations") or {}).get(name) or "")

    def settings_drift(self) -> list[dict]:
        """Keys the GUI wrote whose live value no longer matches, newest information first.

        ── THIS IS PRODUCT CODE, NOT A HELPER FOR TESTS ──────────────────────────────────────────

        The first version of this lived inline in the settings view, and the tests reimplemented it
        in a local helper to check the behaviour. MUTATION TESTING SHOWED THE TESTS PROVED NOTHING
        ABOUT THE VIEW: breaking the view's `reverted` expression to treat an absent key as a revert
        left the entire suite green, because no test ever ran the view's copy. A test that
        reimplements the logic it is checking tests its own copy.

        So the computation lives here, where the view calls it and a test can too.
        """
        written = self.gui_written_keys()
        if not written:
            return []
        live = self.read()
        rows = []
        for key, rec in sorted(written.items()):
            want = str(rec.get("value") or "")
            current = live.get(key)
            rows.append({
                "key": key,
                "chosen": want,
                "at": str(rec.get("at") or ""),
                "current": "" if current is None else str(current),
                # A key absent from the ConfigMap cannot have been reverted by an apply: the
                # manifest simply may not define it. Reporting one would send an operator looking
                # for a deploy that did nothing.
                "reverted": current is not None and str(current) != want,
            })
        return rows

    def gui_written_keys(self) -> dict[str, dict[str, str]]:
        """Keys the GUI wrote, with the value and time. Empty when nothing was written.

        Used by the settings view to warn before a deploy silently reverts an operator's change,
        rather than only reporting it after the fact.
        """
        raw = self.configmap_annotation(GUI_WRITE_ANNOTATION)
        if not raw:
            return {}
        with contextlib.suppress(ValueError, TypeError):
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return {str(k): dict(v) for k, v in parsed.items() if isinstance(v, dict)}
        return {}

    def restart(self, target: str) -> None:
        """Roll a workload so it re-reads the ConfigMap.

        A ConfigMap env var is read at process start, so a change without a restart is INERT -- the
        operator would be told "saved" about something that is not in effect.

        THERE IS NO /restart ENDPOINT. This first version POSTed to
        `.../deployments/<name>/restart`, which does not exist: the live deployment answered 403
        and the change sat unapplied while reporting success-with-a-caveat. `kubectl rollout
        restart` works by PATCHING the pod template with a timestamp annotation, which changes the
        template hash and rolls the pods. That is what this does now.
        """
        kind, _, name = target.partition("/")
        if kind not in ("deploy", "ds", "statefulset"):
            raise ConfigError(f"cannot restart '{target}': unknown workload kind '{kind}'")
        path = {"deploy": "deployments", "ds": "daemonsets",
                "statefulset": "statefulsets"}[kind]
        url = f"{self.api_host}/apis/apps/v1/namespaces/{self.namespace}/{path}/{name}"

        # THE SAME KEY kubectl uses, so either tool sees the other's rollout. A stable,
        # ISO-8601 second-resolution stamp: two restarts inside one second would produce the same
        # annotation and the second would be a no-op.
        stamp = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        patch = {
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {"kubectl.kubernetes.io/restartedAt": stamp}
                    }
                }
            }
        }
        body = json.dumps(patch).encode()
        req = urllib.request.Request(url, data=body, method="PATCH")
        req.add_header("Authorization", f"Bearer {self.token()}")
        # Merge patch, so only the annotation changes: a strategic or JSON patch here could
        # reorder containers, and an update PUT would replace the whole workload spec.
        req.add_header("Content-Type", "application/merge-patch+json")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=self._ssl_context()):
                return
        except urllib.error.HTTPError as exc:
            detail = ""
            with contextlib.suppress(Exception):
                detail = exc.read().decode()[:300]
            if exc.code == 403:
                raise ConfigError(
                    f"the configuration was SAVED but {target} could not be restarted (403). The "
                    f"GUI's ServiceAccount needs patch on {path} in {self.namespace}. Until it is "
                    f"rolled, {target} is still running the old settings."
                ) from exc
            raise ConfigError(
                f"the configuration was SAVED but {target} could not be restarted ({exc.code}): "
                f"{detail}"
            ) from exc
        except urllib.error.URLError as exc:
            raise ConfigError(
                f"the configuration was SAVED but {target} could not be restarted: {exc.reason}"
            ) from exc
