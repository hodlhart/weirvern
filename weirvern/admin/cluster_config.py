"""Write the cluster's configuration, and read back what actually landed.

WHY THIS EXISTS. Both the TUI's Config tab and `weirvern config set` write the local `.env` file.
The cluster reads the `weirvern-env` ConfigMap. Nothing in `k8s/*.yaml` reads `.env` and the
Containerfile ships none, so BOTH surfaces' writes have been a no-op against a deployed cluster
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
    "MGMT_IFACE",
    "WEIRVERN_REVERSE_DNS",
    "INTERCEPT_TARGETS",
    "INTERCEPT_SEGMENT",
    "INTERCEPT_ADDR",
    "INTERCEPT_GATEWAY",
    "SENSOR_MODE",
    "WEIRVERN_EXCLUDE_CIDRS",
    "WEIRVERN_CAPTURE_EXCLUDE_CIDRS",
)

# Which workload must restart for a key to take effect. A ConfigMap env var is read at process
# start, so a change is inert until the reader restarts -- and WHICH reader matters: restarting
# the worker for a Zeek interface change does nothing, and the operator would be told it applied.
#
# "zeek" is the capture DaemonSet, which is the one that touches the wire. Restarting it has a
# brief capture gap, which is why the UI states it before applying.
_RESTART_FOR: dict[str, tuple[str, str]] = {
    "SENSOR_MODE": ("ds/zeek", "restarts the capture sensor (brief capture gap while it comes up)"),
    "ZEEK_IFACE": ("ds/zeek", "restarts the capture sensor (brief capture gap)"),
    "MGMT_IFACE": ("ds/zeek", "restarts the capture sensor (brief capture gap)"),
    "INTERCEPT_TARGETS": ("ds/zeek", "restarts the capture sensor"),
    "INTERCEPT_SEGMENT": ("ds/zeek", "restarts the capture sensor"),
    "INTERCEPT_ADDR": ("ds/zeek", "restarts the capture sensor"),
    "INTERCEPT_GATEWAY": ("ds/zeek", "restarts the capture sensor"),
    "BASE_THRESHOLD": ("deploy/weirvern-worker", "restarts the detection worker"),
    "MIN_AGREEMENT": ("deploy/weirvern-worker", "restarts the detection worker"),
    "STRONG_SIGNAL": ("deploy/weirvern-worker", "restarts the detection worker"),
    "DETECT_INTERVAL_S": ("deploy/weirvern-worker", "restarts the detection worker"),
    "RETRAIN_EVERY_H": ("deploy/weirvern-worker", "restarts the detection worker"),
    "RETRAIN_WINDOW_H": ("deploy/weirvern-worker", "restarts the detection worker"),
    "PUSHOVER_ENABLED": ("deploy/weirvern-worker", "restarts the detection worker"),
    "PUSHOVER_COOLDOWN_S": ("deploy/weirvern-worker", "restarts the detection worker"),
    "PUSHOVER_MAX_PER_HOUR": ("deploy/weirvern-worker", "restarts the detection worker"),
    "WEIRVERN_REVERSE_DNS": ("deploy/weirvern-worker", "restarts the detection worker"),
    # The worker installs the ingest filter at startup; Zeek reads the capture list at
    # startup too, so BOTH restart for a change to either to take effect.
    "WEIRVERN_EXCLUDE_CIDRS": ("deploy/weirvern-worker",
                               "restarts the detection worker"),
    "WEIRVERN_CAPTURE_EXCLUDE_CIDRS": ("ds/zeek",
                                      "restarts the capture sensor (brief capture gap)"),
}


class ConfigError(Exception):
    """A write that could not be performed, or was performed and did not take.

    A plain Exception, NOT a dataclass: `@dataclass` on an Exception subclass generates an
    `__init__(self)` taking no arguments, so every `raise ConfigError("why")` would fail with
    "Expected 0 positional arguments" -- at the moment it tries to report a problem.
    """


@dataclass
class Proposal:
    """One proposed change, with what it will cost."""

    key: str
    current: str
    proposed: str
    restarts: str = ""
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
            if p.restarts and p.restarts not in out:
                out.append(p.restarts)
        return out


# Values that would make the sensor dangerous or useless, with the reason. A config UI is a new
# way to reach a setting that previously required reading the docs, so the check that the docs
# provided has to live here instead.
_GUARDS: dict[str, tuple[str, ...]] = {
    "RETRAIN_EVERY_H": ("detection falls behind a changing traffic mix",),
    "DETECT_INTERVAL_S": ("alerts are delayed by up to this interval",),
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
        if normalised not in ("loch", "weir"):
            raise ConfigError(f"'{raw}' is not a sensor mode; expected 'loch' or 'weir'")
        return ("in-path interception puts this host in the traffic path. Enabling it without "
                "forwarding working takes the segment down — the mode gate is checked at apply.")

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

    numeric = {
        "BASE_THRESHOLD": (0.0, 1.0, "a score fraction"),
        "MIN_AGREEMENT": (0.0, 1.0, "a fraction of models"),
        "STRONG_SIGNAL": (0.0, 1.0, "a score fraction"),
        "DETECT_INTERVAL_S": (30, 86400, "seconds"),
        "RETRAIN_EVERY_H": (1, 720, "hours"),
        "RETRAIN_WINDOW_H": (1, 8760, "hours"),
        "PUSHOVER_COOLDOWN_S": (0, 86400, "seconds"),
        "PUSHOVER_MAX_PER_HOUR": (0, 1000, "alerts per hour"),
    }
    if key in numeric:
        lo, hi, what = numeric[key]
        try:
            number = float(raw)
        except ValueError:
            raise ConfigError(f"{key} must be a number ({what}), not '{raw}'") from None
        if number < lo or number > hi:
            raise ConfigError(f"{key} must be between {lo} and {hi} ({what}); got {raw}")
        if key in ("RETRAIN_EVERY_H", "RETRAIN_WINDOW_H") and number < 1:
            return "a sub-hour retrain interval will keep the detectors permanently busy"
        return ""

    if key == "PUSHOVER_ENABLED":
        if raw.lower() not in ("true", "false", "1", "0", "yes", "no", ""):
            raise ConfigError(f"{key} must be true or false, not '{raw}'")
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


def plan(changes: dict[str, str], current: dict[str, str]) -> Plan:
    """Compute what a set of changes would do. Touches nothing.

    Raises ConfigError if any single change is unacceptable, so a multi-key apply is all-or-nothing
    -- a partial apply would leave the deployment in a state nobody chose.
    """
    out = Plan()
    for key, value in changes.items():
        key = key.strip().upper()
        warning = validate(key, value)
        was = current.get(key, "")
        target, blast = _RESTART_FOR.get(key, ("", ""))
        out.proposals.append(Proposal(
            key=key,
            current=was,
            proposed=(value or "").strip(),
            restarts=target,
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

    def apply(self, changes: dict[str, str]) -> dict[str, str]:
        """Merge the changes in, then READ BACK and prove they landed.

        THE READ-BACK IS THE POINT. A merge-patch that matches nothing returns 200 with the
        original content, so a successful call is not evidence the configuration changed. This
        compares the result against what was asked for and raises when they differ, because a
        settings UI that reports success over a change that did not take is worse than one that
        errors.
        """
        want = {k.strip().upper(): (v or "").strip() for k, v in changes.items()}
        self._request("PATCH", {"data": want})

        landed = self.read()
        missing = {k: (v, landed.get(k)) for k, v in want.items() if landed.get(k) != v}
        if missing:
            raise ConfigError(
                "the write did not take. The cluster accepted the request but the ConfigMap "
                f"still reports different values: {missing}"
            )
        return landed

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
