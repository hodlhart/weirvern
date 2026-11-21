#!/usr/bin/env python3
"""DEAD-MAN WATCHDOG: page when the pipeline stops, and say so when the pager is unplugged.

WHY THIS EXISTS (measured 2026-11-21). `weirvern.flows` and `weirvern.zeek_conn` both stopped at
2026-11-20 23:33 and nothing reached a human for eighteen hours. Every component stayed Ready and
each log line described its own last action truthfully: the ingester said "Ingested 0 flow
records", the sweep said it "examined NOTHING", and the freshness verdict was `logger.error`.
`PUSHOVER_ENABLED=0` with both keys empty, so all 32,897 `alert_events` rows were `log-only` and
zero were sent -- a monitoring channel that had never been connected, reported as a quiet network.

This process is deliberately NOT part of the worker. It runs as its own CronJob, on its own
schedule, with its own ServiceAccount, so a worker that is crash-looping, OOMKilled, or simply
never scheduled cannot take its own watchdog with it. It asks one question per cycle: *is the
thing that is supposed to be advancing still advancing, and if not, can I tell anyone?*

WHAT IT CHECKS
  * `weirvern.flows` and `weirvern.zeek_conn` freshness, using the SAME `ingest_freshness`
    measurement the worker and the Health panel use (one definition, three surfaces). Three
    distinct states, never a bare zero: STALLED (a row exists and is older than 600s), NO_DATA
    (the sink has never held a row), UNREADABLE (the query failed -- we do not know).
  * container restarts in the last interval, and any OOMKilled container.
  * node filesystem > 85% (read from a read-only hostPath mount, so no `nodes` RBAC is needed).
  * ClickHouse free space below its merge headroom (a floor plus twice the largest active part).
  * any Job in `weirvern` with `Failed`/`FailureTarget` in the last hour, excluding this
    watchdog's own Jobs -- otherwise an unconfigured pager would page about itself forever.
  * the `weirling-ingest-tls` leaf certificate expiring within 30 days.

DELIVERY, AND THE HONEST FAILURE MODE
External delivery is POLICY (`ALERT_DELIVERY`). This version ships `record`: alerts are console
records, nothing is sent, the run writes a `watchdog_delivery` row with status `disabled` and
exits 0. That is a documented choice, not a fault, and it must not leave a red CronJob behind --
a permanently failed Job teaches an operator to ignore the colour that means "capture is down".

`ALERT_DELIVERY=pushover` opts in. When Pushover is then enabled but a key is empty, the run
writes a structured ERROR line, writes `watchdog_delivery=unconfigured`, exits 3 and does NOT
return success for a page it did not send: a green CronJob over a disconnected pager is the same
lie as `log-only` in `alert_events`.

USAGE
    python3 scripts/watchdog.py --dry-run     # verdict + exact payloads, sends/writes nothing
    python3 scripts/watchdog.py               # CronJob path; exit 3 = asked for delivery, cannot send
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import ssl
import sys
import urllib.request
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests

from weirvern import ingest_freshness

LOG = logging.getLogger("weirvern.watchdog")

PUSHOVER_ENDPOINT = "https://api.pushover.net/1/messages.json"
HEALTH_TABLE = "weirvern.health"

# 600s, not the worker's 300s detection budget: this is the dead-man page, and two missed
# five-minute buckets are already unambiguous. The Health panel still uses the tighter budget.
STALE_AFTER_S = 600.0
DISK_LIMIT_PCT = 85.0
CERT_MIN_DAYS = 30.0
JOB_FAILURE_WINDOW_S = 3600.0
RESTART_LOOKBACK_S = 600.0
OOM_LOOKBACK_S = 3600.0
COOLDOWN_S = 1800.0
CLICKHOUSE_MIN_FREE_BYTES = 10 * 1024**3  # 10 GiB floor for merges

OK = "ok"
STALLED = "stalled"
NO_DATA = "no_data"
UNREADABLE = "unreadable"
RESTART = "restart"
OOMKILLED = "oomkilled"
PRESSURE = "pressure"
FAILED = "failed"
EXPIRING = "expiring"
UNCONFIGURED = "unconfigured"
DISABLED = "disabled"
DELIVERY_ERROR = "error"

# External delivery is a POLICY, not an accident. This version records alerts in the console and
# sends nothing; `ALERT_DELIVERY=pushover` opts in. A deployment that never configured a pager
# must not report a permanent failure -- on 2026-11-21 three consecutive watchdog Jobs sat in
# `Error` for a configuration choice, which trains an operator to ignore the colour that is
# supposed to mean "capture is down".
ALERT_DELIVERY_ENV = "ALERT_DELIVERY"
DELIVERY_RECORD = "record"
DELIVERY_PUSHOVER = "pushover"

# Every status that is not OK is a fault. `watchdog_delivery=unconfigured` is in this set for the
# Health panel's overall verdict, but `plan_actions` never tries to page about the pager.
# `disabled` is the deliberate policy state and is NOT a fault.
FIRING_STATES = {STALLED, NO_DATA, UNREADABLE, RESTART, OOMKILLED, PRESSURE, FAILED,
                 EXPIRING, DELIVERY_ERROR, UNCONFIGURED}

CRITICAL_CHECKS = {"flows", "zeek_conn", "pod_restarts", "node_disk", "clickhouse_space"}


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(when: datetime) -> str:
    return when.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _as_aware(value: Any) -> datetime | None:
    """ClickHouse returns naive datetimes for DateTime64; they are UTC by column declaration."""
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _parse_kube_time(raw: Any) -> datetime | None:
    return _as_aware(raw)


def _human_age(seconds: float) -> str:
    value = float(seconds)
    if value < 90:
        return f"{value:.0f}s"
    if value < 5400:
        return f"{value / 60.0:.1f}m"
    if value < 172800:
        return f"{value / 3600.0:.1f}h"
    return f"{value / 86400.0:.1f}d"


def _gib(n: int | float) -> str:
    return f"{float(n) / (1024 ** 3):.1f} GiB"


@dataclass(frozen=True)
class Check:
    """One thing the watchdog looked at, with an explicit state.

    A missing check is not a pass: every run emits every name, even when the probe could not
    measure (`unreadable`). The project's F047/F081 rule applies here as much as to the Health
    panel -- a row that is absent is indistinguishable from a row that was fine.
    """

    name: str
    status: str
    detail: str
    value: Any = None
    severity: str = "critical"

    @property
    def firing(self) -> bool:
        return self.status in FIRING_STATES

    def as_dict(self) -> dict[str, Any]:
        return {
            "check": self.name,
            "status": self.status,
            "firing": self.firing,
            "severity": self.severity,
            "detail": self.detail,
            "value": self.value,
        }


@dataclass(frozen=True)
class Delivery:
    configured: bool
    status: str
    reason: str = ""
    mode: str = DELIVERY_PUSHOVER

    def as_dict(self) -> dict[str, Any]:
        return {"configured": self.configured, "status": self.status, "reason": self.reason}


# ── sinks ────────────────────────────────────────────────────────────────────────────────────────

def check_sinks(client: Any, *, limit_s: float = STALE_AFTER_S) -> list[Check]:
    """Both raw sinks, through the one measurement the rest of the project uses.

    `measure_sinks` is imported rather than reimplemented: the worker's log line, the Health
    probe and this page must not disagree about whether the pipeline is advancing. Only the
    DISPLAY is built here, because `Freshness.detail()` is worded for `flows` and would say
    "weirvern.flows holds no rows" for a `zeek_conn` fault.
    """
    verdicts = ingest_freshness.measure_sinks(client, limit_s=limit_s, zeek=True)
    checks: list[Check] = []
    for name, verdict in verdicts.items():
        table = "weirvern.flows" if name == "flows" else ingest_freshness.ZEEK_TABLE
        # `ingest_freshness` spells the healthy state `fresh`; the watchdog's ledger and exit
        # logic use one closed set where `ok` is the only passing status, so map it at the edge
        # rather than making every consumer know both vocabularies.
        status = OK if verdict.state == ingest_freshness.FRESH else verdict.state
        if verdict.state == ingest_freshness.FRESH:
            detail = (f"{table} is advancing: newest row {_human_age(verdict.age_s or 0)} old "
                      f"(limit {_human_age(limit_s)})")
        elif verdict.state == ingest_freshness.STALLED:
            detail = (f"{table} IS STALLED: newest row {_human_age(verdict.age_s or 0)} old "
                      f"(limit {_human_age(limit_s)}). The sink is not advancing; every view "
                      f"built from it is stale rather than quiet. Check the collector "
                      f"(`kubectl -n weirvern logs deploy/goflow2`) and the capture tap "
                      f"(`kubectl -n weirvern logs ds/zeek -c tap`).")
        elif verdict.state == ingest_freshness.NO_DATA:
            detail = (f"{table} holds NO ROWS: nothing has ever been ingested into this sink. "
                      f"This is 'never arrived', not 'arrived and stopped' -- check the exporter "
                      f"and the tap's target selection.")
        else:
            detail = (f"{table} IS UNREADABLE: the freshness query failed, so whether ingest is "
                      f"advancing is UNKNOWN, not zero: {verdict.error}")
        checks.append(Check(name=name, status=status, detail=detail,
                            value=verdict.as_value(), severity="critical"))
    return checks


# ── Kubernetes state ────────────────────────────────────────────────────────────────────────────

class KubeClient:
    """The three reads this watchdog needs, over the in-cluster API.

    It deliberately does NOT use `kubectl` (absent from the worker image) or the Python client
    (not a declared dependency). The `weirvern-viewer` ServiceAccount already has get/list on
    pods and jobs in this namespace, so pod restarts and failed Jobs cost no RBAC change. Node
    disk is measured from a hostPath mount instead of a `nodes` grant; the TLS secret is mounted
    as a volume because the viewer role deliberately cannot read Secrets.
    """

    def __init__(self, base_url: str, token: str, ca_path: str | None, namespace: str = "weirvern",
                 timeout: float = 10.0):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.ca_path = ca_path
        self.namespace = namespace
        self.timeout = timeout

    @classmethod
    def in_cluster(cls, namespace: str = "weirvern") -> KubeClient:
        host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        if not host:
            raise RuntimeError("not running in a cluster (KUBERNETES_SERVICE_HOST is unset)")
        token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        try:
            token = Path(token_path).read_text().strip()
        except OSError as exc:
            raise RuntimeError(f"no service-account token at {token_path}: {exc}") from exc
        ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        return cls(f"https://{host}:{port}", token,
                   ca_path if Path(ca_path).exists() else None, namespace)

    def _get(self, path: str) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"},
        )
        context = ssl.create_default_context(cafile=self.ca_path) if self.ca_path \
            else ssl.create_default_context()
        with urllib.request.urlopen(request, timeout=self.timeout, context=context) as response:
            return json.loads(response.read().decode("utf-8"))

    def pods(self) -> dict[str, Any]:
        return self._get(f"/api/v1/namespaces/{self.namespace}/pods")

    def jobs(self) -> dict[str, Any]:
        return self._get(f"/apis/batch/v1/namespaces/{self.namespace}/jobs")


class _Broken:
    """A source that could not be constructed; every read reports the reason instead of raising."""

    def __init__(self, reason: str):
        self.reason = reason

    def pods(self) -> dict[str, Any]:
        raise RuntimeError(self.reason)

    def jobs(self) -> dict[str, Any]:
        raise RuntimeError(self.reason)


def _previous_counts(previous: Mapping[str, Any]) -> dict[str, int]:
    raw = (previous or {}).get("value")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (TypeError, ValueError):
            raw = {}
    if not isinstance(raw, dict):
        return {}
    counts = raw.get("counts") or {}
    if not isinstance(counts, dict):
        return {}
    out: dict[str, int] = {}
    for key, value in counts.items():
        try:
            out[str(key)] = int(value)
        except (TypeError, ValueError):
            continue
    return out


def check_pod_restarts(kube: Any, previous: Mapping[str, Any], now: datetime) -> Check:
    """Restarts in the last interval, plus any OOMKilled container.

    THE COUNT ALONE IS NOT ENOUGH. `restartCount` is cumulative for the container's lifetime, so
    a pod that restarted once a week ago would page forever. The evidence used here is (a) a
    `lastState.terminated.finishedAt` inside the lookback, (b) a restartCount that grew since
    the previous health row, and (c) a container currently waiting in CrashLoopBackOff /
    ImagePullBackOff / ErrImagePull -- the state that took capture down for 1h50m on 2026-11-19.
    """
    try:
        pods = kube.pods()
    except Exception as exc:  # noqa: BLE001 - a probe must not crash the watchdog
        return Check("pod_restarts", UNREADABLE,
                     f"cannot list pods, so restarts are UNKNOWN rather than zero: {exc}",
                     severity="critical")

    prior = _previous_counts(previous)
    counts: dict[str, int] = {}
    restarted: list[str] = []
    oom: list[str] = []
    waiting: list[str] = []
    for pod in pods.get("items", []) or []:
        meta = pod.get("metadata") or {}
        pod_name = str(meta.get("name") or "?")
        uid = str(meta.get("uid") or pod_name)
        status = pod.get("status") or {}
        for field_name in ("containerStatuses", "initContainerStatuses"):
            for container in status.get(field_name) or []:
                cname = str(container.get("name") or "?")
                ident = f"{uid}/{cname}"
                restart_count = int(container.get("restartCount") or 0)
                counts[ident] = restart_count
                label = f"{pod_name}/{cname}"

                last = ((container.get("lastState") or {}).get("terminated") or {})
                last_reason = str(last.get("reason") or "")
                finished = _parse_kube_time(last.get("finishedAt"))
                if (last_reason == "OOMKilled" and finished is not None
                        and 0 <= (now - finished).total_seconds() <= OOM_LOOKBACK_S):
                    oom.append(f"{label} (OOMKilled {_iso(finished)})")
                if finished is not None and 0 <= (now - finished).total_seconds() <= RESTART_LOOKBACK_S:
                    restarted.append(f"{label} (last exit {last_reason or 'terminated'} "
                                     f"{_human_age((now - finished).total_seconds())} ago)")
                if ident in prior and restart_count > prior[ident]:
                    restarted.append(f"{label} (restartCount {prior[ident]} -> {restart_count})")

                current = container.get("state") or {}
                current_terminated = current.get("terminated") or {}
                if str(current_terminated.get("reason") or "") == "OOMKilled":
                    oom.append(f"{label} (currently OOMKilled)")
                current_waiting = (current.get("waiting") or {})
                if str(current_waiting.get("reason") or "") in {
                        "CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull"}:
                    waiting.append(f"{label} ({current_waiting.get('reason')})")

    if oom:
        status, detail = OOMKILLED, "OOMKilled container(s): " + "; ".join(sorted(set(oom))[:6])
    elif restarted:
        status, detail = RESTART, ("container restart(s) in the last "
                                   f"{_human_age(RESTART_LOOKBACK_S)}: "
                                   + "; ".join(sorted(set(restarted))[:6]))
    elif waiting:
        status, detail = RESTART, "container(s) not starting: " + "; ".join(sorted(set(waiting))[:6])
    else:
        status, detail = OK, (f"no restarts in the last {_human_age(RESTART_LOOKBACK_S)} "
                              f"across {len(counts)} container(s)")
    return Check("pod_restarts", status, detail, value={"counts": counts}, severity="critical")


# ── capacity ────────────────────────────────────────────────────────────────────────────────────

def check_node_disk(path: str, *, limit_pct: float = DISK_LIMIT_PCT,
                    usage: Callable[[str], Any] = shutil.disk_usage) -> Check:
    """The node's filesystem, measured through a read-only hostPath mount of `/`."""
    try:
        measured = usage(path)
    except OSError as exc:
        return Check("node_disk", UNREADABLE,
                     f"cannot measure {path}, so disk pressure is UNKNOWN: {exc}")
    total = int(getattr(measured, "total", 0) or 0)
    used = int(getattr(measured, "used", 0) or 0)
    free = int(getattr(measured, "free", 0) or 0)
    if total <= 0:
        return Check("node_disk", UNREADABLE, f"{path} reported a zero-sized filesystem")
    pct = 100.0 * used / total
    value = {"used_pct": round(pct, 2), "free_bytes": free, "total_bytes": total}
    if pct > limit_pct:
        return Check("node_disk", PRESSURE,
                     f"node filesystem {pct:.1f}% used (limit {limit_pct:.0f}%), only "
                     f"{_gib(free)} free at {path}: capture and ClickHouse share this disk",
                     value=value)
    return Check("node_disk", OK,
                 f"node filesystem {pct:.1f}% used, {_gib(free)} free (limit {limit_pct:.0f}%)",
                 value=value, severity="warning")


def check_clickhouse_space(client: Any,
                           *, min_free_bytes: int = CLICKHOUSE_MIN_FREE_BYTES) -> Check:
    """Free space against the space a merge actually needs.

    `max_bytes_to_merge_at_max_space_in_pool` is 150 GiB on the shipped deployment -- larger
    than the whole disk -- so using it as the bar would fire forever and teach the operator to
    ignore this row. The headroom used instead is the larger of a configurable floor (10 GiB)
    and twice the largest active part, which is the amount a merge of that part can need. The
    formula is printed in the detail so the verdict can be checked rather than trusted.
    """
    try:
        row = client.query(
            "SELECT free_space, total_space FROM system.disks WHERE name = 'default' LIMIT 1"
        ).result_rows[0]
        free = int(row[0] or 0)
        total = int(row[1] or 0)
    except Exception as exc:  # noqa: BLE001
        return Check("clickhouse_space", UNREADABLE,
                     f"cannot read system.disks, so ClickHouse free space is UNKNOWN: {exc}")

    largest = 0
    note = ""
    try:
        rows = client.query(
            "SELECT max(bytes_on_disk) FROM system.parts "
            "WHERE database = currentDatabase() AND active"
        ).result_rows
        largest = int(rows[0][0] or 0) if rows and rows[0] else 0
    except Exception as exc:  # noqa: BLE001 - the floor still gives a usable bar
        note = f"; largest active part unreadable ({exc}), using the floor"

    headroom = max(int(min_free_bytes), 2 * largest)
    value = {"free_bytes": free, "total_bytes": total, "headroom_bytes": headroom,
             "largest_part_bytes": largest}
    if total <= 0:
        return Check("clickhouse_space", UNREADABLE, "system.disks reported a zero-sized disk")
    pct = 100.0 * free / total
    if free < headroom:
        return Check("clickhouse_space", PRESSURE,
                     f"ClickHouse has only {_gib(free)} free of {_gib(total)} ({pct:.1f}%), "
                     f"below its {_gib(headroom)} merge headroom (floor 10 GiB, or 2x the "
                     f"largest active part){note}: merges can fail and ingest will back up",
                     value=value)
    return Check("clickhouse_space", OK,
                 f"ClickHouse has {_gib(free)} free of {_gib(total)} ({pct:.1f}%); "
                 f"merge headroom {_gib(headroom)}{note}", value=value, severity="warning")


# ── jobs and certificates ──────────────────────────────────────────────────────────────────────

def _is_watchdog_job(name: str, labels: Mapping[str, str]) -> bool:
    return (name == "weirvern-watchdog" or name.startswith("weirvern-watchdog-")
            or labels.get("app.kubernetes.io/name") == "weirvern-watchdog")


def check_failed_jobs(kube: Any, now: datetime,
                      *, window_s: float = JOB_FAILURE_WINDOW_S) -> Check:
    """Any Job that reached Failed/FailureTarget in the window.

    THIS WATCHDOG'S OWN JOBS ARE EXCLUDED. It exits 3 every cycle while the pager is
    unconfigured, so including itself would turn one honest configuration failure into a
    self-sustaining page storm.
    """
    try:
        jobs = kube.jobs()
    except Exception as exc:  # noqa: BLE001
        return Check("failed_jobs", UNREADABLE,
                     f"cannot list jobs, so failed Jobs are UNKNOWN: {exc}")

    failed: list[str] = []
    for job in jobs.get("items", []) or []:
        meta = job.get("metadata") or {}
        name = str(meta.get("name") or "?")
        if _is_watchdog_job(name, meta.get("labels") or {}):
            continue
        status = job.get("status") or {}
        for condition in status.get("conditions") or []:
            if str(condition.get("type") or "") not in {"Failed", "FailureTarget"}:
                continue
            if str(condition.get("status") or "").lower() != "true":
                continue
            changed = _parse_kube_time(condition.get("lastTransitionTime"))
            if changed is None or not (0 <= (now - changed).total_seconds() <= window_s):
                continue
            reason = condition.get("reason") or condition.get("type")
            failed.append(f"{name} ({reason})")
            break
    failed = sorted(set(failed))
    if failed:
        return Check("failed_jobs", FAILED,
                     f"{len(failed)} Job(s) failed in the last {_human_age(window_s)}: "
                     + "; ".join(failed[:8]), value={"jobs": failed}, severity="warning")
    return Check("failed_jobs", OK,
                 f"no Job reached Failed/FailureTarget in the last {_human_age(window_s)}",
                 severity="warning")


def check_tls_cert(path: str, now: datetime, *, min_days: float = CERT_MIN_DAYS) -> Check:
    """The ingest gateway's leaf certificate, from the `weirling-ingest-tls` Secret.

    The Secret is mounted as a volume rather than read through the API: the viewer role
    deliberately grants no Secret access, and a monitoring identity that can read every Secret
    is a larger privilege than a certificate deadline needs.
    """
    try:
        pem = Path(path).read_bytes()
    except OSError as exc:
        return Check("tls_cert", UNREADABLE,
                     f"cannot read the certificate at {path} (is the weirling-ingest-tls Secret "
                     f"mounted?), so expiry is UNKNOWN: {exc}", severity="warning")
    try:
        from cryptography import x509  # noqa: PLC0415 - keep module import cheap
        certificates = x509.load_pem_x509_certificates(pem)
        if not certificates:
            raise ValueError("the PEM contains no certificate")
        leaf = certificates[0]
        expiry = getattr(leaf, "not_valid_after_utc", None)
        if expiry is None:  # cryptography < 42
            expiry = leaf.not_valid_after.replace(tzinfo=UTC)
    except Exception as exc:  # noqa: BLE001
        return Check("tls_cert", UNREADABLE,
                     f"cannot parse the certificate at {path}: {exc}", severity="warning")

    days = (expiry - now).total_seconds() / 86400.0
    value = {"expires_at": _iso(expiry), "days_left": round(days, 1)}
    if days < min_days:
        return Check("tls_cert", EXPIRING,
                     f"the ingest certificate expires in {days:.1f} days ({_iso(expiry)}), "
                     f"under the {min_days:.0f}-day floor: renew weirling-ingest-tls",
                     value=value, severity="warning")
    return Check("tls_cert", OK,
                 f"the ingest certificate expires in {days:.1f} days ({_iso(expiry)})",
                 value=value, severity="warning")


# ── delivery ───────────────────────────────────────────────────────────────────────────────────

def delivery_config(env: Mapping[str, str]) -> Delivery:
    """Whether a page could actually leave the cluster, and whether that is even the policy.

    Three states, deliberately distinct:

    * `record` (the default) -- this version does not send external alerts. Every alert is a
      console record. The watchdog says so once, in plain words, and exits 0.
    * `pushover` with both halves set -- pages are attempted; a failed POST is a real fault.
    * `pushover` with a half missing -- `unconfigured`, loud, and exit 3. This is the state that
      is worth waking someone for, because someone asked for delivery and is not getting it.

    BOTH HALVES ARE CHECKED. `PUSHOVER_ENABLED=1` with empty keys is the same silent state as
    `PUSHOVER_ENABLED=0`; the deployment measured on 2026-11-21 had both halves wrong, and the
    only visible fact was 32,897 rows saying `log-only`.
    """
    explicit = (env.get(ALERT_DELIVERY_ENV) or "").strip().lower()
    raw = (env.get("PUSHOVER_ENABLED") or "0").strip().lower()
    enabled = raw in {"1", "true", "yes", "on"}
    missing = [key for key in ("PUSHOVER_USER_KEY", "PUSHOVER_API_TOKEN")
               if not (env.get(key) or "").strip()]

    if explicit == DELIVERY_RECORD:
        return Delivery(False, DISABLED,
                        "external delivery is off for this version (ALERT_DELIVERY=record); "
                        "alerts are recorded in the console", mode=DELIVERY_RECORD)
    if enabled and not missing:
        return Delivery(True, OK, "", mode=DELIVERY_PUSHOVER)
    if explicit == DELIVERY_PUSHOVER:
        reason = (f"PUSHOVER_ENABLED is {env.get('PUSHOVER_ENABLED', '<unset>')!r}, not 1"
                  if not enabled else f"{', '.join(missing)} is empty")
        return Delivery(False, UNCONFIGURED, reason, mode=DELIVERY_PUSHOVER)
    # Nothing was asked for. That is this version's documented behaviour, not a fault.
    return Delivery(False, DISABLED,
                    "external delivery is off for this version; alerts are recorded in the "
                    "console and nothing is sent", mode=DELIVERY_RECORD)


def delivery_check(delivery: Delivery) -> Check:
    if delivery.configured:
        return Check("watchdog_delivery", OK,
                     "Pushover is configured; delivery is attempted below", severity="warning")
    if delivery.status == DISABLED:
        return Check("watchdog_delivery", DISABLED,
                     "External delivery is off for this version: alerts are recorded in the "
                     "console and nothing is sent. Set ALERT_DELIVERY=pushover to enable it.",
                     severity="info")
    return Check("watchdog_delivery", UNCONFIGURED,
                 f"ALERTS CANNOT BE DELIVERED: {delivery.reason}. Someone asked for delivery "
                 f"and is not getting it; the watchdog is running, but no page can leave the "
                 f"cluster.",
                 severity="critical")


def _message(check: Check, now: datetime, *, recovery_from: str = "") -> str:
    if recovery_from:
        return (f"✅ {check.name} RECOVERED (was {recovery_from})\n{check.detail}\n"
                f"checked {_iso(now)}")
    return f"🚨 {check.name} {check.status.upper()}\n{check.detail}\nchecked {_iso(now)}"


def build_payload(check: Check, env: Mapping[str, str], now: datetime,
                  *, recovery_from: str = "") -> dict[str, Any]:
    """The exact body POSTed to Pushover (form-encoded). Tokens are real here, redacted in reports."""
    critical = check.name in CRITICAL_CHECKS and not recovery_from
    return {
        "token": env.get("PUSHOVER_API_TOKEN", ""),
        "user": env.get("PUSHOVER_USER_KEY", ""),
        "message": _message(check, now, recovery_from=recovery_from)[:1024],
        "title": (f"Weirvern watchdog — {check.name} recovered" if recovery_from
                  else f"Weirvern watchdog — {check.name} {check.status.upper()}")[:100],
        "priority": 1 if critical else 0,
        "sound": "siren" if critical else "pushover",
    }


def post_pushover(payload: Mapping[str, Any], *,
                  post: Callable[..., Any] = requests.post,
                  timeout: float = 10.0) -> tuple[bool, str]:
    try:
        response = post(PUSHOVER_ENDPOINT, data=dict(payload), timeout=timeout)
    except Exception as exc:  # noqa: BLE001 - delivery failure must be a verdict, not a crash
        return False, f"{type(exc).__name__}: {exc}"
    if int(getattr(response, "status_code", 0) or 0) == 200:
        return True, "sent"
    body = str(getattr(response, "text", ""))[:200]
    return False, f"HTTP {getattr(response, 'status_code', '?')}: {body}"


@dataclass
class Action:
    check: Check
    kind: str                      # "alarm" | "recovery"
    payload: dict[str, Any] = field(default_factory=dict)
    suppressed: bool = False
    reason: str = ""
    sent: bool | None = None
    error: str = ""

    def as_dict(self, *, redact: bool = False) -> dict[str, Any]:
        payload = dict(self.payload)
        if redact and payload:
            payload["token"] = "<redacted>"
            payload["user"] = "<redacted>"
        return {
            "check": self.check.name,
            "kind": self.kind,
            "suppressed": self.suppressed,
            "reason": self.reason,
            "sent": self.sent,
            "error": self.error,
            "pushover": payload,
        }


def plan_actions(checks: list[Check], previous: Mapping[str, Any], delivery: Delivery,
                 env: Mapping[str, str], *, now: datetime,
                 cooldown_s: float = COOLDOWN_S) -> list[Action]:
    """Which checks are due a page, a recovery, or a cooldown suppression.

    The same firing status inside the cooldown is suppressed. A DIFFERENT firing status is sent
    immediately (restart -> oomkilled is new information). An unconfigured channel records the
    alarm as suppressed-by-configuration so the health row and the exit code can say a page was
    owed even though nothing was sent.
    """
    actions: list[Action] = []
    for check in checks:
        if check.name == "watchdog_delivery":
            continue
        prev = previous.get(check.name) or {}
        prev_status = str(prev.get("status") or "")
        prev_firing = prev_status in FIRING_STATES
        last = _as_aware(prev.get("last_notified_at"))

        if check.firing:
            if not delivery.configured:
                reason = ("delivery-disabled-by-policy: alerts are recorded only"
                          if delivery.status == DISABLED
                          else f"delivery-unconfigured: {delivery.reason}")
                actions.append(Action(check, "alarm", suppressed=True, reason=reason))
                continue
            if (prev_firing and prev_status == check.status and last is not None
                    and (now - last).total_seconds() < cooldown_s):
                actions.append(Action(check, "alarm", suppressed=True,
                                      reason=f"cooldown: re-sent after {int(cooldown_s)}s"))
                continue
            actions.append(Action(check, "alarm",
                                  payload=build_payload(check, env, now)))
        elif prev_firing and check.status == OK:
            if not delivery.configured:
                reason = ("delivery-disabled-by-policy: alerts are recorded only"
                          if delivery.status == DISABLED
                          else f"delivery-unconfigured: {delivery.reason}")
                actions.append(Action(check, "recovery", suppressed=True, reason=reason))
                continue
            actions.append(Action(check, "recovery",
                                  payload=build_payload(check, env, now,
                                                        recovery_from=prev_status)))
    return actions


def load_previous(client: Any) -> dict[str, dict[str, Any]]:
    """The last run's rows, one per check. An absent table is 'no history', not a failure.

    A watchdog on a deployment whose schema predates this table must still run: the first cycle
    then has no cooldown state, which is safe (it may send one extra page), rather than refusing
    to start.
    """
    if client is None:
        return {}
    try:
        rows = client.query(
            "SELECT check_name, status, detail, value, consecutive, last_notified_at "
            f"FROM {HEALTH_TABLE} FINAL"
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        LOG.warning("no previous watchdog health rows (%s): first run, or the schema is older", exc)
        return {}
    out: dict[str, dict[str, Any]] = {}
    for row in rows or []:
        out[str(row[0])] = {
            "status": str(row[1] or ""),
            "detail": str(row[2] or ""),
            "value": row[3] if len(row) > 3 else "",
            "consecutive": int(row[4] or 0) if len(row) > 4 else 0,
            "last_notified_at": row[5] if len(row) > 5 else None,
        }
    return out


def write_health(client: Any, checks: list[Check], actions: list[Action],
                 previous: Mapping[str, Any], now: datetime) -> None:
    """Upsert one row per check. Never raises: a failed ledger write must not lose the page."""
    sent = {action.check.name: action for action in actions if action.sent}
    rows = []
    for check in checks:
        prev = previous.get(check.name) or {}
        last_notified = _as_aware(prev.get("last_notified_at"))
        if check.name in sent:
            last_notified = now
        if check.firing and str(prev.get("status") or "") == check.status:
            consecutive = int(prev.get("consecutive") or 0) + 1
        elif check.firing:
            consecutive = 1
        else:
            consecutive = 0
        rows.append([
            check.name,
            check.status,
            check.detail[:4000],
            "" if check.value is None else json.dumps(check.value, default=str)[:8000],
            consecutive,
            last_notified,
            now,
        ])
    try:
        client.insert(
            HEALTH_TABLE,
            rows,
            column_names=["check_name", "status", "detail", "value", "consecutive",
                          "last_notified_at", "updated_at"],
        )
    except Exception as exc:  # noqa: BLE001
        LOG.error("cannot write %s (the page was still attempted): %s", HEALTH_TABLE, exc)


# ── orchestration ─────────────────────────────────────────────────────────────────────────────

def evaluate(*, client: Any, kube: Any, env: Mapping[str, str], now: datetime,
             previous: Mapping[str, Any], host_root: str, cert_path: str,
             limit_s: float = STALE_AFTER_S, disk_limit_pct: float = DISK_LIMIT_PCT,
             clickhouse_min_free_bytes: int = CLICKHOUSE_MIN_FREE_BYTES,
             disk_usage: Callable[[str], Any] = shutil.disk_usage) -> list[Check]:
    """Every check, always every name, in a stable order."""
    delivery = delivery_config(env)
    return [
        *check_sinks(client, limit_s=limit_s),
        check_pod_restarts(kube, previous.get("pod_restarts") or {}, now),
        check_node_disk(host_root, limit_pct=disk_limit_pct, usage=disk_usage),
        check_clickhouse_space(client, min_free_bytes=clickhouse_min_free_bytes),
        check_failed_jobs(kube, now),
        check_tls_cert(cert_path, now),
        delivery_check(delivery),
    ]


def _exit_code(delivery: Delivery, actions: list[Action]) -> int:
    if delivery.mode == DELIVERY_PUSHOVER and not delivery.configured:
        return 3
    if any(action.sent is False for action in actions if not action.suppressed):
        return 4
    if any(action.sent for action in actions if action.kind == "alarm"):
        return 1
    return 0


def _would_exit(delivery: Delivery, actions: list[Action]) -> int:
    """The exit code a real run would produce, for `--dry-run`."""
    if delivery.mode == DELIVERY_PUSHOVER and not delivery.configured:
        return 3
    if any(action.kind == "alarm" and not action.suppressed for action in actions):
        return 1
    return 0


def _structured_failure(delivery: Delivery, actions: list[Action], now: datetime) -> None:
    """One JSON line an operator (or a log query) can act on without reading the prose."""
    owed = [action.check.name for action in actions
            if action.kind == "alarm" and action.suppressed]
    if delivery.status == DISABLED:
        LOG.info("%s", json.dumps({
            "event": "watchdog_delivery_disabled",
            "severity": "info",
            "reason": delivery.reason,
            "alarms_recorded_only": owed,
            "checked_at": _iso(now),
        }, sort_keys=True))
        return
    LOG.error("%s", json.dumps({
        "event": "watchdog_delivery_unconfigured",
        "severity": "error",
        "reason": delivery.reason,
        "alarms_that_could_not_be_sent": owed,
        "checked_at": _iso(now),
        "note": ("The watchdog is running and found faults, but no page can leave the cluster. "
                 "Set PUSHOVER_ENABLED=1 and both keys in weirvern-secrets."),
    }, sort_keys=True))


def run(*, dry_run: bool = False, env: Mapping[str, str] | None = None,
        now: datetime | None = None, client: Any = None, kube: Any = None,
        previous: Mapping[str, Any] | None = None,
        post: Callable[..., Any] = requests.post,
        host_root: str = "/host", cert_path: str = "/tls/tls.crt",
        limit_s: float = STALE_AFTER_S, disk_limit_pct: float = DISK_LIMIT_PCT,
        cooldown_s: float = COOLDOWN_S,
        clickhouse_min_free_bytes: int = CLICKHOUSE_MIN_FREE_BYTES,
        disk_usage: Callable[[str], Any] = shutil.disk_usage) -> tuple[int, dict[str, Any]]:
    """Evaluate, deliver, record. Returns (process exit code, JSON report).

    Exit codes: 0 healthy/nothing owed, 1 page(s) delivered, 3 the pager is unconfigured,
    4 a configured delivery failed. `--dry-run` always returns 0 and writes/sends nothing; the
    hypothetical code is `report["exit_code"]`.
    """
    env = dict(os.environ if env is None else env)
    now = now or _now()
    previous = previous or {}
    delivery = delivery_config(env)

    checks = evaluate(client=client, kube=kube, env=env, now=now, previous=previous,
                      host_root=host_root, cert_path=cert_path, limit_s=limit_s,
                      disk_limit_pct=disk_limit_pct,
                      clickhouse_min_free_bytes=clickhouse_min_free_bytes,
                      disk_usage=disk_usage)
    actions = plan_actions(checks, previous, delivery, env, now=now, cooldown_s=cooldown_s)

    if not delivery.configured:
        _structured_failure(delivery, actions, now)

    if not dry_run:
        for action in actions:
            if action.suppressed:
                LOG.info("watchdog %s %s suppressed (%s)", action.check.name,
                         action.kind, action.reason)
                continue
            ok, reason = post_pushover(action.payload, post=post)
            action.sent = ok
            action.error = "" if ok else reason
            if ok:
                LOG.info("watchdog %s %s sent", action.check.name, action.kind)
            else:
                LOG.error("%s", json.dumps({
                    "event": "watchdog_delivery_failed",
                    "severity": "error",
                    "check": action.check.name,
                    "kind": action.kind,
                    "reason": reason,
                    "checked_at": _iso(now),
                }, sort_keys=True))

        # The delivery row reflects what actually happened, not what was configured.
        failed_sends = [action for action in actions
                        if not action.suppressed and action.sent is False]
        if not delivery.configured:
            pass  # already `unconfigured`
        elif failed_sends:
            checks = [check if check.name != "watchdog_delivery" else
                      Check("watchdog_delivery", DELIVERY_ERROR,
                            f"{len(failed_sends)} Pushover delivery(ies) failed: "
                            + "; ".join(f"{a.check.name}: {a.error}" for a in failed_sends)[:800],
                            severity="critical")
                      for check in checks]
        if client is not None:
            write_health(client, checks, actions, previous, now)

    code = _exit_code(delivery, actions)
    # `_exit_code` reads what HAPPENED; a dry run has no sends, so it must report what WOULD
    # happen -- otherwise `--dry-run` on a stalled sink would print exit 0 and teach the operator
    # that the verdict is quiet.
    would_exit = code if not dry_run else _would_exit(delivery, actions)
    report = {
        "event": "weirvern_watchdog",
        "checked_at": _iso(now),
        "dry_run": dry_run,
        "dry_run_note": ("nothing was sent and no health row was written" if dry_run else ""),
        "delivery": delivery.as_dict(),
        "overall": "firing" if any(check.firing for check in checks) else "ok",
        "checks": [check.as_dict() for check in checks],
        "alarms": [action.as_dict(redact=dry_run) for action in actions
                   if action.kind == "alarm"],
        "recoveries": [action.as_dict(redact=dry_run) for action in actions
                       if action.kind == "recovery"],
        "exit_code": would_exit,
        "would_exit": would_exit if dry_run else None,
    }
    return (0 if dry_run else code), report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true",
                        help="print the verdict and the exact Pushover payloads; send/write nothing")
    parser.add_argument("--json", action="store_true", help="print the report as JSON (default)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    env = dict(os.environ)
    client = None
    try:
        # Settings(), NOT get_settings(): validate() refuses to construct when
        # PUSHOVER_ENABLED=1 has empty keys, which is precisely the state this process exists to
        # REPORT. A watchdog that cannot start because the pager is misconfigured is no watchdog.
        from weirvern import db  # noqa: PLC0415
        from weirvern.config import Settings  # noqa: PLC0415
        client = db.connect(Settings(), retries=1, delay_s=0.0)
    except Exception as exc:  # noqa: BLE001
        LOG.error("ClickHouse unavailable; sink and disk checks will report UNREADABLE: %s", exc)

    try:
        kube: Any = KubeClient.in_cluster(env.get("WATCHDOG_NAMESPACE", "weirvern"))
    except Exception as exc:  # noqa: BLE001
        LOG.error("Kubernetes API unavailable; pod/job checks will report UNREADABLE: %s", exc)
        kube = _Broken(str(exc))

    previous = load_previous(client)
    code, report = run(
        dry_run=args.dry_run,
        env=env,
        client=client,
        kube=kube,
        previous=previous,
        host_root=env.get("WATCHDOG_HOST_ROOT", "/host"),
        cert_path=env.get("WATCHDOG_TLS_CERT", "/tls/tls.crt"),
        limit_s=float(env.get("WATCHDOG_STALE_S", STALE_AFTER_S)),
        disk_limit_pct=float(env.get("WATCHDOG_DISK_PCT", DISK_LIMIT_PCT)),
        cooldown_s=float(env.get("WATCHDOG_COOLDOWN_S", COOLDOWN_S)),
    )
    print(json.dumps(report, indent=2, default=str))
    return code


if __name__ == "__main__":
    sys.exit(main())
