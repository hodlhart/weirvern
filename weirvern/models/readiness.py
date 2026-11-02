"""Cold-start readiness for a deployment that has never seen this network.

The detectors learn from the deployment's own traffic; there is no universal "normal".
That makes the first hours a distinct state: the models may have an artifact and may score
windows, but the network has not produced enough behaviour for a local baseline to mean
anything. This module names that state, and the worker uses it to keep the console readable
without paging on a warm-up baseline.

The gate is deliberately about DATA, not about a fixed wall-clock age: a network with no
traffic never becomes ready. A missing/unknown read is also not ready -- "we could not tell
whether there was enough data" must not silently page.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Readiness:
    state: str                 # "ready" | "warming" | "unknown" | "disabled"
    ready: bool
    hours: int
    windows: int
    hosts: int
    observed_hours: float
    zeek_hosts: int
    reasons: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "ready": self.ready,
            "hours": self.hours,
            "windows": self.windows,
            "hosts": self.hosts,
            "observed_hours": self.observed_hours,
            "zeek_hosts": self.zeek_hosts,
            "reasons": list(self.reasons),
        }


def _query_one(client, sql: str):
    result = client.query(sql)
    rows = getattr(result, "result_rows", None)
    if rows is None:
        rows = result
    return rows[0] if rows else ()


def assess(client, settings) -> Readiness:
    """Measure whether this deployment has enough local traffic to be past warm-up.

    `settings.ml_warmup_hours == 0` disables the gate explicitly. The default keeps pages
    suppressed while the local baseline is still being learned; detections continue to be
    stored and shown, so this is not a blind period.
    """
    hours = max(0, int(getattr(settings, "ml_warmup_hours", 24)))
    min_windows = max(1, int(getattr(settings, "ml_warmup_min_windows", 12)))
    min_hosts = max(1, int(getattr(settings, "ml_warmup_min_hosts", 1)))

    if hours == 0:
        return Readiness("disabled", True, 0, 0, 0, 0.0, 0,
                         ("warm-up gate disabled",))

    try:
        row = _query_one(
            client,
            "SELECT count(), uniqExact(window_start), uniqExact(src_addr), "
            "       dateDiff('hour', min(window_start), max(window_start)) "
            "FROM weirvern.flows_aggregated "
            f"WHERE window_start >= now() - INTERVAL {hours} HOUR",
        )
        rows, windows, hosts, observed = (list(row) + [0, 0, 0, 0])[:4]
    except Exception as exc:  # noqa: BLE001
        return Readiness(
            "unknown", False, hours, 0, 0, 0.0, 0,
            (f"could not read the local baseline window: {type(exc).__name__}: {exc}",),
        )

    windows = int(windows or 0)
    hosts = int(hosts or 0)
    observed = float(observed or 0.0)
    reasons: list[str] = []
    if int(rows or 0) == 0:
        reasons.append("no local flow windows yet")
    elif windows < min_windows:
        reasons.append(f"{windows} distinct windows; need {min_windows}")
    if hosts < min_hosts:
        reasons.append(f"{hosts} hosts; need {min_hosts}")

    zeek_hosts = 0
    try:
        zrow = _query_one(
            client,
            "SELECT uniqExact(src_addr) FROM weirvern.zeek_conn "
            f"WHERE ts >= now() - INTERVAL {hours} HOUR",
        )
        zeek_hosts = int((zrow or (0,))[0] or 0)
        if zeek_hosts == 0:
            reasons.append("Zeek coverage absent")
    except Exception:
        # Zeek is an optional second sensor. Its absence is reported, not treated as zero
        # traffic and not used to block a flow-only deployment.
        reasons.append("Zeek coverage could not be read")

    ready = not any("need" in r or "no local" in r for r in reasons)
    state = "ready" if ready else "warming"
    return Readiness(state, ready, hours, windows, hosts, observed, zeek_hosts,
                     tuple(reasons))
