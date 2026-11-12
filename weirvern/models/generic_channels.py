"""Any collected source can carry a ripple (RIP source-agnostic channels).

WHY THIS EXISTS. The fusion could only hear from seven hand-written specialists plus temporal and
changepoint models. Meanwhile the deployment already collects, with real volume on 2026-11-12:
zeek_http 116k, zeek_files 81k, zeek_ssh 19k, zeek_weird 1.6M, zeek_quic 5.9k, zeek_dhcp 1.3k,
zeek_kerberos 1.4k, zeek_ntlm 413, zeek_x509 306, zeek_tunnel 133, zeek_smb_* 206. None of it
reached the ripple layer. A product cannot ship a detector that only sees the sources someone
wrote a specialist for.

HOW A SOURCE BECOMES A CHANNEL. A ChannelSpec declares four things: the table, the host column,
the value whose diversity matters, and the family it belongs to. The score is the same shape for
every source -- how far this window's volume and diversity sit above the host's own recent
normal -- so adding a source is a declaration, not a new algorithm.

CALIBRATION. A score is not a p-value. Each host's windows over the last `LOOKBACK_DAYS` are
scored with the SAME function, and the current window is ranked against them. A source with no
history for a host produces no evidence at all, never a zero.

WHAT THIS CANNOT DO. A source that is silent because nothing happened and a source that is silent
because collection broke look identical here; freshness remains the collection layer's job.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from weirvern.models.ripple import ChannelEvidence, empirical_pvalue

WINDOW_MINUTES = 5
LOOKBACK_DAYS = 7
MIN_WINDOWS = 24          # at least two hours of the host's own history before ranking it
SCORE_FLOOR = 1.0         # ratio at or below 1.0 is "at or below normal"


@dataclass(frozen=True)
class ChannelSpec:
    """One source table, reduced to the two questions every source can answer.

    volume:   how much of this source did the host produce in the window?
    diversity: how many distinct values of `value_column` did it touch?

    A port scan shows up as volume on ssh/conn; a beacon as low volume with fixed diversity; an
    HTTP implant as a new user-agent (diversity) at ordinary volume. One score covers all three.
    """

    channel: str
    family: str
    table: str
    host_column: str
    value_column: str | None
    scale: str = "5m"

    def sql(self, *, since_s: int) -> str:
        value = (f", uniqExact({self.value_column}) AS u" if self.value_column
                 else ", 0 AS u")
        return (f"SELECT {self.host_column}, toStartOfFiveMinute(ts) AS w, count() AS n{value} "
                f"FROM {self.table} "
                f"WHERE ts >= now() - INTERVAL {int(since_s)} SECOND "
                f"GROUP BY {self.host_column}, w ORDER BY w")


#: The sources this deployment already collects and the ripple layer could not hear.
SPECS: tuple[ChannelSpec, ...] = (
    ChannelSpec("http", "http", "weirvern.zeek_http", "src_addr", "user_agent"),
    ChannelSpec("files", "files", "weirvern.zeek_files", "src_addr", "mime_type"),
    ChannelSpec("ssh", "ssh", "weirvern.zeek_ssh", "src_addr", "client"),
    ChannelSpec("weird", "weird", "weirvern.zeek_weird", "src_addr", "name"),
    ChannelSpec("quic", "quic", "weirvern.zeek_quic", "src_addr", "server_name"),
    ChannelSpec("dhcp", "dhcp", "weirvern.zeek_dhcp", "client_addr", "host_name"),
)


def score_window(n: float, u: float, *, median_n: float, median_u: float) -> float:
    """How far this window sits above the host's own normal, in multiples.

    Ratios rather than z-scores: these counts are heavy-tailed and a mean/std would be set by the
    tail. A window at normal volume and normal diversity scores 1.0; ten times the volume scores
    10.0. Both components are kept because a quiet, diverse window is exactly what a tunnel looks
    like, and a loud, monotonous one is what a scan looks like.
    """
    # A normal window must score exactly 1.0, so the denominator is the median itself; the
    # floor of 1.0 only avoids dividing by zero for a source the host has never used.
    volume = float(n) / (float(median_n) if median_n > 0 else 1.0)
    diversity = float(u) / (float(median_u) if median_u > 0 else 1.0)
    return round(max(volume, diversity), 6)


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (ordered[middle - 1] + ordered[middle]) / 2.0


def _per_host(rows: list[Any], value_index: int | None) -> dict[str, list[tuple[datetime, float, float]]]:
    out: dict[str, list[tuple[datetime, float, float]]] = {}
    for row in rows:
        host, window, n = str(row[0] or ""), row[1], float(row[2] or 0)
        u = float(row[value_index]) if value_index is not None and len(row) > value_index else 0.0
        if not host:
            continue
        out.setdefault(host, []).append((window, n, u))
    for host in out:
        out[host].sort(key=lambda item: item[0])
    return out


def evidence(client: Any, hosts: list[str], *, now: datetime | None = None,
             specs: tuple[ChannelSpec, ...] = SPECS) -> dict[str, list[ChannelEvidence]]:
    """host -> evidence, one piece per source that has both a current window and history."""
    moment = now or datetime.now(UTC)
    wanted = set(hosts)
    out: dict[str, list[ChannelEvidence]] = {}
    since_s = LOOKBACK_DAYS * 86400

    for spec in specs:
        try:
            rows = list(client.query(spec.sql(since_s=since_s)).result_rows)
        except Exception:  # noqa: BLE001 - one missing source must not silence the others
            continue
        value_index = 3 if spec.value_column else None
        for host, windows in _per_host(rows, value_index).items():
            if host not in wanted or len(windows) < MIN_WINDOWS + 1:
                continue
            history, current = windows[:-1], windows[-1]
            # Score every historical window against the ones before it, with the same function
            # used on the current one. That is what makes the rank meaningful.
            scores: list[float] = []
            for index, (_w, n, u) in enumerate(history):
                prior = history[:index]
                if not prior:
                    scores.append(SCORE_FLOOR)
                    continue
                scores.append(score_window(
                    n, u,
                    median_n=_median([x[1] for x in prior]),
                    median_u=_median([x[2] for x in prior])))
            median_n = _median([w[1] for w in history])
            median_u = _median([w[2] for w in history])
            score = score_window(current[1], current[2], median_n=median_n, median_u=median_u)
            reference = [s for s in scores if math.isfinite(s)]
            pvalue = empirical_pvalue(score, reference)
            if not math.isfinite(pvalue):
                continue
            age_s = max(0.0, (moment - current[0]).total_seconds())
            out.setdefault(host, []).append(ChannelEvidence(
                channel=spec.channel, family=spec.family, scale=spec.scale,
                model_id=f"source:{spec.channel}", model_version="source-scan/1",
                score=score, pvalue=pvalue, freshness_s=age_s, present=True))
    return out


__all__ = ["ChannelSpec", "LOOKBACK_DAYS", "MIN_WINDOWS", "SPECS", "WINDOW_MINUTES", "evidence",
           "score_window"]
