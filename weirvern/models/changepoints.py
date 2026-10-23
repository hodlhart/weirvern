"""A shadow change-point channel: when did this host's normal change?

Page-Hinkley is deliberate: it is cheap, streaming, explainable, and answers the "misconfigured or
new device" question without adding another anomaly score to the ensemble. A change point says
"the regime changed here"; it does not say "malicious".
"""
from __future__ import annotations

import math

from clickhouse_connect.driver.client import Client

from weirvern import __version__
from weirvern.clock import utcnow


def page_hinkley(values: list[float], *, delta: float = 0.05, threshold: float = 6.0,
                 warmup: int = 8) -> list[dict]:
    """Return detected changes as dicts with index, direction and magnitude.

    Series are z-normalised before the test. The first live run compared raw byte/packet counts
    against an absolute threshold of 5, so large series reported a change on ordinary jitter
    (31k shadow rows); a 5-unit allowance means something different at 10 KB and 10 MB. After
    normalisation the threshold is in standard deviations and one step is not re-reported.
    """
    if len(values) <= warmup:
        return []
    xs = [float(v) for v in values]
    mean_all = sum(xs) / len(xs)
    var = sum((v - mean_all) ** 2 for v in xs) / len(xs)
    sd = math.sqrt(var)
    if sd < 1e-9:
        return []  # a constant series has no regime to change
    zs = [(v - mean_all) / sd for v in xs]
    changes: list[dict] = []
    mean = sum(zs[:warmup]) / warmup
    m_up = 0.0
    m_down = 0.0
    for i in range(warmup, len(zs)):
        m_up = max(0.0, m_up + zs[i] - mean - delta)
        m_down = max(0.0, m_down + mean - zs[i] - delta)
        if m_up > threshold or m_down > threshold:
            direction = "up" if m_up > threshold else "down"
            magnitude = abs(zs[i])
            # A bounded confidence: the exceedance over the configured threshold, not a
            # probability of an attack.
            prob = min(0.99, 0.5 + 0.49 * min(1.0, (max(m_up, m_down) - threshold) / threshold))
            changes.append({"index": i, "direction": direction,
                            "probability": round(prob, 3),
                            "magnitude": round(magnitude, 3),
                            "run_length": i - (changes[-1]["index"] if changes else 0)})
            # Re-anchor to the new regime; otherwise every later sample re-fires the same step.
            mean = sum(zs[max(0, i - warmup + 1):i + 1]) / min(warmup, i + 1)
            m_up = m_down = 0.0
        else:
            # Slow adaptation to ordinary drift, so a gradual trend is not a permanent alarm.
            mean = (mean * (i - 1) + zs[i]) / i
    return changes


def run(client: Client, *, limit_hosts: int = 25, days: int = 7) -> dict:
    hosts = [str(r[0]) for r in client.query(
        "SELECT src_addr, count() AS n FROM weirvern.netflow_anomalies "
        "WHERE detected_at >= now() - INTERVAL 7 DAY GROUP BY src_addr "
        "ORDER BY n DESC LIMIT " + str(int(limit_hosts))).result_rows if r and r[0]]
    written = 0
    out = []
    for host in hosts:
        for metric, col in (("bytes", "total_bytes"), ("packets", "total_packets")):
            rows = client.query(
                "SELECT window_start, " + col + " FROM weirvern.flows_aggregated "
                "WHERE src_addr = %(h)s AND window_start >= now() - INTERVAL %(d)s DAY "
                "ORDER BY window_start",
                parameters={"h": host, "d": int(days)},
            ).result_rows
            values = [float(r[1] or 0) for r in rows]
            for change in page_hinkley(values)[:5]:
                when = rows[change["index"]][0]
                client.insert(
                    "weirvern.ml_changepoints",
                    [[utcnow(), host, metric, change["direction"], when,
                      change["probability"], change["run_length"], change["magnitude"],
                      "page_hinkley", __version__, utcnow()]],
                    column_names=["detected_at", "src_addr", "metric", "direction",
                                  "changepoint_at", "probability", "run_length", "magnitude",
                                  "algorithm", "model_version", "computed_at"],
                )
                written += 1
                out.append({"host": host, "metric": metric, **change})
    return {"available": True, "hosts": len(hosts), "rows": written,
            "changes": out[:50], "model_version": __version__}


__all__ = ["page_hinkley", "run"]
