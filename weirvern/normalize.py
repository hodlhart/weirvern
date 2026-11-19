"""Normalized traffic — operator judgement that the models learn as normal.

THE SHAPE OF THE FEATURE (operator, 2026-11-19):

  * The console shows a FEED of near-similar traffic, flows and DNS, that can be filtered by
    source, segment, port, DNS name and bytes. Reading it is the review.
  * Selecting rows and pressing Normalize records them here. The row turns colour in the feed.
  * What makes them normal is that the host's adaptive baseline absorbs their distribution: the
    statistics widen, the baseline score for that traffic falls, and the models stop finding it
    anomalous. NOTHING IS SILENCED. There is no suppression list, and the alert path never reads
    this module.
  * A normalization is PERMANENT until the operator removes it. Removal is a new row with
    status='removed', never a delete.

The pooling math lives here rather than in the detector so it can be tested without ClickHouse.
"""
from __future__ import annotations

import math
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

ACTIVE = "active"
REMOVED = "removed"
SOURCES = ("flow", "dns")


def new_entry(*, source: str, src_addr: str, dst_prefix: str = "", dst_port: int = 0,
              proto: int = 0, dns_name: str = "", dns_qtype: int = 0,
              flows: int = 0, bytes_: int = 0, packets: int = 0,
              samples: int = 0, avg_bytes: float = 0.0, var_bytes: float = 0.0,
              avg_packets: float = 0.0, var_packets: float = 0.0,
              first_seen: datetime | None = None, last_seen: datetime | None = None,
              actor: str = "operator", note: str = "") -> dict[str, Any]:
    """One row as it is written. Validation is here so a bad selection cannot reach the table."""
    if source not in SOURCES:
        raise ValueError(f"unknown source: {source!r}")
    if not str(src_addr).strip():
        raise ValueError("a normalization must name the host it belongs to")
    if source == "dns" and not str(dns_name).strip():
        raise ValueError("a DNS normalization must name a domain")
    now = datetime.now(UTC)
    return {
        "entry_id": uuid4().hex,
        "created_at": now,
        "created_by": actor or "operator",
        "source": source,
        "status": ACTIVE,
        "removed_at": None,
        "removed_by": "",
        "src_addr": str(src_addr).strip(),
        "dst_prefix": str(dst_prefix or ""),
        "dst_port": int(dst_port or 0),
        "proto": int(proto or 0),
        "dns_name": str(dns_name or ""),
        "dns_qtype": int(dns_qtype or 0),
        "flows": max(0, int(flows or 0)),
        "bytes": max(0, int(bytes_ or 0)),
        "packets": max(0, int(packets or 0)),
        "samples": max(0, int(samples or 0)),
        "avg_bytes": float(avg_bytes or 0.0),
        "var_bytes": float(var_bytes or 0.0),
        "avg_packets": float(avg_packets or 0.0),
        "var_packets": float(var_packets or 0.0),
        "first_seen": first_seen or now,
        "last_seen": last_seen or now,
        "note": str(note or ""),
    }


def removal(entry: dict[str, Any], *, actor: str = "operator") -> dict[str, Any]:
    """The row that supersedes `entry`: same identity, removed, with who and when."""
    out = dict(entry)
    out.update({
        "status": REMOVED,
        "removed_at": datetime.now(UTC),
        "removed_by": actor or "operator",
        "created_at": datetime.now(UTC),
    })
    return out


def pool(host: dict[str, float], seed: dict[str, float]) -> dict[str, float]:
    """Combine a host's observed statistics with a normalized pattern's, as two samples.

    POOLED, NOT REPLACED. The host keeps what it has observed and the operator's traffic is added
    to it, with the standard combined-variance identity:

        n  = n1 + n2
        m  = (n1*m1 + n2*m2) / n
        v  = ((n1-1)*v1 + (n2-1)*v2 + n1*n2/n * (m1-m2)^2) / (n-1)

    A band can only WIDEN: callers keep the larger percentile, never the smaller. A normalization
    is a statement that something is normal, never a statement that the host is quieter than it
    has been.
    """
    n1 = max(0.0, float(host.get("samples", 0) or 0))
    n2 = max(0.0, float(seed.get("samples", 0) or 0))
    if n2 <= 0:
        return dict(host)
    if n1 <= 0:
        m2 = float(seed.get("avg", 0.0) or 0.0)
        v2 = max(0.0, float(seed.get("var", 0.0) or 0.0))
        return {"samples": n2, "avg": m2, "var": v2}

    m1 = float(host.get("avg", 0.0) or 0.0)
    v1 = max(0.0, float(host.get("var", 0.0) or 0.0))
    m2 = float(seed.get("avg", 0.0) or 0.0)
    v2 = max(0.0, float(seed.get("var", 0.0) or 0.0))
    n = n1 + n2
    m = (n1 * m1 + n2 * m2) / n
    v = (0.0 if n <= 1
         else ((n1 - 1) * v1 + (n2 - 1) * v2 + (n1 * n2 / n) * (m1 - m2) ** 2) / (n - 1))
    return {"samples": n, "avg": m, "var": max(0.0, v)}


def widen(current: float, seed: float, samples: int, *, minimum_samples: int = 20) -> float:
    """A percentile moves only when the seed is big enough to mean something, and only upward."""
    if samples < minimum_samples:
        return current
    return max(float(current or 0.0), float(seed or 0.0))


def summarise(rows: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """What the tab says above the feed: how many entries, split by source and status."""
    active = [r for r in rows if r.get("status") == ACTIVE]
    return {
        "total": len(rows),
        "active": len(active),
        "flow": sum(1 for r in active if r.get("source") == "flow"),
        "dns": sum(1 for r in active if r.get("source") == "dns"),
        "hosts": len({r.get("src_addr") for r in active if r.get("src_addr")}),
    }


def sigma(avg: float, var: float) -> float:
    """The detector wants a standard deviation; the pool carries a variance."""
    return math.sqrt(max(0.0, float(var or 0.0)))
