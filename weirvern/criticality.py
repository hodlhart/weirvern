"""The console's ONE criticality vocabulary for corroborating model detections.

WHY THIS MODULE EXISTS. The Alerts tab has two lists: ripples (the finding) and the model's
fused-score detections (corroboration). The ripple row already carries a three-band criticality
computed from its measured evidence. The model rows carry a four-value severity produced by the
ensemble (`low`/`medium`/`high`/`critical`). Rendering those four values beside the ripple's
three would put two severity scales on one page and make the reader learn which list they are
looking at from the colours.

So the model row's existing severity is MAPPED here, once, onto the ripple vocabulary:

    critical, high  -> high
    medium          -> medium
    low             -> low
    absent/unknown  -> unclassified

`unclassified` is a real state, not a synonym for low: a row with no severity must look like a
row nobody classified. Mapping it to `low` would turn silence into a reassuring rank.

The function is deliberately server-side and shipped on every row (`severity_band`), so the
browser never restates the mapping and a second consumer cannot drift from the first.
"""
from __future__ import annotations

from collections.abc import Iterable
from typing import Any

BAND_VOCABULARY = ("high", "medium", "low")
UNCLASSIFIED = "unclassified"
# Highest first: the Alerts list is ordered by criticality, then recency.
BAND_RANK = {"high": 3, "medium": 2, "low": 1, UNCLASSIFIED: 0}
BAND_ORDER = ("high", "medium", "low", UNCLASSIFIED)


def corroboration_band(severity: str | None) -> str:
    """Map an ensemble severity onto the ripple's three-band vocabulary.

    `critical` folds into `high`: the ripple vocabulary tops out at high, and a critical model
    detection is, for corroboration purposes, the strongest support a ripple can have. An
    absent value is `unclassified` -- never `low`.
    """
    value = str(severity or "").strip().lower()
    if value in ("critical", "high"):
        return "high"
    if value == "medium":
        return "medium"
    if value == "low":
        return "low"
    return UNCLASSIFIED


def annotate_bands(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Stamp every row with the one band the browser renders. Mutates and returns the list."""
    for row in rows:
        row["severity_band"] = corroboration_band(row.get("severity"))
    return list(rows)


def band_rank(band: str | None) -> int:
    """Sort key: high, medium, low, then unclassified."""
    return BAND_RANK.get(str(band or "").strip().lower(), 0)


def band_counts_from_severity_counts(severity_counts: dict[str, Any] | None) -> dict[str, Any]:
    """Fold a `{severity, count}` tile payload into the one band vocabulary.

    Kept beside the mapper so a count and a row can never use different rules. A failed read
    stays a failed read: `available: false` is passed through with its reason, never zeroed.
    """
    data = severity_counts or {}
    if data.get("available") is False:
        return {"available": False, "reason": data.get("reason", "severity counts were not read"),
                "counts": []}
    totals: dict[str, int] = {}
    for item in data.get("counts") or []:
        band = corroboration_band(item.get("severity"))
        totals[band] = totals.get(band, 0) + int(item.get("count") or 0)
    return {"available": True, "reason": "", "counts": [
        {"band": band, "count": totals[band]} for band in BAND_ORDER if totals.get(band)
    ]}


def sort_band_then_recency(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Order rows by band (high first) then newest detection, for callers without SQL ordering."""
    return sorted(
        rows,
        key=lambda row: (band_rank(row.get("severity_band")),
                         str(row.get("detected_at") or "")),
        reverse=True,
    )


__all__ = [
    "BAND_ORDER",
    "BAND_RANK",
    "BAND_VOCABULARY",
    "UNCLASSIFIED",
    "annotate_bands",
    "band_counts_from_severity_counts",
    "band_rank",
    "corroboration_band",
    "sort_band_then_recency",
]
