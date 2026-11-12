"""The operating point a deployment chooses for itself (no slider, no operator).

WHY THIS EXISTS. `fuse()` takes a `max_p`, and that number was a constant chosen by a human:
0.05. Measured on the live deployment on 2026-11-12, that constant produced 6 ripple verdicts in
44 host-evaluations -- 13.6% of hosts, every hour. No customer wants a system that calls one host
in seven anomalous on its first day, and no customer is going to tune the number.

WHAT REPLACES IT. The deployment states a BUDGET ("at most this fraction of host-evaluations may
become a ripple") and derives the p-value threshold from its own recent fused results. The budget
is a product promise; the threshold is an implementation detail that follows from it.

COLD START. A deployment that has not seen enough of its own traffic cannot know what normal is,
so it does not guess: every host is reported `unknown` with the reason and the counts, until the
history is deep enough. That is the honest state for a new install, and it is also what makes the
first threshold defensible instead of arbitrary.

WHAT THIS IS NOT. It is not a label. Nothing here knows whether a ripple was real; the budget is
a rate the operator is willing to look at, and the threshold is whatever produces that rate on
this deployment's own data.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

#: Fraction of host-evaluations allowed to become a ripple. One percent of hourly passes is
#: roughly one event per host every four days -- a rate a person can actually read.
DEFAULT_TARGET_RATE = 0.01
#: Never looser than the constant this replaces; a self-calibrating system must not be able to
#: drift into firing more often than the human-chosen value it superseded.
MAX_P_CAP = 0.05
#: A p-value below this is not believable from a finite reference population.
MIN_P_FLOOR = 1e-6
#: How many past evaluations each monitored host should contribute before the point is trusted.
PASSES_PER_HOST = 100


@dataclass(frozen=True)
class OperatingPoint:
    max_p: float
    samples: int
    required: int
    target_rate: float
    cold_start: bool
    reason: str

    def as_dict(self) -> dict[str, object]:
        return {
            "max_p": round(self.max_p, 9),
            "samples": self.samples,
            "required": self.required,
            "target_rate": self.target_rate,
            "cold_start": self.cold_start,
            "reason": self.reason,
        }


def required_samples(hosts: int, *, passes_per_host: int = PASSES_PER_HOST) -> int:
    """Enough history that every monitored host, not just the fleet in aggregate, is calibrated."""
    return max(50, max(1, hosts) * passes_per_host)


def derive(values: list[float], *, hosts: int, target_rate: float = DEFAULT_TARGET_RATE,
           passes_per_host: int = PASSES_PER_HOST) -> OperatingPoint:
    """Pick the combined-p threshold that would have produced `target_rate` fires historically."""
    required = required_samples(hosts, passes_per_host=passes_per_host)
    clean = [float(v) for v in values if math.isfinite(float(v)) and 0.0 < float(v) <= 1.0]
    if len(clean) < required:
        return OperatingPoint(
            max_p=MIN_P_FLOOR, samples=len(clean), required=required,
            target_rate=target_rate, cold_start=True,
            reason=(f"learning this deployment's baseline: {len(clean)} of {required} "
                    f"evaluations needed before a threshold can be derived"))

    ordered = sorted(clean)
    # The value at the target quantile: a threshold at or below it would have fired on at most
    # target_rate of the history that produced it.
    index = min(len(ordered) - 1, max(0, int(target_rate * len(ordered))))
    chosen = ordered[index]
    bounded = min(MAX_P_CAP, max(MIN_P_FLOOR, chosen))
    return OperatingPoint(
        max_p=bounded, samples=len(clean), required=required, target_rate=target_rate,
        cold_start=False,
        reason=(f"{target_rate:.2%} budget over {len(clean)} evaluations on {max(1, hosts)} "
                f"host(s) -> max_p {bounded:.2g}"))


__all__ = ["DEFAULT_TARGET_RATE", "MAX_P_CAP", "MIN_P_FLOOR", "OperatingPoint", "PASSES_PER_HOST",
           "derive", "required_samples"]
