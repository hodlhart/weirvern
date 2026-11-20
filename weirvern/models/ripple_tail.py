"""A parametric tail for baselines the empirical test cannot resolve.

WHY THIS EXISTS. `empirical_pvalue_two_sided` is rank-based and assumption-free, which is why it
is the default: it needs no model of the host. But its smallest attainable value is 1/(n+1), so a
baseline of 30 windows can express no p below 0.032 and a baseline of 94 -- the 6h scale's live
count on 2026-11-20 -- can express no p below 0.0105. The ripple bar is p <= 0.01. Those scales
were therefore measured and then refused by `_usable`: honest, and mute.

A count channel can do better without inventing a result. Its baseline windows are counts, and a
count with a bursty, over-dispersed baseline is what the negative binomial describes: mean mu and
size r, with variance mu + mu^2/r. Fitting those two numbers from the baseline and reading the
tail at the current window gives a p-value that can go below 1/(n+1). The empirical p is still
preferred whenever it can resolve the bar (n >= 100); this module is only for the shortfall.

WHY NEGATIVE BINOMIAL AND NOT POISSON. Live flow/conn counts are bursty: the variance exceeds the
mean. A Poisson tail fitted to such a baseline is too thin, so an ordinary busy window lands in
its far tail and a ripple is manufactured. The negative binomial's extra parameter absorbs that
over-dispersion. Poisson is used ONLY when the baseline's variance is statistically
indistinguishable from its mean (the chi-square dispersion test below), and the chosen method is
recorded on the row: 'negbin', 'poisson' or 'insufficient'.

WHAT IT REFUSES. A baseline that is all zero, constant, non-finite, or too short to estimate a
variance produces method='insufficient' and NO p-value. A channel whose statistic is not a count
(bytes, ratios, a boolean change flag) is not a candidate at all: a negative binomial over byte
sums is a category error, and those channels keep the empirical test. The fit is never allowed to
claim more than `TAIL_P_FLOOR` (1e-6): below that the normal approximation inside the tail, and
the fit's own uncertainty, are doing more work than the data, and a fabricated 1e-300 would
dominate a score built from -log10(p).

THE VALIDATION IS SEPARATE AND NOT OPTIONAL. A fitted tail is a model, and a model can be
miscalibrated. `scripts/ripple_tail_far.py` measures the realised false-alarm rate on held-out
normal windows (fit on the baseline, score the next window) per scale. A scale whose realised FAR
is materially above the nominal 1% is not shipped as usable; see `ripple_evidence.TAIL_DISABLED`.
"""
from __future__ import annotations

import math

from scipy.special import betainc, gammainc, gammaincc
from scipy.stats import chi2 as _chi2

NEGBIN = "negbin"
POISSON = "poisson"
INSUFFICIENT = "insufficient"
TAIL_METHODS = frozenset({NEGBIN, POISSON})

#: The dispersion test's level. If the Poisson variance assumption is not rejected at this level,
#: the simpler model is used; the instruction is "fall back to Poisson only when the baseline
#: variance is indistinguishable from the mean", and this is that test.
DISPERSION_ALPHA = 0.05

#: The smallest p the fitted tail is allowed to report. It is a TRUST floor, not a resolution
#: bound: below 1e-6 the fitted distribution's shape, not the measurement, is what the number
#: describes. The empirical test's 1/(n+1) floor is reported separately and never overwritten.
TAIL_P_FLOOR = 1e-6


def _nan() -> float:
    return float("nan")


def _finite(value: float) -> bool:
    return math.isfinite(float(value))


class TailFit:
    """One fitted baseline: the method, its parameters, and why it was chosen.

    Frozen and JSON-ready. `size`/`prob` are the negative binomial's r and p; they are NaN for
    the Poisson fallback, where `mean` is the only parameter. `summary()` is the string stored on
    an evidence row so a reader can see what produced the p-value without a second query.
    """

    __slots__ = ("method", "n", "mean", "variance", "dispersion_index", "size", "prob",
                 "dispersion_p", "reason")

    def __init__(self, method: str, n: int, mean: float = _nan(), variance: float = _nan(),
                 dispersion_index: float = _nan(), size: float = _nan(), prob: float = _nan(),
                 dispersion_p: float = _nan(), reason: str = "") -> None:
        self.method = method
        self.n = int(n)
        self.mean = float(mean)
        self.variance = float(variance)
        self.dispersion_index = float(dispersion_index)
        self.size = float(size)
        self.prob = float(prob)
        self.dispersion_p = float(dispersion_p)
        self.reason = reason

    @property
    def usable(self) -> bool:
        return self.method in TAIL_METHODS

    def as_dict(self) -> dict[str, object]:
        return {
            "method": self.method,
            "n": self.n,
            "mean": None if not _finite(self.mean) else round(self.mean, 6),
            "variance": None if not _finite(self.variance) else round(self.variance, 6),
            "dispersion_index": (None if not _finite(self.dispersion_index)
                                 else round(self.dispersion_index, 6)),
            "size": None if not _finite(self.size) else round(self.size, 6),
            "prob": None if not _finite(self.prob) else round(self.prob, 9),
            "dispersion_p": (None if not _finite(self.dispersion_p)
                             else round(self.dispersion_p, 6)),
            "reason": self.reason,
        }

    def summary(self) -> str:
        """The provenance string an evidence row carries. No floating-point noise."""
        if self.method == NEGBIN:
            return (f"negbin n={self.n} mean={self.mean:.6g} var={self.variance:.6g} "
                    f"index={self.dispersion_index:.3g} size={self.size:.6g}")
        if self.method == POISSON:
            return (f"poisson n={self.n} mean={self.mean:.6g} var={self.variance:.6g} "
                    f"index={self.dispersion_index:.3g} (dispersion p={self.dispersion_p:.3g})")
        return f"insufficient: {self.reason}" if self.reason else "insufficient"

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return f"TailFit({self.summary()})"


def _insufficient(n: int, reason: str, **kwargs: float) -> TailFit:
    return TailFit(INSUFFICIENT, n, reason=reason, **kwargs)


def fit_counts(reference: list[float]) -> TailFit:
    """Fit a negative binomial (or Poisson) to one host's baseline counts.

    THE DECISION, IN ORDER:
      1. fewer than two finite values -> insufficient (no variance to estimate);
      2. a non-positive mean or a zero variance -> insufficient (degenerate; a model fitted to a
         constant is a model of nothing, and reporting p=0 from it would be a fabrication);
      3. the chi-square dispersion test does not reject Poisson at `DISPERSION_ALPHA` ->
         'poisson' (the variance is indistinguishable from the mean);
      4. otherwise -> 'negbin' with size r = mu^2 / (var - mu).

    Method of moments is deliberate: with 30-100 windows a likelihood fit is not meaningfully
    better and is harder to explain in a row's provenance. The realised calibration of this
    choice is measured by `scripts/ripple_tail_far.py`, not assumed here.
    """
    values = [float(item) for item in reference if _finite(item)]
    n = len(values)
    if n < 2:
        return _insufficient(n, "fewer than two finite baseline windows")
    if any(item < 0 for item in values):
        return _insufficient(n, "the baseline contains a negative count")
    mean = sum(values) / n
    variance = sum((item - mean) ** 2 for item in values) / (n - 1)
    if not _finite(mean) or not _finite(variance):
        return _insufficient(n, "the baseline mean or variance is not finite")
    if mean <= 0.0:
        return _insufficient(n, "every baseline window is zero", mean=mean, variance=variance,
                             dispersion_index=0.0)
    if variance <= 0.0:
        return _insufficient(n, "zero variance: every baseline window is identical", mean=mean,
                             variance=variance, dispersion_index=0.0)
    index = variance / mean
    # Poisson's variance equals its mean. The test statistic (n-1)*var/mean is chi-square with
    # n-1 degrees of freedom under that hypothesis; a small p means real over-dispersion.
    try:
        statistic = (n - 1) * index
        dispersion_p = float(_chi2.sf(statistic, n - 1))
    except Exception:  # noqa: BLE001 - a failed test is a named state, not a crash
        return _insufficient(n, "the dispersion test could not be evaluated", mean=mean,
                             variance=variance, dispersion_index=index)
    if not _finite(dispersion_p):
        return _insufficient(n, "the dispersion test returned a non-finite p", mean=mean,
                             variance=variance, dispersion_index=index)
    if dispersion_p > DISPERSION_ALPHA:
        return TailFit(POISSON, n, mean=mean, variance=variance, dispersion_index=index,
                       dispersion_p=dispersion_p)
    denominator = variance - mean
    if denominator <= 0.0:
        # Unreachable when dispersion_p <= alpha, kept because a negative denominator would
        # otherwise produce a negative size and a meaningless tail.
        return _insufficient(n, "over-dispersion was detected with a non-positive denominator",
                             mean=mean, variance=variance, dispersion_index=index,
                             dispersion_p=dispersion_p)
    size = (mean * mean) / denominator
    if not _finite(size) or size <= 0.0:
        return _insufficient(n, "the negative binomial's size is not finite", mean=mean,
                             variance=variance, dispersion_index=index,
                             dispersion_p=dispersion_p)
    prob = size / (size + mean)
    if not (0.0 < prob < 1.0):
        return _insufficient(n, "the negative binomial's probability is outside (0,1)",
                             mean=mean, variance=variance, dispersion_index=index,
                             dispersion_p=dispersion_p, size=size)
    return TailFit(NEGBIN, n, mean=mean, variance=variance, dispersion_index=index, size=size,
                   prob=prob, dispersion_p=dispersion_p)


def _count(value: float) -> int | None:
    """The integer a count statistic carries, or None when it is not a count."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    if not _finite(number) or number < 0.0:
        return None
    nearest = round(number)
    if abs(number - nearest) > 1e-9:
        return None
    return int(nearest)


def tail_pvalue(value: float, fit: TailFit) -> float:
    """Two-sided fitted-tail p-value, defined the same way as the empirical one.

    The empirical test reports min(P(X >= x), P(X <= x)) over the baseline. This returns the
    same quantity from the fitted distribution, so a row's p-value means one thing whichever
    method produced it. Both tails include equality, and the smaller is reported -- a host that
    went quiet is as much a change as one that spiked.

    Returns NaN when the value is not a non-negative integer or the fit is not usable. The floor
    is `TAIL_P_FLOOR`, never zero: p=0 is not a number this test can honestly produce.
    """
    if not fit.usable:
        return _nan()
    k = _count(value)
    if k is None:
        return _nan()
    try:
        if fit.method == POISSON:
            # P(X <= k) = Q(k+1, mu); P(X >= k) = P(k, mu) for k >= 1.
            lower = float(gammaincc(k + 1, fit.mean))
            upper = 1.0 if k == 0 else float(gammainc(k, fit.mean))
        else:
            # P(X <= k) = I_p(r, k+1); P(X >= k) = 1 - I_p(r, k) for k >= 1.
            lower = float(betainc(fit.size, k + 1, fit.prob))
            upper = 1.0 if k == 0 else 1.0 - float(betainc(fit.size, k, fit.prob))
    except Exception:  # noqa: BLE001 - a numerical failure is a missing p, not a fake one
        return _nan()
    lower = min(1.0, max(0.0, lower))
    upper = min(1.0, max(0.0, upper))
    result = min(lower, upper)
    if not _finite(result):
        return _nan()
    return float(min(1.0, max(TAIL_P_FLOOR, result)))


def p01_thresholds(fit: TailFit, alpha: float = 0.01) -> dict[str, int | None]:
    """The counts at which each tail reaches `alpha`: the fitted tail's resolution, in counts.

    `upper` is the smallest count whose upper tail is at or below alpha; `lower` is the largest
    count whose lower tail is. They are what an operator can compare a channel's value against,
    and what the per-scale report prints in place of a p-floor. None when the fit is unusable.
    """
    if not fit.usable or not 0.0 < float(alpha) < 1.0:
        return {"upper": None, "lower": None}
    from scipy.stats import nbinom, poisson  # local: only the report path needs the ppf

    try:
        if fit.method == POISSON:
            upper = int(poisson.ppf(1.0 - alpha, fit.mean))
            lower = int(poisson.ppf(alpha, fit.mean))
        else:
            upper = int(nbinom.ppf(1.0 - alpha, fit.size, fit.prob))
            lower = int(nbinom.ppf(alpha, fit.size, fit.prob))
    except Exception:  # noqa: BLE001
        return {"upper": None, "lower": None}
    # ppf can return the last count whose CDF is still <= the target; step up until the actual
    # two-sided tail at that count is <= alpha, so the printed number is the one the test uses.
    for _ in range(64):
        if tail_pvalue(upper, fit) <= alpha:
            break
        upper += 1
    if lower < 0:
        lower = 0
    return {"upper": int(upper), "lower": int(lower)}


__all__ = ["DISPERSION_ALPHA", "INSUFFICIENT", "NEGBIN", "POISSON", "TAIL_METHODS",
           "TAIL_P_FLOOR", "TailFit", "fit_counts", "p01_thresholds", "tail_pvalue"]
