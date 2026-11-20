"""Missing-data handling for the ML feature path — the machinery behind the
`ml_missing_features` flag (default OFF).

WHY THIS MODULE EXISTS. The models were built on the assumption that every source answered.
Measured on the live deployment: Isolation Forest carries 77 features, 63 of them from Zeek,
but Zeek is visible on ~14 hosts against ~3,730 NetFlow hosts. For the other ~3,716 hosts the
feature assembly had no row to read, so it wrote 0 — and 0 is not a neutral value in this
vector. It is the most extreme value on every count feature (no bytes, no packets, no
connections) and the most reassuring value on every ratio feature (no rejects, no entropy, no
DNS errors). The model cannot tell "we did not look" from "we looked and saw nothing", and the
measured consequence was a false-alarm rate of 0.33/0.33/1.00 against a 0.01 target.

THE RULE, in one line: a value that was not measured is `None` (and NULL in ClickHouse), never
0; a measured zero stays 0.

WHAT IS HERE:

  * `coverage()` / `below_floor()` — how much of a detector's vector was actually measured.
  * `MissingAwarePreprocessor` — median-imputes the training-time neutral and appends one
    `<feature>__missing` indicator per column, so the model sees both the imputed value and
    the fact that it was imputed. This is used only when the flag is ON.
  * `masked_distance()` — a distance over observed dimensions only, rescaled to the
    full vector's dimension so a partially observed window is not systematically closer.

NOTHING HERE IS ON BY DEFAULT. `ModelConfig.missing_features` is False, `Settings.
ml_missing_features` is False, and with the flag off neither this preprocessor nor the
null-preserving assembly path is entered — the score path is the one that existed before.
"""
from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from typing import Any

import numpy as np

# A window must have at least this share of its detector's columns measured to be scored at
# all, and at least this share of the reference population's coverage to be calibrated on.
#
# WHY 0.15 AND NOT 0.5. The wide vector is 77 columns of which 63 are Zeek, and a NetFlow-only
# host legitimately measures 14 (10 host + 4 diversity): 0.18. A floor of 0.5 would call every
# such window insufficient and the flag-ON path would never score anything. 0.15 is the line
# between "the core flow features were measured" (14/79 of the telemetry union, 0.18) and "even
# the diversity table was missing" (10/79, 0.13) — the latter is the case that genuinely has no
# score in it. It is a policy knob (`ML_MIN_FEATURE_COVERAGE`), not a measured constant.
DEFAULT_MIN_COVERAGE = 0.15

# The suffix the indicator columns carry. Kept in one place so the training and scoring paths
# cannot disagree about the name of a column that only exists inside the model.
INDICATOR_SUFFIX = "__missing"


def _is_observed(value: Any) -> bool:
    """True when `value` is a real measurement (a finite number), False for None/NaN/inf."""
    if value is None:
        return False
    try:
        return math.isfinite(float(value))
    except (TypeError, ValueError):
        return False


def coverage_counts(features: Mapping[str, Any] | None,
                    names: Sequence[str]) -> tuple[int, int]:
    """The (observed, expected) column counts behind `coverage`.

    THE ONE PLACE observed-vs-expected IS COMPUTED. `coverage()` divides these two numbers and
    nothing else does the count itself, so a calibration row stores the same measurement the
    detector's score was built from rather than a second definition that can drift.
    """
    expected = len(names)
    if not expected:
        return 0, 0
    data = features or {}
    observed = sum(1 for name in names if _is_observed(data.get(name)))
    return observed, expected


def coverage(features: Mapping[str, Any] | None, names: Sequence[str]) -> float:
    """The share of `names` that carries a measured value.

    A missing column and a measured zero are different facts, and only the first counts
    against coverage. `names` empty means there is nothing to measure and the answer is 1.0
    (a detector with no vector contract cannot be under-covered).
    """
    observed, expected = coverage_counts(features, names)
    if not expected:
        return 1.0
    return observed / expected


def below_floor(features: Mapping[str, Any] | None, names: Sequence[str],
                floor: float | None = None) -> bool:
    """True when this window has too little measured data to be scored.

    `None` or a non-finite floor means "no floor configured" and nothing is excluded.
    """
    if floor is None:
        return False
    try:
        value = float(floor)
    except (TypeError, ValueError):
        return False
    if not math.isfinite(value):
        return False
    return coverage(features, names) < value


def _column_neutral(column: np.ndarray) -> float:
    """The median of a column's observed values, or 0.0 when nothing in it was observed.

    An all-missing column has no training-time neutral to fall back to. 0.0 is the honest
    placeholder there and the indicator column is 1 for every row, so the model can learn to
    ignore the value entirely — which is the correct behaviour for a feature no window has.
    """
    good = column[np.isfinite(column)]
    if good.size == 0:
        return 0.0
    return float(np.median(good))


def column_neutrals(X: np.ndarray) -> np.ndarray:
    """Per-column medians of the observed values in a (rows, columns) matrix."""
    matrix = np.asarray(X, dtype=float)
    if matrix.ndim != 2:
        raise ValueError(f"expected a 2-D matrix, got shape {matrix.shape}")
    return np.asarray([_column_neutral(matrix[:, j]) for j in range(matrix.shape[1])],
                      dtype=float)


class MissingAwarePreprocessor:
    """Median-impute + standardise, with an explicit missing indicator per column.

    THE INDICATOR IS THE POINT. Imputing the median alone would tell the model a value it
    never saw, and the model would treat it as measured. The appended 0/1 column says
    "this one was filled in", so a window whose DNS features were all imputed is separable
    from one that genuinely sat at the median.

    The fitted object (including `neutral_`) is pickled with the detector, so the scoring path
    imputes with the SAME numbers the training matrix used. That is what "training-time
    neutral" means; computing a fresh median at predict time would drift every retrain.
    """

    def __init__(self, *, indicators: bool = True) -> None:
        self.indicators = bool(indicators)
        self.neutral_: np.ndarray | None = None
        self.n_features_ = 0
        self.scaler = None  # StandardScaler, created in fit_transform
        self.fitted = False

    # -- internals -----------------------------------------------------------------------
    def _check(self, X: Any, *, expected: int | None) -> np.ndarray:
        matrix = np.asarray(X, dtype=float)
        if matrix.ndim == 1:
            matrix = matrix.reshape(1, -1)
        if matrix.ndim != 2:
            raise ValueError(f"expected a 2-D matrix, got shape {matrix.shape}")
        if expected is not None and matrix.shape[1] != expected:
            raise ValueError(
                f"expected {expected} feature column(s), got {matrix.shape[1]}: the vector "
                f"and the preprocessor disagree about the feature set"
            )
        return matrix

    def _fill(self, matrix: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        if self.neutral_ is None:
            raise ValueError("Preprocessor not fitted")
        missing = ~np.isfinite(matrix)
        filled = np.where(missing, self.neutral_, matrix)
        return filled, missing

    def _augment(self, scaled: np.ndarray, missing: np.ndarray) -> np.ndarray:
        """Append the 0/1 indicators UNScaled.

        Standardising an indicator would turn "was missing" into a z-score against how often
        that column happened to be missing in training, which is a property of the training
        sample rather than of the window being scored. Keeping it 0/1 keeps the model's input
        readable: the value column carries the imputed measurement, the indicator carries the
        fact, and neither can be mistaken for the other.
        """
        if not self.indicators:
            return scaled
        return np.hstack([scaled, missing.astype(float)])

    # -- public API ----------------------------------------------------------------------
    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        from sklearn.preprocessing import StandardScaler  # noqa: PLC0415 - optional at import

        matrix = self._check(X, expected=None)
        self.neutral_ = column_neutrals(matrix)
        self.n_features_ = matrix.shape[1]
        filled, missing = self._fill(matrix)
        scaler = StandardScaler()
        scaled = scaler.fit_transform(filled)
        self.scaler = scaler
        self.fitted = True
        return self._augment(scaled, missing)

    def transform(self, X: np.ndarray) -> np.ndarray:
        if not self.fitted or self.scaler is None:
            raise ValueError("Preprocessor not fitted")
        matrix = self._check(X, expected=self.n_features_)
        filled, missing = self._fill(matrix)
        return self._augment(self.scaler.transform(filled), missing)

    def transform_with_mask(self, X: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
        """Transformed matrix plus the observed mask over the ORIGINAL feature columns.

        The mask is what the masked distance consumes; the indicators (when enabled)
        are part of the transformed matrix but never part of the mask.
        """
        if not self.fitted or self.scaler is None:
            raise ValueError("Preprocessor not fitted")
        matrix = self._check(X, expected=self.n_features_)
        filled, missing = self._fill(matrix)
        transformed = self._augment(self.scaler.transform(filled), missing)
        return transformed, ~missing

    def indicator_columns(self) -> int:
        """How many trailing columns are missing indicators (0 when disabled)."""
        return self.n_features_ if self.indicators and self.fitted else 0


def indicator_names(names: Sequence[str]) -> list[str]:
    """The `<feature>__missing` column names for a feature set, in indicator order."""
    return [f"{name}{INDICATOR_SUFFIX}" for name in names]


def model_input_columns(names: Sequence[str], *, indicators: bool = True) -> list[str]:
    """Exactly what the model's input vector contains, column for column.

    Recorded in the artifact so the 77 values + 77 indicators are auditable by name rather
    than by position. With indicators off it is the feature list unchanged.
    """
    if not indicators:
        return list(names)
    return list(names) + indicator_names(names)


def masked_distance(point: np.ndarray, centre: np.ndarray, observed: np.ndarray) -> float:
    """Distance to `centre` over the observed dimensions only, rescaled to full width.

    A partially observed point would otherwise be CLOSER than a fully observed one simply
    because fewer terms are summed — missing data would read as similarity to the cluster,
    which is the same failure as turning a missing source into 0, only quieter. Multiplying
    by sqrt(n_total / n_observed) restores the scale: with every dimension observed it is the
    ordinary Euclidean distance, and with half observed it is the Euclidean distance over the
    half that was measured, scaled to what the full vector's distance would plausibly be.
    """
    mask = np.asarray(observed, dtype=bool)
    total = int(mask.size)
    seen = int(mask.sum())
    if total == 0 or seen == 0:
        return float("inf")
    delta = (np.asarray(point, dtype=float) - np.asarray(centre, dtype=float))[mask]
    sum_sq = float(np.dot(delta, delta))
    return math.sqrt(sum_sq * total / seen)


def null_absent_zeek(X: np.ndarray, names: Sequence[str]) -> np.ndarray:
    """Turn "the source produced no row" back into NaN in a TRAINING matrix.

    The training queries LEFT JOIN the Zeek summary and the summary coalesces each missing
    aggregate to 0, so a host Zeek never saw arrives as a row of zeroes — the same defect the
    scoring path fixes in `extract_zeek_features`. This is the matrix-side equivalent:

      * `zeek_present == 0` means the host had no Zeek row at all (a row only exists when some
        log observed it), so every Zeek column becomes NaN;
      * a family whose count column is 0 was never observed (its aggregate only exists for
        count >= 1), so that family's columns become NaN.

    Only columns named in `names` are touched, and the matrix is copied: the caller's array
    may be reused as the Gradient Boosting student's input. With the flag off this function is
    never called, so training is bit-for-bit what it was.
    """
    from weirvern.zeek_features import (  # noqa: PLC0415 - avoids an import cycle risk
        ZEEK_FAMILY_COUNT_COLUMNS,
        ZEEK_FAMILY_FEATURES,
        ZEEK_FEATURES,
        ZEEK_PRESENCE_FEATURE,
    )

    matrix = np.array(X, dtype=float, copy=True)
    index = {name: i for i, name in enumerate(names)}

    absent_row = None
    if ZEEK_PRESENCE_FEATURE in index:
        absent_row = matrix[:, index[ZEEK_PRESENCE_FEATURE]] <= 0
        if bool(absent_row.any()):
            for name in ZEEK_FEATURES:
                if name in index:
                    matrix[absent_row, index[name]] = np.nan

    for family, count_column in ZEEK_FAMILY_COUNT_COLUMNS.items():
        if count_column not in index:
            continue
        absent = matrix[:, index[count_column]] <= 0
        if not bool(absent.any()):
            continue
        for name in ZEEK_FAMILY_FEATURES[family]:
            if name in index:
                matrix[absent, index[name]] = np.nan
    return matrix


__all__ = [
    "DEFAULT_MIN_COVERAGE", "INDICATOR_SUFFIX", "MissingAwarePreprocessor", "below_floor",
    "column_neutrals", "coverage", "coverage_counts", "indicator_names", "masked_distance",
    "model_input_columns", "null_absent_zeek",
]
