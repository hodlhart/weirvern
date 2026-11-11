"""Fixed-budget evaluation and promotion harness for the detection ensemble.

WHY THIS EXISTS. A score is not a decision. A candidate model can look better on a histogram
while being worse at the only thing an operator pays for: the top N alerts per day. This module
scores EVERY stored host-window (not only the alert tail), holds out whole days, and compares a
candidate with the baseline at the SAME alerts/day budget.

THE DECISION IS DELIBERATELY CONSERVATIVE. Missing labels do not promote a model; a candidate
that only produces more raw alerts does not promote; and a candidate that loses precision or
detection at the fixed budget is rejected with the reason recorded. Nothing here writes to
production tables; the caller owns the client and the report.

The live calibration population is written by `calibration.record_population` into
`ml_window_scores`; candidate models write to `ml_candidate_scores`. Both are read-only inputs.
"""
from __future__ import annotations

import json
import math
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from typing import Any

# The production models in the fused ensemble today. DBSCAN is intentionally absent: it is
# ineligible under the live calibration (observed FAR 1.0 against a 0.01 target) and must not
# be treated as a baseline vote.
DEFAULT_BASELINE_MODELS = ("Adaptive Baseline", "Isolation Forest", "Gradient Boosting")

# A window is "raw alerted" for the diagnostic when any contributing baseline model scores at
# or above the medium band. This is not the promotion gate; the fixed budget is. It exists so a
# candidate cannot claim a win merely by moving the unbounded alert count.
RAW_ALERT_SCORE = 0.60

# CE-4: only machine-verified evidence may pass the gate. `weak` is a label with unknown
# accuracy; `unknown` is a label whose source was not recorded. Neither is a verified positive.
VERIFIED_SOURCES = frozenset({"synthetic", "canary", "background"})
MIN_VERIFIED_ATTACK_WINDOWS = 1
MIN_VERIFIED_NEGATIVE_HOURS = 0.1
POLICY_VERSION = "ce4-v1"


@dataclass(frozen=True)
class ScoreRow:
    window_start: datetime
    src_addr: str
    model_name: str
    score: float

    @property
    def key(self) -> tuple[datetime, str]:
        return (self.window_start, self.src_addr)


@dataclass(frozen=True)
class Window:
    window_start: datetime
    src_addr: str
    scores: dict[str, float]

    @property
    def key(self) -> tuple[datetime, str]:
        return (self.window_start, self.src_addr)

    def fused(self, models: Iterable[str] | None = None) -> float:
        """Max fusion over the named models; missing models contribute zero, never a guess."""
        want = set(models or self.scores)
        return float(min(0.99, max((self.scores.get(name, 0.0) for name in want), default=0.0)))


@dataclass(frozen=True)
class Selected:
    window_start: datetime
    src_addr: str
    score: float
    day: date


@dataclass
class Metrics:
    name: str
    budget_per_day: int
    days: int
    windows: int
    selected: int
    alerts_per_day: float
    raw_alerts_per_day: float
    precision: float | None = None
    detection_rate: float | None = None
    false_alarms_per_host_day: float | None = None
    episode_count: int = 0
    latency_min: float | None = None
    explanation_coverage: float | None = None
    labels_available: bool = False
    verified_attack_windows: int = 0
    verified_negative_hours: float | None = None
    verification_coverage: float | None = None
    weak_only_selected: int = 0
    unlabelled_selected: int = 0
    clean_replay_false_alarms_per_host_day: float | None = None
    live_precision: str = "not measured"
    distribution: dict[str, dict[str, float]] = field(default_factory=dict)
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "budget_per_day": self.budget_per_day, "days": self.days,
            "windows": self.windows, "selected": self.selected,
            "alerts_per_day": round(self.alerts_per_day, 4),
            "raw_alerts_per_day": round(self.raw_alerts_per_day, 4),
            "precision": _rounded(self.precision), "detection_rate": _rounded(self.detection_rate),
            "false_alarms_per_host_day": _rounded(self.false_alarms_per_host_day),
            "episode_count": self.episode_count, "latency_min": _rounded(self.latency_min),
            "explanation_coverage": _rounded(self.explanation_coverage),
            "labels_available": self.labels_available,
            "verified_attack_windows": self.verified_attack_windows,
            "verified_negative_hours": _rounded(self.verified_negative_hours),
            "verification_coverage": _rounded(self.verification_coverage),
            "weak_only_selected": self.weak_only_selected,
            "unlabelled_selected": self.unlabelled_selected,
            "clean_replay_false_alarms_per_host_day":
                _rounded(self.clean_replay_false_alarms_per_host_day),
            "live_precision": self.live_precision,
            "distribution": self.distribution,
            "reasons": list(self.reasons),
        }


@dataclass(frozen=True)
class Decision:
    promote: bool
    reasons: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {"promote": self.promote, "reasons": list(self.reasons)}


def _rounded(value: float | None) -> float | None:
    return None if value is None else round(float(value), 4)


def as_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if value is None:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _day(value: datetime) -> date:
    return value.astimezone(UTC).date() if value.tzinfo else value.date()


def build_windows(rows: Iterable[ScoreRow]) -> dict[tuple[datetime, str], Window]:
    """Group raw per-model rows into host-windows, preserving every model's score."""
    out: dict[tuple[datetime, str], Window] = {}
    for row in rows:
        if not row.src_addr or row.window_start is None or not math.isfinite(row.score):
            continue
        key = row.key
        entry = out.get(key)
        if entry is None:
            entry = Window(row.window_start, row.src_addr, {})
            out[key] = entry
        # ReplacingMergeTree can leave duplicate keys; the caller normally reads FINAL, but a
        # last-write-wins map keeps a duplicated fixture deterministic too.
        entry.scores[row.model_name] = row.score
    return out


def score_distribution(windows: Iterable[Window], models: Iterable[str]) -> dict[str, dict[str, float]]:
    """Per-model count/quantiles/saturation, including benign windows, not just alerts."""
    names = list(models)
    values: dict[str, list[float]] = {name: [] for name in names}
    for window in windows:
        for name in names:
            score = window.scores.get(name)
            if score is not None and math.isfinite(score):
                values[name].append(float(score))
    out: dict[str, dict[str, float]] = {}
    for name, scores in values.items():
        ordered = sorted(scores)
        n = len(ordered)
        if not n:
            out[name] = {"count": 0}
            continue
        def q(p: float, values: list[float] = ordered, count: int = n) -> float:
            return values[min(count - 1, max(0, int(round((count - 1) * p))))]
        out[name] = {
            "count": float(n), "p50": round(q(0.50), 4), "p90": round(q(0.90), 4),
            "p99": round(q(0.99), 4), "max": round(ordered[-1], 4),
            "saturated": round(sum(1 for s in ordered if s >= 0.95) / n, 4),
        }
    return out


def select_fixed_budget(scores: dict[tuple[datetime, str], float], budget_per_day: int,
                        *, days: int | None = None) -> list[Selected]:
    """Top `budget_per_day` windows per UTC day; deterministic tie-break.

    The budget is enforced per day, not by a global score threshold. A candidate cannot buy
    recall by alerting more: both sides get the same number of slots.
    """
    limit = max(0, int(budget_per_day))
    by_day: dict[date, list[tuple[datetime, str, float]]] = {}
    for (window_start, src_addr), score in scores.items():
        if not math.isfinite(float(score)):
            continue
        by_day.setdefault(_day(window_start), []).append((window_start, src_addr, float(score)))
    selected: list[Selected] = []
    allowed_days = sorted(by_day)[-days:] if days else sorted(by_day)
    for day in allowed_days:
        ranked = sorted(by_day[day], key=lambda item: (-item[2], item[1], item[0]))
        for window_start, src_addr, score in ranked[:limit]:
            selected.append(Selected(window_start, src_addr, score, day))
    return selected


def _label_index(labels: Iterable[dict[str, Any]]) -> dict[tuple[datetime, str], dict[str, Any]]:
    out: dict[tuple[datetime, str], dict[str, Any]] = {}
    for item in labels:
        when = as_datetime(item.get("window_start"))
        addr = str(item.get("src_addr") or "").strip()
        if when is None or not addr:
            continue
        out[(when, addr)] = dict(item)
    return out


def _episodes(selected: Iterable[Selected], gap_minutes: int = 30) -> int:
    by_host: dict[str, list[datetime]] = {}
    for item in selected:
        by_host.setdefault(item.src_addr, []).append(item.window_start)
    episodes = 0
    for times in by_host.values():
        ordered = sorted(times)
        if not ordered:
            continue
        episodes += 1
        for previous, current in zip(ordered, ordered[1:], strict=False):
            if (current - previous) > timedelta(minutes=gap_minutes):
                episodes += 1
    return episodes


def measure(windows: dict[tuple[datetime, str], Window], *, models: Iterable[str],
            budget_per_day: int, name: str, labels: Iterable[dict[str, Any]] = (),
            days: int | None = None, gap_minutes: int = 30,
            explanations: dict[tuple[datetime, str], Any] | None = None) -> Metrics:
    """Measure one policy at a fixed budget. No writes; all inputs are caller-owned."""
    models = tuple(models)
    scores = {key: window.fused(models) for key, window in windows.items()}
    selected = select_fixed_budget(scores, budget_per_day, days=days)
    by_day: dict[date, int] = {}
    for key, _score in scores.items():
        by_day[_day(key[0])] = by_day.get(_day(key[0]), 0) + 1
    days_measured = max(1, len(by_day) if not days else min(days, len(by_day) or 1))
    raw = sum(1 for score in scores.values() if score >= RAW_ALERT_SCORE)
    label_index = _label_index(labels)

    def _tier(item: dict[str, Any]) -> str:
        source = str(item.get("label_source") or "").strip().lower()
        if source in VERIFIED_SOURCES:
            return "verified"
        if source == "weak":
            return "weak"
        return "unknown"

    def _label_kind(item: dict[str, Any]) -> str:
        return str(item.get("label") or "").strip().lower()

    verified_attack = {key for key, item in label_index.items()
                       if _label_kind(item) == "attack" and _tier(item) == "verified"}
    verified_benign = {key for key, item in label_index.items()
                       if _label_kind(item) == "benign" and _tier(item) == "verified"}
    labels_available = bool(label_index)
    true_selected = [item for item in selected
                     if (item.window_start, item.src_addr) in verified_attack]
    false_selected = [item for item in selected
                      if (item.window_start, item.src_addr) in verified_benign]
    selected_label_tiers = [
        _tier(label_index[(item.window_start, item.src_addr)])
        for item in selected if (item.window_start, item.src_addr) in label_index
    ]
    weak_only_selected = sum(1 for tier in selected_label_tiers if tier in ("weak", "unknown"))
    unlabelled_selected = sum(
        1 for item in selected if (item.window_start, item.src_addr) not in label_index
    )
    verification_coverage = (
        (len(selected) - weak_only_selected - unlabelled_selected) / len(selected)
        if selected else None
    )
    negative_hours = 0.0
    for _key, item in label_index.items():
        if _label_kind(item) == "benign" and _tier(item) == "verified":
            try:
                negative_hours += max(0.0, float(item.get("duration_min") or 5.0)) / 60.0
            except (TypeError, ValueError):
                negative_hours += 5.0 / 60.0
    clean_replay_false = [
        item for item in false_selected
        if str((label_index.get((item.window_start, item.src_addr)) or {})
               .get("label_source") or "").lower() == "background"
    ]
    precision = (len(true_selected) / len(selected)) if labels_available and selected else None
    detected = {(item.window_start, item.src_addr) for item in true_selected}
    detection_rate = (len(detected) / len(verified_attack)) if labels_available and verified_attack else None
    # The denominator is every observed host-day, not just the selected slots: otherwise a
    # candidate that alerts on one host looks like it has the same false-alarm rate as one
    # that alerts across ten.
    host_days = {(window.src_addr, _day(window.window_start)) for window in windows.values()}
    false_per_host_day = (len(false_selected) / len(host_days)) if labels_available and host_days else None
    clean_replay_false_per_host_day = (
        len(clean_replay_false) / len(host_days) if labels_available and host_days else None
    )
    latency = None
    if labels_available and true_selected:
        starts: list[float] = []
        for selected_item in true_selected:
            label = label_index.get((selected_item.window_start, selected_item.src_addr)) or {}
            start = as_datetime(label.get("start"))
            if start is not None:
                starts.append(max(0.0, (selected_item.window_start - start).total_seconds() / 60.0))
        if starts:
            latency = sum(starts) / len(starts)
    explanation = None
    if explanations is not None and selected:
        explanation = sum(1 for selected_item in selected
                          if bool(explanations.get((selected_item.window_start,
                                                    selected_item.src_addr)))) / len(selected)
    return Metrics(
        name=name, budget_per_day=int(budget_per_day), days=days_measured,
        windows=len(windows), selected=len(selected),
        alerts_per_day=len(selected) / days_measured, raw_alerts_per_day=raw / days_measured,
        precision=precision, detection_rate=detection_rate,
        false_alarms_per_host_day=false_per_host_day,
        episode_count=_episodes(selected, gap_minutes), latency_min=latency,
        explanation_coverage=explanation, labels_available=labels_available,
        verified_attack_windows=len(verified_attack),
        verified_negative_hours=round(negative_hours, 4) if labels_available else None,
        verification_coverage=verification_coverage,
        weak_only_selected=weak_only_selected,
        unlabelled_selected=unlabelled_selected,
        clean_replay_false_alarms_per_host_day=clean_replay_false_per_host_day,
        distribution=score_distribution(windows.values(), models),
    )


def promote(baseline: Metrics, candidate: Metrics, *, tolerance: float = 0.0,
            coverage: dict[str, Any] | None = None) -> Decision:
    """The promotion gate. Conservative by construction.

    A candidate must be measured on labels, must not regress detection, precision or false
    alarms, and must show a real gain -- not merely more raw alerts. The fixed budget already
    caps both sides to the same number of slots, so a candidate cannot win by flooding.
    """
    reasons: list[str] = []
    # GT-3: a model cannot be promoted on a source that was not measured. This is deliberately
    # separate from model accuracy: a healthy score over a dead feed is not evidence.
    if coverage is not None and not coverage.get("promotion_ok", False):
        missing = coverage.get("required_missing") or []
        reasons.append("source coverage is not usable"
                       + (": " + ", ".join(str(x) for x in missing) if missing else ""))
    if not candidate.labels_available:
        reasons.append("no labels: precision, detection and false alarms are unmeasured")
    # CE-4: verified evidence, not a label count. A weak-only or unlabelled candidate is not
    # measurable no matter how attractive its alert count looks.
    if candidate.verified_attack_windows < MIN_VERIFIED_ATTACK_WINDOWS:
        reasons.append(
            f"verified attack windows {candidate.verified_attack_windows} < "
            f"{MIN_VERIFIED_ATTACK_WINDOWS}; weak/unknown labels are not ground truth"
        )
    if (candidate.verified_negative_hours is None
            or candidate.verified_negative_hours < MIN_VERIFIED_NEGATIVE_HOURS):
        reasons.append(
            f"verified negative hours {candidate.verified_negative_hours} < "
            f"{MIN_VERIFIED_NEGATIVE_HOURS}"
        )
    if candidate.weak_only_selected and candidate.verification_coverage is not None \
            and candidate.verification_coverage <= 0:
        reasons.append("every selected window has only weak or unknown labels")
    if (candidate.clean_replay_false_alarms_per_host_day is not None
            and candidate.clean_replay_false_alarms_per_host_day > candidate.budget_per_day):
        reasons.append("clean-replay false alarms exceed the page budget")
    if not baseline.labels_available:
        reasons.append("baseline has no labels: there is no comparison to win")
    if candidate.detection_rate is None or baseline.detection_rate is None:
        reasons.append("detection rate is not measurable for both sides")
    elif candidate.detection_rate < baseline.detection_rate - tolerance:
        reasons.append(f"detection regressed ({candidate.detection_rate:.3f} < "
                       f"{baseline.detection_rate:.3f})")
    if candidate.precision is None or baseline.precision is None:
        reasons.append("precision is not measurable for both sides")
    elif candidate.precision < baseline.precision - tolerance:
        reasons.append(f"precision regressed ({candidate.precision:.3f} < "
                       f"{baseline.precision:.3f})")
    if (candidate.false_alarms_per_host_day is not None
            and baseline.false_alarms_per_host_day is not None
            and candidate.false_alarms_per_host_day > baseline.false_alarms_per_host_day + tolerance):
        reasons.append("false alarms per host/day increased")
    if candidate.alerts_per_day > baseline.budget_per_day + 1e-9:
        reasons.append("candidate exceeded the fixed alert budget")
    if (candidate.raw_alerts_per_day > baseline.raw_alerts_per_day
            and (candidate.precision is None or baseline.precision is None
                 or candidate.precision <= baseline.precision + tolerance)):
        reasons.append("candidate only produced more raw alerts; precision did not improve")
    if (not reasons
            and candidate.precision is not None and baseline.precision is not None
            and candidate.precision <= baseline.precision + tolerance
            and candidate.detection_rate is not None and baseline.detection_rate is not None
            and candidate.detection_rate <= baseline.detection_rate + tolerance):
        reasons.append("no measured improvement at the selected budget")
    return Decision(promote=not reasons, reasons=reasons)


def load_window_scores(client: Any, *, days: int = 7,
                       models: Iterable[str] | None = None) -> list[ScoreRow]:
    """Read the calibration population; no writes. Missing table is an explicit failure."""
    wanted = list(models or DEFAULT_BASELINE_MODELS)
    query = ("SELECT window_start, src_addr, model_name, score "
             "FROM weirvern.ml_window_scores FINAL "
             "WHERE window_start >= now() - INTERVAL %(days)s DAY")
    params: dict[str, Any] = {"days": int(days)}
    if wanted:
        query += " AND model_name IN %(models)s"
        params["models"] = tuple(wanted)
    rows = client.query(query, parameters=params).result_rows
    out: list[ScoreRow] = []
    for row in rows:
        when = as_datetime(row[0])
        if when is None:
            continue
        try:
            score = float(row[3])
        except (TypeError, ValueError):
            continue
        out.append(ScoreRow(when, str(row[1] or ""), str(row[2] or ""), score))
    return out


def load_candidate_scores(client: Any, model_name: str, *, days: int = 7) -> list[ScoreRow]:
    """Read one shadow candidate's scores; the candidate is never promoted from here."""
    # `ml_candidate_scores` is a plain MergeTree (it keeps the append-only evidence trail), so
    # FINAL is invalid there. Pick the newest row per (model, window, host) explicitly instead.
    rows = client.query(
        "SELECT window_start, src_addr, model_name, argMax(score, computed_at) AS score "
        "FROM weirvern.ml_candidate_scores "
        "WHERE model_name = %(name)s AND window_start >= now() - INTERVAL %(days)s DAY "
        "GROUP BY window_start, src_addr, model_name",
        parameters={"name": str(model_name), "days": int(days)},
    ).result_rows
    out: list[ScoreRow] = []
    for row in rows:
        when = as_datetime(row[0])
        if when is None:
            continue
        try:
            score = float(row[3])
        except (TypeError, ValueError):
            continue
        out.append(ScoreRow(when, str(row[1] or ""), str(row[2] or ""), score))
    return out


def labels_from_json(path: str | Path) -> list[dict[str, Any]]:
    payload = json.loads(Path(path).read_text())
    if not isinstance(payload, list):
        raise ValueError("labels must be a JSON list of {src_addr, window_start, label}")
    return [dict(item) for item in payload if isinstance(item, dict)]
