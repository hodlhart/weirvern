# LRN-1 active-learning feedback — 2026-10-31

**Purpose:** a review is a bounded, attributable adjustment, not a training label. The operator
can attach a before/after change to a host/role budget or threshold with a reason and expiry;
the adjustment is replayable, revertible and expires without touching the model artifact.

## Schema

Additive `weirvern/schema/040_ml_review_adjustments.sql`:

`adjustment_id, created_at, reviewer, scope, subject, metric, before_value, after_value,
reason, review_window_start, review_src_addr, expiry, reverted_at, revert_reason, active`.

`ReplacingMergeTree(created_at)`, ordered by `adjustment_id`, 90-day TTL after expiry.

## API

`POST /api/review` still writes the disposition. An optional `adjustment` object writes the
provenance in the same transaction:

```json
{"window_start": "...", "src_addr": "198.51.100.10", "state": "false_positive",
 "adjustment": {"metric": "page_budget", "before_value": 2, "after_value": 1,
                "reason": "duplicate vendor scan", "expiry_days": 14}}
```

`scope` defaults to `host`, `subject` to `src_addr`; metric bounds are
`page_budget 0–10`, `threshold 0–1`, `score_weight 0–1`.

## Replay, revert and expiry

- `build_adjustment` validates and clamps; a no-op is refused.
- `effective_value(base, adjustment)` returns `after` only while active, unexpired and not
  reverted; otherwise the base value.
- `revert` keeps before/after and writes `reverted_at`/`revert_reason`.
- `select_uncertain` returns at most the requested budget, closest to the band midpoint first.
- No code path writes `ml_models` or `netflow_anomalies`.

## Dashboard

The review cell renders a small `metric before → after` provenance chip when an adjustment is
attached; the title carries scope, subject, reason, reviewer and `expired or reverted` state.
The adjustment index is read separately, so a missing table is an explicit provenance error,
not a silent “none”.

## Verification

- `tests/test_active_learning.py`: 6 tests — before/after/reason/reviewer/expiry, replay,
  revert, expiry, bounds, no-op refusal, bounded uncertain queue, adjustment-store-only write.
- Gate PASS.
- No production schema application, model retrain or alert-path change.

## Limits

- The current UI exposes the provenance chip, not a free-form adjustment editor; an operator
  or automation supplies the adjustment object through the review API.
- Adjustments are host-scoped by default; role-scoped adjustments remain an explicit subject.
- Expiry is provenance-preserving; the row remains for review after it stops being effective.
