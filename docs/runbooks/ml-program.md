# ML program runbook — continuous re-baseline and retirement

**Status:** active program runbook. This is the operating contract for the Weirvern ML work,
not a one-time checklist.

## 1. Owners and cadence

| Role | Owner | Cadence |
|---|---|---|
| Program accountable | Samuel Hart | monthly review |
| Execution / evidence | Hermes Agent | weekly, and every card close |
| Fixed-budget review | Operator (single-token reviewer) | monthly and before any promotion |
| Release approval | Operator | every production change |

Weekly: inspect the Models tab shadow channels and drift channel; confirm no channel is
silently empty. Monthly: fixed-budget comparison and calibration review. Quarterly: re-baseline
the feature set and retire models that lose. After any sensor or network change: rerun coverage
before trusting a zero or a quiet channel.

## 2. Metrics

- **Alert precision / false-positive rate** at the fixed page budget, not at an unbounded score
  threshold.
- **Pages per day** and episode count; a dashboard flood is not a paging flood.
- **Calibration observed FAR** against the target; the eligibility gate uses target × 3.
- **Source coverage** per table (flows, DNS, TLS/JA4, identity, Zeek conn); zero-row sources are
  named, never trained on.
- **Drift PSI** per model/host, with the manual `retrain_policy` recommendation.
- **Latency** and **failure mode** for each shadow channel.

## 3. Fixed-budget gate

The comparison harness is `scripts/eval_detection.py` against the disposable ClickHouse corpus.
Every candidate reports the same budget, the same seeded attacks, the benign false-positive
count and its latency. A candidate that does not beat the current baseline at that budget is
recorded as rejected; it is not promoted on a plausible story.

## 4. Retirement rule

Retire a model or feature when any of:

1. it fails the fixed-budget gate for **two consecutive monthly reviews**;
2. its source coverage is zero for **30 days** and it cannot state an explicit unavailable;
3. its drift notice is `drift` for **two consecutive reviews** with no approved re-baseline;
4. its alert contribution is indistinguishable from a duplicate detector.

Retirement means remove it from the production registry and evidence path, archive the
comparison, and keep the commit history. It does **not** mean delete the data or silently
change thresholds. No retirement or re-baseline is automatic.

## 5. Rollback

- Production image: restore the previous kustomization tag and roll out; do not edit a running
  model in place.
- Shadow layer: set `ML_SHADOW=false` to stop the shadow pass; detection continues.
- Schema: all ML schema changes are additive; rollback is the previous image, not a table drop.
- Model artifact: restore the last gated artifact and re-run calibration; a retrain is never
  automatic.
- Any rollback is recorded on the affected card and in the next review.

## 6. Program gate and blockers

Before closing the program, run every board's stats and list:

```
hermes kanban --board wv-ml-foundation stats
hermes kanban --board wv-ml-production stats
hermes kanban --board wv-ml-sources stats
hermes kanban --board wv-ml-temporal stats
hermes kanban --board wv-ml-learning stats
```

A blocked card is not stale if this section names its reason, owner and review date. The gate
fails if a blocked card is absent from this table, or if a card is closed without a gate log and
a commit.

| Blocked card | Reason | Owner | Reviewed |
|---|---|---|---|
| LRN-1 active learning | review feedback path not yet implemented | operator / Hermes | 2026-10-31 |

When LRN-1 is implemented, remove its row in the same change that closes it. A card may not be
closed while it is listed here as blocked.

## 7. Current inventory (2026-10-31)

- `wv-ml-foundation`: 4 done / 0 blocked
- `wv-ml-production`: 3 done / 0 blocked
- `wv-ml-sources`: 4 done / 0 blocked
- `wv-ml-temporal`: 3 done / 0 blocked
- `wv-ml-learning`: 1 done (LRN-2 rejection) / 1 done (this runbook) / 1 blocked (LRN-1)

## 8. Approval boundary

No production alert path, model artifact, UI deployment or schema application without operator
approval. Shadow work writes only candidate/measurement tables. The live cluster remains the
last approved release until the release ritual is run and verified.
