# Calibration on the scored population — 2026-10-30

**Purpose:** PRD-2 evidence. The eligibility gate existed at `c4b9756`, but its reference was the
stored alert tail. This change records every scored host-window and calibrates on that population.

## What shipped

- `ml_window_scores` schema (`038_ml_window_scores.sql`): one row per model per scored
  host-window, written **before** the threshold, agreement gate, severity and episode budget.
- `ensemble.detect_flows(..., score_population=...)`: caller-owned sink; raw scores only.
- `calibration.record_population`: best-effort write; detection continues if the store is absent.
- `calibration.run`: primary reference is `ml_window_scores` for `ML_CALIBRATION_DAYS` (default 7);
  the alert tail is a **named fallback** when the population is too small or absent.
- `calibration.eligibility`: a calibration older than the newest `ml_models.trained_at` for that
  model is stale and forces ineligible until it is recalibrated. Retraining cannot silently
  re-enable a model on its old evidence.

## Live current state (before deployment)

The live cluster has not yet produced `ml_window_scores`, so its current calibration is the tail
that the prior code used. It is still useful as the "before" side:

| model | observed FAR | target | threshold | samples |
|---|---:|---:|---:|---:|
| DBSCAN | 96.61% | 1% | 0.99 | 11,448 |
| Adaptive Baseline | 6.70% | 1% | 0.99 | 8,271 |
| Isolation Forest | 0.85% | 1% | 0.8553 | 10,396 |
| Gradient Boosting | 0.86% | 1% | 0.9891 | 6,970 |

Under `target × 3`, DBSCAN and Adaptive Baseline are ineligible; IF and GB are eligible. This is
the same decision the gate already made; the denominator is what changes after deployment.

The live alert path in the same 24 hours recorded **2,659 decisions, all `log-only`, zero sent**.
The queue is a dashboard flood, not a paging flood; PRD-1's episode budget is the layer that
reduces the review surface.

## Regression

Disposable-ClickHouse seeded eval after the change: **263 verdicts**, scan critical, beacon
medium, exfil critical, 1/9 benign high+, busiest 26/60, deterministic. The population recorder
does not alter detection; the eval database had its synthetic calibration rows cleared before the
run so the result was not contaminated by test fixtures.

## Honest limits

- Until the worker is deployed with schema 038, live calibration remains the labelled fallback.
- The population table is a 30-day TTL measurement store; it is not an alert source.
- The dashboard's calibration view still shows the stored rows; it will show the population
  reference only after the worker writes them.
- Deployment and schema application remain a separate operator decision.
