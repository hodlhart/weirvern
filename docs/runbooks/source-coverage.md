# Source coverage, clock and replay

## Coverage snapshot (2026-11-11 05:03 UTC)

| Source class | Evidence table | Rows | Newest | Age | State |
|---|---|---:|---|---:|---|
| NetFlow | `flows` | 5,099,225 | 22:59:30Z | 4m 6s | fresh |
| NetFlow aggregate | `flows_aggregated` | 897,944 | — | — | fresh (modelled window table) |
| Zeek connection | `zeek_conn` | 5,549,440 | 22:59:58Z | 3m 38s | fresh |
| Zeek DNS/TLS | `zeek_dns` / `zeek_ssl` | 352,123 / 139,365 | latest via health | <15m | fresh |
| Zeek notice | `zeek_notice` | 2,072 | latest via health | <15m | fresh |
| Findings | `netflow_anomalies` | 22,702 | 23:01:25Z | 2m 12s | fresh |
| Sensor heartbeat | `sensor_status` | live | health heartbeat | < stale bound | running |

The health payload reports `ingest_freshness` and `zeek_freshness` separately. A deployment with
no Zeek sensor is reported as `not applicable`, not as a passing freshness probe; an empty
`zeek_conn` on a deployed sensor is a failure. `readiness.py` uses the same rule for the local
baseline: missing data is `unknown`/`warming`, never a quiet network.

`tests/test_ml_source_coverage.py` proves every feature-bearing Zeek log and the NetFlow
features reach the models; `tests/test_health_probes.py` proves stale/empty/missing sources do
not read as healthy. `tests/test_ml_table_coverage.py` keeps the deliberate no-host-feature
exemptions from silently becoming “unused”.

## Clock and staleness

`scripts/source_health.py` is the executable gate. It reads each source's count, newest event
and age against ClickHouse's own `now()`, and exits non-zero when a required source is empty,
stale, or has an event more than 120 seconds in the future. `zeek_*` and `sensor_status` are
optional sources: an empty optional source is reported, not used to fail a flow-only deployment.

Run:

```sh
WEIRVERN_SENSOR_HOST=root@<sensor> python scripts/source_health.py --json
```

Measured at the snapshot: flows 247s, `zeek_conn` 219s, anomalies 132s; no source timestamp was
in the future. Live gate output (2026-11-11 23:08 local / 05:08 UTC) was `ok=true` with all
required sources fresh. `zeek_notice` was 1544s old and correctly reported `stale` as an optional
source rather than silently zeroed.

The freshness bound is 15 minutes for ingest and Zeek, matching `ingest_freshness`/`zeek_freshness`.
A source whose age cannot be read is `unknown`, not zero. A future timestamp beyond 120 seconds is
`clock_skew`, not freshness.

## Replay and restore

- A ClickHouse backup (`prod-readiness-20261111-0500`) restored into `weirvern_restore` in
  3.17s. `netflow_anomalies` matched exactly; TTL-managed flow tables were non-empty and inside
  their pre/post backup bounds, with expiry explained.
- **Exact score replay, fixed window:** `ml_window_scores` for
  `2026-11-10 22:00:00`–`22:30:00` (America/Chicago), read with `FINAL` because the table is
  `ReplacingMergeTree`:
  - live: 416 rows, `sum(cityHash64(src_addr, model_name, toString(score), model_version))`
    = `15832185913492734196`
  - restored: 416 rows, same hash `15832185913492734196`
  - `computed_at` range 22:06:15–22:31:20 on both
  No row was missing and no score changed. Without `FINAL`, the raw counts differed
  (416 vs 468) because the restored parts had not merged; that is a storage detail, not a
  replay gap.
- The archived model set was extracted and loaded: Isolation Forest v4, schema 4, 77 features,
  scored a fixed fixture at `0.1500738323`.
- `scripts/eval_detection.py` records its seed, inputs and phase, and re-runs the deterministic
  corpus with identical verdicts; `tests/test_detection_eval.py` fails if that record or the
  deterministic rerun disappears.
- The backup restore is the live-data replay path; the seeded harness is the repeatable scoring
  path. Neither claims that a production precision number exists without an oracle.

## Surfaces

- `/api/health` exposes `ingest_freshness`, `zeek_freshness`, `models`, `tables` and the sensor
  heartbeat. Missing probes are present with an explanation, not omitted.
- The Models view exposes `feature_coverage` (`baseline_features` / `model_inputs`) and model
  staleness. No percentage is computed when the denominator is unknown.
- The source coverage audit (`scripts/audit_ml_coverage.py --live`) names collected-but-unmodelled
  tables rather than presenting raw volume as model coverage.

## Operating rule

A green health line requires a **fresh, readable source with a bounded clock**. A missing source,
an empty table on a deployed sensor, or a future timestamp is a fault and must say which.
