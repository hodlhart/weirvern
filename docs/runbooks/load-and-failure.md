# Load, soak and failure injection

The load profile is read-only. Failure injection is done on the test deployment with the
operator watching; a failed drill is written down, not hidden.

## Load profile — executed 2026-11-11

`scripts/load_profile_read.py --seconds 60 --workers 6` against the live console, six concurrent
workers over five read routes:

| Route | n | Errors | p50 | p95 | p99 |
|---|---:|---:|---:|---:|---:|
| `/api/health` | 188 | 0 | 305.8 ms | 373.7 ms | 400.9 ms |
| `/api/anomalies?limit=50` | 188 | 0 | 136.1 ms | 193.2 ms | 199.6 ms |
| `/api/findings?limit=50` | 188 | 0 | 84.8 ms | 157.6 ms | 166.0 ms |
| `/api/settings` | 188 | 0 | 92.4 ms | 163.7 ms | 174.7 ms |
| `/api/update` | 188 | 0 | 5.0 ms | 27.9 ms | 36.2 ms |

Result JSON: `/tmp/wv-load-60s.json`. This is query load, not synthetic ingest: generating flow
or Zeek records would write into the live deployment, which this card does not do. Ingest and
model-scoring load are recorded by `scripts/slo_report.py` and the 24-hour soak.

## Soak — running

`scripts/soak_monitor.sh 1440` started on the box at 2026-11-11 12:30 UTC, sampling every five
minutes for 24 hours. It records health, pod readiness, container memory, ingest lag and active
ClickHouse parts. A sample with failed health, a non-Running live pod, or ingest lag >600 s is a
failure; a `ContainerStatusUnknown` leftover is logged as stale metadata, not as a healthy pod.
The card is not complete until the log ends with `SOAK PASS`.

## Failure matrix

| Failure | How injected | Expected | Executed |
|---|---|---|---|
| Worker restart | delete the worker pod; deployment recreates it | ready in seconds; health green; no data loss | **yes — ready in 3 s**, health green, new pod `weirvern-worker-6d4454fcf6-68m78` |
| GUI/API failure | scale GUI to zero and wait for the pod to disappear | console unreachable; API reads fail; restore to one | **yes — clean outage observed**; restore and healthz 200 took 44 s |
| ClickHouse restart | delete the ClickHouse pod; PVC persists | short write gap; schema and data intact; health recovers | **yes — ready in 42 s**, health green, 3-day TTL still active; flow count fell 5,169,770 → 5,020,179 as the TTL boundary advanced, not a schema loss. In-flight UDP records during the gap are not recoverable and are recorded as a known gap |
| Sensor loss | stop the sensor/ingest path; wait past freshness threshold | source reads stale/not measured; no false "clean" | no — requires a second sensor or a controlled segment |
| Expired certificate | use an expired test cert on a scratch listener | TLS error visible; no silent fallback | no — would require replacing the live cert; do in a scratch namespace |
| Alert delivery failure | disable Pushover; force an alert | delivery row says `not_configured`; report fails | **yes by configuration** — `PUSHOVER_ENABLED=0`; `slo_report.py` reports a breach, not green |

## Recovery targets

The PRG-0 targets are RPO 24 h and RTO 4 h. The worker restart (3 s) and GUI restore (17 s) are
well inside the RTO; the ClickHouse and node-rebuild paths remain the long poles and are covered
by `release-dr-drill.md`.

## Why the unexecuted rows are not silently green

Each row above says **no** and why. A failure that was not injected is unknown, not absent; the
30-day review must not read this table as "all failure modes passed".
