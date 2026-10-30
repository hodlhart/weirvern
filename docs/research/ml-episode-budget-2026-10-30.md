# Episodes and page budget — 2026-10-30

**Purpose:** PRD-1 evidence. One host incident is many five-minute anomaly windows; the queue
must show the incident, and only one high/critical episode per host should page.

## What shipped

- `weirvern/alert_episodes` schema (`037_alert_episodes.sql`, ReplacingMergeTree).
- `weirvern/episodes.py`: 30-minute gap grouping, highest severity/score, role carry-through,
  per-host page budget, claim-once semantics.
- Worker: refresh episodes after a detection sweep, claim one pageable window per episode, pass
  the decision to `push_alert`; non-pageable windows are audited as `budget`, not dropped.
- `/api/episodes`: the incident view (`occurrences`, `pageable`, `page_reason`, `paged_at`).
- Raw `netflow_anomalies` rows remain untouched.

## Live replay

Read the production 24-hour anomaly table and grouped it in memory without writing:

| metric | value |
|---|---:|
| anomaly rows | 2,615 |
| episodes (30-minute gap) | **91** |
| hosts | 20 |
| pageable at 2/host, high+ | **27** |
| critical episodes | 31 |
| high episodes | 5 |
| medium episodes | 25 |
| low episodes | 30 |

The busiest episodes contain 288 windows but are one incident; that is the point of the layer.
The page budget is applied per host, so a noisy host cannot consume the queue.

## Determinism / grouping proof

`tests/test_episodes.py` proves:

- three continuous five-minute windows → one episode;
- a 31-minute silence → two episodes;
- hosts never share an episode;
- budget marks only the highest-ranked episode for a host;
- medium never pages, and a claimed episode consumes the host's budget.

`tests/test_episodes_db.py` proves the writer emits all 16 columns in order, and
`tests/test_alert_budget.py` proves `_pageable=False` is audited as `budget` without sending.
A live ClickHouse run of the migration and writer produced a 2-window episode, claimed it once,
and on refresh preserved `paged_at` and did not page it again.

## Seeded regression

Disposable-ClickHouse eval after the change: **263 verdicts**, scan critical, beacon medium,
exfil critical, 1/9 benign high+, busiest host 26/60, deterministic. Unchanged.

## Honest limits

- The budget is per **host**; `role` is carried on the episode for the next tuning pass but there
  is no role-specific budget value yet.
- The web UI has the `/api/episodes` endpoint but the Anomalies tab does not yet render an
  episode column; the existing grouped-anomaly view remains the operator surface.
- Deployment/schema application is a separate operator decision.
