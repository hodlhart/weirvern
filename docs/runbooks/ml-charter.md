# ML charter and autonomy envelope

**Status:** operator-approved 2026-11-11. This is the definition of "best" for the autonomous
detector and the safety envelope it may operate inside. No per-model approval is required inside
the envelope.

## 1. Who and what

| Question | Answer |
|---|---|
| Operator / consumer | Samuel Hart, single operator; alerts are consumed in the Weirvern console and the configured page channel |
| Decisions supported | investigate a host, block a destination through Sluice, escalate, tune/ticket, or ignore |
| Page vs ticket | **Page:** high or critical episode, at most 2 pages per host per 24 h. **Ticket:** every other anomaly, finding or drift notice, in the console and alert log |
| Alert channels | Console is the system of record; Pushover is the page channel when configured. Log-only is **not** paging and is recorded as `not_configured` |
| Coverage expected | flows, Zeek conn/SSL/DNS/notice, identity observations; a missing source is `not measured`, never zero |
| Retention / privacy | flows 3 days, aggregates 7 days, Zeek 30–90 days, audit 365 days, backups 14 days local + 14 days off-cluster; `capture_password` stays off |
| Review cadence | weekly shadow/drift inspection; monthly fixed-budget review; quarterly re-baseline; 30-day post-launch review |

## 2. Non-goals and what will not be measured

- No payload inspection, TLS interception, credential capture or endpoint EDR.
- No automatic network response beyond a Sluice block that the operator's policy permits.
- No claim of **live precision** without an oracle. Precision is measured only at a fixed budget
  against generated/held-out scenarios; the live number is `not measured` with a reason.
- No compliance certification (SOC 2, ISO 27001) is implied by this program.
- The following risks are **not measured** in this release: insider abuse by an authorized
  operator, encrypted command-and-control that produces no flow-shape signal, and compromise of
  an upstream image before it reaches this deployment. They are named so a quiet dashboard is not
  mistaken for their absence.

## 3. Autonomy envelope

The operator sets this once; automation may promote, canary and retire **inside** these bounds.

| Control | Bound |
|---|---|
| Page budget | `EPISODE_PAGE_BUDGET=2` per host per 24 h; `EPISODE_PAGE_MIN_SEVERITY=high` |
| Allowed model families | Isolation Forest, Gradient Boosting, DBSCAN, Adaptive Baseline; specialists (DNS, TLS/JA4, beacon, graph, flow-shape, identity) stay shadow-only until they pass the same gate |
| Shadow soak before first canary | **14 days** of shadow scores with a fixed budget and no production effect |
| Canary size / duration | At most 5% of hosts (or one sensor), at least 72 hours, one candidate at a time |
| Rollback thresholds | 24 h page volume >2× the incumbent; fixed-budget precision@k worse than incumbent by >10% relative; any seeded attack the incumbent caught is missed; p95 scoring latency >2×; a required source becomes unreadable. Any one triggers rollback |
| Maximum promotion rate | One production promotion per 14 days; never more than one promotion in flight; a failed canary pauses the program, not just that model |
| Kill switch | `ML_ELIGIBILITY=false` removes uncalibrated models from the fusion; `EPISODE_PAGE_BUDGET=0` stops pages; `ML_SHADOW=false` stops shadow. Applied through Settings, no code change |
| Human role | May inspect canary/attack incidents; **not** a labeling queue and not a per-model approval step |

## 4. How a candidate moves

1. Shadow-only for 14 days at the fixed budget; missing labels stay `unknown`.
2. Machine gate compares precision@k, detection, false alarms per host/day, latency and
   explanation coverage against the incumbent on the same window.
3. Canary at the bound above; automated checks gate continuation.
4. Promote; record the decision, artifact and rollback point. A candidate that loses is recorded
   as rejected — it is not promoted on a plausible story.

## 5. Review

The operator re-reviews this envelope at OP-3 and after any incident that changes the page
budget, a model family, or the coverage contract. An exception without an expiry is a silent
failure.
