# 30-day post-launch review

Scheduled at cutover; due 30 days after the launch date. The review is a decision meeting, not a
status readout. Fill every row with a number, a date, or the word **unknown** with a reason.

## Record

| Field | Value |
|---|---|
| Launch date | |
| Version / commit | |
| Review date | launch + 30 days |
| Attendees | operator + one reviewer |
| Decision | continue / fix / roll back / retire a component |

## Success metrics

| Metric | Target | Measured | Source |
|---|---|---|---|
| Availability of the console and worker | ≥99% of 5-minute probes | | `e2e_smoke.sh` / health logs |
| Ingest lag p95 | ≤300 s | | `slo_report.py` |
| Query latency p95 | ≤2 s | | `slo_report.py` |
| Worker/model lag p95 | ≤900 s | | `slo_report.py` |
| Alert precision | not measured without an oracle; record review outcomes instead | | alert reviews |
| False pages | 0 unactionable pages per week | | alert log + operator notes |
| Coverage gaps | every required source fresh ≥95% of the month | | source freshness / SLO |
| Model changes | every promotion has shadow evidence and a rollback point | | ML board |
| Incidents | count, severity, time to detect, time to recover | | incident log |
| Backup restore | at least one verified restore in the month | | backup records |

## What to read

- `scripts/slo_report.py --json` for the month, not a single day.
- `e2e_smoke.sh` results and any skipped run (a skipped run is not a pass).
- Incident records and the alerts that produced them.
- Source freshness and the list of sources that were `not measured`.
- ML promotions, rollbacks and retirements; no promotion without its shadow soak.

## Decision

Choose one, with a reason and an owner:

- **Continue** — targets met; carry the known issues with owners and expiry.
- **Fix** — name the defect, the fix owner and the date; no new scope in the same breath.
- **Roll back** — name the version and the rollback evidence; data is not rolled back, so state
  the restore point.
- **Retire a component** — name the component, its replacement (or none), and what stops.

## Follow-up

- [ ] Decision recorded on the program board and linked to the launch record.
- [ ] Each follow-up has an owner and a date.
- [ ] Any accepted exception has an expiry; an exception without an expiry is a silent failure.
- [ ] Next review scheduled if the decision is fix or roll back.
