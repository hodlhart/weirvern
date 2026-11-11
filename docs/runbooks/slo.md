# SLO board

`scripts/slo_report.py` measures the promises in `production-readiness.md` and exits non-zero
when a measured SLO is outside its bound **or cannot be measured**. It does not turn an absent
metric green.

Run:

```sh
WEIRVERN_SENSOR_HOST=root@<node> python scripts/slo_report.py
```

| SLO | Bound | Runbook | Measured 2026-11-11 |
|---|---|---|---|
| Ingest freshness | ≤ 300s | `source-coverage.md` | 28s OK |
| Query latency | ≤ 2.0s | `production-readiness.md` | 0.42s OK |
| Worker/model score freshness | ≤ 900s | `source-coverage.md` | 128s OK |
| Model training freshness | ≤ 6h | `production-readiness.md` | 220s OK |
| Console TLS expiry | ≥ 14 days | `security-surface.md` | 69.9 days OK |
| Off-cluster backup age | ≤ 36h | `release-dr-drill.md` | 0.9h OK |
| Alert delivery | successful delivery exists | `production-readiness.md` | **not_configured** |

## Alert delivery

Pushover is disabled (`PUSHOVER_ENABLED=0`); alerts are recorded log-only. The SLO report prints
`not_configured` and exits non-zero. That is deliberate: a delivery SLO with no delivery channel
is not a pass. The operator must either configure Pushover or accept the log-only posture in the
risk register. This is the one SLO that is currently not met.

## Alerting and runbooks

- The report is the alert source: a cron wrapper can run it hourly and print only on non-zero.
- Every SLO row names its runbook.
- An unreadable ClickHouse or TLS endpoint becomes `unknown`; it is never converted to a pass.

## Dashboard

The report is the single readable SLO board; the same values are what the Health view's component
probes summarize. The console does not compute a fabricated percentage when a probe is missing.
