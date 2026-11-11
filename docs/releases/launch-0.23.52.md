# Launch record — 0.23.52

| Field | Value |
|---|---|
| Launch date | 2026-11-11 |
| Version / commit | `0.23.52` / `525f30a` |
| Deployment | Single-node k3s on `weirvern.home` (CT 111) |
| Rollback target | `weirvern-worker:0.23.17`; data via `prod-readiness-20261111-044707` |
| Rollback owner | Weirvern operator |
| On-call | Single operator; escalation through the operator's normal channel |
| Review due | 2026-12-11 (30 days) |
| Decision | **continue**, with the known issues below; review template `launch-review-30d.md` |

## Cutover checks

| Check | Result |
|---|---|
| Gate | PASS (`/tmp/wv-batch3-gate.log`) |
| E2E smoke | PASS — 9 health checks, ingest→anomaly→evidence, findings, 49 settings rows, release identity 0.23.52 |
| Canary | PASS — bounded `weirvern-canary` pod, shipped config, `/api/healthz`, namespace removed |
| Code rollback | PASS — 0.23.52 → 0.23.17 → 0.23.52 |
| Data restore | PASS — scratch restore 3.17 s; exact counts and fixed-window replay |
| Model rollback | PASS — archived 7,241-file set, fixture `0.1500738323` |
| Backup | `prod-readiness-20261111-044707`, encrypted off-cluster, key operator-held |
| TLS | Console certificate valid ≥14 days at cutover; chain and hostname checked |
| Accounts | Sign-in works; rejected sign-in returns 401 and writes an auth audit row |
| Alert delivery | **not configured** (`PUSHOVER_ENABLED=0`); log-only is stated, not treated as paging |
| SLO report | Every row measured; unmeasured is unknown; alert delivery row fails by design |

## Known issues at launch

| Issue | Owner | Expiry / next action |
|---|---|---|
| Alert delivery disabled | operator | configure Pushover or accept log-only in writing |
| No registry; release tags rather than digest pulls | operator | registry prerequisite; digest deploy recorded as exception |
| Single node, no HA; RPO 24 h / RTO 4 h | operator | capacity/recovery runbook |
| 24-hour soak not yet complete | operator | REL-1; do not claim soak evidence until it finishes |
| Third-party Critical findings (goflow2, Zeek) | upstream | next base refresh; accepted upstream risk |
| Desktop small touch targets (29–39 per audit) | operator | UX follow-up; mobile targets pass |

## Abort criteria

Failed restore, broken or expired TLS, missing source that cannot be stated, alert storm or a
silently dropped page, model gate failure, or a canary health failure. On abort the previous
version keeps serving and the reason is recorded.

## Links

- Release record: `docs/releases/0.23.52.md`
- Release checklist: `docs/runbooks/release-checklist.md`
- Rollback/DR drill: `docs/runbooks/release-dr-drill.md`
- Review template: `docs/runbooks/launch-review-30d.md`
- Program board: `wv-prod-program` (this record is linked from REL-3)
