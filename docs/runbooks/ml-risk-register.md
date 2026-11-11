# ML risk register

Reviewed at every monthly ML review and at the 30-day launch review. A risk without an owner
and a review date is an opinion, not a register entry.

| # | Risk | Likelihood | Impact | Mitigation | Owner | Review |
|---|---|---|---|---|---|---|
| R1 | **Missed attack** — a real intrusion scores below the page gate or has no flow signature | Medium | Critical | fixed-budget detection on seeded scenarios; held-out days; source-coverage gate; alert only on evidence; `not measured` never becomes clean | Operator | 2026-12-11 |
| R2 | **Alert fatigue** — pages exceed the operator's attention budget | High | High | 2 pages/host/24 h; high/critical only; episodes collapse windows; false pages counted in the 30-day review | Operator | 2026-12-11 |
| R3 | **Automated ground-truth bias** — synthetic/canary labels overfit the generator | Medium | High | hold out whole scenarios and days; weak labels never `verified`; live precision `not measured`; contamination `unknown` | Operator | 2027-02-11 |
| R4 | **Concept drift** — the network changes and the baseline silently ages | High | High | drift PSI per model/host; staleness on Models; monthly re-baseline; retrain is deliberate, not automatic | Operator | 2026-12-11 |
| R5 | **Telemetry / source gap** — a missing feed is read as quiet | Medium | Critical | per-source freshness (fresh/stale/not measured/failed/unknown); required-source coverage gate; no zero for absent data | Operator | 2026-12-11 |
| R6 | **Feedback-loop collapse** — the system learns from its own alerts or from an operator's silence | Medium | High | no operator-label queue; review outcomes are evidence only, not training labels; rejected candidates recorded; fixed-budget evaluation independent of production alerts | Operator | 2027-02-11 |
| R7 | **Adversarial or poisoned input** — an attacker shapes traffic to train or evade the model | Low | Critical | documented ranges excluded from learning; canary/honeypot positives; no auto-promotion without shadow; source provenance; audit trail | Operator | 2027-02-11 |
| R8 | **Automation acts too broadly** — a bad promotion blocks or pages beyond the envelope | Low | High | 14-day shadow, bounded canary, rollback thresholds, one promotion in flight, kill switches | Operator | 2026-12-11 |
| R9 | **Upstream image compromise** — a third-party Critical finding is reachable | Medium | High | SBOM + Grype + CVE gate; third-party Critical findings recorded as accepted upstream risk with owner and next scan | Operator | 2026-12-11 |
| R10 | **Privacy / retention breach** — flow or audit data kept longer than stated | Low | High | 365-day audit TTL, 3/7/30–90-day data retention, `capture_password` off, no payloads | Operator | 2026-12-11 |

## Residual risk statement

R1 and R5 are the pair that can make a quiet console look safe: a missed attack and a missing
source are different failures and must never be collapsed into "no alerts". R3, R6 and R7 are the
reasons the program does not use a human label queue: the alternative is not "no labels", it is
machine-generated labels with provenance and an explicit `unknown`.
