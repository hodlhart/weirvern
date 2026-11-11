# Production readiness: scope, targets and risk

This is the definition of production grade for this deployment. It is deliberately
specific about what is supported and what is not. A deployment that claims more
availability than it can measure is not production grade; it is an unowned promise.

## Supported deployment

- One k3s node running the worker, GUI, ClickHouse, goflow2 and the scanner.
- One sensor node carrying the dedicated capture NIC and Zeek.
- Single replica of the worker and GUI. ClickHouse is a single StatefulSet.
- **No high availability.** A node or disk loss is an outage, recovered from backup
  and a rebuild. HA is a separate project, not an implied property of this one.

The supported topology is the one in `docs/deployment.md`; the limitations in
`docs/architecture.md` and `docs/operations.md` remain authoritative.

## Targets

| Property | Target | Measurement |
|---|---|---|
| Console/API availability | 99.5% monthly, best effort | External health probe; a failed probe is an incident, not a silent gap |
| Ingest freshness | p95 <= 5 minutes | Newest flow/Zeek row age vs wall clock |
| Common console reads | p95 <= 2 seconds warm | `/api/health`, `/api/assets`, `/api/baselines`, `/api/findings` |
| Recovery point (RPO) | <= 24 hours | Last successful off-cluster backup |
| Recovery time (RTO) | <= 4 hours | Restore drill on a scratch target |
| Backup retention | 14 daily copies | ClickHouse backup and model artifacts |
| Raw flow retention | 3 days | Schema TTL |
| Aggregate/alert retention | 7-30 days per table | Schema TTL and prune job |
| Audit retention | 90 days | Audit table policy |

These are operating targets, not a commercial SLA. The first 30 days establish the
baseline; the targets are reviewed against measured data rather than assumed.

## Security boundary

- The supported user path is HTTPS through the local ingress. The plain HTTP
  NodePort is **break-glass only** and must be firewalled off the management
  segment when the ingress is healthy.
- Nothing is internet-reachable by default: ClickHouse is cluster-internal,
  goflow2 is a local collector, and remote sensors use mTLS with a per-sensor
  identity.
- The management network is the trust boundary for the console. An operator who
  exposes it to an untrusted segment has changed the security model and must treat
  the deployment as compromised until reviewed.
- `capture_password` stays off. Zeek HTTP/DNS data is personal data and follows the
  retention and access rules in `docs/security.md` and `USAGE_POLICY.md`.

## Operator model

- One operator owns the deployment, the alert channel and the launch decision.
- Paging is best effort: the operator is not a 24/7 SOC. The page budget and
  cooldown limits are protections against alert storms, not a staffing plan.
- Machine-learning promotion is automatic inside a bounded policy: one promotion
  in flight, bounded canary, automatic rollback and a kill switch. The operator
  approves the **launch scope once**, not each model.
- Source loss, stale models and missing evidence are `unknown`/degraded states.
  They never page as a clean network.

## Non-goals

- High availability, multi-region failover or zero-downtime upgrades.
- A 24/7 human SOC or a contractual availability SLA.
- Compliance certification (SOC 2, ISO 27001, FedRAMP).
- Multi-tenant isolation or internet-facing multi-customer operation.
- Guaranteed live precision without a trusted oracle. The product reports
  `not measured` where that evidence does not exist.

## Requirement ownership

| Area | Production requirement | Owner |
|---|---|---|
| Data and recovery | Restore-tested backups, retention, privacy, schema restore path | Operator |
| Platform | Immutable artifacts, capacity honesty, SLOs, upgrade and DR drills | Operator |
| Security | Threat model, least privilege, secrets, CVE response, audit and incident response | Operator |
| Operator experience | Task closure, explainability, failure states, documentation | Operator |
| Release | Test strategy, load/failure testing, canary and rollback, launch review | Operator |
| ML | Automated ground truth, machine-verified gate, diverse ensemble, automatic promotion and retirement | Operator + policy |

## Change policy

- **Automatic:** model canary, promotion, rollback and retirement inside the
  configured envelope, when the machine-verified gate is green.
- **Scheduled:** schema migrations, ingress/TLS changes, cluster upgrades and
  destructive maintenance require a backup and a rollback rehearsal.
- **Emergency:** security patches may be expedited, but the change record, image
  digest and post-change verification are mandatory.
- **Default deny:** missing evidence, stale telemetry, missing model card or a
  failed restore blocks promotion rather than producing a warning that is ignored.

## Risk register

| Risk | Impact | Mitigation | Review |
|---|---|---|---|
| ClickHouse/PVC loss | Loss of collected history | Off-cluster backup, restore drill, RPO check | Monthly |
| Sensor blind spot or dead feed | False calm | Source coverage, freshness SLO, `unknown` state | Monthly |
| Node loss | Outage | Documented single-node recovery, RTO drill | Monthly |
| Silent alert-delivery failure | Missed incident | Delivery health, end-to-end test, external probe | Monthly |
| TLS/certificate expiry | Console unavailable | Expiry monitoring and renewal test | Monthly |
| Credential or token compromise | Full console access | Least privilege, rotation, no secrets in logs, audit | Quarterly |
| Supply-chain compromise | Arbitrary code in cluster | Pinned digests, SBOM, CVE scan, restricted registry | Quarterly |
| Bad model promotion | Alert flood or missed detection | Machine-verified gate, canary, rollback, one in flight | Per promotion |
| Feedback-loop collapse | Model learns its own noise | Independent generated evidence, no self-training without holdout | Monthly |
| Operator error during change | Outage or data loss | Checklist, backup, peer review of high-risk changes | Per change |
