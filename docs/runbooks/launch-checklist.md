# Launch checklist — production cutover

A cutover is a release with a narrower blast radius. This checklist is the gate; the release
record (`docs/releases/<version>.md`) is the evidence.

## Entry conditions

- [ ] PRG-2 readiness gate complete; every phase board done or its exception accepted in writing.
- [ ] Release checklist complete for the candidate (`release-checklist.md`).
- [ ] Gate PASS and E2E SMOKE PASS on the box that will serve.
- [ ] Backup verified by restore, not by file existence.
- [ ] Rollback owner named and reachable; rollback target recorded.

## Surface

- [ ] **DNS:** the console name resolves to the intended address from the operator network;
      no wildcard or public record was added by accident.
- [ ] **TLS:** certificate chain, expiry (≥14 days at cutover) and hostname match checked with
      `openssl s_client`; the private key is not in the repository or an image.
- [ ] **Accounts:** the user store is readable, sign-in succeeds, a failed sign-in is rejected
      and audited; no default password remains.
- [ ] **Backups:** the latest off-cluster object opens with the operator-held key; the restore
      path was exercised this release cycle.
- [ ] **Alert delivery:** configured and tested end to end, or explicitly recorded as
      **not configured** with the consequence stated. Log-only is not paging.
- [ ] **SLOs:** `scripts/slo_report.py` reports every row; unmeasured is unknown, never green.
- [ ] **On-call:** one named operator and one escalation path; the alert destination is reachable.
- [ ] **Known issues:** the open list is attached to the launch record, with owner and expiry.

## Abort criteria

Abort the cutover and leave the previous version serving if **any** of these is true:

1. A restore fails or a count/replay check differs from the recorded result.
2. TLS is broken, expired, or serves the wrong hostname.
3. A required source is missing, stale or unreadable and the console cannot say so.
4. Alerts storm (>10× the 24-hour baseline) or a page is silently dropped.
5. The model gate fails, or a model is promoted without its shadow evidence.
6. The canary fails its health probe, or the previous version cannot be restored.

Abort is a success of the process, not a failure of the release. Record the reason and the
version left serving.

## During

- [ ] Announce start and the rollback target.
- [ ] Apply; watch worker, GUI, ingest, scanner and Zeek readiness.
- [ ] Read the running version and image ID in the pod.
- [ ] Run `scripts/e2e_smoke.sh`; run `/api/health`; read source freshness.
- [ ] Watch the first 30 minutes of alert volume, worker lag and ClickHouse memory.

## Exit

- [ ] Release record completed and linked from the program board.
- [ ] Launch announcement names the version, the rollback owner and the known issues.
- [ ] 30-day review scheduled (`launch-review-30d.md`).
