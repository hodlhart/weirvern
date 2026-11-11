# Release checklist

Copied and filled for every release; the completed copy lives in `docs/releases/<version>.md`.
A release is not started until the first block is complete.

## Before

- [ ] Commit and gate: `./scripts/gate.sh` PASS (record the log path).
- [ ] Images built from that commit; record tag **and image ID** for worker, scanner and Zeek.
- [ ] `scripts/verify_versions.sh` agrees across code, kustomize and README.
- [ ] Schema version and migration listed; no down migration claimed.
- [ ] Backup completed and verified: name, size, restore check. `scripts/backup_clickhouse.sh`.
- [ ] Previous release tag and model archive recorded as the rollback target.
- [ ] Owner named; change record opened in `docs/releases/`.

## Canary

- [ ] `scripts/canary_rehearsal.sh <worker-image>` — bounded pod, shipped ConfigMap/Secret,
      readiness, `/api/healthz`; must print `CANARY PASS`.
- [ ] Canary failure aborts the release; the previous version keeps serving.
- [ ] Canary namespace deleted; no Service or Ingress was created.

## Full rollout

- [ ] Update the tree's image tag (never a literal `sed` that silently no-ops) and
      `kubectl apply -k k8s/`, or the documented equivalent.
- [ ] Rollout status for worker, GUI, ingest, scanner, Zeek.
- [ ] Read the running version in the pod and the image ID, not just the deployment spec.
- [ ] `scripts/e2e_smoke.sh` PASS against the live console.
- [ ] `/api/health` green; no new alert storm; source freshness visible.

## Rollback

- [ ] Code: previous tag, rollout ready, in-pod version read, health green.
- [ ] Model: previous set from `superseded/<stamp>/`, fixture score matches.
- [ ] Data: restore to scratch, verify counts and a fixed-window replay, then restore for real.
- [ ] Record the rollback reason and the version left serving.

## After

- [ ] Release record completed: commit, image IDs, schema, backup, canary, rollback, owner.
- [ ] CHANGELOG entry names the change (or the release record links it).
- [ ] 30-day review scheduled on the program board (REL-3).
- [ ] No mutable tag was the rollback target; the registry limitation, if it applies, is stated.
