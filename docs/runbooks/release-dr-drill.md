# Release and disaster-recovery drill

## Release rehearsal (2026-11-11)

Pre-change state:

| Item | Value |
|---|---|
| Worker / GUI / ingest | `weirvern-worker:0.23.52` |
| Scanner | `weirvern-scanner:0.14.14` |
| Zeek | `weirvern-zeek:0.5.0` |
| ClickHouse | `clickhouse-server:26.8` (pinned image) |
| Schema | 047 |
| Backup | `prod-readiness-20261111-0500` |
| Rollback target | `weirvern-worker:0.23.17` |
| RPO / RTO | 24 hours / 4 hours |

## Code rollback — executed

- Set `deploy/weirvern-worker` to `weirvern-worker:0.23.17`.
- Rollout became ready in 3 seconds; in-pod version read **0.23.17**.
- `/api/health` was green for all probes.
- Rolled forward to `0.23.52`; rollout ready; in-pod version **0.23.52**.
- This proves the deployment can return to the previous image without a schema rollback. The
  schema is add-only, so code rollback is the supported first move when a release is bad.

## Data rollback — executed

- Restored `prod-readiness-20261111-0500` into `weirvern_restore` in **3.17 seconds**.
- `netflow_anomalies` matched exactly; TTL-managed flow tables were within pre/post bounds.
- Fixed-window `ml_window_scores` replay was exact: 416 rows and the same
  `cityHash64` sum on live and restored data.
- Scratch database was dropped after verification.

## Model rollback — executed

- Extracted the archived model set from the encrypted off-cluster backup (7,241 files).
- Loaded `Isolation Forest v4`, schema 4, 77 features, and scored the fixed fixture at
  `0.1500738323`.
- The archived model set is part of the same backup; restoring ClickHouse without it would be a
  different deployment.

## Disaster recovery

The node is a single failure domain. If it is lost:

1. The operator declares a disaster in the incident log.
2. Pause alert delivery and do not treat silence as a clean network.
3. Provision the replacement node and restore the latest off-cluster backup.
4. Start ClickHouse, restore the model set, then start worker, ingest and GUI.
5. Verify table counts, fixed-window score replay and `/api/health`.
6. Reopen alerting only after the verification.

Manual steps are the node rebuild, secret restoration from the operator-held material, and the
DNS/address cutover. There is no traffic failover because there is no second node.
The measured restore step is 3.17 seconds; the RTO budget includes node rebuild and verification,
not just the database restore.

## Ownership

The deployment operator declares a disaster and owns the cutover. A second operator should read
the steps aloud; no single person both restores and verifies. The release record names the backup,
schema, image tags and rollback target.

**Known limitation:** the local cluster has no registry, so the rollback proof uses immutable
release tags and recorded image IDs, not digest pulls. A registry-backed digest deploy is a
separate infrastructure prerequisite.
