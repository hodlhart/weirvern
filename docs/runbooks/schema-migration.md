# Schema migration and rollback contract

ClickHouse migrations in this repository are **add-only**. There is no down
migration. A code rollback is safe only when the schema did not advance; after a
schema change the recovery path is a restored backup, not a reverse DDL script.

## Rules

1. A migration is a numbered file in `weirvern/schema/`, applied in order by the
   schema Job. It must be idempotent (`IF NOT EXISTS`) and additive.
2. Destructive changes (drop column, narrow type, delete rows, rewrite a table)
   are refused in review. A new table or a nullable/defaulted column is the
   supported shape.
3. Every migration is rehearsed against a restored copy before production. The
   rehearsal records: backup name, restore duration, table counts, and the
   queries/views that read the changed table.
4. The release record names the schema version, the backup used and the rollback
   target. A code rollback after a schema advance is explicitly not supported
   without restoring data.
5. A failed migration is not retried blindly: the previous schema/data must be
   intact, or the restore path is invoked. The failed attempt is recorded.
6. `scripts/audit_schema.py` must pass: no dead columns, no unread tables, no
   phantom references.

## Rehearsal evidence (2026-11-11)

- Restored `prod-readiness-20261111-0500` into `weirvern_restore`.
- `netflow_anomalies` matched exactly; TTL-managed `flows`/`flows_aggregated`
  were non-empty and within their pre/post bounds, as expected for TTL expiry.
- Restore took 3.17 seconds; the scratch database was dropped after verification.
- `scripts/audit_schema.py` passed: no dead columns, no unread tables, no phantom
  references (`/tmp/wv-schema-audit.log`).

No new schema migration was pending at this rehearsal. The rehearsal proves the
restore path and the audit, not a hypothetical destructive change.

## Release checklist

- [ ] Take a backup with `scripts/backup_clickhouse.sh`.
- [ ] Restore it to `weirvern_restore` and verify counts.
- [ ] Run `scripts/audit_schema.py`.
- [ ] Render the manifests with `kustomize build k8s/`.
- [ ] Record schema version, backup name, image digest and rollback target.
- [ ] Apply during a maintenance window; watch the schema Job.
- [ ] On failure: stop, keep the old pods/data, restore the backup or revert the
      image only if the schema did not advance.
- [ ] Drop scratch databases and record the result.
