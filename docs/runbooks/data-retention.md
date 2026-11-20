# Data retention and privacy matrix

This is the per-table retention contract for the live deployment. The schema TTL is
the enforcement mechanism; the prune job and backup policy are separate. A table
being listed here is not permission to collect more of it.

**Common rules**

- Owner: the deployment operator. Access is limited by the console roles and the
  cluster RBAC; the viewer role cannot read Secrets.
- Basis: authorized network security monitoring under `USAGE_POLICY.md`; personal
  data is minimized and is not sold or shared.
- Deletion: ClickHouse TTL, except backups, which expire under the backup policy.
- `capture_password` stays off. No table below requires packet payload.
- Time is UTC at write; TTL is evaluated by ClickHouse against the column shown.

## One retention window, derived from free disk

`DATA_RETENTION_DAYS` — the Settings row **data retention (auto or days)** — governs every
table the detection and ripple layers read. **Default `auto`. Bounds 7-365 days** when set
explicitly. Admin-only, applied through the normal stage → plan → apply flow.

In `auto`, the window is measured, not chosen:

    budget_bytes  = free_bytes × DATA_RETENTION_RATIO / 100     # ratio default 40%
    bytes_per_day = Σ(table_bytes / that table's observed span)  # the managed tables, measured
    days          = floor(budget_bytes / bytes_per_day)

`free_bytes` comes from `system.disks` (the disk that holds this database's parts) and
`bytes_per_day` from `system.parts` over the managed tables. Each table is divided by ITS
OWN span, because a table keeping 7 days and one keeping 30 did not write their bytes over
the same interval. Parts whose `min_time` is the `toDateTime(0)` sentinel (an empty part or
an unpartitioned table) do not define a span; their bytes still count, against the union
span. Nothing is configured by hand and no rate is guessed.

If a table's current TTL cannot be read or parsed, it is left exactly as it is and the
receipt says `NOT CHANGED: TTL unreadable`; there is no fallback day count. A generated
interval is also refused if it exceeds the derived window, so a read failure can never
lengthen a table's retention.

`DATA_RETENTION_RATIO` — the row **retention disk budget (%)** — is the share of FREE space
the tables may occupy. **Default 40%, bounds 10-70.** The rest is merge headroom: ClickHouse
must be able to compact parts and run mutations, and a table budgeted to the last byte stops
accepting inserts exactly when it is biggest. Above 70% the next merge can fill the disk,
which is why that end is refused rather than merely warned.

**Floor and cap.** A derived value below **7 days** is held at 7, and the row says what the
disk actually supports ("disk supports 4 days; holding the 7-day floor"). Above **365** it is
capped. An explicit override above the measured budget is **refused**, with the budget named
(`the measured budget is 45 day(s)`); an explicit value at or below `max(7, budget)` is
accepted, because 7 is the policy minimum.

### The ratchet: the window does not silently contract

Deriving from FREE space has one failure mode the arithmetic cannot avoid: a fuller disk
derives a shorter window, so history started expiring without anyone choosing it (measured on
the live deployment: the derived window moved 284 → 258 days with no settings change). The
**highest window ever derived is persisted as a floor** in
`$MODEL_DIR/retention_ratchet.json` (the same worker-owned volume as
`detect_cursor.json`), with the day count and the date it was set. The effective window is
`max(derived_from_disk, floor)`.

- **It only rises on its own.** A larger derivation raises the floor and records the new date.
  A smaller one never lowers it.
- **It falls only by explicit operator action.** An apply that lowers the effective window —
  an explicit day count below the floor, or a lower `DATA_RETENTION_RATIO` whose derived
  window is below the floor — is refused unless the request carries `reset_ratchet: true` and
  a reason. The record names the actor, the old floor and the new one. In the console, the
  existing destructive-retention confirmation is that explicit action.
- **Capacity wins over policy.** `ML_RETENTION_MAX_DISK_FRACTION` (**default 0.85**) is the
  hard share of the VOLUME a held window may occupy. If honouring the floor would exceed it,
  the floor is NOT honoured: the control holds the longest window that fits and says so on the
  Settings row, in the worker log at WARNING, and in the Health checks —
  `retention floor 284d needs 96% of the volume; holding 212d, the most the disk supports`.
  The stored floor is not rewritten to the smaller number; it stays until an operator resets
  it, so a temporary disk pressure does not destroy the promise permanently.

The operator-side record of a reset or explicit raise lives in the `RETENTION_RATCHET`
ConfigMap key; the worker consumes the newer of that record and its own file, so a reset takes
effect immediately and a later derivation can still raise the floor.

Why 7 days is the floor at all: the ripple layer measures a host against its own trailing
history at 1h, 6h, 24h and 7d scales with a **30 non-overlapping window minimum**. Thirty 6h
windows is 7.5 days and thirty 24h windows is 30 days, so a window shorter than 7 days cannot
support even the 6h scale. A disk that cannot hold 30 days still runs, with the 24h scale
reported as "baseline too short" rather than measured — the row says so instead of pretending.

How it is enforced:

1. **At creation.** `weirvern/schema/*.sql` creates every managed table at the **7-day
   floor** — a bootstrap, not a policy. A brand-new database has no ingest to measure, and the
   floor is the safe direction.
2. **At startup.** `weirvern/retention.py:ensure` runs from `db.apply_schema` (the schema Job
   and every worker start). It re-derives from the CURRENT disk and observed ingest, compares
   each table's TTL in `system.tables`, and runs
   `ALTER TABLE <t> MODIFY TTL <column> + INTERVAL <n> DAY` only where they differ. A disk
   that fills, or traffic that grows, moves the number at the next start with nobody editing a
   day count.
3. **On apply.** A Settings apply writes the ConfigMap keys, re-derives, runs the same
   ALTERs, and **reads the effective TTL back from `system.tables`**. The receipt reports what
   the cluster has, not what was requested; a table the ALTER could not change is named with
   its previous TTL still in place.

**Lowering is destructive.** ClickHouse applies a TTL on its next merge, not when the ALTER
returns: shortening the window deletes older rows in the background and cannot be undone by
raising the value again. The console presents it as destructive and requires a written reason,
which is recorded with the actor and the time. Nothing in this code path drops a partition or
truncates a table.

### Managed tables (7-day bootstrap, then derived)

The TTL is the same for all of them and is derived from free disk at startup and on apply;
the table below is the SET, not a per-table policy.

| Table | TTL column | Why it is in the window |
|---|---|---|
| `flows` | `timestamp` | raw flow records; every aggregate is derived from them |
| `flows_aggregated` | `window_start` | legacy 5-minute host windows, still read by the console |
| `flows_aggregated_diversity` | `window_start` | per-host diversity features |
| `flows_aggregated_temporal` | `window_start` | per-host timing features |
| `flows_window` | `window_start` | the detection stack's window unit and the ripple flow source |
| `zeek_conn` | `ts` | connection volume/diversity/reset channels |
| `zeek_dns` | `ts` | DNS volume, query diversity, NXDOMAIN and reverse channels |
| `zeek_http` | `ts` | HTTP metadata used as anomaly evidence |
| `zeek_ssl` | `ts` | TLS metadata and JA4 fingerprints |
| `zeek_ssh` | `ts` | SSH authentication history |
| `zeek_notice` | `ts` | Zeek's own security notices |
| `zeek_weird` | `ts` | protocol anomalies |
| `zeek_kerberos` | `ts` | identity channel read by `ripple_evidence.py` |
| `zeek_ntlm` | `ts` | identity channel read by `ripple_evidence.py` |
| `zeek_smb_files` | `ts` | SMB file channel read by `ripple_evidence.py` |
| `ml_ripple_evidence` | `window_start` | the ripple layer's own evidence store |

The identity tables used to keep 60-90 days. They are now on the same window because
a baseline that reads all of them over the same span cannot mix retentions. That is a
deliberate trade, decided by the disk: at a derived 35 days `zeek_smb_files` gains five
days, `zeek_ntlm` and `zeek_kerberos` lose 25 and 55; a larger disk derives longer and
the same three move together.

### Never on this control

| Table | Why |
|---|---|
| `schema_versions` | the applied-schema history; expiring it erases how the database got here |
| `fleet_audit` | privileged-action audit trail; retention is a legal/forensic decision |
| `model_actions`, `ml_model_cards`, `ml_models` | model promotion, provenance and metrics |
| `host_watches`, `network_scopes`, `weirlings`, `host_roles` | operator intent and configuration, not telemetry |

## The rest of the corpus (its own per-table policy)

| Table | Retention | Data class | Deletion |
|---|---:|---|---|
| `netflow_anomalies` | 30 days | Security findings with host addresses | TTL on `detected_at` |
| `near_misses` | 7 days | Tuning evidence with host addresses | TTL on `window_start` |
| `alert_reviews` | 30 days | Operator dispositions and notes | TTL on `window_start` |
| `alert_events` | 30 days | Delivery records | TTL on `sent_at` |
| `alert_episodes` | 30 days | Incident grouping | TTL on `updated_at` |
| `baseline_history` | 30 days | Per-host statistical baselines | TTL on `computed_at` |
| `host_fingerprints` | 90 days | Device identity evidence; may include hostnames/MAC | TTL on `ts` |
| `host_identity` | 90 days | Current device identity verdict | TTL on `updated_at` |
| `ntlm_identity_daily` | 180 days | Identity/auth metadata; personal data | TTL on `day` |
| `zeek_files` | 30 days | File metadata; may contain names | TTL on `ts` |
| `zeek_quic` | 30 days | QUIC metadata | TTL on `ts` |
| `zeek_smb_mapping` | 60 days | SMB mapping metadata | TTL on `ts` |
| `zeek_ldap_search` | 30 days | LDAP query metadata; personal data | TTL on `ts` |
| `zeek_dce_rpc` | 90 days | RPC metadata | TTL on `ts` |
| `zeek_dhcp` | 90 days | Lease/hostname/MAC; personal data | TTL on `ts` |
| `zeek_tunnel` | 90 days | Tunnel metadata | TTL on `ts` |
| `zeek_x509` | 60 days | Certificate metadata | TTL on `ts` |
| `ml_window_scores` | 30 days | Per-host model scores | TTL on `computed_at` |
| `ml_candidate_scores` | 30 days | Candidate evidence | TTL on `computed_at` |
| `ml_temporal_scores` | 30 days | Temporal model scores | TTL on `computed_at` |
| `ml_changepoints` | 90 days | Change-point evidence | TTL on `computed_at` |
| `ml_drift` | 90 days | Drift reports | TTL on `computed_at` |
| `ml_review_adjustments` | expiry + 90 days | Bounded review adjustments | TTL on `expiry` |
| `host_hour_features` | 30 days | Host-hour detector input, derived from `flows_window` | TTL on `hour` |
| `host_hour_scores` | 30 days | Host-hour detector output | TTL on `hour` |
| `host_reference_samples` / `host_reference_stats` | 30 days / 2 days | Host-hour reference stores | TTL on `hour` / `computed_at` |
| `sensor_status` | 7 days | Sensor health | TTL on `ts` |
| `table_size_history` | 30 days | Operational metrics | TTL on `at` |
| `sluice_events` | 90 days | Enforcement audit | TTL on `ts` |
| `sluice_rules` | 400 days | Durable enforcement rules | TTL on `created_at` |
| `sluice_state` | 30 days | Gate state | TTL on `updated_at` |
| `weirling_probe_requests` | 1 day | Enrollment/probe requests | TTL on `requested_at` |
| `weirling_sonar_requests` | 1 day | Sonar survey requests | TTL on `requested_at` |
| `asset_registry`, `asset_services`, `asset_findings`, `asset_scans`, `asset_changes`, `asset_observations` | no TTL | Asset inventory and scan evidence | Manual retention |

## Backups

- ClickHouse backups are full-database artifacts on the ClickHouse PVC, copied
  off-cluster encrypted, with 14 daily copies retained locally.
- Model artifacts travel with the database backup; both are encrypted with the
  same operator-held key.
- A backup is not a retention extension: restoring an old backup can reintroduce
  data that TTL had expired. Treat restored data under the same retention rules
  and drop scratch databases after verification.

## Deletion and access

- A deletion request is handled by dropping the named rows or letting TTL expire;
  aggregate counts may remain but must not reconstruct the deleted personal data.
- Access is role-scoped and audited. A viewer cannot read Secrets or mutate
  settings; the retention row renders read-only for that role.
- `capture_password` must remain **off**; enabling it would add credentials to
  HTTP metadata and is out of policy.
