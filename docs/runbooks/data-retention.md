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

| Table | Retention | Data class | Deletion |
|---|---:|---|---|
| `flows` | 3 days | Network metadata (addresses, ports, volumes) | TTL on `timestamp` |
| `flows_aggregated` | 7 days | Aggregated network metadata | TTL on `window_start` |
| `flows_aggregated_diversity` | 7 days | Aggregated diversity features | TTL on `window_start` |
| `flows_aggregated_temporal` | 7 days | Aggregated temporal features | TTL on `window_start` |
| `netflow_anomalies` | 30 days | Security findings with host addresses | TTL on `detected_at` |
| `near_misses` | 7 days | Tuning evidence with host addresses | TTL on `window_start` |
| `alert_reviews` | 30 days | Operator dispositions and notes | TTL on `window_start` |
| `alert_events` | 30 days | Delivery records | TTL on `sent_at` |
| `alert_episodes` | 30 days | Incident grouping | TTL on `updated_at` |
| `baseline_history` | 30 days | Per-host statistical baselines | TTL on `computed_at` |
| `host_fingerprints` | 90 days | Device identity evidence; may include hostnames/MAC | TTL on `ts` |
| `host_identity` | 90 days | Current device identity verdict | TTL on `updated_at` |
| `ntlm_identity_daily` | 180 days | Identity/auth metadata; personal data | TTL on `day` |
| `zeek_conn` | 7 days | Connection metadata | TTL on `ts` |
| `zeek_dns` | 7 days | DNS queries; personal data | TTL on `ts` |
| `zeek_ssl` | 7 days | TLS metadata/JA4; personal data | TTL on `ts` |
| `zeek_http` | 30 days | HTTP metadata/URLs/user agents; personal data | TTL on `ts` |
| `zeek_files` | 30 days | File metadata; may contain names | TTL on `ts` |
| `zeek_notice` | 30 days | Zeek notices; security evidence | TTL on `ts` |
| `zeek_quic` | 30 days | QUIC metadata | TTL on `ts` |
| `zeek_smb_files` | 30 days | SMB file metadata; may contain names | TTL on `ts` |
| `zeek_ldap_search` | 30 days | LDAP query metadata; personal data | TTL on `ts` |
| `zeek_dce_rpc` | 90 days | RPC metadata | TTL on `ts` |
| `zeek_dhcp` | 90 days | Lease/hostname/MAC; personal data | TTL on `ts` |
| `zeek_kerberos` | 90 days | Authentication metadata; personal data | TTL on `ts` |
| `zeek_ssh` | 90 days | SSH metadata; personal data | TTL on `ts` |
| `zeek_tunnel` | 90 days | Tunnel metadata | TTL on `ts` |
| `zeek_weird` | 90 days | Protocol anomalies | TTL on `ts` |
| `zeek_ntlm` | 60 days | NTLM metadata; personal data | TTL on `ts` |
| `zeek_smb_mapping` | 60 days | SMB mapping metadata | TTL on `ts` |
| `zeek_x509` | 60 days | Certificate metadata | TTL on `ts` |
| `ml_window_scores` | 30 days | Per-host model scores | TTL on `computed_at` |
| `ml_candidate_scores` | 30 days | Candidate evidence | TTL on `computed_at` |
| `ml_temporal_scores` | 30 days | Temporal model scores | TTL on `computed_at` |
| `ml_changepoints` | 90 days | Change-point evidence | TTL on `computed_at` |
| `ml_drift` | 90 days | Drift reports | TTL on `computed_at` |
| `ml_review_adjustments` | expiry + 90 days | Bounded review adjustments | TTL on `expiry` |
| `sensor_status` | 7 days | Sensor health | TTL on `ts` |
| `table_size_history` | 30 days | Operational metrics | TTL on `at` |
| `sluice_events` | 90 days | Enforcement audit | TTL on `ts` |
| `sluice_rules` | 400 days | Durable enforcement rules | TTL on `created_at` |
| `sluice_state` | 30 days | Gate state | TTL on `updated_at` |
| `weirling_probe_requests` | 1 day | Enrollment/probe requests | TTL on `requested_at` |
| `weirling_sonar_requests` | 1 day | Sonar survey requests | TTL on `requested_at` |
| `host_watches` | no TTL | Operator intent; reviewed manually | Manual delete |
| `ml_models` | no TTL | Model registry/metrics | Manual retention |
| `asset_registry`, `asset_services`, `asset_findings`, `asset_scans`, `asset_changes`, `asset_observations` | no TTL | Asset inventory and scan evidence | Manual retention |
| `audit` tables (when added) | 90 days minimum | Privileged actions | TTL/retention policy |

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
  settings.
- `capture_password` must remain **off**; enabling it would add credentials to
  HTTP metadata and is out of policy.
