# Source-to-feature registry

**Status:** living contract for the ML detection program. It answers one question per harvested
field: **is this a feature, a planned feature, a join/evidence key, an output, or excluded?**

This file is checked by `scripts/audit_feature_registry.py --check`. The machine-readable table is
between the `registry:begin` / `registry:end` markers; the prose below it explains the contracts.

Status vocabulary:

- **feature-now** — already consumed by a production or shadow feature vector.
- **feature-planned** — harvested, with a named target and a coverage gate; not in a model yet.
- **join-only** — used to join/attribute evidence; never a numeric feature.
- **output** — produced by the system (alerts, scores, state); never an input feature.
- **excluded** — not used by ML, with a reason (display, control plane, payload, free text).

<!-- registry:begin -->
alert_events | output
alert_reviews | output
baseline_history | feature-now
blocklist_domains | excluded
blocklist_sources | excluded
dns_reverse_map | join-only
fleet_audit | excluded
flows | join-only
flows_aggregated | feature-now
flows_aggregated_diversity | feature-now
flows_aggregated_temporal | feature-now
host_fingerprints | join-only
host_identity | join-only
host_roles | feature-planned
host_watches | excluded
ml_calibration | output
ml_calibration_history | output
ml_candidate_scores | output
ml_changepoints | output
ml_models | output
ml_temporal_scores | output
model_actions | excluded
near_misses | output
netflow_anomalies | output
network_scopes | join-only
ntlm_identity_daily | excluded
schema_versions | excluded
sensor_status | join-only
sluice_events | excluded
sluice_rules | excluded
sluice_state | excluded
table_size_history | excluded
weirling_enrollments | excluded
weirling_probe_requests | excluded
weirling_sonar_requests | excluded
weirlings | excluded
zeek_conn | feature-now
zeek_dce_rpc | feature-planned
zeek_dhcp | feature-now
zeek_dns | feature-now
zeek_files | feature-now
zeek_http | feature-now
zeek_kerberos | feature-planned
zeek_ldap_search | feature-now
zeek_notice | feature-now
zeek_ntlm | feature-planned
zeek_quic | feature-now
zeek_smb_files | feature-planned
zeek_smb_mapping | feature-planned
zeek_ssh | feature-now
zeek_ssl | feature-now
zeek_tunnel | feature-now
zeek_weird | feature-now
zeek_x509 | join-only
<!-- registry:end -->

---

## 1. NetFlow

### `flows` (raw landing table)

Raw rows are the replay/audit trail and the source of the aggregates. They are not fed directly
to a model: a single flow is not a host-window, and the raw addresses are join keys.

| fields | status | use |
|---|---|---|
| `timestamp`, `sampler_address`, `time_flow_start`, `time_flow_end`, `in_if`, `out_if`, `next_hop` | join-only | provenance, interface and sensor attribution |
| `src_addr`, `dst_addr`, `src_port`, `dst_port`, `proto`, `etype` | join-only | entity/edge keys; aggregate before any feature |
| `bytes`, `packets`, `tcp_flags`, `sampling_rate` | feature-planned | raw-flow/scan specialist; sampling confidence |
| `src_as`, `dst_as`, `src_vlan`, `dst_vlan`, `ip_tos`, `ip_ttl`, `frag_offset` | feature-planned | AS/VLAN context, fragmentation, TTL anomalies |

### `flows_aggregated`

| fields | status | use |
|---|---|---|
| `window_start`, `window_end`, `src_addr` | join-only | host-window key |
| `flow_count`, `total_bytes`, `total_packets`, `unique_dst_ips` | feature-now | DBSCAN/IF/GB |
| `avg_bytes`, `avg_packets` | feature-planned | shape/variance features; currently derivable |

### `flows_aggregated_diversity`

| fields | status | use |
|---|---|---|
| `window_start`, `src_addr` | join-only | host-window key |
| `unique_dst_ports`, `port_entropy`, `bytes_stddev`, `unique_connections` | feature-now | IF/GB; ports/entropy/connection density |
| `unique_dst_addrs`, `packets_stddev`, `min_bytes`, `max_bytes`, `active_minutes` | feature-planned | size profile, activity density |

### `flows_aggregated_temporal`

| fields | status | use |
|---|---|---|
| `window_start`, `src_addr` | join-only | host-window key |
| `activity_regularity`, `burstiness` | feature-now | DBSCAN/IF/GB |
| `minute_activity`, `inter_flow_avg`, `inter_flow_stddev` | feature-planned | periodicity, burst shape, beacon work |

## 2. DNS

### `zeek_dns`

| fields | status | use |
|---|---|---|
| `ts`, `uid`, `src_addr`, `dst_addr` | join-only | window/host/resolver keys |
| `proto`, `trans_id` | excluded | protocol constant / random identifier |
| `query`, `answers` | join-only | hunting/evidence; never a numeric feature |
| `qtype` | feature-now | TXT/NULL/ANY/PTR mix |
| `rcode` | feature-now | error/failure ratio (all zero in the current window) |
| `query_len` | feature-now | mean/std/max shape |
| `query_entropy` | feature-now | mean/max entropy; tunnel shape |

Planned DNS specialist adds unique-subdomain ratio, new-domain ratio, qtype mix, TXT/NULL share,
answer-count profile, resolver fan-out and query periodicity. Coverage gate: DNS was observed on
only 14 hosts in 24h; no DNS is `zeek_present=0`, not normal.

## 3. Zeek connection and protocol logs

### `zeek_conn`

| fields | status | use |
|---|---|---|
| `ts`, `uid`, `src_addr`, `src_port`, `dst_addr`, `dst_port`, `proto` | join-only | connection/edge keys |
| `service` | feature-now | service variety |
| `conn_state` | feature-now | REJ/S0/completed ratios |
| `history` | feature-planned | state-grammar counts, not a raw string |
| `duration`, `orig_bytes`, `resp_bytes`, `orig_pkts`, `resp_pkts` | feature-planned | asymmetry, duration, bytes/packet |

### `zeek_ssl` / JA4

| fields | status | use |
|---|---|---|
| `ts`, `uid`, `src_addr`, `dst_addr`, `dst_port` | join-only | connection keys |
| `version`, `cipher` | feature-now/planned | modern-TLS ratio now; downgrade planned |
| `server_name` | feature-planned | SNI/cert consistency, service mapping |
| `ja4`, `ja4_orig` | feature-now/planned | JA4 count/novelty now; rarity, days-since-seen, SNI consistency planned |
| `validation_status`, `established` | feature-planned | cert/connection trust evidence |

JA4 coverage: 12 hosts and 17 distinct fingerprints in 24h. Use novelty/rarity rules; do not train
a fleet model on this sample.

### `zeek_http`

| fields | status | use |
|---|---|---|
| `ts`, `uid`, `src_addr`, `src_port`, `dst_addr`, `dst_port` | join-only | connection keys |
| `method`, `status_code`, `resp_mime` | feature-planned | method/status/mime mix |
| `host`, `uri`, `referrer`, `user_agent` | join-only/excluded | free text/tokens; hash or evidence only |
| `resp_bytes`, `uri_len`, `uri_entropy` | feature-now/planned | URI entropy now; response/upload shape planned |

### `zeek_files`

| fields | status | use |
|---|---|---|
| `ts`, `uid`, `fuid`, `src_addr`, `dst_addr` | join-only | file/connection keys |
| `f_source`, `mime_type` | feature-now | MIME variety |
| `filename` | excluded | free text/PII surface |
| `md5`, `sha1`, `sha256` | join-only | threat-intel lookup, never a feature |
| `seen_bytes`, `total_bytes`, `missing` | feature-now/planned | size profile now; missing/ratio planned |

### `zeek_ssh`

| fields | status | use |
|---|---|---|
| `ts`, `uid`, `src_addr`, `src_port`, `dst_addr`, `dst_port` | join-only | connection keys |
| `version`, `auth_success`, `auth_attempts` | feature-planned | brute-force/direction features |
| `direction`, `client`, `server` | feature-planned | client/server role; identity context |

Current 24h coverage: **zero rows**. No learned feature until the sensor path is verified.

### `zeek_dhcp`

| fields | status | use |
|---|---|---|
| `ts`, `uids`, `client_addr`, `server_addr`, `assigned_addr`, `requested_addr` | join-only/planned | MAC↔IP binding, rogue server, duplicate address |
| `mac` | join-only | stable entity key, never a numeric feature |
| `host_name`, `client_fqdn`, `domain` | excluded | free text/PII |
| `lease_time`, `msg_types`, `duration` | feature-now/planned | lease behavior now; msg-type mix planned |

## 4. Identity and lateral movement

These tables are harvested but currently empty in the 24h window. Their status is planned, gated
on coverage.

### `zeek_kerberos`

`ts, uid, src_addr, dst_addr, dst_port` join keys; `request_type` planned; `client`, `service`
join-only/identity graph; `success` planned failure ratio; `error_msg` excluded free text;
`ticket_from`, `ticket_till` planned lifetime; `cipher` planned; `forwardable`, `renewable` planned.

### `zeek_ntlm`

`ts, uid, src_addr, dst_addr` join keys; `username`, `hostname`, `domainname` join-only identity
graph (no raw feature); `success` planned failure ratio; server names/tree join-only/planned.

### `zeek_smb_mapping`

`ts, uid, src_addr, dst_addr` join keys; `path` planned admin-share flag; `service`, `share_type`,
`native_file_system` planned categorical; no free-text feature.

### `zeek_smb_files`

`ts, uid, src_addr, dst_addr, fuid` join keys; `action` planned write/rename/delete rates;
`path`, `filename` excluded/PII; `size` planned; `prev_name` excluded; timestamps planned.

### `zeek_dce_rpc`

`ts, uid, src_addr, dst_addr, dst_port` join keys; `rtt` planned numeric; `named_pipe`, `endpoint`,
`operation` planned bounded categoricals.

### `zeek_ldap_search`

`ts, uid, src_addr, dst_addr, dst_port` join keys; `ldap_filter` join-only/planned filter-shape
novelty; `base_object`, `scope`, `deref_aliases`, `result` planned categorical; `result_count`
feature-now numeric.

### `zeek_x509`

`ts`, `fingerprint` join-only; certificate fields (`subject`, `issuer`, validity, key/sig algorithm,
key length, CA flag) join-only/planned via SSL chain; `san_dns` join-only; `host_cert`,
`client_cert` planned. No `src_addr`; never a direct per-host feature.

### `host_roles`, `host_identity`, `host_fingerprints`, `software`

Join-only/planned identity layer: roles are thresholds, identity/fingerprints are entity keys, and
new-software/version novelty is planned. MACs, usernames and banners are not numeric features.

## 5. Outputs, state and control plane

`netflow_anomalies`, `alert_events`, `alert_reviews`, `ml_models`, `ml_calibration*`,
`ml_candidate_scores`, `ml_changepoints`, `ml_temporal_scores`, `near_misses` are **outputs**.
They are not input features and must never be read back into training as normal.

`network_scopes` is join-only for the scope predicate. `sensor_status`/capture loss are join-only
confidence gates, not features. Sluice, fleet, weirling, audit, blocklist and table-size tables are
**excluded** from ML with their existing display/control roles.

## 6. Rules

- Every feature must have a source table and a presence rule.
- Every harvested table must appear in the machine block above.
- Every non-feature field must say why.
- A planned field with zero rows is not a feature; it is a coverage task.
- Raw payloads, free text, hashes, IPs, MACs and UIDs are never numeric features.
- A feature-list change bumps `FEATURE_SCHEMA_VERSION` and retrains every affected model.

## 7. Check

```bash
cd /home/admin/repos/wv-wlfix
env -u PYTHONPATH python3 scripts/audit_feature_registry.py --check
```

The script fails if a schema table is missing from the machine block, if a status is unknown, or
if the registry names a table the schema does not declare. `tests/test_feature_registry.py` proves
the guard fires when a table is removed.
