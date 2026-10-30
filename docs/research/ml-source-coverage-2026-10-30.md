# Live ML source coverage — 2026-10-30

**Purpose:** the evidence for FND-2. What each harvested source actually delivered in the last
24 hours, which model sees it, and which sources cannot support a model yet.

**Method:** `scripts/audit_ml_coverage.py --live --host sensor.example` plus live ClickHouse
counts. Window: last 24 hours ending 2026-10-30 14:34 UTC. No production change.

---

## 1. Summary

The collector is not uniformly feeding the models. The **NetFlow aggregate layer and Zeek
`conn`/`dns`/`ssl`** are the sources with real volume. Several protocol logs are empty, and DNS
and JA4 are visible on only a small subset of hosts.

| source | rows (24h) | source hosts | status |
|---|---:|---:|---|
| `flows_aggregated` | 636,045 | 3,730 | strong |
| `flows_aggregated_diversity` | 631,141 | — | strong |
| `flows_aggregated_temporal` | 636,045 | — | strong |
| `zeek_conn` | 221,339 | 2,188 | strong; overlap with flow hosts 2,168 |
| `zeek_dns` | 25,925 | **14** | real but narrow |
| `zeek_ssl` | 1,361 | **12** | narrow; **17 distinct JA4** |
| `zeek_http` | 3,482 | **10** | narrow |
| `zeek_files` | 4,214 | **10** | narrow |
| `zeek_ssh` | **0** | **0** | unavailable |
| `zeek_dhcp` | 42 | 11 | low volume, high identity value |
| `zeek_kerberos` | **0** | **0** | unavailable |
| `zeek_ntlm` | **0** | **0** | unavailable |
| `zeek_smb_mapping` / `zeek_smb_files` | **0** | **0** | unavailable |
| `zeek_dce_rpc` | **0** | **0** | unavailable |
| `zeek_ldap_search` | **0** | **0** | unavailable |
| `zeek_x509` | 112 | — (no `src_addr`) | join-only |
| `host_roles` | 17,556 | — | collected, **unused by ML** |

`host_roles` composition: **74 monitored unknown**, **60 workstation**, **10 media**, **4
server**, plus external rows. The seven empty protocol tables are a **coverage** fact, not a
normal-traffic result.

## 2. DNS

- 25,925 rows, **14 source hosts**, 1,938 distinct host-windows.
- Qtypes: A 11,947; AAAA 7,264; PTR 4,072; SRV 2,108; ANY 436; TXT 16.
- Rcode: **0 for every row**. A tunnel detector cannot rely on NXDOMAIN or resolver errors
  here; it must use shape (entropy, length, unique/new domains, TXT/NULL, qtype mix).
- Coverage is the constraint: most of the 3,730 flow hosts have no DNS observation. The model
  must represent that as `zeek_present=0`, not as normal DNS.

## 3. JA4/TLS

- 1,361 SSL rows, 12 hosts, **17 distinct JA4 fingerprints**.
- 1,156 of 1,361 rows carry a valid JA4 (85% within the SSL rows), but the fleet sample is tiny.
- Sufficient for **novelty and rarity rules**; not sufficient for a learned fleet-wide JA4 model.
- `zeek_x509` has no `src_addr`; it is join-only via certificate fingerprints/SNI, never a
  per-host feature.

## 4. NetFlow and Zeek conn

- `flows_aggregated` is the strongest source: 636k rows, 3,730 source hosts, plus diversity and
  temporal side tables.
- `zeek_conn` covers 2,188 hosts and overlaps 2,168 flow hosts. That is enough for connection
  shape, S0/REJ, duration and asymmetry features.
- The current production IF/GB models use 77 columns; DBSCAN uses 19; the repaired HDBSCAN
  challenger uses 19.

## 5. What this means

**Usable now:** NetFlow aggregates, Zeek conn, DNS (shape features where observed), SSL/JA4
(novelty/rarity rules), DHCP (identity), HTTP/files (narrow).

**Not usable as a learned feature yet:** SSH, Kerberos, NTLM, SMB, DCE/RPC, LDAP — zero rows in
the window. A model trained on these would learn a constant, not behaviour.

**Configuration gap:** `host_roles` exists but no model or threshold reads it.

**Immediate fixes before adding features**

1. Verify the Zeek sensor sees the same VLANs as NetFlow; DNS 14 hosts and JA4 12 hosts are too
   narrow for fleet features.
2. Check the SSH/Kerberos/NTLM/SMB/DCE-RPC log paths and the `site/local.zeek` load set.
3. Enable the file-action set needed for SMB write features (`FILE_WRITE`) rather than assuming
   it is logged.
4. Populate `host_roles` for the monitored population; 74 unknown is a threshold gap.
5. Keep capture-loss/sensor health as a confidence gate, not a feature.

## 6. Evidence commands

```bash
cd /home/admin/repos/wv-wlfix
env -u PYTHONPATH python3 scripts/audit_ml_coverage.py --live --host sensor.example
```

The per-source query counts are in the 2026-10-30 live read; the schema and source inventory are
in `docs/research/zeek-log-research-ml.md`. This report does not alter a collector, model,
schema or UI.
