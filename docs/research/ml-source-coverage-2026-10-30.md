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

## 7. Follow-up — multi-NIC capture repair (2026-11-01)

The 2026-10-30 coverage gap had a concrete capture cause. `trunk-init` writes the port it
probed to `/state/ifaces`; the Zeek startup treated that file as the WHOLE capture set. With
`ZEEK_IFACES=eth1,eth2` and `CAPTURE_IFACE=eth1`, it captured only eth1 and silently ignored
eth2. The fix merges the trunk state with the configured ports, replacing the parent only
when VLAN children were detected (commit `8120984`, gate PASS, live DaemonSet verified).

After the repair, both capture processes are running and writing their own log directories:

| source | 24h rows | 24h source hosts | change |
|---|---:|---:|---|
| `zeek_conn` | 223,547 | 2,168 | stable |
| `zeek_dns` | 48,809 | **21** (was 14) | +7; both `.2` and `.3` segments now present |
| `zeek_ssl` | 1,548 | **17** (was 12) | +5; both segments present |
| `zeek_ssh` | 45 | 1 | present |
| `zeek_smb_mapping`, `zeek_kerberos`, `zeek_ntlm`, `zeek_dce_rpc` | **0** | **0** | still unavailable |

The 30-minute post-fix window shows DNS from both segments and fresh `eth2` `conn`, `dns`,
`ssl` and `ssh` logs. The `ml_window_scores` population also widened to 11,728 rows across 22
hosts after the fix. SMB/Kerberos/NTLM/DCE still have no rows; that is now a traffic/segment
question, not the multi-NIC startup bug. Verify the Zeek protocol load set and whether those
protocols exist on either captured segment before adding features or claiming coverage.

The SMB case is a concrete example of why a zero is not a clean negative. A 24-hour `conn` audit
found 3,716 connections to TCP/445 from one internal host to another, 7.05 GB outbound, and
**zero response bytes**, with no `smb_mapping` records. `base/protocols/smb` is in the default
Zeek closure, so this is a one-way/asymmetric capture limitation, not a missing analyzer. The
T1021.002 mapping stays unavailable until both directions of that conversation are visible;
the 445 volume alone must not be read as lateral movement.
