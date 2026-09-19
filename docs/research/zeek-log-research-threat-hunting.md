# Zeek Logs for Threat Hunting: Ranked Recommendations for Weirvern

**Scope.** Which Zeek log files give the most *threat-hunting* leverage in a network security
monitoring deployment — i.e. which logs let an analyst test a hypothesis about adversary behaviour,
rather than merely see that a connection existed.

**Deployment under discussion.** Weirvern: single sensor, Zeek 9.0.0, logs → ClickHouse.
Already ingested (8): `conn`, `dns`, `ssl`, `notice`, `http`, `files`, `ssh`, `weird`.

**Relationship to the existing docs.** `weirvern-zeek-log-expansion.md` ranks the same candidate logs
by **ML/feature-vector value**; `zeek-retention-privacy-research.md` assigns **retention** by privacy
class. This document is the third lens: **investigative value**. Rankings differ on purpose — e.g.
`dhcp.log` ranks ~6th for ML (it seeds asset clustering) but 8th here, because for hunting it is a
*pivot* (IP → device at a past time), not a detection. Where I disagree with either sibling doc I say so.

**Verification method.** Field names below are read from the **Zeek 9.0.0 tag source tree**, not from
memory and not from `master`. I cloned `github.com/zeek/zeek` and checked out tag `v9.0.0`
(`VERSION` = `9.0.0`), then extracted every `&log` field from the record definitions under `scripts/`.
Each log entry names the file that *declares* it, because a column named after a field in a script
that isn't loaded is still an empty column. External corroboration is cited inline. Anything I could
not verify is flagged **[unverified]** or **[could not reproduce]** — see §6.

> **Version warning that affects two docs.** `docs.zeek.org/en/current/` currently serves the
> **9.1.0-dev** docs (page titles read `Book of Zeek (9.1.0-dev.108)`). Its `ssl.log` and `x509.log`
> worked examples show *older* field names than the 9.0.0 source: the examples use `cert_chain_fuids`
> and an `id` field in `x509.log`, whereas **9.0.0 declares `cert_chain_fps` /
> `client_cert_chain_fps`** (`scripts/base/protocols/ssl/files.zeek`) and **`fingerprint`**
> (`scripts/base/files/x509/main.zeek`). Do not build a ClickHouse schema from the docs' JSON
> examples. The authoritative list of log *filenames* is `doc/reference/zeekscript/log-files.rst`;
> the authoritative field lists are the record definitions cited below.

---

## 1. Ranked table — logs worth adding, best hunting value first

All 25 rows are logs Weirvern does **not** ingest yet.

| # | Log | Declared in (`scripts/…`) | Key `&log` fields | What it reveals that `conn.log` cannot |
|---|-----|---------------------------|-------------------|------------------------------------------|
| 1 | **kerberos.log** | `base/protocols/krb/main.zeek` | `ts, uid, id, request_type, client, service, success, error_msg, from, till, cipher, forwardable, renewable` | `conn.log` sees `service=krb` on port 88 and nothing else. This log names the **ticket type (AS/TGS/AP), the principal, the requested service (SPN), and the ticket encryption type** — the exact fields that constitute Kerberoasting and AS-REP roasting. |
| 2 | **dce_rpc.log** | `base/protocols/dce-rpc/main.zeek` | `ts, uid, id, rtt, named_pipe, endpoint, operation` | The only log carrying **RPC interface + operation name + named pipe**. Remote service creation, WMI execution, remote registry and DCSync are *operation-level* facts; `conn.log` collapses all of them to `service=dce_rpc`. |
| 3 | **smb_mapping.log** | `base/protocols/smb/main.zeek` (`SMB::TreeInfo`) | `ts, uid, id, path, service, native_file_system, share_type` | The **share path a client mounted**. `conn.log` says `service=smb`; it cannot say `\\HOST\ADMIN$`. Admin-share access is the defining observable of SMB lateral movement. |
| 4 | **smb_files.log** | `base/protocols/smb/main.zeek` (`SMB::FileInfo`) | `ts, uid, id, fuid, action, path, name, size, prev_name, times` | **Action semantics** — `FILE_WRITE` / `FILE_READ` / `FILE_RENAME` / `FILE_DELETE` — with the share path. `files.log` (already ingested) has MIME and hashes but no action and no share path, so it cannot distinguish "tool was written to a remote admin share" from "user opened a document". |
| 5 | **ntlm.log** | `base/protocols/ntlm/main.zeek` | `ts, uid, id, username, hostname, domainname, server_nb_computer_name, server_dns_computer_name, server_tree_name, success` | The **identity↔host binding**. Pass-the-Hash appears as one identity authenticating from many hosts, or many identities against one host — a bipartite graph that exists nowhere else in the corpus. |
| 6 | **x509.log** | `base/files/x509/main.zeek` | `ts, fingerprint, certificate, san, basic_constraints, host_cert, client_cert`; nested `certificate.{version, serial, subject, issuer, cn, not_valid_before, not_valid_after, key_alg, sig_alg, key_type, key_length, exponent, curve, tbs_sig_alg}`, `san.{dns, uri, email, ip, other_fields}`, `basic_constraints.{ca, path_len}` | `ssl.log` (already ingested) logs **fingerprints only** (`cert_chain_fps`). It cannot tell you whether the cert behind a fingerprint is self-signed, a CA, expired, short-key, or has a SAN that contradicts the SNI. Those properties exist only here. |
| 7 | **ldap_search.log** | `base/protocols/ldap/main.zeek` (`LDAP::SearchInfo`) | `ts, uid, id, message_id, scope, deref_aliases, base_object, result_count, result, diagnostic_message, filter, attributes` | The **search filter string** and `base_object`. AD enumeration is *defined* by filter content; nothing else exposes it. Note it is written to a separate stream/file from `ldap.log` (`LDAP::LDAP_SEARCH_LOG`, `$path="ldap_search"`). |
| 8 | **dhcp.log** | `base/protocols/dhcp/main.zeek` | `ts, uids, client_addr, server_addr, mac, host_name, client_fqdn, domain, requested_addr, assigned_addr, lease_time, client_message, server_message, msg_types, duration` | The only log with **L2 identity**. It converts an IP in `conn.log` into a MAC and hostname — the pivot that makes every other log attributable after a lease expires. Also exposes rogue DHCP servers via a `server_addr` that isn't yours. |
| 9 | **tunnel.log** | `base/frameworks/tunnels/main.zeek` | `ts, uid, id, tunnel_type, action` | Explicit **encapsulation type** (`Tunnel::IP`, `GRE`, `TEREDO`, `AYIYA`, `SOCKS`, `GTPv1`, `HTTP`, `VXLAN`, `GENEVE` — enum in `src/types.bif`) and lifecycle (`DISCOVER`/`CLOSE`/`EXPIRE`). `conn.log` carries `tunnel_parents` (a UID) but never the *type*, so it cannot distinguish an authorised IPsec-ish tunnel from protocol tunneling for evasion. |
| 10 | **analyzer.log** | `base/frameworks/analyzer/logging.zeek` | `ts, analyzer_kind, analyzer_name, uid, fuid, id, proto, failure_reason, failure_data` | A **parser-violation fingerprint**. Where `weird.log` (ingested) is a grab-bag, this is structured per-analyzer failure — useful for evasion hypotheses (a tool deliberately malforming a protocol). |
| 11 | **quic.log** | `base/protocols/quic/main.zeek` | `ts, uid, id, version, client_initial_dcid, client_scid, server_scid, server_name, client_protocol, history` | Fills a **TLS blind spot**: QUIC is encrypted at the transport layer and bypasses `ssl.log` entirely, so on a modern network a growing share of egress simply has no TLS record. This recovers `server_name` (SNI) and the ALPN protocol. |
| 12 | **unknown_protocols.log** | `policy/misc/unknown-protocols.zeek` | `ts, analyzer, protocol_id, first_bytes, analyzer_history` | A **negative-space signal**: protocol identity Zeek has never seen. Genuinely unsupervised — it cannot be evaded by matching a known signature. (Privacy caveat in §4.3: `first_bytes` is raw payload.) |
| 13 | **signatures.log** | `base/frameworks/signatures/main.zeek` | `ts, uid, src_addr, src_port, dst_addr, dst_port, note, sig_id, event_msg, sub_msg, sig_count, host_count` | Zeek's **own horizontal/vertical scan thresholds exposed as data** (`horiz_scan_thresholds = {5,10,50,100,500,1000}`). `sig_count`/`host_count` are pre-aggregated scan features rather than raw events. |
| 14 | **software.log** | `base/frameworks/software/main.zeek` | `ts, host, host_p, software_type, name, version, unparsed_version` | Per-host **software inventory with version**. Feeds `Notice::Vulnerable_Version` and `Software_Version_Change` (the latter is the "attacker replaced sshd" detection); `conn.log` has no notion of application identity. |
| 15 | **known_services.log** | `policy/protocols/conn/known-services.zeek` | `ts, host, port_num, port_proto, service` | First-seen **listening service per host** — a backdoor port appearing on an existing asset is visible as a new tuple. |
| 16 | **known_hosts.log** | `policy/protocols/conn/known-hosts.zeek` | `ts, host` | First-seen asset. Minimal (2 fields) but the cheapest baseline for "is this host new?", which is a common hunt pivot. |
| 17 | **pe.log** | `base/files/pe/main.zeek` | `ts, id, machine, compile_ts, os, subsystem, is_exe, is_64bit, uses_aslr, uses_dep, uses_code_integrity, uses_seh, has_import_table, has_export_table, has_cert_table, has_debug_data, section_names` | **Static executable metadata** for transferred binaries. A very old `compile_ts`, missing ASLR/DEP bits and unusual `section_names` triage the *tool* rather than the traffic. |
| 18 | **rdp.log** | `base/protocols/rdp/main.zeek` | `ts, uid, id, cookie, result, security_protocol, client_channels, keyboard_layout, client_build, client_name, client_dig_product_id, desktop_width, desktop_height, requested_color_depth, cert_type, cert_count, cert_permanent, encryption_level, encryption_method` | RDP **client fingerprint and negotiation outcome**. `conn.log` shows `service=ssl` on 3389 (the RDP doc's own example) — it cannot show *which client* or whether negotiation was downgraded. |
| 19 | **smtp.log** | `base/protocols/smtp/main.zeek` | `ts, uid, id, trans_depth, helo, mailfrom, rcptto, date, from, to, cc, reply_to, msg_id, in_reply_to, subject, x_originating_ip, first_received, second_received, last_reply, path, user_agent, tls` | Mail **envelope + relay identity**. `helo` vs sending domain mismatch and `x_originating_ip` are the classic anomalies; `conn.log` sees only port 25/587. |
| 20 | **socks.log** | `base/protocols/socks/main.zeek` | `ts, uid, id, version, user, password, status, request, request_p, bound, bound_p` | Internal **proxy/pivot** usage. Rare on most networks, which is what makes it high-precision. |
| 21 | **known_certs.log** | `policy/protocols/ssl/known-certs.zeek` | `ts, host, port_num, subject, issuer_subject, serial` | Cert→host binding that survives **SNI absence**, plus cross-host certificate reuse (`serial`) — a pivot for grouping infrastructure. |
| 22 | **ftp.log** | `base/protocols/ftp/info.zeek` | `ts, uid, id, user, password, command, arg, mime_type, file_size, reply_code, reply_msg, data_channel, fuid` | FTP **command and path** semantics (`RETR`/`STOR`, argument paths) — staging and exfil over a cleartext channel. |
| 23 | **websocket.log** | `base/protocols/websocket/main.zeek` | `ts, uid, id, host, uri, user_agent, subprotocol, client_protocols, server_extensions, client_extensions` | C2 over WebSocket handshakes. A WS upgrade on an unusual host is a small, tractable hunt; `conn.log` shows one long-lived TCP flow. |
| 24 | **radius.log** | `base/protocols/radius/main.zeek` | `ts, uid, id, username, mac, framed_addr, tunnel_client, connect_info, reply_msg, result, ttl` | Network-auth events — identity + hardware binding in one row. Only useful if RADIUS/VPN is actually on the wire. |
| 25 | **smb_cmd.log** | `policy/protocols/smb/log-cmds.zeek` (requires the policy load) | `ts, uid, id, command, sub_command, argument, status, rtt, version, username, tree, tree_service, referenced_file` | Command-level SMB detail. **Ranked last despite rich fields** because its own script header says it is "primarily useful for debugging" and expects high volume. See §4. |

---

## 2. How I ranked, and the one place I'd overturn a prior decision

**The ranking axis is adversarial semantics per row**, not row count. A log earns the top of the list
when it converts a *technique* into a queryable predicate. That is what separates `kerberos.log`
(`cipher` = RC4 + fan-out of distinct `service` values from one `client` is Kerberoasting) from
`known_hosts.log` (`ts, host` — useful, but it answers "is this new?", a single narrow question).

Corroboration for "these specific logs, because these specific techniques": MITRE's BZAR package
detects ATT&CK-like activity by combining exactly the SMB and DCE-RPC logs — it flags T1003.006
DCSync from `dce_rpc` `endpoint::operation` containing `drsuapi::DRSGetNCChanges`, and T1021.002 /
T1570 / T1569.002 / T1047 / T1053.00x from `smb_write` paths containing `ADMIN$` or `C$` correlated in
time with `svcctl::CreateServiceW`, `IWbemServices::ExecMethod`, or `atsvc::JobAdd`. That is the
reference implementation confirming that the top four rows are the ones carrying lateral-movement and
execution semantics. ([github.com/mitre-attack/bzar](https://github.com/mitre-attack/bzar))

**The technique-to-log mapping is verified against ATT&CK pages I fetched**, not asserted:

| Technique | Log that carries it | Verifying source |
|---|---|---|
| T1558.003 Kerberoasting | kerberos.log (`service`, `cipher`, `request_type`) | attack.mitre.org/techniques/T1558/003/ |
| T1550.002 Pass the Hash | ntlm.log (`username`↔`hostname`) | attack.mitre.org/techniques/T1550/002/ |
| T1569.002 Service Execution | dce_rpc.log (`svcctl::CreateServiceW`) | attack.mitre.org/techniques/T1569/002/ |
| T1021.002 SMB/Admin Shares | smb_mapping.log (`path`), smb_files.log (`action`) | attack.mitre.org/techniques/T1021/002/ |
| T1021.001 RDP | rdp.log (`client_name`, `security_protocol`) | attack.mitre.org/techniques/T1021/001/ |
| T1071.004 DNS C2 | dns.log (already ingested) | attack.mitre.org/techniques/T1071/004/ |
| T1048.003 Exfil over Alt Protocol | smtp.log / ftp.log / dns.log | attack.mitre.org/techniques/T1048/003/ |
| T1572 Protocol Tunneling | tunnel.log (`tunnel_type`) | attack.mitre.org/techniques/T1572/ |
| T1046 Network Service Discovery | signatures.log (`sig_count`, `host_count`) | attack.mitre.org/techniques/T1046/ |

### 2.1 Where I disagree with `weirvern-zeek-log-expansion.md`

That doc demotes `tunnel.log` to position 23 and places `dhcp.log` at 6. I have them at **9** and **8**.
Reason: for hunting, `tunnel.log` is one of very few logs where the **mere existence of a row is the
finding**. Zeek's own documentation says so plainly — "*the presence of a `tunnel.log` in your collection
of Zeek outputs means Zeek has detected and reported on encapsulated traffic. If you do not expect to
see such activity in your environment, it is worth investigating*"
([docs.zeek.org/en/current/logs/tunnel.html](https://docs.zeek.org/en/current/logs/tunnel.html)). A log
whose empty/non-empty state is itself a signal deserves better than last place in a *hunting* ranking,
even though it produces almost no ML features. Conversely `dhcp.log` drops because its hunting role is
pivoting, not detecting.

### 2.2 Where I'd overturn an earlier rejection: `x509.log` (rank 6)

The sibling doc already argues this and I agree, from the hunting side. The original objection was
"volume without investigative value." Volume is bounded three times over by default in 9.0.0:
x509.log deduplicates via `deduplication_index` / `relog_known_certificates_after`; the default site
policy loads `policy/protocols/ssl/log-hostcerts-only.zeek` (present and active in `scripts/site/local.zeek`),
which suppresses CA-chain entries; and `log_x509_in_files_log` is off, so certs don't duplicate into
`files.log`. What remains is one row per distinct **leaf** certificate per day.

The investigative value is that `ssl.log` structurally *cannot* express it: `cert_chain_fps` is an
ordered vector of fingerprint strings (`scripts/base/protocols/ssl/files.zeek`). To ask "is this
server's certificate self-signed, or does its SAN contradict the SNI?" you must join to `x509.log` on
`fingerprint`. **Posture:** ingest it, keep dedup and `log-hostcerts-only`, store `fingerprint` as the
join key, and project `certificate.subject`, `certificate.issuer`, `certificate.key_length`,
`certificate.sig_alg`, `certificate.not_valid_after`, `basic_constraints.ca`, and `san.dns`. Drop
`extensions[].value` — largest field, least signal, and it is bulk certificate content.

---

## 3. Already-ingested logs: what the current 8 already buy you

For completeness, so the gap analysis is honest — these are not "missing", and two of them are
irreplaceable:

- **`conn.log`** — the `uid` join key. Every other log resolves through it; nothing else can anchor a
  6-month-old `notice.log` back to a 5-tuple.
- **`dns.log`** — highest hunting value of the eight. `query`, `answers`, `rcode_name`
  (`NXDOMAIN` volume = DGA/beaconing), `TTLs`, `rejected`, `qtype_name`. Also carries `rtt`.
- **`http.log`** — `uri`, `host`, `user_agent`, `status_code`, `trans_depth`, `proxied`.
- **`ssl.log`** — `server_name` (SNI), `version`, `cipher`, `curve`, `resumed`, `last_alert`,
  `established`, `cert_chain_fps` (`client_cert_chain_fps`), `sni_matches_cert`, and `ssl_history`
  (a compact handshake-state string — see the documented letter table in the `SSL::Info` record).
  **Missing from your corpus because they are off by default:**
  `subject`/`issuer` (`log_include_server_certificate_subject_issuer = F`).
- **`ssh.log`** — `auth_success`, `auth_attempts`, `direction`, `client`, `server`, `cipher_alg`,
  `kex_alg`, `host_key_alg`, `host_key_fingerprint`. `host_key_fingerprint` pins a host independent
  of IP, which is excellent for lateral-movement hunting. (The `hassh*` fields in Zeek's own ssh.log
  doc example come from the separate `corelight/hassh` package, not core Zeek.)
- **`files.log`** — `fuid`, `mime_type`, `filename`, `seen_bytes`, `analyzers`, plus `md5`/`sha1`/`sha256`
  from `base/files/hash/main.zeek`. Hashes are the durable pivot to threat intel.
- **`notice.log`** — the closest thing Zeek has to IDS alerts.
- **`weird.log`** — protocol-level surprises. Useful, but see §4 on its volume.

**One high-ROI field expansion, not a new log:** loading
`policy/protocols/ssl/ssl-log-ext.zeek` adds `client_ciphers`, `ssl_client_exts`, `ssl_server_exts`,
`sigalgs`, `hashalgs`, `client_curves`, `client_supported_versions`, `server_key_share_group`,
`ticket_lifetime_hint`, `dh_param_size`, `orig_alpn` to the **already-ingested** `ssl.log`. Core Zeek
9.0.0 emits **no** `ja3` field — I confirmed by grepping the entire `scripts/` tree; there is no
`ja3.zeek` anywhere in the tree. JA3/JA4 arrives either via the `salesforce/ja3` package or by
computing the hash in ClickHouse from these columns.

---

## 4. LOW value, or actively risky — and why

### 4.1 Operational logs — not hunting data (do not feed the hunting corpus)

These are diagnostics about Zeek itself, not about the adversary. They belong in a monitoring table,
never in the hunt corpus:

- **`stats.log`** (`ts, peer, mem, pkts_proc, bytes_recv, pkts_dropped, events_proc, active_tcp_conns, …`, 27 fields)
- **`reporter.log`** (`ts, level, message, location`)
- **`capture_loss.log`** (`ts, ts_delta, peer, gaps, acks, percent_lost`) — **agree with keeping it out of the
  hunt corpus, with a refinement:** `percent_lost` is a *detection-quality* signal, not a detection.
  High loss invalidates any negative result ("I hunted and found nothing") because your sensor was
  blind. Route it to a table that annotates query confidence.
- **`loaded_scripts.log`**, **`packet_filter.log`**, **`broker.log`**, **`cluster.log`**,
  **`config.log`**, **`openflow.log`**, **`netcontrol*.log`**, **`telemetry*.log`**,
  **`analyzer_debug.log`** (explicitly a development stream), **`print.log`**, **`prof.log`**,
  **`stdout.log`/`stderr.log`**.

### 4.2 High volume, low signal-per-row

- **`smb_cmd.log`** — rich fields, but the declaring script's own header says it is "primarily useful
  for debugging", and it logs per SMB command *with its reply*. It also requires an explicit
  `@load policy/protocols/smb/log-cmds.zeek`. Ranked 25th for this reason.
- **`weird.log`** (already ingested) — Zeek's own docs are blunt: "*Weirds can often be ignored
  because of volume.*" The 24-hour sample in the docs shows one home network producing 553
  `window_recision` and 128 `non_ip_packet_in_ethernet` events, and Fatema Bannat Wala's write-up
  reports a university network with **2.6M `DNS_RR_unknown_type`** in 24 hours. Two concrete
  triage rules from that source: `possible_split_routing` usually means *your* asymmetric
  capture/load-balancing is misconfigured, not that someone is attacking you; and `bad_ICMP_checksum`
  / `TCP_Christmas` **are** scanner-correlated, but `bad_ICMP_checksum` is also generated by ordinary
  traceroute and network troubleshooting, so never auto-block on it.
  ([zeek.org/2019/11/what-is-weird-in-zeek/](https://zeek.org/2019/11/what-is-weird-in-zeek/))
- **`known_services.log`** — note from the docs' own example that many entries have an *empty*
  `service` set (ephemeral ports). Filter on non-empty `service`.

### 4.3 Privacy-exposing — the concrete, source-verified list

The default site policy in 9.0.0 has `HTTP::default_capture_password` off,
`LDAP::default_capture_password` off, and FTP redacts the password (and the `PASS` argument) with the
literal string `"<hidden>"` for any user not in `guest_ids`, which defaults to
`{ "anonymous", "ftp", "ftpuser", "guest" }` (`scripts/base/protocols/ftp/main.zeek`).
**The following are the functional equivalent of turning that back on**, because they ship raw
payload/credential bytes into the database by default:

| Field | Log | Why it is a payload leak |
|---|---|---|
| `first_bytes` | `unknown_protocols.log` | Raw **hex** payload prefix of an unidentified protocol (written via `bytestring_to_hexstr`). |
| `failure_data` | `analyzer.log` | 40-byte payload excerpt, truncated by `failure_data_max_size = 40`. **Do not try to disable this by setting `failure_data_max_size = 0` — see the correction below.** |
| `payload` | `mqtt_publish.log` | Message body. IoT-only; truncation requires `MQTT::max_payload_size`, which shortens rather than removes. |
| `community` | `snmp.log` | A **plaintext credential** by protocol design (it is the v1/v2c community string; for v3 it carries the username). |
| `message` | `syslog.log` | Free-text device content — a log-analytics problem, not a network-feature problem. Put it in its own namespace. |
| `username`/`password` | `socks.log` | `password` is only assigned when `capture_password` is true (`option default_capture_password = F`). Keep it off. |
| `mac` | `dhcp.log` | A persistent hardware identifier — the strongest pseudonymous tracker on the wire. |
| `from, to, cc, subject, msg_id` | `smtp.log` | Direct identifiers plus message content in one row. Highest privacy surface of any log here. |
| `filter`, `base_object` | `ldap_search.log` | Reveal directory structure. The bind `argument` is already set to `"REDACTED"` while `default_capture_password` is off. |

**Two rules that fall out of this table.** (1) Any log whose *default* output includes payload bytes
should have those columns dropped at ingestion, not just excluded from the feature store — ClickHouse
retention is what makes it a leak. Note the trap: for `analyzer.log` the truncation guard is
**inverted** —

```zeek
option failure_data_max_size = 40;
...
if ( failure_data_max_size > 0 )
    rec$failure_data = info$data[0:failure_data_max_size];
else
    rec$failure_data = info$data;      # <- 0 means log the WHOLE payload
```

`scripts/base/frameworks/analyzer/logging.zeek`. Setting it to `0` disables the *truncation*, i.e. it
logs the **entire** violating payload instead of the first 40 bytes. This directly contradicts the
guidance in `weirvern-zeek-log-expansion.md` §5, which recommends "set `failure_data_max_size = 0` if
you want the log without payload". That is wrong as written: there is no option value that removes the
field. **Drop `failure_data` at the ClickHouse ingest layer instead.** (2) `dhcp.log:mac`,
`ntlm.log:username`, `kerberos.log:client` are the fields that convert this corpus from traffic
telemetry into identifiable persons. That is the price of ranks 1, 5 and 8; pay it deliberately, and
see `zeek-retention-privacy-research.md` for the periods.

### 4.4 Situational — add only if the protocol exists on your wire

`irc.log` (legacy botnet C2, `nick/user/command/value/addl` — effectively extinct on a modern
network), `modbus.log` / `dnp3.log` / `known_modbus.log` (ICS-only), `rfb.log` (VNC), `mysql.log` /
`postgresql.log` / `redis.log` (add only if those servers are actually exposed on the wire),
`sip.log` (VoIP), `mqtt_*.log` (IoT, and see the payload note above), `snmp.log`,
`traceroute.log` (only 4 fields — `ts, src, dst, proto` — gated behind an unloaded policy script, and
`scripts/site/local.zeek` warns it "could possibly cause performance trouble"), `ocsp.log` (gated
behind an unloaded policy script, and only useful if you also run `validate-ocsp.zeek`, which puts a
live outbound dependency on the sensor).

---

## 5. Practical notes that change whether a log is actually useful

Two things that are easy to get wrong, both verified in the 9.0.0 source:

1. **`kerberos.log` suppresses AS-REP-roasting evidence by default.** `KRB::ignored_errors` suppresses
   `NEEDED_PREAUTH`. The source comment is explicit that detecting AS-REP roasting requires logging
   `NEEDED_PREAUTH`. If you want that hunt, empty the set and accept the noise.
   Also: `error_code` is declared **without** `&log` — it is *not in the log*. Use `error_msg`.
2. **Several logs only exist if a policy script is loaded**, and the declaring file is not always
   where you'd guess — `known_hosts`/`known_services`/`known_certs` live under
   `policy/protocols/…` and are loaded by `scripts/site/local.zeek`, not `base/`; `smb_cmd.log` needs
   `policy/protocols/smb/log-cmds.zeek`; `unknown_protocols.log`, `traceroute.log` and
   `capture_loss.log` need their policy scripts. `intel.log` needs `Intel::read_files` plus the
   `frameworks/intel/seen` scripts to be loaded before it will ever match — the framework's "where"
   locations are enumerated in `policy/frameworks/intel/seen/where-locations.zeek` and span conn, DNS,
   HTTP headers/URL, files (hash and name), SMTP fields, `SSH::IN_SERVER_HOST_KEY`,
   `SSL::IN_SERVER_NAME`, `SMB::IN_FILE_NAME` and `X509::IN_CERT`. The authoritative check is
   `Log::create_stream`'s `$path=` — the declaring script is part of the investigation.

---

## 6. What I fetched, and what I could not verify

**Fetched successfully (HTTP 200)** — these are the URLs behind every claim above:

- `https://docs.zeek.org/en/current/logs/index.html` — the common-logs walkthrough index
- `https://docs.zeek.org/en/current/` — Book of Zeek front page (title reads **9.1.0-dev.108**)
- `https://docs.zeek.org/en/current/scripts/base/protocols/dhcp/main.zeek.html`
- Per-log docs: `.../logs/dhcp.html`, `.../logs/x509.html`, `.../logs/tunnel.html`, `.../logs/rdp.html`,
  `.../logs/smtp.html`, `.../logs/ntp.html`, `.../logs/quic.html`, `.../logs/pe.html`,
  `.../logs/smb.html`, `.../logs/conn.html`
- `https://zeek.org/2019/11/what-is-weird-in-zeek/` (Fatema Bannat Wala — weird taxonomy and volume)
- `https://github.com/mitre-attack/bzar` — ATT&CK→SMB/DCE-RPC indicator mapping
- `https://docs.securityonion.net/en/2.4/zeek.html` and `.../en/2.4/` — deployment practice
  (JSON output, HOME_NET, AF-PACKET workers, capture-loss vs packet-loss distinction)
- ATT&CK technique pages: `T1572`, `T1046`, `T1558/003`, `T1021/001`, `T1021/002`, `T1550/002`,
  `T1569/002`, `T1048/003`, `T1071/004`
- **`github.com/zeek/zeek` cloned locally, checked out tag `v9.0.0`** — every field name in §1 and §3
  was extracted programmatically from record definitions in this tree, and the log→file map from all
  76 `Log::create_stream` calls. The official log catalogue (all filenames grouped by category) is
  `doc/reference/zeekscript/log-files.rst`; the per-log narrative docs behind `docs.zeek.org/.../logs/*.html`
  are the RST sources under `doc/reference/logs/`.

**Fetches that failed — reported rather than papered over:**

- **`docs.zeek.org` aggressively rate-limits (HTTP 429).** `.../logs/socks.html`,
  `.../logs/signatures.html`, `.../logs/unknown_protocols.html`, `.../logs/intel.html`,
  `.../logs/software.html`, `.../logs/kerberos.html` and `.../logs/dce_rpc.html` returned **404** —
  those per-log walkthrough pages **do not exist**; the walkthrough set is the 25 files listed in
  `doc/reference/logs/index.rst`. Others (`ntlm`, `ldap`, `ftp`, `irc`, `dnp3`, `modbus`, `sip`, and
  even `dhcp`/`tunnel`/`x509` on retry) returned **429**. I worked around this entirely by reading the
  RST sources from the v9.0.0 clone instead, so nothing here depends on a blocked page.
- `corelight.com/blog/*` and `elastic.co/blog/zeek-network-security-monitoring` returned **404** —
  those specific posts are gone. **No Corelight or Elastic blog content is cited in this document**;
  I did not substitute another source and pretend it was theirs.
- `web_search` is broken in this environment (returns empty); `web_extract`'s backend is search-only
  and cannot extract URLs. All retrieval above used `curl` and `urllib` directly, per the task note.

**Could not verify / [unverified]:**

- I did **not** have access to a running Weirvern cluster (`kubectl` unavailable from this session), so
  I could not confirm which policy scripts *this deployment* actually loads, nor read the live
  ClickHouse schema. §5 item 2 is therefore a general rule, not a statement about Weirvern's config.
- Two sibling-doc claims I could **not** reproduce against the v9.0.0 tree and did not repeat as fact:
  (a) that `conn.log` gains `speculative_service` by default — the script
  `policy/protocols/conn/speculative-service.zeek` exists but I did not trace its load status;
  (b) that x509.log's volume is "smaller than `known_certs.log`" — plausible given dedup, but I could
  not verify row counts without live data.
- **The `tunnel_type` values are verified from `src/types.bif`** (`NONE, IP, AYIYA, TEREDO, SOCKS,
  GTPv1, HTTP, GRE, VXLAN, GENEVE`), not from the log doc, which only mentions IP, GRE and TEREDO.
- Where the docs' JSON examples disagree with the 9.0.0 source (noted in the warning box at the top),
  I trusted the **source**, not the example.

---

### Sources

- Zeek 9.0.0 source (`github.com/zeek/zeek`, tag `v9.0.0`) — record definitions under
  `scripts/base/protocols/*/main.zeek`, `scripts/base/protocols/ftp/info.zeek`,
  `scripts/base/files/{pe,x509}/main.zeek`, `scripts/base/protocols/ssl/files.zeek`,
  `scripts/base/protocols/ssl/ssl-log-ext.zeek`, `scripts/base/frameworks/{files,signatures,tunnels,
  software,notice,analyzer,intel}/`, `scripts/base/misc/`, `scripts/policy/protocols/`,
  `scripts/policy/misc/`, `src/types.bif`, `scripts/site/local.zeek`
- Official log catalogue: `doc/reference/zeekscript/log-files.rst` — **the rendered page URL is
  [unverified]**: both candidate paths returned HTTP 429 from docs.zeek.org and I could not confirm
  which one serves it. The RST source in the v9.0.0 tree is authoritative and is what I read.
- Per-log documentation source: `doc/reference/logs/*.rst` (dhcp, tunnel, x509, rdp, smb, quic, pe,
  ssh, ssl, weird-and-notice, known-and-software, analyzer, capture-loss-and-reporter, conn, dns,
  smtp, ntp, ftp, ldap, irc, postgresql, traceroute, files, http)
- https://docs.zeek.org/en/current/logs/index.html · https://zeek.org/2019/11/what-is-weird-in-zeek/
- https://github.com/mitre-attack/bzar
- https://docs.securityonion.net/en/2.4/zeek.html
- ATT&CK: T1046, T1048.003, T1021.001, T1021.002, T1071.004, T1550.002, T1558.003, T1569.002, T1572
- Related project docs: `weirvern-zeek-log-expansion.md` (ML-value ranking),
  `zeek-retention-privacy-research.md` (retention/privacy)
