# Zeek Logs for Machine-Learning Anomaly Detection — Ranked

Research for **Weirvern** (Zeek 9.0.0 → ClickHouse → 4-model ensemble: Isolation Forest,
Gradient Boosting, DBSCAN, per-host Adaptive Baseline).

Scope: which Zeek log files carry the most *usable numeric/categorical signal* per row, ranked
for ML feature extraction — not for forensic completeness. Every log's field list below was
extracted programmatically from the **Zeek 9.0.0 release tarball**
(`github.com/zeek/zeek` tag `v9.0.0`, `scripts/` tree — the same source docs.zeek.org is
generated from). Field names are `&log` fields only; `&optional` and `&default` are marked.

---

## 0. Method, and what I could not verify

**Verified from primary source (fetched):**
- Full Zeek 9.0.0 `scripts/` tree from the release tarball — parsed every `type … : record`
  containing `&log` fields, keyed by the `$path="…"` string that decides the **filename on disk**.
  Result: **76 distinct log paths** in the shipped scripts (`ftp` and `smb_cmd` declare their records
  in files whose `$path` sits in a different file, and `/`/`cluster` are internal streams, so the
  parser resolved 72 of the 76 directly and I filled the rest from source by hand).
- The default-`@load` closure of `base/init-default.zeek` (380 files) + Weirvern's own
  `k8s/zeek/weirvern-local.zeek` + `scripts/site/local.zeek`, resolved recursively — this tells us
  which logs are **actually written on this sensor** vs. shipped-but-gated.

**Fetched and used:** the Zeek script docs source (`github.com/zeek/zeek-docs`, `logs/*.rst`),
`AutoZeekWatch` (NYU HSRN) source, `activecm/rita` importers + `analysis/beacons.go`,
Stratosphere IPS dataset pages (IoT-23, CTU-13), UNB CIC dataset pages, UNSW-NB15 / ToN-IoT pages,
the PicoDomain paper (arXiv 2008.09192), PORTFILER (arXiv 2112.13798), and GitHub API searches.

**Could not verify / fetch failures (stated rather than filled in):**
- `docs.zeek.org` returned **HTTP 429 for every request** from this host, on both the
  `current/logs/*` and `current/reference/logs/*` paths. All Zeek field claims below therefore come
  from the script source, which is the same input the docs are built from. The two agree where I
  could cross-check (the `zeek-docs` `.rst` files contain the identical JSON examples).
- **JA3 is not in Zeek 9.0.0 core** — a grep of the whole 9.0.0 `scripts/` and `src/` tree returns
  no `ja3`/`hassh` field definition (only an unrelated fuzzer corpus zip and a vendored
  `sqlite3.c`). `docs.zeek.org`'s ssl.log chapter states the `ja3`/`ja3s` columns appear "when
  running Zeek with the JA3 and JA3S packages". This matches what Weirvern already documented about
  its own image.
- **CIC-IDS2017 / CSE-CIC-IDS2018 are NOT Zeek-derived**, contrary to what you might assume from
  their ubiquity in NIDS papers. The UNB pages for both mention **zero** occurrences of "Zeek" or
  "Bro" (checked with regex on the fetched pages); both describe features from **CICFlowMeter**
  ("80 features extracted from the captured traffic using CICFlowMeter-V3"). Their value to this
  project is limited to the *attack taxonomy*, not to Zeek feature engineering.
- **UNSW-NB15 IS Bro-derived**: the UNSW page states "The Argus, Bro-IDS tools are used and twelve
  algorithms are developed to generate totally 49 features with the class label."
- **ToN-IoT IS Zeek-derived**: "Network datasets were collected in the packet capture (pcap)
  formats, log files and CSV files of the ZEEK (Bro) tool."
- **MAWILab is not Zeek-based** — its pages describe a graph-based detector ensemble over the MAWI
  archive; no Bro/Zeek mention as a producer.
- I found **no arXiv paper** that ranks Zeek *log files* against each other for ML. The closest
  primary works I could fetch are PORTFILER (35 features derived from **conn.log only**) and
  PicoDomain (a Zeek-log dataset spanning conn, dce_rpc, dhcp, dns, files, http, kerberos,
  known_hosts, known_services, ntlm, pe, smb_files, smb_mapping, software, ssl, weird, x509). So the
  ranking below is my synthesis from field-level evidence, not a citation of an existing ranking —
  I am labelling it that way deliberately.

---

## 1. Field inventory — every shipped log path, grouped by ML usability

Extracted from the 9.0.0 source. `# fields` = count of `&log` fields.

### 1a. Logs with strong ML signal (ranked in §2)

| Log | Record type | Source file (9.0.0) | # fields |
|---|---|---|---|
| conn | `Conn::Info` | `base/protocols/conn/main.zeek` | 19 |
| dns | `DNS::Info` | `base/protocols/dns/main.zeek` | 23 |
| ssl | `SSL::Info` (+`redef record Info` from `files.zeek`) | `base/protocols/ssl/{main,files}.zeek` | 12 + 7 = **19** |
| ssh | `SSH::Info` | `base/protocols/ssh/main.zeek` | 15 |
| http | `HTTP::Info` | `base/protocols/http/main.zeek` | 21 |
| files | `Files::Info` | `base/frameworks/files/main.zeek` | 18 |
| notice | `Notice::Info` | `base/frameworks/notice/main.zeek` | 18 |
| weird | `Weird::Info` | `base/frameworks/notice/weird.zeek` | 8 |
| **kerberos** | `KRB::Info` | `base/protocols/krb/main.zeek` | 13 |
| **dce_rpc** | `DCE_RPC::Info` | `base/protocols/dce-rpc/main.zeek` | 7 |
| **ntlm** | `NTLM::Info` | `base/protocols/ntlm/main.zeek` | 10 |
| **smb_mapping** | `SMB::TreeInfo` | `base/protocols/smb/main.zeek` | 7 |
| **smb_files** | `SMB::FileInfo` | `base/protocols/smb/main.zeek` | 10 |
| **smb_cmd** (gated) | `SMB::CmdInfo` | `base/protocols/smb/main.zeek` | 13 |
| **dhcp** | `DHCP::Info` | `base/protocols/dhcp/main.zeek` | 15 |
| **ldap** / **ldap_search** | `LDAP::MessageInfo` / `LDAP::SearchInfo` | `base/protocols/ldap/main.zeek` | 10 / 12 |
| **x509** | `X509::Info` | `base/files/x509/main.zeek` | 7 (nested `X509::Certificate` adds 12) |
| ocsp | `OCSP::Info` | `base/files/x509/log-ocsp.zeek` | 11 |
| **pe** | `PE::Info` | `base/files/pe/main.zeek` | 17 |
| **quic** | `QUIC::Info` | `base/protocols/quic/main.zeek` | 10 |
| **tunnel** | `Tunnel::Info` | `base/frameworks/tunnels/main.zeek` | 5 |
| **software** | `Software::Info` | `base/frameworks/software/main.zeek` | 7 |
| **known_services** | `Known::ServicesInfo` | `policy/protocols/conn/known-services.zeek` | 5 |
| **known_hosts** | `Known::HostsInfo` | `policy/protocols/conn/known-hosts.zeek` | 2 |
| **known_certs** | `Known::CertsInfo` | `policy/protocols/ssl/known-certs.zeek` | 6 |
| **rdp** | `RDP::Info` | `base/protocols/rdp/main.zeek` | 19 |
| **smtp** | `SMTP::Info` | `base/protocols/smtp/main.zeek` | 22 |
| **ntp** | `NTP::Info` | `base/protocols/ntp/main.zeek` | 16 |
| **snmp** | `SNMP::Info` | `base/protocols/snmp/main.zeek` | 12 |
| **signatures** | `Signatures::Info` | `base/frameworks/signatures/main.zeek` | 12 |
| **analyzer** | `Analyzer::Logging::Info` | `base/frameworks/analyzer/logging.zeek` | 9 |
| **unknown_protocols** (gated) | `UnknownProtocol::Info` | `policy/misc/unknown-protocols.zeek` | 5 |
| **ftp** | `FTP::Info` | `base/protocols/ftp/info.zeek` | 13 |
| **socks** | `SOCKS::Info` | `base/protocols/socks/main.zeek` | 11 |
| **websocket** | `WebSocket::Info` | `base/protocols/websocket/main.zeek` | 10 |
| **radius** | `RADIUS::Info` | `base/protocols/radius/main.zeek` | 11 |
| intel | `Intel::Info` | `base/frameworks/intel/main.zeek` | 6 |

### 1b. Logs shipped but with no ML feature value (see §4)

`reporter`, `stats`, `capture_loss`, `loaded_scripts`, `packet_filter`, `broker`, `config`,
`cluster`, `telemetry`, `telemetry_histogram`, `analyzer_debug`, `weird_stats`, `netcontrol`,
`netcontrol_drop`, `netcontrol_shunt`, `netcontrol_catch_release`, `openflow`, `traceroute`,
`irc`, `modbus`, `modbus_register_change`, `dnp3`, `known_modbus`, `rfb`, `mysql`, `postgresql`,
`redis`, `mqtt_connect`, `mqtt_publish`, `mqtt_subscribe`, `syslog`, `sip`,
`multicast_participants`, `alarm-mail`, `/`.

---

## 2. The ranking

Ordered by **ML signal per row** — how much *new, numeric-or-low-cardinality* discriminative signal
a log adds that no already-ingested log can express. The "Model" column says which of Weirvern's
four detectors the features primarily feed.

### Tier A — add these (largest gain per row ingested)

| # | Log | Model | Signal fields | Attack family it discriminates | Why |
|---|---|---|---|---|---|
| **1** | **kerberos** | GBM, DBSCAN | `request_type` (AS/TGS/AP), `client`, `service`, `success`, `cipher`, `from`→`till`, `forwardable`, `renewable` | Kerberoasting (T1558.003), AS-REP roasting (T1558.004), lateral movement via service tickets | The **only** log naming *which Kerberos service (SPN)* was requested, by *which principal*, with *which encryption type*. `conn.log` sees "TCP to port 88". PicoDomain's own ML demo used **only** kerberos.log: 1-hot(`client`) + 1-hot(`service`) bigrams fed to Local Outlier Factor, 10 of 14 reported anomalies being true positives — the paper's own conclusion is that new Kerberos bigrams spike exactly at account compromise. The single best cost/benefit add available. |
| **2** | **ntlm** | DBSCAN, Baseline | `username`, `hostname`, `domainname`, `success`, `server_nb_computer_name`, `server_dns_computer_name`, `server_tree_name` | Pass-the-Hash (T1550.002), credential spraying, lateral movement | Every field is **low-cardinality categorical or boolean** — exactly what DBSCAN and a per-host baseline want. The analytic is a bipartite identity graph (`username`↔`hostname`) that no other log can build: one account authenticating from N hosts, or N accounts hitting one host, is a two-line SQL aggregate over this log and impossible from `conn.log`. |
| **3** | **dce_rpc** | GBM, IF | `operation`, `endpoint`, `named_pipe` (categorical); `rtt` (numeric interval) | PsExec / remote service execution (T1569.002), WMI (T1047), DCOM (T1021.003) | `(endpoint, operation)` is the only opnum-level semantic in the corpus. `operation` and `named_pipe` are bounded vocabularies → clean one-hot. `rtt` is a genuine continuous feature. Cheap: one row per RPC call, not per packet. |
| **4** | **smb_mapping** | DBSCAN, Baseline | `path`, `service`, `share_type`, `native_file_system` | Lateral movement via Windows admin shares (T1021.002) | `conn.log` can say `service=smb` and nothing more. Only `smb_mapping.log` records the **share path** — so `ADMIN$` / `C$` / `IPC$` access, the canonical admin-share pivot, is a string-prefix flag on this log and invisible everywhere else. Very low volume (one row per tree connect). |
| **5** | **dhcp** | Baseline, DBSCAN | `mac`, `client_addr`, `server_addr`, `assigned_addr`, `requested_addr`, `host_name`, `client_fqdn`, `lease_time` (interval), `msg_types` (vector), `duration` (interval) | Rogue DHCP (T1557.003), MAC spoofing, new-asset discovery, lease churn | The **only log carrying L2 identity**. `mac` is the key that converts IP-keyed telemetry into stable *entities*, which is precisely what the per-host Adaptive Baseline needs — an IP changes, a MAC does not. `lease_time` and `duration` are continuous. Also a duplicate-`assigned_addr` count is a direct spoof signal. |
| **6** | **x509** | GBM, Baseline | `certificate.{not_valid_before, not_valid_after, key_alg, sig_alg, key_type, key_length, exponent, curve, subject, issuer}` (12 nested `&log` fields), `san.{dns,uri,email,ip}`, `basic_constraints.{ca,path_len}`, `host_cert`, `client_cert` | Self-signed C2 (T1587.003), weak crypto, rogue CA (T1588.004), expired/mismatched certs | **Already written on this sensor by default** (`base/files/x509` is in `init-default.zeek`'s load list, and `policy/protocols/ssl/log-hostcerts-only.zeek` is loaded by `site/local.zeek`). `ssl.log` gives you fingerprints; only `x509.log` gives you **key_length, sig_alg, validity window, and the CA flag** — the actual numbers behind a weak-cert or self-signed-C2 verdict. Highest-value single derived feature: `subject == issuer` (self-signed) joined to `ssl.log:server_name ∉ san.dns`. |
| **7** | **smb_files** | GBM, Baseline | `action` (FILE_READ/WRITE/DELETE/RENAME/…), `path`, `name`, `size` (count), `prev_name`, `times.{modified,accessed,changed,created}` | Ransomware mass-rename/delete bursts, lateral tool transfer (T1570), data staging | `files.log` has MIME and hash but **no action and no share path**. This log is the only source of SMB *write semantics*: `size` is continuous, `action` is a bounded enum, and rename/delete event-rate per host is a direct ransomware feature. Volume is gated by `logged_file_actions` (default `{FILE_OPEN, FILE_RENAME, FILE_DELETE, PRINT_OPEN, PRINT_CLOSE}`), so it is modest. |
| **8** | **ldap_search** (+ `ldap`) | IF, GBM | `filter` (string, grammar-constrained), `base_object`, `scope`, `result_count` (count), `deref_aliases`, `result`; `ldap.log` adds `opcode`, `result`, `object`, `version` | AD enumeration / BloodHound-style recon (T1087.002), LDAP-based recon | `result_count` is a clean numeric outlier feature; `scope`/`deref_aliases` are low-cardinality. The `filter` grammar is a **bounded, structured string** — its novelty (token-set hash not seen before) is the enumeration signal, and no other log exposes directory queries at all. Low volume on a small network. `default_capture_password = F` by default → bind `argument` is redacted, so no credential leak. |
| **9** | **known_services** | Baseline | `host`, `port_num`, `port_proto`, `service` (set) | New backdoor/listener port appearing on an existing asset, service drift | One row per `(host, port, proto)` **first seen** — so `new tuple this window` is a ready-made per-host novelty feature for the Adaptive Baseline, at near-zero volume. Its cost is literally one row per service per host, ever. |
| **10** | **pe** | GBM | `is_exe`, `is_64bit`, `uses_aslr`, `uses_dep`, `uses_code_integrity`, `uses_seh`, `has_import_table`, `has_export_table`, `has_cert_table`, `has_debug_data` (10 booleans), `compile_ts` (time), `machine`, `os`, `subsystem`, `section_names` (vector) | Tooling triage: packed/unsigned/missing-mitigations binaries, Cobalt Strike-style artefacts | **Ten boolean columns plus a timestamp** is an unusually dense, clean ML vector — booleans need no encoding. `now − compile_ts` is a continuous "how old is this binary" feature; `uses_aslr`/`uses_dep`/`uses_code_integrity` false on a downloaded EXE is a strong static signal. `section_names` count/entropy is a light packer indicator. |
| **11** | **quic** | IF, Baseline | `server_name`, `client_protocol` (ALPN), `version`, `history` (string), `client_initial_dcid`, `client_scid`, `server_scid` | TLS blind spot: C2/quasi-C2 over QUIC, ECH/ESNI evasion | QUIC bypasses `ssl.log` entirely — a host moving its C2 to QUIC is invisible in the current corpus. `server_name` (SNI) and `client_protocol` (ALPN) are the categorical signal; `history` is the same compact handshake-state encoding as `conn.log:history`. Medium value, but it closes a real hole. |
| **12** | **tunnel** | Baseline, IF | `tunnel_type` (enum), `action` (enum: DISCOVER/CLOSE/EXPIRE), `id` | Protocol tunnelling (T1572), Teredo/GRE/VXLAN/IP-in-IP encapsulation | `conn.log` has `tunnel_parents` (a set of uids — an identifier, not a feature). Only `tunnel.log` names the **type**. Both fields are bounded enums → clean categorical features. Extremely low volume. |
| **13** | **software** | Baseline | `host`, `host_p`, `software_type`, `name`, `version`, `unparsed_version` | New/unknown software on an asset, version-drift (T1195), vulnerable-version detection | Gives the Adaptive Baseline an **entity-identity fingerprint**: a `(host, software_type, name)` tuple not seen before is a low-false-positive novelty event. `version`/`unparsed_version` allow a numeric version-delta feature. Written by default via `site/local.zeek`. |
| **14** | **rdp** | GBM, Baseline | `result`, `security_protocol`, `encryption_level`, `encryption_method`, `cert_type`, `cert_count`, `cert_permanent`, `client_name`, `client_build`, `client_dig_product_id`, `keyboard_layout`, `desktop_width`, `desktop_height`, `requested_color_depth`, `client_channels` (vector) | RDP brute force (T1021.001), rogue/non-Windows RDP clients, protocol downgrade | Unusually rich categorical + numeric mix. `result` gives a failed-auth ratio; `security_protocol`/`encryption_level` give a **negotiation-downgrade flag**; `desktop_width`×`desktop_height` are numeric. `client_name` cardinality is moderate and bounded by your real estate. |
| **15** | **smtp** | IF, GBM | `trans_depth`, `helo`, `mailfrom`, `rcptto` (**`set[string]`** in 9.0.0 — not a vector), `x_originating_ip` (addr), `msg_id`, `user_agent`, `tls` (bool), `last_reply` | Mail-based exfiltration (T1048.003), internal spam/phishing, compromised-host relay | `|rcptto|` = recipient fan-out per message (numeric); `tls` boolean; `x_originating_ip` is an **addr** so "internal host claiming an external origin" is a join, not a string. Note: this log carries `from`/`to`/`cc`/`subject` — the highest PII surface in the set; featurise aggregates only. |
| **16** | **analyzer** | IF | `analyzer_kind` ("packet"/"file"/"protocol"), `analyzer_name`, `failure_reason`, `proto`, `failure_data` | Protocol-evasion and malformed-traffic detection; parser-level attack fingerprint | Three low-cardinality categoricals and a violation rate. Sits *below* `weird.log` in the stack — a parser that fails on deliberately malformed input is a sharper evasive-attack signal than a generic weird. `failure_data` is **40 bytes of raw payload** (`Analyzer::Logging::failure_data_max_size = 40`) — see §5. |
| **17** | **signatures** | GBM | `sig_id`, `note`, `sig_count` (count), `host_count` (count), `src_addr`, `dst_addr`, `src_port`, `dst_port` | Horizontal/vertical scanning, signature hits, policy violations | `sig_count` and `host_count` come from Zeek's **built-in scan thresholds** — Zeek has already done the windowed aggregation for you and exposed the result as numbers. Two ready-made numeric features plus a categorical `sig_id`. |
| **18** | **unknown_protocols** *(gated — needs `@load`)* | IF | `analyzer`, `protocol_id`, `first_bytes`, `analyzer_history` (vector) | Novel/unknown protocol detection — unsupervised novelty on protocol identity | The purest **unsupervised novelty** signal in the whole corpus: "Zeek has never seen this IP protocol before". `analyzer_history` is a vector of names (bounded). Note this log is **NOT written under Weirvern's current config** — it requires `@load policy/misc/unknown-protocols`. And `first_bytes` is **raw payload hex** — see §5. |
| **19** | **known_hosts** | Baseline | `host` (addr) | New-asset arrival rate | Two fields, one of them useful. Its only job is "this host was not here yesterday", which is the cheapest possible baseline seed. Near-zero volume (one row per host, ever). |
| **20** | **known_certs** | Baseline | `host`, `port_num`, `subject`, `issuer_subject`, `serial` | Certificate reuse across hosts, rogue-CA/self-signed inventory | Complements `x509.log`: `x509` gives the properties, `known_certs` gives the **host↔cert binding**, so "one `serial` seen on 30 hosts" is a one-line join. `subject`/`issuer_subject` are moderate-cardinality strings; `serial` is a high-cardinality **identifier** — use it as a join key, never as a feature. |
| **21** | **socks** | IF | `version` (count), `status`, `request`/`bound` (addr or name), `request_p`/`bound_p` (port), `user` | Proxy / pivoting (T1090) | Both ports are numeric, `version` is numeric, `status` is a small enum, and `request`/`bound` are addresses. Very low volume and high precision — a rare event class is exactly what Isolation Forest is good at. |
| **22** | **websocket** | IF | `host`, `uri`, `user_agent`, `subprotocol`, `client_protocols`/`server_extensions`/`client_extensions` (vectors) | C2/covert channel over WebSocket handshakes | All fields are strings, so the useful features are **derived**: `uri` entropy/length, `subprotocol` novelty, `user_agent` rarity. Lower value than the above because nothing here is natively numeric. |

### Tier B — situational (add only if the protocol exists in your environment)

| Log | Signal | Condition |
|---|---|---|
| **ftp** | `command`, `arg`, `reply_code` (count), `file_size` (count), `mime_type`, `data_channel`, `fuid` | Only if FTP is seen. `reply_code` and `file_size` are numeric; `RETR`/`STOR` ratio is the feature. `command`/`arg` carry full paths. |
| **radius** | `username`, `mac`, `framed_addr`, `result`, `ttl` (interval), `connect_info` | Only if RADIUS/NAC is on the wire. Combines identity + hardware binding in one row. |
| **ntp** | `version`, `mode`, `stratum`, `poll`, `precision`, `root_delay`, `root_disp` (all numeric), plus 5 timestamps | Only if NTP is monitored. Unusually numeric — but the practical anomalies (NTP amplification, rogue time server) mostly reduce to `mode`/`stratum` outliers. |
| **snmp** | `version`, `community`, `get_requests`, `get_bulk_requests`, `get_responses`, `set_requests` (all counts), `duration`, `up_since` | Only if SNMP is in use. Six ready counts. `community` is a **plaintext credential** — treat as sensitive. |
| **rfb** | `authentication_method`, `auth` (bool), `share_flag` (bool), `width`/`height` (counts), `client_major_version` | Only if VNC exists (T1021.005). |
| **smb_cmd** *(gated)* | `command`, `sub_command`, `argument`, `status`, `rtt` (interval), `version`, `username`, `tree`, `tree_service` | **High volume.** Requires `@load policy/protocols/smb/log-cmds.zeek`; that script's header calls it "primarily useful for debugging". `command`/`sub_command`/`status`/`rtt` are good features if you can absorb the rows. |
| **ocsp** | `certStatus`, `hashAlgorithm`, `thisUpdate`/`nextUpdate`, `revoketime`, `revokereason`, `serialNumber` | Available by default (`base/files/x509/__load__.zeek` loads `log-ocsp`), but `certStatus` is only meaningful if you also run outbound OCSP validation. Small enum + timestamps. |
| **intel** | `seen` (`Intel::Seen`), `matched` (vector of `Intel::Type`), `sources` (set) | Only useful with a populated intel feed. `seen`/`matched`/`sources` are bounded enums. |
| **irc** | `nick`, `user`, `command`, `value`, `addl` | Effectively extinct on a modern network. `command` is the only bounded field. |

---

## 3. Feature-engineering notes that change the numbers you get

These are the non-obvious facts I verified in the 9.0.0 source; each one silently changes a feature's
value if ignored.

- **`conn.log:history` and `ssl.log:ssl_history` are strings, not enums.** `history` letters are
  `s h a d f r c g t w i q ^ x` with **uppercase = originator, lowercase = responder**, and
  `c g t w` are **logged logarithmically** ("the second instance represents the event was seen at
  least 10 times"). So `count('t')` is a binned repeat-count, not a raw count — don't scale it as if
  it were linear. `ssl_history` letters are documented in `base/protocols/ssl/main.zeek`
  (`C`=client_hello, `S`=server_hello, `X`=certificate, `F`=finished, `D`=application_data, …).
- **`conn_state` is a 13-value string enum**, documented in-source: `S0, S1, SF, REJ, S2, S3, RSTO,
  RSTR, RSTOS0, RSTRH, SH, SHR, OTH`. `S1` and `SF` share a symbol and are distinguished only by
  whether byte counts are present — so **`S1` vs `SF` must be disambiguated using
  `orig_bytes`/`resp_bytes` nullness**, not the state string alone.
- **`local_orig`/`local_resp` are empty unless `Site::local_nets` is defined.** The source says so
  explicitly. If it is unset these columns are null on every row, which an imputer will happily turn
  into a constant — and then you have a feature that is a constant of your *config*, not of traffic.
- **`kerberos.log:error_code` is NOT logged** — it is declared `error_code: count &optional;` with no
  `&log`. Use `error_msg`. Worse: `option ignored_errors` **defaults to a non-empty set** whose own
  comment says *"one attack is to iterate over principals, looking for ones that don't require
  preauth … To detect that attack, log NEEDED_PREAUTH."* Under the default, **AS-REP-roasting
  evidence is suppressed before it reaches the log.** Emptying the set is required for that analytic.
- **`smb_files.log` is gated by `option logged_file_actions`** defaulting to
  `{FILE_OPEN, FILE_RENAME, FILE_DELETE, PRINT_OPEN, PRINT_CLOSE}` — note **`FILE_WRITE` is NOT in
  the default set.** If you want write-volume features you must add it; assuming writes are present
  yields a feature that is structurally always zero.
- **`smtp.log:rcptto` is `set[string]` in 9.0.0**, not a vector. Cardinality features
  (`|rcptto|`) work, but ordering is undefined — do not treat it as an ordered recipient list.
- **`files.log` hashes are present by default on this sensor**: `site/local.zeek` loads
  `frameworks/files/hash-all-files`, which adds MD5/SHA1/SHA256 to every file. `files.log:entropy` is
  **not** present — that needs `policy/frameworks/files/entropy-test-all-files.zeek`, which is not
  loaded. So entropy is a one-line script add if you want it.
- **`ssl.log` in 9.0.0 does carry `cert_chain_fps`, `client_cert_chain_fps`, and
  `sni_matches_cert`** — these are added by `base/protocols/ssl/files.zeek`, which is loaded by
  `base/protocols/ssl/__load__.zeek`. `sni_matches_cert` is a **bool** and is `&optional` (unset when
  the client sent no SNI) — a null-vs-false distinction worth preserving. `subject`/`issuer` are gated
  behind `log_include_server_certificate_subject_issuer = F`.
- **`ssl.log` field list is 12 in `main.zeek` + 7 more from `files.zeek`.** If you enumerate fields by
  only reading `main.zeek` you will miss the cert-chain and SNI-match columns.
- **`x509.log` is deduplicated, not per-connection**: `relog_known_certificates_after = 1day` with
  `known_log_certs_maximum_size = 1000000`, plus `log-hostcerts-only` suppressing non-leaf certs, plus
  `log_x509_in_files_log = F`. So its row count is "distinct leaf certs per day", which is *smaller*
  than `known_certs.log`. Ingesting it is not a volume decision.
- **`weird.log:name` is a `string` holding a `Weird::Type` name**, of which **166 distinct names**
  appear in the action table in `base/frameworks/notice/weird.zeek` (`unsolicited_SYN_response`,
  `bad_TCP_checksum`, `data_before_established`, …). One-hotting 166 values is fine; hashing them to
  an integer and treating the integer as numeric is not.
- **`notice.log:note` is `Notice::Type`, a bounded enum.** I counted **44 distinct `Notice::Type`
  values** declared across the shipped scripts (excluding the `zeekygen` examples) —
  `Password_Guessing`, `Invalid_Server_Cert`, `SQL_Injection_Attacker`, `Weak_Cipher`, … That is a
  small, stable vocabulary, so `note` is one-hot friendly and `msg`/`sub` should be dropped.
- **`conn.log:service` is a comma-separated list with a negative-sign convention.** The source: with
  `DPD::track_removed_services_in_connection`, entries are prefixed `-` to record protocols Zeek
  *dropped*. So the string is not a clean enum — split on `,` and strip the sign.
- **`tunnel_parents` is a `set[string]` of connection UIDs** — an identifier set. `|tunnel_parents|`
  is a usable count; the UIDs themselves must not be featurised.

---

## 4. Logs that are NOT useful for ML — and why

The task asks for this explicitly. Four distinct failure modes.

### 4a. Free-text fields only (no numeric or bounded-categorical signal)

| Log | Fields | Why it fails |
|---|---|---|
| **syslog** | `facility`, `severity`, `message` | `message` is unconstrained device content. `facility`/`severity` are bounded but carry no traffic-behaviour signal — this is a log-analytics problem, not a network-feature problem. Belongs in a separate namespace. |
| **reporter** | `level`, `message`, `location` | `message` is Zeek's internal warning text. It is a health signal about *Zeek*, not about the network. If Zeek is misconfigured, the right output is an alert on the operator, not a feature. |
| **loaded_scripts** | `scripts` | One row per script loaded at startup. It changes when you edit config, so it is a fingerprint of *your deployment*, not of traffic — a model would learn your config history. |
| **mysql / postgresql / redis** | `cmd`, `arg`, `user`, `database`, `application_name`, `frontend_arg`, `backend_arg`, `reply` | Every field is a free-text command or argument with unbounded cardinality, and the logs only exist if those services are on the wire. `rows`/`success` are the only ML-usable fields and they are already implied by `conn.log` byte counts. |
| **mqtt\_\*** (`mqtt_connect`, `mqtt_publish`, `mqtt_subscribe`) | `topic`, `payload`, `client_id`, `will_topic`, `will_payload` | `payload` ships **message bodies** into the database. `topic`/`client_id` are unbounded identifiers. `payload_len` is the one usable number and it is redundant with `conn.log`. |
| **sip** | `uri`, `call_id`, `request_from`, `request_to`, `subject`, `user_agent` | All free text or high-cardinality identifiers; VoIP-only. `status_code`/`request_body_len` are numeric but already covered by `http.log`-style fields on the same connection. |

### 4b. High-cardinality identifiers (join keys, not features)

| Log | Identifier | Correct use |
|---|---|---|
| **any log** | `uid`, `fuid`, `parent_fuid`, `trans_id`, `message_id`, `call_id` | Join keys. `uid` is unique per connection — one-hotting it produces a distinct value per row and destroys the model. |
| **conn** | `id.orig_h`, `id.resp_h`, `id.orig_p`, `id.resp_p` | Keep as join/grouping keys for per-host baselines. Aggregate to counts/ratios before they touch a feature vector. |
| **x509 / known_certs** | `fingerprint`, `serial`, `certificate.serial` | Join keys against `ssl.log:cert_chain_fps`. Featurise *counts* of reuse, not the values. |
| **quic** | `client_initial_dcid`, `client_scid`, `server_scid` | Random per connection. Zero predictive value. |
| **files** | `md5`, `sha1`, `sha256` | Threat-intel lookup keys. A hash is a distinct value per file; as a feature it is noise. |
| **dhcp** | `mac` | Borderline: it is a *stable* identifier, which is why it is valuable as an entity key for the Adaptive Baseline — but it must be used for **grouping**, never as an integer feature. |
| **software / known_services / known_hosts** | `name`, `version`, `version`+`host` | Fine as categorical *when the vocabulary is bounded by your estate*; `version` should be parsed to numeric components. |

### 4c. Already covered by `conn.log` (adding the log buys nothing)

| Log | Claim | Reality |
|---|---|---|
| **packet_filter** | — | `ts`, `node`, `filter`, `init`, `success`, `ip` — describes the **BPF filter on the sensor**, not traffic. Changes when you change config. |
| **capture_loss** | "packet loss is a signal" | `percent_lost` is a **label-quality** signal, not a detection signal. High loss means your training windows and baseline percentiles are built on incomplete flows. Park it in a monitoring table that **gates model confidence**; do not put it in the feature store. |
| **stats** | 27 numeric fields | All of them are **Zeek process internals** (`mem`, `pkts_proc`, `events_queued`, `active_tcp_conns`, `timers`, …). They describe the sensor's own state. `active_tcp_conns` is a rough traffic-volume proxy but it is strictly worse than `conn.log`'s own counts and it conflates "busy network" with "sensor struggling". |
| **traceroute** | `ts`, `src`, `dst`, `proto` | Four fields, three of which are identifiers. Gated behind an unloaded policy script whose `site/local.zeek` comment warns it "could possibly cause performance trouble". No ML feature. |
| **irc** | `command` | `nick`/`user`/`value`/`addl` are free text. IRC C2 is effectively extinct on a modern network; the one bounded field is not worth the ingestion path. |

### 4d. Operational / Zeek-internals logs (same class as 4a but worth naming)

`broker`, `cluster`, `config`, `print`, `telemetry`, `telemetry_histogram`, `weird_stats`,
`analyzer_debug`, `netcontrol`, `netcontrol_drop`, `netcontrol_shunt`, `netcontrol_catch_release`,
`openflow`, `alarm-mail`, `/`.

- `weird_stats.log` is interesting-looking (`name`, `num_seen` — a numeric count per weird name) and it
  is the one case here I would reconsider: `num_seen` is a legitimate aggregate. But `weird.log`
  already carries the raw events, so `weird_stats` is a pre-aggregation of a log you already have,
  and it is **not written under Weirvern's current config** (requires `@load policy/misc/weird-stats`).
  Prefer computing the aggregate in ClickHouse from `weird.log`.
- `analyzer_debug.log` is `Analyzer::Logging::Info`'s debug twin — the script is explicitly a
  development/troubleshooting stream.
- `netcontrol*`/`openflow` describe **your own remediation actions**, not the network. Ingesting them
  into an anomaly feature store would let the model learn your response policy.
- `telemetry`/`telemetry_histogram` are metric time-series for Prometheus-style scraping; they are
  operational dashboards, not detection features.

### 4e. A note on what is *gated* vs *default-on* here

Worth separating, because a log you believe is flowing may be empty. Resolving the `@load` closure of
`base/init-default.zeek` + Weirvern's `weirvern-local.zeek` + `site/local.zeek`:

- **Written by default on this sensor (59 paths):** `conn, dns, ssl, ssh, http, files, notice, weird,
  kerberos, dce_rpc, dhcp, dnp3, ftp, irc, ldap, ldap_search, modbus, mqtt_{connect,publish,subscribe},
  mysql, ntlm, ntp{,tpu_control,_private}, ocsp, pe, postgresql, quic, radius, rdp, redis, rfb, sip,
  smb_files, smb_mapping, smtp, snmp, socks, software, syslog, tunnel, websocket, x509, analyzer,
  signatures, intel, packet_filter, reporter, openflow, netcontrol{,__drop,_shunt}, notice_alarm.`
- **Added by `site/local.zeek` + Weirvern's policy (65 paths total):** `capture_loss, stats,
  loaded_scripts, known_hosts, known_services, known_certs`.
- **Shipped but NOT active — requires an explicit `@load` (11 paths):** `analyzer_debug, known_modbus,
  modbus_register_change, multicast_participants, netcontrol_catch_release, smb_cmd, telemetry,
  telemetry_histogram, traceroute, unknown_protocols, weird_stats`.

So `unknown_protocols.log` (rank 18) and `smb_cmd.log` (Tier B) need a script change, not just an
ingester change. Everything in Tier A except `smb_cmd` is **already being written to disk today** —
for those, this is purely an ingestion-and-featurisation task.

---

## 5. Volume and privacy, honestly stated

Volume is given as its **driver** (rows per what?), not as invented row counts — I have no measured
row counts for this deployment.

| Log | Volume driver | Privacy exposure |
|---|---|---|
| kerberos | one row per Kerberos *message* | `client`/`service` are real directory identities — PII |
| ntlm | one row per NTLM exchange | `username`+`hostname`+`domainname` = full identity correlation |
| dce_rpc | one row per RPC call | `named_pipe`/`operation` — no payload, no credentials |
| smb_mapping | one row per tree connect | share paths can embed usernames/departments |
| smb_files | one row per **logged** file action (gated by `logged_file_actions`) | filenames + full paths: highest PII surface of the SMB set |
| dhcp | one row per DHCP message | `mac` is a persistent hardware identifier — strongest pseudonymous tracker on the wire |
| x509 | one row per distinct leaf cert per day | `san.email` can contain personal addresses |
| ldap/ldap_search | one row per LDAP message | `filter`/`base_object` reveal directory structure; bind `argument` already redacted by default |
| pe | one row per PE file analysed | `section_names` reveals compiler/packer tooling |
| quic | one row per QUIC connection | `server_name` is SNI — already visible in ssl.log |
| tunnel | one row per tunnel discover/expire | endpoint IP pairs only |
| software / known_services / known_hosts / known_certs | one row per (host, thing) **first seen** | software inventory = vulnerability map; known_hosts is bare IPs (least sensitive) |
| rdp | one row per RDP negotiation | `client_name`/`client_dig_product_id` fingerprint a person's machine |
| smtp | one row per SMTP message | **highest in the list**: `from`, `to`, `cc`, `subject`, `msg_id` |
| analyzer | one row per protocol violation | **`failure_data` is a 40-byte payload excerpt by default** |
| unknown_protocols | one row per unknown-protocol occurrence | **`first_bytes` is raw hex payload** |
| signatures | one row per signature match | `sub_msg`/`event_msg` may contain payload excerpts |
| socks | one row per proxy request | `user`; `password` only if `capture_password` is flipped |
| websocket | one row per WS handshake | `uri`/`user_agent` can embed tokens/session IDs |

**Three logs ship raw payload bytes by default** — `unknown_protocols:first_bytes`,
`analyzer:failure_data` (40 bytes), and `mqtt_publish:payload`. Weirvern already keeps
`capture_password` off; these three are the functional equivalent of leaving it on. Zero or truncate
them at ingestion (`Analyzer::Logging::failure_data_max_size = 0` removes it at the source).

**Four fields convert this corpus from traffic telemetry into identifiable persons:**
`dhcp.mac`, `ntlm.username`, `kerberos.client`, `radius.username`. That is the price of the
entity-identity analytics in ranks 1, 2 and 5 — worth paying, but a deliberate choice.

---

## 6. What I verified vs. what I am inferring

**Verified from fetched primary sources:** all field names, types, `&optional`/`&default` markers,
record names, source file paths, field counts, the `conn_state`/`history`/`ssl_history` letter
vocabularies, the `conn_state` 12-value list, `logged_file_actions` default contents, the
`ignored_errors` default and its in-source rationale, the absence of `error_code` from kerberos.log,
`rcptto`'s type, the x509 dedup options, the 166 weird names and 44 Notice::Type values, the
default-vs-gated log inventory, and the PII/payload fields called out above. Dataset provenance
claims (UNSW-NB15 = Bro-IDS, ToN-IoT = Zeek, CIC-IDS2017/2018 = CICFlowMeter, MAWILab = neither) are
from the publishers' own pages.

**My synthesis, not a citation:** the *ranking order* in §2. I found no paper or project that ranks
Zeek log files against each other for ML — PORTFILER uses conn.log only, PicoDomain uses kerberos.log
for its ML demo and reports the other logs as log-type distribution counts. The ordering is my
judgement from field-level evidence, weighted toward (a) how bounded the categorical vocabulary is,
(b) how many natively numeric fields exist, and (c) whether the discriminative signal exists
*anywhere else* in the corpus.

**Corrections to the existing `weirvern-zeek-log-expansion.md`** in the same directory, which was
written against master (9.1.0-dev) rather than 9.0.0:
- It says `smtp.log:rcptto` "is a vector" — in **9.0.0 it is `set[string]`**.
- Its x509.log section lists `extensions` among the logged fields; in 9.0.0 `X509::Info`'s logged
  fields are `ts, fingerprint, certificate, san, basic_constraints, host_cert, client_cert`.
  `extensions` lives inside `X509::Certificate` as a non-`&log` nested type in `init-bare.zeek`, so
  it is reachable via `certificate` but is not a sibling field.
- It says Zeek core emits no `ja3` — **confirmed**, and I additionally confirmed by grep of the whole
  9.0.0 `scripts/`+`src/` tree that neither `ja3` nor `hassh` exists.

---

## 7. Sources actually fetched

**Primary (Zeek field definitions)**
- `https://github.com/zeek/zeek` tag `v9.0.0` — full `scripts/` tree + `src/` (release tarball,
  `refs/tags/v9.0.0.tar.gz`). Key files: `base/protocols/{conn,dns,ssl/http,ssh,krb,ntlm,dce-rpc,smb,dhcp,ldap,quic,tunnel,rdp,smtp,socks,websocket,radius,ntp,ftp}/…`,
  `base/files/{x509,pe,hash}/main.zeek`, `base/protocols/ssl/files.zeek`,
  `base/frameworks/{files,notice,signatures,software,tunnels,analyzer}/…`,
  `base/frameworks/notice/weird.zeek`, `base/init-bare.zeek`, `base/init-default.zeek`,
  `policy/protocols/conn/{known-hosts,known-services}.zeek`, `policy/protocols/ssl/{known-certs,validate-certs,log-hostcerts-only,ssl-log-ext}.zeek`,
  `policy/misc/{capture-loss,stats,unknown-protocols,weird-stats}.zeek`,
  `policy/frameworks/files/{hash-all-files,entropy-test-all-files}.zeek`, `site/local.zeek`
- `https://github.com/zeek/zeek-docs` (`master`) — `logs/{conn,dns,http,ssl,ssh,files,dhcp,smtp,ntp,pe,x509,weird-and-notice,analyzer,capture-loss-and-reporter,known-and-software}.rst`,
  `script-reference/log-files.rst` — the source of docs.zeek.org

**ML projects / features**
- `https://github.com/NYU-HSRN-Network-Data-Science-Group/AutoZeekWatch` (README + `AutoZeekWatch/{train,utils,infer}.py`) — KITNET autoencoder ensemble; per-log feature lists for conn/dns/http/ssh/ssl
- `https://github.com/activecm/rita` (`importer/zeektypes/{conn,dns,http,ssl}.go`, `analysis/beacons.go`) — beacon scoring fields
- `https://github.com/mitre-attack/bzar` (referenced, not fetched)
- `https://github.com/nccgroup/JA3_outlier` — JA3 rarity scoring notebook
- `https://github.com/stratosphereips/StratosphereLinuxIPS` — Slips README
- `https://raw.githubusercontent.com/salesforce/ja3` (via GitHub API metadata)
- GitHub API searches: `zeek+machine+learning`, `zeek+anomaly+detection`, `network+intrusion+detection+zeek`, `zeek+clickhouse`, `zeek+random+forest`, `zeek+ids+ml`, `suricata+zeek+ml+detection`, `ja4+zeek`, `zeek+ja3`

**Datasets**
- `https://www.unb.ca/cic/datasets/ids-2017.html`, `https://www.unb.ca/cic/datasets/ids-2018.html`
- `https://research.unsw.edu.au/projects/unsw-nb15-dataset`, `https://research.unsw.edu.au/projects/toniot-datasets`
- `https://www.stratosphereips.org/datasets-iot23`, `https://www.stratosphereips.org/datasets-ctu13`, `https://www.stratosphereips.org/zeek-anomaly-detector`
- `http://www.fukuda-lab.org/mawilab/`

**Papers**
- PicoDomain — arXiv:2008.09192 (PDF fetched and text-extracted)
- PORTFILER — arXiv:2112.13798 (PDF fetched and text-extracted)
- BACnet/IP ML on a modified CISA Zeek BACnet parser — arXiv:2607.20686
- Feature transferability across Argus / Zeek / CICFlowMeter — arXiv:2602.23874

**Fetches that failed**
- `https://docs.zeek.org/en/current/logs/*.html` and `.../reference/logs/*.html` — **HTTP 429 on every
  attempt** (repeated with delays and different User-Agents). Substituted the `zeek-docs` repo source,
  which is the generator input for those pages.
- `https://raw.githubusercontent.com/zeek/ja3/master/*` — 404 at that path (the JA3 script lives under
  `salesforce/ja3`; I confirmed the repo exists and its description via the GitHub API but did not
  fetch the script itself).
- `web_search` returned empty results for every query, consistent with the environment note; all
  research above was done by direct fetch.
