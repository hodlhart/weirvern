# Zeek log expansion: the decision, and why

Two research reports ranked every candidate log Weirvern does not ingest — one by **threat-hunting
value**, one by **ML signal per row**. Both were extracted from the **Zeek 9.0.0 release source tree**
(`github.com/zeek/zeek` tag `v9.0.0`, `scripts/`), not from documentation and not from memory.

- `zeek-log-research-threat-hunting.md` (348 lines, 25 logs ranked)
- `zeek-log-research-ml.md` (415 lines, every shipped log path inventoried)

They were produced independently and agree on the top of the list, which is the useful signal.

## What this deployment actually writes today

**8 logs ingested**: `conn`, `dns`, `ssl`, `notice`, `http`, `files`, `ssh`, `weird`.
**72 log paths are declared** by the installed Zeek 9.0.0 scripts.

An important correction from the research, which changes what "add a log" means: several logs are
**already being written by the sensor and simply not ingested.** Enabling them is a policy change,
not a new capability:

| Log | Status on this sensor | Why it matters |
|---|---|---|
| `x509` | **already written** (`base/files/x509` is in `init-default.zeek`) | `ssl.log` has fingerprints only; key length, sig alg, validity window and the CA flag exist only here |
| `software` | **already written** (loaded via `site/local.zeek`) | per-host software inventory; `Software_Version_Change` is the "attacker replaced sshd" detection |
| `known_services`, `known_hosts` | **already written** (loaded from the base policy) | first-seen service/host — a per-host novelty feature at near-zero volume |
| `kerberos`, `dce_rpc`, `ntlm`, `smb_mapping`, `smb_files`, `ldap_search`, `tunnel`, `quic`, `rdp`, `smtp` | written **if the protocol appears** | the Tier-2 set already mapped; the rest are new |

So the ordering below is deliberate: ingest what the sensor already produces before adding
anything that requires a policy change.

## The decision

**Add these five, in this order.** Both reports place them in their top six, and each answers a
question no ingested log can.

| # | Log | Hunting rank | ML rank | The specific thing it adds |
|---|---|---|---|---|
| 1 | `dhcp` | 8 | 5 | **The only log with L2 identity.** Converts an IP in `conn.log` into a MAC and hostname — the pivot that makes every other log attributable after a lease expires. A per-host baseline keys on the MAC, which is stable, rather than an IP, which is not. Also exposes rogue DHCP via a foreign `server_addr`. |
| 2 | `x509` | 6 | 6 | **Already written and unread.** `ssl.log` structurally cannot express it: `cert_chain_fps` is a vector of fingerprint strings. "Is this cert self-signed, expired, or short-key?" requires this log. Highest-value derived feature: `subject == issuer` joined to `server_name ∉ san.dns`. |
| 3 | `tunnel` | 9 | 12 | **The existence of a row is the finding.** Zeek's own docs say so. `conn.log` carries `tunnel_parents` (a UID set — an identifier, not a feature) but never the *type*. Both fields are bounded enums. Near-zero volume. |
| 4 | `quic` | 11 | 11 | **Closes a TLS blind spot.** QUIC is encrypted at the transport layer and bypasses `ssl.log` entirely, so on a modern network a growing share of egress has no TLS record at all. Recovers `server_name` (SNI) and the ALPN protocol. |
| 5 | `ldap_search` | 7 | 8 | **AD enumeration is defined by filter content.** `result_count` is a clean numeric outlier feature; the `filter` grammar is a bounded structured string whose novelty is the BloodHound-style enumeration signal. `default_capture_password = F`, so bind arguments are redacted. |

**Retention follows the existing rule** (`004_zeek_identity.sql`): bounded, shortest where the
exposure is greatest. `x509` carries certificate subjects which name organisations and internal
hostnames; `dhcp` carries MAC and hostname; `ldap_search` carries directory filters and base
objects. None of these get the flow tables' volume-based 7 days, and none go unbounded.

**Deliberately NOT added, with the reason stated rather than implied:**

| Log | Why not |
|---|---|
| `signatures` | Its `sig_count`/`host_count` are useful, but they are Zeek's *own* scan thresholds — and Weirvern computes the equivalent from raw flows in `flows_aggregated_diversity`, which is already a feature. Adding it would duplicate a signal we derive. |
| `pe` | Ten clean booleans, genuinely dense — but only populated when an executable crosses the wire, and this deployment's `files.log` shows no PE transfers. Adding a table that stays empty is the defect class this project keeps finding. Revisit when PE traffic exists. |
| `unknown_protocols` | The purest unsupervised novelty signal available, and **gated** — requires `@load policy/misc/unknown-protocols`. Its `first_bytes` is **raw payload**, which conflicts with the standing privacy invariant that no payload bytes are stored. Worth revisiting only with the payload field dropped. |
| `smb_cmd` | Ranked last by the hunting report despite rich fields, because Zeek's own script header calls it "primarily useful for debugging" and it is high volume. |
| `smtp`, `ftp`, `radius`, `rcon`, `rfb`, `ntp`, `snmp`, `irc` | Protocol not present on this segment. |
| `ocsp`, `known_certs`, `intel` | Useful only with outbound OCSP validation, or a populated intel feed, respectively. The intel feed is a separate feature (the threat-intel registry). |

## What the research changed in the code (already done)

The ML report's §5 privacy notes and the hunting report's §4 both flag raw-payload fields. Two of
them are in logs we might otherwise have added — `unknown_protocols.first_bytes` (above) and
`analyzer.failure_data` (40 bytes, `&log &optional`). Neither is added, so the privacy invariant
("no payload bytes, ever") is intact without exception.

The ML report also confirms two things this project had already established the hard way:
- **JA3 is not in Zeek 9.0.0 core** — a grep of the whole tree returns no `ja3`/`hassh` field. This
  matches the dead `ja3`/`ja3s` columns we removed.
- **CIC-IDS2017/2018 are NOT Zeek-derived** despite their ubiquity in NIDS papers — they come from
  CICFlowMeter. UNSW-NB15 *is* Bro-derived and ToN-IoT *is* Zeek-derived. Worth knowing before
  citing a dataset as validation for a Zeek feature set.
