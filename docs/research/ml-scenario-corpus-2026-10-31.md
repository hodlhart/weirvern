# FND-3 scenario corpus — 2026-10-31

**Purpose:** test infrastructure for the specialist cards. The original harness proved three
behaviours (port scan, beacon, exfil). This adds six flow-visible behaviours, each on its own
documentation-address host, so a detection gap names the scenario instead of hiding in a total.

## Scenarios

| scenario | host | starts | deadline | expected technique / evidence |
|---|---|---|---|---|
| `ssh_brute` | `198.51.100.210` | attack start | 10 min | T1110 — repeated short connections to one SSH service |
| `smb_lateral` | `198.51.100.211` | +2 min | 10 min | T1021.002 — one SMB attempt per internal host |
| `dce_rpc` | `198.51.100.212` | +3 min | 10 min | T1021.003 — endpoint-mapper fan-out |
| `dns_tunnel` | `198.51.100.213` | attack start | 15 min | T1071.004 — many short queries to the resolver |
| `quic_c2` | `198.51.100.214` | attack start | 20 min | T1071 — periodic small UDP/443 callbacks |
| `http_c2` | `198.51.100.215` | +1 min | 20 min | T1071.001 — upload-sized HTTP posts to multiple endpoints |

The scenario hosts receive a benign pre-attack baseline, then their seeded behaviour, so the
adaptive baseline and host-history features have a reference. The fixture is opt-in:
`--new-scenarios` is off by default; `scripts/eval_detection.py` turns it on.

## Harness

```
CLICKHOUSE_HOST=127.0.0.1 CLICKHOUSE_PORT=8123 \
  python scripts/eval_detection.py --minutes 300 --devices 12
```

`scripts/eval_detection.py` prints one line per scenario:

- severity (`medium+` required)
- first detection and **latency** against the scenario deadline
- expected technique and whether it appeared in `attack_techniques`
- pass/fail; failures increment the exit code

Existing scan / beacon / exfil assertions, the benign floor and the no-storm check still run.
A missing SSH-brute verdict is removed in a guard proof and the scenario checker must go red;
the same guard is pinned by `tests/test_scenario_corpus.py`.

## Measured run (2026-10-31, disposable ClickHouse)

- `319` verdicts; deterministic across a second scoring pass.
- Port scanner: medium; beacon: medium; exfiltration spike: critical.
- `ssh_brute`, `smb_lateral`, `dce_rpc`, `dns_tunnel`, `quic_c2`: critical.
- `http_c2`: critical.
- Benign hosts: within floor (2 of 9 at high+, worst 1 window).
- No storm among non-attack hosts.
- Expected ATT&CK IDs were **not mapped** by the current detector for these new scenarios; the
  harness prints `technique not mapped`. The fixture defines them for the specialist cards; it
  does not claim the current flow model produces those IDs.

## Limits

- Flow-only. DNS tunnel here is a flow-shape proxy, not payload or query entropy. New-JA4,
  NTLM, and rogue DHCP/MAC spoof remain Zeek/DHCP specialist fixtures; this corpus does not
  pretend to cover them.
- The HTTP staging fixture uses a multi-endpoint 8080 fan-out; a single quiet post was not
  separable from the benign heavy tail.
- No production table, schema, alert path or model change.
