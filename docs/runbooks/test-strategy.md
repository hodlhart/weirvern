# Test strategy

The pyramid is not a diagram in a slide; it is the set of checks that decide whether a release
ships. `scripts/gate.sh` is the one command that runs the fast layers; the live smoke is the
end-to-end layer that needs a running deployment.

## The matrix

| Critical behaviour | Unit / contract | Integration | End-to-end |
|---|---|---|---|
| Install and prerequisites | `test_install_dns.py`, `test_image_layout.py`, `test_image_pins.py` | `scripts/verify_installer.sh` | `scripts/e2e_smoke.sh` status section |
| Flow ingest and schema | `test_ingester.py`, `test_ingest_arity_contract.py`, `test_schema.py` | `test_schema_migrations.py` | `e2e_smoke.sh` ingest→anomaly |
| Anomaly scoring and evidence | `test_ensemble.py`, `test_evidence.py`, `test_evidence_states.py`, `test_flow_evidence.py` | `test_scoring.py`, `test_detection_eval.py` | `e2e_smoke.sh` evidence section |
| Findings and asset posture | `test_findings.py`, `test_asset_posture.py` | `test_scanner.py` | `e2e_smoke.sh` findings section |
| Settings read/plan/apply | `test_settings_controls.py`, `test_settings_tab.py`, `test_apply_checks.py`, `test_apply_receipt.py` | `test_settings_drift.py` | `e2e_smoke.sh` settings section |
| Sluice enforcement | `test_sluice.py`, `test_sluice_rule_management.py`, `test_enforce.py` | `scripts/prove_sluice_end_to_end.py`, `scripts/prove_sluice_port_scoping.py` | live rule/revoke drill in `release-dr-drill.md` |
| Accounts, sessions, audit | `test_gui_users.py`, `test_gui_auth.py`, `test_write_trail.py` | `test_privacy_invariants.py` | live 401→audit row (SEC-3) |
| ML readiness, calibration, budget | `test_ml_calibration.py`, `test_model_artifact_schema.py`, `test_alert_budget.py` | `scripts/eval_detection.py`, `scripts/eval_budget.py` | model gate and shadow soak (ML board) |
| Release identity and rollback | `test_image_contract.py`, `test_update.py` | `scripts/verify_versions.sh` | `release-dr-drill.md` drill; `e2e_smoke.sh` release identity |

## What the gate runs

`scripts/gate.sh` runs, in order: sanitation of the tracked tree and commit messages, ruff, mypy,
schema audit, README claims, version agreement, shell syntax under each script's own shebang,
installer logic, liveness/cleanup guards, two mutation-proof suites, frontend ``node --check``,
the pytest suite, and the parse/count sanitation invariants. A stage that cannot run is a **SKIP**
in the summary, never a pass.

The browser DOM harness (`scripts/jsdom_render.js`) and `npm ci` run in CI, not in the local gate.
`scripts/e2e_smoke.sh` is the read-only live layer: health, ingest→anomaly→evidence, findings,
settings and release identity. It needs a running deployment and a token file; it never writes.

## Skip ledger

A skipped test is not a pass. These are the current skips and their disposition:

| Test | Why it skips | Disposition |
|---|---|---|
| `test_config_wiring.py:145` | every ConfigMap key is already imported through `envFrom`; the per-key assertion is satisfied by the stronger shape | intentional branch, kept visible |
| `test_logo.py:91` | ImageMagick is not installed on this host | accepted environment exception; derivations are pinned by `test_logo`'s structural checks |
| `test_zeek_policy_loads.py:59,70` | Zeek is not installed on the host | accepted environment exception; the running Zeek image is the runtime proof, and `test_zeek_policy_loads` runs where Zeek exists |
| `test_zeek_tier3.py:93` | DHCP is keyed on MAC, not an address pair; the address-pair assertion is covered below it | intentional negative branch |
| `test_zeek_tier3.py:220` | the decision document lives outside this repository | accepted documentation exception |

## Fixtures

Every test fixture uses documentation ranges: `192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`, and `2001:db8::/32`. A private LAN address in a fixture is a test bug; the gate's
sanitation check is the backstop.

## Gaps that are explicitly not covered by a unit test

- **Rollback** is an operator drill, not a unit test: the deployment is single-node and the
  supported rollback is re-applying the previous release tag and reading the running version.
  `release-dr-drill.md` records the drill and the evidence; `e2e_smoke.sh` pins the identity of
  whatever is running.
- **Install on a clean host** is exercised by `scripts/verify_installer.sh` against simulated
  machines and by `docs/deployment.md`; no disposable host is available in this environment.
- **Sensor loss and expired certificates** are failure-injection drills in REL-1, not unit tests.
