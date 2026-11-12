# ML program review — 2026-11-12

- **Status:** fail
- **Review id:** `ml-program-2026-11-12`
- **Next review:** 2026-12-12
- **Decision:** fix: complete the named phase cards and attach verified evidence

## Failures
- wv-ml-ripple t_81c45fc1 RIP-1 — Truth layer: ripple generator, clean replay and canaries (blocked)
- wv-ml-ripple t_429b6447 RIP-2 — Multi-scale temporal detector (blocked)
- wv-ml-ripple t_4a6a8a9d RIP-3 — Relational graph detector (blocked)
- wv-ml-ripple t_8ef0f275 RIP-4 — Protocol-semantic detector (blocked)
- wv-ml-ripple t_d0257785 RIP-5 — Calibrated fusion and explanation (todo)
- wv-ml-ripple t_5afd6c80 RIP-6 — Automatic evaluation and promotion loop (blocked)
- wv-ml-ripple t_383e92f2 RIP-7 — Product surface and per-site onboarding (blocked)
- wv-ml-ripple t_bd350233 RIP-8 — Independent audit and promotion gate (blocked)
- wv-ml-data t_d2db265e DATA-1 — Make DNS visible for every monitored host (blocked)
- wv-ml-data t_ebd19c2e DATA-2 — Role and identity coverage (blocked)
- wv-ml-data t_2989a4ee DATA-3 — Clean attack-free background replay (blocked)
- wv-ml-data t_7dba8e52 DATA-4 — Synthetic ripple generator (blocked)
- wv-ml-data t_e18236b3 DATA-5 — Canary and honeypot services (blocked)
- wv-ml-data t_8f207ba1 DATA-6 — Auto-label assembly and provenance (blocked)
- wv-ml-data t_b3a2c3ee DATA-7 — Leakage-safe splits and evaluation manifest (blocked)
- wv-ml-data t_90dd0234 DATA-8 — Data quality SLO and gap dashboard (blocked)
- wv-ml-data t_13919fdd DATA-9 — Per-site onboarding and backfill (blocked)
- wv-ml-data t_9731c2a1 DATA-10 — Nmap/scanner asset telemetry in the data contract (blocked)
- wv-prod-release t_d470d880 REL-1 — Load, soak and failure-injection testing (blocked)
- wv-prod-program t_2698e1ae PRG-2 — Production readiness gate and launch decision (blocked)
- verification report is missing; unlabelled zero is not a clean result

## Blocked or missing phase cards
- `t_81c45fc1` [wv-ml-ripple] RIP-1 — Truth layer: ripple generator, clean replay and canaries — **blocked**
- `t_429b6447` [wv-ml-ripple] RIP-2 — Multi-scale temporal detector — **blocked**
- `t_4a6a8a9d` [wv-ml-ripple] RIP-3 — Relational graph detector — **blocked**
- `t_8ef0f275` [wv-ml-ripple] RIP-4 — Protocol-semantic detector — **blocked**
- `t_d0257785` [wv-ml-ripple] RIP-5 — Calibrated fusion and explanation — **todo**
- `t_5afd6c80` [wv-ml-ripple] RIP-6 — Automatic evaluation and promotion loop — **blocked**
- `t_383e92f2` [wv-ml-ripple] RIP-7 — Product surface and per-site onboarding — **blocked**
- `t_bd350233` [wv-ml-ripple] RIP-8 — Independent audit and promotion gate — **blocked**
- `t_d2db265e` [wv-ml-data] DATA-1 — Make DNS visible for every monitored host — **blocked**
- `t_ebd19c2e` [wv-ml-data] DATA-2 — Role and identity coverage — **blocked**
- `t_2989a4ee` [wv-ml-data] DATA-3 — Clean attack-free background replay — **blocked**
- `t_7dba8e52` [wv-ml-data] DATA-4 — Synthetic ripple generator — **blocked**
- `t_e18236b3` [wv-ml-data] DATA-5 — Canary and honeypot services — **blocked**
- `t_8f207ba1` [wv-ml-data] DATA-6 — Auto-label assembly and provenance — **blocked**
- `t_b3a2c3ee` [wv-ml-data] DATA-7 — Leakage-safe splits and evaluation manifest — **blocked**
- `t_90dd0234` [wv-ml-data] DATA-8 — Data quality SLO and gap dashboard — **blocked**
- `t_13919fdd` [wv-ml-data] DATA-9 — Per-site onboarding and backfill — **blocked**
- `t_9731c2a1` [wv-ml-data] DATA-10 — Nmap/scanner asset telemetry in the data contract — **blocked**
- `t_d470d880` [wv-prod-release] REL-1 — Load, soak and failure-injection testing — **blocked**
- `t_2698e1ae` [wv-prod-program] PRG-2 — Production readiness gate and launch decision — **blocked**

## Sources
- flows: rows=5202488 state=stale usable=False
- flows_aggregated: rows=924152 state=stale usable=False
- zeek_conn: rows=6353522 state=stale usable=False
- zeek_ssl: rows=139058 state=stale usable=False
- zeek_dns: rows=350741 state=stale usable=False
- zeek_notice: rows=2219 state=stale usable=False

## Model cards
- Adaptive Baseline: production hash=c736c6b397f5e522c3fdd99585fbee5f87d90644ed39eb4996b8d227c4faa1b6
- DBSCAN: retired hash=9c528d3a400e620ecf6e2cfe1ab0fde5f1e346961d14ed4fa2ca165c0de1092d
- Gradient Boosting: production hash=3c8ffb252f3d59869af296d6d9b505f3d86134838441ef42661753637eb1b9f6
- Isolation Forest: production hash=9ad91fb954d7af5b2899749d72a4fa69db9a1c104de699d16466f52208e7243a

## Verification
- {'available': False, 'reason': 'not supplied'}
