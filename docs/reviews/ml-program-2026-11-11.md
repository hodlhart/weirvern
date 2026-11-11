# ML program review — 2026-11-11

- **Status:** fail
- **Review id:** `ml-program-2026-11-11`
- **Next review:** 2026-12-11
- **Decision:** fix: complete the named phase cards and attach verified evidence

## Failures
- wv-ml-truth t_c511ef1c GT-1 — Automated ground truth and weak-label pipeline (blocked)
- wv-ml-truth t_7b3d365e GT-4 — Canary and honeypot automated positives (blocked)
- wv-ml-truth t_a6886454 GT-2 — Scenario corpus for every model family (blocked)
- wv-ml-candidates t_7edcfc5d CE-1 — HDBSCAN vs DBSCAN at a fixed budget (blocked)
- wv-ml-candidates t_662ba4f7 CE-5 — Multi-scale ripple ensemble (blocked)
- wv-ml-candidates t_c36ebb27 CE-2 — Shadow-specialist disposition matrix (blocked)
- wv-ml-candidates t_f7fcd9c5 CE-3 — Reproducible monthly evaluation report (blocked)
- wv-ml-promotion t_6eadd9ae PR-2 — Autonomous canary promotion and rollback (blocked)
- wv-ml-promotion t_3deb4781 PR-3 — Autonomous decision ledger and program gate (blocked)
- verification report is missing; unlabelled zero is not a clean result

## Blocked or missing phase cards
- `t_c511ef1c` [wv-ml-truth] GT-1 — Automated ground truth and weak-label pipeline — **blocked**
- `t_7b3d365e` [wv-ml-truth] GT-4 — Canary and honeypot automated positives — **blocked**
- `t_a6886454` [wv-ml-truth] GT-2 — Scenario corpus for every model family — **blocked**
- `t_7edcfc5d` [wv-ml-candidates] CE-1 — HDBSCAN vs DBSCAN at a fixed budget — **blocked**
- `t_662ba4f7` [wv-ml-candidates] CE-5 — Multi-scale ripple ensemble — **blocked**
- `t_c36ebb27` [wv-ml-candidates] CE-2 — Shadow-specialist disposition matrix — **blocked**
- `t_f7fcd9c5` [wv-ml-candidates] CE-3 — Reproducible monthly evaluation report — **blocked**
- `t_6eadd9ae` [wv-ml-promotion] PR-2 — Autonomous canary promotion and rollback — **blocked**
- `t_3deb4781` [wv-ml-promotion] PR-3 — Autonomous decision ledger and program gate — **blocked**

## Sources
- flows: rows=5343104 state=fresh usable=True
- flows_aggregated: rows=929817 state=fresh usable=True
- zeek_conn: rows=6087052 state=fresh usable=True
- zeek_ssl: rows=142338 state=fresh usable=True
- zeek_dns: rows=356091 state=fresh usable=True
- zeek_notice: rows=2184 state=fresh usable=True

## Model cards
- Adaptive Baseline: production hash=c736c6b397f5e522c3fdd99585fbee5f87d90644ed39eb4996b8d227c4faa1b6
- DBSCAN: retired hash=9c528d3a400e620ecf6e2cfe1ab0fde5f1e346961d14ed4fa2ca165c0de1092d
- Gradient Boosting: production hash=3c8ffb252f3d59869af296d6d9b505f3d86134838441ef42661753637eb1b9f6
- Isolation Forest: production hash=9ad91fb954d7af5b2899749d72a4fa69db9a1c104de699d16466f52208e7243a

## Verification
- {'available': False, 'reason': 'not supplied'}
