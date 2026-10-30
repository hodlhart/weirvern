# Fixed-budget detection baseline — 2026-10-30

**Purpose:** FND-4. The current production ensemble's seeded-attack baseline, the commands that
produce it, and the evaluation protocol every later specialist must use.

This is **not** a claim that the system detects real attacks in production. It is the
reproducible floor the program measures against.

---

## 1. Run

Disposable ClickHouse `clickhouse/clickhouse-server:26.8` on localhost; a separate `MODEL_DIR`;
no live database writes.

```bash
mkdir -p /tmp/wv-eval-models
MODEL_DIR=/tmp/wv-eval-models \
CLICKHOUSE_HOST=127.0.0.1 CLICKHOUSE_PORT=18124 \
CLICKHOUSE_USER=default CLICKHOUSE_PASSWORD=test \
python scripts/eval_detection.py --host 127.0.0.1 --port 18124 --minutes 300 --devices 12
```

Seed: 42; 300 simulated minutes; 12 devices; attacks begin at minute 200. The harness pins the
seed clock to the most recent UTC midnight.

## 2. Result

| item | measured |
|---|---:|
| seeded flows | 18,557 |
| aggregated host-windows | 720 |
| final verdicts | 263 |
| port scanner | **critical** |
| beacon | **medium** |
| exfiltration spike | **critical** |
| benign hosts at high+ | **1 of 9** |
| worst benign host | 1 window |
| busiest host | 26 of 60 windows |
| determinism | identical second run (263 verdicts) |

The harness passed all of its assertions: every seeded attack reached a final verdict, the
scanner was located within ±1 window, benign traffic stayed within the calibrated floor, and the
run did not storm.

**Important limitation:** the demo generator emits no Zeek records, so every Zeek feature in this
run is the legitimate absent case (imputed/zero). This baseline exercises the NetFlow path, not
DNS, JA4, SSH, Kerberos, NTLM, SMB or DCE/RPC. Those require the expanded corpus (FND-3) and the
live benign windows.

## 3. Evaluation protocol for every new specialist

A candidate must be compared at the **same alerts/day** on the same window, and report:

- per-family recall (scan, beacon, exfil, DNS tunnel, brute force, lateral, rogue DHCP, JA4,
  encrypted C2, staging);
- **precision@k** and **incidents/day**, not raw row counts;
- **time-to-detect** and episode-level recall (a multi-window attack counts once);
- false alarms per host/day by role;
- source ablation: remove DNS, JA4, Zeek-identity, graph; measure the contribution;
- score saturation and calibration population/age;
- runtime, explanation coverage and model version.

**Rules**

- Public datasets are for feature mechanics only; they are not this network's benchmark. The
  primary negative reference is live benign traffic plus operator reviews.
- Time-split validation; no random windows across the same day.
- A candidate that wins by alerting more is rejected.
- A specialist without a benign reference and a budget is a prototype, not a production model.
- Every promotion has a kill switch and a before/after replay.

## 4. Current baseline context

- Live 24h: 2,652 anomaly rows, 709 critical, 2,664 log-only alert decisions.
- 30-minute host grouping: ~84 incidents; the critical/high subset ~79 (57 at 60 minutes).
- DBSCAN observed false-alarm rate: 99.94% vs 1% target.
- HDBSCAN/GLOSH full-feature A/B: no demonstrated precision gain; do not promote.

The next baseline after FND-3 must include the new scenarios and report the same table. Until then,
the 263-verdict result is the only reproducible end-to-end floor.

## 5. Evidence

- `scripts/eval_detection.py` output from the disposable run.
- `docs/research/hdbscan-glosh-full-evaluation-2026-10-30.md` for the model A/B baseline.
- `docs/research/ml-source-coverage-2026-10-30.md` for source coverage.
