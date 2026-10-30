# HDBSCAN GLOSH — full-feature live A/B, seeded A/B, and ML data coverage

**Date:** 2026-10-30
**Status:** shadow analysis and shadow-candidate code only. No production alert path, model
artifact, UI or schema was changed. The live build remains 0.23.14; the candidate code is on
`feat/sluice-rule-sheet` at `8858ffd`.
**Question:** replace DBSCAN with HDBSCAN/GLOSH, and are the ML models using all collected DNS
and traffic?

---

## 1. Bottom line

**Do not replace DBSCAN.** With the correct 19-feature production vector, HDBSCAN's medoid score
and GLOSH both mostly re-rank the existing saturated queue; neither demonstrates better precision.
The seeded demo A/B also shows no improvement over DBSCAN at the top of the ranking.

**The challenger was not using the production feature vector.** It selected only the eight NetFlow
columns and omitted the Zeek/DNS tail. It also ranked all source addresses, including internet
peers. Both defects are now fixed in the shadow candidate:

- `weirvern/models/candidates.py` now selects **`DBSCAN_FEATURES`**: 8 flow aggregates + 11 Zeek
  columns, including `zeek_dns_count`, `zeek_dns_mean_query_entropy` and
  `zeek_dns_rcode_error_ratio`.
- It applies `networks.training_filter_sql()` so the matrix contains only monitored hosts.
- A live shadow run wrote **5,000 rows / 22 hosts / 0 external addresses**, 30 clusters,
  1,233 noise rows (24.66%) and 19 feature columns.

**DNS and traffic coverage is real but uneven.** The production Isolation Forest and Gradient
Boosting models use **77 features**, including all 13 DNS features and the full flow block. DBSCAN
deliberately uses a **19-feature subset** (8 flow + 11 Zeek, of which 3 are DNS). The collector is
not the problem; the challenger was. Separately, DNS is only visible for **14 hosts / 27,023 rows**
in the last 24 hours, versus 3,730 flow hosts, so most host-windows correctly carry the
`zeek_present=0` absent case.

---

## 2. Live full-feature A/B

5,000 monitored host-windows, 19 features, 22 hosts, 72-hour window. Production alerts are a
proxy for "what the current queue contains", not ground truth.

| metric | medoid HDBSCAN | GLOSH HDBSCAN |
|---|---:|---:|
| clusters | 30 | 28 |
| noise | 1,231 (24.62%) | 1,219 (24.38%) |
| NaN scores | 0 | **417 (8.34%)** |
| top 1% (50 rows) in production alerts | **49/50 (98%)** | **46/50 (92%)** |
| top 2% (100) | 96/100 (96%) | 91/100 (91%) |
| top 5% (250) | 239/250 (95.6%) | 222/250 (88.8%) |
| production alerts overall | 4,405/5,000 (88.1%) | same |
| Spearman vs medoid | — | **0.621** |
| top-1% overlap | — | **0/50** |

The base rate is the key number: **88.1%** of this monitored sample is already in the production
alert set. A random 50-row cut would contain about **44** production alerts. The medoid score's
49/50 is therefore a mild re-ranking of the queue, not evidence of precision; GLOSH's 46/50 is
slightly below it. The two rankings agree broadly (ρ=0.621) and disagree completely at the
extreme top 1%.

GLOSH at different `min_cluster_size` values, same matrix:

| `min_cluster_size` | clusters | noise | top-1% production alerts |
|---:|---:|---:|---:|
| 5 | 125 | 28.7% | 50/50 (100%) |
| 20 | 45 | 24.1% | 49/50 (98%) |
| 40 | 28 | 24.4% | 46/50 (92%) |
| 80 | 17 | 24.5% | 46/50 (92%) |

At a 88% base rate, these differences are not evidence that any setting detects better. They are
different ways to recover the same queue. GLOSH is undefined for 417 rows (8.3%) even with the
full vector; the candidate must define a NaN policy before it can be scored.

---

## 3. Seeded-attack A/B

A disposable ClickHouse (`clickhouse/clickhouse-server:26.8`) was seeded with the project's
deterministic demo generator: 12 devices, 300 minutes, attacks begin at minute 200. The three
attack source hosts contributed **180 host-windows**; the nine benign hosts contributed **540**.
The demo has no Zeek records, so its 11 Zeek columns are the legitimate absent case (zeros). The
19-feature matrix was scored by the real production DBSCAN formula (`eps=0.6, min_samples=5`,
percentile calibration) and by HDBSCAN medoid/GLOSH.

| top cut | DBSCAN attack rows | HDBSCAN medoid attack rows | GLOSH attack rows |
|---|---:|---:|---:|
| 1% (8 rows) | 2/8 | 3/8 | 2/8 |
| 2% (15) | 5/15 | 4/15 | 4/15 |
| 5% (36) | 15/36 | 14/36 | 13/36 |
| 10% (72) | 27/72 | 26/72 | 28/72 |

The attack base rate is **25%** (180/720), so a random top-1% cut expects about 2 attack rows.
DBSCAN and GLOSH both get 2; medoid gets 3. At 5% the DBSCAN baseline is marginally ahead. **This
seed does not show a false-positive or detection improvement from HDBSCAN/GLOSH**, and one seed is
not a precision benchmark. It is still a useful negative result: the candidate's apparent gains on
the live queue were an artefact of re-ranking a saturated queue, not of finding more attacks.

The disposable database was used only for this harness and was stopped afterwards.

---

## 4. Are we using all collected DNS and traffic?

### 4.1 What the live models actually carry

From the latest `ml_models` rows:

| model | feature columns | DNS features | flow features |
|---|---:|---:|---:|
| Isolation Forest | **77** | 13 | 14 |
| Gradient Boosting | **77** | 13 | 14 |
| DBSCAN | **19** | 3 | 8 |
| HDBSCAN challenger (fixed) | **19** | 3 | 8 |

The production IF/GB models carry the full `ZEEK_FEATURES` block, including the DNS count, mean
query entropy, mean query length, rcode/failed ratios, unique ratio, max entropy, length standard
deviation, NXDOMAIN/TXT/NULL ratios, answer count and new-domain ratio, plus the five graph
features. DBSCAN deliberately carries the smaller clustering subset (count, mean entropy, rcode
error ratio), because its sample size is small and every extra dimension makes density estimation
worse. The shadow challenger now matches DBSCAN exactly.

### 4.2 What is collected but not in a feature vector

`scripts/audit_ml_coverage.py --live --host sensor.example` reports:

- **5,507,057 of 10,985,135 rows (50.1%)** are read by a feature module.
- The shortfall is mostly correct by design: raw `flows` (1.6M rows) are fed forward by
  materialized views into `flows_aggregated*`; alert outputs, model state, candidate scores,
  sensor status and schema versions are not features.
- The audit still names genuinely unused data: **`host_roles` (17,556 rows)**, `dns_reverse_map`
  (4,016), `blocklist_domains` (746,890, Sluice/display only), `ntlm_identity_daily` (0),
  `model_actions`, `sluice_state` and fleet/control metadata. `host_roles` is the important one:
  roles exist but do not drive a feature or a threshold yet.

Some aggregate fields are also not in the vectors: `avg_bytes`, `avg_packets`,
`unique_dst_addrs`, `packets_stddev`, `min_bytes`, `max_bytes`, `active_minutes`,
`inter_flow_avg`, `inter_flow_stddev`. Some are redundant with existing features; they are not
silently missing, but they are not used.

### 4.3 DNS data coverage is real but sparse

24-hour live counts:

- `zeek_dns`: **27,023 rows**, **14 source hosts**, 1,938 distinct host-windows.
- `flows_aggregated`: **3,730 source hosts**.
- `zeek_conn`: **2,208 source hosts**; intersection with flow hosts: **2,168**.
- DNS rows are 1.3% of total collected volume.

So DNS is used where it exists, but most flow hosts have no DNS observation. That is exactly why
`zeek_present` exists: the model must distinguish "Zeek did not observe this host-window" from
"Zeek observed it and there was nothing unusual". It also means adding DNS features to the
clustering vector does not magically improve hosts that DNS cannot see.

---

## 5. What changed in the shadow candidate

`weirvern/models/candidates.py`:

- imports `DBSCAN_FEATURES`, `ZEEK_DBSCAN_FEATURES`, `ZEEK_JOIN_ON` and `zeek_join_cte`;
- `matrix_sql()` selects the 19 production columns in the exact `DBSCAN_FEATURES` order;
- `run()` loads `network_scopes` and applies `training_filter_sql()`; it returns an explicit
  `available: false` when scopes exist but none is monitored;
- reports `feature_columns` and `scope_filtered` in its result.

`tests/test_ml_shadow.py` additions:

- the matrix carries the production Zeek/DNS tail (19 columns);
- the monitored-scope predicate is present in the SQL;
- a scope declaration with no monitored scope refuses to rank.

Targeted tests: **11 passed**.

Live shadow run:

```json
{"available": true, "rows": 5000, "clusters": 30, "noise": 1233,
 "min_cluster_size": 40, "score_p50": 0.5, "score_p99": 0.99,
 "model_version": "0.23.15", "feature_columns": 19, "scope_filtered": true}
```

A follow-up query confirmed **5,000 rows, 22 hosts, 0 non-monitored addresses**.

---

## 6. Decision and next gate

1. **No DBSCAN→HDBSCAN swap.** The full-feature and seeded results do not show a precision or
   detection gain.
2. **Keep HDBSCAN shadow.** The scope filter and full feature vector are now correct, which makes
   the next A/B meaningful.
3. **GLOSH remains a research score.** It needs a NaN policy and a chosen `min_cluster_size` on a
   validation window; `min_cluster_size=20` and 40 are the only two worth testing.
4. **Episode grouping and a per-host budget remain the P0 fix** for the false-positive queue.
5. **Feature work:** `host_roles` is collected but unused; role-aware baselines (ML-13) are the
   next feature gap. DNS coverage is sensor-limited, not code-limited.

No production deployment was performed. The live build is still 0.23.14.

---

## 7. Files and reproduction

- `weirvern/models/candidates.py` — fixed shadow candidate.
- `tests/test_ml_shadow.py` — added coverage tests.
- `/tmp/glosh-full-matrix.tsv` — 5,000 × 19 monitored live matrix.
- `/tmp/glosh-full-analysis.json` — full-feature live result.
- `/tmp/glosh-seeded-matrix.tsv` — 720-row disposable demo matrix.
- `/tmp/glosh_seeded_eval.py` — seeded A/B script.
- `/tmp/glosh-venv` — Python 3.12 analysis environment (scikit-learn 1.9.1, hdbscan 0.8.44).
- `/tmp/ml-coverage-audit.txt` — live coverage audit output.

Reproduce:

```bash
env -u PYTHONPATH /tmp/glosh-venv/bin/python /tmp/glosh_full_analysis.py
env -u PYTHONPATH /tmp/glosh-venv/bin/python /tmp/glosh_seeded_eval.py
```
