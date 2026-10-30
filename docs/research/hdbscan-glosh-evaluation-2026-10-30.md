# HDBSCAN GLOSH evaluation — live 5,000-row A/B

**Date:** 2026-10-30
**Status:** shadow analysis only. No production table, alert path, model artifact or UI was changed.
**Question:** does HDBSCAN's native **GLOSH** outlier score beat the challenger's current
medoid-distance percentile, and should HDBSCAN replace DBSCAN?

---

## 1. Bottom line

**No swap is justified by this run.**

- On the current challenger's **all-address** sample, GLOSH's top 1% is **49/50 external or
  non-monitored addresses**, with only **1** row in the production alert set. The challenger's
  matrix is not scope-filtered; GLOSH is ranking peers, not alert entities.
- On a **monitored-only** sample (192.168.2/24 + 192.168.3/24), GLOSH is **undefined for 1,225
  of 5,000 rows (24.5%)**, is strongly parameter-sensitive, and its top 1% recovers **32/50**
  current production alerts versus **48/50** for the existing medoid score. That does **not**
  prove it is worse — the current queue is 89% of the monitored sample and is itself the thing
  under review — but it proves GLOSH is **not a drop-in improvement**.
- GLOSH is a genuine outlier score, not a percentile. That is an improvement in principle. It
  still needs a scope filter, a NaN policy, a chosen `min_cluster_size`, and a fixed-budget
  evaluation against seeded attacks before it can replace anything.

---

## 2. Method

- Exported **5,000** live host-window rows from the same 8-feature projection DBSCAN and the
  HDBSCAN challenger use (`log` bytes/packets/destination IPs/flows, destination-port count,
  port entropy, activity regularity, burstiness), 72-hour window, hash-ordered.
- Preprocessing mirrors the challenger: median impute, standardize.
- Models:
  - **sklearn HDBSCAN** `min_cluster_size=40, min_samples=5, store_centers="medoid"` — the
    live challenger's current score (distance to nearest medoid, converted to a percentile).
  - **hdbscan 0.8.44 HDBSCAN** `min_cluster_size=40, min_samples=5` — native
    `outlier_scores_` (GLOSH).
- Two matrices:
  - **all addresses** — exactly the challenger's current sample; 4,565/5,000 rows are
    external/other, only 249 are in a monitored scope.
  - **monitored only** — 5,000 rows from 22 monitored hosts in 192.168.2/24 and 192.168.3/24.
- The production alert row set (`netflow_anomalies`) is used only as a **proxy**: it tells us
  whether a candidate re-finds the current queue, not whether the queue is right. There is no
  ground-truth attack label in this sample.
- No production write. The analysis is reproducible from the local TSV exports and
  `/tmp/glosh_analysis2.py`.

---

## 3. Results

### 3.1 The all-address matrix is dominated by external peers

| | all-address sample |
|---|---:|
| rows | 5,000 |
| monitored-scope rows | 249 |
| external/observe rows | 4,751 |
| GLOSH top 1% in production alerts | **1/50** |
| GLOSH top 1% external or non-monitored | **49/50** |
| medoid top 1% in production alerts | **39/50** |

This is a scope defect in the current challenger: `matrix_sql()` does not filter to monitored
scopes. GLOSH ranks the external peer population ahead of the internal hosts, which violates
the standing rule that external addresses are peer dimensions, never alert entities.

### 3.2 Monitored-only matrix

| | medoid | GLOSH |
|---|---:|---:|
| clusters | 23 | 23 |
| noise | 1,386 (27.7%) | 1,455 (29.1%) |
| NaN scores | 0 | **1,225 (24.5%)** |
| score p50 | 0.50 | 0.127 |
| score p99 | 0.99 | 0.784 |
| finite rows | 5,000 | 3,775 |
| production alerts overall | 4,451/5,000 (89.0%) | same |

Top-of-ranking comparison:

| cut | medoid production alerts | GLOSH production alerts |
|---|---:|---:|
| top 1% (50) | **48/50 (96%)** | **32/50 (64%)** |
| top 2% (100) | 93/100 (93%) | 77/100 (77%) |
| top 5% (250) | 228/250 (91%) | 201/250 (80%) |

The two rankings are related but not interchangeable: Spearman **ρ = 0.718** on the 3,775
finite rows, yet their **top 1% sets have zero overlap**. They agree on the broad ordering and
disagree on the extreme tail — which is the only part an alert budget uses.

### 3.3 GLOSH is parameter-sensitive

Monitored matrix, `min_samples=5`:

| min_cluster_size | clusters | noise | GLOSH p99 | top-1% production alerts |
|---:|---:|---:|---:|---:|
| 5 | 117 | 25.4% | 0.994 | **30/50 (60%)** |
| 20 | 45 | 25.6% | 0.927 | **45/50 (90%)** |
| 40 | 23 | 29.1% | 0.784 | **32/50 (64%)** |
| 80 | 17 | 31.8% | 0.701 | **32/50 (64%)** |

The setting that best re-finds the current queue is **`min_cluster_size=20`**, not the
challenger default of 40. That is a selection on a proxy label, so it cannot be promoted
without the seeded-attack and benign-window evaluation. It does show that “HDBSCAN” is not a
single model: the parameter chooses a different definition of normal.

The base rate matters: **89% of the monitored sample is already in the production alert set**.
A random 50-row cut would therefore contain about **44.5** production alerts. GLOSH at
`min_cluster_size=20` finds **45/50**, which is indistinguishable from random; at the default
40 it finds **32/50**, which is below random. The medoid score's **48/50** is only a mild
enrichment over the same base rate. None of these numbers measures precision, because the
current queue is the saturated object under review, not ground truth.

### 3.4 What GLOSH's top 1% contains

On the monitored matrix, **18 of the 50** GLOSH top-1% rows are not in the current production
alert set. They come from **six monitored hosts**, including the two gateway/DNS hosts. Those
18 are the interesting part: they may be misses by the current queue, or they may be normal
gateway volume. There is no label in this sample to decide, so they cannot be called
improvements.

---

## 4. Interpretation

**GLOSH is a better *type* of score than the medoid percentile.** It is a real outlier score
with a local-density interpretation, not a rank that is uniform by construction. That matters:
the medoid percentile guarantees a 1% tail without measuring anything.

**But it is not a production replacement yet:**

1. **Scope:** the challenger must filter to monitored scopes before fitting/scoring. GLOSH on
   all addresses is an external-peer ranker and would violate the alert-entity rule.
2. **Undefined scores:** 24.5% NaN on the monitored sample is not a corner case. A production
   scorer needs an explicit policy (for example, score NaN as evidence-only, or use a separate
   density distance for those rows), and the policy must be tested.
3. **Parameter choice:** 30/50 vs 45/50 top-1% recovery across `min_cluster_size` settings is
   too large to ignore. Select on a time-split validation window, then freeze for the A/B.
4. **No truth:** the current alert set is 89% of the monitored sample. Recovering it is not
   precision. GLOSH's 18 non-queue rows could be the best thing in this run or the worst; only
   labels and seeded attacks can tell.

**Decision:** keep DBSCAN shadow-only for now; fix the challenger's scope filter; test GLOSH
at `min_cluster_size=20` and 40 against the medoid score at the same alert budget; require
seeded port-scan/exfiltration detection and benign-window false alarms. If GLOSH wins, replace
the medoid score inside HDBSCAN, then consider replacing DBSCAN. Do not run DBSCAN and HDBSCAN
as two independent votes.

---

## 5. Reproduction

Data exports (scratch, not committed):

- `/tmp/glosh-matrix.tsv` — all-address 5,000 rows
- `/tmp/glosh-mon-matrix.tsv` — monitored-only 5,000 rows
- `/tmp/glosh-prod.tsv` — production rows for the proxy join
- `/tmp/glosh-analysis2.json` — full result
- `/tmp/glosh_analysis2.py` — analysis script
- Environment: `/tmp/glosh-venv` (Python 3.12, scikit-learn 1.9.1, hdbscan 0.8.44, numpy 2.4.6)

Commands:

```bash
env -u PYTHONPATH /tmp/glosh-venv/bin/python /tmp/glosh_analysis2.py
```

The ClickHouse matrix SQL is the same projection as `weirvern/models/candidates.py`
(`FEATURES_SQL`), with an optional `src_addr LIKE '192.168.2.%' OR ... '192.168.3.%'` filter
for the monitored sample.

---

## Sources

- Campello, Moulavi & Sander, *Density-Based Clustering Based on Hierarchical Density
  Estimates* (HDBSCAN), 2013.
- scikit-learn HDBSCAN documentation:
  https://scikit-learn.org/stable/modules/generated/sklearn.cluster.HDBSCAN.html
- hdbscan documentation, GLOSH outlier detection:
  https://hdbscan.readthedocs.io/en/latest/outlier_detection.html
- Prior Weirvern research: `docs/research/ml-model-candidates-2026-10-23.md` and
  `docs/research/ml-false-positive-reduction-2026-10-29.md`.
