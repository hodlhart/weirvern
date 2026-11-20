# Cross-sectional detector bake-off — 2026-11-20

**Status:** offline evaluation on the deployed ClickHouse data. No production detector, config,
threshold or table was changed. Harness: `scripts/cross_sectional_bakeoff.py` (commit
`8cfdb81`, version 0.23.100). Raw results: the JSON files reproduced by the commands in Appendix B.

**Question.** DBSCAN is being retired. Its replacement must answer a cross-sectional question —
*does this host-window look unlike the population of host-windows?* — with a continuous score
that can be conformalised against `weirvern/models/calibration.py` at a 0.01 false-alarm target.
This report measures six candidates on the same 19-feature vector, the same walk-forward split,
and the same threshold rule, and recommends one.

---

## 1. Bottom line

**Recommendation: adopt kNN distance (k = 10) on the 19-feature vector, calibrated separately
per measured-coverage stratum.**

- Held-out FAR **1.18%** at a 0.01 target, 95% CI **[0.99%, 1.41%]**, pooled over **10,347
  held-out windows** in four walk-forward folds.
- The rate is consistent *within every coverage stratum*: **1.05% / 1.07% / 1.24%** for 8/19,
  16/19 and 19/19 measured columns. No other candidate is consistent across strata; this is the
  property that makes the score usable on the deployment as it actually is.
- Score is continuous and fine-grained: ~2,590 distinct values per fold (2,721 on the largest
  test day), median **102 distinct values per host**; 2% of rows at the modal value (vs **24–48%** for DBSCAN).
- Rank correlation with the existing detectors is **+0.46 with Isolation Forest** and **+0.36
  with Gradient Boosting** — below the 0.7 redundancy bar, so it is not a duplicate, but it is
  the most correlated candidate that still passes and its marginal value is *modest*.
- Cost at 5,000 training windows: **0.01 s to fit**, **4.8 µs per window to score** — the
  cheapest candidate that works.

**Runner-up: LOF with `novelty=True` (k = 20), same preprocessing and the same per-stratum
calibration.** It is the only genuinely *independent* score (ρ = **−0.08** with IF, **−0.15**
with GB, per-stratum) and lands at 1.69% pooled FAR. It is not the winner because its score is unbounded and
its per-fold FAR moves between 0% and 7.9% (and, without collapsing duplicate reference rows, it
produced a threshold of **8.5 × 10⁸** in one fold — a detector that is silently off).

**If per-stratum calibration is not implemented, the slot should stay empty.** With one
threshold across all coverage levels, every candidate's "1%" is an artefact: partial-coverage
windows alert at **0.0%** while fully observed windows alert at **2.3–2.5%**, and the headline
number is just a weighted average of the two. See §5.1 — this is the central finding of the
exercise and the reason the recommendation is conditional on a calibration change.

**Do not adopt:** GMM-BIC (4× target), EllipticEnvelope (0.43% — consistently silent),
Isolation Forest on 19 features (0.24% — effectively off, and method-redundant with the IF
already in the ensemble), DBSCAN as shipped (degenerate score, 97.9% of live scores at its
ceiling).

---

## 2. Data: what the box actually holds

Measured on `sensor.example`, 2026-11-20 (queries in Appendix A).

| fact | value |
|---|---|
| monitored scopes (`network_scopes`, `monitored = 1`) | `203.0.113.0/24`, `198.51.100.0/24` |
| host-windows in the extraction | **28,531** |
| distinct source hosts | **24** |
| time span | 2026-11-12 13:50 → 2026-11-19 21:05 (7.3 days) |
| `flows_window` retention (TTL) | 258 days declared, **7.3 days present** |
| hosts surviving production's `sipHash64(src_addr) % 5 == 1` cut | **5 of 24** |
| high/critical `netflow_anomalies` in the period | **5 rows** (4 on 11-12, 1 on 11-13) |

Rows per day (monitored scopes, `total_bytes > 0`): 2,099 / 5,424 / 5,237 / 5,424 / 2,967 /
1,189 / 3,367 / 2,824; hosts per day 21–23. Two days (11-16, 11-17) are visibly light — the
sensor was not producing a full day — and are called out wherever they affect a fold.

**A literal week-on-week split is not expressible.** The retention is 7.3 days, so "train on week
N, validate on week N+1" cannot be run even once. The folds below use the deployment's own
reference length: `RETRAIN_WINDOW_H = 72` hours of normal traffic, then the **next 24 hours**,
which no candidate has seen. The 24 h unit is the natural walk-forward step because
`RETRAIN_EVERY_H = 6` and the alert budget is quoted per day.

**Coverage is not smooth; it has exactly three levels.** After `null_absent_zeek`:

| columns measured | rows | share | what is absent |
|---|---|---|---|
| **8/19** (0.4211) | 5,972 | 20.9% | no Zeek row at all — all 11 Zeek columns NaN, including `zeek_present` |
| **16/19** (0.8421) | 8,627 | 30.2% | Zeek connection data present, **no DNS rows** (the 3 DNS columns NaN) |
| **19/19** (1.0000) | 13,932 | 48.8% | nothing absent |

Two further facts that matter for §5.2 and §5.6:

- **826 host-windows (2.9%) are exact duplicates** of another window's 19-vector. Quiet hosts
  produce identical vectors; this is what breaks LOF's density ratio and flattens DBSCAN's
  distance into a step function.
- **Three rows in the whole dataset carry the high/critical flag** used by
  `_flagged_exclusion_clause` (of the five high/critical `netflow_anomalies` rows in the period,
  three match a monitored host-window that has traffic), all before the first fold. The
  training-hygiene clause removes **nothing** from any fold in this period. That is a measurement,
  not a decision: the clause is inert on this data because the severity tiers did not reach
  high/critical on monitored hosts.

---

## 3. Protocol

### 3.1 Folds (72 h normal reference → next 24 h held out)

| fold | train window | test window | train rows (normal) | used | fit / cal | test rows | test hosts | complete-case test |
|---|---|---|---|---|---|---|---|---|
| F1 | 2026-11-13 00:00 → 11-16 00:00 | 11-16 00:00 → 11-17 00:00 | 16,084 | 5,000 | 3,333 / 1,667 | 2,967 | 23 | 1,722 |
| F2 | 2026-11-14 00:00 → 11-17 00:00 | 11-17 00:00 → 11-18 00:00 | 13,628 | 5,000 | 3,333 / 1,667 | 1,189 | 21 | 595 |
| F3 | 2026-11-15 00:00 → 11-18 00:00 | 11-18 00:00 → 11-19 00:00 | 9,580 | 5,000 | 3,333 / 1,667 | 3,367 | 20 | 2,549 |
| F4 | 2026-11-16 00:00 → 11-19 00:00 | 11-19 00:00 → 11-20 00:00 | 7,523 | 5,000 | 3,333 / 1,667 | 2,824 | 20 | 2,016 |

Half-open intervals: a window at exactly 00:00 belongs to the later fold. Pooled held-out
population: **10,347 windows**.

### 3.2 Reference construction

1. **Normal windows only**: rows whose `(src_addr, 5-minute bucket)` appears in
   `netflow_anomalies` with `severity IN ('high','critical')` are dropped from the reference —
   the same predicate `_flagged_exclusion_clause` splices into every training query.
2. **The full monitored population**, then a deterministic cut to **5,000** rows by a stable
   digest of `(src_addr, window_start)`. This deliberately does **not** reproduce production's
   `sipHash64(src_addr) % 5 == 1`, because with 24 hosts that cut leaves **5 hosts**, and a
   cross-sectional reference of 5 hosts is not a population. The 5,000 cap is production's
   `dbscan_n_samples` and is what the cost figures are quoted at.
3. **Fit / calibration split**: every third row in the stable order is held out for calibration
   (1,667 rows), the other 3,333 are the fit set. The threshold is chosen on data the model did
   not fit — otherwise "0.01 in-sample" is a statement about memorisation. This mirrors
   `calibration.fit()`'s even/odd split.

### 3.3 Threshold and measurement

- Threshold rule: `weirvern.models.calibration.conformal_threshold(scores, 0.01)` — the
  ⌈(n+1)·0.99⌉-th smallest calibration score. The repo's own function, unmodified.
- **Train FAR** below is measured on the calibration slice *at that threshold* (it is ≈0.96% by
  construction and confirms the rule was applied). The **in-sample** FAR — threshold taken from
  the fit half itself, then measured on the fit half — is reported separately in §5.11, because
  that is where the "0.01 in-sample, 0.4 out-of-sample" failure lives.
- **Held-out FAR** = share of the next day's windows at or above the threshold. 95% intervals
  are Wilson. `far_test_clean` (excluding high/critical held-out windows) equals `far_test` in
  every fold — there are no flagged rows in any test day.
- **Redundancy**: Spearman ρ against the production scores stored in `ml_window_scores` for the
  *same* `(src_addr, window_start)` — the real Isolation Forest, Gradient Boosting, DBSCAN and
  Adaptive Baseline scores as deployed, not a reimplementation. Coverage of the join is 100% of
  the 28,531 rows. These production scores are **not** held-out (the models retrain every 6 h on
  the last 72 h, which includes the scored windows); that is fine for a redundancy question and
  is stated so it cannot be mistaken for a FAR measurement.

### 3.4 The six candidates, as configured

All six share the vector, the reference rows, the fit/calibration split, and the threshold rule.
Preprocessing is named per candidate because it is part of the candidate.

| # | candidate | model | preprocessing | score |
|---|---|---|---|---|
| 1 | **kNN-10** | `NearestNeighbors(n_neighbors=10)` | median impute (training-time neutral) + `StandardScaler` | distance to the 10th neighbour |
| 2 | **LOF-20** | `LocalOutlierFactor(n_neighbors=20, novelty=True)` | same | `−score_samples` (LOF; higher = odder) |
| 3 | **GMM-BIC** | `GaussianMixture(covariance_type="diag")`, components 1..12 by BIC on the fit set, `reg_covar=1e-6`, `n_init=2` | same | `−score_samples` (negative log-likelihood) |
| 4 | **EllipticEnvelope** | `EllipticEnvelope(contamination=0.06, support_fraction=0.75, random_state=42)` | same | `mahalanobis()` |
| 5 | **IForest-19** | `IsolationForest(contamination=0.06, random_state=42)` on the 19 features | same | `−score_samples` |
| 6 | **DBSCAN-shipped** | `DBSCAN(eps=0.6, min_samples=5)`, cluster centres, percentile calibration (`calibrate_distance`) | `MissingAwarePreprocessor(indicators=False)` — exactly `DBSCANDetector` | distance to nearest centre, calibrated |

Variants run as sensitivities and reported where they change the conclusion: `kNN-10-robust`
(`RobustScaler`), `kNN-10-masked` (distance over observed dimensions only, rescaled —
`masked_distance`), `kNN-10+ind`, `LOF-20-dedup` (exact duplicate reference rows collapsed),
`LOF-20-dedup+ind`, `EllipticEnvelope+ind`. `+ind` appends one unscaled 0/1 missing indicator
per column, the `MissingAwarePreprocessor` rule applied to a non-DBSCAN model.

---

## 4. Results — the required table

**Primary protocol:** 72 h reference → next 24 h, all monitored windows, one threshold per
candidate (no stratification). 10,347 held-out windows.

| candidate | train FAR¹ | held-out FAR (95% CI) | distinct scores | cost (fit / score) | ρ with IF | ρ with GB | verdict |
|---|---|---|---|---|---|---|---|
| **kNN-10** | 0.96% | **1.87%** [1.62–2.14] | 2,590 | 0.01 s / 4.8 µs·win | +0.465 | +0.359 | **winner**, but see §5.2 |
| LOF-20 | 0.96% | 0.71% [0.56–0.89] | 2,541 | 0.11 s / 6.5 µs·win | +0.060 | +0.057 | runner-up |
| GMM-BIC | 0.96% | 4.17% [3.80–4.57] | 2,590 | 5.27 s / 0.39 µs·win | +0.415 | +0.340 | reject |
| EllipticEnvelope | 0.96% | 1.09% [0.91–1.31] | 2,594 | 0.67 s / 0.25 µs·win | +0.435 | +0.345 | reject (§6.4) |
| IForest-19 | 0.96% | 0.46% [0.35–0.61] | 2,465 | 0.30 s / 3.5 µs·win | +0.441 | +0.351 | reject (§6.5) |
| DBSCAN-shipped | 0.96% | 0.85% [0.69–1.05] | 1,690 | 0.59 s / 81.7 µs·win | +0.375 | +0.270 | retire (§6.6) |

Per-fold held-out FAR (%) — the spread is the story, not the pooled mean:

| candidate | F1 (11-16) | F2 (11-17) | F3 (11-18) | F4 (11-19) |
|---|---|---|---|---|
| kNN-10 | 2.60 | 1.43 | 1.63 | 1.56 |
| LOF-20 | 0.37 | 0.84 | 1.22 | 0.39 |
| GMM-BIC | 2.80 | 13.37 | 3.92 | 2.02 |
| EllipticEnvelope | 1.38 | 1.09 | 0.03 | 2.05 |
| IForest-19 | 1.25 | 0.08 | 0.24 | 0.07 |
| DBSCAN-shipped | 1.04 | 0.34 | 0.74 | 0.99 |

¹ 0.96% is the conformal rank at n = 1,667 (⌈1668 × 0.99⌉ = 1,652). One fold lands at 1.26%
(LOF F4) because there the threshold falls on the single extreme score that also blew the
threshold up to 8.5 × 10⁸; ties at a threshold are counted as alerts, which is why a score with
tied values cannot express a 1% budget exactly.

"Distinct scores" is the median over folds of distinct held-out values; DBSCAN's 1,690 comes with
**24% of rows (up to 48% in F4) at one value**, versus 2% for every other candidate. See §5.5.

---

## 5. Analysis

### 5.1 The headline FAR is not a false-alarm rate on the population

The deployment's windows fall into three disjoint coverage strata (§2). With one threshold, the
alert budget does not spread over the population — it lands almost entirely on the fully observed
stratum:

| candidate | ρ(score, coverage) | FAR on **partial** rows | FAR on **full** rows | partial share of windows |
|---|---|---|---|---|
| kNN-10 | +0.50 | **0.00%** | 2.52% | 35% |
| LOF-20 | −0.08 | 1.28% | 0.25% | 35% |
| GMM-BIC | +0.53 | 1.07% | 4.49% | 35% |
| EllipticEnvelope | +0.32 | **0.00%** | 2.28% | 35% |
| IForest-19 | +0.40 | **0.00%** | 0.24% | 35% |
| DBSCAN-shipped | +0.37 | **0.00%** | 1.18% | 35% |
| kNN-10-masked | +0.44 | **0.00%** | 2.51% | 35% |
| kNN-10+ind | +0.52 | **0.00%** | 2.53% | 35% |
| LOF-20-dedup+ind | −0.12 | 3.27% | 0.02% | 35% |

Read the kNN row: a host-window with 11 columns absent (or 3, for the DNS-less stratum) scores
*at the population median* on those columns, which makes it one of the **most normal** points in
the space. Its alert rate is exactly
zero; the 1.87% headline is 2.52% on the 65% of windows that are fully observed. DBSCAN behaves
identically (0.00% / 1.18%). This is the failure `weirvern/models/missing.py` was written about,
in the opposite direction from the one it anticipated: absence does not read as an anomaly, it
reads as **normality**, and the detector goes blind on 35% of the population while reporting a
healthy rate.

**Adding missing indicators does not fix it** (`kNN-10+ind`: partial-row FAR still 0.00%)
because the indicator columns enter the distance for *every* partial row in the reference too, so
the threshold rises with them. **`masked_distance` does not fix it either** (`kNN-10-masked`:
0.00%) because the NetFlow-only stratum is internally very homogeneous — its members are close to
each other in the 8 observed dimensions, and the √(19/8) rescale is a constant.

The one candidate whose partial rows alert more than its full rows is LOF (1.28% vs 0.25%), and
that is not a virtue: it is the duplicate/cluster pathology of §6.2, where rows sitting next to a
pile of identical quiet windows get an enormous density ratio. `LOF-20-dedup+ind` shows the other
extreme — 3.27% of partial rows versus 0.02% of full ones — i.e. a coverage change becomes an
alert storm. On the 11-14 test day, where 67% of windows were partial, that variant produced
**15.5% FAR**.

**Conclusion: no candidate handles a half-missing vector honestly with one threshold. The
coverage stratum has to be part of the calibration key.** That is the change that turns kNN from
a 2.5%-on-half-the-population detector into a 1.18%-on-all-of-it detector (§5.2).

### 5.2 Per-stratum calibration — the configuration that works

Calibrating and measuring **within each coverage stratum** (8/19, 16/19, 19/19), then pooling by
window count over the same 10,347 held-out windows:

| candidate | 8/19 (n=759) | 16/19 (n=2,706) | 19/19 (n=6,882) | **pooled (n=10,347)** | 95% CI | ρ with IF |
|---|---|---|---|---|---|---|
| **kNN-10** | **1.05%** | **1.07%** | **1.24%** | **1.18%** | [0.99–1.41] | +0.457 |
| kNN-10-robust | 1.32% | 1.48% | 0.60% | 0.88% | [0.72–1.08] | +0.344 |
| LOF-20 | 1.58% | 1.59% | 1.74% | 1.69% | [1.46–1.96] | −0.083 |
| LOF-20-dedup | 8.56% | 0.63% | 1.24% | 1.61% | [1.39–1.88] | −0.010 |
| GMM-BIC | 6.85% | 2.70% | 3.95% | 3.84% | [3.48–4.22] | +0.288 |
| EllipticEnvelope | 0.66% | 0.44% | 0.41% | 0.43% | [0.33–0.58] | +0.390 |
| IForest-19 | 0.00% | 0.44% | 0.19% | 0.24% | [0.16–0.36] | +0.516 |
| DBSCAN-shipped | 5.01% | 0.63% | 0.71% | 1.01% | [0.83–1.22] | +0.211 |

kNN is the only candidate whose FAR is within a quarter of a point of the target in **every**
stratum. LOF is also stable across strata (1.58/1.59/1.74) but at 1.7× the target. DBSCAN's 1.01%
pooled hides 5.01% in the smallest stratum. Of the rest, GMM is four times the budget and EE and
IF19 are effectively silent.

Per-fold within stratum (kNN-10): 8/19 = 8.45 / 0.76 / 0 / 0; 16/19 = 0.09 / 3.02 / 1.88 / 1.14;
19/19 = 1.68 / 2.35 / 1.61 / 0.05. The smallest stratum holds ~190 windows per fold, so its
per-fold rate is noisy by construction; the pooled figure is the one to quote.

### 5.3 Complete-case sensitivity

Restricting reference *and* evaluation to fully observed windows (the "abstain on partial
telemetry" policy):

| candidate | pooled FAR | per-fold (%) | ρ with IF |
|---|---|---|---|
| kNN-10 | 1.24% [1.00–1.52] | 1.68 / 2.35 / 1.61 / 0.05 | +0.616 |
| LOF-20-dedup | 1.24% [1.00–1.52] | 0.41 / 8.57 / 0.27 / 0.99 | +0.206 |
| DBSCAN-shipped | 0.71% [0.54–0.94] | 2.21 / 1.34 / 0.00 / 0.15 | +0.546 |
| EllipticEnvelope | 0.41% [0.28–0.59] | 1.34 / 0.00 / 0.00 / 0.25 | +0.590 |
| IForest-19 | 0.19% [0.11–0.32] | 0.46 / 0.00 / 0.00 / 0.25 | +0.516 |
| GMM-BIC | 3.95% [3.52–4.44] | 1.80 / 8.74 / 5.88 / 1.93 | +0.658 |

kNN holds at 1.24%; LOF matches it but with an 8.6% day; EE and IF19 collapse to zero alerts on
three of four days. Note kNN's correlation with IF rises to **0.62** here — on a homogeneous
population the two scores agree more, and that is the honest redundancy number to quote.

### 5.4 Shorter-reference sensitivity (24 h → 24 h, six folds)

The production reference is 72 h; this run exists to show the conclusion is not an artefact of
one reference length. Pooled FAR, mixed population:

| candidate | 24 h → 24 h | 72 h → 24 h |
|---|---|---|
| kNN-10 | 3.29% | 1.87% |
| LOF-20 | 2.45% | 0.71% |
| EllipticEnvelope | 1.42% | 1.09% |
| IForest-19 | 1.54% | 0.46% |
| DBSCAN-shipped | 1.96% | 0.85% |
| GMM-BIC | 4.18% | 4.17% |

Everything degrades when the reference shrinks to one day — the calibration has half the order
statistics behind it and the day-to-day population shift dominates. kNN is the most sensitive to
the shorter reference (3.29%), which is worth stating plainly: the recommendation depends on the
deployed 72 h window, and a future change to `RETRAIN_WINDOW_H` would need this re-measured.

### 5.5 Score-distribution sanity

| candidate | distinct values (median) | modal share | per-host distinct (median) | std (F1) | max score (F4) |
|---|---|---|---|---|---|
| kNN-10 | 2,590 | 0.02 | 102 | 1.28 | 9.0 |
| LOF-20 | 2,541 | 0.02 | 99 | 1.92 | 7.9 × 10⁹ |
| GMM-BIC | 2,590 | 0.02 | 102 | 26.3 | 6.0 × 10⁵ |
| EllipticEnvelope | 2,594 | 0.02 | 102 | 1.18 × 10³ | 1.2 × 10⁴ |
| IForest-19 | 2,465 | 0.02 | 95 | 0.067 | 0.70 |
| DBSCAN-shipped | **1,690** | **0.24** | **65** | 0.215 | 0.94 |

DBSCAN is the only degenerate score: `calibrate_distance` maps everything at or below the
training p50 to exactly **0.0** and everything above p99 into a narrow 0.85–0.99 band, so a
quarter of held-out windows (half, on 11-19) share one value and the detector cannot be
thresholded with any precision. Its **live** distribution is worse — see §6.6.

LOF's `7.9 × 10⁹` is the duplicate-neighbourhood pathology: with exact duplicate reference rows,
a point adjacent to such a cluster gets an infinite density ratio. In F4 that pushed the 99th
percentile of the calibration scores to **8.52 × 10⁸**, i.e. above every score the detector then
produced — the detector was silently off and its 0.39% FAR in that fold is an artefact of being
off, not of being good.

### 5.6 Per-host coverage and alert concentration

| candidate | hosts with alerts (F1/F2/F3/F4) | max share from one host (median) | persistence lift |
|---|---|---|---|
| kNN-10 | 9 / 7 / 6 / 2 | 0.47 | 14.4× |
| LOF-20 | 7 / 4 / 7 / 6 | 0.37 | 0.0× (all singletons) |
| LOF-20-dedup+ind | 9 / 8 / 4 / 11 | 0.36 | 22.2× |
| GMM-BIC | 15 / 15 / 13 / 4 | 0.47 | 7.7× |
| EllipticEnvelope | 5 / 3 / 1 / 3 | **0.84** | 2.0× |
| IForest-19 | 3 / 1 / 1 / 1 | **1.00** | 12.4× |
| DBSCAN-shipped | 3 / 3 / 4 / 2 | 0.57 | 4.5× |

"Persistence lift" is P(alert at *t* | alert at *t−1*, same host, 5 minutes earlier) divided by
the FAR — a label-free test of whether the score tracks a sustained state rather than i.i.d.
noise. kNN's 14× and LOF-dedup+ind's 22× say the alerts are structured; DBSCAN's 4.5× and EE's 2×
say theirs are close to noise.

**Alert concentration matters operationally.** IForest-19 spends its entire budget on **one host**
in three of four folds (share 1.00) and EllipticEnvelope on one host in F3 — a global
distance-from-the-centre score identifies the *chronically* unusual hosts, not changing
behaviour. kNN and LOF spread alerts over 4–11 hosts. This is the strongest argument against the
IF control that does not depend on its FAR.

### 5.7 Cost at 5,000 training windows

| candidate | fit (s) | score (µs/window) | score time, 3,000 windows (ms) | relative fit |
|---|---|---|---|---|
| kNN-10 | **0.01** | 4.8 | 14 | 1× |
| LOF-20 | 0.11 | 6.5 | 19 | 11× |
| IForest-19 | 0.30 | 3.5 | 11 | 30× |
| DBSCAN-shipped | 0.59 | 81.7 | 245 | 59× |
| EllipticEnvelope | 0.67 | 0.25 | 0.8 | 67× |
| GMM-BIC | 5.27 | 0.39 | 1.2 | 527× |

Measured on this box (CPython 3.11, sklearn 1.9.1, single thread), fit on 3,333 rows and scored on
the held-out fold. All are cheap enough for a 5-minute sweep; the differences are not a reason to
choose between them, except that GMM's BIC sweep is ~500× the cost of kNN for a worse result.

### 5.8 Redundancy

Spearman ρ against the **production** scores stored for the same windows:

| candidate | IF | GB | DBSCAN | Adaptive Baseline |
|---|---|---|---|---|
| kNN-10 | +0.465 | +0.359 | +0.029 | — |
| LOF-20 | **+0.060** | **+0.057** | −0.004 | — |
| GMM-BIC | +0.415 | +0.340 | +0.035 | — |
| EllipticEnvelope | +0.435 | +0.345 | +0.047 | — |
| IForest-19 | +0.441 | +0.351 | +0.021 | — |
| DBSCAN-shipped | +0.375 | +0.270 | +0.004 | — |

**No candidate crosses the 0.7 redundancy bar.** That is a genuine result and it is slightly
surprising: a 19-feature Isolation Forest is *not* a duplicate of the 77-feature one (ρ 0.44) —
the narrower vector produces a different ranking. But the ordering matters for the recommendation:
LOF at ρ ≈ 0.06 is the only candidate that would add an independent view; kNN at 0.46 (0.62 on
complete cases) is correlated enough that its marginal contribution is modest. kNN's ρ against
production DBSCAN is ~0.03 because the production DBSCAN score is a near-constant (§6.6) — a
correlation with a constant is not evidence of independence.

### 5.9 Missing features: what each candidate does, and what it costs

| candidate | treatment of an absent column | can absence look like an anomaly? |
|---|---|---|
| kNN-10 | median impute with the **reference** median; scaled; no indicator | **No — it looks like normality.** Partial rows alert at 0.00% vs 2.52% for full rows |
| LOF-20 | same | Yes, but for the wrong reason: duplicate-cluster density ratios; 1.28% vs 0.25% |
| GMM-BIC | same; the imputed point is scored under the fitted density | No: 1.07% vs 4.49% |
| EllipticEnvelope | same; Mahalanobis over all 19 dimensions | No: 0.00% vs 2.28% |
| IForest-19 | same | No: 0.00% vs 0.24% |
| DBSCAN-shipped | median for the dense fit; **masked distance** over observed dimensions at score time (`masked_distance`) | No: 0.00% vs 1.18% — the rescale does not overcome the homogeneity of the 8/19 stratum |
| kNN-10-masked | distance over observed dimensions only, rescaled | No: 0.00% |
| kNN-10+ind / EE+ind | median impute **plus** one unscaled 0/1 indicator per column | No: indicators raise the threshold along with the score; 0.00% |
| LOF-20-dedup+ind | same | **Yes, catastrophically**: 3.27% of partial rows vs 0.02% of full; 15.5% FAR on a day when 67% of windows were partial |

The only configuration in which absence neither hides a host nor fabricates an alert is
**per-stratum calibration**: within a stratum every row has the same observed dimensions, so the
comparison is like-for-like (§5.2). Anything else either blinds the detector on 35% of windows or
turns a DNS outage into an alert storm.

---

## 6. Candidate-by-candidate verdicts

### 6.1 kNN distance, k = 10 — **adopt**

- Held-out FAR 1.87% single-threshold, **1.18% [0.99–1.41] with per-stratum calibration**, and
  1.05/1.07/1.24 within the three strata — the most consistent result in the study.
- Continuous, 2,590 distinct values, 102 per host, 2% modal share. No fitting failure mode: no
  covariance to invert, no density ratio to divide by zero, no local minima, deterministic.
- 0.01 s fit, 4.8 µs/window. Cheapest candidate that works.
- Alerts spread over 4–9 hosts, 14× temporal persistence lift.
- **Weakness, stated plainly:** ρ = +0.46 with Isolation Forest (+0.62 on complete cases). It is
  the most redundant candidate that still passes the 0.7 bar. If the ensemble's goal is a
  genuinely independent fourth opinion, LOF is the better score and this is the trade being made.
- **Second weakness:** it is the most sensitive to a shorter reference (3.29% at 24 h).

### 6.2 LOF, k = 20, `novelty=True` — **runner-up, conditional**

- The only independent score (ρ = −0.08 IF, −0.15 GB, per-stratum) and stable across coverage strata
  (1.58/1.59/1.74 → 1.69% pooled).
- **Unbounded score.** With exact duplicate reference rows, sklearn's LOF divides by an infinite
  local reachability density and returns astronomical values: without `dedup` the F4 threshold
  was **8.52 × 10⁸** and the detector produced 0.39% FAR by being switched off. Collapsing
  duplicate reference rows (`LOF-20-dedup`) fixes the threshold (2.5–5.6) but changes the result
  to 1.61% pooled with an 8.56% stratum day.
- Per-fold FAR 0.41 / 7.90 / 1.18 / 1.79 on complete cases — an 8% day is a console flood at a
  1% budget.
- Also the worst cost/benefit of the cheap models (6.5 µs/window, 11× kNN's fit).
- Adopt only if a bounded score is engineered first (winsorise the reference at a finite ceiling,
  or score the log-LOF), and re-run this harness on that variant.

### 6.3 Gaussian Mixture, diagonal, BIC — **do not adopt**

4.17% pooled, 13.37% on F2, 3.84% per-stratum, 4.65% at 24 h. It is the only candidate that
*overshoots* the budget in every protocol by 2–13×, and the only one whose BIC-selected component
count changes the tail behaviour day to day. 527× kNN's fit cost. No configuration tested brings
it near 1%.

### 6.4 EllipticEnvelope — **do not adopt**

Its pooled 1.09% is the closest single-threshold number to target and it is misleading: the
per-fold rate is 1.38 / 1.09 / **0.03** / 2.05, and with per-stratum calibration the pooled figure
is **0.43%** with per-fold **1.21 / 0.17 / 0.03 / 0.21%** — three of four days at or below 0.21%,
and two of those days produced a *single* alert each. A Mahalanobis distance in 19 dimensions
estimated from 3,333 rows is dominated by a handful of extreme points — the score's std is
1.18 × 10³ and its max 1.2 × 10⁴ — so the 99th percentile is an unstable statistic. It also
concentrates alerts on 1–3 hosts (max share 0.84 in the single-threshold run). It is either
alerting on the same chronically unusual hosts or not alerting at all.

### 6.5 Isolation Forest on the 19 features — **do not adopt**

The control answers the method question: **the feature set is not the problem, and IF is not the
answer either.** 0.46% pooled, 0.19% complete-case, 0.24% per-stratum (per-fold **0.54 / 0.25 /
0.03 / 0.18%**); 1 host receives 100% of alerts in three of four folds. It is the IF already in
the ensemble wearing a narrower vector — same family, same concentration pathology, and a quarter
of the alert rate it was asked for. If the slot were filled with this, the ensemble would gain a
correlated, near-silent detector.

### 6.6 DBSCAN as shipped — **retire, as planned**

- **The live score is saturated.** Over 27,454 stored DBSCAN scores for monitored hosts
  (11-12 → 11-19): **97.89% are ≥ 0.99**, 99.83% are ≥ 0.35 (the console's `BASE_THRESHOLD`),
  p50 = 0.99, p99 = 0.99, max = 0.99. A detector whose score is 0.99 on 98% of windows cannot be
  given a threshold: any cut below the ceiling fires on essentially everything, which is the
  FAR ≈ 1.0 the retirement is about.
- In this harness it looks better than it is (0.85% single-threshold, 1.01% per-stratum) because
  **my retrain is healthier than the deployed artifact**: I use all 24 hosts, production's
  `sipHash64 % 5 == 1` leaves **5**. Five hosts is not a reference population, and it is the
  likely reason the deployed calibration is pinned at the ceiling.
- Even the healthier retrain is degenerate: 24–48% of windows at one value, 65 distinct values
  per host, 81.7 µs/window (17× kNN), 5.01% FAR in the 8/19 stratum, and per-stratum per-fold
  rates of 1.42 / 3.70 / 0.36 / 0.21% — its pooled 1.01% is as unstable as anything else here.
- Its 0.85% should not be read as "DBSCAN is fine after all". It is the FAR of a step function
  whose threshold happens to sit in a sparse band.

---

## 7. Recommendation

### 7.1 Winner: kNN distance, k = 10, per coverage stratum

Reproduce exactly:

1. **Vector** — `weirvern.features.DBSCAN_FEATURES`, 19 columns in that order (8 NetFlow
   aggregates + 11 Zeek, including the JA4 pair and the DNS triple). Build it with
   `scripts/cross_sectional_bakeoff.py::matrix_sql`, which is assembled from `_BASE_SQL`,
   `ZEEK_DBSCAN_FEATURES`, `zeek_join_cte` and `ZEEK_JOIN_ON` — not a second copy of the feature
   list.
2. **Absent values** — `null_absent_zeek(X, DBSCAN_FEATURES)`: a host-window with no Zeek row
   becomes NaN in all 11 Zeek columns; a window with `zeek_dns_count == 0` becomes NaN in the 3
   DNS columns. Never 0.
3. **Reference** — last 72 h of monitored host-windows with `total_bytes > 0`, excluding
   high/critical `netflow_anomalies` buckets, deterministic cut to 5,000
   (`ORDER BY blake2b(src_addr|window_start)`; production's `sipHash64` cut to 5,000 is
   equivalent and was not used because of the 1-in-5 host sampling).
4. **Split** — every third row in that order is calibration (1,667), the rest fit (3,333).
5. **Preprocessing** — per-column median of the *observed* values in the fit set
   (`weirvern.models.missing.column_neutrals`), then `StandardScaler` fitted on the filled fit
   matrix. Same neutral and scaler at score time (persist them in the artifact).
6. **Model** — `sklearn.neighbors.NearestNeighbors(n_neighbors=10)` fitted on the scaled fit
   matrix. Score = distance to the 10th neighbour. No tuning of k; 10 is the brief's value and
   was not searched.
7. **Calibration** — partition by measured-coverage share into the strata the deployment
   actually produces (**8/19, 16/19, 19/19**); within each stratum, threshold =
   `conformal_threshold(calibration_scores, 0.01)` = the ⌈(n+1)·0.99⌉-th smallest. Alert when
   `score ≥ threshold` **for the window's own stratum**.
8. **Abstain** — below `ML_MIN_FEATURE_COVERAGE` (0.15), return no score, the existing
   `below_floor` rule. On this deployment that never triggers (the minimum observed is 8/19 =
   0.42) but it is the guard that keeps a future telemetry collapse from being scored.

Expected: **1.18% pooled held-out FAR [0.99–1.41] over 10,347 windows; 1.05/1.07/1.24 within the
three strata; 0.01 s fit; 4.8 µs/window.**

**Production change this requires (not made here):** `ml_calibration` currently stores one
threshold per model. The winner needs one threshold per (model, coverage stratum). That is a
schema/calibration-harness change — out of scope for this task, and the reason the recommendation
is conditional. Without it, the honest answer is "leave the slot empty": a single threshold gives
0% on 35% of windows and 2.5% on the rest.

### 7.2 Runner-up: LOF, k = 20, `novelty=True`, duplicate-collapsed reference

Choose it over kNN **if** the ensemble's priority is an independent view rather than a stable
rate: ρ = −0.08 with IF and −0.15 with GB is the only genuinely new signal in the six. Required
before adoption: a bounded score (collapse duplicate reference rows and winsorise at a finite
ceiling), per-stratum calibration, and a re-run of this harness. As specified in the brief it is
not deployable: it produced an 8.5 × 10⁸ threshold in one fold.

### 7.3 Do not adopt

| candidate | why not |
|---|---|
| GMM-BIC | 4.17% pooled, 13.4% on one fold, 3.84% per-stratum, 4.65% at 24 h — 2–13× the budget in every protocol; 527× kNN's fit cost |
| EllipticEnvelope | 0.43% per-stratum with three of four days at ≤0.21% (two of them a single alert); heavy-tailed (std 1.2 × 10³) so the 99th percentile is unstable; up to 100% of a fold's alerts from one host (median share 0.84) |
| IForest-19 | 0.24% per-stratum / 0.19% complete-case — effectively off; 100% of alerts on one host in three folds; method-redundant with the IF already in the ensemble (and ρ only 0.44, so it is not even a cheap proxy) |
| DBSCAN-shipped | live score 97.9% at ceiling; 24–48% modal share; 65 distinct values per host; 5.01% FAR in the 8/19 stratum; trains on 5 hosts in production |

### 7.4 What "leave the slot empty" would mean

If per-stratum calibration is not on the table, the measured numbers do not support filling the
slot:

- A single threshold makes every candidate's FAR a coverage artefact (0% on 35% of windows,
  2.4–2.5% on the rest).
- The two candidates that look closest to target under one threshold (EE 1.09%, DBSCAN 0.85%)
  are the two whose alert sets are concentrated on 1–3 hosts and whose per-fold rate collapses to
  ~0 on quiet days.
- The ensemble already contains IF + GB + Adaptive Baseline; a fourth score that is blind on a
  third of the population and correlated at 0.5 with IF adds little.

That is a defensible outcome, and it is the one I would report if the calibration key cannot
change. With the stratum key, kNN is a clear, modest, measurable improvement over the incumbent.

---

## 8. Limitations

1. **No labels.** There is no ground truth for these windows. This report measures false-alarm
   behaviour, score structure and redundancy; it does **not** measure detection power. A model
   that alerts less is not thereby better, and the per-host spread / persistence / independence
   columns are the only evidence about usefulness.
2. **Seven days, four folds, 24 hosts.** The population is small and the days are not
   exchangeable (two light days). Fold-level FAR at a 1% target carries ~±0.7 points of binomial
   noise on ~3,000 windows, and the day-to-day shift is larger than that — which is itself the
   finding in §5.1.
3. **The extraction spans 2026-11-12 → 2026-11-19 only** because that is all `flows_window`
   retains, despite a 258-day TTL. A week-on-week protocol is not expressible on this box.
4. **Production scores used for the correlation are not held out** (6-hourly retrain on the last
   72 h). The correlation is a redundancy measure, not a FAR.
5. **The DBSCAN baseline in this harness is healthier than the deployed artifact** (all hosts vs
   the 1-in-5 host cut). Its measured FAR is therefore an upper bound on its quality, and its
   live saturation (§6.6) is the number that matters for the retirement decision.
6. **k was not tuned.** kNN k=10 and LOF k=20 are the brief's values. A k sweep is the obvious
   next experiment for the winner.

---

## Appendix A — queries run

All queries ran through `ssh root@sensor.example 'kubectl -n weirvern exec clickhouse-0 --
clickhouse-client --query "..."'`, except the extraction (query on stdin, via
`scripts/cross_sectional_bakeoff.py extract`).

**A1. Retention and population**

```sql
SELECT min(window_start), max(window_start), count() FROM weirvern.flows_aggregated;
-- 2026-11-12 13:50:00 | 2026-11-19 21:05:00 | 46258447

SELECT toDate(window_start) d, count() rows, uniqExact(src_addr) hosts, uniqExact(window_start) wins
FROM weirvern.flows_window WHERE window_start >= '2026-11-12' GROUP BY d ORDER BY d;

SELECT toDate(window_start) d, count() rows, uniqExact(src_addr) hosts
FROM (
  SELECT window_start, src_addr, sumMerge(total_bytes) AS tb
  FROM weirvern.flows_window
  WHERE (isIPAddressInRange(src_addr,'198.51.100.0/24')
      OR isIPAddressInRange(src_addr,'203.0.113.0/24'))
    AND window_start >= '2026-11-12'
  GROUP BY window_start, src_addr
) WHERE tb > 0 GROUP BY d ORDER BY d;
-- 2099/21, 5424/22, 5237/22, 5424/23, 2967/23, 1189/21, 3367/20, 2824/20

SELECT uniqExact(src_addr) AS all_hosts, uniqExactIf(src_addr, sipHash64(src_addr) % 5 == 1) AS one_in_five
FROM weirvern.flows_window
WHERE (isIPAddressInRange(src_addr,'198.51.100.0/24') OR isIPAddressInRange(src_addr,'203.0.113.0/24'))
  AND window_start >= '2026-11-12';
-- 24 | 5
```

**A2. Training hygiene**

```sql
SELECT toDate(window_start) d,
       countIf(severity IN ('high','critical')) hc, count()
FROM weirvern.netflow_anomalies
WHERE window_start >= '2026-11-12' GROUP BY d ORDER BY d;
-- 11-12: 4, 11-13: 1, every later day: 0
```

**A3. The stored ensemble scores (saturation and the correlation join)**

```sql
SELECT model_name, count() n,
       round(avg(score >= 0.99), 3) ge99, round(avg(score <= 0.0), 3) zero,
       round(avg(score >= 0.35), 3) ge35,
       round(quantile(0.5)(score), 4) p50, round(quantile(0.9)(score), 4) p90,
       round(max(score), 4) mx
FROM weirvern.ml_window_scores FINAL
WHERE window_start >= '2026-11-12'
GROUP BY model_name ORDER BY model_name;

SELECT count() n, round(avg(score >= 0.99), 4) at_ceiling, round(avg(score >= 0.35), 4) above_base,
       round(quantile(0.5)(score), 4) p50, round(quantile(0.99)(score), 4) p99, round(max(score), 4) mx
FROM weirvern.ml_window_scores FINAL
WHERE model_name = 'DBSCAN'
  AND window_start >= '2026-11-12' AND window_start < '2026-11-20';
-- 27454 | 0.9789 | 0.9983 | 0.99 | 0.99 | 0.99
```

**A4. The extraction** — `scripts/cross_sectional_bakeoff.py::matrix_sql(start, end, scopes)`.
Its shape below; `:start` / `:end` stand for the formatted literals the builder interpolates, and
the exact text is written to disk by `extract --sql-out`:

```sql
WITH <zeek_join_cte(start, end)>
SELECT a.window_start, a.src_addr,
       log(a.total_bytes + 1), log(a.total_packets + 1), log(a.unique_dst_ips + 1),
       log(a.flow_count + 1), log(coalesce(d.unique_dst_ports, 0) + 1),
       coalesce(d.port_entropy, 0), coalesce(t.activity_regularity, 1.0),
       coalesce(t.burstiness, 1.0),
       z.zeek_conn_count, z.zeek_service_count, z.zeek_rej_ratio, z.zeek_notice_count,
       z.zeek_weird_count, z.zeek_present, z.zeek_ja4_count, z.zeek_ja4_novelty,
       z.zeek_dns_count, z.zeek_dns_mean_query_entropy, z.zeek_dns_rcode_error_ratio,
       if(f.src_addr != '', 1, 0) AS flagged,
       s.prod_isolation, s.prod_gradient, s.prod_dbscan, s.prod_adaptive
FROM (SELECT window_start, src_addr, sumMerge(total_bytes) AS total_bytes,
             sumMerge(total_packets) AS total_packets, uniqMerge(unique_dst_ips) AS unique_dst_ips,
             countMerge(flow_count) AS flow_count
      FROM weirvern.flows_window
      WHERE window_start >= :start AND window_start < :end
      GROUP BY window_start, src_addr) a
LEFT JOIN (SELECT window_start, src_addr, sum(unique_dst_ports) AS unique_dst_ports,
                  max(port_entropy) AS port_entropy
           FROM weirvern.flows_aggregated_diversity GROUP BY window_start, src_addr) d
       ON a.window_start = d.window_start AND a.src_addr = d.src_addr
LEFT JOIN (SELECT window_start, src_addr, max(activity_regularity) AS activity_regularity,
                  max(burstiness) AS burstiness
           FROM weirvern.flows_aggregated_temporal GROUP BY window_start, src_addr) t
       ON a.window_start = t.window_start AND a.src_addr = t.src_addr
<ZEEK_JOIN_ON>
LEFT JOIN (SELECT src_addr, toStartOfFiveMinutes(window_start) AS ws
           FROM weirvern.netflow_anomalies
           WHERE window_start >= :start AND window_start < :end
             AND severity IN ('high','critical')
           GROUP BY src_addr, ws) f
       ON f.src_addr = a.src_addr AND f.ws = a.window_start
LEFT JOIN (SELECT window_start, src_addr,
                  maxIf(score, model_name='Isolation Forest')  AS prod_isolation,
                  maxIf(score, model_name='Gradient Boosting') AS prod_gradient,
                  maxIf(score, model_name='DBSCAN')            AS prod_dbscan,
                  maxIf(score, model_name='Adaptive Baseline') AS prod_adaptive
           FROM weirvern.ml_window_scores FINAL
           WHERE window_start >= :start AND window_start < :end
           GROUP BY window_start, src_addr) s
       ON s.window_start = a.window_start AND s.src_addr = a.src_addr
WHERE a.window_start >= :start AND a.window_start < :end
  AND a.total_bytes > 0
  AND (isIPAddressInRange(a.src_addr, '203.0.113.0/24')
    OR isIPAddressInRange(a.src_addr, '198.51.100.0/24'))
ORDER BY a.window_start, a.src_addr
```

**A5. Schema and catalog checks**

```sql
SHOW CREATE TABLE weirvern.flows_window;      -- AggregatingMergeTree, TTL 258 days
SHOW CREATE TABLE weirvern.ml_window_scores;  -- ReplacingMergeTree(computed_at),
                                              -- ORDER BY (model_name, window_start, src_addr)

SELECT name, total_rows FROM system.tables WHERE database = 'weirvern' ORDER BY name;
SELECT name, type FROM system.columns WHERE database = 'weirvern' AND table = 'flows_window';

SELECT model_name, count() n, uniqExact(src_addr) hosts,
       min(window_start), max(window_start)
FROM weirvern.ml_window_scores GROUP BY model_name;
-- DBSCAN / Isolation Forest / Gradient Boosting / Adaptive Baseline: 72,978 rows, 27 hosts
-- __fused__: 13,844 rows, 24 hosts

SELECT count() FROM weirvern.ml_window_scores s
INNER JOIN (SELECT window_start, src_addr FROM weirvern.flows_window
            WHERE window_start >= '2026-11-18' AND window_start < '2026-11-19'
            GROUP BY window_start, src_addr) k
  ON s.window_start = k.window_start AND s.src_addr = k.src_addr
WHERE s.model_name = 'Isolation Forest';
-- 3350 of 3367 keys on that day -> the production-score join covers 99.5%+ of the matrix

SELECT * FROM weirvern.network_scopes;   -- read to find the monitored CIDRs (table has 6 rows)
```

---

## Appendix B — fold boundaries and reproduction

**Folds** (`FOLDS` in `scripts/cross_sectional_bakeoff.py`):

```
F1  2026-11-13 00:00 → 2026-11-16 00:00   test 2026-11-16 00:00 → 2026-11-17 00:00
F2  2026-11-14 00:00 → 2026-11-17 00:00   test 2026-11-17 00:00 → 2026-11-18 00:00
F3  2026-11-15 00:00 → 2026-11-18 00:00   test 2026-11-18 00:00 → 2026-11-19 00:00
F4  2026-11-16 00:00 → 2026-11-19 00:00   test 2026-11-19 00:00 → 2026-11-20 00:00
```

**Extraction**

```sh
export WEIRVERN_SENSOR_HOST=root@sensor.example
.venv/bin/python scripts/cross_sectional_bakeoff.py extract \
  --start "2026-11-12 00:00:00" --end "2026-11-20 00:00:00" \
  --scope 203.0.113.0/24 --scope 198.51.100.0/24 \
  --out /tmp/bakeoff.tsv.gz --sql-out /tmp/bakeoff.sql
# {"out": "/tmp/bakeoff.tsv.gz", "rows": 28531, "features": 19, ...}
```

**Runs**

```sh
# primary: 72h -> 24h, all windows, one threshold
.venv/bin/python scripts/cross_sectional_bakeoff.py run \
  --data /tmp/bakeoff.tsv.gz --out /tmp/bakeoff.json

# per-stratum calibration (the winner's configuration)
for lvl in 0.4211 0.8421 1.0; do
  .venv/bin/python scripts/cross_sectional_bakeoff.py run \
    --data /tmp/bakeoff.tsv.gz --out /tmp/bakeoff_stratum_$lvl.json --coverage-level $lvl
done

# complete-case sensitivity
.venv/bin/python scripts/cross_sectional_bakeoff.py run \
  --data /tmp/bakeoff.tsv.gz --out /tmp/bakeoff_cc.json --complete-case

# 24h -> 24h sensitivity (six folds)
.venv/bin/python scripts/cross_sectional_bakeoff.py run \
  --data /tmp/bakeoff.tsv.gz --out /tmp/bakeoff_24h.json \
  --fold-spec "S1,2026-11-13 00:00:00,2026-11-14 00:00:00,2026-11-14 00:00:00,2026-11-15 00:00:00" \
  --fold-spec "S2,2026-11-14 00:00:00,2026-11-15 00:00:00,2026-11-15 00:00:00,2026-11-16 00:00:00" \
  --fold-spec "S3,2026-11-15 00:00:00,2026-11-16 00:00:00,2026-11-16 00:00:00,2026-11-17 00:00:00" \
  --fold-spec "S4,2026-11-16 00:00:00,2026-11-17 00:00:00,2026-11-17 00:00:00,2026-11-18 00:00:00" \
  --fold-spec "S5,2026-11-17 00:00:00,2026-11-18 00:00:00,2026-11-18 00:00:00,2026-11-19 00:00:00" \
  --fold-spec "S6,2026-11-18 00:00:00,2026-11-19 00:00:00,2026-11-19 00:00:00,2026-11-20 00:00:00"
```

`run` prints the pooled table to stdout and writes every per-fold, per-candidate number to the
JSON: thresholds, saturation flags, FAR (all / clean / partial / full), degeneracy, coverage,
per-host alerts, persistence, correlations and timings.

**Environment:** CPython 3.11.15, numpy 2.4.6, scikit-learn 1.9.1, scipy 1.17.1.

---

## Appendix C — the in-sample trap

Threshold taken from the **fit half itself** (the naive reading of "0.01 on the training fold")
instead of from the held-out calibration slice, then measured on the next day:

| candidate | F1 | F2 | F3 | F4 |
|---|---|---|---|---|
| kNN-10 | 2.29% | 1.43% | 1.34% | 2.44% |
| LOF-20 | 0.78% | 1.85% | 2.05% | 0.39% |
| GMM-BIC | 2.39% | **15.48%** | 4.69% | 3.26% |
| EllipticEnvelope | 1.99% | 1.35% | 0.03% | 2.69% |
| IForest-19 | 0.64% | 0.17% | 0.21% | 0.53% |
| DBSCAN-shipped | 1.35% | 0.17% | 0.59% | 1.38% |

The in-sample threshold is not catastrophic for these models at this sample size, but it is
uniformly *worse* than the calibration-split threshold for kNN (2.29–2.44% vs 1.56–2.60%) and it
more than triples GMM's bad day (15.48%). The calibration slice costs 1,667 rows and is the
difference between a threshold that means something and one fitted to the data it is judging.
