# ML model candidates — research note, 2026-10-23

**Status:** research only. No new model is implemented, trained in production, or deployed. The
severity/independence changes from the preceding review are staged but not live.

## The constraint that decides the answer

The current models are **unsupervised novelty detectors on 5-minute host-window aggregates**:
Isolation Forest, a Gradient Boosting student, DBSCAN, and a per-host percentile baseline. The
live data already shows the failure mode that a new detector would amplify: 2,128 stored
detections in seven days, 276 labelled critical, and DBSCAN at 0.99 on 1,096 of them. Adding a
fifth uncalibrated score to `max` fusion would produce **more alerts**, not better ones.

So the useful question is not "which model is more powerful?" It is:

> Which model answers a question the current four cannot answer, and can its output be
> calibrated and explained well enough to change a decision?

That rules out most of the usual list before benchmarking.

## What was tested on the live feature matrix

To avoid judging models only from papers, I exported **5,000 rows of the live 8-feature DBSCAN
matrix** (the last 72 hours, sampled by the same hash ordering the trainer uses), median-imputed
and standardized it, and fit candidates in the project's own scikit-learn 1.9.1 environment.
This is a **structural** comparison (cluster count, noise fraction, score spread, runtime), not a
detection-quality benchmark: there are no ground-truth labels for these windows.

### HDBSCAN is not a drop-in DBSCAN upgrade

| HDBSCAN setting | clusters | noise fraction | runtime |
|---|---:|---:|---:|
| `min_cluster_size=5, min_samples=5` | 310 | 2.6% | 0.13 s |
| `min_cluster_size=20, min_samples=5` | 110 | 14.1% | 0.10 s |
| `min_cluster_size=40, min_samples=5` | 57 | 17.6% | 0.10 s |
| `min_cluster_size=80, min_samples=5` | 25 | 17.8% | 0.10 s |

The result is extremely parameter-sensitive: the same data yields **310 clusters with 2.6%
noise** or **25 clusters with 17.8% noise**. That is not a better DBSCAN; it is a different
definition of normal. The shipped DBSCAN produced 63 clusters on 5,000 rows. HDBSCAN's advantage
— clusters of varying density — is real, but it needs a fixed alert budget and seeded-attack
evaluation before it can replace anything. `sklearn.cluster.HDBSCAN` is available in the current
environment, so this is a **no-new-dependency challenger**, not an addition.

### LOF is unstable on this data

`LocalOutlierFactor` produced degenerate scores because the feature matrix contains duplicate
rows and zero-distance neighbours:

| LOF neighbours | flagged as noise | p99 score | max score |
|---:|---:|---:|---:|
| 10 | 14.0% | 9.3e8 | 1.7e10 |
| 20 | 19.5% | 5.8e8 | 2.1e10 |
| 100 | 19.8% | 66.6 | 7.8e9 |

The p99 moves by seven orders of magnitude with a neighbour-count change. A model whose score
is dominated by duplicate points is not a fifth opinion; it is another source of arbitrary
severity. **Do not add LOF** without a duplicate/zero-distance strategy and a fixed calibration.

## Candidates that answer a NEW question

### 1. Conformal / extreme-value calibration — highest value, not a detector

**Question:** "How often will this rule alert if I hold it to a fixed false-alarm budget?"

Conformal anomaly detection calibrates any score against a reference distribution and produces a
p-value with a finite-sample false-alarm guarantee. Extreme-value theory (POT/DSPOT) does the same
for the tail of a univariate stream without assuming a Gaussian distribution. Neither adds a
detector; both turn the existing scores into a **budgeted** decision.

Why it fits here: the current threshold is a global `BASE_THRESHOLD` (0.35), with adaptive
multipliers; the observed score distributions are saturated. A per-role/per-host conformal
calibration would let the operator say "at most N high/critical per day for this cohort" and
measure whether the system met it. The project's own `baseline-ml-design.md` already asks for
"budget-calibrated thresholds per cohort (target false alarms/day), conformal-style quantiles of
the historical score distribution."

**Recommendation: P0, before any new detector.** Implement as a calibration layer around the
current ensemble, not as another score.

### 2. Matrix Profile (STUMPY) — the one genuinely new detector worth adding

**Question:** "Is this window's *shape* unlike the motifs this host repeats?"

The current features are magnitudes and counts in one 5-minute window. They cannot see that a
host's 03:00 pattern is a compressed or reversed version of its usual pattern, or that a new
sawtooth appeared while every scalar stayed in range. The matrix profile is the standard
nearest-neighbour representation for exactly that: motifs (repeated shapes) and discords
(segments with no close neighbour). STUMPY provides `stump`, `mstump`, streaming, and
multi-dimensional variants.

Fit: one series per host per metric (bytes, packets, unique destinations, flows), on the existing
5-minute grid; 72 hours is 864 points per series. Run only for hosts with enough history, on a
sampled cadence, and store a **discord score + the matched window index** as evidence. This is
the best candidate for a **temporal specialist** that is independent of the tabular models.

Cost: new dependency, CPU/memory, and a second time scale. It should not enter `max` fusion until
its score is calibrated and tested against the seeded port-scan/exfil harness.

**Recommendation: P1, shadow mode first.**

### 3. Bayesian online change-point / Page-Hinkley — the "misconfigured" channel

**Question:** "Is this a new persistent regime, or a spike inside the old one?"

A new device, a moved service, a changed backup schedule, or a misconfiguration is a
**changepoint**, not a one-window outlier. BOCPD maintains a posterior over run length and gives
the probability that the most recent observation started a new regime; Page-Hinkley/CUSUM are
cheaper sequential tests for a sustained shift. The existing design already names
Page-Hinkley-style relearn per host-band; it is not implemented.

This is the most direct answer to the operator's "or even misconfigured traffic": a sustained
shift should produce a **drift/change notice**, not 300 repeated critical windows. It is also
cheap and explainable ("bytes changed regime at this window and stayed there").

**Recommendation: P1, context channel; do not feed it into the anomaly score.**

### 4. ECOD / COPOD — offline challenger to Isolation Forest

Both are parameter-free, computationally cheap, and interpretable via per-feature tail
probabilities. COPOD models the empirical copula; ECOD uses empirical cumulative distributions.
They are plausible replacements for, or challengers to, Isolation Forest on this tabular matrix,
especially because the current IF calibration is saturating.

But they are still **one more uncalibrated score**. The right use is an offline bake-off against
IF on the seeded attacks and benign periods, at a fixed budget; the winner replaces IF, not joins
it.

**Recommendation: P2, offline benchmark only.** Adds PyOD as a dependency.

### 5. HDBSCAN — replace DBSCAN only after a challenger trial

Already covered above: no new dependency, but parameter-sensitive. If it wins at the same alert
budget with stable clusters across retrains, it can replace DBSCAN. It should not be added
alongside DBSCAN — two density scores on the same features are not independent evidence.

## What NOT to add

- **Local Outlier Factor (LOF):** unstable on duplicate/zero-distance rows in the live matrix;
  its score moved by seven orders of magnitude with `n_neighbors`. DBSCAN/HDBSCAN already cover
  local density.
- **One-Class SVM / SVDD:** poor scaling and calibration on 5,000+ samples; no explanation beyond
  a distance; would add another opaque score.
- **Autoencoders, LSTM/GRU, Transformers:** the project has small n, no labels, and a hard
  explainability bar; the design note explicitly rules out deep models. They would also obscure
  which measurement drove an alert.
- **A second supervised classifier (XGBoost/LightGBM/Random Forest):** the only labels are 9
  review outcomes; a supervised model would learn the reviewer's current queue, not the network.
- **Graph neural networks / node embeddings:** interesting for peer relationships, but no
  labels, no stable graph, and the current graph is already an investigation surface. Defer.

## Recommended portfolio

1. **Calibration layer (P0):** conformal p-values per host/role plus a target alerts/day budget.
   This is the only change that directly fixes "too many alerts".
2. **Temporal specialist (P1):** Matrix Profile on local-host metric series, shadow mode,
   explainable discord evidence.
3. **Change channel (P1):** BOCPD/Page-Hinkley for sustained-regime notices, separate from
   incidents.
4. **Density challenger (P1):** HDBSCAN vs DBSCAN, same features, fixed-budget A/B; replace, do not
   add.
5. **Tabular challenger (P2):** ECOD/COPOD vs Isolation Forest, offline only.
6. **No LOF, no one-class SVM, no deep sequence models, no second supervised classifier.**

The current four detectors remain the production ensemble until a challenger beats them on the
seeded-attack harness **and** stays inside the alert budget on ordinary days.

## Evaluation protocol (before any production promotion)

- Use `scripts/eval_detection.py` (seeded port scan, exfiltration, benign hosts) plus the review
  outcomes and marked benign periods. Report detection at the **same alerts/day** for every
  candidate, not at its own best threshold.
- Measure: seeded-attack detection and latency, false positives on benign windows, alerts per
  host/day by role, score saturation, cluster stability across retrains, explanation coverage,
  runtime and artifact size.
- Run candidates in **shadow mode**: write their scores and evidence to a candidate table, never
  into `netflow_anomalies` or `alert_events`, until the comparison is reviewed.
- A candidate that wins only by alerting more is rejected by definition.

## Sources

- Campello, Moulavi & Sander, *Density-Based Clustering Based on Hierarchical Density Estimates*
  (HDBSCAN), 2013; scikit-learn HDBSCAN documentation:
  https://scikit-learn.org/stable/modules/generated/sklearn.cluster.HDBSCAN.html
- hdbscan documentation, GLOSH outlier detection:
  https://hdbscan.readthedocs.io/en/latest/outlier_detection.html
- Yeh et al., *Matrix Profile I: All Pairs Similarity Joins for Time Series*, ICDM 2016,
  DOI 10.1109/ICDM.2016.0179; STUMPY documentation: https://stumpy.readthedocs.io/en/stable/
- Adams & MacKay, *Bayesian Online Changepoint Detection*, arXiv:0710.3742:
  https://arxiv.org/abs/0710.3742
- Siffer, Fouque, Termier & Largouët, *Anomaly Detection in Streams with Extreme Value Theory*,
  KDD 2017: https://www.kdd.org/kdd2017/papers/view/anomaly-detection-in-streams-with-extreme-value-theory
- Laxhammar & Falkman, *Inductive Conformal Anomaly Detection for Sequential Detection of
  Anomalous Sub-Trajectories*, 2013:
  https://link.springer.com/article/10.1007/s10472-013-9381-7
- Li et al., *COPOD: Copula-Based Outlier Detection*, ICDM 2020; PyOD detector catalogue:
  https://pyod.readthedocs.io/en/latest/pyod.models.tabular.html
- Breunig et al., *LOF: Identifying Density-Based Local Outliers*, SIGMOD 2000.
- Lavin & Ahmad, *Evaluating Real-time Anomaly Detection Algorithms — the Numenta Anomaly
  Benchmark*, arXiv:1510.03336: https://arxiv.org/abs/1510.03336
- Project design: `references/baseline-ml-design.md` (multi-scale bands, shrinkage, novelty,
  role priors, budget-calibrated thresholds) and `scripts/eval_detection.py` (seeded attacks).
