# ML alert review — 2026-10-23

**Status:** research and review. The severity changes described in "Proposed contract" are staged in
`weirvern/ensemble.py`, `weirvern/explain.py` and `weirvern/worker.py`; they are not deployed and
the historical rows have not been rewritten. The current live build is 0.19.27.

## The question

The operator's report is not "the models are inaccurate" in the abstract. It is:

> I have lots of alerts, but the focus is on finding bad or malicious or even misconfigured
> traffic. This makes it look like my home network has lots of bad traffic.

So the review separates three questions that the console currently answers with one word,
*anomaly*:

1. **Is this unusual for this host?** (the model score)
2. **How much evidence supports it?** (a measured deviation, a structural signature, or novelty)
3. **Does it matter for this host's role?** (gateway / media service / workstation / external peer)

The live data says the first answer is often yes while the second and third are missing, and the
severity label reports the first as if it were all three.

## What was measured

Seven days of `weirvern.netflow_anomalies`, read from the live cluster on 2026-10-23. The window
covers 2,128 stored detections.

### Severity volume

| severity | rows | median score | max score |
|---|---:|---:|---:|
| critical | 276 | 0.99 | 0.99 |
| high | 100 | 0.891 | 0.891 |
| medium | 338 | 0.792 | 0.99 |
| low | 1,149 | 0.356 | 0.678 |

This is not an alert-notification flood: `alert_events` contains 1,863 decisions and **all of them
are `log-only`** (0 sent) — Pushover is off. It is a **dashboard** flood, and the critical count is
what makes the network look compromised.

### Severity is not evidence

- **163 of 276 critical rows** carried a measured `deviation_magnitude` below **1 sigma**.
- **113 of 276 critical rows** had **no named primary deviation at all**.
- Across critical + high, **266 of 376** had less than **2 sigma** of measured deviation and
  **184** had no named deviation.
- The gateway supplied **322 high/critical rows**; many are a 4.4 KB vs 3.4 KB byte window
  (1.3x, about 2 sigma) or a 3-vs-2 destination count. The model calls that `critical` because a
  score crossed 0.95, not because the measurement is large.

`critical` is therefore not a claim about magnitude, intent, or danger. It is a claim about a
model score. That is the mismatch the operator is seeing.

### The score distributions are saturated, not incident-shaped

| detector | rows at its top bucket | share of the 2,128 stored detections |
|---|---:|---:|
| DBSCAN | 1,096 at 0.99 | 51.5% |
| Gradient Boosting | 859 at 1.0 | 40.4% |
| Isolation Forest | 352 at 0.9+ | 16.5% |

A detector that scores half of its stored detections at 0.99 is not saying "half of this network
is malicious"; it is saying its calibration and the live distribution no longer describe the same
population. The rows are already the top tail, so this is conditional on detection -- but a
healthy calibration should not put half of that tail at the maximum. The model view shows this as
a score distribution; the severity tiers then turn the top of that distribution into incident
language.

The live artifacts are healthy in the literal sense — Isolation Forest trained on 80,000 rows,
Gradient Boosting on 40,000, DBSCAN on 5,000 with 63 clusters — so this is a **calibration and
entity-scope** problem, not a "training did not run" problem.

### The ensemble double-counts one observation

`Gradient Boosting` is not an independent detector. `GradientBoostingDetector.train()` labels its
training rows with `teacher.predict(Xs)` from the Isolation Forest; it is a semi-supervised
student of the forest. The severity gate nevertheless counts both scores as independent
corroboration:

- 240 high/critical rows carry `Isolation Forest, Gradient Boosting, DBSCAN`.
- 134 carry all four detector names.
- 13 are `Isolation Forest + Gradient Boosting` only, with no DBSCAN or baseline strong signal.

Counting the teacher and its student as two witnesses inflates the exact gate that is supposed to
prevent a single model's opinion from becoming an incident.

### Entity scope is too wide

- **863 of 2,128** detections have a **non-private source address** — a remote peer appearing as
  the "host" being scored. They are 40% of the table and only 4 are high/critical.
- External peers have **no baseline**; `explain()` correctly says `no baseline for this host`.
  A row with no baseline cannot support a 3-sigma claim, yet it can still be labelled critical by
  the score/agreement path.
- The local high/critical rows are concentrated in service hosts: the gateway, the Overseerr
  host (~20 high/critical), and the Umbrel host (~18). These are exactly the hosts whose normal
  behavior is broad and whose per-host baseline is least stationary.

The design note in `references/baseline-ml-design.md` already names the missing layer: **entity
layer — host -> segments -> cohorts -> role**, plus **role priors** so an infrastructure
chokepoint is not treated like a workstation. The shipped detector still scores every source
address as an entity.

### The feedback loop is barely used

`alert_reviews` holds 5 `false_positive`, 4 `ack`, and 34 empty states. The system has a feedback
column but not yet a threshold that learns from it. That is 9 reviewed outcomes against 2,128
detections; the review workload itself is evidence that the queue is too broad.

## Research basis

- **Axelsson (1999), "The Base-Rate Fallacy and the Difficulty of Intrusion Detection."** For a
  realistic base rate, the false-alarm rate is the limiting factor; reaching a substantial
  Bayesian detection rate requires false-alarm rates on the order of **1 in 100,000**. The paper's
  lesson is not "detect less" — it is that **a detector's positive rate is not its precision**,
  and an interface that presents every positive as an incident trains the operator to ignore the
  one that matters.
- **scikit-learn `IsolationForest` documentation.** `contamination` is "the amount of
  contamination of the data set, i.e. the proportion of outliers"; it sets the threshold at fit
  time. The shipped value is `0.06`, so the training distribution deliberately contains 6%
  "outliers". That is a model-design choice, not an incident rate, and the console must not
  translate the top of that distribution into `critical` without an independent measurement.
- **Kuncheva & Whitaker (2003), "Measures of Diversity in Classifier Ensembles."** Diversity among
  ensemble members is the reason combination helps; correlated members do not add independent
  evidence. A student model trained on its teacher's labels is the limiting case: high agreement
  is expected and carries little corroboration.
- **Praetorian, "Alert Fatigue and False Positives" (industry summary).** The average SOC sees
  about 960 alerts/day with 50–80% false positives; the recommended response is **tiered
  alerting** (validated threat / suspicious / informational) and **environmental context**
  (asset role, criticality, history), not one severity vocabulary for every detection.
- **This repository's own `references/baseline-ml-design.md`.** It already specifies the correct
  target: MAD-based robust z-scores, shrinkage toward a cohort, a first-class **novelty** channel,
  **role priors**, **budget-calibrated thresholds at a fixed false-alarm rate**, and review
  verdicts as durable labels. The current severity path implements none of those three gates.

## What is wrong, stated as contracts

1. **Severity contract (P0).** A `critical`/`high` label must require **both** independent
   corroboration and material evidence. "Material" means a measured deviation at the critical/high
   threshold, a direct structural signature (the port-scan case), or a novelty observation (a TLS
   fingerprint the host has never used). A high score with none of those is a **lead**, not an
   incident.
2. **Independence contract (P0).** Isolation Forest and its Gradient Boosting student are one
   family. Severity counts independent families, not detector names. DBSCAN and Adaptive Baseline
   remain separate.
3. **Entity contract (P1).** Only a monitored endpoint may be an alert entity. A remote peer is a
   dimension of a local host's behavior; it may appear in evidence, but "the internet address
   itself is an anomalous host" is not a finding.
4. **Role contract (P1).** Gateway, media service, workstation and external peer have different
   normal shapes. Role-aware thresholds and features are required before the same cardinality
   change is treated as equally suspicious on all of them.
5. **Budget contract (P1).** Alerts are budgeted per host/cohort at a target false-alarm rate, with
   episode deduplication; review verdicts adjust the host-band threshold. A 2,128-row week is not a
   budget.

## Proposed first change (staged, not deployed)

The smallest change that makes the current console truthful:

- Add **`strong_model_families()`**: `Isolation Forest` and `Gradient Boosting` share the
  `forest` family; `DBSCAN` = `density`; `Adaptive Baseline` = `baseline`.
- Extend `severity_of()` with optional `strong_families`, `deviation_magnitude` and `novelty`.
  When evidence is supplied:
  - critical requires score ≥0.95, ≥2 independent families, and (≥3σ **or** signature **or**
    novelty);
  - high requires score ≥0.85, ≥2 independent families, and (≥2σ **or** signature **or** novelty);
  - otherwise the row is capped at **medium**.
- Re-evaluate severity in `worker.detection_sweep()` after `explain()` has the host's baseline,
  because the ensemble does not have the measured deviation.
- Keep the raw `strong_models` count in the row/console, and add `strong_families` beside it.

**Simulated on the stored seven days** (using the same columns, before any deployment):
critical **276 → 49**, high **100 → 6**. The remaining rows are not deleted or hidden; they become
medium/low. The 49 critical rows still include 29 from the gateway, which is a role/entity problem
for the P1 work, not something a severity gate should hide.

## What this does not claim

- It does not turn Weirvern into a malware or misconfiguration classifier. It remains a passive
  **novelty/volume anomaly** detector; "anomaly" is not "malicious".
- It does not prove the 49 remaining critical rows are true positives. There is no ground-truth
  label set; the review did not create one.
- It does not fix the saturated DBSCAN/Gradient Boosting calibration. The severity gate makes the
  output honest while the calibration work is designed; it does not make the detectors better.
- It does not rewrite historical `netflow_anomalies` rows. A backfill is needed before the
  dashboard's old critical count matches the new contract.
- It does not implement role priors, cohort budgets, or remote-peer entity separation. Those are
  the P1 items.

## Recommended order

1. **P0:** ship the severity/independence contract; backfill the seven-day window with an explicit
   before/after count and a reason.
2. **P0:** add a model-view line that separates *score distribution* from *severity distribution*,
   so "0.99" is never read as "99% malicious".
3. **P1:** entity scope and role priors (gateway/media service first); use the existing DHCP /
   identity store and `INTERFACE_NETWORKS` as the evidence, not a denylist.
4. **P1:** calibrate DBSCAN/Gradient Boosting against the scoring distribution (or explicitly
   present their scores as uncalibrated until then).
5. **P2:** budget-calibrated thresholds and review feedback; measure alerts per host/day and
   false-positive rate by role.

## References

- S. Axelsson, *The Base-Rate Fallacy and the Difficulty of Intrusion Detection*, 1999.
  https://users.ece.cmu.edu/~dbrumley/courses/18487-f15/reading/Axelsson_1999_The%20base-rate%20fallacy%20and%20its%20implications%20for%20the%20difficulty%20of%20intrusion%20detection.pdf
- scikit-learn, *IsolationForest* (contamination parameter).
  https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html
- L. I. Kuncheva and C. J. Whitaker, *Measures of Diversity in Classifier Ensembles and Their
  Relationship with the Ensemble Accuracy*, Machine Learning 51, 2003.
  https://link.springer.com/article/10.1023/A:1022859003006
- Praetorian, *Alert Fatigue and False Positives: Why More Alerts Mean Less Security*.
  https://www.praetorian.com/security-101/alert-fatigue-and-false-positives/
- `references/baseline-ml-design.md` in the `weirvern` skill: multi-scale baselines, shrinkage,
  novelty, role priors, budget-calibrated thresholds, feedback.
- `references/model-lifecycle.md`: contamination counting, student/teacher coupling, and why a
  trained artifact is not automatically a usable model.
