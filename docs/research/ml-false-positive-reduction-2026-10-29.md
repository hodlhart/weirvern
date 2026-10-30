# Reducing Weirvern false positives — live measurements, research, and a solution set

**Date:** 2026-10-29
**Status:** research and design only. Nothing in this document is deployed. The live build is 0.23.14.
**Scope:** the ML alert-quality problem the operator reported as “still getting far too many false positives.”
**Evidence:** live ClickHouse reads from `weirvern.netflow_anomalies`, `alert_events`, `alert_reviews`, `ml_calibration`, `host_roles`, and `ml_models`; the repository at `956aea4`; and the external sources listed at the end.

---

## 1. Bottom line

The problem is **not** that the detectors need another model. The current production path still has three structural defects:

1. **Every 5-minute host-window is presented as a separate finding.** There is no incident/episode grouping and no per-host alert budget. A host that is statistically unusual all day produces hundreds of rows and one continuous “incident.”
2. **The ensemble still uses `max` fusion, and DBSCAN is saturated.** DBSCAN’s observed false-alarm fraction is **99.94%** against a **1%** target, yet it can still set the fused score. Lowering the global score threshold barely helps: **1,853 of 2,652** rows in 24 hours still score at least 0.95.
3. **The calibration work is shadow-only and measures the wrong population.** `ml_calibration.reference_source` says “stored anomaly scores (tail only), not all scored windows.” A budget cannot be enforced against a tail that was selected *because* it already passed the old bar.

The highest-value response is a **production budget + episode layer** around the existing detectors, followed by **detector eligibility** (quarantine saturated DBSCAN until it is calibrated), then **role-aware baselines** and **review feedback**. The research supports this ordering: alert correlation and calibrated, cost-sensitive triage reduce volume without changing the detector; adding another uncalibrated score increases it.[4][9][10] The base-rate and evaluation pitfalls are the reason the budget, not another detector, is the first change.[2][6]

Measured on the live 24-hour window:

- **2,652** stored anomaly rows across **21** hosts.
- **709 critical**, **56 high**, **1,276 medium**, **611 low**.
- **1,783 of 2,652 (67%)** have **one or fewer independent model families**.
- **2,664** `alert_events` decisions, **all `log-only`** — this is a dashboard/queue flood, not a Pushover storm.
- **959** near misses.
- The four busiest hosts each produced **281–288 rows** — essentially one detection every five minutes for the whole day.
- Grouping those rows into **host episodes with a 30-minute gap** collapses the 24 hours to **84 episodes**; the critical/high subset collapses from **761 rows to 79 episodes** (57 at a 60-minute gap). Grouping is not a model change; it is the missing unit of work.

---

## 2. What the operator is actually seeing

“False positive” in this system currently means at least two different things, and the console does not separate them:

- **A model lead:** a score above the current bar, with no material deviation, no structural signature and no novelty. This is a hunting lead, not an incident.
- **A real incident:** a measured deviation, a structural signature, or a new behavior that the operator can act on.

The research literature calls the first population “benign triggers” and treats the second as the thing an analyst queue should contain.[7] A survey of SOC alert screening finds that filtering, triage, correlation and contextualization are distinct downstream stages, and that operational validation is the persistent gap.[6] The current console collapses all four stages into one severity word.

NIST SP 800-94 already states the governing trade-off: false positives and false negatives cannot both be eliminated, and “tuning” is the maintenance activity that changes the balance for the environment.[1] The correct question is therefore not “how do we make the score higher?” but “what is the alert budget, and which evidence earns a place in it?”

---

## 3. Live baseline (measured, not inferred)

### 3.1 Volume and severity

Read at 2026-10-29 22:58 America/Chicago, rolling 24 hours:

| severity | rows | hosts | average score | rows with ≤1 family |
|---|---:|---:|---:|---:|
| critical | 709 | 18 | 0.990 | 79 |
| high | 56 | 10 | 0.981 | 0 |
| medium | 1,276 | 18 | 0.963 | 1,165 |
| low | 611 | 15 | 0.430 | 539 |

The critical count is dominated by two-family rows (472), with 158 three-family rows and 79 one-family rows. Many of the two-family rows are the gateway and the busy DMZ/service hosts; a two-family agreement is not automatically an incident when both families are broad-volume models.

### 3.2 Every five minutes, for the whole day

The busiest hosts:

| host | rows/24h | critical | medium | average score | ≤1 family |
|---|---:|---:|---:|---:|---:|
| 198.51.100.58 | 288 | 208 | 72 | 0.99 | 106 |
| 203.0.113.1 | 287 | 222 | 65 | 0.99 | 65 |
| 203.0.113.153 | 283 | 10 | 273 | 0.99 | 273 |
| 198.51.100.1 | 281 | 53 | 186 | 0.90 | 229 |
| 198.51.100.123 | 228 | 5 | 40 | 0.51 | 217 |

A host with 288 rows has a detection in **every 5-minute bucket of the day**. The operator experiences that as a continuous false alarm; the data model experiences it as 288 independent findings. It is one episode.

### 3.3 Thresholds cannot fix a saturated score

Rolling 7 days: **9,321** rows; 6,580 at ≥0.8, 6,359 at ≥0.9, 3,106 with ≥2 families at ≥0.8. In the 24-hour window:

- score ≥ 0.50: **2,169** rows
- score ≥ 0.70: **1,976**
- score ≥ 0.80: **1,913**
- score ≥ 0.90: **1,853**
- score ≥ 0.95: **1,853**

Raising the global floor from 0.50 to 0.95 removes only **316 rows (12%)**. The score distribution is piled against the ceiling; a threshold is not a budget.

### 3.4 DBSCAN is over its budget by two orders of magnitude

Latest `ml_calibration` rows:

| model | target FAR | observed FAR | threshold | samples |
|---|---:|---:|---:|---:|
| DBSCAN | 1% | **99.94%** | 0.9994 | 4,657 |
| Adaptive Baseline | 1% | **7.17%** | 0.9900 | 3,401 |
| Gradient Boosting | 1% | **1.19%** | 0.9892 | 2,777 |
| Isolation Forest | 1% | **1.18%** | 0.8546 | 4,159 |

The DBSCAN score is `calibrate_distance(distance_to_nearest_centroid)` against percentiles of the **training** distances. That calibration is structurally optimistic: 5,000 training rows, 79 clusters and 41 outliers, then the live stream sits far outside the training manifold. The detector says “0.99” on nearly everything; `max` fusion selects it. The other models are not clean either, but DBSCAN is the dominant saturated vote.

The calibration is also **not measuring the right population**. It reads `netflow_anomalies` — the already-selected tail — rather than every scored host-window. A split-conformal threshold on the selected tail is not the false-alarm rate of the detector; it is the false-alarm rate of the old alert rule, re-labelled. The source string in the table is honest about this, which is why the result should not be wired into production as-is.

### 3.5 The feedback loop is inert

`alert_reviews`: **34 blank**, **5 false_positive**, **4 ack**. Only nine reviewed outcomes against thousands of rows. The review UI records the label but no threshold, calibration or training path reads it. The review workload is itself evidence that the queue is too broad.

### 3.6 Roles are present but not used for scoring

`host_roles` contains 106 `unknown`, 86 `workstation`, 15 `media` and 3 `server` monitored hosts. The busiest four hosts are all `unknown`. A gateway, a media server and a workstation do not have the same normal shape; the role table exists but is not yet part of the production threshold or feature path. This is exactly the “role prior” gap in the design note.

---

## 4. Root causes, ranked

### P0-1 — No incident unit and no budget

`netflow_anomalies` is keyed `(window_start, src_addr)` and the UI lists rows. There is no `alert_episodes` table, no grouping key, no `alerts/day` target, and no per-host cap that changes presentation. Every five-minute window is a row by construction.

### P0-2 — Max fusion over a saturated density score

`ensemble.fuse_scores()` uses `max` by default; `DBSCAN` is 99.94% over its target and contributes `0.99` to most rows. The agreement gate cannot help when one saturated model plus a broad baseline produces two “families.” The severity contract improved the *language* but did not make the density score honest.

### P0-3 — Calibration is shadow-only and tail-only

`models/calibration.py` computes split-conformal thresholds and observed FAR, but the worker writes them to `ml_calibration`; no production threshold reads the result. The reference set is stored detections only, so the observed FAR is conditional on the old gate.

### P1-1 — Role and seasonality are absent from production scoring

The baseline detector is per-host, but there is no day/week band, no shrinkage to a role/cohort, and no role-aware threshold. A gateway’s broad normal range and a workstation’s narrow normal range are scored with the same global settings. The research note’s proposed “minute/day/week bands + shrinkage + novelty” remains a design, not a shipped path.

### P1-2 — Review labels do not feed anything

The five false-positive labels are durable facts; they do not affect a host threshold, a calibration reference or a review sampling policy. The literature on alert fatigue and triage treats analyst outcomes as the signal for prioritization; here they are write-only.[6][7][10]

### P1-3 — Evaluation is not at a fixed alert budget

The current metrics are score distributions and counts, not precision at a fixed alerts/day, false alarms per host/day, or detection latency on the seeded harness. Without that, every proposed model can look better by alerting more.

---

## 5. What the research says

The sources below are external; the live numbers above are this system’s own evidence.

- **NIST SP 800-94** treats anomaly detection as profile-based and states that false positives and false negatives trade off; “tuning” is the operational discipline that adjusts profiles and thresholds to the environment.[1] The implication is not “raise the threshold”; it is “maintain a profile and a budget per entity.”
- **Arp et al., “Dos and Don’ts of Machine Learning in Computer Security,”** identifies ten recurring pitfalls, including sampling bias, label inaccuracy, inappropriate baselines, inappropriate measures and the **base-rate fallacy**.[2] The relevant failures here are evaluating only the selected alert tail, using score thresholds as if they were precision, and treating correlated detectors as independent evidence.
- **BARS** shows that **benign-anchored** feature selection — with the benign class as the reference rather than a shifting global mean — reduces false positives by **15–32%** while preserving detection on class-imbalanced NIDS data.[3] The transferable lesson is to anchor “normal” to the benign population (and to the host/role), not to a global score mean.
- **MAAC** correlates alerts by attack stage and semantics, reducing alert volume by **90%** and reconstructing multi-step paths.[4] It supports **grouping and correlation as a first-class product**, not as a display filter.
- **Conformal prediction** gives finite-sample validity under an **exchangeability** assumption; streaming and time-series data violate that assumption, which is exactly why a naive split-conformal threshold on a rolling network stream needs per-window recalibration or weighted/adaptive conformal, not a one-time global fit.[5]
- The **alert-screening survey** (119 records, 87 core studies) separates filtering, triage, correlation and contextualization, and names operational validation, robustness and evaluation practice as the persistent gaps.[6] It supports a staged pipeline instead of one severity label.
- The **benign-user activity expert survey** reports that up to **99%** of alerts can be triggered by benign user behavior, and that normal behavior varies significantly between organizations.[7] A threshold alone cannot encode this; the system needs environment context and role-aware normal models.
- **Explainability research** finds SOC analysts accept lower predictive accuracy when explanations are relevant, evidence-backed and role-aware; contextual depth beats a dashboard score.[8] The “why” is not decoration; it is how an analyst decides to dismiss a lead.
- **Splunk risk-based alerting** groups events into risk objects and only creates a notable when a risk threshold or ATT&CK pattern is met; it reports reduced alert volume and higher fidelity.[9] It is an industry confirmation of the risk/budget/incident pattern, not a reason to copy a vendor.
- **Decision-aware triage** research explicitly combines calibrated confidence, uncertainty cues and **cost-sensitive thresholds** because false alarms and missed attacks have asymmetric costs.[10] The current single global threshold has no cost model and no per-role budget.

What the research does **not** support: adding an autoencoder/LSTM, a second supervised classifier trained on the five review labels, LOF on this duplicate-heavy matrix, or another uncalibrated density score. Those either fail the small-n/explainability contract or make the calibration problem worse.

---

## 6. Recommended solution set

### P0 — Ship a production alert budget and episode layer

**What:** a first-class **incident** (episode) object, not a new detector.

- Add `alert_episodes` (or a materialized/derived episode view): `episode_id`, `src_addr`, `started_at`, `ended_at`, `primary_feature`, `max_severity`, `max_score`, `families`, `occurrence_count`, `review_state`. A new episode starts when no qualifying window for that host has appeared in the last **30 minutes**; a qualifying window extends the open episode.
- Add a **per-host/role budget** (config, e.g. `ALERT_BUDGET_CRITICAL_PER_DAY`, `ALERT_BUDGET_HIGH_PER_DAY`, initially 1–2 per host/day; the operator sets the number). The budget is the contract; it is not a score threshold.
- The pageable alert path and the default Anomalies view consume **episodes**, not raw windows. Raw windows remain stored and reachable as evidence; nothing is deleted.
- Medium/low rows are **observations** by default. A one-family row is a lead; it can be reviewed but cannot page.
- Measure before/after on the same window: rows, episodes, critical/high episodes, alerts sent, and seeded-attack detection/latency.

**Why this is first:** it attacks the 2,652-row → 84-episode gap directly, it is reversible, and it does not require a model change. MAAC’s 90% reduction and Splunk’s risk-notable model both support this shape.[4][9]

**Acceptance:** a 24-hour replay shows the episode count and the pageable count; a seeded port scan/exfil still appears as an episode with the same detection latency; no raw evidence is deleted; the UI names “incident” and “occurrence” separately.

### P0 — Quarantine saturated detectors and enforce model eligibility

**What:** a **model eligibility gate** driven by calibration, not by hope.

- Compute calibration on **every scored host-window**, not only rows that already passed. Persist the score distribution (or a bounded reservoir) per model and per host/role.
- A detector whose `observed_far` exceeds a multiple of its target (e.g. **3×**) is **ineligible to set the fused score** until it passes a holdout window. DBSCAN is immediately ineligible at 99.94%; Adaptive Baseline at 7.17% is also over budget.
- While ineligible, the detector may still write **shadow evidence** and contribute to the explanation, but it cannot make a one-family window pageable. A direct structural signature (port scan) remains a valid independent exception.
- Recalibrate DBSCAN against the **live holdout**, not the training percentile; if the live distance distribution still separates benign/attack poorly, keep it shadow-only and run the HDBSCAN/ECOD challenger A/B rather than promoting it.
- The calibration report must show **target vs observed** and **eligibility** in words on Models; no score may be labelled “probability.”

**Acceptance:** DBSCAN’s observed FAR is no longer 99.94% in production; a 24-hour replay shows the fused-score distribution without DBSCAN; the seeded scan still alerts through the signature exception; no detector is silently re-enabled after a retrain.

### P0 — Make calibration a production decision layer

**What:** use the existing conformal code as the budget mechanism.

- Build a **calibration set from all scored windows over a trailing window**, split by time (fit/validate), per **host / role / global** with shrinkage when samples are thin.
- Convert each detector score to a **conformal p-value**; combine independent families with a calibrated rule (e.g. Fisher/Stouffer or a learned cost-sensitive layer), not `max`. Use a **fixed alert budget** to choose the p-value cutoff; report the achieved alerts/day.
- Use **time-decayed/weighted conformal** or periodic recalibration because exchangeability is violated on a non-stationary network.[5]
- Keep a **shadow** threshold and a **production** threshold side by side for one release; do not flip both at once.

**Acceptance:** on a held-out day, the observed high/critical episode rate is within the configured budget ± a stated tolerance; the detection rate and latency on the seeded harness do not regress; the calibration table names the reference population and its age.

### P1 — Role-aware, seasonal baselines

**What:** finish the design note’s bands, not a new detector.

- Add **minute/day/week** bands with decayed statistics; compare a window to the same hour/day where possible; use **MAD/robust z**, not standard deviation.
- Use **shrinkage** to a segment/role/cohort baseline (`n/(n+k)`), with the chosen rung visible in the why: “mostly cohort-informed (12 samples).”
- Use `host_roles` in the threshold path: gateway, media, server, workstation, unknown. Unknown is not a workstation; ask the operator to classify the top hosts. Do not whitelist infrastructure.
- Keep external peers out of the per-host alert entity; the peer layer already exists and must remain a dimension.

**Acceptance:** the gateway/media hosts’ episode rate falls without hiding the seeded gateway attack; the role and shrinkage rung are visible in the API/UI; unknown-role hosts are named as a configuration gap.

### P1 — Turn review verdicts into a feedback loop

**What:** labels change the budget, not the training set’s definition of normal.

- A `false_positive` review adjusts the **host/role budget or threshold** (with a recorded reason and an expiry), and samples the host for a later check. It must **not** be fed back as a normal training row; baseline poisoning is a real attack path.
- Add an **active-learning review queue**: show the highest-uncertainty windows (near the budget boundary, conflicting families, thin windows), not every row. Review outcomes are labels for calibration and evaluation, not ground truth for supervised training.
- Record the label, reviewer, time, feature and model version; join to the calibration reference.

**Acceptance:** after N reviews, the false-positive rate per host/role changes in the intended direction; no reviewed false positive becomes a normal training example; the queue’s review volume is bounded.

### P1 — Evaluation at a fixed alert budget

**What:** a promotion gate for every future method.

- Score **all** host-windows, not only the alert tail; hold out whole days, not random windows.
- Report: alerts/day, **precision@k**, false alarms per host/day by role, detection rate and latency on seeded attacks, explanation coverage, runtime, score saturation.
- Use the seeded harness (`scripts/eval_detection.py`) plus benign periods and review labels.
- A candidate that “wins” by alerting more is rejected by definition; compare at the same alerts/day.

**Acceptance:** a written report with the same-window before/after table; a candidate is eligible only if it meets the budget and does not regress seeded detection.

### P2 — Candidate methods, in order

1. **Matrix Profile / change channels:** already shadow; keep them as **notices** and evidence, not incident scores until they win at a fixed budget.
2. **HDBSCAN vs DBSCAN:** replace only after A/B; do not add a second density vote. See the 2026-10-30 assessment below.
3. **ECOD/COPOD:** offline challenger only.
4. **Benign-anchored feature selection (BARS-style):** use it to test whether the current feature set is dominated by class-symmetric volume features; do not add a dependency until the fixed-budget harness exists.[3]
5. **No** LOF, one-class SVM, autoencoders/LSTMs, or a second supervised classifier trained on five labels.

#### HDBSCAN swap assessment (2026-10-30)

HDBSCAN is the right *direction* for variable density, but it is **not a drop-in replacement** and the existing shadow challenger does not yet prove it reduces false positives.

- The live 5,000-row matrix gives **310 clusters / 2.6% noise** at `min_cluster_size=5`, versus **25 clusters / 17.8% noise** at `min_cluster_size=80` (the documented runs). That is a different definition of normal, not a better DBSCAN.
- The challenger's score is a **percentile rank of distance to the nearest medoid**, not a calibrated outlier probability. In the latest 5,000-row run its top 1% is exactly **50 rows**, with a score cutoff of 0.99 by construction; a 1% budget is therefore guaranteed without measuring a false-alarm rate.
- Of those top-50 HDBSCAN rows, **39 were already production alerts**, **35 had a production DBSCAN score of 0.99**, and **29 had one or fewer independent families**. One busy host accounted for 22 of the 50. This is mostly a **re-ranking of the existing queue**, not a clean new signal.
- The 11 top-50 rows that were not production alerts are the interesting part: they may be misses or new leads, but without labels they cannot be called improvements.

**Decision:** do not swap the live detector. First make DBSCAN ineligible to set the fused score (ML-12), then run the fixed-budget A/B (ML-15): HDBSCAN vs DBSCAN on all scored windows, seeded attacks, precision@1%, recall and cluster stability. If HDBSCAN wins, replace DBSCAN in one release and remove DBSCAN from the ensemble; never run both as independent votes. If it loses, keep DBSCAN shadow-only or recalibrate it.

Sources for this assessment: [scikit-learn HDBSCAN](https://scikit-learn.org/stable/modules/generated/sklearn.cluster.HDBSCAN.html), [HDBSCAN GLOSH outlier detection](https://hdbscan.readthedocs.io/en/latest/outlier_detection.html), and the live `ml_candidate_scores` / `netflow_anomalies` reads above.

A direct GLOSH run on 2026-10-30 is recorded in `docs/research/hdbscan-glosh-evaluation-2026-10-30.md`: GLOSH is undefined for 24.5% of the monitored sample, is parameter-sensitive (30/50 to 45/50 top-1% recovery across `min_cluster_size`), and on the current all-address challenger matrix its top 1% is 49/50 external or non-monitored addresses. Fix the scope filter before any HDBSCAN A/B.

The follow-up full 19-feature and seeded A/B is in
`docs/research/hdbscan-glosh-full-evaluation-2026-10-30.md`.



---

## 7. Expected effect, with the caveat

The live 24-hour window:

- Raw rows: **2,652**
- Host episodes at a 30-minute gap: **≈84**
- Critical/high rows: **761**
- Critical/high episodes at 30 minutes: **≈79**; at 60 minutes: **≈57**

That is a **~30× reduction in the unit of work** before any model change. It does **not** prove the remaining episodes are true positives; only the operator’s reviews and the seeded harness can answer that. It also does not make DBSCAN correct. The budget/eligibility layer is what stops a saturated score from turning into a page.

A realistic target for this home network is **a small number of pageable incidents per day** (the operator should set the number; the design should not invent it). A target of “all critical rows” is not a budget and will reproduce the current queue.

---

## 8. Kanban program

The work is carded on `weirvern-ml`; no implementation card is ready to dispatch until the operator opens it.

- **ML-10 — False-positive reduction research and decision record** (this document; done).
- **ML-11 — Production alert budget and episode layer** (P0; blocked).
- **ML-12 — Detector eligibility and DBSCAN quarantine** (P0; blocked).
- **ML-13 — Role-aware, seasonal baselines** (P1; blocked).
- **ML-14 — Review feedback and active-labelling loop** (P1; blocked).
- **ML-15 — Fixed-budget evaluation and promotion harness** (P0; blocked).

Dependency order: ML-15 first (measurement), then ML-12 (eligibility), ML-11 (episode/budget), ML-13 (roles), ML-14 (feedback). ML-15 can start immediately after approval because it changes no production alert path.

---

## 9. What not to do

- **Do not lower or raise `BASE_THRESHOLD` and call it a fix.** 1,853 of 2,652 rows still score ≥0.95; the distribution is saturated.
- **Do not count Isolation Forest and Gradient Boosting as two independent families.** GB is trained on IF’s labels; that is one observation stated twice, and the code already says so.
- **Do not feed false-positive reviews back as normal training rows.** Use them as labels for calibration/evaluation; baseline poisoning is an attack path.
- **Do not delete or hide raw rows.** Group them into episodes and keep the evidence reachable.
- **Do not add another uncalibrated detector.** The research and the live data agree: the bottleneck is evaluation and budget, not detector count.[2][6]

---

## 10. Reproduction / audit queries

All times are ClickHouse `America/Chicago`, the box’s naive local clock.

```sql
-- Volume and severity, rolling 24h
SELECT severity, count(), uniqExact(src_addr), round(avg(anomaly_score), 3),
       countIf(strong_families <= 1)
FROM weirvern.netflow_anomalies
WHERE window_start >= now() - INTERVAL 24 HOUR
GROUP BY severity ORDER BY count() DESC;

-- Score-threshold sensitivity (the point: raising the bar barely helps)
SELECT countIf(anomaly_score >= 0.5), countIf(anomaly_score >= 0.8),
       countIf(anomaly_score >= 0.95)
FROM weirvern.netflow_anomalies
WHERE window_start >= now() - INTERVAL 24 HOUR;

-- Calibration: target vs observed
SELECT model_name, target_far, observed_far, threshold, validation_count,
       reference_source, computed_at
FROM weirvern.ml_calibration
WHERE computed_at = (SELECT max(computed_at) FROM weirvern.ml_calibration)
ORDER BY observed_far DESC;

-- Review labels
SELECT state, count() FROM weirvern.alert_reviews FINAL GROUP BY state;
```

Episode grouping is a 30-minute gap per `src_addr` over ordered `window_start`; a SQL implementation can use `runningDifference`/window functions or a small Python replay. Whichever is used, the test must prove one continuous 5-minute series becomes one episode and two separated series become two.

---

## Sources

Rendered from the citation ledger:

## Sources

[1] https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-94.pdf — NIST SP 800-94 Guide to IDPS
[2] https://www.usenix.org/system/files/sec22summer_arp.pdf — Arp et al., Dos and Don'ts of Machine Learning in Computer Security
[3] https://arxiv.org/abs/2607.13203 — BARS: Benign-Anchored Ranking and Selection
[4] https://arxiv.org/abs/2011.07793 — MAAC: Novel Alert Correlation Method
[5] https://arxiv.org/abs/2410.06494 — Conformal Prediction: A Data Perspective
[6] https://arxiv.org/abs/2605.08316 — AI-Driven Security Alert Screening and Alert Fatigue Mitigation in SOCs: A Survey
[7] https://www.skopik.at/ait/2025_ares4.pdf — Benign User Activities that Trigger False Positives in IDS: An Expert Survey
[8] https://arxiv.org/abs/2503.02065 — Too Much to Trust? Explainability in AI-Driven SOCs
[9] https://lantern.splunk.com/Security_Use_Cases/Threat_Investigation/Implementing_risk-based_alerting — Splunk Lantern: Implementing risk-based alerting
[10] https://arxiv.org/abs/2601.04486 — Decision-Aware Trust Signal Alignment for SOC Alert Triage
