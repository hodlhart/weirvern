# Weirvern ML — full research and review

**Date:** 2026-11-02
**Build:** 0.23.17 (deployed and verified on `weirvern.home`)
**Scope:** production detection path, live ClickHouse evidence, calibration, episodes, alert budget, feedback and candidate models.
**Status:** research and live audit only. No code or model change is implied by this document.

---

## 1. Bottom line

The detectors are no longer the main problem. The last 24 hours contain **~960 stored anomaly rows, of which 959 are low/medium and only 2 are high/critical**. The ML models behind those rows are mostly calibrated close to the 1% target: Isolation Forest 1.0%, Gradient Boosting 1.18%, Adaptive Baseline 1.12%. DBSCAN is correctly ineligible at 97.46%.

What is still broken is the layer above the models:

1. **The episode table is duplicating itself.** The live table has **2,487 rows for 19 hosts** in 24 hours. Replaying the same anomaly rows through the shipped code produces **68 episodes** — a 36x inflation. One host has **237 rows** for one continuous incident. `paged_at` is null on every row, and the page budget is therefore not doing what the dashboard implies.
2. **The raw anomaly queue is still being presented as the daily workload.** 959 of 960 rows are low/medium; 296 have no named primary deviation and 683 have zero independent strong families. Those are leads, not incidents.
3. **Calibration is measured on the right population now, but split the wrong way.** `calibration.fit` uses even/odd row halves, not time-ordered halves. The stream is non-stationary; exchangeability is the wrong assumption, and the AB eligibility check races its five-minute retrain.

The right order is: **fix episode identity and the page path first; separate leads from incidents second; then improve calibration and role baselines.** Adding another detector is not supported by this review.

---

## 2. Live evidence

All times are ClickHouse `America/Chicago`; read at 2026-11-01 21:22–21:25.

### 2.1 What is actually firing

Rolling 24 hours:

| severity | rows | hosts | average score | average strong families |
|---|---:|---:|---:|---:|
| critical | 1 | 1 | 0.960 | 1.00 |
| high | 1 | 1 | 0.945 | 1.00 |
| medium | 577 | 16 | 0.853 | 0.51 |
| low | 415 | 16 | 0.553 | 0.00 |

The current queue is therefore **959 low/medium versus 2 high/critical** — the alert-volume problem is now a presentation and evidence problem, not a “too many criticals” problem. The seven-day table still contains the older storm (15,264 rows, including 3,912 critical), so it must not be used as the current baseline; the daily series shows the change from 10/27–10/31 to 11/01.

### 2.2 Queue composition

Of 961 rows in the later 24-hour read:

- **959** were low/medium.
- **296** had an empty `primary_deviation_feature` — score-only, no named measurement.
- **683** had `strong_families = 0`.
- Top hosts were `host A (busy service host)` (271 rows), `host B` (93), `DATA-segment gateway` (83), `host C` (73), `WIRED-segment gateway` (69). Most are known infrastructure or busy service hosts.
- The top primary features were `unique_dst_ips` (333), empty (297), `total_packets` (201), `total_bytes` (128).

A row with no primary deviation and no strong family is not an incident. It may be a useful hunting lead, but the default console currently gives it the same status as a measured deviation.

### 2.3 Episodes: the P0 finding

Current `alert_episodes FINAL` rows with `updated_at` in 24 hours:

- **2,487 rows across 19 hosts.**
- **0** have `paged_at`; **1,746** are marked critical and pageable.
- `host A (busy service host)` alone has **237 rows**, with episode starts every five minutes from 03:30 onward.
- Rebuilding episodes from the same 960 anomaly rows with the shipped `build_episodes` and `apply_budget` produces **68 episodes**, **1 pageable**.
- The worker itself logs `Episodes: 66 built, 1 pageable` while the table contains 2,487 rows.

**Mechanism:** `episodes.refresh()` queries only the last 24 hours and keys a row by `(src_addr, episode_start)`. For a continuously anomalous host, the oldest window falls out of the lookback every cycle, so the computed `episode_start` shifts forward by five minutes. A new key is inserted, and `ReplacingMergeTree` cannot dedupe a different key. The old overlapping rows remain forever. This is a correctness bug, not cosmetic inflation:

- the dashboard shows dozens of “incidents” for one host;
- `paged_at` never lands because the claim path reads an episode whose `page_window` may be from an older duplicate;
- `alert_events` records the resulting `budget` decisions;
- the per-host daily page budget is measured against a table that does not represent per-host incidents.

This is the first thing to fix, before any model work.

### 2.4 Models and calibration

Latest `ml_calibration` (all-scored population, 7 days):

| model | target FAR | observed FAR | threshold | sample / validation | state |
|---|---:|---:|---:|---:|---|
| Isolation Forest | 1% | **1.00%** | 0.859 | 3,388 / 1,694 | eligible |
| Gradient Boosting | 1% | **1.18%** | 0.980 | 3,388 / 1,694 | eligible |
| Adaptive Baseline | 1% | **1.12%** | 0.990 | 3,388 / 1,694 | eligible, but see race |
| DBSCAN | 1% | **97.46%** | 0.990 | 3,388 / 1,694 | **ineligible** |

`calibration.eligibility` verified live: `Adaptive Baseline True, DBSCAN False, Gradient Boosting True, Isolation Forest True`. The worker log at 21:25 showed **Adaptive Baseline and DBSCAN barred**, while 21:20 showed only DBSCAN. AB retrains every five minutes; if the model artifact is newer than the last calibration row, the stale-calibration guard bars it for a cycle. That is a safe direction, but it makes the fused score pulse between “AB included” and “AB excluded,” and it is visible in the log.

The calibration population is now correct (`ml_window_scores`, all scored host-windows). The **split is not temporal**: `fit()` takes even and odd array positions. On a non-stationary stream that is not a proper held-out future; it is a random interleave. The exchangeability limitation is exactly why adaptive conformal methods exist.[4]

### 2.5 Coverage, features and drift

- Flow coverage: **284 five-minute windows, 3,397 hosts, 133,201 rows** in 24 hours.
- Zeek: **2,156 hosts** on `zeek_conn`; DNS 21 hosts; TLS 17 hosts. Both capture interfaces are live.
- DNS/TLS coverage remains far smaller than flow coverage; absence is represented by `zeek_present = 0`, not by “normal”.
- SMB/Kerberos/NTLM/DCE remain zero or one-way; the SMB asymmetry is documented and must not be read as lateral movement.
- `ml_drift`: **268 drift + 27 watch rows across 17 hosts**. Example: `WIRED-segment gateway53`, baseline mean 0.0029 (n=84) → current 0.4587, PSI 7.73. But `host C` has baseline n=10 and `DATA-segment gateway62` n=16; PSI with ten bins and tiny samples is unstable. Treat these as review triggers, not model failures.
- `host_roles`: 8,724 `external`, 54 `unknown`, 32 `workstation`, 5 `media`, 1 `server`. The role table is dominated by external peers and is not used in scoring or budget. The busiest monitored hosts are not classified well enough for role-aware baselines.
- Reviews: 34 blank, 5 `false_positive`, 4 `ack`; zero `ml_review_adjustments`. There is not enough label volume to compute precision.

### 2.6 Candidate models

Shadow candidates are alive but not production: HDBSCAN 27,329 rows/22 hosts in 24h, External exposure 35,453/19, Beacon 11,305/20, Flow 3,858/22, DNS 2,148/17, TLS 877/14, Graph 360/18. They are not evidence for promotion by themselves; every candidate needs the same fixed-page-budget replay and seeded-attack non-regression. The prior HDBSCAN/GLOSH A/B already found no false-positive advantage. Do not add a second density vote.

---

## 3. External research: what the literature and vendor practice say

The findings below are not a reason to copy a product; they explain why the ordering above is correct.

- **NIST SP 800-94** treats anomaly detection as profile-based and states that false positives and false negatives trade off; tuning is the operational discipline that adjusts profiles and thresholds to the environment.[1] The transferable rule is a profile and a budget per entity, not a universal score.
- **Arp et al., “Dos and Don’ts of Machine Learning in Computer Security”** documents recurring pitfalls including sampling bias, inappropriate baselines, inappropriate measures and the base-rate fallacy.[2] The relevant failures here are evaluating only the selected alert tail, treating a score as if it were precision, and counting correlated detectors as independent evidence.
- **scikit-learn’s IsolationForest documentation** defines `contamination` as the expected proportion of outliers used to set the decision offset; it is not an accuracy or probability claim.[3] Calibration has to come from a held-out population, which is what `ml_calibration` now attempts.
- **Gibbs and Candès, adaptive conformal inference** shows that split-conformal coverage depends on exchangeability; under distribution shift the threshold must be re-estimated online rather than fitted once.[4] An even/odd split on a rolling network stream is especially weak evidence for next-day coverage.
- **MAAC** correlates alerts and reduces repeated alerts by grouping them into multi-step attack context.[5] The live episode duplication is the inverse failure: the system has the grouping primitive but writes the same incident repeatedly.
- **Splunk risk-based alerting** groups events into risk objects and only creates a notable when a risk threshold or pattern is met.[6] That is the same product shape recommended here: incidents are the unit of work, events are evidence.

---

## 4. Recommendations, in order

### P0 — Make episodes idempotent and make the page budget usable

**What:** give an episode a stable identity and merge overlap instead of inserting a new row when the 24-hour window slides.

Implementation options, in order of preference:

1. Compute episodes over a lookback longer than the maximum expected incident (for example `EPISODE_LOOKBACK_H`, initially 7 days), and merge any new episode whose `[start, end]` overlaps an existing episode; keep the earliest start, extend the end, and recompute `occurrences`/`window_count` from the union.
2. Or persist an explicit `episode_id` derived from the first window after the gap, and update that row on each refresh; never use the sliding-window start as identity.
3. Mark stale/overlapping rows as superseded rather than leaving them pageable. Raw windows must remain untouched.

**Why first:** it directly explains 2,487 rows → 68 episodes and 1,746 pageable rows → 1. The page path cannot be judged until it reads a truthful episode table.

**Acceptance:**

- Two consecutive refreshes with a sliding window produce the same episode start and the same count; no duplicate `(src_addr, overlapping interval)` rows.
- A 24-hour replay produces roughly one episode for a continuous host and one page per budgeted episode.
- `paged_at` is set on exactly the page that was sent; `alert_events` no longer records `budget` for an episode that was never considered.
- A test drives `refresh` twice with a shifted window and goes red on the current implementation.

### P0 — Make the default queue an incident queue, not a row queue

**What:** the console should show, by default:

- high/critical **episodes** that are pageable;
- newly appearing hosts or newly appearing behaviours;
- at most the operator’s per-host daily budget.

Low/medium and zero-family rows belong in a **Leads** view with the evidence that made them. A row with no primary deviation is a model-only lead, not an incident. This is a display and contract change, not a detector change.

**Acceptance:** the default view’s 24-hour count falls from ~960 rows to the episode/budget count; every displayed incident names at least one measured feature or structural signature; no raw evidence becomes unreachable.

### P1 — Fix calibration ordering and make it temporal

- Run calibration **after** the AB/Baseline refresh in the same cycle, or let eligibility use a calibration row whose `model_version` matches the artifact rather than a strict timestamp comparison. Measure how often each model is barred.
- Replace the even/odd split with a **time-ordered holdout**: fit on earlier windows, validate on later windows, then report the observed FAR on the next unseen day.
- Keep adaptive/weighted conformal as the next experiment for drift; do not call the current split-conformal number a guarantee.[4]
- Preserve `reference_source` and show sample counts beside every threshold.

**Acceptance:** a held-out day’s observed high/critical episode rate is within the configured budget ± a stated tolerance; AB is not intermittently barred without a stated reason; DBSCAN stays ineligible until it passes a live holdout.

### P1 — Role-aware and peer-aware baselines

The busiest hosts are gateways and service hosts, but `host_roles` is dominated by `external`. Classify the top monitored hosts first; then use a shrunk role/cohort baseline (`n/(n+k)`) instead of a single global threshold. Do not whitelist infrastructure; a gateway can be compromised.

**Acceptance:** the gateway/service hosts’ episode rate falls at the same budget; a seeded gateway attack still appears; the role and shrinkage rung are visible in the why line.

### P1 — Turn reviews into a bounded feedback loop

Only nine reviews exist and none feed an adjustment. Show the highest-uncertainty windows (near the budget boundary, conflicting families, no primary feature), not every row. A `false_positive` review should adjust the host/role budget or threshold with an expiry; it must **not** be fed back as a normal training row. Keep labels for calibration/evaluation.

**Acceptance:** after a fixed review batch, the false-positive rate per role moves in the intended direction; no reviewed false positive becomes normal training data; review volume is bounded.

### P2 — Drift and candidate promotion

- Require `n >= 30` per side (or use a Bayesian/KS test) before calling PSI “drift”; the current n=10–21 cases are not actionable.
- Keep HDBSCAN, External exposure, Beacon and the specialists shadow-only until they win at the same page budget without a seeded regression.
- Do not add LOF, one-class SVM, autoencoders or another supervised classifier on five labels.
- Keep the coverage contract: absent SMB/Kerberos/DNS/TLS is “unavailable”, never zero-is-normal.

---

## 5. What success should look like

For the same 24-hour replay:

| measure | current | target |
|---|---:|---:|
| stored anomaly rows | ~960 | unchanged (evidence retained) |
| episode rows | 2,487 | ~68 (or fewer after merge) |
| pageable episodes | 1,746 | ≤ 2 per host/day |
| default queue rows | ~960 | incident count only |
| rows with no primary deviation | 296 | 0 in the incident view |
| high/critical rows | 2 | preserve or improve seeded recall |
| DBSCAN in fused score | excluded | stays excluded until live holdout passes |

The model work is not finished, but it is no longer the first bottleneck. The first release should be the episode/page fix plus the queue contract. Calibration and role work follow on the same fixed-budget replay.

---

## 6. Reproduction queries

```sql
-- Current volume and severity (rolling 24h)
SELECT severity, count(), uniqExact(src_addr), round(avg(anomaly_score),3),
       round(avg(strong_families),2)
FROM weirvern.netflow_anomalies
WHERE detected_at >= now() - INTERVAL 24 HOUR
GROUP BY severity ORDER BY severity;

-- Episode duplication (use FINAL; this is the table the page path reads)
SELECT count(), uniqExact(src_addr), max(occurrences), countIf(paged_at IS NOT NULL)
FROM weirvern.alert_episodes FINAL
WHERE updated_at >= now() - INTERVAL 24 HOUR;

-- Which hosts carry the duplicate rows
SELECT src_addr, count(), min(episode_start), max(episode_start), max(occurrences)
FROM weirvern.alert_episodes FINAL
WHERE updated_at >= now() - INTERVAL 24 HOUR
GROUP BY src_addr ORDER BY count() DESC LIMIT 20;

-- Calibration target versus observed, and eligibility
SELECT model_name, target_far, observed_far, threshold, sample_count, validation_count,
       reference_source, model_version, computed_at
FROM weirvern.ml_calibration FINAL
ORDER BY model_name;

-- Queue evidence gap
SELECT count(), countIf(primary_deviation_feature=''), countIf(strong_families=0),
       countIf(severity IN ('low','medium'))
FROM weirvern.netflow_anomalies
WHERE detected_at >= now() - INTERVAL 24 HOUR;
```

The 68-episode replay is reproduced by reading the last 24 hours of `netflow_anomalies`, calling `weirvern.episodes.build_episodes(rows, episode_gap_minutes)`, then `apply_budget(..., per_host_budget, min_severity)`. That is the same code the worker calls; the difference between its 68 and the table’s 2,487 is the defect.

---

## 7. What not to do

- Do not lower or raise `BASE_THRESHOLD` and call it a fix; the current queue is 99.8% low/medium, and the score distribution is already compressed near the ceiling.
- Do not add a detector to mask a grouping bug.
- Do not re-enable DBSCAN because a new calibration looks better on the tail; require a live holdout.
- Do not feed false-positive reviews back as normal training rows; that is baseline poisoning.
- Do not treat `attack_techniques` as a coverage requirement again; it was removed for a reason.
- Do not use the seven-day totals as the current baseline; they include the pre-0.23.15 storm.

---

## Sources

[1] https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-94.pdf — NIST SP 800-94, Guide to Intrusion Detection and Prevention Systems
[2] https://www.usenix.org/system/files/sec22summer_arp.pdf — Arp et al., Dos and Don'ts of Machine Learning in Computer Security
[3] https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.IsolationForest.html — scikit-learn IsolationForest documentation
[4] https://arxiv.org/abs/2106.00170 — Gibbs and Candès, Adaptive Conformal Inference Under Distribution Shift
[5] https://arxiv.org/abs/2011.07793 — Wang et al., MAAC: Novel Alert Correlation Method To Detect Multi-step Attack
[6] https://lantern.splunk.com/Security_Use_Cases/Threat_Investigation/Implementing_risk-based_alerting — Splunk Lantern, Implementing risk-based alerting
