# Drastically improving real-anomaly detection — research and execution plan

**Date:** 2026-10-30
**Status:** plan, not a release. No production change is implied by this document.
**Scope:** Weirvern's detection stack: NetFlow, DNS, Zeek protocol logs, JA4/TLS, host identity,
the ML ensemble, the incident/alert layer, and the evaluation system.

---

## 1. Executive summary

We do not have a model problem first. We have a **detection-coverage and measurement problem**:

- The current ML ensemble is trained on aggregate host-window features and a subset of Zeek
  features. It can find the three seeded behaviours the harness knows (port scan, beacon,
  exfiltration), but the harness has no DNS-tunnel, lateral-movement, brute-force, rogue-DHCP,
  JA4-novelty or encrypted-C2 scenarios. It cannot tell us whether those are detected.
- The **data is unevenly harvested**: DNS is visible for 14 source hosts in 24 hours, JA4 for 12
  hosts / 17 distinct fingerprints, SSH for zero hosts, and several lateral-movement logs
  (Kerberos, NTLM, SMB, DCE/RPC) have no rows in the last day. A model cannot learn what the
  sensor never sees.
- The **decision layer is still missing**: there is no incident object, no per-host budget, and
  DBSCAN is saturated (99.94% observed false-alarm rate). This makes every model change hard to
  judge because the queue is already unusable.

The plan therefore has one rule: **maximize verified detection per unit of analyst attention,
not the number of detectors.** We build coverage and labels first, then specialists per data
source, then a risk/incident layer. Deep models and graph neural networks come after the data
and labels exist, not before.

**Immediate priorities**

1. **P0 — Coverage and feature registry.** Know every field we harvest, which model sees it,
   and which sensor is not producing it.
2. **P0 — Evaluation corpus.** Expand the seeded harness from 3 attacks to 10+ classes, with
   benign windows and per-class latency.
3. **P0 — Incident budget.** Episodes, per-host budget and DBSCAN eligibility; this is the
   false-positive fix and the measurement frame for every later specialist.
4. **P1 — Source specialists:** DNS, JA4/TLS, flow/scan, identity/lateral, temporal/beacon,
   graph/peer. Each writes evidence; only the incident layer pages.
5. **P1/P2 — Learning loop and drift:** active learning from reviews, time-split validation,
   drift monitors. Self-supervised/GNN/LLM work only after the corpus is credible.

---

## 2. What “real anomaly” means here

A **real anomaly** is an observable behaviour that is both **unusual for this entity** and
**meaningful for the threat model** — not merely a rare row. We will score and report on:

| Family | Examples | Primary evidence |
|---|---|---|
| Reconnaissance | external scan, internal sweep, service discovery | Zeek conn state / S0-REJ ratios, flow port diversity, fan-out |
| Initial access | exploit attempt, credential brute force, rogue device | SSH/NTLM failures, HTTP paths, DHCP server/MAC anomalies |
| Execution / lateral | SMB admin shares, DCE/RPC service control, Kerberos service tickets | SMB/RPC/Kerberos logs, identity graph, new peer edges |
| C2 / beacon | periodic callback, DNS tunnel, HTTPS/QUIC C2 | inter-arrival regularity, DNS entropy/length, JA4/SNI novelty |
| Exfiltration | volume spike, asymmetric transfer, DNS/HTTP smuggling | bytes asymmetry, file/HTTP metadata, DNS TXT/NULL, destination rarity |
| Encrypted / evasive | new TLS stack, downgrade, QUIC, unknown protocol | JA4 novelty/rarity, TLS version/cipher, certificate, ALPN |
| Low-and-slow | gradual drift, new service, changed schedule | day/week baselines, change points, matrix profile |

This is deliberately larger than “the score is high.” A high score is a **lead**; an incident
needs an actor, an asset, a behaviour, and evidence.

---

## 3. What the live system shows today

### 3.1 Queue and model

- **2,652** anomaly rows in 24 hours; **709 critical**, 56 high, 1,276 medium, 611 low.
- **1,783 rows (67%)** have one or fewer independent families.
- **2,664 alert decisions, all `log-only`** — a dashboard flood, not a Pushover storm.
- **DBSCAN observed false-alarm rate: 99.94%** against a 1% target.
- Grouping by host with a 30-minute gap collapses the day to **~84 incidents**; the
  critical/high subset to **~79** (57 at 60 minutes).
- Seeded harness baseline (production models, demo data): **263 verdicts**, port scan
  **critical**, beacon **medium**, exfiltration **critical**; **1 of 9** benign hosts at high+;
  busiest host 26 of 60 windows. This passes the current three-class bar. It is not a
  real-anomaly benchmark.

### 3.2 Feature coverage

From the latest `ml_models` and a live 24-hour inventory:

| model | columns | DNS features | flow features | other |
|---|---:|---:|---:|---|
| Isolation Forest | 77 | 13 | 14 | full Zeek block |
| Gradient Boosting | 77 | 13 | 14 | full Zeek block |
| DBSCAN | 19 | 3 | 8 | 11 Zeek total |
| HDBSCAN challenger | 19 | 3 | 8 | 11 Zeek total, scope-filtered |

The production IF/GB models already carry the full DNS and flow feature blocks. DBSCAN deliberately
uses a small subset for density estimation. The old HDBSCAN challenger was the exception — it
used only the eight flow columns; that is fixed in the shadow candidate.

### 3.3 Source coverage is uneven

24-hour live counts:

| source | rows | source hosts | note |
|---|---:|---:|---|
| `flows_aggregated` | 636,045 | 3,730 | the NetFlow feature base |
| `zeek_conn` | 221,339 | 2,188 | connection shape; overlap with flow hosts 2,168 |
| `zeek_dns` | 25,925 | **14** | DNS is the largest visibility gap |
| `zeek_ssl` | 1,361 | 12 | only **17 distinct JA4** fingerprints in 24h |
| `zeek_http` | 3,482 | 10 | sparse |
| `zeek_files` | 4,214 | 10 | sparse |
| `zeek_ssh` | 0 | 0 | no SSH on the tap |
| `zeek_dhcp` | 42 | 11 | low volume, high identity value |
| `zeek_kerberos` / `ntlm` / `smb_*` / `dce_rpc` | 0 | 0 | lateral-movement telemetry absent |
| `host_roles` | 17,556 | — | 74 monitored unknown, 60 workstation, 10 media, 4 server; **not used by any model** |

DNS qtypes in 24h: A 11,947, AAAA 7,264, PTR 4,072, SRV 2,108, ANY 436, TXT 16. Rcode is 0 for
all 25,925 rows. That is a quiet, healthy DNS profile — which means a DNS-tunnel detector must be
sensitive to **shape** (entropy, length, query uniqueness, TXT/NULL) and not rely on errors.

JA4 coverage is the second gap: 17 fingerprints across 12 hosts is not a fleet baseline. It is
enough for **novelty and rarity rules**, not for a learned JA4 model.

---

## 4. Research findings that shape the plan

### 4.1 ML anomaly detection fails when it is treated as a classifier

Sommer and Paxson's *Outside the Closed World* is still the clearest statement of the problem:
network intrusion detection is not a closed-world classification task, anomaly detection is good
at finding **similar-but-not-identical** behaviour, and operational deployment is rare for good
reasons. The paper's guidance — clearly state the detection goal, use realistic benign data,
measure false positives, and do not assume novel attacks are automatically outliers — applies
directly here. [S1]

Arp et al.'s *Dos and Don'ts of Machine Learning in Computer Security* adds the recurring pitfalls:
sampling bias, label inaccuracy, inappropriate baselines and measures, and the base-rate fallacy. [S2]

**Consequence:** every specialist must have a stated target behaviour, a benign reference, and a
false-alarm budget. “The model flags unusual traffic” is not a detection goal.

### 4.2 Public NIDS datasets are not our ground truth

KDD-99/NSL-KDD and the CIC-family datasets have documented distribution, labelling and realism
problems; benchmarking work recommends modern alternatives but still cannot make them represent
this network. [S3] UNSW-NB15 and ToN-IoT are more modern but are still different sensors, address
plans and traffic mixes.

**Consequence:** use public datasets only to validate feature implementations and model mechanics.
The **primary** evaluation is the seeded generator plus live benign periods and operator reviews.

### 4.3 Tabular trees remain the right default at this scale

Grinsztajn et al. show tree-based models remain state-of-the-art on medium-sized tabular data
(~10K samples), even before considering speed. [S4] Our models are exactly in that regime; the
current IF/GB/DBSCAN stack is not obviously wrong because it is not deep.

**Consequence:** add specialists and better features before adding deep architectures. A deep
sequence model must beat a tree/feature baseline at the same alert budget to earn a place.

### 4.4 Drift is not an edge case

Concept-drift and feature-drift surveys show that static NIDS models degrade as traffic, assets
and attacks change; most studies treat drift as an afterthought. [S5] Recent work such as
DriftXpert proposes proactive drift adaptation, but it is a research direction, not a drop-in
production component. [S6]

**Consequence:** every model has a time-split evaluation, a drift monitor and a retrain trigger.
A model that was good last month is not assumed good today.

### 4.5 Graph, multimodal and self-supervised methods are promising but not first

Graph work shows that topology and edge direction carry intrusion signal beyond per-host rows
(EDGMAT, XG-NID). [S7][S8] Contrastive self-supervised work reports lower false-positive rates
than classical anomaly detection by learning benign representations (CLAN). [S9] These are real
research directions, but they need large, representative benign corpora and labels this
deployment does not yet have.

**Consequence:** start with **graph-derived features** (degree, fan-in/out, new-edge ratio, peer
rarity) in a tree/statistical model. A GNN or contrastive encoder is a Phase 3 challenger, not a
Phase 1 dependency.

### 4.6 DNS and JA4 are high-value because they see what NetFlow cannot

DNS tunneling research consistently finds that shape features — query length, entropy, unique
subdomains, record type and response behavior — are the discriminative signal; simple volume
thresholds are weak. [S10]

JA4 is a TLS ClientHello fingerprint designed to identify client software even when the payload is
encrypted; the broader JA4 fingerprinting work extends the idea across protocols. [S11] A new JA4 on an internal
host, or a JA4 that is rare across the fleet, is a high-precision novelty event. The limitation is
coverage: 17 fingerprints/day cannot support a fleet-wide model.

### 4.7 Correlation and risk beat “one score per window”

MAAC reports large alert-volume reductions by correlating alerts by attack stage and semantics. [S12]
Risk-based alerting groups events into risk objects and only creates a notable when a threshold or
pattern is met. [S13] This is the right shape for the incident layer: many pieces of evidence,
one incident, one budget.

### 4.8 Calibration and analyst feedback are the bridge from scores to decisions

Conformal prediction gives finite-sample false-alarm control under exchangeability; network
streams violate that, so calibration must be time-aware and periodically refreshed. [S14]
Alert-fatigue research and analyst-facing studies consistently show that triage, context and
feedback matter more than another score. [S15]

**Consequence:** the decision layer is not cosmetic. It is what makes a specialist's evidence
usable and what turns review labels into better priorities.

---

## 5. Target architecture

```
collectors
  NetFlow (flows)            DNS (zeek_dns)          Zeek protocol logs         TLS/JA4
        │                          │                         │                       │
        └────────────── normalized event + entity store ────────────────────────────┘
                                   │
                         feature registry / windows
                     (5m, 1h, 24h, 7d; host, peer, service, domain, JA4, identity)
                                   │
        ┌───────────────┬──────────┴──────────┬───────────────┬────────────────┐
        │               │                     │               │                │
   flow/scan        DNS specialist       TLS/JA4 specialist  identity/        temporal/beacon
   specialist                                                   lateral          + graph/peer
        │               │                     │               │                │
        └───────────────┴────────── evidence objects ─────────┴────────────────┘
                                   │
                         risk + incident builder
                    (episode, severity, budget, why, review)
                                   │
                         page / queue / evidence
```

**Rules**

- A specialist writes **evidence**, not a page. The incident builder decides.
- Every feature carries its **source** and **presence**; absent is not zero.
- Every detector is calibrated against a benign reference and evaluated at a fixed budget.
- Raw rows are never deleted; the incident references them.
- No model reads its own prior output as a feature.
- No free-text field, hash, IP, MAC, `uid`, `fuid`, `trans_id` or raw payload becomes a numeric
  feature; those are keys or evidence.

---

## 6. Leveraging every harvested source

This is the source-to-feature contract. “Now” is what production models use; “plan” is what the
program adds. Some fields are deliberately join-only or excluded, and that is stated rather than
pretended.

### 6.1 NetFlow

| harvest | now | plan |
|---|---|---|
| `flows` raw: 5-tuple, bytes, packets, tcp_flags, proto, AS, VLAN, interfaces, TTL/TOS, sampling | raw landing table / replay; aggregates are the model input | **raw-flow specialist** for scans, fragmentation, spoofing, sampling confidence; do not featurise raw addresses |
| `flows_aggregated`: flow_count, total_bytes, total_packets, unique_dst_ips, avg_bytes/packets | flow_count, bytes, packets, unique destinations | add inter-flow variance, bytes-per-packet shape, active-minute profile, destination fan-out by role |
| `flows_aggregated_diversity`: ports, unique addrs/connections, entropy, stddev, min/max, active_minutes | ports, entropy, bytes stddev, connection density | add min/max/size variance, port-set novelty, service/port role mismatch |
| `flows_aggregated_temporal`: minute activity, regularity, burstiness, inter-flow avg/stddev | regularity, burstiness | add inter-arrival periodicity, burst shape, time-of-day deviation |

### 6.2 DNS

`zeek_dns` fields: timestamp, uid, src/dst, proto, trans_id, query, qtype, rcode, answers,
query_len, query_entropy.

**Now (IF/GB):** count, mean/max entropy, mean length, length std, rcode-error ratio, failed
ratio, unique ratio, NXDOMAIN, TXT, NULL, answer-count mean, new-domain ratio.
**Now (DBSCAN):** count, mean entropy, rcode-error ratio.

**Plan:** a dedicated DNS specialist with:

- query length/entropy distributions and **max**, not just mean;
- unique-subdomain ratio, new-domain ratio against a 7-day host baseline;
- qtype mix, TXT/NULL/ANY share, response answer count;
- NXDOMAIN/failure bursts (currently zero, so do not rely on it);
- resolver fan-out and query-rate periodicity (beacon-like DNS);
- domain-to-host graph: one domain queried by many hosts, one host querying many new domains;
- **presence**: `zeek_dns` coverage is only 14 hosts; a host with no DNS is not “normal DNS”,
  it is “DNS unobserved.”

**Not a feature:** raw `query` text and `trans_id`; these are hunting/evidence fields. A domain
reputation feed is a separate enrichment, not a training feature.

### 6.3 Zeek `conn`

Fields: src/dst, ports, proto, service, duration, orig/resp bytes/packets, conn_state, history.

**Now:** conn count, service count, REJ ratio, S0 ratio, completed ratio.
**Plan:** duration distribution, bytes-per-packet, orig/resp asymmetry, **history/state grammar**
(not a raw string), retransmit/close behavior, per-port service novelty, fan-in/out.

`history` is a compact state string; featurise counts of the meaningful letters, not the string
as an integer. `S1` vs `SF` needs byte-count nullness to disambiguate.

### 6.4 Zeek DNS/HTTP/SSH/files/DHCP

| log | now | plan |
|---|---|---|
| `zeek_http` | count, URI entropy mean/max, host count, error ratio, post ratio | method/status mix, URI-shape novelty, user-agent rarity (hash, not raw), POST-to-upload size |
| `zeek_ssh` | count, attempts, fail ratio/failures, client/server count, present | **no data currently**; fix sensor/config before modeling; add auth failure bursts, direction, client/server role |
| `zeek_files` | count, bytes mean/max, MIME count, unique ratio | file-size profile, MIME novelty, hash-to-threat-intel (join, not feature), entropy if enabled |
| `zeek_dhcp` | events, MAC count, server count, lease mean | MAC↔IP binding stability, rogue server, duplicate address, lease churn; use MAC as entity key, not a numeric feature |

### 6.5 Identity and lateral movement

| log | now | plan |
|---|---|---|
| `zeek_kerberos` | **no ML feature**; only ATT&CK rules | SPN/service novelty, principal→service graph, request-type mix, failure ratio, ticket lifetime/cipher |
| `zeek_ntlm` | **no ML feature** | username↔host bipartite graph, failure ratio, new host/account pairs |
| `zeek_smb_mapping` | **no ML feature** | ADMIN$/C$/IPC$ access, share novelty, share-type mismatch |
| `zeek_smb_files` | **no ML feature** | action mix (read/write/rename/delete), size/rate, file-type profile; enable `FILE_WRITE` in `logged_file_actions` |
| `zeek_dce_rpc` | **no ML feature** | endpoint/operation novelty, named-pipe activity, RTT |
| `zeek_ldap_search` | count, filter shapes, result mean/max | filter-token novelty, base-object scope, enumeration bursts |
| `host_roles` / `host_identity` / `software` | roles collected but unused; software feeds identity store | role-aware thresholds; new-software/version novelty; stable MAC/identity entity |

These tables are empty in the current 24-hour window. That is a **coverage** issue, not a modelling
result. The plan starts with sensor/config verification before adding features that would be
constant zero.

### 6.6 TLS / JA4

`zeek_ssl`: version, cipher, server_name, JA4, JA4_orig, validation_status, established.

**Now:** JA4 count, JA4 novelty (host baseline), modern-TLS ratio. **JA4 coverage: 12 hosts,
17 distinct fingerprints in 24h.**

**Plan:**

- per-host **new-JA4 ratio** and **days-since-last-seen**;
- fleet **JA4 rarity** (number of hosts/connections using a fingerprint);
- JA4 ↔ SNI/server-name consistency and **JA4-to-service** baseline;
- JA4 with missing/invalid SNI, certificate failure, or a downgrade in TLS version/cipher;
- JA4 change on a host that normally uses a stable client;
- **extended fingerprint variants** only after the base JA4 coverage is real; do not infer
  fingerprint types from data that is not collected.

JA4 is an identity signal, not a verdict: a new browser build is normal; a new JA4 on a server
that should never initiate TLS is not.

### 6.7 X.509 and certificates

`zeek_x509` has no `src_addr`; it cannot be a per-host feature directly. Join it through
`ssl.log` certificate-chain fingerprints or SNI/host. Plan: certificate age, self-signed
subject==issuer, weak key/signature, SAN/SNI mismatch, reuse across hosts, expired/not-yet-valid.
Use serial/fingerprint as join keys, not numeric features.

### 6.8 Capture health

`capture_loss` and sensor stats are **not detection features**. They gate confidence: a window
with high capture loss must be marked low-confidence and excluded from training/calibration rather
than imputed as normal.

---

## 7. Detection portfolio

### 7.1 Specialists (each produces evidence, calibrated separately)

1. **Flow/scan specialist** — port diversity, S0/REJ, fan-out, short-lived connections, raw-flow
   flags. Catches horizontal/vertical scans and service discovery.
2. **DNS specialist** — entropy/length/unique/new-domain/qtype shape. Catches tunnels and DGA-like
   behavior; emits the query-shape evidence, not the domain text.
3. **TLS/JA4 specialist** — JA4 novelty/rarity, SNI/cert mismatch, downgrade, QUIC. Catches new
   clients, rogue TLS, encrypted C2.
4. **Identity/lateral specialist** — Kerberos SPN/principal novelty, NTLM failures, SMB admin
   shares, RPC operations, LDAP filter novelty. Catches lateral movement.
5. **Temporal/beacon specialist** — inter-arrival regularity, periodicity, matrix profile,
   change points. Catches low-and-slow C2 and regime changes.
6. **Graph/peer specialist** — fan-in/out, new edges, peer rarity, reciprocity, community change.
   Catches role changes and east-west movement.
7. **Baseline/role specialist** — robust per-host/role/seasonal bands; this is the normal model,
   not a novelty model.

The existing IF/GB remain as general tabular scorers. DBSCAN stays only if it passes its
eligibility gate; its current saturation is a production defect.

### 7.2 Fusion

Replace `max` with an **evidence/risk object**:

- each specialist produces `(score, calibrated_p, evidence, source_coverage, model_version)`;
- a **noisy-OR / logistic stack** combines independent evidence, with a penalty for correlated
  sources (IF + GB are not independent; GB is trained on IF);
- the incident builder groups by host/time/peer, assigns severity from evidence, and applies the
  budget;
- a single high score from one saturated model cannot page alone.

### 7.3 What not to build first

- a GNN on a graph with a few hundred edges and no labels;
- a self-supervised encoder on 77 tabular features with 10K rows;
- an LLM that reads raw logs and assigns verdicts;
- another density model on the same features;
- a supervised classifier trained on five review labels.

These are Phase 3 challengers at the earliest. The research supports them as directions, not as
the first production bet. [S4][S7][S9]

---

## 8. Evaluation and labelling

### 8.1 The corpus

- **Seeded attacks**: extend `scripts/demo_flows.py` / `eval_detection.py` to 10+ scenarios:
  port scan, horizontal sweep, beacon, DNS tunnel, exfil over DNS/HTTP, SSH brute force, NTLM
  brute force, SMB admin-share lateral, DCE/RPC service execution, rogue DHCP/MAC spoof, new JA4
  client, QUIC C2, data staging/rename burst.
- Each scenario: attack start, expected technique, expected evidence, and a **detection deadline**.
- **Benign windows**: live traffic from ordinary days; role-labelled hosts; known maintenance.
- **Reviews**: operator labels are evaluation labels, not normal-training rows.
- **Replay**: store the feature matrix and raw evidence so a failed run is reproducible.

### 8.2 Metrics

- **Per-family recall** at a fixed alerts/day budget.
- **Precision@k** and **incidents/day**, not raw row precision.
- **Time-to-detect** and **episode-level recall** (an attack spanning windows counts once).
- **False alarms per host/day** by role.
- **Source ablation**: remove DNS, JA4, Zeek-identity, graph; measure contribution.
- **Drift**: week-over-week score distribution and recall; retrain trigger.
- **Stability**: same seed → same verdicts; retrain-to-retrain variance.
- **Explanation coverage**: every incident names the evidence that earned it.

### 8.3 Rules

- Time-split validation, never random windows across the same day.
- Public datasets are for mechanics, not precision claims.
- A candidate that wins by alerting more is rejected by definition.
- A specialist without a benign reference and a budget is a research prototype.

---

## 9. Phased plan

### Phase 0 — Measure and cover (2 weeks, P0)

**Deliverables**

- a source-feature registry (committed as part of this program) mapping every harvested
  table/field to used / planned / join-only / excluded, with owner and presence rule.
- Live coverage report per source and per monitored host; sensor/config fixes for DNS, JA4, SSH,
  SMB/Kerberos/NTLM/DCE-RPC, software/known-services.
- Expanded seeded corpus (at least 10 scenarios) and a baseline report from `eval_detection.py`.
- Capture-loss/confidence gate.

**Acceptance:** every monitored host has a coverage row; every new scenario has a reproducible
expected outcome; missing sources are named, not silently zero.

### Phase 1 — Make the queue usable (2 weeks, P0)

**Deliverables**

- Episodes + per-host/role budget (observe-only for 24h, then enforce).
- DBSCAN eligibility gate; signature exception preserved.
- Incident UI/API with evidence, occurrence count and budget state.
- Before/after replay: rows, episodes, pageable count, seeded detection/latency.

**Acceptance:** a 24-hour replay meets the budget; seeded scan/beacon/exfil do not regress; raw
evidence is preserved; a failed episode read is named.

### Phase 2 — Source specialists (4 weeks, P1)

**Deliverables**

- DNS specialist (shape, new-domain, qtype, resolver fan-out) in shadow.
- JA4/TLS specialist (novelty, rarity, SNI/cert mismatch, downgrade) in shadow.
- Flow/scan specialist (raw-flow flags and connection state).
- Identity/lateral specialist (Kerberos/NTLM/SMB/RPC/LDAP) once coverage is non-zero.
- Role-aware baselines and `host_roles` in the threshold path.
- Source ablation report.

**Acceptance:** each specialist has a seeded scenario, a benign reference and a fixed-budget
result; at least one new family is detected without a queue regression; no specialist pages
directly.

### Phase 3 — Temporal, graph and drift (4 weeks, P1/P2)

**Deliverables**

- Beacon/periodicity feature family (inter-arrival, autocorrelation, matrix profile).
- Graph/peer feature family (fan-in/out, new-edge ratio, peer rarity, reciprocity).
- Drift monitors and time-split retraining policy.
- Active-learning review queue; labels feed calibration/evaluation, not normal training.
- GNN / contrastive encoder as an **offline challenger only**.

**Acceptance:** graph/temporal features improve a seeded family at the same budget or are
rejected; drift alarms are explainable; active-learning review volume is bounded.

### Phase 4 — Continuous improvement (ongoing)

- Quarterly re-baseline against the expanded corpus.
- Retire models that cannot beat the simple baseline at the same budget.
- Re-check source coverage after every sensor or network change.
- Keep a written “why this detector exists” for every specialist.

---

## 10. First 10 days — concrete

1. Build the source-feature registry and run a per-host coverage query.
2. Fix the DNS/JA4/SSH/SMB sensor path; do not add features that will be constant zero.
3. Add five seeded scenarios to the harness: DNS tunnel, SSH brute, SMB lateral, rogue DHCP,
   JA4-novel client.
4. Implement ML-11 episodes/budget and ML-12 DBSCAN eligibility with before/after replay.
5. Specify DNS and JA4 specialist features (no model training yet) and card them.
6. Record baseline metrics: per-family recall, incidents/day, precision@budget, MTTD, coverage.

---

## 11. Success criteria

The program succeeds when, on the same benign day and the same seeded corpus:

- **real family recall** increases across at least four new families;
- **incidents/day** falls inside the operator budget;
- **precision@budget** is measured and improves, not assumed;
- **MTTD** is recorded per family;
- **source coverage** is explicit for every host;
- every page has evidence and a reviewable incident, not a bare score.

A model that raises recall by flooding the queue fails the program.

---

## 12. Risks and mitigations

| risk | mitigation |
|---|---|
| Sensor blind spots (DNS/JA4/identity) | coverage gate; no model on absent data; fix collectors first |
| Public-dataset overfitting | seeded + live benign evaluation; dataset only for mechanics |
| Label scarcity | active learning; operator reviews as evaluation labels; weak supervision from rules |
| Drift | time-split validation, drift monitors, scheduled retrain |
| Correlation hides an attack | raw evidence retained; incident can be expanded; no deletion |
| Too many specialists | one evidence contract, one budget, one incident object; retire losers |
| Privacy | aggregate features; no raw payloads/free text/hashes as features; join-only identifiers |
| False confidence from a single score | calibrated p-values, source coverage, evidence, budget |

---

## 13. Sources

- **[S1]** Sommer & Paxson, *Outside the Closed World: On Using Machine Learning for Network
  Intrusion Detection*, IEEE S&P 2010. https://oaklandsok.github.io/papers/sommer2010.pdf
- **[S2]** Arp et al., *Dos and Don'ts of Machine Learning in Computer Security*, USENIX Security
  2022. https://www.usenix.org/system/files/sec22summer_arp.pdf
- **[S3]** Divekar et al., *Benchmarking datasets for Anomaly-based Network Intrusion Detection:
  KDD CUP 99 alternatives*, arXiv:1811.05372. https://arxiv.org/abs/1811.05372
- **[S4]** Grinsztajn, Oyallon & Varoquaux, *Why do tree-based models still outperform deep
  learning on tabular data?*, arXiv:2207.08815. https://arxiv.org/abs/2207.08815
- **[S5]** Shyaa et al., *Evolving cybersecurity frontiers: A comprehensive survey on concept
  drift and feature dynamics aware machine and deep learning in intrusion detection systems*,
  Engineering Applications of AI 137 (2024). https://doi.org/10.1016/j.engappai.2024.109143
- **[S6]** Zha et al., *Navigating the Latent Manifold: Proactive Concept Drift Adaptation for
  Resilient NIDS*, arXiv:2609.08623. https://arxiv.org/abs/2609.08623
- **[S7]** Li et al., *Network Intrusion Detection with Edge-Directed Graph Multi-Head Attention
  Networks*, arXiv:2310.17348. https://arxiv.org/abs/2310.17348
- **[S8]** Farrukh et al., *XG-NID: Dual-Modality Network Intrusion Detection using a
  Heterogeneous Graph Neural Network and Large Language Model*, arXiv:2408.16021.
  https://arxiv.org/abs/2408.16021
- **[S9]** Wilkie et al., *Contrastive Self-Supervised Network Intrusion Detection using
  Augmented Negative Pairs*, arXiv:2509.06550. https://arxiv.org/abs/2509.06550
- **[S10]** Amirov et al., *DNS Tunneling: Threat Landscape and Improved Detection Solutions*,
  arXiv:2507.10267. https://arxiv.org/abs/2507.10267
- **[S11]** FoxIO, *JA4 network fingerprinting standards*.
  https://github.com/FoxIO-LLC/ja4
- **[S12]** *MAAC: Novel Alert Correlation Method*, arXiv:2011.07793.
  https://arxiv.org/abs/2011.07793
- **[S13]** Splunk Lantern, *Implementing risk-based alerting*.
  https://lantern.splunk.com/Security_Use_Cases/Threat_Investigation/Implementing_risk-based_alerting
- **[S14]** *Conformal Prediction: A Data Perspective*, arXiv:2410.06494.
  https://arxiv.org/abs/2410.06494
- **[S15]** *AI-Driven Security Alert Screening and Alert Fatigue Mitigation in SOCs: A Survey*,
  arXiv:2605.08316. https://arxiv.org/abs/2605.08316
- **Internal evidence:** `docs/research/zeek-log-research-ml.md` (Zeek field inventory and
  default/gated log analysis), `docs/research/ml-false-positive-reduction-2026-10-29.md`,
  `docs/research/hdbscan-glosh-full-evaluation-2026-10-30.md`.
