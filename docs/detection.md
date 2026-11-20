# Detection and alerting

*Part of the [Weirvern](../README.md) documentation.*

What the detectors are, what they see, what an alert
means, and how the console presents it.

## Detection and alerting

### The ensemble

Five detectors, each contributing a normalised 0–1 score:

| Detector | What it catches | Notes |
|---|---|---|
| Isolation Forest | Multivariate outliers across the full feature vector | Calibrated against its own training distribution |
| Gradient Boosting | Non-linear patterns, trained on IF's labels (a distillation) | Probability calibrated; class-imbalanced weighting |
| KNN distance | A host-window that sits far from the population of host-windows on the same measured columns | Distance to the k-th neighbour (k = 10) in the standardised 19-column vector; the reference set travels with the artifact |
| LOF | A host-window whose local neighbourhood is sparser than its neighbours' — a *local* density outlier | Independent of kNN: `novelty=True`, k = 20, its own reference set and artifact. Scored as `log1p(LOF)` so the number is bounded |
| Adaptive Baseline | Per-host percentile deviation (p95/p99/p999) | Learns each host's normal; needs ≥10 observations |

**DBSCAN was removed on 2026-11-20, not retired.** Of 27,454 stored scores, **97.89% sat at 0.99
or above** (p50 = p99 = max = 0.99): a score at its ceiling on 98% of windows cannot be given a
threshold, and any cut below the ceiling fires on essentially everything. The class, its feature
and query paths, its family, its registry row and its artifacts on the models PVC are gone; the
Detectors table has **no row for it**, because removal is not a status. `CHANGELOG` 0.23.102 keeps
the dated measurement.

**The cross-sectional pair was measured, not guessed.** `docs/research/cross-sectional-detector-2026-11-20.md`
contains the bake-off: six candidates on the same 19-feature vector, the same walk-forward folds
and the same conformal rule. kNN at k = 10 was the only candidate whose false-alarm rate held
within a quarter of a point of target in *every* coverage stratum (1.05% / 1.07% / 1.24% at a
0.01 target); LOF is the only genuinely independent score (ρ = −0.08 with Isolation Forest,
against kNN's +0.46). Both enter the ensemble at the neutral weight of 1.0, and the shipped
`max` fusion does not read weights at all.

Scores are fused (default `max`) and gated by `BASE_THRESHOLD` **on a calibrated scale**. Each
detector's raw score is mapped by `score × BASE_THRESHOLD / threshold_i`, so its own conformal
threshold lands exactly on 0.35. Without this, the bar's meaning moved with the membership:
measured live on 2026-11-20, KNN alone (whose 1% threshold sat at 0.962) exceeded a raw 0.35 on
**79.2%** of windows, while the same 0.35 over five members was a different quantile again. With
the map, 0.35 is each detector's own measured 1% point whether one, two or five detectors are
eligible. The raw fused score is still what severity, confidence and the stored anomaly score read;
only the alert comparison uses the calibrated scale.

**Fusion reads ELIGIBLE detectors only, and an ineligible one is *removed*, not zeroed.** A model
is excluded when a measurement is missing; it is not counted as a zero (a zero still drags a mean
fusion down, and in `max` fusion it would look identical to an opinion of "normal").

**Eligibility is measured evidence, not a model card.** `ml_model_cards` is a hand-curated
registry: it is written only when somebody edits a card, so it goes stale the moment the engine
retrains, and on 2026-11-20 it had no row at all for the two cross-sectional detectors — which
barred them by **absence**. A card is documentation of intent (owner, approved version, rollback)
and cannot veto a working detector. A detector is eligible when all three hold, each measured by
the engine:

1. **fresh** — its newest calibration row is no older than `RETRAIN_EVERY_H` plus
   `ML_CALIBRATION_GRACE_H` (the calibration pass runs after the retrain it measures);
2. **covered** — that row recorded `coverage_observed` / `coverage_expected`; NULL means coverage
   was never measured, and an unmeasured vector is not evidence;
3. **in budget** — its realised false-alarm rate's **Wilson 95% upper bound** is within
   `ML_TARGET_FAR × ML_ELIGIBILITY_MULTIPLE` (0.01 × 3 = 0.03 by default), judged only once the
   validation sample reaches `ML_ELIGIBILITY_MIN_WINDOWS` (300). Below that floor the state is
   `calibrating (n=X, need Y)` and the detector keeps whatever state it held: 5 exceedances in 110
   windows is 0.045, but its interval is 0.020–0.102, so it cannot separate the 1% target from the
   3% tolerance. At n=300 a detector realising the 1% target has an upper bound of 2.9%.

A failing check names itself in the Detectors table (`not contributing: coverage not recorded`,
`not contributing: FAR 0.083 (95% CI 0.058-0.117, n=420) above the 0.030 tolerance`), so the
operator is sent to the right remedy. Every FAR is printed with its sample size and interval. A
model with no calibration row is never eligible.

### Promotion and the alert budget

**Being calibrated is not the same as being safe to add.** Measured on the live 24-hour
population, admitting both cross-sectional detectors moved the share of host-windows at or above
`BASE_THRESHOLD` from **25.6% to 42.8%** — the page load doubles, from an automatic decision
nobody made. So a calibrated detector is promoted only when the fused alert rate *with* it stays
inside `ML_FUSED_ALERT_BUDGET`:

- the budget is **30%** by default (`ML_FUSED_ALERT_BUDGET`), which is the measured 25.6%
  baseline plus headroom and **below** the measured 42.8% doubling. It is a policy number and
  belongs to the operator, not to the distribution.
- the rate is measured on `ml_window_scores` over `ML_FUSED_BUDGET_HOURS` (24 h), paired: only
  windows where every compared detector scored. It compares the max over the incumbent members
  with the max including the candidate, at `BASE_THRESHOLD`.
- a detector that would push the rate over budget reads `calibrated, held for budget (fused
  42.8% with it vs 25.6% without; budget 30.0%)`. It is **promoted automatically** on a later
  sweep once the rate fits — no approval, no stored flag.
- a promotion under budget also needs `ML_FUSED_BUDGET_MIN_WINDOWS` (200) behind it: a hold is
  safe on a small sample, a promotion is a claim.
- the guard never demotes an incumbent. Dropping a working detector is not a budget decision; it
  is a detection outage. A stale detector still falls out, because freshness is evidence, not
  seniority.

The Detectors panel states the budget, the bar and the number of windows it was measured over
beside the rows it judged.

**Severity escalation requires independent corroboration and material evidence**:
at least two *families* must agree (Isolation Forest and its Gradient Boosting
student are one family; KNN distance, LOF and the Adaptive Baseline are three separate
families), and the window must carry a material deviation, a structural signature (e.g. a
zero-byte port scan), or true novelty. A strong score alone is not enough — a high score is
a ranking, not an incident. Rows that do not clear the gate stay visible at a
lower severity with their reason; they are not deleted. This gate exists because
measurement showed a 90-false-positive storm without it.

### Coverage-stratified calibration

A host-window whose Zeek row never arrived is not a different *kind* of observation, but every
cross-sectional score built on its shorter vector is systematically **smaller**. Measured before
this change: with one pooled threshold, partial-coverage windows alerted at **0.00%** while fully
observed windows alerted at **2.3–2.5%** — 35% of the population was silently unalertable while
the headline rate looked healthy.

The calibration key is therefore the **coverage stratum** (`19/19`, `16/19`, `8/19` on this
deployment), never the model:

- `weirvern/models/calibration.py` fits a conformal threshold per stratum from `(score, stratum)`
  pairs. It does not know which detector produced a score; a model registers how its stored rows
  map to a key (`ScoreContract`), and the generic coverage contract is the default.
- The scorer grades each window against **its own stratum's** reference quantiles, so a partial
  window at its stratum's 99th percentile is as alertable as a full window at its own.
- A stratum with fewer than **400** reference windows cannot resolve a 1% budget (split-conformal
  needs a calibration half of ≥199 scores for the rank to sit below the maximum). It explicitly
  **falls back to the pooled threshold** and says so in its row — the fallback is written, not
  inferred from a missing row.
- The Detectors table reads the pooled row only; per-stratum measurements are stored with
  `scope = 'coverage'` and `subject = '<observed>/<expected>'`, so the table's status and
  eligibility still answer one question with one number.

### Ripples do not consume detector scores

Ripples are computed from **raw telemetry channels** (bytes, packets, ports, timing, graph
relationships) and stay that way deliberately: independence from the models is the point, and a
model score feeding a channel would turn one observation into two. The only place the two meet is
the anomaly page's **corroboration block**, which is display, not input. Do not wire a detector
score into `weirvern/models/ripple*.py`.

### The two ends of a flow

`flows_window` is keyed on a flow's **source**, so a host that only receives traffic — a file
server, a NAS, a printer, a camera — had no flow evidence at all. Roughly half the addresses on a
LAN are in that position at any moment. Schema `061` adds `flows_window_endpoint`, keyed on
`(window_start, host_addr, direction)`:

| direction | `host_addr` | `unique_peer_ips` |
|---|---|---|
| `out` | the flow's source (the same population `flows_window` holds) | distinct destinations |
| `in` | the flow's destination | distinct senders |

A **parallel table, not a new column**: adding `dst_addr` to `flows_window` would change its grain
from one row per host-window to one row per host PAIR, silently redefining every aggregate that
reads it. The endpoint table is fed by `flows_window_endpoint_mv`, a `UNION ALL` of the two
endpoints over `weirvern.flows`; each flow contributes one row per direction, so the outbound
side can be checked against `flows_window` for exact parity and the inbound side is new
information rather than a recount. The directions are one FAMILY in the ripple layer: inbound
volume cannot corroborate outbound volume, because they are the same flow records seen from
opposite ends.

The ripple **inbound** channels read it through `flow_windows.folded_endpoint()` (merge states plus
the time predicate in one select, the rule that keeps part pruning working). The three original
flow channels stay on `flows_window`: it holds the same outbound population with a longer retained
history, and moving them to the younger endpoint table would cut their baseline and silently stop
their evidence. The **detection sweep, candidate matrix, specialists, scope profiling and
host-hour detector also stay on `flows_window`**: their unit is the per-host outbound window their
models were fitted on, and changing that population mid-flight would reshape every baseline and
score. The endpoint table is a ripple and Network-view source, and its retention is on the same
derived window as everything else.

### Shadow calibration and challengers

The production ensemble is the five detectors above. The newer layer is
read-only and cannot create or change an alert:

- **Calibration** measures a requested false-alarm budget against the stored
  detection population and reports the observed rate per model and per coverage stratum; it is
  not wired to the alert path.
- **HDBSCAN** is a density challenger scored on the same host-window matrix; a
  candidate must beat the production model at the same alerts/day before it can be promoted. Its
  slot is no longer "replace the removed density detector" — that detector is gone and its
  replacement is measured.
- **Matrix Profile** records shape discords that the per-window tabular detectors
  cannot see, and **Page-Hinkley** records regime changes. Both are evidence
  channels, not alert sources.

The Models tab reports each shadow channel's row count, coverage and freshness
independently; an unreadable channel is named, never shown as an empty success.

### Detection quality, measured

Nothing ships on faith: detection quality is a **gated CI job**. The harness seeds
a port scan, a beacon and an exfiltration spike into a scratch database, runs the
real detection sweep against the real materialized views, and asserts the **final
verdicts** — the scan reaches `critical`, the beacon `medium`, the spike
`critical`, and a seeded-benign host stays quiet. A negative control (the same
run with no attacks seeded) proves the harness can actually fail, because a guard
that cannot fail is decoration.

On a live deployment the same idea is reproducible by hand — see
[Verifying that detection actually works](#verifying-that-detection-actually-works).

### What is monitored: operator-declared network scopes

A per-host baseline is only meaningful for a stable host population. `src_addr` on a NetFlow
aggregate can be an internet peer or a scanner, not a monitored asset. Scope is therefore an
operator declaration, not an RFC1918 guess:

| Field | Meaning |
|---|---|
| CIDR | IPv4 or IPv6 network, normalized before storage |
| Label | `internal`, `vpn`, `dmz` or `external` |
| Monitored | whether hosts in this scope are eligible for per-host baselines and alerts |
| Policy | **per-host** (`full` in the API), `aggregate`, `observe` or `off` |

Overlaps resolve by longest-prefix match; ties are broken deterministically. An address outside
every declaration is **unclassified** — a visible configuration gap, not an implicit answer.

When no scopes are declared the worker preserves the legacy unscoped behaviour, so an upgrade
cannot silently stop alerting. Once declarations exist, only monitored scopes are scored;
unmonitored and unclassified traffic is still collected and shown in Weirlings, but it does not
create per-host alerts. Settings → **Monitored networks** edits the declarations; Weirlings →
**Network coverage** shows the same scopes, their 24-hour host/alert counts and the unclassified
remainder.

### What the models see: NetFlow *and* Zeek

Every model trains and scores on features from **both** sensors. The NetFlow half describes
volume and breadth — bytes, packets, destination and port diversity, time of day. The Zeek
half describes **what the traffic is**, which volume alone cannot express:

| Zeek feature group | What it adds | Example |
|---|---|---|
| Connection-state mix | `s0_ratio`, `rej_ratio`, `completed_ratio` | A measured host-window: 89 connections, **88 unanswered SYNs**, zero response bytes. NetFlow reports modest traffic; the state mix is unmistakably a scan. |
| DNS behaviour | query entropy and length, NXDOMAIN and no-answer ratios | Tunnelling and DGA show as high-entropy, long, frequently-failing lookups |
| DNS shape (v4) | unique-query ratio, maximum entropy, query-length spread, TXT/NULL ratios, answer count, new-domain ratio | A single high-entropy tunnel does not disappear into a mean; DGA shows as many one-off names and NXDOMAIN bursts; domains never queried by this host before are the DNS analogue of a new TLS client |
| Service variety | distinct protocols, and novelty against the host's own baseline | A host that begins speaking something it never has |
| TLS | distinct JA4 fingerprints, modern-version ratio | A client changing TLS stack, or downgrading |
| Zeek's own signals | notice and weird counts | A second opinion on the same traffic |
| L2 identity (dhcp) | MAC and server counts, lease duration | The only log with hardware identity — a MAC persists across lease renewals where an IP does not, so a per-host baseline keyed on IP loses its subject every time the lease turns over |
| Certificates (x509) | self-signed, weak-key and short-validity ratios | `ssl.log` stores fingerprints only, so it cannot say whether the certificate behind one is self-signed, expired, or 1024-bit |
| Encapsulation (tunnel) | tunnel event and type counts | The existence of the row is the finding; `conn.log` records that a connection is tunnelled but never what kind |
| QUIC | QUIC share of the host's TLS-like traffic, SNI count | QUIC never reaches `ssl.log`, so a host that moves its C2 to QUIC was previously unnamed |
| Directory (ldap_search) | search count, distinct filter shapes, result counts | Enumeration is defined by filter content, and no other log exposes directory queries at all |
| SSH authentication | attempt counts and failure **ratio** | The clearest brute-force signal on a tap — a failed password is a few bytes each way, indistinguishable from a keepalive in NetFlow |
| HTTP shape | URI entropy, error ratio, POST ratio | Encoded or high-entropy paths are how simple C2 hides and how data is smuggled through a query string; a host whose requests are overwhelmingly 404 is enumerating paths |
| File transfer profile | count, mean/max size, MIME variety | NetFlow byte totals cannot distinguish one 500 MB transfer from 500 transfers of 1 MB |
| Graph relationships (v4) | fan-in, destination concentration, peer rarity, reciprocity, new-peer ratio | Fan-in is the reverse direction — a workstation that starts receiving connections from many hosts has changed role. NetFlow's `unique_dst_ips` is only fan-out. |

Three design points matter when reading the numbers:

- **`zeek_present` is a feature in its own right.** Zeek and NetFlow are separate sensors and
  may observe different hosts — measured on a test deployment: 91 NetFlow hosts against 35
  Zeek hosts with an overlap of **2**. Without a presence flag the models would learn that
  most host-windows are defined by empty features, which is a fact about the deployment
  rather than about the network. Absence is therefore distinguishable from "observed, and
  nothing unusual".
- **Every ingested table feeds the models.** An audit found `zeek_http`, `zeek_files` and
  `zeek_ssh` were mapped, ingested, stored — and read by no query, no feature and no view.
  Three tables' worth of traffic collected and discarded while the deployment looked complete.
  The feature set has grown from 18 columns to 77 in the full IF/GB vector (63 of them Zeek),
  and `tests/test_ml_table_coverage.py` keeps every table read by *something*.
- **The join is LEFT, on `(5-minute window, host)`.** An inner join would silently drop every
  host Zeek did not see; joining on host alone would compare a five-minute window against all
  of that host's history. `weirvern status` reports the actual coverage, and the Adaptive
  Baseline warns when no host has a Zeek behavioural baseline — i.e. when it is silently
  running volume-only.

### The web GUI

**Accounts and roles**, served from the worker image on **HTTPS 443 via Traefik** (the base
NodePort 30088 is break-glass only). It cannot start,
stop, or apply anything: a monitoring surface that can mutate the thing it monitors turns a
UI bug into an outage — but it does manage the deployment's configuration and its own
accounts, and both are gated.

**Setup is one step.** The GUI creates a default `admin` account on its first startup and
prints the generated password **once** to the pod log:

```
kubectl -n weirvern logs deploy/weirvern-gui | grep "initial admin"
```

**Capture it before deploying a newer tag.** The password is printed only by the pod that
created the account — rolling the GUI replaces that pod and the log with it. (If it was
never captured: the sign-in screen carries a "Lost the admin password?" door that accepts
the operator token, and from there Settings → Users → **Reset password** mints a new one.)

**The operator token is generated at install and printed once**, at the end of the install
summary. It is the only recovery path on a deployment with no email, so keep it:

```bash
# read it again later (it lives in weirvern-secrets)
kubectl -n weirvern get secret weirvern-secrets \
  -o jsonpath='{.data.WEIRVERN_GUI_TOKEN}' | base64 -d; echo
```

If it is **empty**, the "Lost the admin password?" door will not accept anything — an empty
token disables writes rather than opening them, which is the safe default. Set one:

```bash
# 1. write the token
kubectl -n weirvern patch secret weirvern-secrets --type merge \
  -p "{\"data\":{\"WEIRVERN_GUI_TOKEN\":\"$(openssl rand -base64 24 | base64 -w0)\"}}"

# 2. RESTART THE GUI -- this is not optional and not merely tidiness
kubectl -n weirvern rollout restart deploy/weirvern-gui

# 3. VERIFY the running pod actually holds it, before you need it
P=$(kubectl -n weirvern get pods --no-headers | grep gui | grep Running | awk '{print $1}' | head -1)
kubectl -n weirvern exec $P -c gui -- printenv WEIRVERN_GUI_TOKEN | tr -d '\n' | head -c 8; echo
```

**Step 2 is the one that bites.** The token reaches the container through `envFrom`, which
injects values **at container start** — so between patching the Secret and restarting the
deployment, the running pod still holds the OLD value and **the token you just set is
rejected**. Measured on a live deployment: a Secret patched 21 seconds after a pod started
left that pod answering 401 to its own token until it was restarted. Without step 3 you
discover this while already locked out, and the natural conclusion -- "the token does not
work" -- is wrong.

Treat it like a root password: it grants admin with no account. An install that predates
this provisioning the token can be given one the same way.

As a last resort, with neither the password nor the token, a new one can be set directly
in the account store from the GUI pod. Change `must_change` is forced, so the account is
held at the password gate until the owner replaces the temporary value:

```bash
P=$(kubectl -n weirvern get pods --no-headers | grep gui | grep Running | awk '{print $1}' | head -1)
kubectl -n weirvern exec $P -c gui -- python -c "
from weirvern.admin import users
from weirvern.admin.cluster_config import ClusterConfig
store = users.UserStore(ClusterConfig(configmap=users.USERS_CONFIGMAP))
store.load()
store.set_password('admin', 'TEMPORARY-PASSWORD', must_change=True)
"
```

Sign in with `admin` and that password, choose your own password when prompted (the change
is forced), then add accounts from **Settings → Users**. There is no email on this
deployment: to help someone who lost their password, an admin uses **Reset password** on
their row and hands over the temporary one, which the account is forced to change at next
sign-in.

Two roles, deliberately only two:

- **admin** — reads everything, changes settings, manages accounts.
- **viewer** — reads everything, changes nothing. Settings render as values with no controls.

Reads require a signed-in account; writes require an admin. The deployment's operator token
(in `weirvern-secrets`) still works everywhere an admin does — it is the break-glass
credential that recovers a lost admin account and drives automation, so accounts can never
lock a deployment out of its own configuration. Accounts live in a `weirvern-users`
ConfigMap, created on first startup; password hashes are scrypt with a per-user salt, and
sessions are in memory, so a restart signs everyone out.

**Per-token credentials** are the third way in, and the one to use for automation. An admin
signs in and mints one under **Settings → Access and security → API tokens**. It carries one of
the same two roles — a `viewer` token reads everything and writes nothing; an `admin` token is
admin-equivalent — and it is revoked individually, taking effect on the next request. The secret
is returned once, at creation; the `weirvern-tokens` ConfigMap holds only its SHA-256 digest and
an eight-character display prefix. A token **cannot** mint or revoke tokens or change a role:
those require a signed-in admin session, so a leaked token cannot protect itself from revocation.
Treat a token like a password and hand it to the automation that needs it, not to a person who
could have an account.

| View | What it answers |
|---|---|
| Health | **Sensor state** (mode, whether it is running, heartbeat age, intercept status), the health probes, ingestion trend, table sizes, and the **alert audit** — every alerting decision, including what was suppressed and why, paged 15 at a time like the inventory and stating when the list is capped. Sits between Models and Settings; still the landing view |
| Ripples | The operator's primary reading: one host and one hour per ripple, with the explanation sentence naming each channel, its value, its baseline median, its scale and its p-value. Click through to the evidence, then to the model anomalies in the same window, which are corroboration rather than the verdict. The full model-anomaly queue — score, agreement, review state and the evidence drill — stays on the same page below the ripples |
| Assets | The **asset inventory**: every host seen, searchable, with bytes, services and anomaly counts; click an address to drill down |
| Network | Every host-to-host connection as a graph — a **force map that settles deterministically** (no randomness, fixed cost: same window, same map), draggable with a Re-settle control, and hosts sit in **IP TTL hop-distance rings** from the sensor wherever the flow records carry the field; **select any number of hosts to track only their connections** |
| Netflow | Volume, protocol mix, top ports, destination spread; **click a protocol or port bar to see the host-to-host pairs behind it** |
| Zeek | Per-log volume, a trend by log, observed services, DNS names; **click a log to see which hosts it contains**, then a host to drill into it |
| Weirlings | The **fleet**: every sensor this hub expects to hear from, compared against what it has actually heard. A weirling is any additional sensor feeding this hub from elsewhere in the network. The point of the view is the distinction every other surface collapses: **you registered a sensor and it never said anything** versus **you have no sensors** (opposite facts that both render as an empty table). Five states, each needing a different action: *alive*, *stale* (it ran and stopped), *never seen* (it never came up), *unregistered* (something is feeding you that nobody declared), and *disabled* (not reporting is expected, so it is **not** raised as a problem). Registering records the expectation only, since nothing here can reach the remote box, and a sensor begins reporting when its own exporter points at this hub. Revoking retires a registration while keeping the row, so "was this ever covered?" outlives the cleanup |
| Models | Training history, score distribution, model agreement, per-feature deviations — and **near misses**: the windows that scored close to the bar, or cleared it and were stopped by the agreement gate. The surface a threshold change should be judged against |
| Identity | What each host **is**, derived passively from traffic already seen — nothing is probed and nothing is sent. Sources are application banners (`software.log`, which names its own platform), DHCP leases, NIC vendors and TLS ClientHello fingerprints. Confidence reflects how many **independent** sources agree, so a hostname convention alone reads as `low`. A host whose sources **contradict** each other is flagged rather than smoothed over — a renamed machine, a dual-boot host or a spoofed hostname all look like that, and it is a finding. Coverage is stated as a fraction of hosts seen, so a small numerator cannot mislead |
| Sluice Gate | What **passes**, and what does not: block traffic by address, port or direction, and see whether the gate is holding. Blocking is compiled into kernel sets on the sensor, so it does not slow what it inspects, and the ledger records which path it actually holds — `channel`, `siphon`, or `none`. Every rule is **bounded** — this system does not create permanent blocks, and a rule that has lapsed shows as lapsed rather than silently continuing to enforce. Live, lapsed and revoked rules look **different**, because "this rule exists but is not enforced" is a different statement from "this rule does not exist". Refused on purpose: a rule with no address, a port without a protocol, the management interface, the sensor's own address, and anything covering the whole internet. Detections may block too, under a criticality policy that is **off by default** — the operator decides whether model output is grounds to stop traffic |
| Evidence | The raw flows and Zeek records inside a specific alert's window |
| Settings | The **effective configuration** — sensor mode and interfaces, detection thresholds and cadence, reverse-DNS mode, ClickHouse target, namespace, version — each setting rendered as the control that changes it (toggle / dropdown / bounded number) with an **ⓘ** in a circle that opens a plain-language explanation, plus **Account** (change your password) and **Users** (admin-only account management). Secrets show as `(set, N chars)` or `(not set)`, never in value |

Three cross-cutting rules, each of which exists because its opposite shipped once:

- **An endpoint that could not be read is not an endpoint with nothing on it.** The Assets and
  Network views name the sources they failed to read, so a short list is never mistaken for a
  quiet network.
- **A zero is stated with its reason.** A Zeek log with no rows in the window is `idle`
  (widen the window) or `never written` (check whether the traffic exists on the segment) —
  measured on a real deployment, three logs held 544, 245 and 394 rows between them but none
  inside the default window, and the panel showed `0` for each while reporting the truth.
- **Absent is not the same as empty.** The near-miss panel says "the table does not exist on
  this deployment yet" rather than rendering an empty list; "nothing nearly alerted" is a much
  stronger claim and a different fact.

**Hostnames come from reverse DNS, and the address is always shown alongside the name.** By
default only private addresses are resolved, so the lookup stays on your network; set
`WEIRVERN_REVERSE_DNS=all` to resolve public addresses too, which sends each one to your
resolver. `WEIRVERN_REVERSE_DNS=off` disables lookups entirely. Results are cached with separate
positive and negative TTLs, and every lookup is bounded by a socket timeout so a slow resolver
cannot stall a page render.

Some tables are **live and empty on this deployment**, which is a fact about the network rather
than the code: `zeek_tunnel`, `zeek_quic` and `zeek_ldap_search` have no traffic on this segment, so
their tables are correctly zero. `zeek_dhcp` has rows, which is the useful check — it is the one
Tier-3 log this segment produces, and it ingests. See
[Deployment](#deployment) for how to confirm this on your own network.

The **Models** view is deliberately built from data that is deep at any volume — training
runs, every score including sub-threshold ones, and the per-feature deviation JSON — rather
than from a scatter of the anomalies themselves. A young deployment has very few anomalies,
and a chart of three points is indistinguishable from a rendering bug. Every panel either
draws real data or states in words what is absent and why.

### Alert hygiene

- Severity tiers (critical/high/medium/low) from fused score and agreement.
- Per-source cooldown + global hourly cap → no alert storms.
- Dedupe keyed on `(src_addr, window_start)`; resend only on re-observation.
- Every send recorded in `alert_events` for audit and testing — and surfaced: the Health tab's
  alert audit shows every decision (outcome, host with its resolved name, score, and the message
  the decision was about), counting suppressed alerts separately from the log-only path (a
  configuration state, not a withheld alert), paged 15 at a time. The fetch is capped, and the
  note says so — a full page with no caveat would read as "this is everything".
- Review dispositions (`ack` / `resolved` / `false_positive`) are persisted per anomaly, which
  is also the label stream a future feedback loop needs.

### Tuning

```bash
weirvern tune
```

The guided tuner shows the alert-rate implication of a threshold change against
the last 7 days of real data before you commit to it. To tune against almost-thresholds
instead — the windows that *nearly* alerted — cross-reference the Models view's near-miss
panel, which records both the "scored just under the bar" and the "cleared the bar, blocked
by the agreement gate" cases.

---
