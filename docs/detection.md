# Detection and alerting

*Part of the [Weirvern](../README.md) documentation.*

What the detectors are, what they see, what an alert
means, and how the console presents it.

## Detection and alerting

### The ensemble

Four detectors, each contributing a normalised 0–1 score:

| Detector | What it catches | Notes |
|---|---|---|
| Isolation Forest | Multivariate outliers across the full feature vector | Calibrated against its own training distribution |
| Gradient Boosting | Non-linear patterns, trained on IF's labels (a distillation) | Probability calibrated; class-imbalanced weighting |
| DBSCAN | Dense clusters vs. outliers — port diversity, fan-out, TLS fingerprints | Score calibrated against the measured distance distribution |
| Adaptive Baseline | Per-host percentile deviation (p95/p99/p999) | Learns each host's normal; needs ≥10 observations |

Scores are fused (default `max`) and gated by `BASE_THRESHOLD`.

**Severity escalation requires independent corroboration and material evidence**:
at least two *families* must agree (Isolation Forest and its Gradient Boosting
student are one family; DBSCAN and the Adaptive Baseline are separate), and the
window must carry a material deviation, a structural signature (e.g. a zero-byte
port scan), or true novelty. A strong score alone is not enough — a high score is
a ranking, not an incident. Rows that do not clear the gate stay visible at a
lower severity with their reason; they are not deleted. This gate exists because
measurement showed a 90-false-positive storm without it.

### Shadow calibration and challengers

The production ensemble is still the four detectors above. The newer layer is
read-only and cannot create or change an alert:

- **Calibration** measures a requested false-alarm budget against the stored
  detection tail and reports the observed rate; it is not wired to the alert path.
- **HDBSCAN** is a density challenger scored on the same host-window matrix; a
  candidate must beat the production model at the same alerts/day before it can
  replace DBSCAN.
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

### MITRE ATT&CK mapping

Every anomaly is mapped to the ATT&CK techniques its measurements actually support, and the
mapping is presented as a **hypothesis, never a finding**:

```
ATT&CK: consistent with T1046 Network Service Discovery (high); also T1018
  - 300 distinct destination ports (threshold 100)
  - port entropy 7.90 (threshold 3.0)
  - 0 bytes out, so no data was moved
  - network visibility: STRONG. Many destination ports from one source with little or no
    return traffic is the signature itself.
  - 284.0 bytes out is not evidence of exfiltration
```

The evidence lines are the point. "T1046" alone reads as a conclusion and stops an analyst
looking; the measurements can be checked, argued with, and dismissed. The `network visibility`
line states what a tap can and cannot see for that technique, and the block is **not rendered
at all** when nothing matched -- an empty frame or an explicit "no technique" line would read as
a clearance, and absence of a mapping is not absence of an attack.

**18 techniques** are mapped, across Discovery, Lateral Movement, Execution, Exfiltration,
Command and Control, Credential Access, Defense Evasion and Initial Access. Techniques that
require endpoint telemetry (process injection, credential dumping, registry changes) are
deliberately excluded and listed with the reason, so "not mapped" is never confused with
"not observable".

The rules are weighted towards the ways a mapping **overstates**, because that is the damaging
direction. Each of these is a test:

| Would be wrong | Why it does not fire |
|---|---|
| Busy server → port scan | The zero/low-byte qualifier is required. 400 ports moving 5 MB is a server. |
| 900-port scan of one host → Active Scanning | T1595 is reconnaissance of a **range**; measured in hosts, not ports. |
| Any DCE/RPC call → service execution | Only a service-control **operation** (`CreateServiceW`) counts. A `NetShareEnum` is low-confidence lateral movement at most. |
| Large transfer → exfiltration | A **ratio** is required. A 50 MB two-way transfer is a backup, not exfil. |
| Many DNS queries → tunnelling | Entropy **and** a failure ratio. Normal browsing is high-volume, low-entropy, answered. |

### What the models see: NetFlow *and* Zeek

Every model trains and scores on features from **both** sensors. The NetFlow half describes
volume and breadth — bytes, packets, destination and port diversity, time of day. The Zeek
half describes **what the traffic is**, which volume alone cannot express:

| Zeek feature group | What it adds | Example |
|---|---|---|
| Connection-state mix | `s0_ratio`, `rej_ratio`, `completed_ratio` | A measured host-window: 89 connections, **88 unanswered SYNs**, zero response bytes. NetFlow reports modest traffic; the state mix is unmistakably a scan. |
| DNS behaviour | query entropy and length, NXDOMAIN and no-answer ratios | Tunnelling and DGA show as high-entropy, long, frequently-failing lookups |
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
  The feature set went from 18 to 33, and `tests/test_ml_table_coverage.py` keeps every table
  read by *something*.
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

| View | What it answers |
|---|---|
| Health | **Sensor state** (mode, whether it is running, heartbeat age, intercept status), the health probes, ingestion trend, table sizes, and the **alert audit** — every alerting decision, including what was suppressed and why, paged 15 at a time like the inventory and stating when the list is capped. Sits between Models and Settings; still the landing view |
| Anomalies | Every anomaly with score, agreement and the "why" line — plus its **review state**: acknowledge, resolve, or mark false-positive, with an unreviewed-only filter. Click through to **evidence** |
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
