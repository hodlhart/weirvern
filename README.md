# Weirvern

<p align="left">
  <img src="docs/logo.png" alt="Weirvern" width="220">
</p>

**Network flow anomaly detection for Kubernetes.** Weirvern turns the NetFlow/sFlow your
network already exports — plus a Zeek sensor for the protocol layer — into per-host behavioural
baselines, flags the deviations that match real attack shapes, and shows a human *why*, with the
measurements that fired.

Current release: **0.17.22** · Runs on any conformant Kubernetes · No payload inspection · Alerts
via [Pushover](https://pushover.net), or log-only.

## What it does

Weirvern reads traffic and turns it into per-host behaviour, alerts with evidence, and — where you
allow it — kernel-level blocks. There are three ways to put it on a network, and choosing between
them is a question about your topology rather than about the software: a copy of the traffic is
safe and can stop nothing, standing in line is what makes blocking possible, and how you get in
line decides which NICs you need. The table after the three placements says it in one screen, for
the person holding the cables.

**`channel` — be the wire.** The box is plugged *in line*: one NIC faces upstream toward the
network, one faces downstream toward the device or segment being protected, and the two are joined
into a bridge. Traffic now passes **through** the box, and by default everything is forwarded
exactly as before — nothing is redirected, no address is forged, and the sensor keeps observing
(`SENSOR_MODE` stays `loch`). What the placement buys is a point where the **Sluice Gate** can drop
a packet: the kernel enforces the rules and forwards everything else. Put it anywhere you are
willing to have a box in the middle — between a segment and its uplink, between two switches, in
front of a lab — as long as you can re-route the cable run through it. It also does not need
anything exotic from the hardware: two ordinary NICs and the kernel's own bridge.

**`siphon` — redirect, without rewiring.** When you cannot (or will not) move cables, the sensor
can put itself in the path at layer 2: it answers ARP for the addresses it is told to intercept, so
the hosts (and the gateway) send their traffic to it, and it relays each packet onward in the
kernel. That is the same mechanism a man-in-the-middle uses, employed deliberately and briefly —
hence the gates: it is opt-in, it needs `NET_ADMIN` (which a passive sensor deliberately does not
have), a preflight refuses to start if the box cannot actually relay, and a **fail-open watchdog**
restores every forged mapping on stop, crash, or a stalled forward, with a hard self-destruct
deadline as the last resort. Nothing is decrypted: TLS sessions still authenticate end to end, and
this is a redirect, not an interception of content. Place it on a single flat segment you want to
watch in-line for a bounded time — a lab, a VLAN under investigation — with the sensor on that
broadcast domain.

**`loch` — watch a copy.** The default, and the one that cannot hurt anything: Zeek listens on a
promiscuous NIC fed by a switch SPAN/mirror port or a passive TAP. It only ever receives. Nothing
is in the path, nothing can drop or delay a frame, no payload is inspected — and that is also why
the Sluice Gate cannot enforce here: a rule compiled on this box would match traffic that never
crosses it. The gate says `degraded` and blocks nothing rather than pretending, which is the honest
behaviour for a mirror port.

**The hub** — the database, detection and the console — sits wherever you run Kubernetes, and its
management NIC is never a capture port. It needs no capture NIC of its own; it needs the sensors
and exporters to reach it.

### Placement, NICs, and what can enforce

| Placed as | NICs to dedicate | In the path? | Sluice Gate enforces? | Where the flow records come from |
|---|---|---|---|---|
| `loch` — mirror / SPAN / TAP | 1 capture NIC, promiscuous, `NET_RAW`. Never the management NIC. | No | **No.** Reports `degraded`; nothing it drops would have crossed it. | An **exporter** on the segment sends NetFlow/sFlow/IPFIX — to the hub, or to **this sensor**, which collects it (`WEIRLING_NETFLOW`) and ships it into the hub. See below. |
| `siphon` — ARP redirect | 1 NIC on the segment, promiscuous, plus `NET_ADMIN` | Yes, **while a supervised intercept is live** | **Yes, while it is live** — recorded as `enforcement: siphon`. When the intercept ends, the gate says so instead of holding. | Same as `loch`, plus `SIPHON_NETFLOW` meters the intercept while it is live. |
| `channel` — in-line bridge | **2 NICs** (upstream + downstream) joined into one bridge, plus `NET_ADMIN` | Yes, continuously — it *is* the wire | **Yes** — the intended enforcement placement, recorded as `enforcement: channel` once verified from the kernel (both ports on one bridge, forwarding, carrier up, bridge-nf in effect, and the node's FORWARD path admitting the bridge). | **Weirvern extracts its own**: `CHANNEL_NETFLOW` samples one port of the bridge and summarises it into IPFIX locally. No external exporter needed for the traffic it carries. |
| hub only | none (its management NIC is never a sensor) | No | No | From the exporters and sensors above. |

A box can play more than one of these roles, and the placement is a **setting**, not an install:
the same image runs the hub, and a sensor can move from `loch` to `channel` without being rebuilt.

A fleet makes that a per-**sensor** question. **Each weirling carries its own intercept plan** —
its mode, capture interface, segment, redirect address, gateway and targets — stored on its own
registration in the hub's registry, because the hub cannot reach a remote box's manifest. The mode
is toggled (and the plan edited) in that weirling's drill-down in the **Weirlings** view, with
**Sonar** surveying *that sensor's* capture port first; the sensor's own agent reads its plan every
refresh (about 30 seconds) and arms — or refuses — itself, inside its own deployment, through the
same supervised intercept the hub runs. An in-cluster weirling needs the opt-in capability patch
beside its unit manifest; one that has not been granted it refuses to arm and says so on its own
heartbeat, with the mode it was asked for and zero mappings, rather than a control that claims to
have worked.

A channel is still a `loch` sensor in the sense that matters — it observes, and it only stops what
a rule names.

**Flow records: who exports them.** The volume features and the per-host baselines are built from
flow records, and **any sensor can collect NetFlow**. Three ways the records arrive, and a
deployment needs only one of them:

- An exporter on the network sends NetFlow/sFlow/IPFIX **to the hub** (router, switch, hypervisor
  vSwitch) — the conventional arrangement.
- An exporter sends **to a sensor on its own segment** instead. Every sensor can run the hub's own
  collector, and with `WEIRLING_NETFLOW=1` its agent ships those records into the hub's `flows`
  table. A deployment can therefore collect from any segment that has a sensor on it, with no
  exporter pointed at the hub and no second transport to secure.
- Weirvern reads its own traffic where it stands: a `channel` samples a port of its bridge
  (`CHANNEL_NETFLOW`), and a `siphon` meters the segment it is intercepting while the intercept is
  live (`SIPHON_NETFLOW`). No exporter is needed for what they carry.

Zeek's behavioural features work in every placement; only the flow model depends on a flow source,
and the console states which is missing rather than drawing an empty chart that reads as a quiet
network.

**The console — what you look at.** Overview (health, workloads, freshest anomalies, top talkers) ·
Assets (a real inventory: names, vendors, OS families, per-host anomalies) · Network (a
deterministic force map of who talks to whom) · Anomalies with a **raw-evidence pivot** per alert
(flows, Zeek sessions, TLS records with their JA4 fingerprints, DNS, notices) · Models, including
**force a retrain** — it trains a candidate on the last window, reports what it found (and whether
the window already held detections, which a retrain would learn as normal) and waits for you to keep
or trash it · Flows (the raw flows themselves, filterable down to every field) · DNS (port-53
questions and answers, with a reverse lookup: which names pointed at an address recently, out of
what DNS actually answered) · Netflow (volume, protocols, ports, fan-out) · Zeek log volumes ·
Identity (passive OS identification, and a lookup by TLS fingerprint for "who else presents this
stack") · Weirlings (the fleet: registered-but-silent is a different fact from never installed, and
each weirling carries its own intercept plan — mode, segment, address, gateway, targets — which
that sensor reads and applies itself; this hub's own weirling carries its capture settings in the
same sheet) ·
Sluice (rules, domain blocklists imported from the internet or your own names, and every gate that
is enforcing, including the ones on other sensors) · **Blocked** (what has been caught — the
recorded name hits — and what is doing the catching: the live rules split by whether they block
or only alert, with the addresses a domain's name currently resolves to) · Settings (the
deployment's knobs — detection, Sluice, blocklists, storage — with bounds, help, and the restart
it costs).

**Detection — what the models conclude.** Four independently trained detectors — Isolation Forest,
Gradient Boosting, DBSCAN and a per-host Adaptive Baseline — fused into one score with a
corroboration gate for severity, over features from NetFlow *and* twelve Zeek logs including JA4 TLS
fingerprints. ATT&CK techniques are presented as hypotheses with their measurements, never as bare
conclusions. Quality is *measured*: a seeded-attack harness runs the real pipeline in CI and asserts
the final verdicts.

**Identity — what the hosts are.** Operating-system family from application banners, DHCP leases,
NIC vendors and TLS ClientHello fingerprints, derived passively: nothing is probed and nothing is
sent. Confidence counts how many independent sources agree, and contradicting sources are flagged
rather than smoothed over.

## Screenshots

> **Placeholder — screenshots land here before publishing.** The console runs on synthetic data
> (RFC 5737 addresses) for these: `scripts/extract_demo_payloads.js` pulls the same payload set the
> UI harness is proven against into `docs/demo/`, so every screenshot shows the real renderer
> rendering fake traffic. Planned: Overview, Anomalies with the gate action, Evidence with the TLS
> section, Sluice (gates + rules), the force map, and Identity with the fingerprint lookup.

> **WARNING**: This tool is for monitoring networks **you own or are explicitly
> authorized to monitor**. See [USAGE_POLICY.md](USAGE_POLICY.md). Unauthorized
> monitoring is illegal in most jurisdictions. You have been warned.

## Quick start

```sh
curl -fsSL https://raw.githubusercontent.com/hodlhart/weirvern/main/install.sh | sudo bash
# with in-path capability pre-provisioned (the mode is still switched in Settings):
curl -fsSL https://raw.githubusercontent.com/hodlhart/weirvern/main/install.sh | sudo bash -s -- --siphon
```

The full procedure — requirements, the checks that refuse to run, the sensor node's capture port
and the ConfigMap — is in [docs/deployment.md](docs/deployment.md).

### The deployment Secret

The installer creates it for you; by hand it is one command. `weirvern-secrets` holds the
ClickHouse password, the break-glass operator token, and the Pushover credentials (left empty
by default, which selects log-only alerting):

```sh
kubectl -n weirvern create secret generic weirvern-secrets \
  --from-literal=CLICKHOUSE_PASSWORD="$(openssl rand -base64 24)" \
  --from-literal=WEIRVERN_GUI_TOKEN="$(openssl rand -base64 24)" \
  --from-literal=PUSHOVER_USER_KEY='' \
  --from-literal=PUSHOVER_API_TOKEN=''
```

To read the break-glass token again later:

```sh
kubectl -n weirvern get secret weirvern-secrets \
  -o jsonpath='{.data.WEIRVERN_GUI_TOKEN}' | base64 -d
```

The worker and the schema Job read the Secret at start; see
[docs/deployment.md](docs/deployment.md) for the full procedure.

## Documentation

- [Architecture](docs/architecture.md) — workloads, the two sensor modes, the channel, TLS
- [Theme](docs/theme.md) — the console's visual system: principles, tokens, component recipes, phases
  fingerprinting, passive identity, and what this design does not scale to yet.
- [Deployment](docs/deployment.md) — requirements, one-command install, step by step, verify,
  upgrade, remove.
- [Detection and alerting](docs/detection.md) — the ensemble, what the models see, ATT&CK mapping,
  the console views, alert hygiene, tuning.
- [Operations](docs/operations.md) — the CLI, lifecycle, backups, key settings, troubleshooting.
- [Security and privacy](docs/security.md) — privileges, RBAC, data sensitivity, network exposure.
- [Development](docs/development.md) — repository layout, tests, and the gate.
- [Branding](docs/README.md) — the project mark and how the favicons are regenerated.

---

## License

MIT — see [LICENSE](LICENSE). Third-party components and their licenses are
listed in [NOTICE](NOTICE).
