# Weirvern

<p align="left">
  <img src="docs/logo.png" alt="Weirvern" width="220">
</p>

**Network flow anomaly detection for Kubernetes.** Weirvern turns the NetFlow/sFlow your
network already exports — plus a Zeek sensor for the protocol layer — into per-host behavioural
baselines, flags the deviations that match real attack shapes, and shows a human *why*, with the
measurements that fired.

Current release: **0.13.0** · Runs on any conformant Kubernetes · No payload inspection · Alerts
via [Pushover](https://pushover.net), or log-only.

## What it does

**Watches without touching the network — `loch`.** A Zeek sensor on a dedicated capture port (a
switch mirror), feeding per-host baselines. Nothing is in the path, nothing can drop a packet, and
no payload is ever inspected. This is the default and it is enough for everything except stopping
traffic.

**Steps into the path when you choose to — `siphon`.** Opt-in interception with a watchdog and a
measured recovery story, for the times you want the box between two segments (a lab, a choke
point). It is a deliberate, reversible act rather than a mode the deployment drifts into.

**Stays in the path and keeps enforcing — `channel`.** A bridge that forwards everything it does
not have a rule about — so it stays `loch` for visibility while the Sluice Gate drops exactly what
the rules name. The path it holds is read from the kernel, never inferred from configuration.

**Stops the traffic you decide to stop — the Sluice Gate.** Kernel-level blocks by address, port
and direction, bounded in time: a duration of `0` means *until revoked*, anything else is minutes,
and every rule is visible as live, lapsed or revoked because those are three different facts. The
operator's own auto-block threshold turns "this scored high" into "stop it" without anyone watching,
and a derived block always writes its reason — the one asked weeks later. Every alert row also
sends straight to the gate, with "all traffic from this host" or one service, pre-filled reason
included. One rule store, many gates: **any sensor that can enforce, does** — the hub and every
weirling with an in-line path install the same rules on their own segment, with the same verified
path checks, and a gate that has stopped reporting is shown as stopped.

**Sees what the models see — the console.** Overview (health, workloads, freshest anomalies, top
talkers) · Assets (a real inventory: names, vendors, OS families, per-host anomalies) · Network (a
deterministic force map of who talks to whom) · Anomalies with a **raw-evidence pivot** per alert
(flows, Zeek sessions, TLS records with their JA4 fingerprints, DNS, notices) · Models, including
**force a retrain** — it trains a candidate on the last window, tells you what it found (and
whether the window already held detections, which a retrain would learn as normal), and waits for
you to keep or trash it · Netflow (volume, protocols, ports, fan-out) · Zeek log volumes ·
Identity (passive OS identification, and a lookup by TLS fingerprint for "who else presents this
stack") · Weirlings (the fleet: registered-but-silent is a different fact from never installed) ·
Sluice (gates, rules, and the fleet's own gate states) · Settings (every knob with bounds, help
and the restart it costs).

**Knows what the models think — detection.** Four independently trained detectors — Isolation
Forest, Gradient Boosting, DBSCAN, and a per-host Adaptive Baseline — fused into one score with a
corroboration gate for severity, over features from NetFlow *and* twelve Zeek logs including JA4
TLS fingerprints. ATT&CK techniques are presented as hypotheses with their measurements, never as
bare conclusions. Quality is *measured*: a seeded-attack harness runs the real pipeline in CI and
asserts the final verdicts.

**Identifies hosts passively.** Operating-system family from application banners, DHCP leases, NIC
vendors and TLS ClientHello fingerprints — nothing is probed and nothing is sent. Confidence counts
how many independent sources agree, and contradicting sources are flagged rather than smoothed
over.

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

## Documentation

- [Architecture](docs/architecture.md) — workloads, the two sensor modes, the channel, TLS
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
