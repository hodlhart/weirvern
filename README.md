# Weirvern

<p align="left">
  <img src="docs/logo.png" alt="Weirvern" width="220">
</p>

**Network flow anomaly detection for Kubernetes.** Weirvern turns the NetFlow/sFlow your
network already exports — plus a Zeek sensor for the protocol layer — into per-host
behavioural baselines, flags the deviations that match real attack shapes, and shows a
human *why*, with the measurements that fired.

Current release: **0.6.7** · Runs on any conformant Kubernetes · No payload inspection ·
Alerts via [Pushover](https://pushover.net), or log-only.

**What you get**

- **Detections with evidence.** Port scans, C2-style beaconing, data-exfiltration spikes,
  credential attacks, lateral-movement patterns — each alert carries the per-detector
  scores, the adaptive threshold it crossed, and a MITRE ATT&CK mapping presented as a
  hypothesis with its measurements, never as a bare conclusion.
- **Two sensors, one model.** Volume (NetFlow) and behaviour (Zeek) each cover what the
  other is blind to. Every detector trains and scores on both.
- **A SOC surface that closes the loop.** A web console with accounts — admin and viewer
  roles — and an alert review lifecycle (ack / resolve / false-positive), a near-miss view for
  threshold tuning, and a complete alert audit — plus a CLI and a TUI for operations.
- **Fail-open by design.** The default mode is passive capture. In-path interception is
  opt-in, gated, and defended by a watchdog with a measured recovery story.

> **WARNING**: This tool is for monitoring networks **you own or are explicitly
> authorized to monitor**. See [USAGE_POLICY.md](USAGE_POLICY.md). Unauthorized
> monitoring is illegal in most jurisdictions. You have been warned.

---

## Contents

- [Capabilities](#capabilities)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Deployment](#deployment)
- [Operations](#operations)
- [Configuration](#configuration)
- [Detection and alerting](#detection-and-alerting)
- [Scaling and limitations](#scaling-and-limitations)
- [Troubleshooting](#troubleshooting)
- [Security and privacy](#security-and-privacy)
- [Development](#development)
- [License](#license)

---

## Capabilities

**Detect.**

- Four independently trained detectors — Isolation Forest, Gradient Boosting, DBSCAN and a
  per-host Adaptive Baseline — fused into one score with a corroboration gate for severity.
- Alert hygiene built in: per-source cooldown, global hourly cap, and dedupe on
  `(host, window)`.
- Detection quality is *measured*, not assumed: a seeded-attack harness runs the real
  pipeline in CI and asserts the final verdicts (see
  [Detection and alerting](#detection-and-alerting)).

**Investigate.**

- Every anomaly links to its raw evidence: the flows and Zeek records inside that alert's
  window.
- An asset inventory and a connection graph, both built to say "this source could not be
  read" rather than drawing an empty panel.
- Review dispositions (`ack` / `resolved` / `false_positive`) per anomaly, with an
  unreviewed-only filter — the workflow does not end at "here is an anomaly".

**Operate.**

- `weirvern` CLI: install checks, apply, wait, status, logs, lifecycle, tuning.
- A web console on a NodePort with accounts and two roles (admin / viewer) — it cannot start,
  stop, or apply anything.
- Health probes, ingestion trends, table sizes, and an alert audit that shows every
  decision the alerting layer made, including what it suppressed and why.

**Deploy.**

- Plain manifests and kustomize; no operators, no CRDs, no external services.
- ClickHouse for storage, with per-table TTLs so high-volume data expires while high-value
  records persist.
- The whole stack fits a single node; the sensor node needs a capture NIC (see
  [Requirements](#requirements)).

---

## Architecture

```
                     ┌──────────────┐      ┌───────────────────────┐
  NetFlow/sFlow ───► │   goflow2    │ ───► │  weirvern-worker     │
  (switches,         │  (collector) │ JSONL │  tail + parse         │
   pfsense, VMs)     └──────────────┘  file  │  batch insert         │
                                             │                       │
  mirrored packets ─► ┌──────────────┐  TSV   │                       │
  (SPAN / mirror      │     Zeek     │ ─────► │                       │
   port / NIC)        │  (sniffer)   │  logs  └──────────┬────────────┘
                      └──────────────┘                    ▼
                                             ┌───────────────────────┐
                                             │     ClickHouse        │
                                             │  flows (raw, TTL 3d)  │
                                             │  flows_aggregated +   │
                                             │    diversity/temporal │
                                             │  zeek_conn/dns/ssl/   │
                                             │    notice/… (Tier 3)  │
                                             │  netflow_anomalies    │
                                             │  alert_reviews        │
                                             │  near_misses          │
                                             │  ml_models, baselines │
                                             │  alert_events         │
                                             └──────────┬────────────┘
                                                        ▼
                                             ┌───────────────────────┐      ┌──────────────┐
                                             │  weirvern-worker     │      │ weirvern-gui │
                                             │  ensemble detectors   │ ───► │ SOC console  │
                                             │  (scikit-learn)       │      │ (accounts)   │
                                             └──────────┬────────────┘      └──────────────┘
                                                        ▼
                                             ┌───────────────────────┐
                                             │  Pushover (phone)     │
                                             └───────────────────────┘
```

### Workloads

| Workload | Kind | Image | Role |
|---|---|---|---|
| `clickhouse` | StatefulSet | `clickhouse/clickhouse-server:26.8` | Time-series store; aggregation via materialized views |
| `goflow2` | Deployment | `netsampler/goflow2:v2.2.6` | NetFlow v5/v9/IPFIX + sFlow collector, JSONL to a host path |
| `zeek` | **DaemonSet** | `weirvern-zeek:0.4.0` | Packet sniffer: conn/DNS/TLS/notice + Tier-1 logs from a NIC or mirror port |
| `weirvern-worker` | Deployment | `weirvern-worker:0.6.7` | Ingest (both sources), ensemble detection, Pushover alerts |
| `weirvern-gui` | Deployment | `weirvern-worker:0.6.7` | Web UI with accounts on NodePort 30088; admins edit, viewers read |
| `weirvern-prune` | **CronJob** | `weirvern-worker:0.6.7` | Enforces the per-component disk caps |
| `weirvern-schema` | Job | `weirvern-worker:0.6.7` | Applies the ClickHouse schema |

Three details of this table are Kubernetes design statements, not incidentals:

- **Zeek is a DaemonSet with `hostNetwork: true`** because a packet sniffer can
  only see traffic on the interface it is attached to — a property of the *node*,
  not of a pod. One sniffer per node is the only correct abstraction.
- **`goflow2` and `weirvern-worker` are node-pinned and single-replica** because
  the collector writes a file that the worker tails. See
  [Scaling and limitations](#scaling-and-limitations).
- **The Zeek image is DERIVED** (`zeek/Containerfile`), not upstream `zeek/zeek:lts`.
  Zeek 9.x core ships no TLS-fingerprint policy at all, so JA4 comes from a package
  installed at build time — and the FoxIO-licensed half of it is **deleted during the
  build**. See [TLS fingerprinting and licensing](#tls-fingerprinting-and-licensing).

### Sensor modes: `loch` and `weir`

`SENSOR_MODE` decides how Weirvern gets packets, and the two modes differ in whether
Weirvern can affect the network at all. That difference is the whole point of naming them.

| Mode | What it does | Can it affect traffic? |
|---|---|---|
| **`loch`** (default) | Passive capture. Zeek listens on a promiscuous NIC fed by a switch SPAN/mirror port or a passive TAP, and observes. | **No.** Still water. |
| **`weir`** | In-path intercept. ARP-forges the gateway mapping so chosen hosts send their off-link traffic to Weirvern, which relays it in the kernel. | **Yes** — Weirvern becomes a router, so it must fail open. |

```bash
weirvern mode                      # what mode is configured, and can it run here
weirvern mode --set loch           # passive (what most deployments want)
weirvern intercept --dry-run       # inspect a weir plan without touching the network
```

**`weir` is opt-in and gated** because failing in it means an outage, not a blind spot.
It requires `CAP_NET_ADMIN` (the passive sensor deliberately does not have it), and
`weirvern intercept` runs a preflight that refuses to start rather than poison a segment
it cannot relay for. `--dry-run` reports the blast radius — every host whose ARP cache
would be forged — and offers addresses that answered no ARP.

**The intercept is operator-triggered and `weirvern status` says so.** Setting
`SENSOR_MODE=weir` configures the *intent*; nothing in the cluster starts an intercept.
`weirvern status` therefore FAILS, with an explanation, when the mode is `weir` but no
intercept has a live heartbeat — because a config that reads "in-path" while redirecting
nothing is exactly the failure mode this project refuses to ship.

**`weir` is an L2/L3 redirect, not a TLS intercept.** Nothing is decrypted, no certificate
is substituted, and no payload is inspected. It is also not a man-in-the-middle in the
cryptographic sense: TLS sessions continue to authenticate end to end.

Safety in `weir` mode comes from the **fail-open watchdog**, which is required rather than
optional. It restores every forged mapping if the process is stopped, killed, or crashes,
and it fails open when forwarding stalls. Three properties are worth knowing before trusting it:

- **Poison frames refresh continuously.** ARP entries age, and a host's real gateway traffic
  refreshes them, so a single poisoning does not hold.
- **A quiet network does not trip it.** The watchdog only treats a still forwarding counter
  as a stall once it has actually *observed* forwarding working — an idle segment looks
  identical to a broken one, and conflating them makes `weir` flap.
- **There is a self-destruct deadline.** `--seconds` bounds the run; `--max-runtime`
  (default: `--seconds + 120s`) restores from inside the process even when no signal can
  ever reach it — the killed-`kubectl exec`-client case. The last resort is the kernel's
  own ARP expiry, measured on stock Linux defaults: **~1 minute** for a host actively
  using the network, and **seconds from that host's next packet** for an idle one.

### TLS fingerprinting and licensing

Weirvern ingests **JA4** TLS client fingerprints (`zeek_ssl.ja4`), and **ships no JA4+**.

The upstream package is split-licensed and the two halves are not interchangeable:

| Component | License | Permitted use |
|---|---|---|
| **JA4** (TLS client fingerprint) | **BSD 3-Clause** | any use, including commercial |
| **JA4+** — JA4S, JA4H, JA4X, JA4SSH, JA4T, JA4TS, JA4L, JA4D | **FoxIO License 1.1** | internal / academic only; **not** for monetization; methods patent pending |

The JA4+ submodules, the package's recorded JA4+ test output, the loader lines referencing
them, and the options that gated them are **deleted at image build time** by
`zeek/prune-ja4plus.sh`, which **fails the build** if any of that did not take — and equally
if JA4's own options were removed, since an over-eager filter would leave a sensor that runs
and fingerprints nothing.

It is deleted rather than switched off for a specific reason. The package gates its
submodules with `@if (JA4S_enabled) @load ./ja4s @endif`, and `@if` is evaluated **when the
file is loaded**, so a disable placed after the package loaded is silently ignored — measured
on a live sensor, `ja4s` populated in 28 of 28 records while the configuration claimed it was
off. That was fixable by load ordering, but it left licensed code in the image with only a
three-line sequence preventing its distribution. There is now nothing to mis-order.

Two consequences for operators:

- **The sensor image and the site policy must be deployed together.** The policy must not
  contain `redef FINGERPRINT::JA4*_enabled = F` lines any more — those options no longer
  exist, and Zeek aborts at startup with `"redef" used but not previously defined`.
- **`anthonykasza/ja4` is not used** despite being pure BSD-3-Clause, because it fails its
  own unit tests on Zeek 9.0.0 and cannot be installed. A fingerprint that is subtly wrong
  is worse than none: it silently fails to match threat-intel data.

### Why both sensors?

They are not redundant — each is blind to a different class of attack:

| | NetFlow/sFlow | Zeek |
|---|---|---|
| Sees | Volume, packet counts, 5-tuple, topology | Protocol behaviour: DNS queries, TLS/JA3 fingerprints, connection states |
| Blind to | Slow scans, DNS tunnelling, JA3-tagged C2, anything payload- or protocol-shaped | Nothing about volume — no idea a host moved 3.6 GB |
| Cost | Cheap (router exports it) | Needs a mirror/SPAN port or a NIC in the traffic path; CPU per packet |

Measured on the test rig: a DNS-tunnelling host showed **0 connections but 40
high-entropy queries** (entropy 4.82 vs 2.52 benign, max label 71 vs 15 chars) —
invisible in flow records. Conversely a 3.6 GB exfil spike is obvious in flows
and unremarkable in conn logs. Zeek's own `notice.log` (e.g. `Scan::Port_Scan`)
is ingested as independent corroboration for the ML ensemble, not as an alert
source of its own.

**NetFlow only?** Scale the Zeek sensor to zero before it ever runs, or skip it
entirely by removing `32-zeek.yaml` from `k8s/kustomization.yaml`. Nothing else
depends on it.

---

## Requirements

| Component | Version | Notes |
|---|---|---|
| Kubernetes | 1.24+ | Any conformant cluster: k0s, k3s, kubeadm, EKS/GKE/AKS |
| `kubectl` | 1.24+ | Has kustomize built in, so the `kustomize` binary is optional |
| Container registry | any | The worker image must be pushed somewhere the nodes can pull from |
| Storage class | dynamic | Defaults to `local-path` (k0s/k3s). Change one field for others |
| Python | 3.11+ | Only for the optional CLI/TUI — the deployment itself needs none |
| [Pushover](https://pushover.net) account | free tier | 7,500 messages/month. Optional — alerts can log-only |

**Cluster sizing.** Measured from the rendered manifests (not estimated), the
shipped workloads total **1.63 CPU / 3.09 GiB of requests** and **8.40 CPU /
12.25 GiB of limits**.

Sizing rule: **a node must satisfy the limits**, not the requests, because the
scheduler admits on requests but the kernel enforces limits. So the practical
requirement for a single node is a machine that can actually give out ~8 cores
and ~12 GiB, even though the shipped requests look like a Raspberry Pi job. That
asymmetry is deliberately generous on CPU (bursty training) and is the first thing
to tune downward if you are capacity-constrained: ClickHouse and the worker are
the two that matter, and both have slack in their limits.

A 4-core / 8 GB node will run Weirvern, but it will be tight and ClickHouse will
be the first thing to suffer. 8 cores / 16 GB is a more honest single-node
homelab target. Do not set ClickHouse's memory limit below 2 GB; it uses whatever
you give it, and below that its own memory-tracking starts refusing queries.

**Sensor node.** The node that carries the mirrored/SPAN traffic (and therefore
runs goflow2, Zeek and the worker) needs:

- **two network interfaces, with different jobs.** The capture port is a dedicated
  NIC fed by a switch SPAN/mirror port or a passive TAP; the management port carries
  the default route, SSH and the cluster API. They must not be the same NIC — see
  below.
- the capture NIC up, and (on a SPAN port) promiscuous
- a label so the workloads can find it: `weirvern.io/sensor-node=true`
- two host directories, group-writable by GID 10001:
  `/var/lib/weirvern/flows` and `/var/lib/weirvern/zeek`

### Why the capture port must be its own interface

A mirror/SPAN port receives **copies of other hosts' traffic**. The management port
only ever sees traffic addressed to this host plus broadcast, so pointing the sensor
at it produces a capture that looks busy and shows you almost none of the network.
This is not hypothetical: on the test deployment the sensor sat on a bridge member
inside a container, and **73% of what it captured was broadcast and multicast, with
no unicast from any other host**. Zeek reported no error.

Ask the sensor node what it has, and what to do about it:

```bash
weirvern interfaces --node <sensor-node>
```

That probes the node itself (via a throwaway hostNetwork pod, so it reports exactly
what Zeek sees) and prints a role for every interface — `mgmt`, `CAPTURE?`,
`bridge`, `virtual` — plus a verdict on the configured `ZEEK_IFACE` and a suggested
alternative. On a single-host install, `--local` inspects the machine you are on.

The command refuses to guess. If every interface is a bridge member, a veth, or the
management port, it says so and explains that the host needs a second physical NIC —
which is the usual conclusion on a virtualised host, because a hypervisor bridge
delivers only flooded traffic to a virtual port. Give the sensor VM/LXC a dedicated
physical NIC (PCI passthrough or a second, unbridged NIC) and mirror the switch port
to that cable.

---

## Deployment

### 1. Label the sensor node

This is the step that a first deployment most often skips, and the symptom of
skipping it is a healthy-looking stack that captures nothing.

```bash
NODE=your-node-name          # kubectl get nodes
kubectl label node "$NODE" weirvern.io/sensor-node=true
```

### 2. Create the host directories on that node

```bash
ssh "$NODE" 'sudo install -d -m 0775 -g 10001 /var/lib/weirvern/flows /var/lib/weirvern/zeek'
```

### 3. Build and push the images

A cluster cannot build an image, so this is a prerequisite rather than an
optional step. **There are two images**: the worker (which also serves the GUI
and runs the schema Job and the prune CronJob) and the Zeek sensor.

```bash
# podman or buildah — any OCI image builder your workstation has
podman build -t registry.example.com/weirvern-worker:0.6.7 .
podman push registry.example.com/weirvern-worker:0.6.7

# The Zeek image is DERIVED, and its build context is zeek/, not the repo root —
# prune-ja4plus.sh and verify-ja4.sh are COPYd from there.
podman build -t registry.example.com/weirvern-zeek:0.4.0 -f zeek/Containerfile zeek/
podman push registry.example.com/weirvern-zeek:0.4.0
```

The Zeek build **fails deliberately** if the JA4+ removal did not complete, or if
it removed too much and JA4 itself would no longer work. A licensing guarantee that
depends on someone reading a comment is not a guarantee, and the failure mode —
shipping licensed code in a distributed image — is invisible at runtime. See
[TLS fingerprinting and licensing](#tls-fingerprinting-and-licensing).

Then point the manifests at them — one place, no per-file editing:

```bash
cd k8s
kustomize edit set image weirvern-worker=registry.example.com/weirvern-worker:0.6.7
kustomize edit set image weirvern-zeek=registry.example.com/weirvern-zeek:0.4.0
cd ..
```

> **Deploy the sensor image and the site policy together.** The policy lives in a
> ConfigMap generated from `k8s/zeek/weirvern-local.zeek`, and it must not carry
> `redef FINGERPRINT::JA4*_enabled = F` lines — those options no longer exist in the
> image, and Zeek aborts at startup with `"redef" used but not previously defined`.
> If you upgrade the sensor without re-applying, the pod crash-loops.

> If the image is private, create an image-pull secret and reference it in
> `k8s/33-worker.yaml` and `k8s/50-schema-job.yaml` under `imagePullSecrets`.

### 4. Configure and deploy

```bash
git clone https://github.com/hodlhart/weirvern.git   # or your fork
cd weirvern

# Review what the cluster will run (no changes made):
kubectl apply -k k8s/ --dry-run=client

# Adjust the non-secret settings — most importantly the two sensor interfaces:
#   ZEEK_IFACE  the CAPTURE port (dedicated NIC fed by a switch mirror/SPAN)
#   MGMT_IFACE  the MANAGEMENT port (default route, SSH, cluster API)
# Check them against the node first: weirvern interfaces --node <sensor-node>
$EDITOR k8s/20-configmap-env.yaml

# Deploy. The namespace and every workload except the Secret come from here.
kubectl apply -k k8s/

# Now create the Secret — AFTER the apply, and never as a committed manifest.
# (A Secret manifest in the kustomization would be re-applied with placeholder
# values on every later apply, silently wiping these — see the SECRETS note in
# k8s/kustomization.yaml.)
#
# CLICKHOUSE_PASSWORD MUST BE NON-EMPTY. The official ClickHouse image locks the
# `default` user to localhost unless a non-default user or a non-empty password
# is configured, and an empty password puts it in that locked branch. The failure
# is misleading: every other pod is refused by a network filter and the error
# blames the password ("Authentication failed: password is incorrect"), while the
# same query works via `kubectl exec` (source 127.0.0.1). Generate one:
#
#   CLICKHOUSE_PASSWORD="$(openssl rand -base64 24)"
#
kubectl -n weirvern create secret generic weirvern-secrets \
  --from-literal=CLICKHOUSE_PASSWORD="$(openssl rand -base64 24)" \
  --from-literal=PUSHOVER_USER_KEY='<your user key>' \
  --from-literal=PUSHOVER_API_TOKEN='<your app token>'

# The worker and the schema Job read the Secret at start, so restart them now
# that it exists.
kubectl -n weirvern rollout restart deploy/weirvern-worker
kubectl -n weirvern delete job weirvern-schema --ignore-not-found
kubectl apply -k k8s/
```

> **Order matters.** The Secret is created by you, not by `apply -k`, precisely
> so that a later `apply` cannot overwrite it. If you create it *before* the
> workloads exist that is fine too — what matters is that nothing in `k8s/`
> defines it.

The schema is applied automatically by the `weirvern-schema` Job, which runs
the application's own `weirvern init-db` code path. There is no separate
schema-loading step and no initdb-directory mechanism to go stale.

### 5. Verify

```bash
# Wait for every workload to report ready, naming any that does not:
weirvern wait

# Workload state, resource use, and database health probes:
weirvern status

# Full control panel, if you prefer a UI:
weirvern tui
```

Then point your exporter at the sensor node's **NodePort** UDP ports — **32055**
(NetFlow) and **32063** (sFlow):

```
netflow destination: <sensor-node-ip>:32055
sflow   destination: <sensor-node-ip>:32063
```

> **These are the NodePorts, not 2055/6343.** The Service is `type: NodePort`, so
> the port that actually listens on the node's IP is the `nodePort`
> (k8s/31-goflow2.yaml). 2055 and 6343 are the *container* ports — they are only
> reachable from inside the cluster. An exporter aimed at UDP 2055 on the node
> sends its packets nowhere, and the only symptom is `ingest_freshness` staying
> red while every pod reports Running. Confirm what is bound with
> `ss -lunp | grep -E '32055|32063'` on the sensor node.

Within a couple of minutes `weirvern status` should show
`ingest_freshness` green, meaning flows are arriving and being aggregated.

### Optional: the CLI and TUI

Both are optional conveniences — the deployment is complete without them, and
everything they do is a `kubectl` invocation you can run yourself.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[admin]"
weirvern install      # checks kubectl, cluster, manifests; creates .env
```

`weirvern` locates the project automatically (nearest ancestor containing
`k8s/kustomization.yaml`), or honours `$WEIRVERN_HOME`. For the TUI to read
ClickHouse from your workstation rather than from inside the cluster:

```bash
kubectl -n weirvern port-forward svc/clickhouse 8123:8123 &
```

### No NetFlow source yet?

Generate synthetic flows to exercise the whole pipeline before wiring up real
hardware:

```bash
kubectl -n weirvern exec deploy/weirvern-worker -- \
  python -m weirvern.tools.demo_flows --minutes 60 --devices 8 --output /data/demo.jsonl
```

Point `TAIL_FILE` at it in the ConfigMap, re-apply, and watch detection with
`weirvern logs weirvern-worker`.

### Verifying that detection actually works

`weirvern status` proves data is flowing; it does not prove the ensemble is
detecting. To check the whole path end to end, inject traffic with a known
answer and confirm it is flagged:

```bash
# Generates backdated flows that include a seeded port scan and an exfil spike
kubectl -n weirvern exec deploy/weirvern-worker -- \
  python -m weirvern.tools.demo_flows --minutes 60 --devices 12 --output /data/demo.jsonl

# Point the tailer at the generated file (in k8s/20-configmap-env.yaml):
#   TAIL_FILE: "/data/demo.jsonl"
kubectl apply -k k8s/ && kubectl -n weirvern rollout restart deploy/weirvern-worker

# Watch the worker; within a sweep or two you should see detections
weirvern logs weirvern-worker
```

Expected result: the seeded scanner and the exfil host appear in
`netflow_anomalies` at `high`/`critical`, while the other hosts stay at
`low`/`medium`. Query it directly:

```bash
kubectl -n weirvern exec deploy/clickhouse -- \
  clickhouse-client --query "SELECT detected_at, src_addr, round(anomaly_score,3), severity
                             FROM weirvern.netflow_anomalies
                             ORDER BY detected_at DESC LIMIT 20"
```

If nothing is flagged, check in this order: `ingest_freshness` green in
`weirvern status` (data arriving), `flows_aggregated` windows spanning the
simulated range (not one collapsed window), then the worker log for training
failures.

The repository also ships the same idea as a CI gate: `scripts/eval_detection.py`
seeds a port scan, a beacon and an exfil spike into a scratch database, runs the
real sweep, and asserts the final verdicts — with a negative control proving the
harness can fail. See [Detection and alerting](#detection-and-alerting).

### Upgrading

```bash
# 1. Build and push the new image
podman build -t registry.example.com/weirvern-worker:0.6.7 .
podman push registry.example.com/weirvern-worker:0.6.7

# 2. Point the manifests at it (single place)
cd k8s && kustomize edit set image weirvern-worker=registry.example.com/weirvern-worker:0.6.7 && cd ..

# 3. Apply. The Deployments roll automatically because they use the Recreate
#    strategy, so the collector and worker stop before their replacements start
#    (required — see the note in k8s/31-goflow2.yaml).
kubectl apply -k k8s/

# 4. If the SCHEMA changed, re-run the schema Job. `kubectl apply` will NOT
#    re-run an unchanged Job object, so delete it first — the Job is idempotent
#    (every statement is CREATE ... IF NOT EXISTS), so re-running is safe.
kubectl -n weirvern delete job weirvern-schema --ignore-not-found
kubectl apply -k k8s/

# 5. Confirm
weirvern wait
```

Your data survives an upgrade: the ClickHouse data and the trained models live on
PVCs, and the collector's output file is on the node's disk.

### Removing Weirvern completely

Four things hold state, and only the first is obvious. Do them in this order:

```bash
# 1. Delete everything in the namespace, INCLUDING the data volumes.
#    Without --volumes the PVCs are orphaned and keep consuming disk.
weirvern down --volumes

# 2. Delete the namespace itself (the manifests create it).
kubectl delete namespace weirvern

# 3. Remove the host directories ON THE SENSOR NODE — these survive everything
#    above, because a hostPath is not a Kubernetes object.
ssh "$NODE" 'sudo rm -rf /var/lib/weirvern'

# 4. Remove the node label.
kubectl label node "$NODE" weirvern.io/sensor-node-

# Optional: the image, if nothing else uses it
podman rmi registry.example.com/weirvern-worker:0.6.7
```

If you created an image-pull secret (`regcred`) it lives inside the namespace and
goes with step 2. The Pushover token, if you created the secret imperatively,
also goes with it — but the token still exists in your Pushover account until you
delete the application there.

---

## Operations

### Using the CLI

| Command | What it does |
|---|---|
| `weirvern install` | Prerequisite check: kubectl, cluster reachability, namespace, manifests, schema, secrets |
| `weirvern apply` | `kubectl apply -k k8s/` — deploy or update the stack |
| `weirvern apply --dry-run` | Validate client-side; changes nothing |
| `weirvern wait` | Block until every workload is ready, naming any that is not |
| `weirvern status` | Workload state, resource use, and database health probes |
| `weirvern logs [workload]` | Logs by label, so it works across rollouts |
| `weirvern start / stop / restart [workload...]` | Lifecycle (see the mapping below) |
| `weirvern config list / get / set / validate` | Inspect and edit `.env` for local runs |
| `weirvern tune` | Guided threshold tuning, with a preview against real data |
| `weirvern mode` | Show the configured sensor mode and whether it can run here |
| `weirvern intercept` | In-path ARP intercept (`weir` mode); always `--dry-run` first |
| `weirvern interfaces` | Probe a node's NICs ("which one is the capture port?") |
| `weirvern tui` | The control panel |
| `weirvern version` | Version, current context, manifest presence |
| `weirvern down [--volumes]` | Delete the workloads; `--volumes` also destroys the data |

### What the lifecycle commands mean on Kubernetes

Container vocabulary does not map cleanly onto Kubernetes, so here is the honest
mapping. The CLI reports which case it took rather than pretending otherwise.

| Command | Kubernetes operation |
|---|---|
| `start` | Scale Deployments/StatefulSets back to their normal replica count |
| `stop` | Scale to zero — **except Zeek**, which is *suspended* (below) |
| `restart` | `kubectl rollout restart` — there is no "restart a pod" verb |
| `down` | Delete the workload objects from the namespace |
| `pull` | A no-op that explains itself: each node's kubelet pulls images |

**Zeek cannot be scaled to zero.** Kubernetes rejects `replicas: 0` on a
DaemonSet, because its entire purpose is one pod per node. `weirvern stop zeek`
therefore *suspends* it — a nodeSelector key no node matches, so the controller
drains the pods and capture stops. The workload reports `suspended` (with a `‖`
marker) rather than `stopped`, because an operator who believes the sensor is
off when it is only suspended would misread their own network coverage.
`weirvern start zeek` removes exactly that key, restoring the manifest's own
selector.

### Doing it without the CLI

```bash
kubectl apply -k k8s/                                  # deploy / update
kubectl -n weirvern get pods -w                       # watch
kubectl -n weirvern rollout status deploy/weirvern-worker
kubectl -n weirvern logs -l app.kubernetes.io/name=weirvern-worker --tail=200
kubectl -n weirvern scale deploy/weirvern-worker --replicas=0     # stop
kubectl -n weirvern rollout restart daemonset/zeek                 # bounce Zeek
kubectl -n weirvern exec -it deploy/weirvern-worker -- bash       # shell
```

### Backups

Two things are worth backing up, and neither is on a `hostPath` in a way a
cluster backup would catch:

- the `clickhouse-data` PVC (all collected flows, anomalies, baselines)
- the `models` PVC (trained model artifacts — small, but retraining takes time)

Both are `ReadWriteOnce` claims; snapshot them with your storage provisioner, or
copy them out:

```bash
kubectl -n weirvern exec deploy/weirvern-worker -- tar cz /models | cat > models-backup.tgz
```

---

## Configuration

There are two configuration surfaces, and the distinction matters:

| Surface | Applies to | Where |
|---|---|---|
| **Cluster** | What the deployment actually runs | `k8s/20-configmap-env.yaml` (+ the out-of-band `weirvern-secrets` Secret) |
| **Local** | The CLI, `init-db`, `tune`, and the TUI's config tab | `.env` (created from `.env.example`) |

Changing `.env` does **not** change the running deployment. After editing the
ConfigMap, `kubectl apply -k k8s/` and restart the affected workload.

### Key settings

| Variable | Default | Meaning |
|---|---|---|
| `CLICKHOUSE_HOST` / `CLICKHOUSE_PORT` | `clickhouse` / `8123` | ClickHouse endpoint (the Service name resolves in-cluster) |
| `ZEEK_IFACE` | `eth1` | **Capture port on the sensor node** — the dedicated NIC receiving mirrored/SPAN traffic. Must not carry the default route, and must not be a bridge member |
| `MGMT_IFACE` | `eth0` | **Management port** — default route, SSH, cluster API. Not sniffed. Used to detect when `ZEEK_IFACE` points at the wrong NIC |
| `ZEEK_LOG_DIR` | `/zeek/logs` | Where the worker reads Zeek logs |
| `TAIL_FILE` | `/data/flows.jsonl` | goflow2 JSONL sink |
| `SENSOR_MODE` | `loch` | `loch` = passive; `weir` = in-path intercept (see [Sensor modes](#sensor-modes-loch-and-weir)) |
| `DETECT_INTERVAL_S` | 300 | Detection sweep cadence (s) |
| `RETRAIN_EVERY_H` | 6 | Full retrain cadence (h) |
| `RETRAIN_WINDOW_H` | 72 | Training data window (h, 3 days) |
| `BASE_THRESHOLD` | 0.35 | Ensemble score floor for alerting |
| `MIN_AGREEMENT` | 0.33 | Fraction of models that must fire |
| `PUSHOVER_ENABLED` | `0` | `1` sends real pushes; `0` logs only |
| `PUSHOVER_USER_KEY` / `PUSHOVER_API_TOKEN` | unset | **Secret** — see step 4 |
| `PUSHOVER_COOLDOWN_S` | 1800 | Per-source alert cooldown |
| `PUSHOVER_MAX_PER_HOUR` | 20 | Global hourly cap |
| `MODEL_DIR` | `/models` | Persisted model artifacts (survive restarts) |

Fusion and severity behaviour (see `weirvern/ensemble.py` docstrings for the
measured rationale behind each of these):

| Setting | Default | Meaning |
|---|---|---|
| `ModelConfig.fusion_mode` | `max` | `max` = strongest detector signal (recommended); `mean` = legacy averaging, retained for A/B |
| `ModelConfig.min_flows_for_full_confidence` | 10 | Windows with fewer flows have their score damped (thin-window statistics are unreliable) |
| `ModelConfig.thin_window_floor` | 0.35 | Lower bound of that damping multiplier |
| `ModelConfig.port_scan_min_ports` / `..._entropy` | 50 / 4.0 | Structural scan signature that lets a lone strong specialist escalate |
| `ModelConfig.near_miss_band` | 0.85 | Fraction of the threshold within which a dropped window is recorded as a near miss (see the Models view) |

### Editing the Zeek policy

`k8s/zeek/weirvern-local.zeek` is the sensor's site policy. It is fed to the
cluster by kustomize's `configMapGenerator`, so the repository copy **is** the
source of truth — there is no manifest copy to keep in sync. Editing it changes
the generated ConfigMap's name hash, which triggers a rolling restart of the
DaemonSet automatically.

---

## Detection and alerting

### The ensemble

Four detectors, each contributing a normalised 0–1 score:

| Detector | What it catches | Notes |
|---|---|---|
| Isolation Forest | Multivariate outliers across the full feature vector | Calibrated against its own training distribution |
| Gradient Boosting | Non-linear patterns, trained on IF's labels (a distillation) | Probability calibrated; class-imbalanced weighting |
| DBSCAN | Dense clusters vs. outliers — port diversity, fan-out | Score calibrated against the measured distance distribution |
| Adaptive Baseline | Per-host percentile deviation (p95/p99/p999) | Learns each host's normal; needs ≥10 observations |

Scores are fused (default `max`) and gated by `BASE_THRESHOLD`.

**Severity escalation requires corroboration**: two-or-more detectors scoring
≥0.85, or one such detector backed by a direct structural signature (e.g. a
zero-byte port scan, which volume-based models cannot see). A single strong
signal without corroboration alerts at `medium` — it is not escalated and not
silenced. This gate exists because measurement showed a 90-false-positive storm
without it.

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

**Accounts and roles**, served from the worker image on **NodePort 30088**. It cannot start,
stop, or apply anything: a monitoring surface that can mutate the thing it monitors turns a
UI bug into an outage — but it does manage the deployment's configuration and its own
accounts, and both are gated.

**Setup is one step.** The GUI creates a default `admin` account on its first startup and
prints the generated password **once** to the pod log:

```
kubectl -n weirvern logs deploy/weirvern-gui | grep "initial admin"
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
| Health | **Sensor state** (mode, whether it is running, heartbeat age, intercept status), the health probes, ingestion trend, table sizes, and the **alert audit** — every alerting decision, including what was suppressed and why. The landing view |
| Anomalies | Every anomaly with score, agreement and the "why" line — plus its **review state**: acknowledge, resolve, or mark false-positive, with an unreviewed-only filter. Click through to **evidence** |
| Assets | The **asset inventory**: every host seen, searchable, with bytes, services and anomaly counts; click an address to drill down |
| Network | Every host-to-host connection as a graph; **select any number of hosts to track only their connections** |
| Netflow | Volume, protocol mix, top ports, destination spread; **click a protocol or port bar to see the host-to-host pairs behind it** |
| Zeek | Per-log volume, a trend by log, observed services, DNS names; **click a log to see which hosts it contains**, then a host to drill into it |
| Models | Training history, score distribution, model agreement, per-feature deviations — and **near misses**: the windows that scored close to the bar, or cleared it and were stopped by the agreement gate. The surface a threshold change should be judged against |
| Evidence | The raw flows and Zeek records inside a specific alert's window |
| Settings | The **effective configuration** — sensor mode and interfaces, detection thresholds and cadence, reverse-DNS mode, ClickHouse target, namespace, version — each setting rendered as the control that changes it (toggle / dropdown / bounded number) with a **?** explaining what it does, plus **Account** (change your password) and **Users** (admin-only account management). Secrets show as `(set, N chars)` or `(not set)`, never in value |

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
  alert audit shows every decision, counting suppressed alerts separately from the log-only
  path (a configuration state, not a withheld alert).
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

## Scaling and limitations

These are stated plainly because they determine whether Weirvern fits your
deployment.

### What does not scale horizontally today

| Constraint | Why | What scaling out requires |
|---|---|---|
| `weirvern-worker` is **single-replica** | Alert cooldown/cap state is in-process, so a second replica would double every notification; the tailer holds a file offset in memory, so two replicas would insert duplicate records | Externalise alert state to ClickHouse; move ingest off file-tailing |
| Ingest is **file-tail**, per node | goflow2 writes JSONL and the worker reads it by byte offset | A broker (Kafka/Redpanda) between collector and consumer |
| `clickhouse` is **single-node** | Replication needs ClickHouse Keeper and a replicated schema — a schema change, not a `replicas` bump | Keeper + `ReplicatedMergeTree` |
| ClickHouse is not HA | One StatefulSet replica | See above |

Do **not** simply raise `replicas` on the worker or the collector. The manifests
pin both to 1 with `Recreate` strategy, and the reasons are documented in
`k8s/31-goflow2.yaml` and `k8s/33-worker.yaml`.

### What does scale

- **Multiple sensor nodes**: each node that needs capture gets its own Zeek
  (DaemonSet handles this automatically) — but each needs its own worker, or the
  transport must change to a broker.
- **Detection depth**: the ensemble is bounded by flow volume, not by the number
  of hosts.
- **Retention**: per-type TTLs in `weirvern/schema/001_weirvern.sql` let
  high-volume data (`flows`) expire quickly while low-volume, high-value data
  (`notice`, `files`) persists far longer.

---

## Troubleshooting

### The stack is up but nothing is detected

Work through these in order — the first two account for most reports.

1. **Is the sensor node labelled?**
   ```bash
   kubectl -n weirvern get pods -o wide          # are goflow2/worker Running?
   kubectl -n weirvern get daemonset zeek
   ```
   If the worker is `Pending`, check `kubectl -n weirvern describe pod <pod>`
   for a nodeSelector mismatch.

2. **Are flows arriving?**
   ```bash
   weirvern status        # look for ingest_freshness
   ```
   Red or "no flow data yet" means the exporter is not reaching the collector.
   Confirm the exporter points at the sensor node's IP on UDP **32055**
   (the NodePort — not 2055, which is the container port and is cluster-internal
   only), and that the
   Service is `externalTrafficPolicy: Local` (it is, by design — see
   `k8s/31-goflow2.yaml`; with the default policy, kube-proxy on another node
   can accept and misroute the UDP packets).

3. **Is Zeek on the right interface?**
   ```bash
   weirvern interfaces --node <sensor-node>
   ```
   Reports a role for every NIC and a verdict on `ZEEK_IFACE`. A sensor pointed at
   the management port, a bridge member, or a veth still runs and still logs — it
   just captures almost none of the network, which is why this check is explicit
   rather than left to reading `ip link` output. The Zeek container also validates
   `ZEEK_IFACE` at startup, warns when the interface is a bridge member or carries
   the default route, and lists the interfaces that do exist if the name is wrong.

4. **Is capture loss hiding the traffic?** Zeek reports dropped packets in its
   own `capture_loss` log; a sensor that cannot keep up degrades detection
   quality without erroring.

### `weirvern status` cannot reach ClickHouse

Expected from a workstation — the Service is cluster-internal. Port-forward it:

```bash
kubectl -n weirvern port-forward svc/clickhouse 8123:8123 &
```

### The schema Job failed

```bash
kubectl -n weirvern logs job/weirvern-schema
```

The Job is idempotent (`CREATE ... IF NOT EXISTS` throughout), so fixing the
cause and re-running is safe:

```bash
kubectl -n weirvern delete job weirvern-schema
kubectl apply -k k8s/
```

### A pod is OOM-killed during retraining

The worker's memory limit is the constraint — training the ensemble over a
3-day window is the spike. Raise the limit in `k8s/33-worker.yaml` rather than
lowering `RETRAIN_WINDOW_H`, which would shorten the baseline.

### Alerts stopped after enabling the NetworkPolicy

`k8s/70-networkpolicy.yaml` is **not** applied by default. If you enabled it,
its egress rule for TCP/443 (Pushover) is the first suspect, and it only takes
effect on a CNI that enforces policy at all.

---

## Security and privacy

### Privileges

The most privileged workload is Zeek, and it needs to be: packet capture is
impossible without `hostNetwork` and `NET_RAW`. It is scoped as tightly as the
task allows — non-root, all other capabilities dropped, no `NET_ADMIN`, and its
only host access is the log directory. Every other workload runs non-root with
all capabilities dropped. See [SECURITY.md](SECURITY.md).

### RBAC

`k8s/60-rbac.yaml` defines two roles: a read-only `viewer` for monitoring
(what the TUI uses) and an `operator` that adds the lifecycle verbs. Neither can
read Secrets — an account that displays health cannot exfiltrate the Pushover
token.

### Data sensitivity

Zeek's `http.log` and `dns.log` contain personal data: hostnames, URLs, user
agents, and — if `capture_password` were enabled — credentials. **Keep
`capture_password` OFF.** It is off by default and Weirvern never enables it;
`http.log`'s `username` field still populates without it.

Handling requirements, retention by data type, and the lawful-basis question are
documented in [USAGE_POLICY.md](USAGE_POLICY.md). Read it before enabling
additional Zeek log types.

### Network exposure

Nothing needs to face the internet. NetFlow/sFlow intake is UDP on the sensor
node, restricted at your firewall to trusted exporters. ClickHouse is
cluster-internal by default (`k8s/30-clickhouse.yaml` ships an optional
externally-reachable Service with `type: NodePort` commented out).

---

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[admin,dev]"
pytest                                          # no cluster or database needed
ruff check weirvern tests
mypy weirvern --ignore-missing-imports
kubeconform -strict -ignore-missing-schemas k8s/
kustomize build k8s/ >/dev/null                 # manifests must assemble
sh scripts/gate.sh                              # the full local gate
```

CI runs lint, type-check and tests on every push
(`.github/workflows/ci.yml`), plus two things a plain test run cannot prove: the
manifests are validated against Kubernetes schemas and assemble, and the
seeded-attack detection harness runs against a real ClickHouse. The suite needs
neither a cluster nor a database: workload-facing tests drive a fake `kubectl`,
so the command construction is verified without one.

Model artifacts are versioned and persisted to `MODEL_DIR` — a worker restart
**does not** lose learned baselines or models (this was a legacy failure mode).

### Checking the GUI

The web UI has no build step and no test framework, so two things are checked instead:

```bash
node --check weirvern/admin/web/app.js          # and soc.js, assets.js
```

The syntax check catches a broken view file, which would otherwise appear as a tab that does
nothing. It cannot catch a *silent* failure — an element id that does not exist, a payload key
read under the wrong name, a click handler that never fires — because none of those raise.

For that, `scripts/jsdom_render.js` executes the shipping JavaScript against the shipping HTML
in a DOM and asserts what appears. It needs a served GUI and one npm package:

```bash
# 1. serve the GUI (any reachable instance)
# 2. then:
npm install jsdom
node scripts/jsdom_render.js http://127.0.0.1:30088
```

It renders the inventory and the graph from real-shaped payloads and checks the behaviours that
matter: that a shift-click tracks a host instead of drilling into it, that several hosts can be
tracked at once, that clearing the selection restores the whole graph, that the review buttons
on an anomaly post a disposition, and that a **failed** query says so rather than drawing an
empty panel. That last one is the point — an empty panel and a broken query look identical on
screen, and this project has shipped that bug more than once.

### End-to-end validation

Unit tests cannot exercise the SQL, the materialized views, or detector training
against real data. To validate the full path, point the stack at a real
ClickHouse and drive it with synthetic traffic:

```bash
kubectl -n weirvern exec deploy/weirvern-worker -- \
  python -m weirvern.tools.demo_flows --minutes 60 --devices 12 --output /data/demo.jsonl
```

Sanity checks: the `flows` row count matches the generated line count,
`flows_aggregated` windows span the simulated time range (not one collapsed
window), and the seeded scanner/exfil hosts appear in `netflow_anomalies` at
high/critical while other hosts stay at low/medium.

### Repository layout

```
weirvern/            application package
  admin/              control plane: CLI, TUI, config I/O, k8s runtime backend
  schema/             ClickHouse schema (packaged; applied by the schema Job)
  models/             the four detectors, scoring, calibration
  ensemble.py         fusion, severity, corroboration gate
  ingester.py         tailers for goflow2 JSONL and Zeek TSV
  worker.py           the detection loop and retrain cadence
k8s/                  manifests + kustomization + Zeek site policy
docs/                 logo, research notes, decision records
scripts/              eval harness, DOM render harness, local gate
tests/                unit tests (no cluster, no database required)
```

---

## License

MIT — see [LICENSE](LICENSE). Third-party components and their licenses are
listed in [NOTICE](NOTICE).
