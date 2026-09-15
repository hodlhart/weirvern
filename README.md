# Weirvern

Network flow anomaly detection for Kubernetes. Weirvern ingests NetFlow/sFlow
from your network, captures packet-level protocol behaviour with Zeek, stores
both in ClickHouse, and runs an ensemble of machine-learning detectors to flag
suspicious host behaviour — port scans, beaconing (C2-style callbacks),
credential-stuffing patterns, and data-exfiltration spikes — then pushes alerts
to your phone via Pushover.

This is the **v20 rebuild**: a from-scratch, production-minded rewrite of the
original FlowForge experiment (an INF 678 class project). Every lesson from the
v14–v19 lineage is baked in — see [CHANGELOG.md](CHANGELOG.md) for the full
lesson map.

> **WARNING**: This tool is for monitoring networks **you own or are explicitly
> authorized to monitor**. See [USAGE_POLICY.md](USAGE_POLICY.md). Unauthorized
> monitoring is illegal in most jurisdictions. You have been warned.

---

## Contents

- [Architecture](#architecture)
- [Requirements](#requirements)
- [Deploy in five steps](#deploy-in-five-steps)
- [Verifying that detection actually works](#verifying-that-detection-actually-works)
- [Upgrading](#upgrading)
- [Removing Weirvern completely](#removing-weirvern-completely)
- [Operations](#operations)
- [Configuration](#configuration)
- [Detection and alerting](#detection-and-alerting)
- [Scaling and limitations](#scaling-and-limitations)
- [Troubleshooting](#troubleshooting)
- [Security and privacy](#security-and-privacy)
- [Development](#development)
- [License](#license)

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
                                             │    notice             │
                                             │  netflow_anomalies    │
                                             │  ml_models, baselines │
                                             │  alert_events         │
                                             └──────────┬────────────┘
                                                        ▼
                                             ┌───────────────────────┐
                                             │  weirvern-worker     │
                                             │  ensemble detectors   │
                                             │  (scikit-learn)       │
                                             └──────────┬────────────┘
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
| `zeek` | **DaemonSet** | `zeek/zeek:lts` | Packet sniffer: conn/DNS/TLS/notice logs from a NIC or mirror port |
| `weirvern-worker` | Deployment | `weirvern-worker:0.4.0` | Ingest (both sources), ensemble detection, Pushover alerts |

Two details of this table are Kubernetes design statements, not incidentals:

- **Zeek is a DaemonSet with `hostNetwork: true`** because a packet sniffer can
  only see traffic on the interface it is attached to — a property of the *node*,
  not of a pod. One sniffer per node is the only correct abstraction.
- **`goflow2` and `weirvern-worker` are node-pinned and single-replica** because
  the collector writes a file that the worker tails. See
  [Scaling and limitations](#scaling-and-limitations).

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
| [Pushover](https://pushover.net) account | free tier | 7,500 messages/month. Optional — alerts can log-only |

**Cluster sizing.** The shipped resource requests total roughly 1.5 CPU / 2 GB
of requests and 7 CPU / 8 GB of limits, driven by ClickHouse and by the
worker's in-memory model training. A 4-core / 8 GB node is a comfortable
single-node homelab deployment; ClickHouse will use whatever memory you give it,
so do not set its limit below 2 GB.

**Sensor node.** The node that carries the mirrored/SPAN traffic (and therefore
runs goflow2, Zeek and the worker) needs:

- the NIC receiving the traffic, up and (ideally) promiscuous
- a label so the workloads can find it: `weirvern.io/sensor-node=true`
- two host directories, group-writable by GID 10001:
  `/var/lib/weirvern/flows` and `/var/lib/weirvern/zeek`

---

## Deploy in five steps

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

### 3. Build and push the worker image

A cluster cannot build an image, so this is a prerequisite rather than an
optional step:

```bash
# podman or buildah — any OCI image builder your workstation has
podman build -t registry.example.com/weirvern-worker:0.4.0 .
podman push registry.example.com/weirvern-worker:0.4.0
```

Then point the manifests at it — one place, no per-file editing:

```bash
cd k8s
kustomize edit set image weirvern-worker=registry.example.com/weirvern-worker:0.4.0
cd ..
```

> If the image is private, create an image-pull secret and reference it in
> `k8s/33-worker.yaml` and `k8s/50-schema-job.yaml` under `imagePullSecrets`.

### 4. Configure and deploy

```bash
git clone https://github.com/hodlhart/weirvern.git   # or your fork
cd weirvern

# Review what the cluster will run (no changes made):
kubectl apply -k k8s/ --dry-run=client

# Adjust the non-secret settings — most importantly ZEEK_IFACE, the interface
# on the sensor node that sees the mirrored traffic:
$EDITOR k8s/20-configmap-env.yaml

# Deploy. The namespace and every workload except the Secret come from here.
kubectl apply -k k8s/

# Now create the Secret — AFTER the apply, and never as a committed manifest.
# (A Secret manifest in the kustomization would be re-applied with placeholder
# values on every later apply, silently wiping these — see the SECRETS note in
# k8s/kustomization.yaml.)
kubectl -n weirvern create secret generic weirvern-secrets \
  --from-literal=CLICKHOUSE_PASSWORD='' \
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

Then point your exporter at the sensor node's UDP ports **2055** (NetFlow) and
**6343** (sFlow). Within a couple of minutes `weirvern status` should show
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

### Upgrading

```bash
# 1. Build and push the new image
podman build -t registry.example.com/weirvern-worker:0.5.0 .
podman push registry.example.com/weirvern-worker:0.5.0

# 2. Point the manifests at it (single place)
cd k8s && kustomize edit set image weirvern-worker=registry.example.com/weirvern-worker:0.5.0 && cd ..

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
podman rmi registry.example.com/weirvern-worker:0.4.0
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
| **Cluster** | What the deployment actually runs | `k8s/20-configmap-env.yaml` (+ `21-secrets.yaml`) |
| **Local** | The CLI, `init-db`, `tune`, and the TUI's config tab | `.env` (created from `.env.example`) |

Changing `.env` does **not** change the running deployment. After editing the
ConfigMap, `kubectl apply -k k8s/` and restart the affected workload.

### Key settings

| Variable | Default | Meaning |
|---|---|---|
| `CLICKHOUSE_HOST` / `CLICKHOUSE_PORT` | `clickhouse` / `8123` | ClickHouse endpoint (the Service name resolves in-cluster) |
| `ZEEK_IFACE` | `eth0` | **Interface on the sensor node** that sees mirrored traffic |
| `ZEEK_LOG_DIR` | `/zeek/logs` | Where the worker reads Zeek logs |
| `TAIL_FILE` | `/data/flows.jsonl` | goflow2 JSONL sink |
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
| Isolation Forest | Multivariate outliers across 14 flow features | Calibrated against its own training distribution |
| Gradient Boosting | Non-linear patterns, trained on IF's labels (a distillation) | Probability calibrated; class-imbalanced weighting |
| DBSCAN | Dense clusters vs. outliers — port diversity, fan-out | Best signal for scanning behaviour |
| Adaptive Baseline | Per-host percentile deviation (p95/p99/p999) | Learns each host's normal; needs ≥10 observations |

Scores are fused (default `max`) and gated by `BASE_THRESHOLD`.

**Severity escalation requires corroboration**: two-or-more detectors scoring
≥0.85, or one such detector backed by a direct structural signature (e.g. a
zero-byte port scan, which volume-based models cannot see). A single strong
signal without corroboration alerts at `medium` — it is not escalated and not
silenced. This gate exists because measurement showed a 90-false-positive storm
without it.

### Alert hygiene

- Severity tiers (critical/high/medium/low) from fused score and agreement.
- Per-source cooldown + global hourly cap → no alert storms.
- Dedupe keyed on `(src_addr, window_start)`; resend only on re-observation.
- Every send recorded in `alert_events` for audit and testing.

### Tuning

```bash
weirvern tune
```

The guided tuner shows the alert-rate implication of a threshold change against
the last 7 days of real data before you commit to it.

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
   Confirm the exporter points at the sensor node's IP on UDP 2055, and that the
   Service is `externalTrafficPolicy: Local` (it is, by design — see
   `k8s/31-goflow2.yaml`; with the default policy, kube-proxy on another node
   can accept and misroute the UDP packets).

3. **Is Zeek on the right interface?**
   ```bash
   weirvern logs zeek
   ```
   The container validates `ZEEK_IFACE` at startup and lists the interfaces that
   do exist if it does not match, rather than failing silently.

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
```

CI runs lint, type-check and tests on every push
(`.github/workflows/ci.yml`). The suite needs neither a cluster nor a database:
workload-facing tests drive a fake `kubectl`, so the command construction is
verified without one.

Model artifacts are versioned and persisted to `MODEL_DIR` — a worker restart
**does not** lose learned baselines or models (this was a legacy failure mode).

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
tests/                unit tests (no cluster, no database required)
```

---

## License

MIT — see [LICENSE](LICENSE). Third-party components and their licenses are
listed in [NOTICE](NOTICE).
