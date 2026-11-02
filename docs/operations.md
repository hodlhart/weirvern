# Operations

*Part of the [Weirvern](../README.md) documentation.*

Day two: the CLI, lifecycle, backups, the settings that matter,
and what to do when something looks wrong.

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
| `weirvern intercept` | In-path ARP intercept (`siphon` mode); always `--dry-run` first |
| `weirvern interfaces` | Probe a node's NICs ("which one is the capture port?") |
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

Two things are worth backing up:

- the `clickhouse-data` PVC — every collected flow, anomaly, baseline and rule
- the `models` PVC — trained model artifacts (small, but retraining takes time)

**ClickHouse data — `scripts/backup_clickhouse.sh`.** ClickHouse's own backup
engine writes a portable artifact onto the clickhouse PVC; nothing here needs
snapshot-capable storage (the shipped `local-path` class has none). The commands,
in full:

```bash
scripts/backup_clickhouse.sh                    # BACKUP DATABASE weirvern, timestamped name
scripts/backup_clickhouse.sh --list             # what is on the PVC now
scripts/backup_clickhouse.sh --restore <name>   # restore into a SCRATCH database, then verify
scripts/backup_clickhouse.sh --prune <name>     # delete one backup
```

Each is a `kubectl -n weirvern exec clickhouse-0 -- clickhouse-client -q '...'`
under the hood; the two commands that matter, by hand:

```sql
BACKUP DATABASE weirvern TO Disk('default', 'backups/weirvern-YYYYmmdd-HHMMSS')
RESTORE DATABASE weirvern AS weirvern_restore FROM Disk('default', 'backups/<name>')
```

Artifacts land at `/var/lib/clickhouse/backups/<name>` on the clickhouse PVC.
This depends on the `weirvern-clickhouse-config` ConfigMap shipped in
`k8s/30-clickhouse.yaml`: it tells ClickHouse the `default` disk is an allowed
backup destination, and without it the backup is refused with
`backups.allowed_disk ... is not set`.

**Verifying a restore.** `--restore` restores into a scratch database
(`weirvern_restore`, dropped and re-created on every run) and prints
live-vs-restored counts for `flows`, `netflow_anomalies` and `flows_aggregated` —
they must match, table for table. Inspect the restored data at leisure; when done:

```bash
kubectl -n weirvern exec clickhouse-0 -- clickhouse-client -q 'DROP DATABASE weirvern_restore'
```

**Retention is manual, on purpose.** Backups accumulate under
`/var/lib/clickhouse/backups/`; nothing prunes them automatically (a scheduled
backup job is deliberately not shipped — wrap this script in a CronJob of your
own if you want one). Watch the PVC's free space.

**The `models` PVC** keeps its simpler path — a tar pulled through the worker:

```bash
kubectl -n weirvern exec deploy/weirvern-worker -- tar cz /models | cat > models-backup.tgz
```

**Not covered:** off-cluster copies (pull an artifact out with
`kubectl cp weirvern/clickhouse-0:/var/lib/clickhouse/backups/<name> ./` if you
need one), encryption at rest, and the data-retention windows themselves (that is
`35-prune-cronjob.yaml`).

---


### Upgrade and rollback

**What an upgrade is.** Images are built with an immutable tag (`sha-<commit>`), manifests are
rendered by kustomize, and the schema is applied by the `weirvern-schema` Job. A release is: build
images → set the image tags → `kubectl apply -k k8s/`.

**Before you start.**

- take a backup: `scripts/backup_clickhouse.sh`
- record the running tags:
  `kubectl -n weirvern get deploy -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.template.spec.containers[0].image}{"\n"}{end}'`
- `weirvern status` (or `kubectl -n weirvern get pods`)
- note the schema version and the release in the change record

**Rolling back the code.** Pin the previous immutable tag on each deployment:

```bash
kubectl -n weirvern set image deploy/weirvern-worker worker=weirvern-worker:sha-<previous>
kubectl -n weirvern set image deploy/weirvern-gui    gui=weirvern-worker:sha-<previous>
kubectl -n weirvern set image deploy/zeek            zeek=weirvern-zeek:sha-<previous>
kubectl -n weirvern rollout status deploy/weirvern-worker
kubectl -n weirvern rollout status deploy/weirvern-gui
kubectl -n weirvern rollout status deploy/zeek
```

The equivalent manifest-first path is `kustomize edit set image` in `k8s/` followed by
`kubectl apply -k k8s/`; the manifests are the source of truth, so a later apply will restore
whatever tag they carry.

**The `IfNotPresent` caveat.** The workloads pull with `imagePullPolicy: IfNotPresent`. Re-using a
tag does not re-pull it, so a rollback to a tag that is already present is only meaningful if
those bits are the ones you want. Always use the immutable `sha-<commit>` tags the build produces
— never a floating tag as a rollback target.

**What cannot be rolled back: the schema.** `weirvern init-db` applies add-only migrations; there
are no down migrations, and data written by a newer version may not be readable by an older one.
Rolling the code back is safe only if the schema did not advance. If it did, restore the
pre-upgrade backup into a scratch database, verify it, then restore for real — see
[Backups](#backups) and `scripts/backup_clickhouse.sh --restore`. That is the contract: **code
rolls back, data does not.**

**Rolling back models.** Artifacts live on the `models` PVC; the previous set is archived under
`superseded/<stamp>/` (`SUPERSEDED_DIR` in `weirvern/models/retrain.py`). Copy the chosen set back
into `MODEL_DIR` and restart the worker; the next cycle warm-loads it.

**If a deployment will not roll back cleanly.** `kubectl -n weirvern rollout undo deploy/<name>`
works while the deployment has revision history, but it is not a substitute for the image pin
when kustomize-managed tags are re-applied. Record the intended tag in the change record so the
next apply cannot silently move the deployment forward again.

## Configuration

There are two configuration surfaces, and the distinction matters:

| Surface | Applies to | Where |
|---|---|---|
| **Cluster** | What the deployment actually runs | `k8s/20-configmap-env.yaml` (+ the out-of-band `weirvern-secrets` Secret) |
| **Local** | The CLI, `init-db`, `tune`, and `weirvern config set` | `.env` (created from `.env.example`) |

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
| `SENSOR_MODE` | `loch` | `loch` = passive; `siphon` = in-path intercept (see [Sensor modes](#sensor-modes-loch-and-siphon)) |
| `CHANNEL_UPSTREAM` / `CHANNEL_DOWNSTREAM` | unset | The two ports of an in-line channel: one bridge, traffic through the box (see [Channel](#channel-enforcement-in-line-still-loch)) |
| `SLUICE_ENABLED` | `0` | Arm the Sluice Gate. Opened by a decision, never by an install |
| `SLUICE_IFACE` | unset | Interface enforcement attaches to; empty = the channel bridge, else the capture port. The management interface is refused at write time |
| `SLUICE_CRITICALITY` | `off` | Whether detections may block on their own (`off` / `high` / `medium` / `strict`; an unknown value refuses every block) — off by default |
| `SLUICE_MAX_BLOCK_S` | 3600 | Ceiling on an automated block's lifetime |
| `SLUICE_INTERVAL_S` | 60 | How often the gate re-arms — also the interval within which a lapsed rule stops being enforced |
| `CHANNEL_NETFLOW` | `off` | `off` / `upstream` / `downstream`: summarise the channel's crossing traffic into the deployment's own collector |
| `DETECT_INTERVAL_S` | 300 | Detection sweep cadence (s) |
| `RETRAIN_EVERY_H` | 6 | Full retrain cadence (h) |
| `RETRAIN_WINDOW_H` | 72 | Training data window (h, 3 days) |
| `BASE_THRESHOLD` | 0.35 | Ensemble score floor for alerting |
| `MIN_AGREEMENT` | 0.33 | Fraction of models that must fire (never below a single detector's share) |
| `ML_WARMUP_HOURS` | 24 | Local history required before a new deployment may page (0 disables) |
| `ML_WARMUP_MIN_WINDOWS` | 12 | Distinct local 5-minute windows required before paging |
| `ML_WARMUP_MIN_HOSTS` | 1 | Distinct local hosts required before paging |
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
   Confirm the exporter points at the sensor node's IP on UDP **32055** (or
   **2055** — both listen on the node; the collector runs with `hostNetwork`),
   and that the
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
