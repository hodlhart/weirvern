# Deployment

*Part of the [Weirvern](../README.md) documentation.*

From an empty machine to a working deployment, the checks that
refuse to proceed, and how to upgrade or remove it.

## Requirements

| Component | Version | Notes |
|---|---|---|
| Kubernetes | 1.24+ | Any conformant cluster: k0s, k3s, kubeadm, EKS/GKE/AKS |
| `kubectl` | 1.24+ | Has kustomize built in, so the `kustomize` binary is optional |
| Container registry | any | The worker image must be pushed somewhere the nodes can pull from |
| Storage class | dynamic | Defaults to `local-path` (k0s/k3s). Change one field for others |
| Python | 3.11+ | Only for the optional CLI — the deployment itself needs none |
| [Pushover](https://pushover.net) account | free tier | 7,500 messages/month. Optional — alerts can log-only |

**Cluster sizing.** Measured from the rendered manifests (not estimated): the
shipped workloads total **2.00 CPU / 3.91 GiB of requests** and **11.45 CPU /
15.62 GiB of limits**. `scripts/measure_sizing.sh` prints exactly these numbers;
its header states the inclusion rule (every container -- init containers included
-- of every rendered workload: worker, GUI, ClickHouse, goflow2, the Zeek DaemonSet -- capture, both init containers and the flow tap sidecar --
the schema Job, the prune CronJob and the watchdog CronJob). The earlier totals here were
unreproducible because no method was stated; rerun the script after any manifest
change.

Sizing rule: **a node must satisfy the limits**, not the requests, because the
scheduler admits on requests but the kernel enforces limits. So the practical
requirement for a single node is a machine that can actually give out ~10 cores
and ~14 GiB, even though the shipped requests look like a Raspberry Pi job. That
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


## Asset scanning and Nmap

Scanning is executed by **weirlings**, not by a central Deployment. Each unit's agent measures
its own Nmap, reports that capability with its distro/version, and claims manual scan jobs from
the hub queue only inside the networks it declares. A host with no capable, in-scope weirling is
refused at job creation with the measured reason rather than queued forever.

The hub builds two images from this tree:

```bash
docker build -t weirvern-worker:sha-<commit> -f Containerfile .
docker build -t weirvern-scan:sha-<commit>   -f Containerfile.scanner .
```

`weirvern-scan` is the Nmap-capable agent image `scripts/deploy-weirling.sh` ships to each
sensor's agent container. It installs `nmap` and `libcap2-bin` and sets
`cap_net_raw,cap_net_admin` on the binary, and the installer starts the container with
`--cap-add NET_RAW --cap-add NET_ADMIN`, so the unit scans out of the box. The agent reports
`scan_mode: syn/udp` and the console hides **Install nmap** because there is nothing to install.
If the image is absent, the unit still deploys and honestly reports `nmap missing`; build it with
the command above and re-run the installer, or pass `--agent-image <ref>`.

### Installing Nmap on a weirling: the two deployment shapes

**A containerised unit gets Nmap from the image, not from the host.** A package installed on the
host is invisible to the agent (it measures its own container filesystem), and a container cannot
install into its own image — so the Install action is deliberately absent when the unit is
capable, and impossible when the image lacks Nmap. Rebuild the scan image instead. The
`nmap`/`libcap2-bin` layer measures 29.1 MB; only sensors run that image.

**A host-installed unit has two privilege paths.** The rest of this section is about that shape.

**Scoped sudoers — recommended, no password.** Give the agent's user one sudoers entry (for
example `/etc/sudoers.d/weirvern-nmap`) that permits exactly the package manager's install
command and nothing else. The agent then reports `sudo_state=passwordless`, the console offers
**Install nmap** with no password field, and one click is enough. Nothing secret ever leaves the
host, and the privilege is bounded by a command allow-list rather than by root. This is the path
to use on a fleet.

**One-click prompt — the fallback.** When the agent reports `sudo_state=password`, the console
shows a single field labelled *sudo password for &lt;host&gt;*. On submit the password travels in the
POST body to the console, then over the cluster network to the ingest gateway, which holds it in
memory for at most five minutes; the target weirling picks it up on its own mTLS poll, pipes it
to `sudo -S`, and the buffer is overwritten. It is never written to ClickHouse, never an
environment variable, never a log line, never an audit row and never a response. The audit
records the actor, host, command, exit code, timestamp and the fact that a password was used —
not the secret. Three attempts per host per ten minutes; the request expires after five. If the
package manager cannot be detected, or the user is not in sudoers, the Install button is
replaced by the copy-command line rather than a prompt that cannot work.

**The tradeoff, in one paragraph.** The scoped-sudoers path removes the password from the flow
entirely and survives a console outage, but it grants a standing privilege on the host. The
prompt path grants nothing standing — the password is used once and discarded — but it depends
on a console and gateway being up, on the operator typing a real secret into a browser, and on
an in-memory request the operator must complete within five minutes. Prefer the first; use the
second when the host cannot be given a sudoers entry.

The install request is addressed to ONE registered weirling and delivered only over that
unit's authenticated channel; an unregistered, revoked or disabled host is refused, and the
console and gateway share one single-scope credential (`WEIRVERN_SCAN_INSTALL_TOKEN`) that
opens the install routes and nothing else.

Full detail, per-distro commands and the queue's derived states: [scanner.md](scanner.md).

## Deployment

### 0. One-command install (single-node Ubuntu)

The fastest path from a bare Ubuntu box to a running deployment. It installs the three
tools (docker as *image builder only*, k3s as the runtime, kustomize), gets the
repository, prepares the node, builds and imports both images into k3s, applies the
manifests (creating the Secret once, never rotating it), waits for real readiness, and
prints the sign-in URL and the one-time admin password:

```bash
curl -fsSL https://raw.githubusercontent.com/hodlhart/weirvern/main/install.sh | sudo bash
# with in-path capability pre-provisioned (the mode is still switched in Settings):
curl -fsSL https://raw.githubusercontent.com/hodlhart/weirvern/main/install.sh | sudo bash -s -- --siphon
```

Run it from a checkout (`sudo ./install.sh [--siphon] [--zeek-iface X --mgmt-iface Y]`)
and it uses that checkout instead of cloning.

A fresh install enables **k3s secrets encryption** (`--secrets-encryption`). The base manifest
serves the dashboard on plain HTTP NodePort 30088 for break-glass; the supported user path is the
local HTTPS ingress. The dashboard is a Flask app served by waitress, and its rendered pages need
`WEIRVERN_FLASK_SECRET` in `weirvern-secrets` (the installer generates it; the GUI container declares
it as required, so a Secret without it refuses to start the pod). After creating the internal CA Secret, apply `k8s/tls` and browse
`https://sensor.example`; the TLS detail is in
[Transport and the trust boundary](security.md#transport-and-the-trust-boundary). The
Secrets-at-rest behaviour, and what an existing cluster must do, is in
[Secrets at rest](security.md#secrets-at-rest).

**If the target host cannot reach GitHub** — an isolated or air-gapped box, or a host you
deliberately keep without deploy credentials — copy the tree and run the installer inside it. No
clone and no network fetch is attempted, because the installer uses the checkout it finds around
itself:

```bash
# from a machine that does have the code:
tar --exclude=.venv --exclude=.git --exclude=__pycache__ -czf weirvern.tgz -C /path/to/weirvern .
scp weirvern.tgz you@target:/tmp/
# on the target:
sudo mkdir -p /opt/weirvern && sudo tar xzf /tmp/weirvern.tgz -C /opt/weirvern
cd /opt/weirvern && sudo ./install.sh
```

That path is identical in effect: same manifests, same image builds, same readiness checks. The
only difference is where the source came from. The private-repository case is the common one — a
`git clone` would ask for credentials the target is not supposed to hold.

**It asks what the deployment should DO, after it is running.** Three questions, each answerable
with Enter, and each written to the cluster ConfigMap so it survives the next `kubectl apply -k`:
which mode the sensor runs in, which traffic to ignore when counting flows, and whether model
detections may block traffic (off by default). A repeated Enter produces a working deployment with
the documented defaults. The same questions can be revisited later:

```bash
sudo sh /opt/weirvern/scripts/install_selections.sh
```

**It detects your interfaces and asks you to confirm them.** Getting this wrong is silent — a
sensor pointed at the management port produces a capture full of this host's own traffic and
broadcast. It looks completely healthy: rows arrive, charts draw, and it contains none of the
network under test. So the installer lists every candidate with the facts that decide the question
and waits for an answer:

```
    Detected 2 interface(s):

      IFACE      ADDRESS            DEFAULT PROMISC  MAC                WHY
      ens18      192.0.2.34/24      yes     no       00:00:5e:00:53:01  carries the default route -> management
      ens19      (none)             no      no       00:00:5e:00:53:02  no address -> looks like a capture port

    Management interface (default route, SSH, cluster API) [ens18]:
    Capture interface (mirror/SPAN, or the segment to sniff)   [ens19]:
    mgmt=ens18  capture=ens19 -- correct? [Y/n]:
```

Virtual interfaces are excluded, and **tunnels deliberately so**: a `tailscale0`, `wg0` or `tun0`
is a valid UP interface *with* an address, so a naive "any interface that is not the default route"
picks it — and its capture is encrypted packets between this host and its peers, which is neither
the local segment nor anything useful. A capture port must be an Ethernet-like device.

A typo is rejected with the list of real names, because the error it would otherwise produce
arrives later from a different component looking like a Zeek bug. An addressed capture port is
flagged (a mirror feed should be passive, so it is offered for removal), and promiscuous mode is
set. Pass `--yes` for automation, `--list-interfaces` to see the detection and exit without
changing anything, or `--zeek-iface`/`--mgmt-iface` to state the answer up front.

It is idempotent: every step checks
first, credentials and trained models are never overwritten, and re-running is how you
roll an update after `git pull`. The sections below are the same sequence by hand —
they are the reference for what the installer does, and for multi-node or
non-Ubuntu clusters where the script's assumptions do not hold.

One requirement worth naming up front: the box needs an x86-64-v3 CPU (Haswell-era or
newer) — the pinned ClickHouse image is an AVX2 build, and on a VM whose CPU model
masks AVX2 (Proxmox's default `kvm64`) it crash-loops with "Illegal instruction" while
the rest of the deployment waits on it. On Proxmox, set the VM's processor type to
`host` before installing (a stop/start applies it — a reboot inside the guest does
not); the installer checks for AVX2 up front and refuses with that remedy named.

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
podman build -t registry.example.com/weirvern-worker:0.13.0 .
podman push registry.example.com/weirvern-worker:0.13.0

# The Zeek image is DERIVED, and its build context is zeek/, not the repo root —
# vendor/ja4-zeek-scripts and verify-ja4.sh are COPYd from there.
podman build -t registry.example.com/weirvern-zeek:0.5.0 -f zeek/Containerfile zeek/
podman push registry.example.com/weirvern-zeek:0.5.0
```

The Zeek build **proves itself**: it fails if the vendored JA4 module is not present at
the path the site policy loads, or if Zeek cannot actually load it — a module that
parses but emits nothing is a sensor that records no fingerprints while looking
healthy. See [TLS fingerprinting](#tls-fingerprinting).

Then point the manifests at them — one place, no per-file editing:

```bash
cd k8s
kustomize edit set image weirvern-worker=registry.example.com/weirvern-worker:sha-<commit>
kustomize edit set image weirvern-zeek=registry.example.com/weirvern-zeek:0.5.0
cd ..
```

**Tag the worker image with the commit it was built from** (`sha-<commit>`), and set that same
tag here. The overlay's `newTag` is a DEPLOYMENT PIN, not a release number: it must name exactly
the tree the image came from. A semantic version in that field says what somebody intended to run,
and it drifts — this repository's overlay once declared `0.23.65` while the cluster ran
`sha-11e0003`, so an `kubectl apply -k` would have moved both workloads to an image nobody had
built and restarted the worker (dropping any live interception) for a tag that did not exist.

A release build can still be tagged with the version (`0.23.65`), and `scripts/verify_versions.sh`
accepts either form; what it refuses is a pin that matches neither the code version nor
`sha-<commit>`. When the pin is a sha tag it is also the only record of what is deployed, so update
it in the same change that builds the image.

> **Deploy the sensor image and the site policy together.** The policy lives in a
> ConfigMap generated from `k8s/zeek/weirvern-local.zeek` and `@load`s the module the
> image ships. An image and a policy from different versions of this repository may
> disagree about what the module provides.
> If you upgrade the sensor without re-applying, the pod crash-loops.

> If the image is private, create an image-pull secret and reference it in
> `k8s/33-worker.yaml` and `k8s/50-schema-job.yaml` under `imagePullSecrets`.

### 4. Configure and deploy

```bash
git clone https://github.com/hodlhart/weirvern.git   # or your fork
cd weirvern

# Review what the cluster will run (no changes made):
sh scripts/apply_safe.sh --check

# Adjust the non-secret settings — most importantly the two sensor interfaces:
#   ZEEK_IFACE  the CAPTURE port (dedicated NIC fed by a switch mirror/SPAN)
#   MGMT_IFACE  the MANAGEMENT port (default route, SSH, cluster API)
# Check them against the node first: weirvern interfaces --node <sensor-node>
$EDITOR k8s/20-configmap-env.yaml

# Deploy. THE GUARD RUNS FIRST: it renders the manifests, compares them with the live
# ConfigMap, restores anything the GUI recorded, and REFUSES before kubectl is invoked if a
# setting that is non-empty live would be blanked. A raw `kubectl apply -k k8s/` did exactly
# that on 2026-11-20 and stopped both captures for 18 hours — do not use it.
sh scripts/apply_safe.sh

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
sh scripts/apply_safe.sh
```

> **Order matters.** The Secret is created by you, not by `apply -k`, precisely
> so that a later `apply` cannot overwrite it. If you create it *before* the
> workloads exist that is fine too — what matters is that nothing in `k8s/`
> defines it.

### Verify the roll — every workload, not two

A release is not one image swap. `deploy/weirvern-worker`, `deploy/weirvern-gui`,
`deploy/weirvern-ingest` (the weirling gateway) and the `tap` container of `ds/zeek` all run the
release image, and each is set separately; the prune CronJob is a fifth workload that `set image`
on the Deployments does not touch. On 2026-11-18 two of them were found days behind
(`weirvern-ingest` at `sha-cd0f002`, `weirvern-scanner` at `sha-283033a`, two releases old) and
the tap was a commit behind — with nothing in the console saying so, because it reports only its
own image.

After any deploy, run the check against the tag you meant to ship:

```sh
ssh <cluster-host> 'sh -s -- --pin sha-<commit>' < scripts/image_drift.sh
```

It prints every workload with its image and verdict, treats the digest-pinned upstream `goflow2` as
external rather than drifting, and exits non-zero when anything lags. No checkout is needed on the
host — the script is streamed in.

The schema is applied automatically by the `weirvern-schema` Job, which runs
the application's own `weirvern init-db` code path. There is no separate
schema-loading step and no initdb-directory mechanism to go stale.

### 5. Verify

```bash
# Wait for every workload to report ready, naming any that does not:
weirvern wait

# Workload state, resource use, and database health probes:
weirvern status
```

Then point your exporter at the sensor node's UDP ports — **32055** (NetFlow) or
**32063** (sFlow), which is what this deployment documents and tests:

```
netflow destination: <sensor-node-ip>:32055
sflow   destination: <sensor-node-ip>:32063
```

> **EITHER THE NODEPORT OR THE CONVENTIONAL PORT WORKS — 32055/32063 and 2055/6343
> both listen on the node.** This note previously said 2055/6343 were "container ports,
> only reachable from inside the cluster" and that aiming an exporter at 2055 "sends
> its packets nowhere". That was true of an earlier design and became WRONG when the
> collector moved to `hostNetwork` — measured on the running deployment:
>
>     $ ss -lunp | grep -E ':2055|:6343'
>     UNCONN  *:2055  users:(("goflow2",pid=3228,fd=6))
>     UNCONN  *:6343  users:(("goflow2",pid=3228,fd=8))
>
> The move was deliberate: a real router was observed sending NetFlow to 2055 while the
> listener was at 32055, and the packets vanished with **nothing logged** — the database
> simply stayed empty and every pod reported Running. Binding the node's own interfaces
> is what makes the collector work with an ordinarily-configured exporter.
>
> The cost is that the ports are open to whatever can reach the node, and NetFlow carries
> no authentication. See SECURITY.md for the two controls (firewall the ports, and
> `WEIRVERN_FLOW_EXPORTER_ALLOW`).
>
> Confirm what is bound with `ss -lunp | grep -E '32055|32063|2055|6343'` on the sensor
> node. If `ingest_freshness` stays red while every pod reports Running, the exporter is
> aimed somewhere the node is not listening — that is still the symptom to check first.

Within a couple of minutes `weirvern status` should show
`ingest_freshness` green, meaning flows are arriving and being aggregated.

### Optional: the CLI

It is an optional convenience — the deployment is complete without it, and
everything it does is a `kubectl` invocation you can run yourself.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
weirvern install      # checks kubectl, cluster, manifests; creates .env
```

`weirvern` locates the project automatically (nearest ancestor containing
`k8s/kustomization.yaml`), or honours `$WEIRVERN_HOME`. For the CLI to read
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
sh scripts/apply_safe.sh && kubectl -n weirvern rollout restart deploy/weirvern-worker

# Watch the worker; within a sweep or two you should see detections
weirvern logs weirvern-worker
```

Expected result: the seeded scanner and the exfil host appear in
`netflow_anomalies` at `high`/`critical`, while the other hosts stay at
`low`/`medium`. Query it directly:

```bash
kubectl -n weirvern exec statefulset/clickhouse -- \
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
podman build -t registry.example.com/weirvern-worker:0.13.0 .
podman push registry.example.com/weirvern-worker:0.13.0

# 2. Point the manifests at it (single place)
cd k8s && kustomize edit set image weirvern-worker=registry.example.com/weirvern-worker:0.13.0 && cd ..

# 3. Apply THROUGH THE GUARD. It merges the GUI's recorded settings back into the
#    render and refuses before kubectl is invoked if a capture setting would be
#    blanked. The Deployments roll automatically because they use the Recreate
#    strategy, so the collector and worker stop before their replacements start
#    (required — see the note in k8s/31-goflow2.yaml).
sh scripts/apply_safe.sh

# 4. If the SCHEMA changed, re-run the schema Job. `kubectl apply` will NOT
#    re-run an unchanged Job object, so delete it first — the Job is idempotent
#    (every statement is CREATE ... IF NOT EXISTS), so re-running is safe.
kubectl -n weirvern delete job weirvern-schema --ignore-not-found
sh scripts/apply_safe.sh

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
podman rmi registry.example.com/weirvern-worker:0.13.0
```

If you created an image-pull secret (`regcred`) it lives inside the namespace and
goes with step 2. The Pushover token, if you created the secret imperatively,
also goes with it — but the token still exists in your Pushover account until you
delete the application there.

---
