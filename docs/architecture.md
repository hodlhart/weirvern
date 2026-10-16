# Architecture

*Part of the [Weirvern](../README.md) documentation.*

How the pieces fit together, what each sensor mode is for, and
what this design does not do yet.

## Architecture

**The data flow, in one pass.** NetFlow/sFlow exports (switches, pfSense, VMs) arrive at the
goflow2 collector, which writes them as JSONL; the worker tails that file and batch-inserts
into ClickHouse. Mirrored packets (a SPAN or mirror port, or a NIC in the path) feed Zeek,
whose log files the same worker tails and parses. ClickHouse holds the raw flows (TTL: 3
days), the aggregated windows with their diversity and temporal tables, the Tier-3 Zeek
tables, and the model outputs — `netflow_anomalies`, `near_misses`, `alert_reviews`,
`alert_events`, and the model and baseline history. The worker's second stage trains the
ensemble and scores every window; the SOC console and the API read what all of that recorded,
and Pushover carries the alerts that pass the hygiene gates.

### Workloads

| Workload | Kind | Image | Role |
|---|---|---|---|
| `clickhouse` | StatefulSet | `clickhouse/clickhouse-server:26.8` | Time-series store; aggregation via materialized views |
| `goflow2` | Deployment | `netsampler/goflow2:v2.2.6` | NetFlow v5/v9/IPFIX + sFlow collector, JSONL to a host path |
| `zeek` | **DaemonSet** | `weirvern-zeek:0.5.0` | Packet sniffer: conn/DNS/TLS/notice + Tier-1 logs from a NIC or mirror port |
| `weirvern-worker` | Deployment | `weirvern-worker:0.13.0` | Ingest (both sources), ensemble detection, Pushover alerts |
| `weirvern-gui` | Deployment | `weirvern-worker:0.13.0` | Web UI with accounts on NodePort 30088; admins edit, viewers read |
| `weirvern-prune` | **CronJob** | `weirvern-worker:0.13.0` | Enforces the per-component disk caps |
| `weirvern-schema` | Job | `weirvern-worker:0.13.0` | Applies the ClickHouse schema |

Three details of this table are Kubernetes design statements, not incidentals:

- **Zeek is a DaemonSet with `hostNetwork: true`** because a packet sniffer can
  only see traffic on the interface it is attached to — a property of the *node*,
  not of a pod. One sniffer per node is the only correct abstraction.
- **`goflow2` and `weirvern-worker` are node-pinned and single-replica** because
  the collector writes a file that the worker tails. See
  [Scaling and limitations](#scaling-and-limitations).
- **The Zeek image is DERIVED** (`zeek/Containerfile`), not upstream `zeek/zeek:lts`.
  Zeek 9.x core ships no TLS-fingerprint policy at all, so the JA4 module is
  **vendored into this repository** (`zeek/vendor/ja4-zeek-scripts/`) and copied into
  the image at build time — no package manager, no network fetch. See
  [TLS fingerprinting](#tls-fingerprinting).

### Sensor modes: `loch` and `siphon`

`SENSOR_MODE` decides how Weirvern gets packets, and the two modes differ in whether
Weirvern can affect the network at all. That difference is the whole point of naming them.

| Mode | What it does | Can it affect traffic? |
|---|---|---|
| **`loch`** (default) | Passive capture. Zeek listens on a promiscuous NIC fed by a switch SPAN/mirror port or a passive TAP, and observes. | **No.** Still water. |
| **`siphon`** | In-path intercept. ARP-forges the gateway mapping so chosen hosts send their off-link traffic to Weirvern, which relays it in the kernel. | **Yes** — Weirvern becomes a router, so it must fail open. |

```bash
weirvern mode                      # what mode is configured, and can it run here
weirvern mode loch                 # passive (what most deployments want)
weirvern mode siphon               # in-path intercept (gated on the sensor's capabilities)
weirvern intercept --dry-run       # inspect a siphon plan without touching the network
```

**`siphon` is opt-in and gated** because failing in it means an outage, not a blind spot.
It requires `CAP_NET_ADMIN` (the passive sensor deliberately does not have it), and
`weirvern intercept` runs a preflight that refuses to start rather than poison a segment
it cannot relay for. `--dry-run` reports the blast radius — every host whose ARP cache
would be forged — and offers addresses that answered no ARP.

**The intercept is supervised by default and `weirvern status` still says so.**
Setting `SENSOR_MODE=siphon` with a complete intercept plan (segment, address, gateway,
and at least one target) makes the worker start and supervise an intercept: it appears on
the sensor panel within seconds, and every forged mapping has a fail-open watchdog
behind it. `weirvern status` FAILS, with an explanation, when the mode is `siphon` but no
intercept has a live heartbeat — because a config that reads "in-path" while redirecting
nothing is exactly the failure mode this project refuses to ship.

**`siphon` is an L2/L3 redirect, not a TLS intercept.** Nothing is decrypted, no certificate
is substituted, and no payload is inspected. It is also not a man-in-the-middle in the
cryptographic sense: TLS sessions continue to authenticate end to end.

Safety in `siphon` mode comes from the **fail-open watchdog**, which is required rather than
optional. It restores every forged mapping if the process is stopped, killed, or crashes,
and it fails open when forwarding stalls. Three properties are worth knowing before trusting it:

- **Poison frames refresh continuously.** ARP entries age, and a host's real gateway traffic
  refreshes them, so a single poisoning does not hold.
- **A quiet network does not trip it.** The watchdog only treats a still forwarding counter
  as a stall once it has actually *observed* forwarding working — an idle segment looks
  identical to a broken one, and conflating them makes `siphon` flap.
- **There is a self-destruct deadline.** `--seconds` bounds the run; `--max-runtime`
  (default: `--seconds + 120s`) restores from inside the process even when no signal can
  ever reach it — the killed-`kubectl exec`-client case. The last resort is the kernel's
  own ARP expiry, measured on stock Linux defaults: **~1 minute** for a host actively
  using the network, and **seconds from that host's next packet** for an idle one.

### Channel: enforcement in line, still `loch`

A channel is a second way to be in the path **without intercepting anything**. Two ports —
upstream toward the network, downstream toward the protected device — are joined into one
bridge, so traffic passes *through* the box while Zeek keeps observing. `SENSOR_MODE` stays
`loch`; nothing is redirected and no ARP is forged. The Sluice Gate's rules are enforced on
that path: the kernel drops exactly what the rules name and forwards everything else.

**The claim is verified from the kernel, never from configuration.** Before the gate reports
a channel it checks that both ports are present, on ONE bridge, forwarding, with carrier up,
with bridge-nf in effect, and that the node's own FORWARD path admits the bridge interface —
without that last check a channel can silently *blackhole the whole segment*, which is worse
than a gate that admits it is not enforcing. What the gate actually found is recorded as
`enforcement` — `channel`, `siphon`, or `none` — so a configured channel with no verified path
degrades to `none` instead of reading "armed".

**The channel's traffic can also be metered.** `CHANNEL_NETFLOW` (`off` / `upstream` /
`downstream`) samples one of the two ports — either sees every crossing frame; sampling both
would count each conversation twice — and summarises it into the deployment's own collector,
so the records land in the same `flows` table the Netflow view and the models already read. It
is a selection, not a second pipeline, and it runs only while a verified channel is active.

### TLS fingerprinting

Weirvern ingests **JA4** TLS client fingerprints (`zeek_ssl.ja4`) — the modern successor
to JA3, which Zeek 9.x core no longer ships.

JA4 is **BSD 3-Clause** — free for any use, including commercial — and the module
(`zeek/vendor/ja4-zeek-scripts/`) is vendored into this repository, license text
included, then copied into the sensor image at build time. No package manager and no
network fetch are involved: the image contains exactly what the repository shows.

Vendoring is deliberate on two counts. A build that depends on a fetch can fail for
reasons that have nothing to do with the code. And a module that lives in this
repository is reviewed like every other file here — the sensor image cannot gain a
fingerprinting method nobody chose.

Two consequences for operators:

- **The sensor image and the site policy ship together.** The policy lives in a
  ConfigMap generated from `k8s/zeek/weirvern-local.zeek` and `@load`s the vendored
  module. An image and a policy from different versions of this repository may
  disagree about what the module provides; deploy them as a pair.
- **Nothing to configure.** There is no option list to get right — the module contains
  only JA4, so there is no disable list and no load ordering to maintain.

### Passive host identification

An address tells you nothing about what a machine *is*. This answers that from evidence the
sensor already collected, without touching the network.

**Nothing is probed.** An authenticated scanner asks a host what it runs; that needs credentials
and a cooperating host, and it is loud. Everything here is derived from traffic that was already
on the wire, so a device that never answers anything is still identifiable if it ever spoke.

| Source | Strength | What it actually says |
|---|---|---|
| `software.log` | **strong** | The application banner names its own platform: `OpenSSH_10.2p1 Ubuntu-2ubuntu3.6` is Ubuntu, said by the build rather than inferred |
| `dhcp.log` | medium | A lease's hostname, FQDN and MAC. Valuable out of proportion to its size because it arrives **before** application traffic — a host that just booted is identifiable, which is when an unknown device is least observable |
| `ssl.log` (JA4) | structural | Transport, TLS version, cipher and extension counts, ALPN — **not** an operating system (see below) |
| MAC OUI | weak | The NIC vendor, which on a VM is the hypervisor. Identifies *what kind of device*, not what runs on it |

**Confidence counts independent sources, not signals.** Three hostname conventions matching is one
hint repeated and stays `low`; a lease and a banner agreeing reaches `high`. A single strong source
(a build banner) can reach `medium` on its own. The rule exists because fingerprinting fails in one
characteristic way that is worse than not having it: **a confident wrong answer nobody rechecks.**

**A host whose sources disagree is a finding, not noise.** A renamed machine, a dual-boot host and
a spoofed hostname all read as "Windows and Linux at once", and the panel shows both claims with
their evidence rather than averaging them into a tidy answer.

**A JA4 deliberately yields no OS.** It identifies a TLS *stack*, and the same fingerprint is shared
by a Windows host and a Mac running the same browser. Naming an operating system from it needs a
labelled hash database, and none is shipped here — for the licence reason the repository's own CI
enforces, and because a downloaded table cannot be verified from inside this repository. The
structural facts are reported; the OS claim waits for evidence that supports it.

**Two tables, because fingerprints change.** `host_fingerprints` holds raw observations with no
interpretation; `host_identity` holds the current verdict. Keeping the raw string is what lets a
better reference table **re-score history** rather than only affecting new traffic — and lets an
operator's confirmation become evidence, which outranks every inference. A verdict stored without
its evidence could never be corrected.

### Why both sensors?

They are not redundant — each is blind to a different class of attack:

| | NetFlow/sFlow | Zeek |
|---|---|---|
| Sees | Volume, packet counts, 5-tuple, topology | Protocol behaviour: DNS queries, TLS/JA4 fingerprints, connection states |
| Blind to | Slow scans, DNS tunnelling, JA4-tagged C2, anything payload- or protocol-shaped | Nothing about volume — no idea a host moved 3.6 GB |
| Cost | Cheap (router exports it) | Needs a mirror/SPAN port or a NIC in the traffic path; CPU per packet |

Measured on the test rig: a DNS-tunnelling host showed **0 connections but 40
high-entropy queries** (entropy 4.82 vs 2.52 benign, max label 71 vs 15 chars) —
invisible in flow records. Conversely a 3.6 GB exfil spike is obvious in flows
and unremarkable in conn logs. Zeek's own `notice.log` (e.g. `Scan::Port_Scan`)
is ingested as independent corroboration for the ML ensemble, not as an alert
source of its own.

**NetFlow only?** Skip the sensor entirely by removing `32-zeek.yaml` from
`k8s/kustomization.yaml`. Nothing else depends on it, and there is no separate off
switch to flip: the sensor is a DaemonSet, and a DaemonSet cannot be scaled to zero —
dropping the manifest is the one way not to run it.

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

**Identify.** Every host's operating-system family, derived **passively** from traffic the sensor
already saw — nothing is probed and nothing is sent, which is the difference between this and an
authenticated scanner that needs credentials and cooperation. Sources are application banners
(`software.log`, which names its own platform), DHCP leases, NIC vendors and TLS ClientHello
fingerprints. Confidence counts how many **independent** sources agree, so a hostname convention
alone reads as `low`; a host whose sources **contradict** is flagged rather than smoothed over.
Coverage is stated as a fraction of hosts seen, so a small numerator cannot mislead. See
[Passive host identification](#passive-host-identification).

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
