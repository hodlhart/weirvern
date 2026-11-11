# Capacity, failure domains and the single-node limit

## Measured sizing

`scripts/measure_sizing.sh` on the current manifests:

- Requests: **1.99 CPU / 3.72 GiB**
- Limits: **10.75 CPU / 17.88 GiB**
- Workloads: goflow2, GUI, ingest, scanner, worker, ClickHouse, prune, Zeek, schema Job

The node has **4 CPU / 10 GiB**. The request total fits; the limit total is overcommitted. The
limits are ceilings, not reserved capacity, but they mean a memory spike can evict or restart a
process rather than being absorbed. ClickHouse is the first victim of memory pressure because it
holds the working set; the worker is next.

| Workload | Requests | Limits | Observed |
|---|---|---|---|
| worker | 500m / 1 GiB | 2 CPU / 4 GiB | ~349 MiB |
| ClickHouse | 500m / 1 GiB | 2 CPU / 4 GiB | ~1.2 GiB |
| GUI / ingest | small | 2 CPU / 4 GiB each | <150 MiB each |

## Availability model

**Single-node, best-effort availability. There is no HA.** The node runs one replica of worker,
GUI, ingest, scanner and one ClickHouse StatefulSet. A node or disk loss is an outage; recovery is
restore from the off-cluster backup, with the PRG-0 RTO of 4 hours. The Zeek sensor is a
DaemonSet on the same node; its capture stops with the node.

This is deliberate: the alternative (a multi-node cluster with replicated ClickHouse) is a
separate project and is not implied by any manifest.

## Pod-failure drill

Measured on 2026-11-11:

- Deleted `weirvern-worker-5f45c77d74-zh2kl` at `05:42:36Z`.
- Replacement pod ready in **7 seconds**.
- `/api/health` green afterwards: ClickHouse, tables, ingest freshness, Zeek freshness, models,
  detect loop, alerts, fingerprint feed and account store all `true`.
- ClickHouse and ingest were not restarted; no data was lost. The only gap is detection scoring
  during those seconds.

A node failure cannot be survived in place: the same test would end in a restore from backup, not
a reschedule. That is the honest failure domain.

## Memory and OOM behavior

- Worker and ClickHouse both have a 4 GiB limit. Exceeding it restarts the container; ClickHouse
  recovers from its PVC, and the worker resumes its tails and scoring.
- No synthetic peak-load run was performed. The observed steady state has substantial headroom,
  but this is not a claim that a crafted traffic burst cannot cause an OOM restart. The accepted
  follow-up is a bounded load test against a restored copy, not production.

## Operator actions

- If ClickHouse is repeatedly OOM-killed: stop adding workloads, lower the worker's concurrent
  sweep, or raise the node memory before changing limits.
- If the worker restarts: check `detect_loop`, ingest freshness and the model probe. A restart is
  safe; a restart loop is not.
- If the node is lost: declare a disaster, restore the latest off-cluster backup, then verify
  counts and model scores before reopening alerting.
