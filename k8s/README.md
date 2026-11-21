# Kubernetes deployment

**This is the only deployment path.** There is no Compose file, by design (see the
main README). The manifests in this directory, assembled by
`kustomization.yaml`, are what `weirvern install` and `weirvern start` drive.

An earlier version of this file described itself as "reference only, legacy
layout" while being the one thing that actually deploys. That was wrong and
actively misleading: it invited a reader to treat the working manifests as
sketches and look for somewhere else to start.

## Files, in the order they are applied

| File | Contains |
|---|---|
| `00-namespace.yaml` | The namespace, with the Pod Security Admission labels (read the comment there before tightening it) |
| `10-storage.yaml` | The `models` PVC |
| `20-configmap-env.yaml` | Non-secret environment (ClickHouse coordinates, Zeek log set, retention, alerting toggles) |
| `20-configmap-schema.yaml` | A decision record, deliberately NOT in the kustomize build: why the schema ships inside the package and is applied by the schema Job rather than copied into a ConfigMap |
| `30-clickhouse.yaml` | ClickHouse StatefulSet (with the backup engine's allow-list drop-in) + the Service the schema Job and worker wait on |
| `31-goflow2.yaml` | NetFlow/sFlow collector (Deployment) — one container, one process per NIC |
| `35-goflow2-launcher.yaml` | The collector launcher ConfigMap: opens `127.0.0.<n>:2055` per NIC named in `NETFLOW_IFACE` |
| `32-zeek.yaml` | Zeek packet sensor (DaemonSet) |
| `33-worker.yaml` | Ingest + detection worker (Deployment) |
| `34-gui.yaml` | The console — Deployment and the NodePort Service it is reached through |
| `35-prune-cronjob.yaml` | The retention CronJob that bounds the Zeek log directory |
| `36-watchdog-cronjob.yaml` | The dead-man watchdog CronJob: pages on stalled sinks, restarts, disk, ClickHouse space, failed Jobs and certificate expiry — and reports `unconfigured` when Pushover's keys are missing |
| `50-schema-job.yaml` | Applies `weirvern/schema/*.sql` — runs the same code path as `weirvern init-db` |
| `60-rbac.yaml` | The role the control plane uses to read workload state |
| `70-networkpolicy.yaml` | Pod-to-pod traffic restrictions |
| `zeek/` | The Zeek site policy, mounted via `configMapGenerator` |

**There is deliberately no Secret manifest.** A committed Secret is overwritten
with empty strings on every `kubectl apply -k`, which silently disables alerting
and database auth. The Secret is created imperatively, once, out of band — see the
main README's Quick start ("The deployment Secret"). Do not re-add a `secretGenerator` or a
`21-secrets.yaml`; the trap is the reason this file says so explicitly.

## Applying it

```bash
sh scripts/apply_safe.sh --check   # decide: render vs live; applies nothing (exit 3 = refused)
sh scripts/apply_safe.sh           # the supported apply: merges GUI settings, refuses a blank
kustomize build k8s/               # render without applying, to review
kubeconform -strict -ignore-missing-schemas k8s/   # validate offline
```

**`kubectl apply -k k8s/` is not a deploy.** The env ConfigMap is manifest-owned, so an apply
restores the manifest's placeholders over the live values. On 2026-11-20 23:33:43 that emptied
`CAPTURE_IFACE`/`NETFLOW_IFACE`, emptied `ZEEK_IFACES` and `INTERCEPT_PLANS`, set `SENSOR_MODE`
back to `loch`, and rolled the DaemonSet two seconds later; flow **and** Zeek capture stopped for
~18 hours while every surface still looked configured.

`scripts/apply_safe.sh` (and `weirvern apply`, which calls the same guard) renders the manifests,
compares them with the live ConfigMap, restores the values recorded in the
`weirvern.io/gui-written-keys` annotation, and **refuses before kubectl is invoked** when a setting
that is non-empty live would be blanked. It then applies the merged render and reads the ConfigMap
back, failing if a capture setting did not survive. Overrides are explicit and audited:
`--allow-blank KEY[,KEY]` and `--allow-capture-change`.

`kustomize build k8s/` and `kubeconform -strict -ignore-missing-schemas k8s/` are
safe: they render and validate the manifests locally, and change nothing. To
validate a real apply client-side, use `weirvern apply --dry-run`. (`weirvern
install` is a prerequisite CHECK, not a dry run: it reads the cluster and runs
one throwaway probe pod to test cluster DNS — it applies nothing.)

## Scaling and limits

Read "Scaling and limitations" in `docs/architecture.md` first. The short
version: **the worker must run as a single replica.** Alert state lives in the
worker process, and the ingest path tails node-local files, so a second replica
would double-alert and fight over the same hostPath.

To exceed that, you must replace the shared-filesystem transport with a real
broker — goflow2 writing to Kafka/Redpanda and ClickHouse's Kafka engine reading
it, which is also the point at which the sensor and the detector can live on
different machines. That is a design change, not a replica count.

## Why some things look over-privileged

Four of the five workloads are rejected by the `baseline` Pod Security level.
`00-namespace.yaml` documents exactly which control each one needs and why the
privileges are genuinely required rather than convenient. If you want a tighter
namespace, the change is to split the sensors into their own namespace — it is not
a label change.

## Editing these manifests

- The schema lives in the application package (`weirvern/schema/*.sql`), not in a
  ConfigMap. Do not re-add a SQL ConfigMap: that was a legacy failure mode where
  the deployed schema drifted from the code.
- Do not re-add boot-time dependency installs. A container that runs `pip install`
  at startup breaks whenever the network does.
- Keep the probes as they are. They encode measured startup behaviour (ClickHouse
  needs real time before it accepts connections) rather than guesses, and relaxing
  them turns a slow start into a crash loop.
- After any change: `kustomize build k8s/ >/dev/null && kubeconform -strict
  -ignore-missing-schemas k8s/`. The test suite also checks that every
  `configMapRef`, volume mount and PVC name resolves, because an unresolved
  reference is rejected at admission rather than at apply time.
