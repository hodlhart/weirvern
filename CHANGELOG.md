# Changelog

## v0.4.0 — Kubernetes-native deployment, control plane, and a
## packaging bug that would have deployed an empty database

The project's deployment target is Kubernetes. This release removes the
single-host container path entirely and replaces it with manifests plus a
control plane, and fixes two bugs that only a non-editable install or a real
cluster would have revealed.

### Added — Kubernetes manifests (`k8s/`)

Applied with `kubectl apply -k k8s/` (kustomize). 20 resources:

| File | Contents |
|---|---|
| `00-namespace.yaml` | Namespace with Pod Security Admission labels (`baseline` enforce, `restricted` audit/warn) |
| `10-storage.yaml` | `clickhouse-data` and `models` PVCs; storage class configurable in one place |
| `20-configmap-env.yaml` | Non-secret settings, mirroring `.env.example` |
| the `weirvern-secrets` Secret | Created imperatively by the operator; deliberately not a manifest |
| `30-clickhouse.yaml` | StatefulSet, headless Service, optional external Service |
| `31-goflow2.yaml` | Collector Deployment + UDP NodePort Service, node-pinned |
| `32-zeek.yaml` | **DaemonSet** with `hostNetwork` and `NET_RAW` |
| `33-worker.yaml` | Detection worker Deployment, node-pinned, single replica |
| `50-schema-job.yaml` | Applies the schema via the application's own `init-db` |
| `60-rbac.yaml` | Least-privilege `viewer` and `operator` roles (neither reads Secrets) |
| `70-networkpolicy.yaml` | Optional hardening; not enabled by default |
| `kustomization.yaml` | Assembles the above; generates the Zeek ConfigMap from source |

Design decisions encoded, not incidental:

- **Zeek is a DaemonSet with `hostNetwork`** — a packet sniffer sees only its own
  node's interface, so per-node is the only correct abstraction. A single-host
  "run the sniffer on the host" idiom has no cluster equivalent and no answer for
  "which node?".
- **Collector and worker are node-pinned and single-replica** — the collector
  writes a file the worker tails by byte offset, so they must share a node. The
  pin is a `nodeSelector` on a labelled sensor node rather than scheduling luck,
  because the failure mode (healthy stack, reading an empty file) is silent.
- **`externalTrafficPolicy: Local`** on the collector Service — with the default
  policy, kube-proxy on another node can accept and misroute the UDP packets.
- **`Recreate` strategy** on both writer and reader — two collectors appending to
  one file interleaves records and corrupts offset tracking.
- **Schema applied by a Job, not an initdb directory** — the initdb directory
  only runs against an empty data directory, which is precisely why schema
  changes never reached a running database in the legacy lineage.

### Added — control plane

- **CLI** (`weirvern`): `install`, `apply [--dry-run]`, `wait`, `init-db`,
  `start`/`stop`/`restart`, `status`, `logs`, `down [--volumes]`, `pull`,
  `config`, `tune`, `tui`, `version`.
- **TUI** (Textual): workload state, health probes, live anomalies, top talkers,
  editable config with secrets masked, logs by label, help.
- **`K8sBackend`** behind the existing `Backend` protocol, driving `kubectl -o
  json` rather than human-readable tables (which change shape between client
  versions and would break the TUI on an unrelated upgrade).
- Project discovery: `$WEIRVERN_HOME`, then the nearest ancestor containing
  `k8s/kustomization.yaml`, then the package location.

Lifecycle vocabulary does not map cleanly onto Kubernetes, so the tool reports the
operation it actually performed:

| Command | Operation |
|---|---|
| `start` / `stop` | Scale Deployments/StatefulSets 1 ↔ 0 |
| `stop zeek` | **Suspend** — Kubernetes rejects `replicas: 0` on a DaemonSet. A JSON-patch `remove` on resume restores the manifest's own selector exactly |
| `restart` | `kubectl rollout restart` (there is no pod-restart verb) |
| `pull` | No-op that explains itself: each node's kubelet pulls images |

### Fixed — a non-editable install deployed an empty database

The schema lived in a repo-level `clickhouse/init/`, resolved as
`Path(__file__).parent.parent / "clickhouse" / "init"`. That is correct in a
checkout and **wrong in an installed wheel**, where it resolved to a
non-existent `site-packages/clickhouse/init`. Verified against a real
non-editable install: `apply_schema()` globbed zero files, applied nothing, and
returned success — so the schema Job in a container image would have reported
completion while creating not a single table.

Two fixes, because either alone is insufficient:

1. The schema moved inside the package (`weirvern/schema/`) and is declared in
   `pyproject.toml`'s package-data, so it ships in the wheel. Verified present
   after a non-editable install.
2. `apply_schema()` now raises when the schema directory is missing or empty. A
   silent no-op that reports success is worse than a crash: it produces a
   running system with no tables.

### Fixed — `copytruncate` log rotation silently skipped records

A file replaced by a **larger** one is indistinguishable from an append by every
`stat()` field — inode (the filesystem may reuse it), size (it grew), and mtime
(a write happened either way). Verified: 5 records written, 4 inserted, one
fragment logged as malformed JSON. This is the standard `copytruncate` rotation
mode.

Detection now uses the content: for a line-oriented log, a valid continuation
offset is preceded by a newline. If the byte before the saved offset is not a
newline, the file is not the one being read and the tailer re-reads from the
start. The Zeek tailer shares the logic. Verified against a case matrix:
initial read, replacement-by-larger, append, unchanged, truncation,
partial-line-hold-back, partial-line-completion, and legacy call signature.

### Fixed — CI red on every push

`test_rotation_detection_re_reads` asserted that delete-and-recreate changes the
inode. That is a filesystem allocator property, not the behaviour under test: it
held on ext4 (0/20 reuses) and failed on GitHub's overlayfs (inode reused), which
turned every push red. Chasing it is what surfaced the `copytruncate` bug above.
Replaced with behaviour-based tests.

### Changed

- **Removed** the single-host orchestration file, the class that wrapped it, and
  all single-host container references from documentation. The `Containerfile` is
  retained: it is the image specification the cluster needs, not orchestration.
- `.gitignore` pattern corrected from `*.env` to `.env*`. The old pattern only
  matched names *ending* in `.env`, so `.env.bak` — written by the config
  editor, containing Pushover tokens and database passwords — would have been
  committed. `.env.local`, `.env.prod` and similar were also unignored.
- `.env` parsing now strips inline trailing comments, matching the `.env.example`
  template that ships them. Previously the worker crashed on `int()` for
  `DETECT_INTERVAL_S=300          # sweep cadence` while the container runtime
  accepted the same line — a divergence between two readers of one file.

### Fixed — the documented secret step was silently undone by `apply -k`

`k8s/21-secrets.yaml` shipped placeholder values and was included in the
kustomization, so the sequence the README documented —

```
kubectl -n weirvern create secret generic weirvern-secrets --from-literal=...
kubectl apply -k k8s/
```

— ended with `apply` OVERWRITING the real credentials with empty strings
(verified: `PUSHOVER_USER_KEY` went from a real key to `""`). Alerting then never
fired, with no error anywhere: the worst possible failure shape for an alerting
system.

The Secret manifest is removed and the Secret is now created out of band only.
A `secretGenerator` reading a gitignored file was tried and rejected: it fixes
the overwrite but makes `kustomize build` fail on a fresh clone and in CI, which
breaks the `--dry-run` inspection an operator uses to decide whether to deploy.

### Fixed — version skew across four places

`pyproject.toml`, `weirvern.__version__`, the image tag in the manifests, and
the CHANGELOG heading disagreed (0.1.0 / 0.1.0 / 0.1.0 / "Unreleased (v0.4.0)").
All now report 0.4.0.

### Changed

- `weirvern install` returns exit code 3 (not ready) when kubectl or a cluster
  is unavailable, distinct from 1 (error). It previously returned 0 in both
  cases, so a wrapper could not distinguish "prerequisites missing" from
  "something broke".
- Every container, including init containers, now declares resource requests and
  limits. A namespace with a ResourceQuota requiring requests would otherwise
  reject the Pod outright, and the short-lived `wait-for-clickhouse` pollers
  could be scheduled onto a full node.
- Added commented `imagePullSecrets` placeholders to the worker Deployment and
  the schema Job: a private registry is the likely case for a personal project,
  and the pods otherwise ImagePullBackOff with no in-repo hint.
- Added a commented control-plane toleration to the Zeek DaemonSet. On a
  single-node cluster that node is tainted `NoSchedule`, so without it the sensor
  stays Pending forever while everything else looks healthy. Commented rather
  than enabled, because tolerating the taint lets a privileged packet sniffer run
  on control-plane nodes in a multi-node cluster — a placement decision, not a
  default.

### Verified

- 155 tests, `ruff` clean, `mypy` clean.
- `kubeconform -strict`: 20/20 resources valid.
- `kustomize build k8s/`: succeeds; every ConfigMap/Secret reference, volume
  mount, PVC reference and probe port resolved programmatically (which caught a
  `clickhouse-logs` mount with no declared volume — the pod would have been
  rejected).
- Schema present after a non-editable install; `apply_schema` raises loudly on an
  empty or missing schema directory.

## Unreleased (v0.3.0) — Zeek packet sensor (second view of the network)

Adds Zeek as an independent sensor alongside NetFlow. Decision rationale and
measured evidence are in the README ("Why both sensors?") — the short version:
each sensor is blind to a different class of attack, and a DNS-tunnelling host
was measured with 0 connections but 40 high-entropy queries (4.82 vs 2.52
benign), which is unreachable from flow records.

### Added

- `zeek` sensor (`zeek/zeek:lts`, BSD-3-Clause) sniffing a chosen NIC / span
  port: `ZEEK_IFACE`, host networking with `NET_RAW` scoped to that workload
  only. Omit `32-zeek.yaml` to run NetFlow-only.
- Four Zeek tables: `zeek_conn`, `zeek_dns` (with computed `query_entropy` and
  `query_len` — the tunnelling signal), `zeek_ssl` (JA3/JA3S), `zeek_notice`
  (Zeek's own curated detections, ingested as corroboration, not as alerts).
- `zeek_host_activity` view joining all four per host per 5-minute window.
- Zeek TSV parser (`parse_zeek_header`, `map_zeek_*`) driven by the `#fields`
  header rather than a hardcoded column order — Zeek's field set varies by build
  and version, and a positional assumption silently shifts every value.
- `k8s/zeek/weirvern-local.zeek` site policy (hourly rotation, no mail, noisy
  notices suppressed). Two corrections since: the `policy/misc/scan` load was
  removed (deleted upstream in Zeek 6.1+), and `k8s/zeek/zeekctl.cfg` was deleted
  because nothing read it — the container runs the `zeek` binary, and that file's
  INI syntax is not Zeek script.

### Bugs found while building this (both caught only by running real inputs)

1. **Resumed Zeek reads dropped records.** Zeek data lines are positional and
   meaningless without their `#fields` header, but a resumed tail starts
   part-way through the file (the tailer deliberately holds back a partial
   trailing line). The header was no longer in front of the data, so the record
   completing that partial line was silently discarded. Fixed by caching and
   threading the parsed header through the tailer's state.
2. **`arrayStringConcat(uniqExact(x))` is illegal in ClickHouse** (needs
   `groupUniqArray`), so the `zeek_host_activity` view failed to create —
   reported only by a real server, not by the unit suite.
3. **`FULL OUTER JOIN` + `coalesce()` lost hosts present in only one source**:
   the DNS-only tunnelling host surfaced with a blank `src_addr` and zeroed
   counters. Replaced with a `UNION DISTINCT` key set LEFT JOINed to each
   source.

## Unreleased (v0.2.0) — full audit + validation

Audited the v0.1.0 baseline end-to-end against a **real ClickHouse server**
(24.8, local instance), which surfaced bugs the unit suite could not. Every fix
below was reproduced first, then fixed, then covered by a regression test.

### Critical bugs found by the audit (all would have broken a first deployment)

| # | Bug | Root cause | Fix / evidence |
|---|---|---|---|
| 1 | Worker **died on first boot** | `worker.py` read `if_model.X_train_unscaled`, an attribute the v20 detector rewrite had removed → AttributeError, retry loop, no training | Attribute restored and set at train time; guarded with `is not None` |
| 2 | **Every query raised TypeError** | `db.py` passed `database=` to `Client.query()`; clickhouse-connect accepts that only on `command()` | Removed; client is bound to the database at connect |
| 3 | **Fresh volume was unbootable** | `connect()` bound straight to the `weirvern` DB, which does not exist yet → `UNKNOWN_DATABASE` on all 30 retries, so `apply_schema()` never ran | Two-phase connect: bootstrap on `default`, `CREATE DATABASE IF NOT EXISTS`, then bind. Verified against a dropped database |
| 4 | **Three tables failed to create** | ClickHouse rejects `TTL <DateTime64 column>` (code 450, BAD_TTL_EXPRESSION) | `TTL toDateTime(col) + INTERVAL …`; all 12 objects now create on a fresh DB |
| 5 | **Duplicate ingestion** | The tailer re-read the file from offset 0 every 5s → every row re-inserted ~12×/min, corrupting aggregates and baselines | Offset + inode tracking with rotation/truncation handling |
| 6 | **Silent flow-record loss** | A half-written trailing JSON line was consumed; once the write finished the remainder was read as a fragment and lost forever | Only newline-terminated lines are consumed; offset points at the start of the partial line |
| 7 | **One collapsed aggregation window** | Materialized views windowed on `timestamp` (ingestion time), so backfilled/historical flows piled into the current 5-min bucket — 79,349 flows and 12.2 GB in one window | Views window on `time_flow_start` (the flow's own time). 102 windows → **10,372**; max window 12.2 GB → 2.6 MB |
| 8 | **Port scanner went unalerted** | Mean fusion averaged DBSCAN's correct 0.99 down to 0.405 — *below* benign hosts (0.543) — because volume-based models score ~0 on a zero-byte scan | `fuse_scores(..., mode="max")`: a confident specialist is no longer averaged away. Legacy mean retained for A/B |
| 9 | **Benign hosts alerted as "critical"** | Raw `predict_proba` is distorted by 15× class-imbalance weights → ordinary windows scored 0.97 | Percentile calibration for GB (and IF) against each model's own training distribution |
| 10 | **Alert storms by design** | Alerts were re-queried from a sliding window, so the same anomaly rows re-alerted every sweep | Sweep returns its own verdicts; alerting consumes them once |
| 11 | **Models went stale forever** | `load_or_train` early-returned after a warm start; the 6h retrain / 5-min baseline refresh had been dropped | Explicit `train_if_due` cadence (full retrain every `RETRAIN_EVERY_H`, baseline refresh each cycle) |
| 12 | **Phase 2 features silently dead** | The worker attached `_diversity`/`_temporal`, but the ensemble never passed them into `extract_features` | Enrichment now reaches the feature vector |

### Detection-quality work (driven by measured results, not preference)

- **Fusion changed from mean to max.** Measured on live data: scanner 0.405 vs
  benign 0.543 under mean fusion; the scanner was never alerted. Under max,
  scanner 0.990 vs benign ceiling well below it.
- **Thin-window damping.** 3–4 flow windows let one heavy-tailed flow (backup,
  streaming) dominate the window's statistics — measured false positives
  (benign 3-flow window, GB 0.96). Scores are damped proportionally below
  `min_flows_for_full_confidence` (10). Genuine attacks were unaffected
  (the scan had 305 flows; the exfil 3.6 GB vs a 65 MB host baseline).
- **Corroborated severity escalation.** `high`/`critical` now require two-or-more
  detectors at ≥0.85, **or** one such detector backed by a direct structural
  signature (≥50 distinct ports at ≥4.0 entropy). This fixes the case where a
  zero-byte SYN scan is invisible to volume models — they are not disagreeing,
  they have no opinion — without re-opening the single-strong-model false-positive
  shape. A lone uncorroborated signal still alerts at `medium`: not escalated,
  not silenced.
- **Realistic demo traffic.** The generator drew byte sizes from a flat uniform
  range, which made every host look statistically novel and masked tuning bugs.
  Now heavy-tailed (80% small / 17% medium / 3% large), matching LAN reality.

### Validation result (live ClickHouse, fresh database, seeded attacks)

```
port scanner .10 : 0.990  critical   (DBSCAN + 300-port structural signature)
exfil .11        : 0.990  critical   (all four detectors >= 0.99)
benign hosts     : 0 at high/critical
ACCEPTANCE: PASS
```

### Hardening / tooling

- `bandit`: 8 medium → 0 high; remaining 11 items individually reviewed and
  documented (B104 is `ipaddress` parsing, not socket binding; B608 f-strings
  interpolate only formatted datetimes and int config, never flow data;
  B301/B403 pickle of the trusted local `MODEL_DIR`; B311 demo RNG).
- `ruff` + `mypy` clean; **68 tests** (was 30) covering ingester offsets/rotation/
  partial-line handling, detector persistence roundtrip, fusion, severity gates,
  signature corroboration, thin-window damping, calibration, and worker cadence.

### Known gaps (next iteration)

- Feedback loop for reducing false positives (needs a review UI).
- Model drift alerting (e.g. F1 decay from `ml_models` history).
- TLS for ClickHouse / auth beyond `default`.
- Real NetFlow validation on hardware (pfSense/switch) — so far exercised with
  the synthetic generator against a real ClickHouse.

## v0.1.0 — the v20 rebuild

Rebuilt from scratch against every lesson of the v14 → v19 legacy lineage.
This is the testing/refinement baseline; nothing is production yet.

### Lessons applied (legacy → v20)

| # | Legacy pain point (v14–v19) | Fix in v20 |
|---|---|---|
| 1 | **Version skew**: v14.11 stayed deployed while v15/v17/v19 sat as drafts in `src/`; nobody could tell what was running | Single source of truth: the deployed artifacts (image tag + persisted models). ML code lives only in `weirvern/models/`; `MODEL_DIR` artifacts are versioned (`_v1.pkl`) and the running version is visible |
| 2 | **State loss**: models trained in-memory each boot; every restart meant cold-start retraining | Detectors persist to disk (pickle) + metadata to `ml_models`; warm start on boot (`BaseDetector.load()`) |
| 3 | **Schema in configmap**: giant YAML-escaped SQL drift; "0 baselines" bugs from schema mismatches | Real `.sql` files packaged with the application, applied idempotently, version-stamped in `schema_versions` |
| 4 | **pip install at pod boot** (`python:3.11-slim` + pip in `command:`) | Build-time install in the `Containerfile`; pinned deps in `pyproject.toml` |
| 5 | **Inline-heredoc tailer** in the goflow2 Deployment | `weirvern/ingester.py` — tested module |
| 6 | **No tests at all** | `tests/` (scoring, features, ensemble, alerts, config, demo) + CI (lint, mypy, pytest) |
| 7 | **Magic numbers across versions** (thresholds, weights, agreement levels changed every release) | All knobs in `weirvern/config.py` (env-driven) with validation |
| 8 | **Explainability bugs**: fake 9.9 z-scores, empty `feature_contributions` | Scored, bounded explainability fields; percentiles/z-score driven |
| 9 | **No alerting**: anomalies sat in a table | Pushover transport + per-source cooldown + hourly cap + full `alert_events` audit |
| 10 | **Runaway pod / no graceful shutdown** | Resource limits, probes, non-root user, SIGTERM handling |
| 11 | **No security posture** | Network exposure minimal (collector UDP only), SECURITY.md, RBAC, Pod Security Admission labels |
| 12 | **Grafana failure → custom TUI** | Control-panel TUI (`weirvern tui`): status, health, anomalies, config, logs |

### Architecture changes vs legacy

- **Kubernetes-native**: manifests under `k8s/`, applied with `kubectl apply -k
  k8s/`. The legacy k0s layout is reflected there (namespace → storage →
  configmaps → workloads → services → jobs).
- ClickHouse database renamed `default` → `weirvern`.
- New `alert_events` table (audit trail), `schema_versions` (schema stamps).
- Worker is one long-running process: ingest thread + detection loop.
- Synthetic traffic generator (`weirvern.tools.demo_flows`) writes goflow2-
  shaped JSONL so the whole pipeline is exercisable without a NetFlow source.

### v19 feature set retained (Phase 2 multi-granularity)

- Diversity metrics: unique dst ports, port entropy (Shannon), bytes stddev,
  connection density.
- Temporal metrics: activity regularity (CV — C2 beaconing), burstiness,
  minute activity.
- Isolation Forest: 14 features, contamination 0.06, extremes sampling.
- DBSCAN: 8 features.
- Adaptive baseline: per-host p95/p99/p999 + σ baselines.
- Adaptive thresholds: pattern-aware sensitivity reduction (floor 0.20).

### Known gaps (next iteration)

- Feedback loop for reducing false positives (needs a review UI).
- Model drift alerting (e.g., F1 decay from `ml_models` history).
- TLS for ClickHouse / auth beyond `default`.
- Real NetFlow validation on hardware (pfsense/switch) — demo generator only so far.
