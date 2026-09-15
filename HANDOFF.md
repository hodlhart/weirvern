# Weirvern — handoff / where to pick up

**Written:** 2026-09-15. **Repo:** `github.com/hodlhart/weirvern` (private), branch
`main`, HEAD `c6dd0dd`, **CI green**. Local checkout is still at
`/home/hart/Documents/flowforge` (renaming the directory is safe; nothing
references that path).

**Gate at time of writing:** 193 tests passing · ruff clean · mypy clean ·
19/19 rendered manifests strict-valid · `kustomize build k8s/` succeeds.

---

## What Weirvern is

Network-flow anomaly detection on Kubernetes. Two sensors feed one pipeline:

- **goflow2** — NetFlow v5/v9/IPFIX + sFlow collector. Writes JSONL to a hostPath.
- **Zeek** — packet sniffer on a chosen NIC, writes TSV logs to a hostPath.

A Python worker tails both, inserts into ClickHouse, and runs a four-model
scikit-learn ensemble (IsolationForest, GradientBoosting, DBSCAN, AdaptiveBaseline)
to flag anomalies, alerting via Pushover.

`weirvern/admin/` is the control plane: a CLI and a Textual TUI that drive the
cluster through `kubectl`.

---

## Just completed: three independent audits, blocking defects fixed

Three reviewers (manifests, Python, docs) ran in parallel. Each found defects that
meant **the deployment did not work**. All blocking ones are now fixed, each
verified by reproduction first. Commit `c6dd0dd` has the full detail; the short
version:

| Defect | Effect | Status |
|---|---|---|
| `PROJECT_DIR` resolved at import | Schema Job crashed instantly → **zero tables created** | Fixed, verified |
| `SitePolicyFile=` passed to Zeek | Not a Zeek identifier → sensor aborted at startup | Fixed, verified from Zeek source |
| `@load policy/misc/scan` | Removed in Zeek 6.1+ → script-load abort | Fixed |
| Worker omitted `zeek_dir` | **Entire Zeek pipeline dead**, silently | Fixed |
| `PUSHOVER_ENABLED` absent from ConfigMap | **No alert could ever send** | Fixed |
| DaemonSet suspend patch | `stop` failed; `start` reported a missing sensor as running | Fixed |
| Zeek rotation glob `.1.log` | Zeek uses `.timestamp.log` → rotated logs never read | Fixed, verified |
| README gave ports 2055/6343 | NodePort is 32055/32063 → exporter sends nowhere | Fixed |
| `ps()`/`logs()`/`apply_schema()` error handling | Errors reported as "missing"/success | Fixed |

The theme worth remembering: **every one of these passed the test suite and looked
healthy in `weirvern status`.** They were found by reading the container layout, the
upstream source, and the manifests — not by running the tests.

---

## NOT done — prioritised

### 1. Deploy it to the real homelab (most valuable next step)

Nothing has ever run against real network hardware. Every acceptance result so far
is synthetic traffic against a real ClickHouse. Until this runs on the actual
network, the false-positive rate is unmeasured, and several things below cannot be
properly validated.

```bash
# on the sensor node
kubectl label node <node> weirvern.io/sensor-node=true
sudo install -d -m 2775 -g 10001 /var/lib/weirvern/flows
sudo chown -R 10001:10001 /var/lib/weirvern/flows /var/lib/weirvern/zeek

# build + push, then point the manifests at it
podman build -t <registry>/weirvern-worker:0.4.0 .
podman push <registry>/weirvern-worker:0.4.0
cd k8s && kustomize edit set image weirvern-worker=<registry>/weirvern-worker:0.4.0

# deploy, then create the Secret AFTER (see README step 4 for why the order matters)
kubectl apply -k k8s/
kubectl -n weirvern create secret generic weirvern-secrets \
  --from-literal=PUSHOVER_USER_KEY='...' --from-literal=PUSHOVER_API_TOKEN='...'
```

Point the exporter at **UDP 32055** (NetFlow) / **32063** (sFlow) — the NodePorts,
not 2055/6343.

### 2. Remaining audit findings (verified, not yet fixed)

**Would prevent normal scheduling / operation:**

- **Pod Security Admission is set to `baseline` in a namespace that needs
  `privileged`.** hostPath, hostNetwork and NET_RAW are all forbidden by baseline,
  so with `enforce: baseline` **no pod in the namespace admits** — not even
  ClickHouse. Fix: `enforce: privileged` for this namespace, or split the sensors
  into their own namespace. `k8s/00-namespace.yaml`.
- **`clickhouse-data` PVC in `k8s/10-storage.yaml` is mounted by nothing.**
  ClickHouse uses the StatefulSet's `volumeClaimTemplate` of the same name, so the
  standalone PVC binds real disk and is unused. Delete it and leave a pointer.
- **k0s ships no `local-path` provisioner** (that's a k3s default). On bare k0s both
  PVCs stay Pending forever. The storage class appears in three places, not one:
  `k8s/10-storage.yaml` (×2) and `k8s/30-clickhouse.yaml`.

**Security hardening (cheap, worth doing):**

- No `seccompProfile` anywhere. For the most privileged workload in the project
  (`hostNetwork` + raw sockets), `RuntimeDefault` is the largest remaining kernel
  attack surface and costs nothing.
- No `automountServiceAccountToken: false`; none of the four workloads uses the API.
- `k8s/60-rbac.yaml` grants no `secrets` verb, but `weirvern install` tries to read
  the Pushover key to verify it — so that check cannot work under the shipped
  viewer role. Either scope a narrow `get` on that one Secret, or state that the
  check needs the operator's own kubeconfig.

**Correctness / docs:**

- **`MIN_AGREEMENT` is documented but never read.** `ensemble.py:241` computes
  `0.33 if final_score < 0.6 else 0.25` as a local literal; `settings.min_agreement`
  is parsed and validated but unused. It's surfaced in `weirvern tune` and
  `.env.example` too. Either wire it up or remove it from the docs.
- **README resource totals are understated**: actual rendered totals are
  1.63 CPU / 3.09 GiB requests and 8.4 CPU / 12.25 GiB limits — the README says
  1.5/2 and 7/8, and its "4-core / 8 GB is comfortable" recommendation is
  contradicted by its own numbers (a single node must satisfy the *limits*).
- **README references a `files` table that does not exist** (`weirvern/schema/`
  has no files table; it lists `notice`, `files` together).
- **Dangling references** to deleted files: `README.md` and `CHANGELOG.md` cite
  `21-secrets.yaml`; `k8s/kustomization.yaml` cited `secrets.env.example`. Mostly
  fixed; grep for any remainder before publishing.
- **`k8s/README.md` is stale** — it describes the k8s/ manifests as "reference
  only, legacy layout" when they are the only deployment path. Two manifests name
  it as the authority for the "why replicas must be 1" constraint, which does not
  exist there (it's in the top README, "Scaling and limitations").
- **README has no toleration/taint guidance** for the single-node case that it
  recommends — the Zeek DaemonSet ships the toleration commented out precisely
  because a single-node kubeadm cluster taints the control plane and the sensor
  then stays Pending with no error.
- **No token-rotation or restore procedure.** Rotation needs an explicit rollout
  restart (the value is read via `envFrom` at pod start); restore must untar into a
  pod whose RWO claim is pinned to the sensor node.
- **`imagePullPolicy: IfNotPresent` + re-pushing the same tag = a silent no-op
  upgrade.** The docs' own private-registry advice creates this; the fix (bump the
  tag, or `Always`) is stated nowhere.

### 3. Tests the reviewers proved mutation-blind

Each of these would still pass if the code were broken — they're worth hardening:

- `tests/test_zeek.py` — hard-coding `tail_zeek_dir` to read only `<type>.log`
  passes the suite. That is exactly the production bug fixed in `c6dd0dd`, and it
  was uncaught. **Add a test built from Zeek's real timestamped names.**
- `tests/test_zeek.py` — the header-caching test only covers a same-file append,
  never a file replacement, so a stale cached `#fields` applied to a new schema is
  undetected.
- `tests/test_admin_runtime.py::test_service_order_matches_workloads` — tautological:
  `SERVICE_ORDER` is *defined* as `[name for name, _ in WORKLOADS]`, so the test
  asserts an expression equals itself.
- `tests/test_admin_runtime.py::test_manifests_declare_every_workload_the_backend_drives`
  — the regex has an `or re.search(rf"name:\s*{name}")` fallback that matches the
  backend's own source, so renaming a workload in the manifests still passes.
- `tests/test_admin_runtime.py` — the `_condense` tests only feed inputs at or below
  the truncation limit, so the truncation branch is never exercised.
- No test asserted that the worker passes `zeek_dir` (which is why the dead Zeek
  pipeline shipped), and none asserted a DaemonSet start *failure*.

### 4. Features discussed but not built

Full list with reasoning in `~/flowforge-backups/recommended-improvements.md`. The
two that matter most:

- **Explainability is not implemented.** `netflow_anomalies` has
  `primary_deviation_feature`, `primary_deviation_zscore`, `deviation_magnitude`,
  `feature_contributions`, `baseline_comparison` — and `worker.py` writes
  `0.0, 0.0, "{}", ""` into four of them, while `_explain_primary()` returns a
  *detector name* despite its docstring claiming a feature. The schema promises
  explainability the code never computes. This is the prerequisite for threat
  hunting and for any ATT&CK mapping.
- **ATT&CK / threat-intel layer.** Licensing is fully researched and verified in
  `~/flowforge-backups/threat-source-licensing.md`. Key facts: ATT&CK is free for
  commercial use with attribution only; **Sigma rules are DRL 1.1** (match messages
  must carry the rule author on screen) — not Apache/MIT as commonly assumed;
  MISP is AGPL-3.0 and must not be embedded.

---

## Loose ends outside the repo

1. **`hodlhart/flowforge` still exists.** Deleting it needs a token scope I did not
   grant myself: `gh auth refresh -h github.com -s delete_repo`, then
   `gh delete hodlhart/flowforge`. The repo is empty of value (0 stars, 0 forks, no
   issues/PRs/releases), so there is no rush.
2. **Local directory is still `~/Documents/flowforge`.** Safe to rename:
   `mv ~/Documents/flowforge ~/Documents/weirvern`.
3. **The logo** is `docs/logo.png` (supplied image) with favicons in `docs/favicon/`.
   The favicons are cropped to the mark (no wordmark) because downscaling the full
   canvas to 16px turns the wordmark into noise, and they are opaque because the
   source background is textured, so a colour-key erodes the dragon's glow. On a
   light browser theme the favicon reads as a dark tile. Regeneration steps are in
   `docs/README.md`. **One flag:** that image has faint artifacts suggesting it was
   edited over a watermark region; if you want a clean asset, regenerate it and swap
   the file — `tests/test_logo.py` will hold the derivatives to the same rules.

---

## Backups

`~/flowforge-backups/`:

| File | What it is |
|---|---|
| `flowforge-pre-rewrite-*.bundle` | Complete git history before the rename/history rewrite (restorable with `git clone`) |
| `flowforge-worktree-*.tgz` | Full pre-rename working tree |
| `recommended-improvements.md` | The feature roadmap with reasoning |
| `threat-source-licensing.md` | Verified licensing for ATT&CK, Sigma, MISP and others |
| `deployment-findings.md` | The fresh-clone walk that found the secret-wipe bug |

---

## How to work on this

```bash
cd ~/Documents/flowforge
source .venv/bin/activate          # or .venv/bin/pytest directly
pytest -q                          # 193 tests, no cluster or DB needed
ruff check weirvern tests
mypy weirvern --ignore-missing-imports
kustomize build k8s/ > /dev/null   # manifests must assemble
kubeconform -strict -ignore-missing-schemas k8s/
```

**Two testing conventions worth keeping:**

The suite needs **no cluster and no database**. Workload-facing tests drive a fake
`kubectl` injected by monkeypatch, so command construction is verified without one.
Keep it that way — a test that needs a cluster will not run in CI.

When you find a real defect, **reproduce it before fixing it and keep the
reproduction as the test.** Every blocking bug above was found that way, and the
one time a guard was added without a test that it *could* fail
(`tests/test_naming.py`), it scanned nothing and passed.
