# Development

*Part of the [Weirvern](../README.md) documentation.*

Repository layout, tests, and the gate every change passes before it
is pushed.

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
  admin/              control plane: CLI, web GUI, config I/O, k8s runtime backend
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
