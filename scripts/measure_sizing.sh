#!/bin/sh
# The cluster-sizing totals in docs/deployment.md, measured from the RENDERED manifests.
#
# WHY THIS IS A SCRIPT AND NOT A NUMBER. The previous totals in the deployment guide were
# unreproducible: two review passes summed to different values because nothing stated what
# counted, and the numbers had quietly stopped matching the manifests (the GUI and the prune
# CronJob landed after they were written). A number nobody can re-derive drifts; the METHOD is
# the durable part.
#
# THE INCLUSION RULE, stated so it cannot drift: every container -- init containers INCLUDED --
# of every rendered workload: the worker, the GUI, ClickHouse, goflow2, the Zeek DaemonSet,
# the schema Job and the prune CronJob.
set -eu

# Prefer the repository venv when it exists: the CI image and a developer checkout both have
# PyYAML there, while a minimal system python may not. The method stays the same either way.
PYTHON=python3
[ -x .venv/bin/python ] && PYTHON=.venv/bin/python

kustomize build k8s/ | "$PYTHON" -c '
import sys, yaml

def q(v):
    s = str(v or 0)
    if s.endswith("m"):
        return float(s[:-1]) / 1000.0
    if s.endswith("Mi"):
        return float(s[:-2]) / 1024.0
    if s.endswith("Gi"):
        return float(s[:-2])
    return float(s)

c = m = lc = lm = 0.0
workloads = []
for d in yaml.safe_load_all(sys.stdin):
    if not d:
        continue
    kind, s = d.get("kind", ""), d.get("spec", {})
    if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job"):
        pods = [s.get("template", {}).get("spec", {})]
    elif kind == "CronJob":
        pods = [s.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})]
    else:
        continue
    workloads.append(d["metadata"]["name"])
    for p in pods:
        for ctr in (p.get("initContainers") or []) + (p.get("containers") or []):
            r = ctr.get("resources") or {}
            req, lim = r.get("requests") or {}, r.get("limits") or {}
            c += q(req.get("cpu")); m += q(req.get("memory"))
            lc += q(lim.get("cpu")); lm += q(lim.get("memory"))
print(f"requests {c:.2f} CPU / {m:.2f} GiB; limits {lc:.2f} CPU / {lm:.2f} GiB")
print("workloads:", ", ".join(workloads))
'
