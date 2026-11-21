#!/bin/sh
# THE SUPPORTED WAY TO APPLY THE MANIFESTS.
#
# `kubectl apply -k k8s/` is NOT safe for this project: the env ConfigMap is manifest-owned, so an
# apply restores the manifest's PLACEHOLDERS over the live values. On 2026-11-20 23:33:43 that
# emptied CAPTURE_IFACE/NETFLOW_IFACE, set SENSOR_MODE back to loch, emptied INTERCEPT_PLANS and
# rolled the DaemonSet two seconds later; flow and Zeek capture stopped for ~18 hours.
#
# This wrapper renders the manifests, compares them with the live ConfigMap, merges the values the
# GUI recorded back in, and REFUSES before kubectl is invoked if a setting that is non-empty live
# would be blanked. It then applies the merged render and reads the ConfigMap back.
#
#   sh scripts/apply_safe.sh --check          # decide only; apply nothing (exit 3 on refusal)
#   sh scripts/apply_safe.sh                  # apply through the guard
#   sh scripts/apply_safe.sh --allow-blank CAPTURE_IFACE   # explicit, audited override
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

PY=${PYTHON:-python3}
[ -x .venv/bin/python ] && PY=.venv/bin/python

exec "$PY" -m weirvern.admin.config_guard --project-dir "$ROOT" "$@"
