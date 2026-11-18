#!/bin/sh
# IMAGE DRIFT — does every weirvern workload run the tag you meant to deploy?
#
# WHY THIS EXISTS. Rolling the code is a manual ritual here (build, import, `set image` per
# workload), and on 2026-11-18 two workloads were found running images from days earlier:
# weirvern-ingest at sha-cd0f002 (42 h old) and weirvern-scanner at sha-283033a, two releases
# behind. Nothing was broken in the console, because the console only ever reports its OWN image
# (`_running_version`), and nothing compared the rest. A stale workload is not a cosmetic detail:
# the scanner predated a ClickHouse timeout fix, and the gateway was serving the field-unit API
# from old code.
#
# RUN IT FROM ANYWHERE THE CLUSTER IS REACHABLE — it needs no repo checkout and no local file:
#
#     ssh root@weirvern.home 'sh -s -- --pin sha-2c3bee529' < scripts/image_drift.sh
#
# EXIT STATUS: 0 when every workload matches the pin, 1 when any workload drifts, 2 on bad usage.
set -eu

PIN=""
NS="${NAMESPACE:-weirvern}"

usage() {
  echo "usage: image_drift.sh --pin <tag> [--namespace <ns>]" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --pin) [ $# -ge 2 ] || usage; PIN="$2"; shift 2 ;;
    --namespace) [ $# -ge 2 ] || usage; NS="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

[ -n "$PIN" ] || usage

command -v kubectl >/dev/null 2>&1 || {
  echo "kubectl is not on PATH; run this where the cluster is reachable" >&2
  exit 2
}

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT INT TERM

# Deployments: name and the first container's image, one per line.
kubectl -n "$NS" get deploy \
  -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.spec.template.spec.containers[0].image}{"\n"}{end}' \
  > "$TMP" || { echo "cannot read deployments in namespace $NS" >&2; exit 2; }

# The Zeek DaemonSet's tap sidecar is rolled with the release too, and it runs the same image.
TAP=$(kubectl -n "$NS" get ds zeek \
  -o jsonpath='{.spec.template.spec.containers[?(@.name=="tap")].image}' 2>/dev/null || true)
[ -n "$TAP" ] && echo "zeek-tap $TAP" >> "$TMP"

printf '%-24s %-46s %s\n' WORKLOAD IMAGE VERDICT
printf '%-24s %-46s %s\n' "------------------------" "----------------------------------------------" "-------"

drift=0
while read -r name image; do
  [ -n "${name:-}" ] || continue
  case "$image" in
    *":$PIN") verdict="ok" ;;
    # The flow collector is an upstream image, not this project's build; its version is pinned by
    # digest in the manifest and is not expected to carry the release tag.
    *"netsampler/goflow2"*) verdict="external (digest-pinned)" ;;
    "") verdict="DRIFT (no image)" ; drift=1 ;;
    *) verdict="DRIFT" ; drift=1 ;;
  esac
  printf '%-24s %-46s %s\n' "$name" "$image" "$verdict"
done < "$TMP"

if [ "$drift" -ne 0 ]; then
  echo
  echo "DRIFT: at least one workload is not running $PIN. Roll it before trusting the release."
  exit 1
fi
echo
echo "every workload runs $PIN"
