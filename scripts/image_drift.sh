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

# Init containers are NOT touched by `set image` on the named containers, so they stay on whatever
# tag was in the manifest when the DaemonSet was last applied. That is how capture died for two
# hours on 2026-11-19: the tap was current, the init containers still named a tag that had been
# pruned, and the pod sat in Init:ImagePullBackOff while every drift check said "present".
kubectl -n "$NS" get ds zeek \
  -o jsonpath='{range .spec.template.spec.initContainers[*]}zeek-init/{.name} {.image}{"\n"}{end}' \
  >> "$TMP" 2>/dev/null || true

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
# ── EVERY IMAGE A WORKLOAD NAMES MUST EXIST LOCALLY ──────────────────────────────────────────
# 0.23.82: a workload's image can vanish while the pod keeps running. k3s prunes images it thinks
# are unused; the zeek DaemonSet had run 34 days on `weirvern-zeek:0.5.0` (a LOCAL-ONLY tag -- there
# is no registry to pull it from), so nothing noticed the image was gone until a tap-image change
# recreated the pod and it sat in ImagePullBackOff for ten minutes with capture down.
echo
missing=0
# Only meaningful on the node itself: no ctr or no cluster means there is nothing to compare.
# Both the tool and a reachable cluster are required: a laptop with `ctr` installed has no node
# images to compare against and would report every workload as at risk.
# k3s keeps its own containerd: the stock `ctr` on the node talks to a different socket and
# answers with nothing, which reads as "every image is missing". Prefer the k3s one.
_ctr_images() {
  if command -v k3s >/dev/null 2>&1; then k3s ctr -n k8s.io images ls -q
  elif command -v ctr >/dev/null 2>&1; then ctr -n k8s.io images ls -q
  else return 1
  fi
}
if _ctr_images >/dev/null 2>&1 && kubectl version --request-timeout=3s >/dev/null 2>&1; then
  images=$(kubectl -n "${NS:-weirvern}" get deploy,ds \
    -o jsonpath='{range .items[*]}{range .spec.template.spec.containers[*]}{.image}{"\n"}{end}{range .spec.template.spec.initContainers[*]}{.image}{"\n"}{end}{end}' \
    2>/dev/null || true)
  # containerd reports fully-qualified names (docker.io/library/weirvern-zeek:0.5.0); a manifest
  # says weirvern-zeek:0.5.0. Compare the last path component, or every local image looks missing.
  present=$(_ctr_images 2>/dev/null | sed 's#^.*/##')
  for image in $images; do
    case "$image" in
      *netsampler/goflow2*|busybox*|*"@sha256"*) continue ;;   # upstream, digest-pinned
      *:*) ;;                                                   # a tag: an image reference
      *) continue ;;                                            # anything else is not one
    esac
    short=${image##*/}
    if ! printf '%s\n' "$present" | grep -qx "$short"; then
      printf 'MISSING %s -- named by a workload, absent from containerd; this pod cannot restart\n' \
        "$image"
      missing=1
    fi
  done
fi
if [ "$missing" -ne 0 ]; then
  echo
  echo "AT RISK: a workload names an image that is not on this node. It runs now; it will not"
  echo "restart. Rebuild and re-import it before the next roll."
  exit 1
fi

echo "every workload runs $PIN and every image it names is present"
