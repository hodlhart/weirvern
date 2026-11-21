#!/bin/sh
# Scan the images this repository builds, write an SBOM and a Grype report, and enforce the gate.
#
# This is intentionally not a CI-only idea: the images are built on the operator host, so the
# scheduled run has to work there too. `anchore/syft` and `anchore/grype` are the only tools
# required; neither is installed on the host itself.
#
#   sh scripts/cve_scan.sh
#   WEIRVERN_SBOM_DIR=/secure/sbom sh scripts/cve_scan.sh
#
# The exit code is the gate's: 0 means no fixable Critical finding in the images built here.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUT=${WEIRVERN_SBOM_DIR:-"$ROOT/../weirvern-sbom"}
mkdir -p "$OUT"

scan_one() {
    image=$1
    name=$(printf '%s' "$image" | tr '/:' '__')
    echo "scanning $image"
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$OUT:/out" \
        anchore/syft:latest "$image" -o "spdx-json=/out/${name}.spdx.json" >/dev/null
    docker run --rm -v "$OUT:/work" anchore/grype:latest \
        "sbom:/work/${name}.spdx.json" -o "json=/work/${name}.vuln.json" >/dev/null
    echo "$OUT/${name}.vuln.json"
}

WORKER=${WEIRVERN_WORKER_IMAGE:-weirvern-worker:0.23.126}
SCANNER=${WEIRVERN_SCANNER_IMAGE:-weirvern-scanner:0.14.14}
WORKER_SCAN=$(scan_one "$WORKER" | tail -1)
SCANNER_SCAN=$(scan_one "$SCANNER" | tail -1)

exec "$ROOT/.venv/bin/python" "$ROOT/scripts/cve_gate.py" "$WORKER_SCAN" "$SCANNER_SCAN" --fail-on Critical
