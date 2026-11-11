# Supply chain and CVE gate

## Builds

- Worker and scanner are built from the repository with pinned base images:
  `python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535`.
- A clean `git archive HEAD` build of the worker was run from `/tmp/wv-repro`; the resulting
  image was recorded as `sha256:c1e4864acc45917752dc12d6adc49c118a14f13fb46ed8b70fbf74eb795c1c78`.
  A clean scanner build from the same tree was recorded as
  `sha256:cab4527c7aaa243e8cfa274492421a8630acbed76cfccd19790ee81f4a55951a`.
- Runtime dependencies are installed at build time from the pinned `pyproject.toml`; the
  deployment does not fetch packages at container boot.

## SBOM

Syft produces SPDX JSON for both release images:

- `/home/admin/weirvern-sbom/weirvern-worker-0.23.52-cve.spdx.json`
- `/home/admin/weirvern-sbom/weirvern-scanner-0.14.14-cve.spdx.json`
- third-party images: `clickhouse-26.8.spdx.json`, `goflow2-v2.2.6.spdx.json`,
  `weirvern-zeek-0.5.0.spdx.json` (Zeek was exported from the cluster's containerd store, so the
  SBOM describes exactly the running derived image)

## CVE gate

`scripts/cve_gate.py` reads Grype JSON and blocks **fixable** findings at or above the selected
severity. The default release threshold is `Critical`:

```sh
python scripts/cve_gate.py scan.json --fail-on Critical
```

Measured on the rebuilt images:

| Image | Critical | High | Medium | Low | Negligible | Gate |
|---|---:|---:|---:|---:|---:|---|
| worker 0.23.52 | 0 | 98 | 107 | 18 | 78 | PASS |
| scanner 0.14.14 | 0 | 70 | 79 | 18 | 58 | PASS |
| clickhouse 26.8 | 0 | 2 | 100 | 21 | 9 | inventory |
| goflow2 v2.2.6 | 22 | 104 | 74 | 14 | 1 | **accepted upstream risk** |
| weirvern-zeek 0.5.0 | 30 | 241 | 182 | 53 | 122 | **accepted upstream risk** |

The final worker image also carries 39 `Unknown`-severity findings (no severity assigned by the scanner); they are inventory, not a pass. The previous worker image had one fixable Critical (`CVE-2026-115557`, Python 3.11.17). Rebuilding
on the pinned Python 3.11.18 base removed it. Remaining High findings are mostly Debian packages
with no fixed version; they are inventory, not a silent pass.

The third-party images are upstream artifacts, not images this repository builds. Their Critical
findings have an owner (upstream maintainer / the next base-image or sensor-image refresh) and a
remediation target of the next scheduled scan; they are not silently omitted from the inventory.
The release gate above is deliberately scoped to the two images built here: failing a release on
an upstream Zeek base with no fixed package would not make the network safer, and would train the
operator to bypass the gate. This is an accepted risk, not a claim that those images are clean.

## Scheduled scan and emergency rebuild

`scripts/cve_scan.sh` writes a fresh Syft SBOM and Grype report for the worker and scanner, then
runs the gate. It is the scheduled job's only entry point:

```sh
sh scripts/cve_scan.sh
```

The job runs monthly on the management host as Hermes cron `f374d0a1f105` (first of the month,
04:00 America/Chicago). The emergency path was rehearsed on 2026-11-11: the
worker had one fixable Critical in Python 3.11.17, the base was updated to 3.11.18, both images
were rebuilt, the new worker SBOM showed **zero Critical**, the gate passed, and the rebuilt
worker was rolled out and read back as Python 3.11.18. The release record names the image ID and
the scan files.

## Update policy

- Re-scan both images on the first of each month and after any base-image update.
- Rebuild within 7 days when a **fixable Critical** appears, within 30 days for a fixable High.
- Do not deploy a new image when the gate fails; record the exception, owner and expiry if a
  release must proceed for an operational reason.
- Keep the SBOM and scan JSON with the release record.

## Known limitation: digest deploy

The local k3s cluster has no registry. A bare digest reference could not be pulled and the
rollout entered `ImagePullBackOff`; it was rolled back to the release tag and all workloads
recovered. The deployment therefore records the immutable build identity in the release record
and deploys the release tag until a registry is available. This is an accepted exception for
PLT-0, not a claim that tag deployment is equivalent to digest deployment.
