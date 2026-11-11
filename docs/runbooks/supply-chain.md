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

## CVE gate

`scripts/cve_gate.py` reads Grype JSON and blocks **fixable** findings at or above the selected
severity. The default release threshold is `Critical`:

```sh
python scripts/cve_gate.py scan.json --fail-on Critical
```

Measured on the rebuilt images:

| Image | Critical | High | Medium | Low | Negligible | Gate |
|---|---:|---:|---:|---:|---:|---|
| worker 0.23.52 | 0 | 90 | 87 | 18 | 78 | PASS |
| scanner 0.14.14 | 0 | 70 | 79 | 18 | 58 | PASS |

The previous worker image had one fixable Critical (`CVE-2026-115557`, Python 3.11.17). Rebuilding
on the pinned Python 3.11.18 base removed it. Remaining High findings are mostly Debian packages
with no fixed version; they are inventory, not a silent pass.

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
