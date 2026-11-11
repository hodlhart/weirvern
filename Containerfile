# Weirvern worker image.
#
# Buildable with any OCI-compatible image builder (podman, buildah, or an
# equivalent), and pushed to a registry your cluster's nodes can pull from:
#
#     podman build -t registry.example.com/weirvern-worker:0.4.0 -f Containerfile .
#     podman push registry.example.com/weirvern-worker:0.4.0
#
# Then point the manifests at it (one place):
#     cd k8s && kustomize edit set image weirvern-worker=registry.example.com/weirvern-worker:0.4.0
#
# Lesson from v1–v19: the deployment must NOT install dependencies at container
# boot. Everything is installed at build time and pinned in pyproject.toml.
FROM python:3.11-slim@sha256:07d4824036af339fa1b6ef769cc99d9c10a141769538b52b3b597c84f7a7b535

# iproute2 IS A RUNTIME DEPENDENCY, not a debugging convenience.
#
# `weirvern intercept` (siphon mode) needs `ip` for 17 operations: reading the interface list,
# assigning and withdrawing its own capture address, installing the table-100 policy route that
# keeps relayed traffic off the management interface, and verifying the forwarding path. The
# base image is python:3.11-slim, which has no iproute2 -- measured in the deployed pod:
#
#     $ ip addr add 198.51.100.250/24 dev eth1
#     sh: 1: ip: not found
#
# So `siphon` mode could not have worked in-cluster even with every capability granted. It would
# have failed at the first ip call, after the preflight had passed, which is the worst place.
#
# ── WHY softflowd AND tcpdump ARE HERE, AND WHY THEY ARE NOT OPTIONAL ─────────────────────────
#
# The channel-netflow probe (`worker._channel_netflow_maybe`) turns the in-line channel's
# crossing traffic into IPFIX records: `tcpdump` taps the port and pipes the capture into
# `softflowd`, which summarises it and exports to goflow2. Both halves are required and both
# were MEASURED in: softflowd's own live-capture loop never dispatches on this kernel (its
# libpcap counter grows while "Packets processed" stays 0, on every interface), while a capture
# file/stream it reads processes perfectly. Without either binary the operator gets a selection
# that silently does nothing -- the same silent-inert class as the missing `nft`, so the same
# test pins these install lines (tests/test_image_contract.py).
#
# Installed at BUILD time per the note below -- never at container boot.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 nftables softflowd tcpdump \
 && rm -rf /var/lib/apt/lists/*

# ── WHY nftables IS HERE, AND WHY IT IS NOT OPTIONAL ──────────────────────────────────────────
#
# The Sluice Gate compiles operator blocks into nftables sets. `choose_backend` asks whether `nft`
# is usable and, if not, returns a backend whose `available()` is False -- so the gate reports
# DEGRADED and blocks nothing. That fallback is correct (it refuses to claim ARMED while enforcing
# nothing), but it means the feature was INSTALLED AND INERT: every deployment announced a Sluice
# Gate tab, offered a block button, and could never enforce a single rule.
#
# MEASURED before this line existed, inside the running worker:
#     $ command -v nft     -> not found
#     $ nft list tables    -> sh: 1: nft: not found
# and the gate's own log line:
#     sluice gate: degraded -- ... the 'none' backend cannot install rules on this host
#     (nft missing, or no NET_ADMIN).
#
# Both halves of that message were true: no binary, and no capability. The capability is granted
# by the siphon overlay (see overlays/siphon/worker-siphon-caps.yaml, which documents why
# runAsUser: 0 is required for added capabilities to be EFFECTIVE rather than merely present in
# the bounding set). The binary has to be here in the image, because a cluster cannot install
# packages at runtime.
#
# A test pins that this line exists -- see tests/test_image_contract.py. Removing it would not
# break any build, any probe, or any other test; it would only make the Sluice Gate silently
# unable to enforce, which is exactly the class of failure this project keeps finding.

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install the package (build-time deps only for the wheel; runtime is pure
# pinned wheels from pyproject). The ClickHouse schema ships inside the package
# (declared in pyproject's package-data) because `weirvern init-db` runs from
# this image in the schema Job — copying the package is therefore sufficient,
# and there is no repo-level schema directory to add.
COPY pyproject.toml README.md LICENSE ./
COPY weirvern ./weirvern
# OP-3: the archived monthly reviews are read by /api/ml/review. They are docs, not package
# data, so they need an explicit copy; without this the dashboard correctly says no archive.
COPY docs/reviews ./docs/reviews
COPY docs/eval-reports ./docs/eval-reports
COPY docs/ledger ./docs/ledger
RUN pip install --no-cache-dir .

# Non-root runtime (lesson: the container ran as root in v1–v19). The UID must
# match the securityContext in the manifests and the hostPath group ownership
# (GID 10001) for the tailed sensor files.
RUN useradd --system --uid 10001 --create-home weirvern
RUN mkdir -p /data /models && chown -R weirvern:weirvern /data /models /app
USER weirvern

ENTRYPOINT ["python", "-m", "weirvern.worker"]
