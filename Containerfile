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
FROM python:3.11-slim

# iproute2 IS A RUNTIME DEPENDENCY, not a debugging convenience.
#
# `weirvern intercept` (weir mode) needs `ip` for 17 operations: reading the interface list,
# assigning and withdrawing its own capture address, installing the table-100 policy route that
# keeps relayed traffic off the management interface, and verifying the forwarding path. The
# base image is python:3.11-slim, which has no iproute2 -- measured in the deployed pod:
#
#     $ ip addr add 192.168.3.250/24 dev eth1
#     sh: 1: ip: not found
#
# So `weir` mode could not have worked in-cluster even with every capability granted. It would
# have failed at the first ip call, after the preflight had passed, which is the worst place.
#
# Installed at BUILD time per the note below -- never at container boot.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 \
 && rm -rf /var/lib/apt/lists/*

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
RUN pip install --no-cache-dir .

# Non-root runtime (lesson: the container ran as root in v1–v19). The UID must
# match the securityContext in the manifests and the hostPath group ownership
# (GID 10001) for the tailed sensor files.
RUN useradd --system --uid 10001 --create-home weirvern
RUN mkdir -p /data /models && chown -R weirvern:weirvern /data /models /app
USER weirvern

ENTRYPOINT ["python", "-m", "weirvern.worker"]
