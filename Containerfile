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
