# Weirling mTLS ingest

The gateway is the hub-side half of the weirling trust design:

```
sensor key + CSR ──POST /v1/enroll (one-time token)──▶ gateway
       ◀──────────── leaf certificate + root ──────────
sensor cert ──mTLS──▶ /v1/heartbeat, /v1/flows, /v1/plan
```

It runs on the same image as the worker and writes ClickHouse with hub credentials.
The sensor never receives a database password.

## Prerequisites

1. cert-manager is installed.
2. A **Weirling intermediate** certificate/key exists. Create the `weirling-ca` TLS
   Secret in the `cert-manager` namespace; the root key stays offline.
3. The root certificate is stored in the `weirling-root` Secret with key
   `root-ca.crt`. Sensors install that root once.

## Apply

```sh
kubectl apply -k k8s/mtls
kubectl -n weirvern wait --for=condition=Ready certificate/weirling-ingest-tls --timeout=120s
kubectl -n weirvern rollout status deploy/weirvern-ingest --timeout=120s
```

The Service is exposed as NodePort `30443`. Point sensors at:

```text
https://ingest.sensor.example:30443
```

Do not expose this NodePort to the public internet; allow only the sensor networks.

## Issue an adoption token

```sh
kubectl -n weirvern exec deploy/weirvern-gui -- \
  weirvern weirlings token --sensor-id weirvern-basement --segment "basement" --ttl 3600
```

Give the printed token to the sensor once. The gateway signs its CSR, registers the
sensor and consumes the token. Enrollment refuses a reused, expired, mismatched or
unknown token.

## Identity

The client certificate carries:

```text
URI SAN: spiffe://weirvern/sensor/<sensor-id>
EKU:     clientAuth
Issuer:  Weirling Intermediate CA
```

The gateway checks the URI SAN, then the registry row's `enabled` and `revoked_at` on
every request. A revoked sensor is refused on its next request.

## Adopting a unit

On the target, enrollment is one command against the hub:

```sh
python3 -m weirvern.weirling_client enroll \
  --hub https://ingest.sensor.example:30443 \
  --token "<one-time token>" \
  --sensor-id weirvern-basement \
  --dir /etc/weirvern-weirling/pki \
  --root-ca /etc/weirvern-weirling/pki/root-ca.crt
```

The key and CSR are generated on the target; only the CSR is sent. The command writes
`weirling.key` (0600), `weirling.crt` (leaf + intermediate) and `root-ca.crt`.

`scripts/deploy-weirling.sh --mtls` does this automatically for a new unit: it obtains
a token, copies the root, enrolls, writes the gateway URL and certificate paths to the
env file, and starts the agent with `WEIRLING_GATEWAY_URL` set. `--mtls-token` accepts an
already-issued token.

## Boundary

The default deploy path still uses a per-sensor ClickHouse credential, and an existing
unit keeps that behaviour until it is re-installed or given the gateway env. The
`sensor_agent` now switches to mTLS when `WEIRLING_GATEWAY_URL` is present; the default
is unchanged so a live unit cannot change transport silently.
