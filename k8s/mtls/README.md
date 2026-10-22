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

## Boundary

The existing `sensor_agent` still writes directly to ClickHouse. This gateway is the
secure path for new and migrated units; switching the old agent is a separate change
so an existing sensor cannot silently change behavior during this rollout.
