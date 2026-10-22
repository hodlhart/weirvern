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

## Remote Sonar

The Weirlings sheet's **Sonar for this weirling** action queues a durable request in
`weirling_sonar_requests`. The remote agent claims it over mTLS, runs
`sonar.survey()` on its own capture interface, and posts the measured result back. It
never creates a Job on the hub, so a same-named hub interface cannot be measured by
mistake.

This is why the mTLS agent runs as root with NET_RAW: an ARP survey needs an effective
`NET_RAW` capability, and Docker does not grant one to a non-root UID. The capture
container already carries NET_RAW; the agent does not receive NET_ADMIN.

## What still runs hub-side

- **Domain blocking** is a DNS/resolver action, not a packet action. The blocklists and
  domain rules are evaluated by the hub's DNS path; a remote sensor does not answer DNS
  for its segment, so it cannot make a remote client's resolver return a block answer.
- **Traffic gates** do run on a remote unit when it is installed with `--gate` and sits
  in the path. An mTLS gate reads the live rules and writes its state through
  `/v1/gate/rules`, `/v1/gate/state` and `/v1/gate/events`; no database credential is
  placed on the sensor. Domain rules are enforced as resolved-address packet drops,
  which is not the same as a DNS answer block.

## Boundary

The default deploy path still uses a per-sensor ClickHouse credential, and an existing
unit keeps that behaviour until it is re-installed or given the gateway env. The
`sensor_agent` now switches to mTLS when `WEIRLING_GATEWAY_URL` is present; the default
is unchanged so a live unit cannot change transport silently.
