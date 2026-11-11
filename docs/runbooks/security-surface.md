# Threat model and network surface

## Assets

1. Network metadata: flow records, Zeek logs, hostnames, addresses and findings.
2. Model artifacts and score history.
3. ClickHouse data and its backups.
4. Console sessions, operator token and account store.
5. mTLS CA material and per-sensor identities.
6. Alert delivery credentials.

## Actors and trust boundaries

| Actor | Capability | Trust boundary |
|---|---|---|
| Internet attacker | No route to the node; host is on a private LAN | Upstream router/NAT; host firewall |
| LAN attacker | Can reach LAN services on the node | UFW and Kubernetes Service exposure |
| Compromised monitored host | Produces arbitrary flow/Zeek records | Parser and model boundaries; never trusted input |
| Compromised sensor | Holds a client certificate | mTLS identity and the fleet registry |
| Supply-chain attacker | Controls an image or package | Pinned digests/tags, SBOM and CVE gate |
| Operator error | Can change settings or apply manifests | RBAC, change policy and backups |

## Entry points and observed surface

External scan from the management host (nmap 7.98, 2026-11-11):

| Port | State | Purpose | Control |
|---:|---|---|---|
| 22/tcp | open | SSH administration | UFW: management subnet only |
| 80/tcp | open | Redirect to HTTPS | UFW: LAN only; 308 to 443 |
| 443/tcp | open | Supported console path | TLS, HSTS, LAN only |
| 30088/tcp | open | Plain HTTP break-glass NodePort | UFW: **management host only** |
| 30443/tcp | open | mTLS sensor gateway | Client certificate + fleet registry |
| 30596/tcp | filtered | goflow2 metrics | UFW: LAN only; not a user path |
| 32137/tcp | filtered | Legacy ClickHouse NodePort | Service changed to **ClusterIP**; no NodePort |
| 32055/32063/udp | open/filtered | NetFlow/sFlow ingest | UFW: LAN and sensor VLAN only |

Internal Kubernetes services remain ClusterIP (`clickhouse`, `clickhouse-external`, `weirvern-gui`,
`weirvern-ingest`, `goflow2`). There is no public ingress; the node has no public address.

## TLS and identity

- Console certificate: issued by `Weirvern Console Intermediate CA`; valid
  `2026-10-22`–`2027-01-20`; HSTS is present.
- Sensor gateway certificate: issued by `Weirling Intermediate CA`; valid
  `2026-10-22`–`2027-01-20`.
- The gateway verifies the client certificate URI SAN, then the fleet registry's `enabled` and
  `revoked_at` state on every request. `tests/test_weirling_gateway.py` and
  `tests/test_fleet_store.py` pin that a revoked sensor is refused; the agent stops its intercept
  when the hub reports revocation.
- `--legacy-clickhouse` is the explicit opt-out for a sensor that cannot use the gateway. It is not
  the default and requires a per-sensor database credential.
- No service is internet-reachable; the private LAN is the outer boundary.

## Worst-case impacts and controls

| Path | Worst case | Control |
|---|---|---|
| Stolen operator token | Read and change console state | Token is write-scoped, never rendered; sessions expire; rotate on exposure |
| Stolen sensor certificate | Inject false flow data | Per-sensor identity, registry revocation; ingest is not a control-plane path |
| ClickHouse exposed | Full history read/write | ClusterIP only; no NodePort; credentials in Secret; backups encrypted off-cluster |
| Malicious flow/Zeek record | Parser crash or poisoned baseline | Input validation, bounded fields, training/scoring separation, shadow-first models |
| Supply-chain image | Arbitrary code in cluster | Pinned base images, SBOM, CVE gate, non-root where possible |
| Host firewall disabled | LAN exposure of NodePorts | UFW enabled at boot; the break-glass NodePort is source-restricted |

## Residual risk

- A LAN host can reach the TLS console, the mTLS gateway and the flow ingest ports. That is the
  service's intended audience, not an internet exposure.
- SSH is allowed from the management subnet; key-only access and host hardening remain operator
  responsibilities.
- The deployment is single-node; a host compromise or loss is an outage, recovered from backup.
- The plain NodePort remains as a documented break-glass path restricted to the management host;
  it is not the user path.

## Verification

- External scan output and UFW rules are reproduced in the release evidence.
- `clickhouse-external` was a NodePort in the live cluster and is now ClusterIP; port 32137 is
  filtered.
- TLS certificate and mTLS certificate dates were read with `openssl s_client`.
- mTLS/revocation and fleet-state tests pass in `./scripts/gate.sh`.
