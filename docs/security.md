# Security and privacy

*Part of the [Weirvern](../README.md) documentation.*

Privileges, RBAC, data sensitivity and network exposure --
what this tool can reach, and what it refuses to.

## Security and privacy

### Privileges

The most privileged workload is Zeek, and it needs to be: packet capture is
impossible without `hostNetwork` and `NET_RAW`. It runs as root, because
Kubernetes keeps added capabilities only for root containers — verified on a
real cluster: `runAsUser: 0` leaves `CAP_NET_RAW` effective (`CapEff 0x2000`) and
capture works, while a non-root uid leaves the capability set empty and the
sensor dies with `pcap_error: socket: Operation not permitted`. The reasoning is
recorded next to the setting in `k8s/32-zeek.yaml`. Apart from that uid it is
scoped as tightly as the task allows: all other capabilities dropped, no
`NET_ADMIN`, and its only host access is the log directory. Every other workload
runs non-root with all capabilities dropped. See [SECURITY.md](../SECURITY.md).

### RBAC

`k8s/60-rbac.yaml` defines two roles: a read-only `viewer` for monitoring
(what `weirvern status` uses) and an `operator` that adds the lifecycle verbs. Neither can
read Secrets — an account that displays health cannot exfiltrate the Pushover
token.

The operator role is name-scoped wherever the API allows it, and says where the API does not:

- workload restarts (`patch`) are limited to the exact objects the GUI rolls (`zeek`,
  `weirvern-worker`, `weirvern-gui`);
- ConfigMap writes are limited to the two objects the GUI writes (`weirvern-env`,
  `weirvern-users`); the first-startup `create` is the documented exception, because
  `resourceNames` cannot restrict a create — measured against a live cluster, not assumed;
- `update` appears only on `/scale` subresources, name-scoped to the workloads the CLI's
  stop/start drives — never on a workload object, where a PUT could strip a securityContext;
- the GUI's Sonar survey Job cannot be name-scoped (its name is created with a random suffix).
  A jobs-create grant in this privileged namespace is a node-escape capability; deployments that
  do not use in-GUI surveys should drop `create` on `jobs` and run surveys from the CLI instead.

### Data sensitivity

Zeek's `http.log` and `dns.log` contain personal data: hostnames, URLs, user
agents, and — if `capture_password` were enabled — credentials. **Keep
`capture_password` OFF.** It is off by default and Weirvern never enables it;
`http.log`'s `username` field still populates without it.

Handling requirements, retention by data type, and the lawful-basis question are
documented in [USAGE_POLICY.md](../USAGE_POLICY.md). Read it before enabling
additional Zeek log types.

### Network exposure

Nothing needs to face the internet. NetFlow/sFlow intake is UDP on the sensor
node, restricted at your firewall to trusted exporters. ClickHouse is
cluster-internal by default (`k8s/30-clickhouse.yaml` ships an optional
externally-reachable Service with `type: NodePort` commented out).

---
