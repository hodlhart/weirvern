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

### Transport and the trust boundary

**The supported console path is HTTPS 443 through local Traefik.** The k3s cluster already
runs Traefik and owns host port 443. Apply `k8s/tls` after the internal CA Secret exists: it
creates a cert-manager `Certificate` for `sensor.example`, adds the TLS `Ingress`, redirects HTTP,
adds HSTS, and changes the GUI Service to ClusterIP. The certificate chains to the **Weirvern
Local Root CA**; install that root once on each managed device. Renewal is automatic.

**The base manifest still serves plain HTTP on NodePort 30088.** That remains useful for
break-glass and for a development workstation, but it is not the user path. It has no TLS
listener and must be firewalled off the management segment once the ingress is healthy.

The two older paths remain valid for recovery:

**1. Alternate reverse proxy.** The shipped ingress is Traefik; if you deliberately run a
different proxy, point it at the GUI Service. The console is same-origin, sends its token as
headers (`X-Weirvern-Token`; it also accepts a session cookie), and uses no websockets, so the
proxy only has to preserve the host and the scheme:

```nginx
server {
  listen 443 ssl;
  server_name weirvern.example;
  ssl_certificate     /etc/ssl/certs/weirvern.pem;
  ssl_certificate_key /etc/ssl/private/weirvern.key;

  location / {
    proxy_pass http://127.0.0.1:30088;       # the GUI NodePort
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_read_timeout 120s;                  # settings applies can be slow
  }
}
```

Once the proxy answers, restrict the NodePort at the firewall to the proxy's host — otherwise the
plain HTTP door is still open beside the TLS one.

**2. One operator, no extra components.** `kubectl -n weirvern port-forward svc/weirvern-gui
8088:8088`, or `ssh -L 8088:localhost:8088 <hub>`, then browse `http://127.0.0.1:8088`. The
tunnel is the transport security; nothing else listens.

If neither path is in place and the console is reachable from an untrusted segment, **the operator
token, account credentials and the session travel in clear text.** That is the exposure; it is
stated here rather than left to be discovered.

### Secrets at rest

`install.sh` installs k3s with `--secrets-encryption` on **fresh** installs. Per the k3s
documentation, the first start with that flag generates an AES-CBC key, an encryption config, and
passes it to the kube-apiserver; the Secrets in this namespace (the ClickHouse password, the
GUI/operator token, the Pushover credentials, the account store) are then encrypted in the k3s
datastore on disk.

**Existing clusters installed before this flag are not encrypted.** k3s cannot enable it on a
running server without a restart: follow the k3s procedure (`k3s secrets-encrypt enable`, then
restart the server as that page requires), and use `k3s secrets-encrypt reencrypt` to rewrite
existing Secrets. If that migration is not acceptable, record the exposure here and in the
deployment notes rather than assuming the datastore is encrypted. The installer warns when it
finds an existing k3s without the flag.

Reference: <https://docs.k3s.io/security/secrets-encryption>. The k3s default when the flag is
absent is no encryption at rest.

### Per-weirling database credentials

Every weirling used to ship with the hub's own ClickHouse user and password. One compromised
sensor therefore held the database credential for the whole deployment, and revoking it meant
rotating every other sensor at the same time.

`scripts/deploy-weirling.sh` now creates a **dedicated user per sensor**:

- name `wv_<sensor-id>` (hyphens become underscores);
- `GRANT INSERT ON weirvern.*` and nothing else — no SELECT, no DDL, no access to other
  databases. The shipping path writes `flows`, the `zeek_*` tables and `sensor_status`, all
  through the same ingester code;
- a password generated on the machine running the deploy script (24 random bytes, hex), written
  only to the target's `/etc/weirvern-weirling.env` (0600) and never printed;
- the sensor → user mapping recorded on the hub in
  `/var/lib/weirvern/sensor-credentials.tsv` (0600, root-owned).

Re-running the install rotates that sensor's password (`ALTER USER`) without touching any other
sensor. **To revoke one sensor:** `scripts/deploy-weirling.sh --target … --sensor-id … --remove`
(which also drops the user when `--hub` is given), or by hand:

```sql
DROP USER IF EXISTS wv_<sensor_id>;
```

The other weirlings keep shipping. The hub's own credential is no longer copied anywhere.

### Remote weirlings over mTLS

The per-sensor database credential above is the **legacy** direct-ClickHouse path and is
now an explicit opt-in. The default is the mTLS ingest gateway in
[`k8s/mtls`](../k8s/mtls/README.md): the hub installer creates the CA and server
certificate, `deploy-weirling.sh` obtains a one-time enrollment token, the sensor
generates its own key and CSR, the hub signs a client certificate with the **Weirling
Intermediate CA**, and all plan, heartbeat, flow and Zeek traffic goes over an
authenticated HTTPS connection. The sensor receives no database password.

The gateway enforces the URI SAN `spiffe://weirvern/sensor/<sensor-id>` and checks the
registry's enabled/revoked state on every request. A revoked identity stops a live
intercept on its next plan poll rather than waiting for ARP expiry. `--legacy-clickhouse`
is the explicit migration path, not the default.

---
