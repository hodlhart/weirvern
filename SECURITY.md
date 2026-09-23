# Security Policy

## Supported versions

This project is pre-production (v0.x). Only the latest commit on `main` is
supported.

## Reporting a vulnerability

This is a private development repository. If you are a collaborator and
believe you have found a security issue:

1. Do **not** open a public issue.
2. Report privately via GitHub's private vulnerability reporting
   (Security → "Report a vulnerability") or a private message to the owner.
3. Include: affected component, reproduction steps, impact, and a suggested
   fix if you have one.

The owner will acknowledge within 7 days and coordinate disclosure. This
policy will be replaced with a public one before this repository is made
public or production-deployed.

## Deployment hardening notes (for the operator)

- The worker runs with **no inbound network exposure** by design (outbound
  only to ClickHouse, Pushover). Do not publish port 8080 of the worker to
  the internet.
- **The flow collector is reachable on EVERY interface of the sensor node, on
  2055/6343 UDP and on the NodePorts 32055/32063.** This was previously described
  here as "cluster-internal and not reachable from outside", which is WRONG and was
  corrected after measuring the running deployment:

      $ ss -lunp | grep -E ':2055|:6343'
      UNCONN  *:2055  users:(("goflow2",pid=3228,fd=6))
      UNCONN  *:6343  users:(("goflow2",pid=3228,fd=8))

  `*` is every interface. The collector runs with `hostNetwork: true` deliberately,
  because a real exporter was observed sending NetFlow to the container port rather
  than the NodePort and its packets were discarded with nothing logged — so binding
  the node's own interfaces is what makes a sensor work with an ordinarily-configured
  router. The cost is that the port is open to whatever can reach the node.

  **NetFlow and sFlow are unauthenticated**: the protocol carries no credentials and
  the collector does not verify the sender. So any device that can reach those ports
  can submit records ATTRIBUTED TO ANY ADDRESS IT CHOOSES, and those records feed the
  anomaly models, the baselines and the charts. This is not a defect to be patched
  away in code; it is a property of the protocols, and it is why the two controls
  below matter.

  - **Firewall the ports to your exporters' addresses.** This is the outermost and
    most complete control: nothing else on the segment should be able to reach them.
  - **Set `WEIRVERN_FLOW_EXPORTER_ALLOW`** (comma-separated addresses or CIDRs). It is
    off by default, so records from an unlisted sender are accepted until you turn it
    on — and then they are rejected **and logged at WARNING**, so a device you forgot
    appears as a finding rather than as missing data. Run `weirvern exporters` to see
    which addresses have actually sent records, and it prints the ready-to-paste
    value.
- `.env` contains Pushover tokens — `chmod 600` and keep out of git.
- ClickHouse HTTP port (8123) should not be exposed outside the cluster
  network.
