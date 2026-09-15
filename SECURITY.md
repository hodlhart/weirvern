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
- Collector ports (2055/6343 UDP) are intentionally published on the LAN.
  Restrict at the firewall to your exporters' IPs.
- `.env` contains Pushover tokens — `chmod 600` and keep out of git.
- ClickHouse HTTP port (8123) should not be exposed outside the cluster
  network.
