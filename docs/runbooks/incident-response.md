# Incident response

Every playbook names the first observable, the containment, the evidence to preserve and the
recovery gate. Silence is never evidence of a clean network.

## 1. Credential compromise

**Detect:** repeated rejected sign-ins, an unexpected successful sign-in from a new address, a
token used from more than one workstation, or an account change nobody claims.

**Contain:**
1. If an account is suspect, change its password and role, which revokes every session.
2. If the operator token is suspect, rotate it in the deployment Secret, restart GUI/ingest, and
   confirm the old token fails.
3. If a sensor certificate is suspect, revoke that sensor in Weirlings; the gateway checks the
   fleet registry on every request. Preserve its rows; do not delete evidence.
4. Keep the deployment reachable for the investigation; do not disable the console as a
   containment step.

**Evidence:** `weirvern.fleet_audit` rows for `scope=auth`, `settings`, `fleet`; GUI access logs;
the affected account's session history. Do not copy passwords or tokens into the ticket.

**Recover when:** old credential fails, new credential succeeds, audit rows show the change, and
the health probes are green.

## 2. Sensor compromise

**Detect:** a sensor reports an unexpected mode/interface, sends from an unexpected address, or
its identity is used concurrently.

**Contain:** revoke it in Weirlings (append-only `fleet_audit` row), clear its settings, and treat
its flow/Zeek records as untrusted for the incident window. Do not let a revocation look like a
quiet sensor: the fleet row shows the declared/revoked state.

**Recover when:** the certificate is refused, the sensor is absent from the active list, and a
replacement sensor with a new identity is enrolled and reporting.

## 3. Data loss or corruption

**Detect:** missing partitions, restore failure, or a table count that no longer matches the
pre/post bounds in the backup record.

**Contain:** stop writers that would overwrite the damaged window; do not run `OPTIMIZE` or schema
changes during the incident. Restore to a scratch database first, never over live data.

**Recover when:** the scratch restore passes the count and fixed-window replay checks, then the
live restore has the same proof and `/api/health` is green.

## 4. Bad model promotion

**Detect:** a promotion decision with a reason other than a measured improvement, a sudden alert
volume change, or a score distribution shift without a traffic change.

**Contain:** revert to the previous model set from the backup, keep the candidate available for
analysis, and leave scoring in shadow until the fixed-window comparison is repeated. Promotion is
policy-based; a manual override is not the first move.

**Recover when:** scores and alert volume match the pre-change baseline on the same window.

## 5. TLS expiry or gateway failure

**Detect:** SLO report `tls_expiry_console` under 14 days, client handshake failures, or the mTLS
gateway refusing a certificate that is not revoked.

**Contain:** issue a renewed certificate from the correct CA, deploy it, and verify with
`openssl s_client`; do not disable verification to restore service.

**Recover when:** both console and gateway certificates read the new dates and sensors reconnect.

## Tabletop exercise — 2026-11-11

Scenario: a stolen operator token is used from an unknown workstation to change a setting and
revoke a sensor.

Walked through playbook 1 and 2 with the live surface:

- The write trail is readable at Logs → write trail and is append-only; settings and fleet rows
  already carry actor, action, target, reason and time. **Gap found and fixed in this batch:** a
  successful/failed sign-in was only in the process log, not the audit table; `scope=auth` rows
  are now written.
- Revocation is available in Weirlings and requires a reason; the gateway consults the fleet
  registry.
- **Gap:** Pushover is disabled, so a revocation or login burst does not page anyone. The SLO
  report reports `not_configured`; the operator must watch the console or enable delivery.
- **Gap:** no end-to-end token rotation drill has been executed; the procedure is documented and
  the session/revocation paths are test-covered, but the operator still owns the first live run.
- **Gap:** there is one node and one operator; a second person is required by the DR runbook but
  not available automatically.

The tabletop is a paper exercise, not a live incident. The gaps above are the output.
