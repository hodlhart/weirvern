# Accounts, sessions, secrets and RBAC

## Accounts and sessions

- Accounts live in the `weirvern-users` ConfigMap, one scrypt password hash per account; no
  shared bootstrap password is stored in the repository or rendered in the UI.
- Sessions are in-memory, expire, are revoked by logout, and every session for an account is
  revoked when its password or role changes. `tests/test_gui_users.py` pins session expiry,
  logout and the “change password revokes every session” path.
- The login throttle and lockout behavior are tested in `tests/test_gui_users.py`; a failed login
  does not disclose whether the account exists.
- The operator token is a break-glass write credential, not a user account. It is never rendered
  in a URL and is not logged.
- Successful and rejected sign-ins, and sign-outs, append `scope=auth` rows to the write trail
  (actor, target, reason, time). The credential is never part of that row.
- The write trail has a 365-day TTL; it is append-only and the GUI exposes only its read route.

## Tokens, passwords and secrets

- Tokens/passwords are compared in constant time where the code owns the comparison; the GUI
  session cookie is HttpOnly and SameSite.
- No credential is written to the audit log; `tests/test_status_tokens.py` pins the redaction
  paths.
- The ClickHouse password is delivered through the `weirvern-secrets` Secret, not a ConfigMap.

## RBAC review

Live roles: `weirvern-viewer` and `weirvern-operator`.

- Viewer: get/list on pods, services, endpoints, PVCs, workloads and jobs; pods/log and
  port-forward. No Secrets, no writes.
- Operator: the viewer reads, plus name-scoped `patch` on `zeek`, `weirvern-worker`,
  `weirvern-gui`; name-scoped `/scale` on `goflow2`, `weirvern-worker`, `clickhouse`; configmap
  `patch` only on `weirvern-env` and `weirvern-users`; pods/log and port-forward.
- `batch/jobs create|delete` remains because the GUI's Sonar survey creates Jobs with a random
  suffix; the API server refuses a `resourceNames` restriction for a create it cannot name. This
  is a documented, deliberate exception, not an unused grant. Running surveys from the CLI
  instead is the way to remove it.
- There is no cluster-admin binding and no Secret read in either role.

## Secrets at rest

`k3s secrets-encrypt status` on the live node reports:

```
Encryption Status: Disabled, no configuration file found
```

This is a recorded accepted risk for the single-node deployment: an attacker with root on the
host or the backing disk can read Secrets. Mitigations are host access control, full-disk
encryption at the hypervisor layer (operator responsibility), and the fact that the node is a
private, single-tenant appliance. Enabling k3s secrets encryption requires a cluster restart and
is a separate change; it is not claimed here.

## Rotation

The supported rotation order is:

1. Create the replacement credential or account.
2. Update the consumer or Secret.
3. Restart only the workloads that read it.
4. Verify `/api/health`, a login/logout, and one sensor poll.
5. Revoke the old credential and confirm the old session/credential fails.

A full live rotation drill was not performed in this batch. Session revocation, password-change
session invalidation and revoked-sensor refusal are covered by tests; ClickHouse password and
mTLS key rotation remain operator procedures with the rollback path above. This is recorded as an
accepted test gap, not as a claim that rotation was exercised end-to-end.
