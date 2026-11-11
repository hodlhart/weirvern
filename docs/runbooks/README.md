# Runbook index

Every operational task routes to one of these. If a task has no runbook, that is a documentation
gap to file, not an invitation to improvise.

| Task | Runbook |
|---|---|
| Install, first boot, first alert | `../deployment.md`, `operator-workflows.md` |
| Read an alert, explain it, act on it | `operator-workflows.md` |
| Triage and close an incident | `incident-response.md` |
| Understand source coverage and freshness | `source-coverage.md` |
| Understand retention and deletion | `data-retention.md` |
| Change the schema safely | `schema-migration.md` |
| Back up, restore, recover a node | `release-dr-drill.md` |
| Capacity, restarts and single-node limits | `capacity-and-failure.md` |
| Release, CVE response, SBOM | `supply-chain.md`, `slo.md` |
| Network exposure and TLS | `security-surface.md` |
| Accounts, sessions, RBAC, secrets | `accounts-secrets-rbac.md` |
| Privacy requests and lawful basis | `privacy-operations.md` |

## Failure states that must never look like success

- **Empty vs unavailable.** A failed API read says unavailable and why; it never becomes an empty
  table with a green count.
- **Not scanned vs clean.** No scan result is `not scanned`, not zero findings.
- **Not measured vs zero.** A missing source is `not measured`/`unknown`, not `0`.
- **Warming vs stale.** A model with insufficient history is warming; it is not "quiet".
- **Off vs armed.** A disabled gate says off; a degraded gate names its reason and consequence.
- **Unavailable vs unreviewed.** A failed review read is unknown; it does not say "nobody looked".

These words are part of the interface contract, not decoration. The tests in
`tests/test_source_freshness.py`, `tests/test_status_tokens.py` and the evidence chain pin them.

## Accessibility and responsiveness

`scripts/responsive_audit.py` measures overflow, clipped text, touch targets, unnamed controls and
hover-only facts at desktop, tablet and phone widths. A view is not "done" because it renders; it
is done when that audit is clean for the view and the keyboard path reaches its actions.
