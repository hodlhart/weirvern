# Privacy operations

## What is collected

Weirvern is deployed on the operator's own network. It stores network metadata: flow tuples,
byte/packet counts, DNS/TLS/HTTP metadata, host identities and findings. It does not store payloads
and it does not capture credentials. `capture_password` is off by default and the product never
enables it; `k8s/32-zeek.yaml` documents the decision and the ingester rejects credential fields.

## Lawful basis and purpose

The operator runs the deployment to protect the network they are responsible for. The purpose is
security monitoring: detect anomalies, investigate them, and keep an audit trail of administrative
actions. Data is not sold, shared with a third party, or used for advertising. A deployment that
monitors other people's traffic needs its own lawful basis; the product does not supply one.

## Retention

Retention is set in `docs/runbooks/data-retention.md` and enforced by ClickHouse TTLs:

- Raw flows: 3 days.
- Aggregates and diversity: 7 days.
- Zeek metadata: 30–90 days by table.
- Audit trail: 365 days.
- Backups: local 14, remote 14; encrypted off-cluster copies are retained by the operator.

Deleting a host or an alert is a GUI operation on the finding, not a rewrite of the historical flow
records; the raw retention window is the deletion mechanism. An operator who needs earlier erasure
must use the ClickHouse retention controls and the backup policy, and record the request.

## Access

- Console reads require an account when accounts are provisioned; operators are named, not shared.
- The write trail is append-only and readable in the console; the GUI has no edit or delete route.
- The operator token is break-glass and is never rendered in a URL.
- Backups are encrypted; the key is held by the operator, outside the cluster and repository.

## Requests

An access or deletion request is handled by the deployment operator, who is the controller for
their own network. The operator identifies the subject (address/host), exports the matching
findings and metadata, and records the request and the retention action. There is no automated
DSAR portal and no third-party processor to contact.

## Verification

- `capture_password` is absent/false in the live Zeek configuration; the code path that would
  ingest credentials is not present.
- The schema TTLs are checked by `scripts/audit_schema.py` and cross-checked against
  `system.tables`.
- The audit trail TTL is 365 days; the table has no GUI write route.

## Known limits

- Network metadata can still identify people indirectly (addresses, hostnames, destinations).
  Retention is the main control; there is no per-person redaction in the flow tables.
- A backup copy exists outside the cluster by design; erasing live data does not erase an
  already-created encrypted backup. The operator must expire backups under the same policy.
