# The data coverage contract

The contract itself is machine-readable and lives with the code that reads it:

    weirvern/data/data-coverage-contract.json

It moved there from `docs/design/` on 2026-11-12: the container image copies `weirvern/` and
three specific `docs/` directories, so a contract under `docs/design/` was absent at runtime and
`/api/ml/data-contract` answered `available:false` with a file-not-found error.

What it defines, and why each part exists:

- **host population** — source addresses inside a scope declared `monitored` in
  `weirvern.network_scopes`, the same predicate the detectors train on. With no declarations the
  legacy behaviour (every address in scope) applies and the report says so; it is never reported
  as full coverage.
- **per source** — table, time column, host column, required or optional, freshness bound,
  accepted missingness and what that missingness means in words. `flows`, `flows_aggregated` and
  `ml_window_scores` are required; the Zeek tables are optional because a host that never
  resolves a name or never starts TLS is legitimately absent.
- **families** — dns→`zeek_dns`, tls→`zeek_ssl`, graph→`zeek_conn`, flow/beacon/exposure→`flows`,
  temporal/changepoint/candidate→`flows_aggregated`. Family usability is derived, never declared:
  a family is usable only when every source feeding it is fresh and within its accepted
  missingness, so no detector can claim DNS while `zeek_dns` is dark.

Measured state is served by `GET /api/ml/data-contract` and rendered by `models/data_contract.py`.
