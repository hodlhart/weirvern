# External peer layer — Phase 1 (shadow)

Status: **Phase 1, shadow only.** No external address is an alert entity.

## Contract

- An external peer is a **dimension** of a monitored internal endpoint, not a host with its own
  baseline.
- Inbound means external source → monitored destination. Outbound means monitored source →
  external destination.
- The individual address stays visible and clickable for evidence. The model uses aggregates.
- No `0.0.0.0/0` monitored scope, no per-IP external baseline, no single anonymous external bucket.

## Surfaces

- **Network coverage → External exposure**: inbound/outbound peer counts, bytes, flows,
  top-peer concentration, and the top `/24` presentation prefixes. `observed_only: true`.
- **Host page** (next phase): the same readings for one address, attributed to the local endpoint.
- **Shadow channel**: `weirvern/models/external.py` writes `External exposure` rows to the
  existing `ml_candidate_scores` table on the hourly shadow cadence. It does not write
  `netflow_anomalies`, `alert_events`, or Sluice state.

## Features collected

Inbound: peers, bytes, flows, ports, top-peer share.
Outbound: peers, bytes, flows, ports, top-peer share.

The shadow score is the maximum percentile of those measured features in the sampled population.
It is a **ranking**, not a probability. Promotion to the production path requires a 30-day
backtest at the current internal-host alert budget, with seeded inbound fan-in, new-peer burst,
outbound beaconing, and benign CDN/update traffic.

## Why

The live 24-hour population is thousands of external addresses. A per-IP baseline cannot be
stable, and one synthetic external host destroys attribution. CAIDA's network-telescope work
describes Internet background radiation as continuous, and ASN/prefix aggregation is the
established way to keep a population view without treating every address as a host. See
`docs/research/ml-alert-review-2026-10-23.md`, `references/baseline-ml-design.md`, and the
external-peer recommendation in the project skill.

## Promotion gates

1. 30-day backtest, same internal-host alert budget.
2. Seeded attacks: inbound fan-in scan, new external peer burst, outbound beaconing.
3. Benign controls: CDN, updates, DNS/NTP, backup traffic.
4. No external entity rows in `netflow_anomalies`; no alert volume increase.
