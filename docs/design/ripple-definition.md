# What counts as a ripple

**Status:** definition for the ripple detection programme. Every detector, corpus and
evaluation card cites this document. A model that cannot be measured against this definition is
not accepted, regardless of its score.

## Definition

A **ripple** is a change in the behaviour of a monitored host or group that is:

1. **small at a single window** — it does not clear the ordinary 5-minute alert threshold on its
   own;
2. **persistent or repeated** — it survives more than one window, or recurs with a stable shape;
3. **supported by more than one kind of evidence** — for example flow shape plus DNS cadence, or
   a graph change plus a temporal shift; and
4. **unusual for this host, in this role, at this time** — not merely unusual globally.

A ripple is a **candidate incident**, not automatically a page. Pageability is a separate policy
decision under the alert budget.

## Dimensions

| Dimension | What is measured |
|---|---|
| Amplitude | Robust effect size against the host/role baseline, not a raw score |
| Duration | 5 min, 1 h or 24 h persistence |
| Scale | Which window carries the signal; a ripple can be invisible at 5 min and clear at 1 h |
| Breadth | One host, a peer group, a subnet, or a graph community |
| Correlation | Two or more channels changing in the same direction and time band |
| Novelty | New peer, new service, new JA4 family, new DNS pattern |
| Graph change | New/rare edge, fan-in/out, community split or merge |
| Protocol semantics | DNS tunnel shape, beacon cadence, TLS family drift |

## Quantitative starting points

These are the initial gates for a **ripple candidate**. They are policy defaults, versioned with
the detector; they are not tuning sliders.

- **5-minute scale:** robust z between 1.5 and 3.0 on at least one feature, below the page
  threshold, for at least two consecutive windows.
- **1-hour scale:** at least a 20% relative shift from the same-hour baseline, with a calibrated
  p-value ≤ 0.01 and a change-point confidence ≥ 0.90.
- **24-hour scale:** a sustained shift or a change point with confidence ≥ 0.95, not explained by
  a known maintenance window.
- **Cross-channel:** at least two families with calibrated p ≤ 0.05 in the same time band.
- **Graph:** a new or rare edge, or a community change, with p ≤ 0.01.
- **Protocol:** a DNS/TLS/beacon pattern outside the host's own baseline, not merely a high
  count.
- **Persistence:** one isolated 5-minute spike is a **burst**, not a ripple.
- **Deadline:** 5-minute candidates within 10 minutes; 1-hour candidates within 1 hour;
  24-hour candidates within 6 hours of the shift starting.

The candidate threshold is intentionally below the page threshold. The page decision is made
later by the calibrated fusion and the per-host page budget (currently 2 high/critical episodes
per host per day).

## What is not a ripple

- A one-window volume spike.
- A new service that is stable, explained and repeats its baseline.
- A host that is simply busy all the time.
- A known-bad signature; that is a separate deterministic path and must alert independently.
- A change that cannot be separated from missing data. Missing data is `unknown`, not a ripple.

## Negative reference

A ripple claim is only meaningful against a clean negative:

- at least 24 hours of attack-free background across at least two held-out days;
- no seeded attacks, canary health checks or test traffic in the window;
- contamination risk recorded as unknown unless proven otherwise.

## Evaluation contract

Every ripple detector reports:

- recall on held-out ripple scenarios, by family and scale;
- false alarms per host per day on clean replay;
- pageable episodes per host per day;
- time-to-detect against the deadlines above;
- explanation coverage: the evidence names the host, scale, channel and changed feature/edge;
- `unknown` rate when a channel is missing or stale;
- confidence intervals, not a single run.

A detector that only wins on a single scale, a single family or a single simulator run is not a
win.

## Product language

The console should say **“a change was detected”**, not “anomaly score 0.87”. The evidence chain
is:

`observed → changed → correlated → ruled → done`

A user should be able to answer “what changed, when, on which host, and why does it matter?”
without reading a model card.
