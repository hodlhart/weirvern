# The Normalize tab

Status: agreed with the operator 2026-11-19. Not built yet. This file is the contract the build
follows; if the build disagrees with it, the build is wrong or this file is updated in the same
commit.

## What it is

A feed of near-similar traffic — flows and DNS — that the operator reads the way they read a log:
filter it, select rows, and mark what is normal. Normalized traffic is folded into the host's
adaptive baseline **permanently**, so the models learn it as normal.

## The operator's rules (verbatim intent, 2026-11-19)

1. **DNS is included, not just flows.** A normalized domain is as much "normal" as a normalized
   flow pattern.
2. **No alert silencing.** Normalization changes the baseline, not the alert gate. If the traffic
   stops alerting it is because the model no longer finds it anomalous — not because a page was
   suppressed. There is no `silenced` state anywhere in this feature.
3. **Permanent, with removal.** A normalization stays in force until the operator removes it.
   Removal is recorded, not forgotten.
4. **It looks like a feed log.** Filter by source, segment, port, DNS, bytes; select rows; the row
   changes colour when it is normalized.

## Data model

`weirvern.normal_traffic` — one row per normalized pattern.

| column | meaning |
|---|---|
| `entry_id` | uuid; the remove action targets this |
| `created_at`, `created_by` | who normalized it and when |
| `source` | `flow` or `dns` |
| `status` | `active` or `removed` |
| `removed_at`, `removed_by` | set on removal |
| `src_addr` | the host the pattern belongs to (blank for a segment-wide entry) |
| `dst_prefix` | destination /24 for flow rows |
| `dst_port`, `proto` | flow rows |
| `dns_name`, `dns_qtype` | DNS rows |
| `flows`, `bytes`, `packets` | what was selected, at selection time |
| `avg_bytes`, `var_bytes`, `avg_packets`, `var_packets`, `samples` | the distribution the baseline absorbs |
| `first_seen`, `last_seen` | the observed range of the selected rows |
| `note` | the operator's reason, optional |

Engine `ReplacingMergeTree(created_at)`, `ORDER BY entry_id`, **no TTL**: permanent means permanent.
Removal writes a new row with `status='removed'` so the history survives.

## How it reaches the models

The adaptive baseline is per-host statistics over a 72h window (`baseline_history`). Normalized
entries are merged into the host's statistics as additional samples, pooled rather than replacing:

```
n  = n_host + n_seed
m  = (n_host*m_host + n_seed*m_seed) / n
v  = ((n_host-1)*v_host + (n_seed-1)*v_seed + n_host*n_seed/n * (m_host-m_seed)^2) / (n-1)
```

Percentiles move only when the seed has enough samples to mean something (`samples >= 20`), and
then they are the wider of the two — a normalization widens a band, it never narrows one. The
baseline row records `seeded_entries` so the Models tab can say how much of the band is operator
knowledge rather than observed traffic.

**DNS lane.** The normalized domains become a per-host known-domain set. The DNS features the
detectors already compute (13 of the 77 inputs) treat a known domain as not novel, which is the
same mechanism that makes a domain stop scoring after the host has used it for a while — made
deliberate and permanent instead of incidental and 72 hours long.

**Why no alert change is needed.** The baseline score is a comparison against the host's own
statistics. Widen the statistics to include the traffic and the same traffic stops scoring high.
Nothing in the alert path learns that this feature exists.

## The tab

Controls: window (1h / 24h / 7d), source (All / Flows / DNS), segment (the declared network
scopes), port, minimum bytes, text search, and **Show normalized** (off by default).

Table columns: time · source · host · segment/destination · port/proto · DNS query · bytes · flows ·
score. Colour: normalized rows are green-tinted with a check; selected rows carry the accent;
unselected anomalous rows keep the severity tint they have elsewhere.

Footer: **Normalize selected (N)** — disabled with a stated reason when nothing is selected.
Below the feed: **Active normalizations**, each with what it covers, when, by whom, and **Remove**.

## Invariants

- The feed is read-only until the operator acts; nothing is normalized by the system.
- A row that is already normalized shows as normalized in the feed, and selecting it offers
  Remove rather than Normalize.
- Every write is attributed and reversible; nothing is deleted.
- If the baseline merge cannot run (a failed read, a stale artifact), the tab says so and the
  entries stay active — a failed merge is reported, never silently treated as applied.
