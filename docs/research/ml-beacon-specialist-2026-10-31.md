# TMP-1 beacon/periodicity specialist — 2026-10-31

**Purpose:** a beacon can be almost invisible in volume and still be perfectly periodic. This
specialist scores the inter-arrival shape of raw-flow pairs into `ml_candidate_scores`. It
never writes the alert table and never pages.

## Features (`features_from_times`)

- event count and positive inter-arrival gaps
- median/mean gap, gap coefficient of variation
- `periodicity`: fraction of gaps within 20% of the median
- `regularity`: 1 − min(CV, 1)
- span and count normalisation
- optional payload: median bytes and `small_payload` (1 − median/1 MiB), when sizes are
  supplied; no payload is reported as `unknown`, not zero

Fewer than four distinct events is `present:false`; a burst with no positive gaps is absent.

## Score

With payload:

```
0.40*periodicity + 0.25*regularity + 0.10*count + 0.25*small_payload
```

Without payload: `0.50*periodicity + 0.30*regularity + 0.20*count`.
`use_periodicity=False` is the count-only ablation.

## Shadow write

`run(client, minutes=60)` groups `weirvern.flows` by source/destination pair, keeps pairs with
at least four events, and writes `BeaconSpecialist` rows to `ml_candidate_scores`. The worker
runs it on the hourly shadow tick. It reports pair/host counts, score distribution and elapsed
milliseconds.

## Verification

- Seeded 300-second beacon: **>0.85**; periodic backup with 50 MB payloads: **<0.75**; irregular
  burst: **<0.45**; fewer than four events: absent.
- Disposable raw-flow run: **94 pairs / 18 hosts**, **199.3 ms**, p50 **0.4046**, max
  **0.9249**; the seeded beacon at `198.51.100.11` scored **0.9249** with
  `median_gap=900s; periodicity=1.00; regularity=1.00`.
- `tests/test_beacon_specialist.py`: 8 tests; gate PASS.
- No alert was emitted: the write is to `ml_candidate_scores` only.

## Limits

- Pair-level grouping is deliberately simple; a beacon that rotates destinations is split
  across pairs and will need the graph specialist (TMP-2).
- A perfectly periodic backup with small payloads can still score high; payload evidence is
  the discriminator when available, and the shadow channel is not a page.
- Raw flow TTL is 3 days; the hourly run stays inside it.
