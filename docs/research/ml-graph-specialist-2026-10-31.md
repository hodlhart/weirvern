# TMP-2 graph/peer specialist — 2026-10-31

**Purpose:** the tabular model sees a host's counts, not that one host suddenly talks to forty
peers that never talked back. This specialist builds a bounded source-side graph from
`zeek_conn` and writes `GraphSpecialist` rows to `ml_candidate_scores`. It never writes the
alert table and never pages.

## Features (`features_from_edges`)

- out-degree / in-degree and edge count
- `new_edge_ratio` against a seen-edge set
- `peer_rarity` when destination peer counts are supplied
- `reciprocity`: fraction of outbound edges whose reverse exists
- `fanout_norm`

No outbound edges means `present:false`; a host with no graph is absent, not a zero vector.

## Score

```
0.40*fanout_norm + 0.30*new_edge_ratio + 0.10*peer_rarity + 0.20*(1 - reciprocity)
```

`use_graph_shape=False` is the degree-only ablation.

## Shadow write

`run(client, minutes=15)` groups `zeek_conn` edges by source/destination and writes one
`GraphSpecialist` row per source host to `ml_candidate_scores`. It reports rows/hosts and score
distribution. No alert path.

## Verification

- Synthetic 40-destination star: **>0.80**; reciprocal 10-host mesh: **<0.40**; adding reverse
  edges lowers the star score.
- Absent graph, query-column checks, ablation, candidate-only write and no alert-store write are
  covered by `tests/test_graph_specialist.py` (9 tests).
- Disposable ClickHouse currently has **no `zeek_conn` rows**, so `run()` returns
  `available:false, reason:"no Zeek connection edges in the window"` — the explicit-unavailable
  branch allowed by the card.
- No alert was emitted.

## Limits

- The live Zeek sensor overlap is the constraint; without `zeek_conn` the graph channel is
  explicitly unavailable rather than a zero-score fleet.
- No GNN dependency and no community clustering yet; this is the transparent graph baseline.
- The score is a ranking, not a calibrated probability; fixed-budget review precedes production.
