# SRC-3 raw-flow specialist — 2026-10-31

**Purpose:** the aggregate model sees a zero-byte SYN sweep as small traffic and a busy server
as large traffic. This specialist scores the raw connection shape instead, into the existing
`ml_candidate_scores` shadow store. It does not write the alert table, change a threshold, or
page anyone.

## Features (`features_from_counts`)

- zero-byte flow ratio
- SYN ratio (`tcp_flags & 2`)
- RST ratio (`tcp_flags & 4`)
- short-lived ratio (< 1 s)
- unique destinations and unique destination ports
- average bytes and bytes per packet

Every denominator is guarded. A host with no raw flows is **absent** from the query, not a
zero vector; `run()` reports `available:false, reason:"no raw flows in the window"`.

## Score

Bounded 0..1, transparent:

```
0.45*zero_byte + 0.30*syn + 0.10*min(unique_ports/100, 1)
+ 0.05*min(unique_dsts/50, 1) + 0.05*rst + 0.05*short
```

The evidence string carries every measured ratio and `bytes_per_packet`, so a reviewer can
see why it scored rather than trusting a number.

**Source ablation:** `score(..., use_raw_shape=False)` keeps only volume. The zero-byte SYN
sweep falls from **>0.85** to the volume-only floor; the test asserts the gap is >0.40.

## Shadow write

`run(client, minutes=60)` groups `weirvern.flows` to five-minute host-windows, applies the
monitored-scope predicate, and inserts into `weirvern.ml_candidate_scores` under
`FlowSpecialist`. The worker invokes it on the hourly shadow tick, alongside HDBSCAN,
temporal, change-point and external candidates. A failure is caught by the existing shadow
pass and never stops detection.

## Measured disposable run (2026-10-31)

- 752 candidate rows over 47 windows.
- **177.8 ms** for the query + scoring + insert report time.
- p50 score **0.0205**; max **0.8223**.
- The zero-byte port sweep (`198.51.100.10`) scored **0.8223** with
  `zero_byte=0.94; syn=0.94; unique_ports=404`.
- SMB and DCE zero-byte fan-out hosts scored **0.796/0.800**.
- No alert was emitted: the write is to `ml_candidate_scores` only.

## Limits

- No Zeek fields (S0/REJ history, conn state) in this fixture; those belong to SRC-3's next
  increment, not this rule.
- The score is a ranking, not a calibrated probability. Fixed-budget review comes before any
  production use.
- Raw flow table TTL is 3 days; the hourly run must stay inside that window.
