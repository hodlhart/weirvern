# SRC-2 TLS/JA4 specialist — 2026-10-31

**Purpose:** a new client fingerprint on one host is a lead; the same browser fingerprint on
every host is not. This specialist isolates JA4 novelty, fleet rarity, old TLS versions and
SNI/JA4 inconsistency into the shadow candidate store. It never writes the alert table and
never pages.

## Features (`features_from_sessions`)

- session count and unique-JA4 ratio
- `new_ja4_ratio` (requires a `seen_ja4` history set)
- `fleet_rarity` (requires fleet host counts; 1 − the largest fingerprint's fleet share)
- TLS 1.3 ratio and old-TLS ratio
- SNI/JA4 mismatch ratio when an expected-SNI map is supplied
- unique SNI ratio

A host with no TLS sessions is `present:false`; it scores 0 and says "host absent".

## Score

```
0.35*new_ja4 + 0.25*fleet_rarity + 0.15*unique + 0.15*old_tls + 0.10*sni_mismatch
```

`score(..., use_ja4_shape=False)` is the source ablation: only session count remains.

## Shadow write

`run(client, minutes=60)` aggregates `zeek_ssl`, reads prior `zeek_ssl` for the per-host JA4
history set and fleet host counts, and inserts `TLSSpecialist` rows into
`weirvern.ml_candidate_scores`. The worker invokes it on the hourly shadow tick. If the
history query fails, novelty/rarity are reported **unknown** and the row still scores; the
shadow pass never alerts.

## Verification

- Pure new/rare JA4: **>0.55**; the same common browser fingerprint seen before: **<0.30**.
- Old TLS + SNI mismatch add to the evidence.
- Absent host, query-column checks, ablation, rank and candidate-only write covered by
  `tests/test_tls_specialist.py` (9 tests).
- Disposable `zeek_ssl` seed: 2 host-windows, **20.7 ms**, new fingerprint **0.63** with
  `new_ja4=1.00; fleet_rarity=1.00; unique_ja4=0.20`.
- No alert was emitted: the write is to `ml_candidate_scores` only.

## Limits

- Only 17 live JA4 fingerprints were observed in the coverage report; this is not a learned
  fleet model and does not claim fleet-wide rarity on a small sample.
- History requires prior `zeek_ssl`; the SQL path reports unknown rather than silently zero.
- QUIC is outside `zeek_ssl` and remains a dedicated coverage gap.
- The score is a ranking, not a calibrated probability; fixed-budget review precedes production.
