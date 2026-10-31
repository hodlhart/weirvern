# SRC-1 DNS specialist — 2026-10-31

**Purpose:** a tunnel and a DGA are query-shape problems, not resolver-volume problems. This
specialist isolates entropy, length, uniqueness, qtype and failure ratios into the existing
shadow store. It writes only `ml_candidate_scores`; it never writes the alert table and never
pages.

## Features (`features_from_queries`)

- `query_count`
- `unique_query_ratio` and `unique_domain_ratio` (registrable-domain approximation)
- mean/max query entropy, mean/std query length
- TXT, NULL, SRV, ANY qtype ratios
- NXDOMAIN and error ratios
- `new_domain_ratio` when a `seen_domains` set is supplied; otherwise reported as **unknown**,
  not zero-normal

A host with no queries is `present:false` and scores 0 with “host absent”; it is not a zero
vector. The SQL path uses `zeek_dns` and a monitored-scope predicate.

## Score

```
0.40*entropy_norm + 0.20*length_norm + 0.20*unique
+ 0.10*weird_qtype + 0.05*nxdomain + 0.05*new_domain
```

The evidence string carries every ratio. `score(..., use_dns_shape=False)` is the source
ablation: only query count remains; the seeded tunnel loses >0.40.

## Shadow write

`run(client, minutes=60)` groups `zeek_dns` to five-minute host-windows and inserts
`DNSSpecialist` rows into `weirvern.ml_candidate_scores`. The worker invokes it on the hourly
shadow tick alongside HDBSCAN, flow-shape, temporal, change-point and external candidates.
Failures are contained by the existing shadow pass.

## Verification

- Pure seeded tunnel: 120 high-entropy 48-char labels, TXT queries; benign: 120 repeated
  `www.example*.com` A queries.
- Seeded tunnel score **>0.75**, benign **<0.40**; absent host stated; ablation >0.40.
- Disposable `zeek_dns` seed: 2 host-windows, **158.2 ms**, tunnel **0.8175**, benign
  **0.3378**; evidence includes `unique_queries`, `unique_domains`, `txt`, `nxdomain`.
- `tests/test_dns_specialist.py`: 9 tests; gate PASS.
- No alert was emitted: the write is to `ml_candidate_scores` only.

## Limits

- SQL does not yet carry historical domain novelty; `new_domain_ratio` is reported unknown on
  that path and is available to the pure function when a history set is supplied.
- DNS coverage is the live constraint (small host count); this is a shadow channel, not a
  claim of fleet-wide DNS visibility.
- The score is a ranking, not a calibrated probability; fixed-budget review precedes any
  production use.
