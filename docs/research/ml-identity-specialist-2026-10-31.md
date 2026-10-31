# SRC-4 identity/lateral specialist — 2026-10-31

**Purpose:** Kerberos, NTLM, SMB, DCE/RPC and LDAP are the identity graph. The live tables have
had **zero rows**, so the first duty is a coverage gate, not a detector: a model trained on
zero-row sources learns nothing and then reports a confident zero.

## Coverage gate

`coverage(client, hours=24)` counts each source:

`zeek_kerberos`, `zeek_ntlm`, `zeek_smb_mapping`, `zeek_smb_files`, `zeek_dce_rpc`,
`zeek_ldap_search`.

`run()` returns `available:false` and names every zero/error table. It writes nothing and
alerts nothing. In the disposable ClickHouse every table is zero, so the report is the explicit
gap list above; this is the honest result for the live deployment too.

## Pure features (`features_from_events`)

- Kerberos SPN novelty against a seen set
- NTLM failure ratio and host diversity (counts, not usernames)
- SMB ADMIN$/C$/IPC$ share ratio
- DCE/RPC operation novelty
- LDAP filter-shape novelty
- event count; no events means `present:false`

**Privacy:** usernames, share paths and LDAP filters are consumed to compute counts/ratios and
are never included in the evidence string. A test asserts `alice`, `uid=user`, `ADMIN$` and a
hostname are absent from the emitted evidence.

## Score

```
0.20*kerberos_novelty + 0.25*ntlm + 0.20*smb_admin_share
+ 0.20*rpc_novelty + 0.15*ldap_novelty
```

On synthetic lateral rows it scores **>0.80**; a benign repeated identity pattern stays
**<0.50**. `use_identity_shape=False` is the count-only ablation and loses >0.40.

## Verification

- `tests/test_identity_specialist.py`: 8 tests covering synthetic lateral vs benign, privacy,
  absence, ablation, coverage-zero refusal, complete coverage and no alert-store write.
- Disposable coverage: all six tables zero; `run()` returns
  `identity coverage gap: kerberos, ntlm, smb_mapping, smb_files, dce_rpc, ldap_search`.
- No candidate write and no alert path until a non-zero fixture is reviewed. That is the
  explicit-unavailable branch the card allows.

## Limits

- The live sensors do not currently deliver these logs; enabling them is a separate coverage
  project, not a threshold change.
- The scoring path is not enrolled until a reviewed fixture exists; the pure features are the
  contract the next increment will consume.
- No production table, alert path or model change.
