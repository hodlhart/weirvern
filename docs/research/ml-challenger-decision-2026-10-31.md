# LRN-2 offline challenger decision — 2026-10-31

**Decision: rejected for production; retained as an offline-only question.**

The candidate was a self-supervised / graph challenger (GNN or CLAN-style representation
learning) compared with the existing tree/feature ensemble at the same fixed review budget.
It was not promoted, and no model artifact or production dependency was added.

## Why this is a rejection, not a failed experiment

- **No labels.** The live review store has a handful of dispositions and 34 blank reviews; the
  fixed-budget harness needs enough labelled positives and negatives to distinguish a lift. A
  challenger trained on the unlabelled population can learn the traffic mix, not the task.
- **The graph is sparse where it matters.** The live `zeek_conn` overlap is large, but the
  identity sources are zero-row (Kerberos, NTLM, SMB, DCE/RPC, LDAP). A GNN would be strongest
  on exactly the data that is absent.
- **No reproducible lift claim.** The existing seeded corpus (319 verdicts across the scripted
  attacks) and the baseline feature vector remain the comparison. There is no measured
  challenger result that beats the baseline at the same budget; claiming one would be invented.
- **Explainability and compute cost.** The current specialists produce bounded evidence strings
  and run in milliseconds. A GNN adds a training dependency, a model artifact and a new failure
  mode without a demonstrated budget win.

## What was actually run

The offline path is the existing `scripts/eval_detection.py` harness and the disposable
ClickHouse corpus. It is not wired to production, cannot write alerts, and is not a model
installation. The rejection is recorded here rather than left as an implied capability.

## Revisit trigger

Revisit only when all of the following hold:

1. at least **500 labelled reviews** with both dispositions represented;
2. at least **30 days** of non-zero identity-source coverage;
3. a fixed-budget comparison that reports precision, page count, latency and failure modes
   against the current ensemble;
4. operator approval before any new runtime dependency.

Until then, the graph/peer specialist (TMP-2) remains the transparent graph baseline.
