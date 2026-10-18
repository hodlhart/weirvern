# Responsive audit — 2026-10-18

**Box:** `sensor.example:30088`, build `sha-0f299a62d` · **Method:** `scripts/responsive_audit.py`
(headless Chrome 151 over CDP, touch emulation at ≤720px, `X-Weirvern-Token` from a 0600 file)
**Pairs measured:** 15 views × 4 viewports = **60** · **Screenshots:** 60 PNGs (`/tmp/audit_full/shots`)

Reproduce:

```
scripts/responsive_audit.py --url http://sensor.example:30088 \
    --token-file ~/.weirvern_token --out /tmp/audit_full
```

## The numbers

| view | page overflow @820 | controls <44px | hover-only | unnamed | DOM | API on load |
|---|---|---|---|---|---|---|
| Health | **257px** | 32 | 0 | 0 | 1,777 | 5 |
| Anomalies | **257px** | **632** | 0 | 0 | 5,823 | 9 |
| Logs | **257px** | 27 | 0 | 0 | 1,807 | 7 |
| Network | **257px** | 30 | 0 | 0 | 2,298 | 4 |
| Netflow | **257px** | 24 | 0 | 0 | 2,192 | 5 |
| Discover | **257px** | 33 | 0 | 0 | 3,020 | 5 |
| DNS | **257px** | **147** | 0 | 0 | 2,814 | 5 |
| Zeek | **257px** | 24 | 0 | 0 | 2,021 | 5 |
| Sluice Gate | **257px** | 50 | **5** | **5** | 1,909 | 9 |
| Blocked | **257px** | 31 | 0 | 0 | 1,784 | 5 |
| Identity | **257px** | 26 | 0 | 0 | 1,845 | 5 |
| Weirlings | **257px** | 42 | **2** | 0 | 1,862 | 5 |
| Assets | **257px** | 37 | 0 | 0 | 1,980 | 4 |
| Models | **257px** | 34 | 0 | 0 | **8,650** | 8 |
| Settings | **257px** | 31 | 0 | 0 | 2,112 | 7 |

Every view at 1440 is clean on overflow. Every view at 390 and 320 is clean on **page** overflow —
the phone layout holds. Clipped text: Network and Zeek clip ≥8 elements at every width; Models,
Netflow, Blocked, Identity and Sluice clip at ≤390.

## Findings

- **A-1 (systemic, severity 1) — the tablet width has no plan.** All fifteen views overflow by
  exactly **257px at 820** — the same number everywhere means one root cause, not fifteen bugs: the
  container keeps a desktop minimum above the 720 breakpoint. 820×1180 is the most common tablet
  and a half-snapped laptop window; today it is the only width that is broken everywhere.
- **A-2 (severity 2) — Anomalies carries 632 controls under 44px.** They are the per-row verbs the
  canon bans (C-10: zero per-row verbs). On touch this is a wall of misses.
- **A-3 (severity 2) — 5 unnamed + 5 hover-only controls on Sluice Gate.** The only view where the
  audit found controls with no accessible name at all; the gate's own controls are the ones a
  screen reader cannot describe.
- **A-4 (severity 2) — Models is over the DOM budget** at 8,650 elements (canon: 6,000).
- **A-5 (severity 3) — truncation:** Network/Zeek clip ≥8 text elements at every width; Models and
  Netflow clip at phone widths.
- **Correction to the earlier claim:** the sheet has **136 `title` attributes**, but only **7** of
  them are the *sole* carrier of meaning (2 on Weirlings, 5 on Sluice). The rest repeat a visible
  label. The audit measures meaning, not attributes — this is the number to fix.
- **Positives worth keeping:** API calls on load are 4–9 everywhere (budget 12); the phone layout
  does not scroll sideways on any view; the nav rail's own scroll works.

## What this implies for the design program

`A-1` is one card and touches every view: add the 720–1100 plan. `A-2` is the table-grammar card
(row verbs become filters and a single row affordance). `A-3`/`A-4` are accessibility and budget
cards. None of them is a "make it pretty" card, and all of them are canon clauses with numbers.
