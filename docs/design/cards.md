# Card anatomy

**Status:** locked 2026-11-20 (audit: six classes, six padding rhythms) · **Implementation:**
`style.css` (`--card-*` tokens and the shared anatomy block) · **Pinned by:**
`tests/test_console_unification.py`.

---

## One anatomy

Every card surface is the same box: a **header**, a **body**, a **footer** and an **action
row**, on one spacing scale taken from the canon's 4px ladder.

| token | value | used for |
|---|---|---|
| `--card-pad` | `20px` | a page card's inside edge |
| `--card-pad-tight` | `10px` | a card-row's inside edge (same ladder, one density down) |
| `--card-gap` | `16px` | header → body → footer |
| `--card-tight` | `8px` | between the items inside a header, footer or action row |
| `--card-radius` | `8px` | the canon's largest legal radius |

The six classes (`card`, `ext-card`, `gate-card`, `net-card`, `nz-card`, `rp-card`) share one
selector for background, radius, shadow and `min-width`. Page cards take the page padding;
cards that are rows inside a page card take the tight padding.

## The four parts

- **Header** — `.card-head`, or the card's own `h2`/`h3` (one rhythm: `margin: 0 0 --card-gap`).
  A header carries the title, its muted count/identity, and at most one primary verb.
- **Body** — facts and fields. Facts before fields (see `sheets.md` §2).
- **Footer** — `.card-foot`: provenance, receipts and secondary readings.
- **Action row** — `.card-actions`: the verbs, with the one primary verb first. On a sheet the
  same row is `.sheet-actions` and is sticky (see `sheets.md` §3).

## Variants are layout only

A variant may change **layout** (a fixed-width gate, a grid tile, a phone row) and may carry a
**status edge** (a scope's left border, a severity's left border). It may not declare its own
padding or radius — those belong to the anatomy, and a variant that invents them is the drift
this file exists to stop.

| class | why it is a variant |
|---|---|
| `gate-card` | one fixed-width column on the full-screen sign-in cover; raised shadow |
| `net-card` | a button tile in a grid of scopes; left border carries monitored/observed/unclassified |
| `nz-card` | the phone-only stacked row that replaces the Normalize table at ≤720px |
| `rp-card` | the phone-only stacked row that replaces the ripple table at ≤720px |
| `ext-card` | a nested row inside a card: tone only, no second box (C-5: no card in a card) |
