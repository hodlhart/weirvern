# The canon

`docs/design/canon.json` is the law the lint reads; this file explains **why** each number exists
so a future card can argue with it instead of quietly breaking it. Clauses are numbered `C-n` and
are cited by `DSG-` and `DUP-` cards.

Read `vision.md` first. This document assumes the ambition in it.

---

## C-1 · Type is a five-step ramp

`11 · 13 · 15 · 19 · 27` (`--fs-1`…`--fs-4`, `--fs-6`). There is no `--fs-5` on purpose: the jump
from 19 to 27 is the only loud number in the product, and it belongs to a value, not a heading.

**Why:** a console's calm comes from few sizes used consistently. Every size outside the ramp is
debt, counted by the lint. Raw `font-size: 12px` does not look wrong alone; ten of them make a page
look assembled rather than designed.

## C-2 · Space is a 4px ladder

`0 · 1 · 2 · 4 · 6 · 8 · 10 · 12 · 16 · 20 · 24 · 32`. 1px is hairlines; 2px and 6px are chip and
glyph nudges. Everything else sits on the ladder.

Spacing is **advisory** for now — counted and reported, not gating. The reason is honest: the
current sheet uses off-ladder values in ways that are sometimes right (optical alignment), and a
gate that cries wolf on day one gets disabled. It becomes gating once the baseline is paid down.

## C-3 · Three radii, two shapes

`4 · 6 · 8`, plus pills (`999px`) and circles (`50%`). A radius that is not in the set is debt. A
card and a field may not disagree about how round a corner is.

## C-4 · Colour is a role, never a value

Every colour is a token with a job (`--canvas`, `--surface`, `--surface-2`, `--hover`, `--border`,
`--border-solid`, `--fg`, `--fg-2`, `--muted`, `--dim`, `--accent`, `--ok`, `--warn`, `--bad`,
`--crit`, `--info`, `--offline`, the washes, the chart tokens). A hex outside `:root` is debt.

Two standing rules:

- **One accent.** Accent is spent on active/selected/primary, nowhere else.
- **Severity never travels alone** — colour + glyph + word, so rank survives greyscale and
  colour-blindness (`tests/test_status_tokens.py` pins contrast).

## C-5 · One frame, one header

One shell, one content column. Every view's header is **title + count + exactly one primary verb**.
No card inside a card. No per-view chrome invented for one screen.

**Why:** the fastest way to look like three products is three header patterns. The fastest way to
look like one is to never let a view draw its own frame.

## C-6 · The component cap is eight

`button · field · chip · table · sheet · card · banner · sparkline`. A ninth primitive needs a
written justification appended here.

**Why:** this is the single biggest lever on coherence and the one we have only half-done. BTN-1
fixed buttons; tables, cards and banners still drift. A cap turns "should we build a new widget"
into "which of the eight is this, and if none, why".

## C-7 · Motion marks a state change

100–200ms, no bounce, nothing animating on load, `prefers-reduced-motion` honoured. Motion that
does not mark a change is decoration with a cost.

## C-8 · Responsive is a second product with the same rules

Breakpoints at **420 · 720 · 1100**. The review set is **1440×900, 820×1180, 390×844**, plus a
**320×640** stress pass.

- **Nav:** the tab rail scrolls; the primary surface never hides behind a hamburger.
- **The shell wraps, it does not widen.** The header and the status line are wrapping flex
  rows. A non-wrapping row sets a page minimum above the breakpoint and drags every view
  sideways (2026-10-18: 257px at 820 on all fifteen views).
- **Tables:** at ≤720 a table becomes stacked label/value rows — same fields, same order. Horizontal
  scroll is allowed only inside a designated data grid, never for a page. *Data behind a swipe is
  data a phone operator does not have during an incident.*
- **Sheets:** full height at ≤720; the primary verb sticks in thumb reach.
- **Hover:** a fact that exists only on hover is a defect on touch. Every `title=` needs a tap
  equivalent or must go. The lint ratchets the raw attribute count; the responsive audit measures
  the thing that matters — titles that are the *only* carrier of meaning (7 on 2026-10-18).
- **Open on desktop** is allowed for bulk configuration, never for a primary action.

## C-9 · Touch is 44/36

**44px** for anything primary, **36px floor** for secondary. `--btn-h` is 28px on pointer devices
and raised on touch; the audit measures the live result, not the intent.

Density loses to the thumb on a phone. On desktop, density wins.

## C-10 · Budgets, not vibes

Per view, per viewport: **≤12 API calls on load**, **≤6000 DOM elements**, **zero per-row verbs**
(a dense view carries its weight in filters), and **steps-to-answer** budgets for the five
operator questions (triage 3, find a host 2, prove a block 3, change a setting 4, explain a
detection 2).

A breach is a card. "Feels slow" is not a finding.

## C-11 · Enforcement is a ratchet

`scripts/canon_lint.py` compares the live sheet and markup against this canon and against
`docs/design/canon_baseline.json`:

- **new** violation → gate red;
- **unchanged** debt → passes, listed in the report;
- **removed** debt → report says so, and the baseline shrinks in the same commit.

**Why a ratchet:** the console already violates parts of its own system (11 raw font sizes, 9 radii,
14 stray hex values, 119 hover-only facts). Pretending otherwise would mean either lying in the
canon or a gate that is red from birth. The ratchet tells the truth about today and forbids tomorrow
from being worse. Every `DUP-` and `DSG-` card that pays debt down updates the baseline with it.
