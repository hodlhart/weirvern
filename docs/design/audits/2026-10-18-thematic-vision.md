# R1 — thematic & vision review: Weirvern console

## 1. Header

**Build:** `0.17.5`, image `sha-5d18b9c7b`, commit `5d18b9c`, branch `feat/sluice-rule-sheet`, live at
`http://weirvern.home:30088`. **Date:** 2026-10-18. **Stance:** read-only; no repo, cluster or box mutation. **Judge:** the
served bytes.

**Read:** `vision.md`, `canon.md`, `canon.json`, `ledger.json`/`ledger.md`, `scorecards/2026-10-18.md`,
`audits/2026-10-18-responsive.md`, `peers.md`.

**Measured:** `responsive_audit.py` on 7 views × 1440/820/390 (21 pairs) plus a 7-pair 320×640 pass; served HTML/CSS/JS
fetched and hashed; headless-Chrome CDP probes (cards, `h2`, row verbs, rendered type, control geometry, tab/header
geometry, focusability, interaction tests); `curl` of healthz/weirlings/sluice/settings/blocked/anomalies/evidence;
`canon_lint.py`. All 15 views measured at 1440; 7 at every width.

**Caveat:** at review time the worktree differed from the served bytes in four web files, by an **uncommitted** sheet
standard (`sheets.js`, `.sheet`, `role=dialog`) — the known in-flight fix. The other seven web files hash-matched. The worktree
is being edited concurrently; all findings are against the served bytes, and line numbers are those bytes.

---

## 2. Verdict

A 3 is "on the view, in words, no hunting"; 2 "works, one clear gap"; 1 "the gap is the experience". Previous = scorecard
2026-10-18 / build `7241c4d`, shown as total/average because its denominators vary (45 and 48).

| dimension | seat | score | previous | anchor |
|---|---|---|---|---|
| entry | novice | **2** | 36/48 (2.25) | Six of seven reviewed views open with a live count or sentence; none with title + count + one verb, and at 390 content starts at y=316. Operator seat: 3. |
| vocabulary | novice | **2** | 44/48 (2.75) | Tabs match the ledger 15/15; but "RULED / acknowledged", "0 rules total" over "Rules (6)", "Adopt". |
| flow | novice | **2** | 38/48 (2.38) | Anomaly → "⋯" → Evidence is 2 clicks and ends in the record; Health's failing check has 0 links; DNS's row verb opens a form. |
| state honesty | operator | **3** | 47/48 (2.94) | Degraded names its cause; unknown is dashed; header red at 8/9; "Block unavailable — the Sluice Gate is off". |
| density & hierarchy | operator | **2** | 44/45 (2.93) | DOM 6,173 vs 6,000; 104 rows = 42,952px at 1440, 43,310px at 390. Operator test would say 1. |
| visual system | operator | **2** | 35/48 (2.19) | Calm frame; but 91/95 font sizes raw, accent spent 48 ways, 11 off-set radii. |
| accessibility | novice | **2** | 41/45 (2.73) | 0 unnamed, 0 meaning-only at 390; 31px inputs, 13×13 checkbox, rule rows keyboard-unreachable. |
| recovery | operator | **2** | 37/48 (2.31) | Delete needs a typed reason, Settings has Discard; the Evidence error path prints a cURL contract. |
| time-to-answer | operator | **3** | 33/48 (2.06) | "Why did this fire" on one page in 2 clicks: 9 flows → 0.889 → "36 vs 40 normal, 0.9x" → acknowledged → still open. |

**Movement.**

- **TTA 2.06 → 3.** The chain shipped (`c97f6ea`) and is deployed. On `192.168.3.194` the Evidence page renders five stages,
  each with its own state: the vision's one question is answerable from one screenshot. The only real gain.
- **Honesty 2.94 → 3.** The hardest case is live: gate `degraded`, 0 rules enforced, leftover nft tables. The console says so
  in words on two surfaces and does not paint it green.
- **A11y 2.73 → 2.** Not the old views: the 632-control Anomalies wall is gone (5 under 44 at 390). The drop is the **new**
  Sluice rule list — 6 rows, `tabIndex -1`, 0 focusable children, 0 `keydown`. The audit cannot see it: it measures pointer
  and touch, not keyboard.
- **Density 2.93 → 2 is partly a correction.** The previous total cannot be reconciled with its own audit: Models at 8,650
  DOM is a 1 under the rubric and Anomalies at 6,144 is a 2, so the ceiling is 42/45. I score the build with the rubric.
- **Entry/vocab/flow down 0.25–0.75.** Same judgments, measured anchors. Vocabulary is the chain's stage-4 label and the two
  rule counts on one Sluice screen, not a regression in old tabs.
- **Scorecard integrity:** the previous Evidence row is all 3s, but Evidence has no tab and `#v=evidence` alone lands on
  Health (restore requires `ev.host`). A 3 for a surface no reader can deliberately open is not evidence.

---

## 3. Hard blockers

**HB-1 — the console can say "auto 15s" while auto-refresh is off.** `index.html:100` (`#auto-toggle`) and `index.html:129`
(`#autorefresh`) are two controls for one job; `app.js:3573` clears the timer from the checkbox without touching
`AUTO_PAUSED` or the pill. Measured: 9 API calls at t0, **9 after 20 s with the box unchecked**, pill still "auto 15s";
clicking the pill then reads "paused" while the box stays checked. A frozen page claiming to be live is the exact lie this
product exists to prevent.

No dead end, no unlabelled destructive action: the tab rail is always present, "Delete this rule" requires a typed reason,
Revoke/Disable/Discard are labelled, Adopt is one click but logged.

---

## 4. Canon themes

**C-1 Type — broken.** 95 `font-size` declarations, **91 raw px**; `--fs-1` 3×, `--fs-2` 1×, `--fs-3/4/6` **0×**. Rendered:
11/12/13/16/21/27 plus 13.33/13.26/14.95/15.21; **19px never renders**; 12px carries 1,078 elements on Anomalies. The brand
word is the only 21px on every screen.

**C-2 Spacing — drifts (advisory).** 221 padding/margin/gap values, **45 off-ladder (20%)** across ten values (3, 5, 7, 9, 11,
13, 14, 18, 22, 28).

**C-3 Radii — drifts.** Eleven off-set declarations (2, 3, 7, 10, 12, 14px) against three allowed; `#wl-summary .stat` is
10px (style.css:383) beside 8px cards.

**C-4 Colour — drifts.** 10 CSS hex outside `:root` plus **34 in JS** (`soc.js` 20, `assets.js` 8, `app.js` 6), including a
ten-colour `SOC_PALETTE` with purple/cyan and a second blue `#7f8cff`. `--accent` is spent in **48 selectors**, including
data marks (`.wl-spark`) and status (`.tap.on`). Root has 60 tokens and six aliases (`--panel2`=`--surface-2`, used 22× vs 14×).

**C-5 One frame, one header — broken.** **67 cards, 65 `h2` across 15 views** (Models 10/10, Settings 9/9, Netflow 7/7,
Sluice 7/6); the view header is the first card's `h2` with an "i" button, and there is **one visible `.primary` console-wide**
("Apply changes"); 0 on Health, Anomalies, Sluice. One card-in-card survives (Anomalies "detectors"). 22 ID-scoped selectors,
incl. a Settings-only collapsible-card pattern.

**C-6 Eight primitives — drifts.** Three beyond the cap with no justification in `canon.json`: `.chain`, the
`info-btn`/`info-text` disclosure (37), and the Network `.graph`.

**C-7 Motion — holds.** Two transitions, three keyframes, 120/180 ms, `prefers-reduced-motion` honoured. Done.

**C-8 Responsive — drifts.** **0 overflow at 1440/820/390/320**; A-1 is closed. But only 420/720 exist — the **1100
breakpoint in `canon.json` is absent** — and at 390 the header is **259px** (status line 200px).

**C-9 Touch — drifts.** Buttons and the 6 verbs behind "⋯" are 44px at 390; text inputs are **31px** (`#f-min-score`,
`#dn-domain`, `#bl-domain`) and `#autorefresh` is **13×13**, 1–9 controls per view under 44.

**C-10 Budgets — drifts.** API 5–9 (inside 12). DOM **6,173** on Anomalies (over; Models fixed at 3,567). Row verbs **100 on
DNS** + 5 on Weirlings vs max 0. Steps-to-answer inside budget (2/3, 1/2, 2/3, 3/4, 1/2).

**C-11 Ratchet — drifts.** Lint: "OK — no new debt", known debt hex 10 / font 41 / radius 16 / hover 133. It reads four
CSS/markup proxies; it cannot see 34 JS hex, 65 `h2`, 100 row verbs or 6,173 DOM. A green gate is not canon compliance.

---

## 5. Findings

**HB-1 · sev 1 · two auto-refresh controls that disagree.** Observed: `index.html:100`, `:129`, `app.js:3573`. Measured:
9→9 API calls over 20 s with auto off, pill unchanged; inverse disagreement after clicking the pill. Fix: one control; the
pill starts/stops and states "live · 15s" or "paused".

**F-2 · sev 1 · there is no view header.** Observed: each view is a stack of `.card` with `h2`; the first is the title, then
1–9 more. Measured: 65 `h2`/15 views; 1 visible `button.primary`; content starts at y=316 at 390. Fix: one header primitive
(title + count + one primary); card headings to h3/eyebrow.

**F-3 · sev 1 · DNS keeps 100 per-row verbs at rest.** Observed: `dnsview.js` renders "Block…" in every row. Measured: 100
verbs/100 rows at 1440 and 390; 125 focusable controls. Fix: adopt Anomalies' row disclosure (there: 100 disclosures, 0 verbs).

**F-4 · sev 2 · Anomalies is 47 screens tall because the narrowest column holds the longest text.** Observed: "Matched rule"
128px wide, 241 chars; "Host" 404px, 30 chars. Measured: rows 377/497px, 104 rows → 42,952px (1440), 43,310px (390); DOM
6,173. Fix: clamp to one line, full text in the disclosure.

**F-5 · sev 2 · RULED prints the review state.** Observed: `app.js:2592` `["ruled","ruled", reviewed[1], reviewed[0]]`, where
`reviewed` maps `review_state` (ack → "acknowledged"). Measured live: `/api/evidence` `review_state:"ack"` → "RULED /
acknowledged"; the vision defines ruled as the policy/rule or "no rule — alert only". Fix: source stage 4 from the rule; move
review state to DONE.

**F-6 · sev 2 · the chain is drawn as a stepper.** Observed: `style.css:414` five equal tracks, each step numbered 1–5.
Measured: 5 × 127px boxes with numerals; vision §2 forbids progress semantics. Fix: drop numerals and equal tracks.

**F-7 · sev 2 · Sluice states its gate three times and its rule count twice.** Observed: `#sl-state` (degraded, 0/0),
`#sl-gates` (degraded, 0/0), `#sl-gate-state` ("off · degraded"), and "Rules (6)" below. Measured: 3 gate surfaces; 6 rules in
the store vs 0 "rules total". Fix: one gate block; "6 in the store · 0 installed on this gate".

**F-8 · sev 2 · Sluice rule rows are unreachable by keyboard.** Observed: `sluice.js:311` `<tr class="sl-rule-row"
title="click to open and edit this rule">`, no `tabindex`/`role`/`keydown`. Measured: 6 rows, `tabIndex -1`, 0 focusable
children. Fix: rule cell as a button, or row `tabindex=0` + Enter/Space, with a visible chevron.

**F-9 · sev 2 · the type ramp is declared, not used.** Observed: `--fs-3/4/6` never referenced; table body `font-size: 12px`;
`#wl-summary .stat .v` hard-codes 27px (style.css:387). Measured: 91/95 raw; 12px on 1,078 elements; 19px never renders. Fix:
replace raw sizes with the five tokens, table body 12→13 and brand 21→19 first.

**F-10 · sev 2 · colour debt lives where the gate cannot see it.** Observed: 34 hex in JS plus 10 in CSS; `soc.js` has a
ten-colour palette and a second blue. Measured: lint reports hex 10 / "no new debt". Fix: `--series-*` tokens; lint `web/*.js`.

**F-11 · sev 3 · Health's failing check leads nowhere.** Observed: checks rows have 0 links/buttons; the view has 0 anchors
and 8 buttons. Measured: "ingest_freshness FAIL newest flow 9h49m ago", 0 clicks to a cause. Fix: name the owner view, link to it.

**Also noted, sev 3:** the Evidence deep link without `ev.start` shows "start is required (the alert's window_start), e.g.
/api/evidence?…" over six empty card frames; ten views never state their window in their own frame; and all 6 live rules read
`describes: "(no predicate)"`, so the primary column is six identical strings — rule clarity fails on the box, not in the CSS.

---

## 6. Cards

1. **P0 · UXF- · One refresh control** — ACCEPT: one control starts/stops refresh and states "live · 15s" or "paused"; API
   count over 20 s matches the stated state.
2. **P0 · DSG- · One view header** — ACCEPT: every view opens with title + count + one primary; no card uses `h2` for a
   sub-block; `h2` per view ≤1 at 1440 and 390.
3. **P0 · UXF- · DNS verbs behind one disclosure** — ACCEPT: 0 controls in `tbody` at rest, one summary per row, matching
   Anomalies.
4. **P1 · DSG- · Anomalies rows ≤72px** — ACCEPT: "Matched rule" one line, full text in the disclosure; 100 rows produce
   <8,000px and DOM <6,000.
5. **P1 · UXR- · RULED is a ruling** — ACCEPT: stage 4 shows the matched rule or "no rule — alert only"; review state only
   in DONE; verified on `/api/evidence`.
6. **P1 · DSG- · The chain is a record** — ACCEPT: no numerals, no five equal tracks; does not resemble a stepper.
7. **P1 · UXF- · One gate state on Sluice** — ACCEPT: gate renders once; store and installed counts labelled separately;
   0 duplicate renderers.
8. **P1 · UXF- · Rule rows keyboard-operable** — ACCEPT: Tab reaches each row, Enter opens the sheet, a chevron marks it,
   Escape closes.
9. **P2 · DSG- · Type tokens** — ACCEPT: 0 raw `font-size` in `style.css`; `--fs-3/4/6` used; rendered sizes ⊆
   {11, 13, 15, 19, 27}.
10. **P2 · DUP- · Series colour tokens** — ACCEPT: 0 hex in `web/*.js`; `SOC_PALETTE` maps to `--series-*`; lint reports the
    same count as a grep.

---

## 7. What the vision gets right

- **The chain is real, and it is the differentiator.** Five stages, each with a state; unknown drawn dashed with a reason; the
  verdict names what cannot happen. No peer in `peers.md` can show that page.
- **Words-first honesty survives the hardest live state.** "these tables are still present after deletion" + "Blocking is
  DISABLED (SLUICE_ENABLED=0), so no rule is enforced however many exist." That sentence is worth more than any chart.
- **The row disclosure is the best canon idea, implemented.** 100 rows, 0 verbs at rest, 6 verbs at 44px behind one "⋯",
  keyboard-reachable `summary`. DNS should inherit it, not redesign it.
- **The audit is a real instrument.** A-1's 257px is gone: 0 overflow at 1440/820/390/320.
- **Receipts are habitual.** "reason for deleting (required, recorded with your name)", actor + reason on writes, break-glass
  on the locked-out screen. Do not lose that to a redesign.

Protect the habit of saying the true sentence next to the number. Fix that the console has no header, no type system, and one
control that can claim a state it is not in.

---

## 8. Update, same day — 0.17.6 (SS-1) landed

This review judges **0.17.5** (`sha-5d18b9c7b`). While it ran, the sheet standard shipped as
**0.17.6** (`8befc09`, image `sha-8befc09ef`): `.sheet` is a real class, `sheets.js` owns the
scrim/Escape/focus/Tab behaviour for both sheets, both are labelled dialogs with a sticky
`.sheet-actions` bar, and `docs/design/sheets.md` + `tests/test_sheet_standard.py` pin it.
The review's caveat about four uncommitted web files is closed: the served bytes are the standard.
Browser-measured with `responsive_audit.py --open-sheet new-rule` and `--open-sheet weirvern`:
both sheets are `position: fixed`, 480px at 1440 and 820, full viewport at 390, scrim shown,
0 page overflow, 0 clipped, 0 JS errors. No other finding in this review moved.
