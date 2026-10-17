# The console's visual theme

*(Name: deliberately TBD — the operator will name it. Until then, "the theme".)*

This is the authoritative spec for Weirvern's console look: the tokens, why each value is
what it is, and which patterns are deliberate refusals. It exists so the next change to
`weirvern/admin/web/style.css` starts from the system instead of a one-off.

**Provenance.** Written 2026-10-17 from a design-research pass: the reference console's
shipped design tokens (read from its public design system and a live instance of it), plus a
review of enterprise consoles across security, observability, network and endpoint products
for what holds up in production and what fails. Raw research notes are not shipped in-repo;
this file is the distilled, maintained source of truth.

---

## 1. The principles (why it reads the way it does)

1. **One accent, spent like currency.** In the reference system only ~9% of colour tokens
   resolve to the brand blue, and exactly one slot means "primary". The accent appears ONLY
   for active / selected / focused / primary-action. Everything structural is neutral.
2. **One neutral ramp carries the complexity.** A single lightness ramp over the canvas —
   the chrome recedes because it is one family, not a palette. Structural fills are
   alpha-white steps over the canvas, not new hues.
3. **Surfaces, not outlines.** Depth comes from background steps plus a hairline ring baked
   into the shadow. Drawn solid borders exist only on form controls. A 1px grey outline
   around a card is the wrong tool on near-black — it stripes the page.
4. **Quiet type, loud numbers — only when the number is the point.** This is a 13px UI.
   The big value size (27px) is reserved for a metric that IS the answer; everywhere else,
   numbers are body text.
5. **Status: colour never travels alone.** Every coloured thing carries its word (or a
   glyph + word). Offline/disabled is a NEUTRAL grey, not red; "pending/attention" is
   info-blue or amber, never alarm-red. Red means destructive or failed, and nothing else.
6. **Progressive disclosure without hiding capability.** Power features live behind
   "Advanced" disclosures and detail views — never removed to make a screen look calmer.
7. **The console must not lie.** Empty ≠ error ≠ loading ≠ no-data; each renders as itself,
   with the query parameters in force, and stale data is stamped with its age. (These rules
   come from production postmortems where dashboards that lied made incidents worse.)

## 2. Tokens (`style.css` `:root` — the single table)

```css
--canvas: #131416;            /* app body */
--surface: #1c1e21;           /* card / panel */
--surface-2: #282b2f;         /* raised tile, nav bg, inputs */
--hover: #34383d;             /* row/tile hover */
--border: rgba(249,250,250,.07);   /* hairline divider */
--border-solid: #42474d;      /* form-control borders (the only solid borders) */
--line: var(--border);        /* line-work alias, so var(--line, …) never falls back */
--fg: #f9fafa;                /* headings and values */
--fg-2: #dee0e3;              /* body text */
--muted: #b7bcc2;             /* labels, secondary text */
--dim: #737c87;               /* tertiary, disabled */
--accent: #4797ff;  --accent-hover: #277ff1;  --accent-wash: #05254d;
--ok: #37be5f;  --warn: #e79613;  --bad: #ee6368;  --crit: #ee6368;
--danger: #ee6368;  --info: #4797ff;  --offline: #737c87;
--wash-ok: #123f20;  --wash-bad: #3e1416;  --wash-info: #05254d;
--font: Inter, Lato, "Segoe UI", system-ui, Arial, sans-serif;
--mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
--fs-1: 11px;  --fs-2: 13px;  --fs-3: 15px;  --fs-4: 19px;  --fs-6: 27px;
--s1: 4px;  --s2: 8px;  --s3: 12px;  --s4: 16px;  --s5: 20px;  --s6: 24px;
--r-sm: 4px;  --r-md: 6px;  --r-lg: 8px;
--ring: 0 0 1px 0 hsla(214,8%,98%,.08);
--shadow-low: 0 8px 24px 0 #000, var(--ring);
--shadow-high: 0 12px 48px 0 #000, var(--ring);
--t-fast: .1s;  --t-med: .2s;
--chart-grid: #34383d;  --chart-axis: #b7bcc2;  --chart-area: rgba(249,250,250,.18);
```

Legacy aliases (`--bg`, `--panel`, `--panel2`, `--muted-foreground`, `--card`) map onto the
new names and are kept for one release; a future rename pass retires them together.

## 3. Type scale and usage

- **Page / brand title** — 19/28, weight 400 (regular, not bold).
- **Card / section title** — 15/24, weight 600, sentence case. (No uppercase labels.)
- **Body, labels, controls** — 13/20, weight 400.
- **Secondary label** — 13px in `--muted`; **caption/tertiary** — 11px in `--dim`.
- **Metric value** — 27/36, weight 600, `font-variant-numeric: tabular-nums`, in `--font`
  (not mono). Mono is for IDENTIFIERS (hosts, addresses, keys) only.
- **Buttons** — 13/20, letter-spacing .25px.

## 4. Component recipes

- **Card** (landed): `background: var(--surface); border: 0; radius 8px; padding 20px;
  box-shadow: var(--shadow-low);` — the ring inside the shadow is the edge.
- **Status chip** (phase 2, one recipe replacing `.pill` / `.review-chip` / ad-hoc chips):
  dot + word, `padding 1px 8px`, radius 4px; filled with the wash colours for ok/bad/info;
  neutral bordered for off; `warn` as a 13% mix. Never colour without the word.
- **Metric tile** (phase 2): label ABOVE the value (13px `--muted`), value 27/36, unit in
  small muted text, helper line below in `--dim`; a micro-chart bar chart uses
  `var(--chart-area)` for resting bars and the accent for the current bucket only.
- **Settings row**: key left (13px `--muted`), control right; one row = one control; hairline
  divider between rows; the `i` affordance on every row.
- **Drill-down side sheet** (phase 3): entity detail slides in from the right (see the
  research spec for the exact recipe); editors stay in centered modals.

## 5. Status semantics

- **Severity**: critical/high in `--bad`/`--warn`, medium in `--warn`, low in `--muted`;
  words accompany every colour (`.sev-*` already does this).
- **Fleet states** (current mapping): `alive` = ok green; `stale` = warn; `never seen` =
  bad (an expectation that FAILED); `unregistered` = warn (**attention, not alarm** — the
  adoption flow is the fix); `disabled` = neutral (switched off on purpose). Phase 2 moves
  `unregistered` to the info treatment per principle 5.
- **Stale data is stamped** — every "as of" surface prints its age; no-data never renders
  as green or as zero.

## 6. The adoption flow (the appliance pattern — implemented 2026-10-17)

A sensor the hub is hearing but nobody has declared appears **inline in the fleet list** as
`unregistered`, and its row offers exactly one action: **Adopt** (one click, from the
sensor's own reports; no drill-down, no form). Feedback is status churn on the row
(`unregistered → registering → registered`), and a failure is a **named state with the
reason**, never silence. The declaration's editable fields stay in the sensor's own panel —
one value, one control. Queued refinements: the churn states and the failure label.

## 7. Phases

- **Phase 1 — LANDED** (2026-10-17): palette, typography, card anatomy, control chrome,
  scrollbars, focus ring, reduced-motion.
- **Phase 2 — queued**: the one chip recipe; metric tiles; chart theming.
- **Phase 3 — queued**: sensor drill-down as a slide-in sheet; fleet as a triage worklist
  (badges, filters in the URL, bulk actions); adoption churn states; a pipeline-quality
  self-audit page.

### Deliberate refusals (do not "fix" these later without reading §1)

- No second home for any setting; every other surface links to the one control.
- No hiding sick/offline entries from default views — stale is an explicit filter, not a
  disappearing act.
- No fake progress bars, no green no-data, no spinner without a word for waits over 1s.
- No feature-hiding minimalism: capability is disclosed, not deleted.
- No uppercase labels; no decorative colour; no drawn card borders.

## 8. Changing the theme

- Tokens are the API: change values in `:root`, not rules. No hex outside `:root` except
  the documented focus ring.
- A new colour must be a semantic role (a state or an affordance), never decoration.
- Every pass runs the jsdom harness and `scripts/gate.sh` before it ships.
- Visual changes ship as their own commit with the phase named, so the history reads as a
  system evolving rather than a pile of tweaks.
