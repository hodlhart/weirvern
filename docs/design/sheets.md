# The sheet standard

**Status:** locked 2026-10-18 (operator: *"Make that pop out a standard."*) · **Canon:** C-6 names
`sheet` as one of the eight primitives; C-8 fixes its behaviour at ≤720 and puts the primary verb in
thumb reach. This file defines what C-6 only names.

**Implementation:** `weirvern/admin/web/sheets.js` (`openSheet` / `closeSheet` / `sheetIsOpen` /
`wireSheet`), `.sheet`, `.sheet-scrim`, `.sheet-actions` in `style.css`.
**Pinned by:** `tests/test_sheet_standard.py`, `scripts/jsdom_render.js`, and the responsive audit.

---

## 1. When a sheet, and when not

A **sheet** is for changing or reading **one object**: one weirling, one rule. It enters from the
right edge, over the view; the list underneath does not reflow while you read.

| the job | the surface | why |
|---|---|---|
| change or inspect one object | **sheet** | the object stays the subject; the list is context, not a casualty |
| add one object | **sheet**, opened by the view's one primary verb | adding is an act, not a form at rest (vision §12.2) |
| one blocking question about an act already chosen (confirm, reason, type-to-confirm) | **modal** (`app.js`: `openModal`/`confirmDestructive`) | it is about the act, not about an object; it must be answered before anything else |
| a value shown in place | **field** or **chip** on the object | no overlay for a fact |

**Never**: an editable form at rest on a tab; a second composer for the same object; a modal used
to edit an object; a sheet with its own private scrim or key handler.

### The sheet is the only detail surface (locked 2026-11-20)

Reading **one object** — a weirling, a rule, a blocked hit, a scan — is a sheet, always. A centre
modal is allowed **only** for a destructive or irreversible confirmation, and it must carry the
target, the blast radius and the reason it records. A detail that opened in the centre modal
(a `-detail-` node under `openModal`) is the defect this rule names; the Blocked hit detail was
the last one and is a sheet now. Pinned by `tests/test_console_unification.py`.

## 2. Anatomy

```
<card class="card sheet" role="dialog" aria-modal="true" aria-labelledby="<title-id>"
      aria-hidden="true" tabindex="-1">
  <h2><span id="<title-id>">Title</span> <span class="muted">identity</span>
      <button class="sheet-close">Close</button></h2>
  <body: facts, fields, sections>
  <div class="controls sheet-actions">   <!-- sticky: the primary verb stays in thumb reach -->
    <button class="primary">the one act</button>  <button>secondary</button>
  </div>
  <p role="status" aria-live="polite">the receipt / refusal</p>
</card>
```

- **Title** names the object's class ("Change this weirling", "New rule"), never the instance; the
  instance name sits beside it in muted type.
- **One primary verb.** Secondary acts are plain; destructive is `danger` and separated.
- **Facts before fields.** What the object is, its state and its origin come before anything you
  can change.
- **The receipt lives in the sheet** (`role=status`), so the answer to "did it work?" does not
  vanish when the sheet closes.
- **No card inside a card** (C-5). Sections are headings, not nested cards.

## 3. Size and viewport

- Desktop: `width: min(480px, 94vw)`, full height, right edge, `border-left`, radius 0.
- ≤720px: full width (`100vw`), full height; the action bar is sticky at the foot (C-8).
- The scrim covers the view at 35% black; the sheet is `z-index: 75`, the scrim `74`.
- Motion: `sheet-in` 180ms, right-to-left, once on open; `prefers-reduced-motion` is honoured
  globally.
- The list underneath never scrolls sideways or reflows.

## 4. Behaviour

1. **Entry is the object.** A row click opens that object's sheet; the view's one primary verb
   opens it empty for a new one. A sheet opened from another view switches to the view that owns
   it first — an overlay over an inactive view is an invisible dead end.
2. **Four exits, one code path**: Close, Escape, the scrim, and (where it exists) the breadcrumb's
   back segment. All call `closeSheet`.
3. **Escape belongs to the top sheet only**, handled in the capture phase in `sheets.js`; a sheet
   open over a modal closes before the modal does. No module binds its own Escape for a sheet.
4. **Focus moves in and comes back**: the first field (when creating) or the card; on close it
   returns to the control that opened the sheet. Tab is contained while the sheet is open.
5. **Destructive acts arm twice** and require the reason the server records with the actor and the
   time. The first click names the consequence; nothing is written. The second writes.
6. **A sheet never opens another sheet.** If an object needs another object, close and open.
7. **State is re-read on open.** Never render from a page the operator may not have visited.

## 5. Accessibility

- `role="dialog"`, `aria-modal="true"`, `aria-labelledby` pointing at the visible title span.
- `aria-hidden` is toggled with the sheet (not left `false` while hidden).
- The Close control is text, not an icon; its accessible name is its text.
- Focus is visible (`:focus-visible`), and the card itself is focusable (`tabindex="-1"`).
- Every field has a visible label; placeholders never carry the only meaning (C-8, hover rule).
- Touch: primary controls 44px, secondary 36px floor (C-9); the sticky bar keeps the primary act
  reachable with a thumb.

## 6. Checklist for a new surface

- [ ] It changes or reads exactly one object.
- [ ] It carries `class="card sheet"`, `role="dialog"`, `aria-modal="true"`, `aria-labelledby`.
- [ ] It has exactly one `.sheet-close`.
- [ ] It is opened with `openSheet(card, {scrimId, initialFocus, onClose})` and closed with
      `closeSheet(card)`; it builds no scrim, binds no Escape, and does not toggle `.hidden` itself.
- [ ] The primary verb is in `.sheet-actions`.
- [ ] Destructive acts arm twice and require a reason.
- [ ] It was measured in a browser at 1440×900, 820×1180 and 390×844: fixed, right edge 0, width
      480 / 480 / viewport, page overflow 0, no JS errors.
- [ ] A test or harness check pins the behaviour (see `tests/test_sheet_standard.py`).

## 7. Anti-patterns (each one is a defect, not a preference)

- A "Block a host or network" form sitting on the tab it belongs to.
- Per-row trash/ban icons, or a bulk **delete** (reversible bulk acts are fine).
- An icon-only destructive control.
- A second composer for the same object (the retired `#rule-composer` is the example).
- A class named `sheet` that only works for one id (`#wl-detail-card.sheet` before this standard).
- A sheet that closes one way from its button and another way from Escape.

## 8. Adopted by

| surface | owner | opened by |
|---|---|---|
| Weirling drill-down | `weirlings.js` (`#wl-detail-card`) | a fleet row, the palette, a Sluice gate's sensor |
| Sluice rule | `sluice.js` (`#sl-rule-sheet`) | "New rule", a rule row, the DNS/Blocked "block this domain" verb |

**Known debt, carded not hidden:** the Blocked view's rule card is still a modal (`blocked.js` →
`openModal`). Under this standard it is an edit surface for one rule and belongs in the sheet.
Converting it is the first follow-up; until then it is the one exception, recorded here so it
cannot be mistaken for the pattern.
