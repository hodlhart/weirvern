# Empty states: one component, three facts

**Status:** locked 2026-11-20 (audit: seven classes, three facts) · **Implementation:**
`emptyState()` / `emptyStateCell()` / `emptyRow()` in `weirvern/admin/web/app.js`;
`.empty-state` in `style.css` · **Pinned by:** `tests/test_console_unification.py`,
`tests/test_empty_states.py`, `scripts/jsdom_render.js`.

---

## The rule

An empty region is never just "empty". It is one of exactly three facts, and it says which:

| `data-state` | the word | the fact | what the sentence must carry |
|---|---|---|---|
| `none` | **Nothing here yet** | a measured zero: nothing exists, or nothing was recorded in the window | what was measured and over what window |
| `filtered` | **Nothing matches** | something may exist; the active filters select none of it | **which filters**, by name |
| `failed` | **Could not read** | the read failed — this is **not** an absence | the named reason, and that it is a failure |

A short list, a filtered list and a failed read must never share a look. The `#nw-table`
"No edges" defect is the cautionary case: a graph read that failed printed the same muted line
as a quiet network, so an outage read as calm.

## The component

```js
emptyState({
  state: "filtered",              // none | filtered | failed (default none)
  message: "No host matches …",   // the per-view measurement sentence
  filters: ["search = web", …],   // named by activeFilterLabels(view) or by the renderer
  action: { label: "Clear filters", fn: … },
})
```

- The **word is always in the DOM**, so colour is never the only carrier.
- `filters` is only rendered for `filtered`, and only as names — never as an unlabelled count.
- `action` is a real control that fixes the emptiness, not a link into prose.
- A table uses `emptyStateCell(cols, opts)` (or `emptyRow(tbody, cols, message, action, opts)`).

## Per-view sentences

The component carries the state; the view carries the measurement. Keep the sentence specific
to the view ("No flows from 192.0.2.10 in the last 24h — an empty window is not zero traffic"),
and never replace it with a generic "No data".

## What is NOT an empty state

A cell that states a measured value with no chart beside it (the fleet sparkline's
`N flows` / `—`) is a **value**, not a void. It is `.spark-value`, deliberately outside this
component. Likewise `.review-unreviewed` is a review disposition, not an empty region.
