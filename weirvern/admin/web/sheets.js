/* THE SHEET STANDARD (docs/design/sheets.md; canon C-6 names `sheet` as one of the eight
 * primitives, C-8 fixes its behaviour at <=720 and puts the primary verb in thumb reach).
 *
 * A SHEET is for changing or reading ONE object: a weirling, a rule. It enters from the right,
 * over the view, and the list underneath never reflows. A MODAL (app.js) is for one blocking
 * question -- openModal/closeModal -- and is not an editing surface.
 *
 * One implementation, so a sheet cannot disagree with another sheet:
 *   - one scrim factory (no module builds its own div);
 *   - one Escape handler, on the top sheet only, in the capture phase so a sheet open over a
 *     modal closes before the modal does;
 *   - focus moves into the sheet and returns to the control that opened it;
 *   - Tab stays inside the top sheet while it is open;
 *   - one close control (`.sheet-close`), wired here.
 *
 * openSheet(card, {scrimId, onClose, initialFocus}); closeSheet(card); sheetIsOpen(card).
 * wireSheet(card, opts) once at startup binds the close control and remembers the options.
 */
const SHEET_STACK = [];
const SHEET_DEFAULTS = new WeakMap();

function sheetIsOpen(card) {
  return Boolean(card) && !card.classList.contains("hidden");
}

function sheetScrim(id, cardId) {
  let scrim = document.getElementById(id);
  if (!scrim) {
    scrim = document.createElement("div");
    scrim.id = id;
    scrim.className = "sheet-scrim hidden";
    scrim.setAttribute("aria-hidden", "true");
    document.body.appendChild(scrim);
  }
  // The scrim knows WHICH sheet it belongs to. It cannot be inferred from the id: the weirling
  // sheet is `wl-detail-card` with a `wl-sheet-scrim`, so a prefix rule closes the wrong thing.
  scrim.dataset.sheetCard = cardId;
  if (scrim.dataset.wired !== "1") {
    scrim.dataset.wired = "1";
    scrim.addEventListener("click", () => {
      const card = document.getElementById(scrim.dataset.sheetCard);
      if (card) closeSheet(card);
    });
  }
  return scrim;
}

function sheetFocusables(card) {
  const nodes = [...card.querySelectorAll(
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), '
    + 'textarea:not([disabled]), [tabindex]:not([tabindex="-1"])')];
  // No layout in jsdom: a closest(".hidden") check is the honest test in both engines.
  return nodes.filter((n) => !n.closest(".hidden"));
}

function openSheet(card, opts) {
  if (!card) return;
  const merged = Object.assign({}, SHEET_DEFAULTS.get(card) || {}, opts || {});
  const already = SHEET_STACK.find((e) => e.card === card);
  if (already) {
    already.opts = merged;
    card.classList.remove("hidden");
    card.setAttribute("aria-hidden", "false");
    return;
  }
  const scrim = sheetScrim(merged.scrimId || `${card.id}-scrim`, card.id);
  SHEET_STACK.push({ card, opts: merged, returnTo: document.activeElement });
  card.classList.remove("hidden");
  card.setAttribute("aria-hidden", "false");
  scrim.classList.remove("hidden");
  const wanted = merged.initialFocus ? document.getElementById(merged.initialFocus) : null;
  const target = wanted || card;
  if (target && typeof target.focus === "function") target.focus();
}

function closeSheet(card) {
  if (!card) return;
  const i = SHEET_STACK.findIndex((e) => e.card === card);
  if (i < 0) {
    card.classList.add("hidden");
    card.setAttribute("aria-hidden", "true");
    return;
  }
  const [entry] = SHEET_STACK.splice(i, 1);
  card.classList.add("hidden");
  card.setAttribute("aria-hidden", "true");
  const scrim = document.getElementById(entry.opts.scrimId || `${card.id}-scrim`);
  if (scrim) scrim.classList.add("hidden");
  if (typeof entry.opts.onClose === "function") entry.opts.onClose();
  const back = entry.returnTo;
  if (back && document.contains(back) && typeof back.focus === "function") back.focus();
}

function wireSheet(card, opts) {
  if (!card) return;
  SHEET_DEFAULTS.set(card, Object.assign({}, opts || {}));
  if (card.dataset.sheetWired === "1") return;
  card.dataset.sheetWired = "1";
  const close = card.querySelector(".sheet-close");
  if (close) close.addEventListener("click", () => closeSheet(card));
}

// ONE Escape and one Tab containment, for every sheet. Capture phase: a sheet open over a modal
// takes the key first, and stopImmediatePropagation keeps app.js's modal handler from also
// closing the dialog underneath it.
document.addEventListener("keydown", (e) => {
  if (!SHEET_STACK.length) return;
  const top = SHEET_STACK[SHEET_STACK.length - 1];
  if (e.key === "Escape") {
    // THE SURFACE ON TOP OWNS THE KEY. A palette or a confirmation modal opened over a sheet is
    // above it; closing the sheet underneath would be a sheet that disagrees with the screen.
    const modal = document.getElementById("modal");
    const palette = document.getElementById("palette");
    if ((modal && !modal.classList.contains("hidden"))
        || (palette && !palette.classList.contains("hidden"))) return;
    e.preventDefault();
    if (typeof e.stopImmediatePropagation === "function") e.stopImmediatePropagation();
    e.stopPropagation();
    closeSheet(top.card);
    return;
  }
  if (e.key !== "Tab") return;
  const focusable = sheetFocusables(top.card);
  if (!focusable.length) {
    e.preventDefault();
    top.card.focus();
    return;
  }
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
}, true);
