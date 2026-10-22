/* THE COMMAND PALETTE (BF-11; research cross-cutting #7: Grafana's ⌘K, VS Code's palette).
 *
 * One input over everything: tabs, sensors, settings keys, and actions. Results carry their
 * full path as breadcrumbs ("fleet › edge-alive › enable") so a command is never a guess
 * about where it will take you. Shortcuts stay PLAIN and few: Ctrl/Cmd-K (or /) opens,
 * h is help for whatever you are looking at, f maximizes its main table, g+letter jumps
 * between tabs, and every one of them stays quiet while you are typing in a field.
 *
 * The palette executes by DRIVING THE REAL CONTROLS (clicking the buttons, calling the
 * app's own navigation), never by reimplementing them: a palette that grows a second copy
 * of an action is a palette that drifts from the console.
 */

const PALETTE_TAB_KEYS = {
  health: "h", anomalies: "a", network: "k", netflow: "n", discover: "c", dns: "d",
  zeek: "z", identity: "i", sluice: "l", blocked: "b", weirlings: "w", models: "m",
  host: "o", settings: "s",
};

let PALETTE = { open: false, rows: [], active: 0, gArmedAt: 0, sensors: null, settings: null,
                // The element that had focus before this overlay opened. Kept beside the open
                // flag so close() cannot restore a stale opener from an earlier invocation.
                returnTo: null,
                // US-8: the last commands this session ran (views and actions), newest first.
                recents: [] };
const PALETTE_RECENT_MAX = 6;

function paletteEl() {
  let pal = document.getElementById("palette");
  if (pal) return pal;
  pal = document.createElement("div");
  pal.id = "palette";
  pal.className = "hidden";
  pal.setAttribute("role", "dialog");
  pal.setAttribute("aria-label", "quick links");
  pal.setAttribute("aria-hidden", "true");
  const box = document.createElement("div");
  box.className = "palette-box";
  const input = document.createElement("input");
  input.id = "palette-input";
  input.type = "text";
  input.placeholder = "search or jump to a tab, host, domain, rule or setting\u2026 (Ctrl+K)";
  input.setAttribute("autocomplete", "off");
  const results = document.createElement("div");
  results.id = "palette-results";
  // US-8: the palette teaches its own keys. Small, muted, always there.
  const hint = document.createElement("div");
  hint.className = "palette-hint muted";
  hint.textContent = "\u2191\u2193 move \u00b7 Enter run \u00b7 Esc close \u00b7 Ctrl+K toggles";
  box.appendChild(input);
  box.appendChild(results);
  box.appendChild(hint);
  pal.appendChild(box);
  pal.addEventListener("click", (e) => { if (e.target === pal) paletteClose(); });
  input.addEventListener("input", () => { PALETTE.active = 0; paletteRender(); });
  input.addEventListener("keydown", paletteInputKey);
  document.body.appendChild(pal);
  return pal;
}

function paletteOpen() {
  const pal = paletteEl();
  // THE SHEET STANDARD'S FIRST GUARANTEE (issue #64): remember the control that opened us.
  // Capture only when we were closed; a second open call must not replace the opener with the
  // palette input itself.
  if (!PALETTE.open) PALETTE.returnTo = document.activeElement;
  pal.classList.remove("hidden");
  pal.setAttribute("aria-hidden", "false");
  PALETTE.open = true;
  PALETTE.active = 0;
  const input = document.getElementById("palette-input");
  if (input) { input.value = ""; input.focus(); }
  paletteRender();
  paletteRefreshSources();
}

function paletteClose() {
  const pal = document.getElementById("palette");
  const back = PALETTE.returnTo;
  PALETTE.returnTo = null;
  if (pal) {
    pal.classList.add("hidden");
    pal.setAttribute("aria-hidden", "true");
  }
  PALETTE.open = false;
  // THE SHEET STANDARD'S SECOND GUARANTEE (issue #64): return focus to the opener. Without
  // this the focused element stayed inside the now-hidden overlay, so the next Tab continued
  // from an element the operator could not see. Guard against an opener that was removed, or
  // one that is itself inside the palette (e.g. a caller closes before opening).
  if (back && document.contains(back) && !(pal && pal.contains(back))
      && typeof back.focus === "function") {
    back.focus();
  }
}

/** The focusable nodes inside the palette: input plus any future controls. */
function paletteFocusables() {
  const pal = document.getElementById("palette");
  if (!pal) return [];
  if (typeof sheetFocusables === "function") return sheetFocusables(pal);
  return [...pal.querySelectorAll(
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), '
    + 'textarea:not([disabled]), [tabindex]:not([tabindex="-1"])')]
    .filter((n) => !n.closest(".hidden"));
}

/** Keep Tab and Shift+Tab inside the open palette, exactly as sheets.js does. */
function paletteTrapTab(e) {
  const pal = document.getElementById("palette");
  if (!pal) return;
  const nodes = paletteFocusables();
  if (!nodes.length) {
    e.preventDefault();
    const input = document.getElementById("palette-input");
    if (input) input.focus();
    return;
  }
  const first = nodes[0];
  const last = nodes[nodes.length - 1];
  const active = document.activeElement;
  if (!pal.contains(active)) {
    e.preventDefault();
    (e.shiftKey ? last : first).focus();
    return;
  }
  if (e.shiftKey && active === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && active === last) {
    e.preventDefault();
    first.focus();
  }
}

/** The lazy sources: sensors and settings are fetched once, then cached for the session. */
function paletteRefreshSources() {
  if (PALETTE.sensors === null) {
    PALETTE.sensors = [];
    getJSON("/api/weirlings").then((d) => {
      PALETTE.sensors = (d && d.sensors) || [];
      if (PALETTE.open) paletteRender();
    }).catch(() => {});
  }
  if (PALETTE.settings === null) {
    PALETTE.settings = [];
    getJSON("/api/settings").then((d) => {
      const out = [];
      for (const [group, rows] of Object.entries((d && d.groups) || {})) {
        for (const r of rows || []) out.push({ group, key: r.key, label: r.label });
      }
      PALETTE.settings = out;
      if (PALETTE.open) paletteRender();
    }).catch(() => {});
  }
}

function paletteCommands() {
  const cmds = [];
  for (const tab of document.querySelectorAll(".tab")) {
    const view = tab.dataset.view;
    cmds.push({
      label: `Go to ${tab.textContent.trim()}`,
      path: `console \u203a nav \u203a g ${PALETTE_TAB_KEYS[view] || "?"}`,
      run: () => showView(view),
    });
  }
  for (const s of (PALETTE.sensors || [])) {
    cmds.push({ label: `Open sensor ${s.sensor_id}`, path: `fleet \u203a ${s.state || "?"}`,
                run: () => { showView("weirlings"); if (typeof openWeirling === "function") openWeirling(s.sensor_id).catch(() => {}); } });
    cmds.push({ label: `${s.enabled ? "Disable" : "Enable"} sensor ${s.sensor_id}`,
                path: `fleet \u203a ${s.sensor_id} \u203a power`,
                run: () => { if (typeof wlToggle === "function") wlToggle(s, document.createElement("button")); } });
    cmds.push({ label: `Select ${s.sensor_id} for bulk work`,
                path: `fleet \u203a ${s.sensor_id} \u203a select`,
                run: () => { showView("weirlings"); if (typeof WL_SELECTED !== "undefined") { WL_SELECTED.add(s.sensor_id); if (typeof loadWeirlings === "function") loadWeirlings().catch(() => {}); } } });
  }
  // Cached settings rows render as soon as that source lands.
  for (const r of (PALETTE.settings || [])) {
    cmds.push({
      label: `Open setting ${r.label}`, path: `settings \u203a ${r.group} \u203a ${r.key}`,
      run: () => {
        // US-9: ONE settings-landing implementation (expand the card, then scroll and flash);
        // the per-row Tune verb calls the same helper.
        if (typeof openSettingKey === "function") openSettingKey(r.key);
        else showView("settings");
      },
    });
  }
  // ACTIONS DRIVE THE REAL CONTROLS (no copies): each one is the button's own click.
  const clickWhen = (id, view, delay) => () => {
    showView(view);
    setTimeout(() => { const b = document.getElementById(id); if (b) b.click(); }, delay || 120);
  };
  cmds.push({ label: "Run the siphon probe (30s, in-path)", path: "actions \u203a settings \u203a test run",
              run: clickWhen("st-test", "settings", 160) });
  cmds.push({ label: "Force a model retrain", path: "actions \u203a models \u203a retrain",
              run: () => {
                showView("models");
                setTimeout(() => {
                  const b = document.getElementById("mr-force");
                  if (!b) return;
                  // US-8: state-aware. A disabled button swallows the click silently; the panel
                  // already says WHY (the standing line), so the palette says it out loud.
                  if (b.disabled) {
                    const stand = document.getElementById("mr-stand");
                    const why = (stand && stand.textContent || "").trim()
                      || "the retrain is not available right now";
                    if (typeof showError === "function") {
                      showError(new Error(`retrain unavailable \u2014 ${why}`));
                    }
                    return;
                  }
                  b.click();
                }, 160);
              } });
  cmds.push({ label: "Blocks: filter the recorded blocks by domain", path: "actions \u203a blocks \u203a filter",
              run: () => { showView("blocked");
                           setTimeout(() => { const el2 = document.getElementById("bl-domain"); if (el2) el2.focus(); }, 120); } });
  cmds.push({ label: "Pause or resume auto-refresh", path: "actions \u203a console \u203a live",
              run: () => { const p = document.getElementById("auto-toggle"); if (p) p.click(); } });
  return cmds;
}

/** US-8: ENTITIES FROM THE QUERY ITSELF. A palette that only knows commands makes the
 *  operator translate an address into a command; typing the address IS the navigation.
 *  The entity's home is its own view, and the filter is active when it lands. */
function paletteEntityCommands(q) {
  const s = String(q || "").trim();
  const out = [];
  if (!s) return out;
  const octets = s.split(".");
  const isIP = octets.length === 4
    && octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255);
  const isRule = /^r-[0-9a-z][0-9a-z-]*$/i.test(s);
  const isName = !isIP && /^[a-z0-9]([a-z0-9_-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9_-]*[a-z0-9])?)+$/i.test(s);
  if (isIP) {
    out.push({ label: `Open host ${s} \u2014 traffic, services, anomalies`, path: "entity \u203a host",
               run: () => openHost(s) });
    out.push({ label: `Anomalies for ${s}`, path: "entity \u203a anomalies",
               run: () => { showView("anomalies"); anSetFilter("host", s); } });
  }
  if (isName) {
    out.push({ label: `DNS records for ${s}`, path: "entity \u203a dns",
               run: () => { showView("dns"); if (typeof dnApply === "function") dnApply([["dn-domain", s]]); } });
  }
  if (isRule) {
    out.push({ label: `Open rule ${s}`, path: "entity \u203a sluice",
               run: () => { showView("sluice");
                            if (typeof sluiceHighlightRule === "function") sluiceHighlightRule(s); } });
  }
  return out;
}

/** A subsequence match ("anml" -> "Anomalies"): the cheap fuzzy that still ranks behind
 *  substring hits. Only consulted when no substring match exists, so it can never displace
 *  an exact one. */
function paletteScatter(needle, hay) {
  let i = 0;
  for (const ch of hay) {
    if (ch === needle[i]) i += 1;
    if (i >= needle.length) return true;
  }
  return false;
}

function paletteMatch(q) {
  const needle = String(q || "").trim().toLowerCase();
  const entities = paletteEntityCommands(needle ? String(q).trim() : "");
  const all = paletteCommands();
  if (!needle) {
    // US-8: RECENTS first -- repeat work is one keystroke. Deduped against the list below.
    const seen = new Set();
    const out = [];
    for (const c of [...PALETTE.recents, ...all]) {
      if (seen.has(c.label)) continue;
      seen.add(c.label);
      out.push(c);
      if (out.length >= 12) break;
    }
    return out;
  }
  const scored = [];
  for (const c of all) {
    const label = c.label.toLowerCase();
    const path = c.path.toLowerCase();
    const li = label.indexOf(needle);
    const pi = path.indexOf(needle);
    if (li === -1 && pi === -1) continue;
    scored.push([li === 0 ? 0 : (li > 0 ? 1 : 2), c]);
  }
  scored.sort((a, b) => a[0] - b[0]);
  let rows = scored.map((x) => x[1]);
  if (!rows.length) {
    rows = all.filter((c) => paletteScatter(needle, c.label.toLowerCase()));
  }
  // Entity rows lead: they are the query's own reading of what the operator typed.
  return [...entities, ...rows].slice(0, 12);
}

/** Remember a command as the newest recent (by label, so repeats move rather than duplicate). */
function paletteRemember(c) {
  if (!c || !c.label) return;
  // Marked so the row SAYS it is a recent (its own path follows the marker).
  const marked = (c.path || "").startsWith("recent ")
    ? c : { ...c, path: `recent \u203a ${c.path || ""}` };
  PALETTE.recents = [marked, ...PALETTE.recents.filter((r) => r.label !== c.label)]
    .slice(0, PALETTE_RECENT_MAX);
}

/** US-8: views navigated ANY way become recents ("Go to Anomalies"), so the list reflects the
 *  session's actual last views, not only the ones the palette happened to run. */
function paletteNoteView(view) {
  const tab = [...document.querySelectorAll(".tab")].find((t) => t.dataset.view === view);
  const label = `Go to ${tab ? tab.textContent.trim()
    : view.charAt(0).toUpperCase() + view.slice(1)}`;
  paletteRemember({ label, path: "recent \u203a view", run: () => showView(view) });
}

function paletteRender() {
  const box = document.getElementById("palette-results");
  if (!box) return;
  const input = document.getElementById("palette-input");
  PALETTE.rows = paletteMatch(input ? input.value : "");
  if (PALETTE.active >= PALETTE.rows.length) PALETTE.active = 0;
  box.replaceChildren();
  if (!PALETTE.rows.length) {
    box.appendChild(el("div", { class: "palette-empty muted", text: "nothing matches" }));
    return;
  }
  PALETTE.rows.forEach((c, i) => {
    const row = el("div", {
      class: "palette-row" + (i === PALETTE.active ? " active" : ""),
      attrs: { role: "option", "data-i": String(i) },
      on: { click: () => paletteRun(i) },
    }, [
      el("div", {}, [el("span", { text: c.label })]),
      el("div", { class: "palette-path muted", text: c.path }),
    ]);
    box.appendChild(row);
  });
}

function paletteRun(i) {
  const c = PALETTE.rows[i];
  if (!c) return;
  paletteClose();
  paletteRemember(c);
  try {
    c.run();
  } catch (err) {
    // A command that fails must say so; the palette does not own the action.
    if (typeof showError === "function") showError(err);
  }
}

function paletteInputKey(e) {
  if (e.key === "Escape") { e.preventDefault(); paletteClose(); return; }
  if (e.key === "ArrowDown" || e.key === "ArrowUp") {
    e.preventDefault();
    if (!PALETTE.rows.length) return;
    PALETTE.active = (PALETTE.active + (e.key === "ArrowDown" ? 1 : -1) + PALETTE.rows.length) % PALETTE.rows.length;
    paletteRender();
    return;
  }
  if (e.key === "Enter") {
    e.preventDefault();
    paletteRun(PALETTE.active);
  }
}

/** `f`: maximize the ACTIVE view's main table (toggle). Escape also restores. */
function paletteMaxToggle() {
  const view = document.querySelector(".view.active");
  if (!view) return;
  if (view.querySelector(".card.table-max")) {
    for (const c of view.querySelectorAll(".card.table-max")) c.classList.remove("table-max");
    return;
  }
  const table = view.querySelector("table");
  const card = table && table.closest(".card");
  if (card) card.classList.add("table-max");
}

function paletteTypingIn(e) {
  const t = e.target;
  if (!t || !t.tagName) return false;
  const tag = t.tagName.toUpperCase();
  return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || t.isContentEditable;
}

function paletteGlobalKey(e) {
  // Ctrl/Cmd-K TOGGLES even from a field (it is the escape hatch into the palette).
  if ((e.ctrlKey || e.metaKey) && (e.key === "k" || e.key === "K")) {
    e.preventDefault();
    if (PALETTE.open) paletteClose(); else paletteOpen();
    return;
  }
  if (PALETTE.open) {
    // THE PALETTE OWNS TAB WHILE IT IS OPEN (issue #64). Checked before `paletteTypingIn`
    // because the palette's own input is an INPUT: returning there for a field would let Tab
    // walk out of the overlay into the page behind it.
    if (e.key === "Tab") {
      e.preventDefault();
      paletteTrapTab(e);
      return;
    }
    // The palette input owns the keyboard while it is open (its own handler navigates) --
    // except Escape, which closes from ANYWHERE: an overlay you cannot dismiss with the
    // documented key is a trap.
    if (e.key === "Escape") { e.preventDefault(); paletteClose(); }
    return;
  }
  if (paletteTypingIn(e)) return;   // a field is being typed into: hands off
  if (e.ctrlKey || e.metaKey || e.altKey) return;

  if (Date.now() - PALETTE.gArmedAt < 1400) {
    PALETTE.gArmedAt = 0;
    const view = Object.keys(PALETTE_TAB_KEYS).find((v) => PALETTE_TAB_KEYS[v] === e.key);
    if (view) { e.preventDefault(); showView(view); return; }
  }
  if (e.key === "g") { PALETTE.gArmedAt = Date.now(); return; }
  if (e.key === "/") { e.preventDefault(); paletteOpen(); return; }
  if (e.key === "Escape") {
    const view = document.querySelector(".view.active");
    if (view && view.querySelector(".card.table-max")) { e.preventDefault(); paletteMaxToggle(); }
    return;
  }
  if (e.key === "f") { e.preventDefault(); paletteMaxToggle(); return; }
  if (e.key === "h") {
    // HELP FOR WHAT YOU ARE LOOKING AT: the active view's own info button.
    const view = document.querySelector(".view.active");
    const btn = view && view.querySelector(".info-btn");
    if (btn) { e.preventDefault(); btn.click(); }
  }
}

document.addEventListener("keydown", paletteGlobalKey);

// US-4: the visible entry point (the header button). The keyboard paths stay; hover never
// discovered anything, so the chrome now says the palette exists.
document.addEventListener("DOMContentLoaded", () => {
  const pb = document.getElementById("palette-btn");
  if (pb) pb.addEventListener("click", () => paletteOpen());
});
