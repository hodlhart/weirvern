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

let PALETTE = { open: false, rows: [], active: 0, gArmedAt: 0, sensors: null, settings: null };

function paletteEl() {
  let pal = document.getElementById("palette");
  if (pal) return pal;
  pal = document.createElement("div");
  pal.id = "palette";
  pal.className = "hidden";
  pal.setAttribute("role", "dialog");
  pal.setAttribute("aria-label", "command palette");
  const box = document.createElement("div");
  box.className = "palette-box";
  const input = document.createElement("input");
  input.id = "palette-input";
  input.type = "text";
  input.placeholder = "type a command, a sensor, a setting\u2026";
  input.setAttribute("autocomplete", "off");
  const results = document.createElement("div");
  results.id = "palette-results";
  box.appendChild(input);
  box.appendChild(results);
  pal.appendChild(box);
  pal.addEventListener("click", (e) => { if (e.target === pal) paletteClose(); });
  input.addEventListener("input", () => { PALETTE.active = 0; paletteRender(); });
  input.addEventListener("keydown", paletteInputKey);
  document.body.appendChild(pal);
  return pal;
}

function paletteOpen() {
  const pal = paletteEl();
  pal.classList.remove("hidden");
  PALETTE.open = true;
  PALETTE.active = 0;
  const input = document.getElementById("palette-input");
  if (input) { input.value = ""; input.focus(); }
  paletteRender();
  paletteRefreshSources();
}

function paletteClose() {
  const pal = document.getElementById("palette");
  if (pal) pal.classList.add("hidden");
  PALETTE.open = false;
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
        showView("settings");
        setTimeout(() => {
          const row = document.querySelector(`#view-settings [data-key="${r.key}"]`);
          if (row) {
            row.scrollIntoView({ block: "center" });
            row.classList.add("row-flash");
            setTimeout(() => row.classList.remove("row-flash"), 1600);
          }
        }, 120);
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
              run: clickWhen("mr-force", "models") });
  cmds.push({ label: "Blocked: filter the hits by domain", path: "actions \u203a blocked \u203a filter",
              run: () => { showView("blocked");
                           setTimeout(() => { const el2 = document.getElementById("bl-domain"); if (el2) el2.focus(); }, 120); } });
  cmds.push({ label: "Pause or resume auto-refresh", path: "actions \u203a console \u203a live",
              run: () => { const p = document.getElementById("auto-toggle"); if (p) p.click(); } });
  return cmds;
}

function paletteMatch(q) {
  const needle = String(q || "").trim().toLowerCase();
  const all = paletteCommands();
  if (!needle) return all.slice(0, 12);
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
  return scored.map((x) => x[1]).slice(0, 12);
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
  if (paletteTypingIn(e)) return;   // a field is being typed into: hands off
  if (PALETTE.open) {
    // The palette input owns the keyboard while it is open (its own handler navigates) --
    // except Escape, which closes from ANYWHERE: an overlay you cannot dismiss with the
    // documented key is a trap.
    if (e.key === "Escape") { e.preventDefault(); paletteClose(); }
    return;
  }
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
