/* Weirvern web GUI — frontend logic.
 *
 * No framework, no build step. Three reasons, and they are the same reasons the
 * server uses http.server: this must work with no extra install, there is no
 * toolchain to keep current on a box that may be offline, and the whole surface
 * is four read-only views.
 *
 * SECURITY NOTE THAT SHAPED THIS FILE: every value that reaches the DOM goes
 * through textContent or a DOM constructor, never innerHTML with interpolated
 * data. Flow data contains attacker-controlled strings (Zeek service names come
 * from network traffic, and a hostname is whatever a PTR record says). Building
 * rows with innerHTML would make a crafted service name execute script in the
 * operator's browser at the moment they are investigating that very traffic.
 * `el()` below exists so there is one safe path to use.
 */

const API = {
  overview: "/api/overview",
  anomalies: (min, limit, unreviewed) =>
    `/api/anomalies?min_score=${min}&limit=${limit}` + (unreviewed ? "&unreviewed=1" : ""),
  review: "/api/review",
  host: (addr, hours) => `/api/host?addr=${encodeURIComponent(addr)}&hours=${hours}`,
  evidence: (addr, start, end) =>
    `/api/evidence?addr=${encodeURIComponent(addr)}&start=${encodeURIComponent(start)}` +
    (end ? `&end=${encodeURIComponent(end)}` : ""),
  // The SOC views. `health` is the DEEP check (reads ClickHouse), NOT /api/healthz, which
  // is the Kubernetes liveness probe and answers a bare {"ok":true} without touching the
  // database so a slow database cannot restart the GUI.
  netflow: "/api/netflow",
  zeek: "/api/zeek",
  health: "/api/health",
};

let timer = null;

/* ── small helpers ──────────────────────────────────────────────────────── */

function el(tag, opts = {}, children = []) {
  const node = document.createElement(tag);
  if (opts.class) node.className = opts.class;
  if (opts.text !== undefined) node.textContent = String(opts.text);
  // `value` is not `text`. An <input> has no textContent, so a value passed through opts.text
  // set nothing and every editable settings field rendered BLANK: the operator could not see the
  // value they were about to change, and a stray keystroke would stage an empty string over a
  // working setting. `=== null` is handled because an unset secret reports null, and
  // String(null) would render the word "null".
  if (opts.value !== undefined) node.value = opts.value === null ? "" : String(opts.value);
  // `selected` is a PROPERTY of an <option> the way `value` is of an <input>, and el() used
  // to DROP it (plain option keys that are not handled here are ignored). Every role dropdown
  // in the users panel therefore rendered its FIRST option -- "viewer" -- while the store held
  // "admin": the operator changed the role, the server accepted it, and the re-render showed
  // the wrong value again. That read as "stuck on viewer"; the change had landed each time.
  // Same trap family as the `type:` note further down: both attributes and properties have to
  // be applied, and a dropped one fails silently.
  if (opts.selected !== undefined) node.selected = Boolean(opts.selected);
  if (opts.title) node.title = String(opts.title);
  if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) node.setAttribute(k, v);
  if (opts.on) for (const [ev, fn] of Object.entries(opts.on)) node.addEventListener(ev, fn);
  for (const c of children) if (c) node.appendChild(c);
  return node;
}

function fmtBytes(n) {
  n = Number(n) || 0;
  const units = [["TB", 1e12], ["GB", 1e9], ["MB", 1e6], ["KB", 1e3]];
  for (const [u, d] of units) if (Math.abs(n) >= d) return (n / d).toFixed(1) + " " + u;
  return String(Math.round(n));
}

/**
 * A duration in seconds as a compact age. Mirrors status._human_age in the backend so
 * the same figure cannot render two different ways between server and browser.
 */
// Techniques arrive as JSON in one column. Parsed defensively: a malformed value must
// degrade the technique block, not blank the whole evidence view -- the evidence is what the
// analyst came for.
function parseTechniques(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v : [];
  } catch (e) {
    return [];
  }
}

function fmtAge(seconds) {
  const s = Math.max(0, Math.floor(Number(seconds) || 0));
  if (s < 60) return s + "s";
  if (s < 3600) return Math.floor(s / 60) + "m" + (s % 60) + "s";
  if (s < 86400) return Math.floor(s / 3600) + "h" + Math.floor((s % 3600) / 60) + "m";
  return Math.floor(s / 86400) + "d" + Math.floor((s % 86400) / 3600) + "h";
}

function fmtTime(v) {
  if (!v) return "—";
  const d = new Date(v);
  if (isNaN(d)) return String(v);
  // Local, short. An operator correlating with a firewall uses wall-clock time.
  return d.toLocaleString(undefined, { month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/* A host cell shows the name AND the IP, never one instead of the other: the name is
 * convenient, the IP is the fact that lets an operator search a DHCP lease or a
 * firewall rule.
 *
 * `sameAs` is for DESTINATION columns on a host drill-down: when the destination is the
 * host you are already looking at, repeating its name in every row is noise, so only
 * the IP is shown. Any other destination gets the full label. */
function hostCell(addr, hostname, sameAs = null) {
  if (!addr) return el("span", { class: "muted", text: "—" });
  if (!hostname || addr === sameAs) return el("span", { class: "host", text: addr });
  return el("span", { class: "host" }, [
    el("span", { text: hostname }),
    el("br"),
    el("span", { class: "ip", text: addr }),
  ]);
}

function sevCell(sev) {
  const s = String(sev || "").toLowerCase() || "unknown";
  return el("span", { class: "sev-" + s, text: s });
}

function emptyRow(tbody, cols, message) {
  tbody.replaceChildren(el("tr", {}, [
    el("td", { class: "empty", text: message, attrs: { colspan: String(cols) } }),
  ]));
}

/* The ONE JSON fetch helper, shared by every script. scripts/jsdom_render.js evaluates all
 * three files as one scope and a test pins this as the sole definition: it used to exist TWICE
 * (here and in assets.js), and because <script> tags share a global scope, the later-loaded
 * copy silently won for every call site -- app.js's and soc.js's error semantics were decided
 * by script order, which nothing would have caught if the order changed. Kept here because
 * this file loads first and the other shared helpers live here too. */
async function getJSON(url) {
  const res = await fetch(url, { headers: requestHeaders() });
  // Parse ONCE, tolerating a non-JSON body: an error page must not turn a status into
  // "undefined", and a 200 with a bad body must not throw here with a parse error where the
  // caller expects the payload contract.
  const body = await res.json().catch(() => null);
  if (!res.ok) {
    throw new Error((body && body.error) || `${res.status} ${res.statusText}`.trim());
  }
  return body;
}

/* ── sensor ─────────────────────────────────────────────────────────────── */

/* ── overview ───────────────────────────────────────────────────────────── */

/* ── settings ───────────────────────────────────────────────────────────────
 *
 * READ-ONLY BY DESIGN, and the panel says so. The GUI is served on a LAN port with no
 * authentication, so any write it accepted would be a way to reconfigure the sensor from the
 * network -- the same reasoning the removed About tab carried. This shows the EFFECTIVE
 * configuration and where to change it.
 *
 * A secret shows as "(set, N chars)" or "(not set)" rather than a value: an operator debugging
 * an authentication failure needs to distinguish those two, and the value must not cross an
 * unauthenticated port.
 */
/* ── operator token ─────────────────────────────────────────────────────────
 *
 * Held in sessionStorage, not localStorage and not a cookie: it dies with the tab, and it is not
 * attached to every request to this origin by the browser the way a cookie would be. The server
 * accepts a cookie too (so a reload does not force re-entry) but it is not the primary mechanism.
 *
 * This control cannot ENABLE writes. Whether writes are permitted is decided server-side by
 * whether a token is configured at all -- a browser cannot talk the server into accepting one.
 */
const TOKEN_KEY = "weirvern-token";
const SESSION_KEY = "weirvern-session";

function getToken() {
  try { return window.sessionStorage.getItem(TOKEN_KEY) || ""; } catch (_e) { return ""; }
}

function setToken(v) {
  try {
    if (v) window.sessionStorage.setItem(TOKEN_KEY, v);
    else window.sessionStorage.removeItem(TOKEN_KEY);
  } catch (_e) { /* private mode: the token simply does not persist */ }
}

function getSession() {
  try { return window.sessionStorage.getItem(SESSION_KEY) || ""; } catch (_e) { return ""; }
}

function setSession(v) {
  try {
    if (v) window.sessionStorage.setItem(SESSION_KEY, v);
    else window.sessionStorage.removeItem(SESSION_KEY);
  } catch (_e) { /* private mode: the session simply does not persist */ }
}

/* Every request carries whatever credentials this tab holds, so a read and a write see the
 * same identity. Sent as HEADERS and never as cookies: a cookie would ride along on cross-site
 * requests (the classic CSRF shape), while a custom header cannot be set by a cross-site form. */
function requestHeaders(base) {
  const h = Object.assign({ Accept: "application/json" }, base || {});
  const s = getSession();
  if (s) h["X-Weirvern-Session"] = s;
  const t = getToken();
  if (t) h["X-Weirvern-Token"] = t;
  return h;
}

/* ── who this tab is ─────────────────────────────────────────────────────────
 *
 * AUTH mirrors the server's /api/session answer and is the single source the UI consults for
 * gating: whether accounts exist at all, who is signed in, and what role they carry. The
 * browser never decides any of that -- it renders what the server said on the last probe, and
 * re-probes after every action that could change it (sign in, sign out, password change).
 */
const AUTH = { accounts: false, authenticated: false, username: "", role: "",
               must_change: false, via: "", note: "" };

async function loadSession() {
  const data = await getJSON("/api/session");
  Object.assign(AUTH, {
    accounts: !!(data && data.accounts),
    authenticated: !!(data && data.authenticated),
    username: (data && data.username) || "",
    role: (data && data.role) || "",
    must_change: !!(data && data.must_change),
    via: (data && data.via) || "",
    note: (data && data.note) || "",
  });
  return AUTH;
}

/** Show the sign-in gate, the forced-password gate, or neither. One place, one state. */
function showGate(which, note) {
  const authGate = document.getElementById("auth-gate");
  const pwGate = document.getElementById("pw-gate");
  const gnote = document.getElementById("gate-note");
  if (note && gnote) gnote.textContent = note;
  if (authGate) authGate.classList.toggle("hidden", which !== "auth");
  if (pwGate) pwGate.classList.toggle("hidden", which !== "pw");
  if (which === "pw") {
    const cur = document.getElementById("pw-current");
    if (cur) cur.focus();
  }
}

/** The header chip and the sign-out button, from AUTH. */
function refreshChrome() {
  const chip = document.getElementById("user-chip");
  const out = document.getElementById("sign-out");
  if (!chip) return;
  if (AUTH.authenticated && AUTH.via === "token") {
    chip.textContent = "operator token (break-glass)";
    chip.setAttribute("title", "Admin rights from the deployment operator token; no account.");
    if (out) out.classList.add("hidden");
  } else if (AUTH.authenticated) {
    chip.textContent = `${AUTH.username} · ${AUTH.role}`;
    chip.setAttribute("title", AUTH.must_change
      ? "This account must change its password before it can be used"
      : `Signed in as ${AUTH.username} (${AUTH.role})`);
    if (out) out.classList.toggle("hidden", AUTH.via !== "session");
  } else {
    chip.textContent = "";
    chip.setAttribute("title", "");
    if (out) out.classList.add("hidden");
  }
}

/** The Account card on Settings: who you are, and whether a password can be changed here. */
function refreshAccountCard() {
  const note = document.getElementById("st-account-note");
  const pw = document.getElementById("st-account-pw");
  if (!note) return;
  if (!AUTH.accounts) {
    note.textContent = "This deployment has no accounts provisioned: the operator token "
      + "below is the credential that changes settings. An admin account is created "
      + "automatically on the deployment's first startup.";
    if (pw) pw.classList.add("hidden");
    return;
  }
  if (AUTH.authenticated && AUTH.via === "token") {
    note.textContent = "You are using the break-glass operator token: it grants admin rights "
      + "with no account, so there is no password to change here. Use the Users panel below "
      + "to manage accounts, or sign in with one.";
    if (pw) pw.classList.add("hidden");
    return;
  }
  if (AUTH.authenticated) {
    note.textContent = `Signed in as ${AUTH.username} (${AUTH.role}).`
      + (AUTH.must_change ? " This account must change its password." : "");
    if (pw) pw.classList.remove("hidden");
    return;
  }
  note.textContent = "Not signed in.";
  if (pw) pw.classList.add("hidden");
}

/* ── accounts: sign in, sign out, password change ──────────────────────────── */

async function doLogin(username, password) {
  const resp = await window.fetch("/api/login", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  let payload = null;
  try { payload = await resp.json(); } catch (_e) { payload = null; }
  if (!resp.ok || !payload || !payload.ok) {
    throw new Error((payload && payload.error) || `HTTP ${resp.status}`);
  }
  setSession(payload.session || "");
  await loadSession();
  refreshChrome();
  return payload;
}

async function doLogout() {
  try { await postJSON("/api/logout", {}); } catch (_e) { /* already gone is fine */ }
  setSession("");
  Object.assign(AUTH, { authenticated: false, username: "", role: "", must_change: false,
                        via: "" });
  refreshChrome();
  showGate("auth", "Signed out. Sign in to continue.");
}

/** Change this account's own password. The server revokes every session for it, so the tab
 *  returns to the sign-in gate and proves the change by signing in again.
 *
 *  A 401 here means the session ended (revoked, expired, or a restart) between the gate being
 *  drawn and the form being submitted -- the account is NOT signed in and saying only "sign in
 *  first" leaves the operator staring at a form that cannot work. Clear the dead session and
 *  put the sign-in gate back up, which is what "sign in first" actually asks for.
 */
async function changePassword(current, next) {
  let res;
  try {
    res = await postJSON("/api/password", { current, new: next });
  } catch (err) {
    if (err && err.status === 401) {
      setSession("");
      Object.assign(AUTH, { authenticated: false, username: "", role: "", must_change: false,
                            via: "" });
      refreshChrome();
      showGate("auth", "Your session has ended. Sign in again, then change the password.");
    }
    throw err;
  }
  setSession("");
  Object.assign(AUTH, { authenticated: false, username: "", role: "", must_change: false,
                        via: "" });
  refreshChrome();
  showGate("auth", "Password changed. Sign in with the new one.");
  return res;
}

/** A POST to a write route, with whatever credentials this tab holds. Throws with the server's reason. */
async function postJSON(path, body) {
  const resp = await window.fetch(path, {
    method: "POST",
    headers: requestHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(body),
  });
  let payload = null;
  try { payload = await resp.json(); } catch (_e) { payload = null; }
  if (!resp.ok) {
    // The server's own words. A 401/403 here is a real answer, not a transport failure.
    const err = new Error((payload && payload.error) || `HTTP ${resp.status}`);
    err.status = resp.status;
    err.payload = payload;
    throw err;
  }
  return payload || {};
}

/* ── staged changes ─────────────────────────────────────────────────────────
 *
 * NOTHING IS WRITTEN UNTIL APPLY. Every edit stages locally; the plan is then fetched from the
 * server so the validation and the blast radius come from the SAME code that will perform the
 * write. A second copy of the rules in JavaScript would drift from the server's, and the copy
 * that drifts is the one nobody tests -- so the browser never decides whether a value is legal.
 */
const STAGE = { changes: {}, plan: null };

/* The last settings payload's rows, keyed by row key. SONAR stages its recommendations
 * through the SAME dedupe the manual controls use (stageChange needs each key's CURRENT
 * value to decide "staged or unchanged"), and the rows are the only place that value
 * lives client-side. Cleared and repopulated on every loadSettings. */
let SETTINGS_ROWS = {};

/* ── setting controls ─────────────────────────────────────────────────────────
 *
 * EVERY EDITABLE SETTING RENDERS AS ITS NATURAL CONTROL -- a toggle for on/off, a dropdown for a
 * choice, a constrained number input for a number -- instead of a free-text box. The operator
 * picks a value rather than typing one, so the two failure modes a text box invites both
 * disappear: a typo that the server rejects only after Apply, and a value whose legal range
 * was never visible in the first place.
 *
 * The control spec (kind, bounds, options) comes from the SERVER (`controls` on the settings
 * payload), derived from the same table `validate()` enforces -- so what the control permits and
 * what the write path accepts cannot drift apart. The JS never decides what is legal; it only
 * renders the bounds the server stated.
 *
 * `text` remains for the genuinely free-text keys (interface names, addresses, CIDR lists) --
 * it is a deliberate per-key choice in the registry, not a fallback for missing specs.
 */

/** One editable setting rendered as its natural control. Stages on change; never writes. */
function settingControl(row, shown, spec) {
  const key = row.key;
  const stage = (v) => stageChange(key, v, String(row.value));
  const s = spec || { control: "text" };

  if (s.control === "toggle") {
    // A BOOLEAN AS A TOGGLE, not a text field reading "true"/"false".
    //
    // The running value arrives in whichever spelling its owner uses: the settings payload
    // renders booleans as "enabled"/"disabled", a hand-edited ConfigMap may say "1"/"on", and
    // the validator accepts true/false/1/0/yes/no. They all MEAN the same switch, so the toggle
    // normalises on read and stages the canonical true/false the write path accepts -- including
    // for the comparison that decides whether anything was actually changed, so flipping a
    // switch back to its running state un-stages it instead of leaving a phantom change.
    const canon = (v) => {
      const t = String(v).toLowerCase();
      if (["true", "1", "yes", "on", "enabled"].includes(t)) return "true";
      if (["false", "0", "no", "off", "disabled"].includes(t)) return "false";
      return String(v);
    };
    const on = canon(shown) === "true";
    // The state word beside the box: "checked means enabled, right?" must not be a guess, so the
    // switch says on/off in words and the word follows the box.
    const stateWord = el("span", { class: "setting-toggle-state", text: on ? "on" : "off" });
    const box = el("input", {
      class: "setting-toggle",
      attrs: { type: "checkbox", "data-key": key },
      on: { change: (ev) => {
        const now = ev.target.checked;
        stateWord.textContent = now ? "on" : "off";
        stageChange(key, now ? "true" : "false", canon(row.value));
      } },
    });
    box.checked = on;
    return el("span", { class: "setting-ctl-group" }, [
      el("label", { class: "setting-toggle-label" }, [box, stateWord]),
    ]);
  }

  if (s.control === "select") {
    // A DROPDOWN, with the current value selected. If the running value is not among the
    // options (a hand-edited ConfigMap), it is added so the control shows reality instead of
    // silently displaying a different value than what is running.
    const opts = (s.options || []).slice();
    if (shown !== "" && !opts.includes(String(shown))) opts.push(String(shown));
    const sel = el("select", {
      class: "setting-select",
      attrs: { "data-key": key },
      on: { change: (ev) => stage(ev.target.value) },
    });
    for (const o of opts) {
      const opt = el("option", { value: o, text: o });
      if (String(shown) === o) opt.selected = true;
      sel.appendChild(opt);
    }
    return sel;
  }

  if (s.control === "number") {
    // A NUMBER INPUT with the server's own bounds and step. min/max mean the browser refuses
    // most bad values before Apply; the server still validates (it must), and the hint states
    // the range so the constraint is visible rather than enforced-by-surprise.
    //
    // `type` rides in attrs: `el()` applies attrs via setAttribute, and a bare `type:` option
    // is silently ignored -- the input would default to text and the control would be the thing
    // this revision exists to remove. (The old text input passed `type: "text"` the same way and
    // looked correct only because "text" is the default.)
    const input = el("input", {
      class: "setting-input setting-number", value: shown,
      attrs: { type: "number", "data-key": key, inputmode: "decimal", spellcheck: "false",
               autocomplete: "off" },
      on: { input: (ev) => stage(ev.target.value) },
    });
    if (s.min !== undefined) input.setAttribute("min", String(s.min));
    if (s.max !== undefined) input.setAttribute("max", String(s.max));
    if (s.step !== undefined) input.setAttribute("step", String(s.step));
    const range = (s.min !== undefined && s.max !== undefined)
      ? `${s.min}–${s.max}${s.unit ? " " + s.unit : ""}` : "";
    return el("span", { class: "setting-ctl-group" }, [
      input,
      range ? el("span", { class: "setting-unit", text: range }) : null,
    ]);
  }

  // text -- the deliberate free-text keys. data-key kept so the DOM harness and any other
  // selector can find it by key regardless of control kind.
  return el("input", {
    class: "setting-input", value: shown,
    attrs: { type: "text", "data-key": key, spellcheck: "false", autocomplete: "off" },
    on: { input: (ev) => stage(ev.target.value) },
  });
}

function stageChange(key, value, original) {
  // A new edit supersedes the previous apply's message: leaving a stale "saved" line next to a
  // fresh staged change would claim a state that no longer holds.
  LAST_APPLY.text = "";
  if (value === original) delete STAGE.changes[key];
  else STAGE.changes[key] = value;
  STAGE.plan = null;   // any edit invalidates a previously fetched plan
  renderStage();
}

function discardStage() {
  STAGE.changes = {};
  STAGE.plan = null;
  // Re-render from the server's values so the inputs and the table agree again.
  loadSettings().catch(showError);
}

/** The outcome of the last apply, shown until the next apply. Survives a settings reload. */
const LAST_APPLY = { text: "" };

function renderStage() {
  const keys = Object.keys(STAGE.changes);
  const count = document.getElementById("st-stage-count");
  const note = document.getElementById("st-stage-note");
  const list = document.getElementById("st-stage-list");
  const apply = document.getElementById("st-stage-apply");
  const discard = document.getElementById("st-stage-discard");
  if (!list) return;

  if (count) count.textContent = keys.length ? `${keys.length} staged` : "";
  if (apply) apply.disabled = keys.length === 0;
  if (discard) discard.disabled = keys.length === 0;

  list.replaceChildren();
  if (!keys.length) {
    // THE RESULT OF THE LAST APPLY OUTLIVES THE RELOAD. loadSettings() runs after an apply and
    // calls this function, which would otherwise erase the confirmation an operator just waited
    // for -- they would see "no changes staged" and have to guess whether it worked.
    if (note) {
      note.textContent = LAST_APPLY.text
        || "No changes staged. Edit a value above to stage one.";
    }
    return;
  }
  if (note) {
    note.textContent = "Staged, not applied. Apply will write the cluster configuration and "
      + "restart whatever reads it.";
  }

  // A staged edit whose value the server would reject is shown BEFORE apply, so nobody discovers
  // a typo by pressing the button.
  const bad = [];
  for (const key of keys) {
    const row = el("div", { class: "stage-row" }, [
      el("span", { class: "stage-key mono", text: key }),
      el("span", { class: "stage-arrow", text: "→" }),
      el("span", { class: "stage-val mono", text: STAGE.changes[key] || "(empty)" }),
    ]);
    if (STAGE.plan) {
      const p = (STAGE.plan.proposals || []).find((x) => x.key === key);
      if (p && p.warning) {
        row.appendChild(el("div", { class: "stage-warn", text: "⚠ " + p.warning }));
        bad.push(key);
      }
    }
    list.appendChild(row);
  }
  if (STAGE.plan) {
    const targets = STAGE.plan.restart_targets || [];
    list.appendChild(el("div", { class: "stage-blast" }, [
      el("strong", { text: targets.length ? "Will restart: " : "No restart needed." }),
      el("span", {
        text: targets.join(", "),
        attrs: { title: "A ConfigMap value is read at process start, so a change is inert until " +
                        "the reader restarts." },
      }),
    ]));
  }
}

/** Ask the server what the staged changes would do. Touches nothing. */
async function planStage() {
  const body = { changes: STAGE.changes };
  STAGE.plan = await postJSON("/api/settings/plan", body);
  renderStage();
  return STAGE.plan;
}

/** Apply, then report exactly what happened. */
async function applyStage() {
  const note = document.getElementById("st-stage-note");
  const keys = Object.keys(STAGE.changes);
  if (!keys.length) return;
  if (note) note.textContent = "applying…";
  try {
    // Plan first, always: the server may insist on explicit confirmation, and a plan the operator
    // never saw is not consent. This also surfaces a rejected value before anything is written.
    await planStage();
    // ONLY the staged keys. The server returns proposals for what was sent, but filtering here
    // means a stray proposal can never block an apply with a confirmation prompt for a change the
    // operator did not make.
    const stagedKeys = new Set(Object.keys(STAGE.changes));
    const warns = (STAGE.plan.proposals || [])
      .filter((p) => p.warning && stagedKeys.has(p.key));
    if (warns.length) {
      const ok = window.confirm(
        "This change is allowed but costly:\n\n" +
        warns.map((p) => `${p.key}: ${p.warning}`).join("\n\n") +
        "\n\nApply anyway?");
      if (!ok) { if (note) note.textContent = "not applied — you declined the warning"; return; }
    }
    const res = await postJSON("/api/settings/apply", { changes: STAGE.changes, confirmed: true });

    // Report the outcome in the server's terms. A saved-but-not-restarted change is INERT, so it
    // is shown as a problem rather than folded into a success line.
    STAGE.changes = {};
    STAGE.plan = null;
    const parts = ["saved: " + Object.entries(res.applied || {}).map(([k, v]) => `${k}=${v || "(empty)"}`).join(", ")];
    if ((res.restarted || []).length) parts.push("restarted " + res.restarted.join(", "));
    if ((res.restart_errors || []).length) {
      parts.push("NOT APPLIED — " + res.restart_errors.join("; "));
    }
    LAST_APPLY.text = parts.join(" · ");
    if (note) note.textContent = LAST_APPLY.text;
    await loadSettings();
  } catch (err) {
    // A refused write states the server's reason: a missing token, an RBAC gap, a bad value.
    if (note) note.textContent = "not applied — " + (err.message || err);
    if (err.status === 401) { setToken(""); await refreshAuthNote(); }
  }
}


/* ── TEST RUN (the siphon probe) ─────────────────────────────────────────────
 *
 * THE MOST CONSEQUENTIAL BUTTON ON THE PAGE. It flips the sensor to siphon mode for 30
 * seconds (real ARP-forging, real relaying), then the SERVER reverts the mode to loch and
 * restarts the worker, whose orderly shutdown restores every mapping. The revert lives on
 * the server (a finally, plus a timer backstop) precisely because this browser tab cannot
 * be trusted to send a second request -- a closed tab, a lost network, a dead machine.
 *
 * It is synchronous from the browser's point of view: the fetch stays open for the whole
 * window and the button says so. That is deliberate -- a fire-and-forget probe would need
 * a job and a poller, and this one's entire value is the observed window, which the
 * response carries.
 */
async function runSiphonTest() {
  const btn = document.getElementById("st-test");
  const note = document.getElementById("st-test-note");
  if (SONAR_STATE.testRunning) return null;
  SONAR_STATE.testRunning = true;
  if (btn) { btn.disabled = true; btn.textContent = "Testing… (up to 30s)"; }
  if (note) note.textContent = "Test run in progress: siphon is switching on, the intercept "
    + "will run for about 30 seconds, then the mode reverts to loch automatically. "
    + "Do not close this tab.";

  try {
    const res = await postJSON("/api/settings/test", { seconds: 30 });
    renderTestNote(res);
    return res;
  } catch (err) {
    if (note) note.textContent = "Test run: " + ((err && err.payload && err.payload.error)
      || (err && err.message) || String(err));
    return null;
  } finally {
    SONAR_STATE.testRunning = false;
    if (btn) { btn.disabled = false; btn.textContent = "Test run (30s)"; }
    // The mode may have changed (there, and back). Re-read so the rows reflect the CLUSTER.
    try { await loadSettings(); } catch (_e) { /* the note below still stands */ }
  }
}

/** What the probe saw, in the server's terms. Never invents a verdict. */
function renderTestNote(res) {
  const note = document.getElementById("st-test-note");
  if (!note) return;
  note.replaceChildren();
  if (!res) return;
  if (res.ok === false) {
    note.appendChild(el("span", { class: "sonar-err", text: res.error || "the test did not run" }));
    return;
  }
  const bits = [];
  bits.push(res.reverted
    ? `Test complete: siphon ran for ${res.seconds}s, then the mode was set back to loch and the intercept stopped.`
    : `WARNING: the mode could NOT be set back to loch — ${res.error || "check the cluster"}. Set it to loch manually.`);
  if (res.observed) {
    bits.push(`The intercept was observed live: ${res.observed.hosts} host(s), `
      + `${res.observed.mappings} mapping(s)${res.observed_s != null ? `, seen ${Math.round(res.observed_s)}s in` : ""}.`);
  } else {
    bits.push("No intercept evidence arrived during the window — see the notes below.");
  }
  if (res.mode_before && res.mode_before === "siphon") {
    bits.push("(The sensor was already in siphon before this test; it is loch now.)");
  }
  note.appendChild(el("div", { class: res.reverted ? "" : "sonar-err", text: bits.join(" ") }));
  for (const n of (res.notes || [])) {
    note.appendChild(el("div", { class: "sonar-note-item", text: "• " + n }));
  }
}


window.LAST_APPLY = LAST_APPLY;


/* ── SONAR ──────────────────────────────────────────────────────────────────
 *
 * Surveys the capture interface's segment and stages the result as PENDING CHANGES --
 * the same staged list the manual controls fill. Nothing is written here: the survey
 * itself is read-only on the network (ARP requests only), and its recommendations become
 * ordinary staged changes that a human reviews and applies.
 *
 * WHY THE RECOMMENDATIONS GO THROUGH stageChange: that is the one path that already
 * knows how to compare against the running value (an unchanged recommendation stages
 * nothing) and how to feed the pending-changes list, the plan fetch, and Apply. A
 * parallel "apply these directly" path would be a second write route in the client with
 * its own bugs -- and the operator asked for the pending-changes review step.
 */
const SONAR_STATE = { running: false, result: null, error: "", testRunning: false };

async function runSonar() {
  const btn = document.getElementById("st-sonar");
  const note = document.getElementById("st-sonar-note");
  if (SONAR_STATE.running) return null;
  SONAR_STATE.running = true;
  SONAR_STATE.error = "";
  if (btn) { btn.disabled = true; btn.textContent = "Surveying…"; }
  if (note) note.textContent = "Surveying the segment: one ARP sweep from the sensor node. "
    + "Nothing is changed — this can take a few seconds.";

  try {
    const res = await postJSON("/api/settings/sonar", {});
    SONAR_STATE.result = res;
    stageSonarRecommendations(res);
    renderSonarNote(res);
    return res;
  } catch (err) {
    SONAR_STATE.error = (err && err.message) || String(err);
    if (note) note.textContent = "Sonar could not survey: " + SONAR_STATE.error;
    return null;
  } finally {
    SONAR_STATE.running = false;
    if (btn) { btn.disabled = false; btn.textContent = "Sonar"; }
  }
}

/** Stage every recommendation through the same dedupe the manual controls use. */
function stageSonarRecommendations(res) {
  const rec = (res && res.recommended) || {};
  for (const [key, value] of Object.entries(rec)) {
    const row = SETTINGS_ROWS[key];
    // The current value is the row's running value; when the row is absent no comparison
    // is possible and the recommendation is staged (it will be validated by the plan).
    const current = row ? String(row.value) : "";
    stageChange(key, String(value), current);
  }
}

/** What Sonar measured, in the panel. Every number here was measured, not guessed. */
function renderSonarNote(res) {
  const note = document.getElementById("st-sonar-note");
  if (!note) return;
  note.replaceChildren();
  if (!res || res.ok === false) {
    note.appendChild(el("span", { class: "sonar-err",
      text: "Sonar could not survey: " + ((res && res.error) || SONAR_STATE.error || "no result") }));
    return;
  }
  const lines = [
    `Interface ${res.interface} is on ${res.segment} (${res.address}).`,
    `${res.hosts_answered} host(s) answered an ARP sweep of ${res.swept} addresses; `
      + `${(res.free_addresses || []).length} free address(es) were found.`,
  ];
  if (res.gateway) {
    lines.push(`Gateway ${res.gateway}${res.gateway_mac ? " (" + res.gateway_mac + ")" : ""}`
      + ` — ${res.gateway_source}.`);
  }
  note.appendChild(el("div", { text: lines.join(" ") }));
  for (const n of (res.notes || [])) {
    note.appendChild(el("div", { class: "sonar-note-item", text: "• " + n }));
  }
  const staged = Object.keys((res.recommended) || {});
  if (staged.length) {
    note.appendChild(el("div", { class: "sonar-note-item",
      text: `Staged ${staged.length} recommendation(s) as pending changes below — review, `
        + `edit or discard them, then Apply. Nothing has been written yet.` }));
  }
}


/** The auth card: what the server said about write access, and the break-glass token path. */
async function refreshAuthNote() {
  const note = document.getElementById("st-auth-note");
  const controls = document.getElementById("st-auth-controls");
  if (!note) return;
  let data = null;
  try { data = await getJSON("/api/settings"); } catch (_e) { data = null; }
  const w = (data && data.writes) || {};
  const caller = (data && data.caller) || {};
  if (controls) controls.classList.remove("hidden");
  if (!AUTH.accounts) {
    // No accounts provisioned: the token is the whole story, as it was before accounts.
    note.textContent = w.enabled
      ? "This deployment has no accounts provisioned. Write access is enabled and this tab "
        + "holds a token. An admin account is created automatically on first startup."
      : (w.reason || "write access is not available");
    return;
  }
  if (caller.via === "token") {
    note.textContent = "This tab holds the operator token: admin rights, no account. Use a "
      + "signed-in account for day-to-day work; the token is the recovery path.";
    return;
  }
  if (AUTH.authenticated) {
    note.textContent = w.enabled
      ? `Signed in as ${AUTH.username} (${caller.role || AUTH.role}): settings below can be `
        + "changed and applied."
      : `Signed in as ${AUTH.username}: ${w.reason || "no write access"}`;
    return;
  }
  note.textContent = "Not signed in. Sign in with an admin account to change settings, or "
    + "paste the operator token below as the break-glass credential.";
}

async function loadSettings() {
  // Resolve the auth note and account card on LOAD, not only when a token button is clicked.
  // It shipped as "checking…" and stayed that way until the operator happened to click a
  // button, so the one card that says whether writes are even possible reported a state that
  // would never resolve -- the orphaned-"loading…" defect again.
  await refreshAuthNote();
  refreshAccountCard();
  const data = await getJSON("/api/settings");
  const sum = document.getElementById("st-summary");
  const win = document.getElementById("st-window");

  if (!data || data.available === false) {
    if (win) win.textContent = "";
    if (sum) sum.textContent = "Unavailable: " + ((data && data.reason) || "no data");
    for (const id of ["st-detect", "st-sensor", "st-runtime"]) {
      const n = document.getElementById(id);
      if (n) { n.replaceChildren(); n.appendChild(chartEmpty("Unavailable.")); }
    }
    return;
  }

  if (win) win.textContent = data.version ? `v${data.version}` : "";
  const groups = data.groups || {};
  const titles = data.titles || {};
  // Remember the rows so SONAR can stage recommendations through the same dedupe the
  // manual controls use (applySonarResult needs each key's CURRENT value).
  SETTINGS_ROWS = {};
  for (const rows of Object.values(groups)) {
    for (const r of rows || []) SETTINGS_ROWS[r.key] = r;
  }
  // SONAR is a write-gated action (it creates a job on the sensor node), so for a viewer
  // or a signed-out browser it is disabled with the same honesty as the other controls:
  // present and explainable, not vanished. THE TEST RUN is write-gated for the same reason
  // and one more: while it runs, the sensor is genuinely in the traffic path.
  const sonarBtn = document.getElementById("st-sonar");
  if (sonarBtn) sonarBtn.disabled = !Boolean(data.writes && data.writes.enabled);
  const testBtn = document.getElementById("st-test");
  if (testBtn) testBtn.disabled = !Boolean(data.writes && data.writes.enabled);
  const total = Object.values(groups).reduce((n, rows) => n + (rows || []).length, 0);
  if (sum) sum.textContent = `${total} settings in effect`;

  for (const key of ["detect", "sensor", "runtime"]) {
    const host = document.getElementById(`st-${key}`);
    if (!host) continue;
    host.replaceChildren();
    const rows = groups[key] || [];
    if (!rows.length) {
      host.appendChild(chartEmpty(`No ${(titles[key] || key).toLowerCase()} settings reported.`));
      continue;
    }
    const editable = new Set(data.editable_keys || []);
    // WHETHER THE CONTROLS RENDER AT ALL depends on the caller's write access, not just on
    // whether the key is editable: a viewer (or a signed-out browser) sees every value and
    // no control, which is what "read-only for viewers" means in pixels. The server still
    // enforces this on Apply -- the UI is rendering the server's answer, not deciding policy.
    const canWrite = Boolean(data.writes && data.writes.enabled);
    for (const r of rows) {
      // Provenance, so a blank is not ambiguous. "The setting does not exist" and "the setting is
      // unset" used to render identically -- three rows for non-existent fields survived review
      // that way. An env-only key is legitimate (the CLI reads it) and is labelled as such.
      const srcTag = r.source === "env" ? "env" : (r.source === "derived" ? "derived" : "");
      // A SECRET IS NEVER EDITABLE FROM HERE. It is reported as set/not-set by design, and a
      // field that let you overwrite a credential through an unauthenticated-by-default,
      // no-TLS port is a different feature with a different threat model.
      const isEditable = canWrite && editable.has(r.key) && !r.secret;
      const staged = STAGE.changes[r.key];
      const shown = staged !== undefined ? staged : String(r.value);

      const valueNode = isEditable
        ? settingControl(r, shown, (data.controls || {})[r.key])
        : el("span", {
            class: "setting-val" + (r.secret ? " secret" : ""),
            // A secret is visibly marked so the reader knows the blank is deliberate.
            text: String(r.value),
            title: r.secret
              ? "reported as set/not-set only; secrets are never editable from this page"
              : "",
          });

      // THE "?" IS ON EVERY ROW, editable or not. A value whose meaning has to be guessed is a
      // value that gets misconfigured, and the explanation is where an operator new to the
      // product learns what a setting does without reading the source.
      const help = el("div", {
        class: "setting-help hidden",
        text: r.help || "No explanation is recorded for this setting.",
      });
      const helpBtn = el("button", {
        class: "setting-help-btn", text: "?",
        attrs: { type: "button", "aria-label": `explain ${r.label}`,
                 "aria-expanded": "false", title: "what this setting does" },
        on: { click: (ev) => {
          // stopPropagation so a click on "?" can never be read as a click on the row.
          ev.stopPropagation();
          const nowHidden = help.classList.toggle("hidden");
          helpBtn.setAttribute("aria-expanded", nowHidden ? "false" : "true");
          helpBtn.classList.toggle("open", !nowHidden);
        } },
      });

      host.appendChild(el("div", {
        class: "setting" + (staged !== undefined ? " staged" : ""),
        attrs: { "data-key": r.key },
      }, [
        el("span", { class: "setting-key", title: r.key }, [
          el("span", { text: r.label }),
          srcTag ? el("span", { class: "setting-src", text: srcTag }) : null,
          isEditable ? null : el("span", { class: "setting-src", text: "read-only" }),
        ]),
        el("span", { class: "setting-ctl" }, [valueNode, helpBtn]),
        help,
      ]));
    }
    renderStage();
  }

  // State the boundary explicitly rather than leaving the reader to discover it by looking for
  // a Save button that does not exist. CONDITIONAL on the server's answer, because both states
  // are real: a viewer (or an anonymous caller) cannot write, and an admin deliberately can.
  // The unconditional "read-only" that used to sit here contradicted the auth card beside it.
  const note = document.getElementById("st-note");
  if (note) {
    const writesOn = Boolean(data.writes && data.writes.enabled);
    const viewer = AUTH.accounts && AUTH.authenticated && !writesOn;
    note.replaceChildren();
    note.appendChild(chartEmpty(writesOn
      ? "Write access is enabled: edits are staged and written only on Apply. This page is "
        + "read-only for viewer accounts; without write access, change values with "
        + "`weirvern config set`. Secrets are reported as set or not set, never in value."
      : viewer
        ? "This account is read-only: it sees every value but cannot change one. "
          + "Admin accounts can stage and apply changes; secrets are reported as set or not "
          + "set, never in value."
        : "This page is read-only. Change these with `weirvern config set`, then "
          + "apply. Secrets are reported as set or not set, never in value."));
  }
  // The Users panel is admin-only; load it here so navigating to Settings does not leave a
  // "loading…" nobody resolves -- the same orphaned-placeholder bug class.
  await loadUsers();
}

/* ── accounts: the admin Users panel ─────────────────────────────────────────
 *
 * Renders ONLY from the server's answers: the user list comes from /api/users, and every
 * action POSTs then reloads the list, so what is on screen is what the store holds. The
 * last-admin guard and the role validation live server-side; this panel surfaces the
 * refusals in the server's own words rather than duplicating the rules.
 */

let USERS_AVAILABLE = null;

async function loadUsers() {
  const card = document.getElementById("st-users-card");
  const note = document.getElementById("st-users-note");
  const body = document.querySelector("#st-users tbody");
  if (!card || !note || !body) return;
  const isAdmin = AUTH.accounts && AUTH.authenticated && AUTH.role === "admin";
  card.classList.toggle("hidden", !isAdmin);
  if (!isAdmin) return;
  let data = null;
  try { data = await getJSON("/api/users"); } catch (err) { data = { available: false, reason: err.message }; }
  USERS_AVAILABLE = !!(data && data.available);
  body.replaceChildren();
  if (!data || !data.available) {
    note.textContent = "Accounts are unavailable: " + ((data && data.reason) || "no reason given");
    return;
  }
  const users = data.users || [];
  note.textContent = `${users.length} account${users.length === 1 ? "" : "s"}. `
    + "Admins edit everything; viewers read.";
  const me = AUTH.username;
  for (const u of users) {
    const row = el("tr", {}, [
      el("td", {}, [
        el("span", { class: "mono", text: u.username }),
        u.username === me ? el("span", { class: "setting-src", text: "you" }) : null,
      ]),
      el("td", {}, [
        el("select", {
          class: "user-role",
          attrs: { "data-user": u.username, "aria-label": `role for ${u.username}` },
          on: { change: (ev) => setRole(u.username, ev.target.value) },
        }, ["viewer", "admin"].map((r) =>
          el("option", { value: r, text: r, ...(u.role === r ? { selected: true } : {}) }))),
      ]),
      el("td", { class: "muted mono", text: u.created_at || "—" }),
      el("td", {}, [
        u.must_change
          ? el("span", { class: "muted", text: "must change" })
          : el("span", { class: "muted", text: "set" }),
      ]),
      el("td", {}, [
        el("button", {
          class: "user-act", text: "Reset password", attrs: { type: "button" },
          title: `set a temporary password for ${u.username}`,
          on: { click: () => resetUserPassword(u.username) },
        }),
        u.username === me ? null : el("button", {
          class: "user-act danger", text: "Delete", attrs: { type: "button" },
          title: `delete ${u.username}`,
          on: { click: () => deleteUser(u.username) },
        }),
      ]),
    ]);
    body.appendChild(row);
  }
}

function usersResult(message, isError) {
  const out = document.getElementById("st-user-result");
  if (!out) return;
  out.textContent = message || "";
  out.style.color = isError ? "var(--danger)" : "";
}

async function setRole(username, role) {
  try {
    await postJSON("/api/users/role", { username, role });
    usersResult(`role for ${username} set to ${role}.`);
    await loadUsers();
  } catch (err) {
    usersResult(String(err.message || err), true);
    await loadUsers();
  }
}

async function deleteUser(username) {
  if (!window.confirm(`Delete the account ${username}? This cannot be undone.`)) return;
  try {
    await postJSON("/api/users/delete", { username });
    usersResult(`deleted ${username}.`);
    await loadUsers();
  } catch (err) {
    usersResult(String(err.message || err), true);
    await loadUsers();
  }
}

async function resetUserPassword(username) {
  const temp = window.prompt(
    `Temporary password for ${username} (at least 8 characters).\n\n` +
    "It is shown only in this dialog; hand it to them directly. They will be required to " +
    "change it at next sign-in.");
  if (!temp) return;
  try {
    await postJSON("/api/users/reset", { username, password: temp });
    usersResult(`temporary password set for ${username} — it must be changed at next sign-in.`);
    await loadUsers();
  } catch (err) {
    usersResult(String(err.message || err), true);
  }
}

async function createUser() {
  const nameField = document.getElementById("st-new-user");
  const roleField = document.getElementById("st-new-role");
  const passField = document.getElementById("st-new-pass");
  const username = (nameField && nameField.value || "").trim();
  const role = (roleField && roleField.value) || "viewer";
  const password = (passField && passField.value) || "";
  if (!username || !password) {
    usersResult("a username and an initial password are required.", true);
    return;
  }
  try {
    await postJSON("/api/users/create", { username, role, password, must_change: true });
    usersResult(`created ${username} (${role}). It must change its password at first sign-in.`);
    if (nameField) nameField.value = "";
    if (passField) passField.value = "";
    await loadUsers();
  } catch (err) {
    usersResult(String(err.message || err), true);
  }
}
/* ── anomalies ──────────────────────────────────────────────────────────── */

/* SOC-1: REVIEW STATE.
 *
 * Before this, the workflow ended at "here is an anomaly": no acknowledge, no resolve,
 * no false-positive, no way to clear the recurring benign alert. The analyst saw the
 * same rows forever and there was no record of what had been looked at.
 *
 * The chip renders what the SERVER says -- `review_state` merged onto every row by the
 * anomalies route -- never local state. A click posts, the list reloads, and what is on
 * screen after the reload is the server's answer. Optimistic local updates would show a
 * decision that a failed write never recorded, which is the one thing a triage tool must
 * not do.
 *
 * "unavailable" is a REAL state, not an error style: the reviews table could not be read
 * (schema job not re-run yet). It must look different from "unreviewed", because claiming
 * nothing has been reviewed when we cannot see it is the confident-empty failure this
 * codebase treats as a bug class.
 */
const REVIEW_LABELS = {
  "": "unreviewed",
  "ack": "ack",
  "resolved": "resolved",
  "false_positive": "false positive",
  "unavailable": "review unavailable",
};

/** The chip's class for a state. Static selectors in style.css; this maps the state onto them. */
function reviewClass(state) {
  if (state === "false_positive") return "review-fp";
  if (state === "unavailable") return "review-unavailable";
  if (state === "ack") return "review-ack";
  if (state === "resolved") return "review-resolved";
  return "review-none";
}

/** One review cell: the state chip, then the actions that are not the current state. */
function reviewCell(a) {
  const state = a.review_state || "";
  const wrap = el("div", {});

  wrap.appendChild(el("span", {
    class: "review-chip " + reviewClass(state),
    text: REVIEW_LABELS[state] !== undefined ? REVIEW_LABELS[state] : state,
    title: a.reviewed_at ? "reviewed " + fmtTime(a.reviewed_at) : "not reviewed yet",
  }));

  // No actions while the review store is unreadable: a write against a store we cannot
  // read would fail after the click, and offering it anyway would advertise a control
  // that cannot work.
  if (state === "unavailable") return wrap;

  wrap.appendChild(el("div", { class: "review-acts" }, [
    ...[["ack", "ack"], ["resolved", "resolve"], ["false_positive", "FP"]]
      .filter(([st]) => st !== state)
      .map(([st, label]) => el("button", {
        class: "review-act", text: label, attrs: { type: "button" },
        title: `mark this anomaly as ${st.replace("_", " ")}`,
        on: { click: (e) => { e.stopPropagation(); postReview(a, st); } },
      })),
    state
      ? el("button", {
          class: "review-act", text: "clear", attrs: { type: "button" },
          title: "back to unreviewed",
          on: { click: (e) => { e.stopPropagation(); postReview(a, ""); } },
        })
      : null,
  ]));
  return wrap;
}

/** Post a disposition and re-render from the server's answer. Failures surface, never pass. */
async function postReview(a, state) {
  try {
    await postJSON(API.review, {
      window_start: a.window_start, src_addr: a.src_addr, state,
    });
  } catch (err) {
    // A refused write states the server's reason (missing token, unknown state, database
    // down). Rendering it beats a chip that silently did not change.
    showError(err);
    return;
  }
  await loadAnomalies();
}

async function loadAnomalies() {
  const min = document.getElementById("f-min-score").value || "0";
  const limit = document.getElementById("f-limit").value || "100";
  const unrev = document.getElementById("f-unreviewed");
  const unreviewedOnly = !!(unrev && unrev.checked);
  const rows = await getJSON(API.anomalies(min, limit, unreviewedOnly));

  const tbody = document.querySelector("#anomalies-table tbody");
  tbody.replaceChildren();
  if (!rows.length) {
    const note = unreviewedOnly
      ? (Number(min) > 0
          ? `No unreviewed anomalies at or above score ${min}.`
          : "No unreviewed anomalies — everything has been triaged.")
      : (Number(min) > 0
          ? `No anomalies at or above score ${min}.`
          : "No anomalies recorded yet.");
    emptyRow(tbody, 8, note);
    return;
  }
  for (const a of rows) {
    const contrib = a.feature_contributions || {};
    const contributing = Object.entries(contrib)
      .sort((x, y) => Math.abs(y[1].z) - Math.abs(x[1].z))
      .slice(0, 3)
      .map(([name, d]) => `${name} z=${d.z}`)
      .join(", ");
    tbody.appendChild(el("tr", { class: "clickable",
                                 attrs: { title: "Show the raw evidence for this alert" },
                                 on: { click: () => openEvidence(a) } }, [
      el("td", { class: "mono", text: fmtTime(a.detected_at) }),
      el("td", { class: "mono", text: fmtTime(a.window_start) }),
      el("td", {}, [hostCell(a.src_addr, a.hostname)]),
      el("td", { class: "mono", text: (a.anomaly_score ?? 0).toFixed(3) }),
      el("td", {}, [sevCell(a.severity)]),
      el("td", { class: "mono", text: a.detected_by_models || "—" }),
      el("td", {}, [
        el("div", { text: a.baseline_comparison || "—" }),
        contributing ? el("div", { class: "muted mono", text: contributing }) : null,
      ]),
      el("td", {}, [reviewCell(a)]),
    ]));
  }
}

/* ── host drill-down ────────────────────────────────────────────────────── */

async function loadHost(addr, hours) {
  const d = await getJSON(API.host(addr, hours));

  document.getElementById("h-results").classList.remove("hidden");
  document.getElementById("h-title").replaceChildren(
    el("span", { text: "Host " }),
    el("span", { class: "mono", text: d.hostname ? `${d.hostname} (${d.src_addr})` : d.src_addr }),
  );

  const stats = document.getElementById("h-stats");
  stats.replaceChildren();
  // SAY WHY WHEN THE QUERY FAILED. A failed sub-query and a host that sent nothing used to
  // produce the identical "No flows" line, so a broken query was indistinguishable from a quiet
  // host -- on the view an analyst opens to answer "did this host do anything". The evidence view
  // already routes its failures through showDataError; this is the same treatment.
  showDataError(d.errors ? Object.entries(d.errors).map(([k, v]) => `${k}: ${v}`).join(" | ") : null);
  const t = d.totals;
  if (!t) {
    stats.appendChild(el("p", { class: "empty",
      text: d.errors
        ? "Host totals could not be read — see the message above."
        : `No flows from ${d.src_addr} in the last ${d.hours}h.` }));
  } else {
    const items = [
      ["bytes", fmtBytes(t.bytes)], ["packets", String(t.packets ?? "—")],
      ["flows", String(t.flows ?? "—")], ["destinations", String(t.unique_destinations ?? "—")],
      ["dest ports", String(t.unique_ports ?? "—")], ["last seen", fmtTime(t.last_seen)],
    ];
    for (const [k, v] of items) {
      stats.appendChild(el("div", { class: "stat" }, [
        el("div", { class: "v", text: v }), el("div", { class: "k", text: k }),
      ]));
    }
  }

  // Sparkline: bar height is proportional to the max bucket, with a visible stub
  // for zero so a gap reads as "no traffic" rather than as a missing element.
  const spark = document.getElementById("h-spark");
  spark.replaceChildren();
  const max = Math.max(1, ...d.timeline.map((b) => Number(b.bytes) || 0));
  for (const b of d.timeline) {
    const bytes = Number(b.bytes) || 0;
    const pct = bytes === 0 ? 0 : Math.max(4, Math.round((bytes / max) * 100));
    spark.appendChild(el("div", {
      class: "bar" + (bytes === 0 ? " zero" : ""),
      attrs: { style: `height:${bytes === 0 ? 2 : pct}%` },
      title: `${fmtTime(b.hour)} — ${fmtBytes(bytes)} / ${b.flows} flows`,
      "data-label": `${fmtTime(b.hour)} · ${fmtBytes(bytes)}`,
    }));
  }
  if (!d.timeline.length) {
    spark.appendChild(el("p", { class: "empty", text: "No timeline data." }));
  }

  const dests = document.querySelector("#h-dests tbody");
  dests.replaceChildren();
  if (!d.top_destinations.length) emptyRow(dests, 4, "No destinations recorded.");
  for (const x of d.top_destinations) {
    dests.appendChild(el("tr", {}, [
      el("td", {}, [hostCell(x.dst_addr, x.hostname, d.src_addr)]),
      el("td", { class: "mono", text: fmtBytes(x.bytes) }),
      el("td", { class: "mono", text: String(x.flows ?? "—") }),
      el("td", { class: "mono", text: String(x.ports ?? "—") }),
    ]));
  }

  const ports = document.querySelector("#h-ports tbody");
  ports.replaceChildren();
  if (!d.top_ports.length) emptyRow(ports, 4, "No ports recorded.");
  for (const x of d.top_ports) {
    ports.appendChild(el("tr", {}, [
      el("td", { class: "mono", text: String(x.dst_port) }),
      el("td", { class: "mono", text: String(x.proto) }),
      el("td", { class: "mono", text: fmtBytes(x.bytes) }),
      el("td", { class: "mono", text: String(x.flows ?? "—") }),
    ]));
  }

  const zeek = document.querySelector("#h-zeek tbody");
  zeek.replaceChildren();
  if (!d.zeek_services.length) {
    // Not an error: the packet sensor may simply not be enabled here.
    emptyRow(zeek, 3, "No Zeek service data (sensor disabled, or no connections seen).");
  } else {
    for (const s of d.zeek_services) {
      zeek.appendChild(el("tr", {}, [
        el("td", { text: s.service }),
        el("td", { class: "mono", text: String(s.conns ?? "—") }),
        el("td", { class: "mono", text: fmtBytes(s.bytes) }),
      ]));
    }
  }

  const anoms = document.querySelector("#h-anoms tbody");
  anoms.replaceChildren();
  if (!d.anomalies.length) {
    emptyRow(anoms, 5, `No anomalies for this host in the last ${d.hours}h.`);
  }
  for (const a of d.anomalies) {
    anoms.appendChild(el("tr", {}, [
      el("td", { class: "mono", text: fmtTime(a.detected_at) }),
      el("td", { class: "mono", text: (a.anomaly_score ?? 0).toFixed(3) }),
      el("td", {}, [sevCell(a.severity)]),
      el("td", { class: "mono", text: a.detected_by_models || "—" }),
      el("td", { text: a.baseline_comparison || a.primary_deviation_feature || "—" }),
    ]));
  }
}

function openHost(addr) {
  if (!addr) return;
  showView("host");
  document.getElementById("h-addr").value = addr;
  document.getElementById("h-hours").value = "24";
  loadHost(addr, 24).catch(showError);
}

/* ── alert evidence (the pivot) ─────────────────────────────────────────── */

/* Show the RAW records inside one alert's detection window. This is the answer to
 * "why did the model flag this" that the aggregate host view cannot give: the host
 * view says what the host has done over 24h; this says what it did in the five
 * minutes the detector scored, which is the only thing that verdict is about. */
function openEvidence(a) {
  if (!a || !a.src_addr) return;
  showView("evidence");
  const start = a.window_start || a.detected_at;
  loadEvidence(a.src_addr, start, a.window_end).catch(showError);
}

async function loadEvidence(addr, start, end) {
  const d = await getJSON(API.evidence(addr, start, end));
  showDataError(d.errors ? Object.entries(d.errors).map(([k, v]) => `${k}: ${v}`).join(" | ") : null);

  document.getElementById("ev-title").textContent =
    d.hostname ? `${d.hostname} (${d.src_addr})` : d.src_addr;
  document.getElementById("ev-sub").textContent =
    `Detection window ${fmtTime(d.window_start)} → ${fmtTime(d.window_end)}. ` +
    `These are the individual records the detector scored — not aggregates.`;

  // The verdict, so the evidence is read in context rather than cold.
  const verdict = document.getElementById("ev-verdict");
  verdict.replaceChildren();
  if (d.anomaly) {
    verdict.appendChild(el("p", { class: "muted" }, [
      el("span", {}, [sevCell(d.anomaly.severity)]),
      el("span", { text: `  score ${(d.anomaly.anomaly_score ?? 0).toFixed(3)}` }),
      el("span", { text: `  · models: ${d.anomaly.detected_by_models || "—"}` }),
    ]));
    if (d.anomaly.baseline_comparison) {
      verdict.appendChild(el("p", { text: d.anomaly.baseline_comparison }));
    }
    // ── ATT&CK techniques ────────────────────────────────────────────────────
    //
    // Rendered with the evidence and the confidence, never as a bare ID. "T1046" alone
    // reads as a finding; "consistent with T1046 (high) -- 300 distinct destination ports
    // (threshold 100)" can be checked, argued with, and dismissed. Only the second is
    // usable, and only the second is honest.
    //
    // NOTHING is rendered when no technique matched. An empty frame or an explicit "no
    // technique" line would read as a clearance, and absence of a mapping is not that.
    const techs = parseTechniques(d.anomaly.attack_techniques);
    if (techs.length) {
      const box = el("div", { class: "attack" }, [
        el("div", { class: "muted", text: "MITRE ATT&CK — hypotheses supported by these measurements" }),
      ]);
      for (const t of techs) {
        box.appendChild(el("div", { class: "attack-row" }, [
          el("span", { class: "mono attack-id", text: t.id }),
          el("span", { text: t.name }),
          el("span", { class: "attack-meta", text: `${t.tactic} · ${t.confidence} confidence` }),
        ]));
        if (t.evidence && t.evidence.length) {
          box.appendChild(el("ul", { class: "attack-evidence" },
            t.evidence.map((e) => el("li", { class: "muted", text: e }))));
        }
        if (t.network_visibility) {
          box.appendChild(el("div", {
            class: "muted attack-vis",
            text: `network visibility: ${t.network_visibility}`,
            }));
          }
        }
        verdict.appendChild(box);
      }
    }

    const s = d.flow_summary;
  const stats = document.getElementById("ev-stats");
  stats.replaceChildren();
  if (s) {
    const cells = [
      ["bytes", fmtBytes(s.bytes)],
      ["packets", String(s.packets ?? "—")],
      ["flows", String(s.flows ?? "—")],
      ["destinations", String(s.unique_destinations ?? "—")],
      ["ports", String(s.unique_ports ?? "—")],
    ];
    for (const [k, v] of cells) {
      stats.appendChild(el("div", { class: "stat" }, [
        el("div", { class: "v", text: v }), el("div", { class: "k", text: k }),
      ]));
    }
  }

  const fl = document.querySelector("#ev-flows tbody");
  fl.replaceChildren();
  if (!d.flows.length) {
    emptyRow(fl, 7, "No flows recorded in this window.");
  } else {
    for (const f of d.flows) {
      fl.appendChild(el("tr", {}, [
        el("td", { class: "mono", text: fmtTime(f.time_flow_start) }),
        el("td", {}, [hostCell(f.dst_addr, f.hostname, d.src_addr)]),
        el("td", { class: "mono", text: String(f.dst_port ?? "—") }),
        el("td", { class: "mono", text: String(f.proto ?? "—") }),
        el("td", { class: "mono", text: fmtBytes(f.bytes) }),
        el("td", { class: "mono", text: String(f.packets ?? "—") }),
        el("td", { class: "mono", text: String(f.duration_ms ?? "—") }),
      ]));
    }
  }

  const zk = document.querySelector("#ev-zeek tbody");
  zk.replaceChildren();
  if (!d.zeek_conn.length) {
    emptyRow(zk, 4, "No Zeek sessions in this window.");
  } else {
    for (const z of d.zeek_conn) {
      zk.appendChild(el("tr", {}, [
        el("td", { class: "mono", text: fmtTime(z.ts) }),
        el("td", {}, [hostCell(z.dst_addr, z.hostname, d.src_addr)]),
        el("td", { text: z.service || z.dst_port || "—" }),
        el("td", { class: "mono", text: fmtBytes((z.orig_bytes ?? 0) + (z.resp_bytes ?? 0)) }),
      ]));
    }
  }

  const dn = document.querySelector("#ev-dns tbody");
  dn.replaceChildren();
  if (!d.zeek_dns.length) {
    emptyRow(dn, 3, "No DNS queries in this window.");
  } else {
    for (const q of d.zeek_dns) {
      dn.appendChild(el("tr", {}, [
        el("td", { class: "mono", text: fmtTime(q.ts) }),
        el("td", { class: "mono", text: q.query || "—" }),
        el("td", { class: "mono", text: String(q.qtype ?? "—") }),
      ]));
    }
  }

  const nt = document.querySelector("#ev-notice tbody");
  nt.replaceChildren();
  if (!d.notice.length) {
    emptyRow(nt, 3, "No Zeek notices for this host in this window.");
  } else {
    for (const n of d.notice) {
      nt.appendChild(el("tr", {}, [
        el("td", { class: "mono", text: fmtTime(n.ts) }),
        el("td", { text: n.note || "—" }),
        el("td", { text: n.msg || "—" }),
      ]));
    }
  }
}

/* ── plumbing ───────────────────────────────────────────────────────────── */

function showError(err) {
  const msg = err && err.message ? err.message : String(err);
  const existing = document.getElementById("err-banner");
  if (existing) { existing.textContent = "Could not load data: " + msg; return; }
  document.querySelector("main").prepend(el("div", {
    class: "banner", attrs: { id: "err-banner" },
    text: "Could not load data: " + msg,
  }));
}

/* A data error reported by the API itself, as opposed to a transport failure.
 * Without this the page renders every panel empty and looks like a deployment with
 * no traffic, which is how an earlier bug hid: the in-cluster server was failing to
 * reach ClickHouse and said so only at debug level. */
function showDataError(msg) {
  const id = "data-banner";
  const existing = document.getElementById(id);
  if (!msg) { if (existing) existing.remove(); return; }
  if (existing) { existing.textContent = "Data unavailable: " + msg; return; }
  document.querySelector("main").prepend(el("div", {
    class: "banner", attrs: { id },
    text: "Data unavailable: " + msg,
  }));
}
function clearError() {
  // BOTH banners, not just one. showError() creates #err-banner and showDataError() creates
  // #data-banner, but this only removed the first -- so a data error stayed pinned to the top of
  // the page after the operator moved to another view, describing a tab they had left. Either id
  // may or may not exist, hence the loop rather than two lookups.
  for (const id of ["err-banner", "data-banner"]) {
    const b = document.getElementById(id);
    if (b) b.remove();
  }
}

function showView(name) {
  for (const t of document.querySelectorAll(".tab")) {
    t.classList.toggle("active", t.dataset.view === name);
  }
  for (const v of document.querySelectorAll(".view")) {
    v.classList.toggle("active", v.id === "view-" + name);
  }
  if (name === "anomalies") loadAnomalies().then(clearError).catch(showError);
  if (name === "models") loadModels().then(clearError).catch(showError);
  if (name === "settings") loadSettings().then(clearError).catch(showError);
  // The Assets inventory loads on demand for the same reason the SOC views do: it runs a
  // query per Zeek host table, and firing that every 15s in the background would put load on
  // ClickHouse for a panel nobody is looking at.
  if (name === "host") loadAssets().then(clearError).catch(showError);
  if (name === "network") loadNetwork().then(clearError).catch(showError);
  // The SOC views load on demand rather than on every refresh cycle: they run several
  // aggregate queries each, and firing them every 15s in the background would put load on
  // ClickHouse for panels nobody is looking at.
  if (name === "netflow") loadNetflow().then(clearError).catch(showError);
  if (name === "zeek") loadZeek().then(clearError).catch(showError);
  if (name === "health") loadHealthDeep().then(clearError).catch(showError);
}

async function refreshAll() {
  // HEALTH, not Overview: the Overview tab is gone and Health is the landing view. Auto-refresh
  // follows whatever is on screen rather than refreshing a view nobody is looking at.
  try {
    await loadHealthDeep();
    clearError();
  } catch (err) {
    showError(err);
  }
}

function startAuto(seconds) {
  if (timer) clearInterval(timer);
  timer = setInterval(refreshAll, seconds * 1000);
}

document.addEventListener("DOMContentLoaded", () => {
  for (const t of document.querySelectorAll(".tab")) {
    t.addEventListener("click", () => showView(t.dataset.view));
  }
  document.getElementById("refresh").addEventListener("click", refreshAll);
  // Onchange rather than a Reload click for a <select>: an operator who picks 24h and
  // then has to press a button has been given a two-step control for a one-step intent.
  const mHours = document.getElementById("m-hours");
  if (mHours) mHours.addEventListener("change", () => loadModels().then(clearError).catch(showError));
  const mReload = document.getElementById("m-reload");
  if (mReload) mReload.addEventListener("click", () => loadModels().then(clearError).catch(showError));
  document.getElementById("autorefresh").addEventListener("change", (e) => {
    if (e.target.checked) startAuto(15); else if (timer) clearInterval(timer);
  });
  document.getElementById("h-go").addEventListener("click", () => {
    const a = document.getElementById("h-addr").value.trim();
    const h = document.getElementById("h-hours").value || "24";
    if (a) loadHost(a, h).then(clearError).catch(showError);
  });
  document.getElementById("h-addr").addEventListener("keydown", (e) => {
    if (e.key === "Enter") document.getElementById("h-go").click();
  });
  for (const id of ["f-min-score", "f-limit", "f-unreviewed"]) {
    document.getElementById(id).addEventListener("change", () => {
      loadAnomalies().then(clearError).catch(showError);
    });
  }
  // SOC view controls. Each reload is explicit rather than automatic for the reason given
  // in showView: these run aggregate queries and should not fire on a background timer.
  for (const [id, fn] of [
    ["nf-reload", loadNetflow], ["zk-reload", loadZeek], ["hp-reload", loadHealthDeep],
    ["st-reload", loadSettings],
    // The token controls. `Use token` stores it and re-reads the page so the server's answer about
    // write access is what updates the UI -- the browser never assumes it succeeded.
    ["st-token-save", async () => {
      const field = document.getElementById("st-token");
      setToken(field ? field.value.trim() : "");
      if (field) field.value = "";
      await refreshAuthNote();
      await loadSettings();
    }],
    ["st-token-clear", async () => {
      setToken("");
      await refreshAuthNote();
      await loadSettings();
    }],
    ["st-stage-apply", () => applyStage().catch(showError)],
    ["st-stage-discard", () => discardStage()],
    // SONAR: the survey button. Disabled for callers without write access (loadSettings
    // sets that from the server's answer) -- a viewer sees it with its help text, which
    // teaches what it does; it is not hidden.
    ["st-sonar", () => runSonar().catch(showError)],
    // The Sonar "?" opens its explanation, the same interaction the setting rows use.
    // Async because the shared wiring loop chains `.then()` on every handler's return.
    ["st-sonar-help", async () => {
      const helpEl = document.getElementById("st-sonar-help-text");
      const btn = document.getElementById("st-sonar-help");
      if (!helpEl) return;
      const nowHidden = helpEl.classList.toggle("hidden");
      if (btn) {
        btn.setAttribute("aria-expanded", nowHidden ? "false" : "true");
        btn.classList.toggle("open", !nowHidden);
      }
    }],
    // THE TEST RUN: probe siphon for 30s, then the server reverts to loch. Write-gated
    // (disabled for viewers the same way the other controls are), because it briefly
    // puts the sensor in the traffic path.
    ["st-test", () => runSiphonTest().catch(showError)],
    ["st-test-help", async () => {
      const helpEl = document.getElementById("st-test-help-text");
      const btn = document.getElementById("st-test-help");
      if (!helpEl) return;
      const nowHidden = helpEl.classList.toggle("hidden");
      if (btn) {
        btn.setAttribute("aria-expanded", nowHidden ? "false" : "true");
        btn.classList.toggle("open", !nowHidden);
      }
    }],
  ]) {
    const b = document.getElementById(id);
    if (b) b.addEventListener("click", () => fn().then(clearError).catch(showError));
  }
  for (const [id, fn] of [
    ["nf-hours", loadNetflow], ["zk-hours", loadZeek], ["hp-hours", loadHealthDeep],
  ]) {
    const i = document.getElementById(id);
    // onchange rather than a button: picking 24h and then pressing Reload is a two-step
    // control for a one-step intent, which the Models view already settled for this codebase.
    if (i) i.addEventListener("change", () => fn().then(clearError).catch(showError));
  }

  // ── Assets inventory controls ──────────────────────────────────────────────
  // The search filters the CACHED payload rather than refetching: a ClickHouse aggregate
  // behind every keystroke makes typing laggy on a busy segment, and the inventory for one
  // window does not change between keystrokes.
  const asSearch = document.getElementById("as-search");
  if (asSearch) asSearch.addEventListener("input", (e) => {
    ASSETS_STATE.search = e.target.value;
    // Back to page 1: filtering 245 hosts down to 3 while sitting on page 12 would show an
    // empty table, which reads as "no matches" rather than "you are past the end".
    ASSETS_STATE.page = 1;
    renderAssets();
  });
  const asSort = document.getElementById("as-sort");
  if (asSort) asSort.addEventListener("change", (e) => {
    ASSETS_STATE.sort = e.target.value;
    // Reordering moves every row, so holding the page number would show a different set of
    // hosts than the one the reader was looking at.
    ASSETS_STATE.page = 1;
    renderAssets();
  });
  const asHours = document.getElementById("as-hours");
  if (asHours) asHours.addEventListener("change", (e) => {
    ASSETS_STATE.hours = Number(e.target.value) || 24;
    ASSETS_STATE.page = 1;
    loadAssets().then(clearError).catch(showError);
  });
  const asReload = document.getElementById("as-reload");
  if (asReload) asReload.addEventListener("click", () => loadAssets().then(clearError).catch(showError));

  // ── Network graph controls ─────────────────────────────────────────────────
  const nwHours = document.getElementById("nw-hours");
  if (nwHours) nwHours.addEventListener("change", (e) => {
    ASSETS_STATE.hours = Number(e.target.value) || 24;
    loadNetwork().then(clearError).catch(showError);
  });
  const nwReload = document.getElementById("nw-reload");
  if (nwReload) nwReload.addEventListener("click", () => loadNetwork().then(clearError).catch(showError));
  const nwClear = document.getElementById("nw-clear");
  if (nwClear) nwClear.addEventListener("click", () => {
    ASSETS_STATE.tracked = [];
    loadNetwork().then(clearError).catch(showError);
  });
  // The edge filter re-renders from the cached payload; it is a view control, not a query.
  const nwMin = document.getElementById("nw-min");
  if (nwMin) nwMin.addEventListener("input", (e) => {
    ASSETS_STATE.minEdges = Number(e.target.value) || 1;
    renderNetwork();
  });
  const nwLabels = document.getElementById("nw-labels");
  if (nwLabels) nwLabels.addEventListener("change", (e) => {
    ASSETS_STATE.showNames = e.target.checked;
    renderNetwork();
  });

  // ── accounts: the gates and their forms ────────────────────────────────────
  const gateForm = document.getElementById("gate-form");
  if (gateForm) gateForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = document.getElementById("gate-error");
    const user = (document.getElementById("gate-user") || {}).value || "";
    const pass = (document.getElementById("gate-pass") || {}).value || "";
    if (err) err.textContent = "";
    try {
      await doLogin(user.trim(), pass);
      await bootAuthed();
    } catch (e) {
      // The server's own words, never a client-side guess about which half was wrong.
      if (err) err.textContent = String(e.message || e);
      const pf = document.getElementById("gate-pass");
      if (pf) { pf.value = ""; pf.focus(); }
    }
  });

  const pwForm = document.getElementById("pw-form");
  if (pwForm) pwForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = document.getElementById("pw-error");
    const cur = (document.getElementById("pw-current") || {}).value || "";
    const next = (document.getElementById("pw-new") || {}).value || "";
    const confirm = (document.getElementById("pw-confirm") || {}).value || "";
    if (err) err.textContent = "";
    if (next !== confirm) { if (err) err.textContent = "the new passwords do not match"; return; }
    try {
      await changePassword(cur, next);
    } catch (e) {
      if (err) err.textContent = String(e.message || e);
    }
  });

  const signOut = document.getElementById("sign-out");
  if (signOut) signOut.addEventListener("click", () => doLogout().catch(showError));

  // ── the break-glass door on the sign-in gate ────────────────────────────────
  // The operator token recovers a lost admin password, and its input must be reachable
  // BEFORE signing in -- the Settings-tab control only helps someone already inside.
  const gateTokenToggle = document.getElementById("gate-token-toggle");
  if (gateTokenToggle) gateTokenToggle.addEventListener("click", () => {
    const block = document.getElementById("gate-token-block");
    if (block) block.classList.toggle("hidden");
    const field = document.getElementById("gate-token");
    if (field && block && !block.classList.contains("hidden")) field.focus();
  });
  const gateTokenForm = document.getElementById("gate-token-form");
  if (gateTokenForm) gateTokenForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = document.getElementById("gate-token-error");
    if (err) err.textContent = "";
    const field = document.getElementById("gate-token");
    setToken(field ? field.value.trim() : "");
    if (field) field.value = "";
    // Let the SERVER decide whether the token works: re-read the session and boot from its
    // answer. A wrong token simply leaves the gate up (the next read refuses), so nothing
    // here claims success on the browser's behalf.
    try {
      await loadSession();
      if (AUTH.authenticated) {
        await bootAuthed();
      } else if (err) {
        err.textContent = "that token is not accepted by this deployment";
      }
    } catch (e) {
      if (err) err.textContent = String(e.message || e);
    }
  });

  const pwSave = document.getElementById("st-pw-save");
  if (pwSave) pwSave.addEventListener("click", async () => {
    const out = document.getElementById("st-pw-result");
    const cur = (document.getElementById("st-pw-current") || {}).value || "";
    const next = (document.getElementById("st-pw-new") || {}).value || "";
    if (out) out.textContent = "";
    try {
      const res = await changePassword(cur, next);
      if (out) out.textContent = res.note || "password changed";
    } catch (e) {
      if (out) out.textContent = String(e.message || e);
    }
  });

  const userCreate = document.getElementById("st-user-create");
  if (userCreate) userCreate.addEventListener("click", () => createUser());

  // THE BOOT SEQUENCE. The gate is resolved BEFORE anything loads a dashboard panel: a read
  // against the wrong identity would render an empty page that looks like a quiet network --
  // the exact confusion the empty-vs-unavailable rule exists to prevent. When accounts are not
  // provisioned this falls straight through, which is the pre-accounts posture.
  boot().catch((err) => { showError(err); });
});

/** Sign in / gate resolution at page load. Renders the right gate or boots the dashboard. */
async function boot() {
  try {
    await loadSession();
  } catch (_e) {
    // /api/session failed at the transport level. Boot anyway: the dashboard will surface the
    // real error, and a deployment without accounts is a supported state.
  }
  refreshChrome();
  if (!AUTH.accounts || AUTH.authenticated) return bootAuthed();
  showGate("auth", AUTH.note || "Sign in to view this dashboard.");
}

/** What runs once there is (or may be) a usable identity: the pre-accounts posture or a
 *  signed-in account, with the forced-change gate in between. */
async function bootAuthed() {
  refreshChrome();
  refreshAccountCard();
  if (AUTH.authenticated && AUTH.must_change) {
    showGate("pw");
    return;
  }
  showGate("");
  refreshAll();
  startAuto(15);
}

/* ── models ───────────────────────────────────────────────────────────────────
 *
 * Charts are hand-rolled SVG. The GUI is deliberately dependency-free (Python stdlib
 * server, no bundler, no CDN) because it has to work on an isolated sensor network --
 * a charting library fetched from the internet is a chart that does not render in the
 * environment this is built for.
 *
 * EVERY PANEL HANDLES EMPTINESS EXPLICITLY. This was built against a deployment with
 * three anomalies: a scatter of three points looks like a rendering bug, and an empty
 * box teaches the analyst nothing. So each panel either draws real data or states in
 * words what is absent and why. Nothing is padded or interpolated to look fuller.
 */

const MODEL_COLORS = {
  "Isolation Forest": "#4ea1ff",
  "Gradient Boosting": "#5ec26a",
  "DBSCAN": "#e0a34a",
  "Adaptive Baseline": "#c07ad6",
  "Ensemble": "#e05c5c",
};

/** A placeholder that says what is missing rather than rendering an empty box. */
function chartEmpty(text) {
  return el("p", { class: "muted chart-empty", text });
}

/** An SVG canvas with a padded drawing area. Returns {svg, plot, x, y} helpers. */
function chartFrame(w, h, pad) {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.setAttribute("class", "svg-chart");
  svg.setAttribute("preserveAspectRatio", "none");
  const plot = { l: pad.l, r: w - pad.r, t: pad.t, b: h - pad.b };
  return { svg, plot, w, h };
}

function svgEl(tag, attrs, text) {
  const n = document.createElementNS("http://www.w3.org/2000/svg", tag);
  for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, String(v));
  if (text !== undefined) n.textContent = String(text);
  return n;
}

/** A horizontal axis label, positioned in the plot area. */
function axisLabel(g, x, y, text, anchor = "middle") {
  g.appendChild(svgEl("text", { x, y, "text-anchor": anchor, class: "axis-label" }, text));
}

/**
 * Training history: samples per retrain, one line per detector.
 *
 * Sample counts on one axis with a log-ish scale, because Isolation Forest spans 360 ->
 * 9496 and a linear axis would flatten every other detector onto the floor.
 */
/** Per-detector freshness: when each last retrained, and whether that is overdue.
 *
 * WHY THIS PANEL EXISTS. The training-history chart below plots RUN COUNT, so a detector that
 * retrained 16 hours ago on a 6-hour cadence drew as a healthy line with plenty of points --
 * visually identical to one retrained a minute ago. Staleness was invisible until this table
 * was added, and it is the question an operator actually has: "are these models still current?"
 *
 * The server computes `stale` so every consumer cannot disagree, and the words here state
 * the remedy rather than only the verdict.
 */
function renderStaleness(rows, intervalH) {
  const body = document.querySelector("#m-stale tbody");
  const note = document.getElementById("m-stale-note");
  const win = document.getElementById("m-stale-window");
  if (!body) return;
  body.replaceChildren();
  if (note) note.replaceChildren();
  if (win) win.textContent = intervalH ? `retrain interval ${intervalH}h` : "";

  if (!rows.length) {
    body.appendChild(el("tr", {}, [
      el("td", { class: "muted", attrs: { colspan: "4" },
                 text: "No detector has recorded a training run yet." }),
    ]));
    return;
  }

  const overdue = rows.filter((r) => r.stale);
  for (const r of rows) {
    const age = r.never_trained
      ? el("span", { class: "muted", text: "never" })
      : el("span", { class: "mono", text: `${Number(r.age_h).toFixed(1)}h` });
    body.appendChild(el("tr", { class: r.stale ? "stale-row" : "" }, [
      el("td", { text: r.model }),
      el("td", { class: "mono muted", text: r.last_trained ? fmtTime(r.last_trained) : "—" }),
      el("td", {}, [age]),
      el("td", {}, [
        r.never_trained
          ? el("span", { class: "sev-medium", text: "never trained" })
          : r.stale
            ? el("span", { class: "sev-high", text: "overdue" })
            : el("span", { class: "sev-low", text: "current" }),
      ]),
    ]));
  }

  if (note && overdue.length) {
    const never = overdue.filter((r) => r.never_trained).map((r) => r.model);
    const old = overdue.filter((r) => !r.never_trained);
    const bits = [];
    if (old.length) {
      bits.push(`${old.map((r) => r.model).join(", ")} last retrained more than ` +
        `${intervalH}h ago — they are scoring against an older traffic mix.`);
    }
    if (never.length) {
      bits.push(`${never.join(", ")} have never trained, so their scores are absent or ` +
        `imputed rather than measured.`);
    }
    note.appendChild(chartEmpty(bits.join(" ")));
  }
}

function renderTrainingHistory(hist) {
  const host = document.getElementById("m-history");
  const legend = document.getElementById("m-history-legend");
  host.innerHTML = "";
  legend.innerHTML = "";

  const series = Object.entries(hist || {}).filter(([, pts]) => pts && pts.length);
  if (!series.length) {
    host.appendChild(chartEmpty("No training runs in this window."));
    return;
  }

  const W = 900, H = 240, PAD = { l: 64, r: 16, t: 12, b: 34 };
  const { svg, plot } = chartFrame(W, H, PAD);

  // A shared time axis across every detector.
  const allT = series.flatMap(([, pts]) => pts.map((p) => new Date(p.t).getTime()));
  const tMin = Math.min(...allT), tMax = Math.max(...allT);
  const span = Math.max(1, tMax - tMin);

  const maxN = Math.max(...series.flatMap(([, pts]) => pts.map((p) => p.n)));
  // log scale so a 26x range stays readable
  const yOf = (n) => {
    const lv = Math.log10(Math.max(1, n));
    const lmax = Math.log10(Math.max(10, maxN));
    return plot.b - (lv / lmax) * (plot.b - plot.t);
  };
  const xOf = (t) => plot.l + ((t - tMin) / span) * (plot.r - plot.l);

  // gridlines at decades
  const lmax = Math.log10(Math.max(10, maxN));
  for (let d = 0; d <= Math.floor(lmax); d++) {
    const v = Math.pow(10, d);
    const y = plot.b - (d / lmax) * (plot.b - plot.t);
    svg.appendChild(svgEl("line", { x1: plot.l, y1: y, x2: plot.r, y2: y, class: "grid" }));
    axisLabel(svg, plot.l - 6, y + 4, v >= 1000 ? (v / 1000) + "k" : String(v), "end");
  }
  svg.appendChild(svgEl("line", { x1: plot.l, y1: plot.b, x2: plot.r, y2: plot.b, class: "axis" }));
  svg.appendChild(svgEl("line", { x1: plot.l, y1: plot.t, x2: plot.l, y2: plot.b, class: "axis" }));
  axisLabel(svg, plot.l, H - 10, fmtTime(new Date(tMin)), "start");
  axisLabel(svg, plot.r, H - 10, fmtTime(new Date(tMax)), "end");

  for (const [name, pts] of series) {
    const colour = MODEL_COLORS[name] || "#888";
    const d = pts.map((p, i) => `${i ? "L" : "M"}${xOf(new Date(p.t).getTime()).toFixed(1)},${yOf(p.n).toFixed(1)}`).join(" ");
    svg.appendChild(svgEl("path", { d, fill: "none", stroke: colour, "stroke-width": 1.8 }));
    // Last point marked and labelled: the current state is the useful figure.
    const last = pts[pts.length - 1];
    svg.appendChild(svgEl("circle", {
      cx: xOf(new Date(last.t).getTime()), cy: yOf(last.n), r: 2.6, fill: colour,
    }));
    legend.appendChild(el("span", { class: "legend-item" }, [
      el("span", { class: "legend-swatch", attrs: { style: `background:${colour}` } }),
      el("span", { text: `${name} — last ${last.n} samples, ${pts.length} run(s)` }),
    ]));
  }
  host.appendChild(svg);
}

/**
 * Score distribution: how many anomalies fall in each 0.1 band, per detector.
 *
 * Shows where the threshold sits relative to the data. Bands are drawn from real counts
 * only; if everything falls in one band, that is what is shown.
 */
function renderScoreDistribution(scores) {
  const host = document.getElementById("m-scores");
  host.innerHTML = "";
  const names = Object.keys(scores || {});
  if (!names.length) { host.appendChild(chartEmpty("No scores recorded.")); return; }
  const total = names.reduce((a, n) => a + (scores[n] || []).length, 0);
  if (!total) { host.appendChild(chartEmpty("No anomalies in this window.")); return; }

  const BANDS = 10;
  const counts = {};
  for (const n of names) {
    counts[n] = new Array(BANDS).fill(0);
    for (const v of scores[n] || []) {
      const b = Math.min(BANDS - 1, Math.max(0, Math.floor((Number(v) || 0) * BANDS)));
      counts[n][b] += 1;
    }
  }
  const max = Math.max(1, ...names.flatMap((n) => counts[n]));
  const W = 440, H = 200, PAD = { l: 34, r: 10, t: 10, b: 30 };
  const { svg, plot } = chartFrame(W, H, PAD);
  const bw = (plot.r - plot.l) / BANDS;

  for (let i = 0; i < BANDS; i++) {
    let y = plot.b;
    for (const n of names) {
      const c = counts[n][i];
      if (!c) continue;
      const h = (c / max) * (plot.b - plot.t);
      svg.appendChild(svgEl("rect", {
        x: plot.l + i * bw + 0.5, y: y - h, width: Math.max(1, bw - 1), height: h,
        fill: MODEL_COLORS[n] || "#888", opacity: 0.85,
      }));
      y -= h;
    }
    axisLabel(svg, plot.l + i * bw + bw / 2, H - 10, (i / 10).toFixed(1));
  }
  svg.appendChild(svgEl("line", { x1: plot.l, y1: plot.b, x2: plot.r, y2: plot.b, class: "axis" }));
  axisLabel(svg, plot.l - 6, plot.t + 10, String(max), "end");
  axisLabel(svg, plot.l - 6, plot.b, "0", "end");
  host.appendChild(svg);
  host.appendChild(el("p", { class: "muted", text: `max ${max} per band, over ${total} score(s)` }));
}

/** Model agreement: how often each detector fired, as a bar per detector. */
function renderAgreement(counts) {
  const host = document.getElementById("m-agreement");
  host.innerHTML = "";
  const entries = Object.entries(counts || {});
  if (!entries.length) {
    host.appendChild(chartEmpty("No fired detections recorded."));
    return;
  }
  entries.sort((a, b) => b[1] - a[1]);
  const max = Math.max(1, ...entries.map(([, c]) => c));
  for (const [name, c] of entries) {
    const colour = MODEL_COLORS[name] || "#888";
    const pct = (c / max) * 100;
    host.appendChild(el("div", { class: "bar-row" }, [
      el("span", { class: "bar-name", text: name, title: name }),
      el("span", { class: "bar-track" }, [
        el("span", { class: "bar-fill", attrs: { style: `width:${pct}%;background:${colour}` } }),
      ]),
      el("span", { class: "bar-val", text: String(c) }),
    ]));
  }
  host.appendChild(el("p", { class: "muted", text:
    "A detector missing here fired on nothing, which is itself worth knowing." }));
}

/** Feature deviations: mean |z| per feature, as horizontal bars against a z=1/2/3 guide. */
function renderFeatureDeviations(rows) {
  const host = document.getElementById("m-features");
  host.innerHTML = "";
  if (!rows || !rows.length) {
    host.appendChild(chartEmpty(
      "No per-feature deviations recorded. These are written from feature_contributions, " +
      "so they appear once an anomaly carries one."));
    return;
  }
  const max = Math.max(1, ...rows.map((r) => r.mean_abs_z), ...rows.map((r) => r.max_abs_z));
  for (const r of rows) {
    const w = (r.mean_abs_z / max) * 100;
    const wMax = (r.max_abs_z / max) * 100;
    host.appendChild(el("div", { class: "bar-row" }, [
      el("span", { class: "bar-name", text: r.feature,
                   title: `${r.feature}: mean |z| ${r.mean_abs_z.toFixed(2)}, peak ${r.max_abs_z.toFixed(2)}, n=${r.n}` }),
      el("span", { class: "bar-track" }, [
        el("span", { class: "bar-fill ghost", attrs: { style: `width:${wMax}%` } }),
        el("span", { class: "bar-fill", attrs: { style: `width:${w}%;background:#4ea1ff` } }),
      ]),
      el("span", { class: "bar-val", text: r.mean_abs_z.toFixed(2) }),
    ]));
  }
  host.appendChild(el("p", { class: "muted", text:
    "Filled bar is the mean deviation; the pale extension is the peak seen. " +
    "z around 1 is normal noise, 3+ is genuinely unusual for that host." }));
}

/* SOC-2: near misses -- what almost alerted.
 *
 * The anomalies list can only ever show what was FLAGGED, so a threshold can only
 * be tuned by guessing without this. Each row carries the score, the bar it faced (the
 * adaptive per-host threshold, not the global setting), and which of the two gates
 * dropped it. Sorted by score descending server-side, so the closest calls are on top.
 *
 * The unavailable state is rendered as its own message, never as an empty table: "the
 * near-miss table does not exist yet" and "nothing nearly alerted" are different facts
 * and the second is a much stronger claim.
 */
function renderNearMisses(data) {
  const note = document.getElementById("m-near-note");
  const body = document.querySelector("#m-near tbody");
  if (!note || !body) return;
  note.replaceChildren();
  body.replaceChildren();

  if (!data.near_misses_available) {
    note.appendChild(el("p", { class: "muted", text:
      data.near_misses_reason || "near-miss data is unavailable" }));
    body.appendChild(el("tr", {}, [
      el("td", { class: "muted", text: "—", attrs: { colspan: 6 } }),
    ]));
    return;
  }
  const rows = data.near_misses || [];
  if (!rows.length) {
    body.appendChild(el("tr", {}, [
      el("td", { class: "muted",
                 text: "No near misses in this window — nothing scored close to the bar.",
                 attrs: { colspan: 6 } }),
    ]));
    return;
  }
  note.appendChild(el("p", { class: "muted", text:
    `${rows.length} window(s) within reach of the bar. Raising the threshold would `
    + `reclassify the below-threshold rows; lowering it would surface the gate rows.` }));
  for (const nm of rows) {
    body.appendChild(el("tr", {}, [
      el("td", { class: "mono", text: fmtTime(nm.window_start) }),
      el("td", {}, [hostCell(nm.src_addr, nm.hostname)]),
      el("td", { class: "num", text: Number(nm.score || 0).toFixed(3) }),
      el("td", { class: "num", text: Number(nm.threshold || 0).toFixed(3) }),
      el("td", { text: nm.reason === "agreement-gate"
                   ? "agreement gate (too few models agreed)"
                   : "below threshold" }),
      el("td", { text: (nm.models || []).join(", ") || "—" }),
    ]));
  }
}

async function loadModels() {
  const hours = (document.getElementById("m-hours") || {}).value || "72";
  const data = await getJSON("/api/models?hours=" + encodeURIComponent(hours));
  const sum = document.getElementById("m-summary");
  const win = document.getElementById("m-window");

  if (!data || !data.available) {
    if (win) win.textContent = "";
    if (sum) sum.textContent = "Unavailable: " + ((data && data.reason) || "no data");
    for (const id of ["m-history", "m-scores", "m-agreement", "m-features"]) {
      const n = document.getElementById(id);
      if (n) { n.innerHTML = ""; n.appendChild(chartEmpty("Unavailable.")); }
    }
    const body = document.querySelector("#m-points tbody");
    if (body) body.innerHTML = "";
    return;
  }

  if (win) win.textContent = "last " + hours + "h";
  if (sum) sum.textContent = data.summary || "";

  renderStaleness(data.staleness || [], data.retrain_interval_h);
  renderTrainingHistory(data.training_history || {});
  renderScoreDistribution(data.scores || {});
  renderAgreement(data.model_counts || {});
  renderFeatureDeviations(data.feature_deviations || []);
  renderNearMisses(data);

  const body = document.querySelector("#m-points tbody");
  body.innerHTML = "";
  if (!(data.points || []).length) {
    body.appendChild(el("tr", {}, [
      el("td", { class: "muted", text: "No anomalies in this window.", attrs: { colspan: 7 } }),
    ]));
    return;
  }
  for (const pt of data.points) {
    const tr = el("tr", { class: "clickable" }, [
      el("td", { class: "num", text: Number(pt.score || 0).toFixed(3) }),
      el("td", { class: "num", text: Number(pt.agreement || 0).toFixed(2) }),
      el("td", {}, [el("span", { class: "sev-" + (pt.severity || "low"), text: pt.severity || "—" })]),
      el("td", { text: (pt.models || []).join(", ") || "—" }),
      el("td", { text: pt.primary || "—" }),
      el("td", { class: "num", text: Number(pt.magnitude || 0).toFixed(2) }),
      el("td", {}, [hostCell(pt.src_addr, pt.hostname)]),
    ]);
    if (pt.src_addr) {
      tr.addEventListener("click", () => { showView("host"); loadHost(pt.src_addr, 24); });
    }
    body.appendChild(tr);
  }
}
