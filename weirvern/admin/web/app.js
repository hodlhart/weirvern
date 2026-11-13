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
    `/api/anomalies?min_score=${min}&limit=${limit}&hours=${trHours()}` +
    (unreviewed ? "&unreviewed=1" : ""),
  episodes: "/api/episodes",
  review: "/api/review",
  watch: "/api/watch",
  host: (addr, hours) => `/api/host?addr=${encodeURIComponent(addr)}&hours=${hours}`,
  findings: (ip = "", severity = "") =>
    `/api/findings` +
    (ip ? `?ip=${encodeURIComponent(ip)}` : "") +
    (severity ? `${ip ? "&" : "?"}severity=${encodeURIComponent(severity)}` : ""),
  evidence: (addr, start, end) =>
    `/api/evidence?addr=${encodeURIComponent(addr)}&start=${encodeURIComponent(start)}` +
    (end ? `&end=${encodeURIComponent(end)}` : ""),
  incident: (addr, start) =>
    `/api/incident?addr=${encodeURIComponent(addr)}&start=${encodeURIComponent(start)}`,
  // The operator's pivot from an alert to a block on the gate, and the fingerprint lookup that
  // answers the OTHER direction from the identity card (which hosts present this one stack).
  sluice: "/api/sluice",
  sluiceBlock: "/api/sluice/block",
  // The DNS view and the reverse map's read path (schema/016).
  dns: "/api/dns",
  // The Blocked ledger: recorded hits + the live rules split by what they do now.
  blocked: "/api/blocked",
  fingerprints: (ja4) => `/api/fingerprints?ja4=${encodeURIComponent(ja4)}`,
  // The SOC views. `health` is the DEEP check (reads ClickHouse), NOT /api/healthz, which
  // is the Kubernetes liveness probe and answers a bare {"ok":true} without touching the
  // database so a slow database cannot restart the GUI.
  netflow: "/api/netflow",
  zeek: "/api/zeek",
  health: "/api/health",
  system: "/api/system",
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

/** The anomalies table's two timestamp columns are a reading line, not a paragraph. Use a
 *  numeric stamp that fits one line at the fixed column width; the row's detail still carries
 *  the full local timestamp. */
function fmtCompactTime(v) {
  if (!v) return "—";
  const d = new Date(v);
  if (isNaN(d)) return String(v);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`;
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

/* THE SEVERITY GRAMMAR -- colour + glyph + word (console research, cross-cutting #3: the label
 * must survive colour-blindness and greyscale, so the SHAPE carries the rank and the hue only
 * reinforces it). One map, one habit: every renderer of a tier goes through sevText(), never
 * through a bare word. */
const SEVERITY_GLYPHS = { critical: "\u25b2", high: "\u25c6", medium: "\u25cf", low: "\u25cb" };
function sevText(sev) {
  const s = String(sev || "").toLowerCase();
  const glyph = SEVERITY_GLYPHS[s];
  return glyph ? glyph + " " + s : s;
}

function sevCell(sev) {
  const s = String(sev || "").toLowerCase() || "unknown";
  return el("span", { class: "sev-" + s, text: sevText(s) });
}

function emptyRow(tbody, cols, message, action) {
  const cell = el("td", { class: "empty", text: message, attrs: { colspan: String(cols) } });
  // AN EMPTY STATE OFFERS THE BUTTON (BF-8): the cause in words, and -- when a control
  // exists that genuinely fixes this emptiness -- the control itself, right here. An empty
  // state that only describes the void makes the reader go find the fix.
  if (action && action.label && typeof action.fn === "function") {
    const fix = el("button", { class: "empty-act", text: action.label, attrs: { type: "button" } });
    fix.addEventListener("click", action.fn);
    cell.appendChild(fix);
  }
  tbody.replaceChildren(el("tr", {}, [cell]));
}

/* The ONE JSON fetch helper, shared by every script. scripts/jsdom_render.js evaluates all
 * three files as one scope and a test pins this as the sole definition: it used to exist TWICE
 * (here and in assets.js), and because <script> tags share a global scope, the later-loaded
 * copy silently won for every call site -- app.js's and soc.js's error semantics were decided
 * by script order, which nothing would have caught if the order changed. Kept here because
 * this file loads first and the other shared helpers live here too. */
// A tab revisit inside one refresh beat should not pay for the same read again. The cache is
// deliberately short: the live pill still refreshes every 15s, and every write clears it so a
// form submit cannot read its own stale pre-write snapshot.
const GET_CACHE = new Map();
const GET_CACHE_TTL_MS = 8000;
// The same read can be started by the view loader and by the boot observer at once. Sharing
// the in-flight promise prevents two expensive ClickHouse reads for one tab activation.
const GET_INFLIGHT = new Map();
function clearGetCache() { GET_CACHE.clear(); }

async function getJSON(url) {
  const headers = requestHeaders();
  // ── THE GLOBAL TIME RANGE RIDES EVERY WINDOWED READ ─────────────────────────────────────────
  // In absolute mode the console appends from/to to any read that carries `hours=`: the server
  // honours the exact range, so the per-view `hours` box can never silently widen it.
  if (TIME_RANGE.mode === "absolute" && url.indexOf("hours=") !== -1 && url.indexOf("from=") === -1) {
    url += "&" + trWindowSuffix();
  }
  const cached = GET_CACHE.get(url);
  if (cached && Date.now() - cached.at < GET_CACHE_TTL_MS) return cached.body;
  const inflight = GET_INFLIGHT.get(url);
  if (inflight) return inflight;
  const request = (async () => {
    const res = await fetch(url, { headers });
    // Parse ONCE, tolerating a non-JSON body: an error page must not turn a status into
    // "undefined", and a 200 with a bad body must not throw here with a parse error where the
    // caller expects the payload contract.
    const body = await res.json().catch(() => null);
    if (!res.ok) {
      throw new Error((body && body.error) || `${res.status} ${res.statusText}`.trim());
    }
    GET_CACHE.set(url, { at: Date.now(), body });
    if (GET_CACHE.size > 96) {
      const now = Date.now();
      for (const [key, entry] of GET_CACHE) {
        if (now - entry.at >= GET_CACHE_TTL_MS) GET_CACHE.delete(key);
      }
      while (GET_CACHE.size > 96) GET_CACHE.delete(GET_CACHE.keys().next().value);
    }
    return body;
  })();
  GET_INFLIGHT.set(url, request);
  try {
    return await request;
  } finally {
    GET_INFLIGHT.delete(url);
  }
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
    // WORDED FROM THE NOTE (WV1-17). "no accounts provisioned" describes a benign first run; an
    // unreadable store is a different situation that happens to look identical from here.
    const authWhy = String(AUTH.note || "").trim();
    note.textContent = authWhy
      ? `${authWhy} Until the store can be read, reads are served without a session and the `
        + "operator token below is what changes settings."
      : "This deployment has no accounts provisioned: the operator token "
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
  clearGetCache();
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

/** POST and read NDJSON progress lines, returning the final result object. */
async function postNDJSON(path, body, onProgress) {
  clearGetCache();
  const resp = await window.fetch(path, {
    method: "POST",
    headers: requestHeaders({ "Content-Type": "application/json" }),
    body: JSON.stringify(Object.assign({}, body || {}, { stream: true })),
  });
  if (!resp.ok) {
    let payload = null;
    try { payload = await resp.json(); } catch (_e) { payload = null; }
    const err = new Error((payload && payload.error) || `HTTP ${resp.status}`);
    err.status = resp.status;
    err.payload = payload;
    throw err;
  }
  if (!resp.body || typeof resp.body.getReader !== "function") {
    return resp.json();
  }
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let result = null;
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let at;
    while ((at = buffer.indexOf("\n")) >= 0) {
      const line = buffer.slice(0, at).trim();
      buffer = buffer.slice(at + 1);
      if (!line) continue;
      let msg = null;
      try { msg = JSON.parse(line); } catch (_e) { continue; }
      if (msg && msg.progress && typeof onProgress === "function") onProgress(msg.progress);
      if (msg && msg.result !== undefined) result = msg.result;
    }
  }
  if (result === null) throw new Error("Sonar returned no result");
  return result;
}

/* ── staged changes ─────────────────────────────────────────────────────────
 *
 * NOTHING IS WRITTEN UNTIL APPLY. Every edit stages locally; the plan is then fetched from the
 * server so the validation and the blast radius come from the SAME code that will perform the
 * write. A second copy of the rules in JavaScript would drift from the server's, and the copy
 * that drifts is the one nobody tests -- so the browser never decides whether a value is legal.
 */
const STAGE = { changes: {}, plan: null };

/* THE STAGE SURVIVES A RELOAD (sessionStorage). The ranked #3 loudest OPNsense complaint in the
 * research: pending changes that vanish when you look away. This session's stage rides the tab's
 * own storage, so a reload lands back on the same review list -- and it dies with the tab, not on
 * the server: nothing staged is ever a server state. */
try {
  const savedStage = JSON.parse(window.sessionStorage.getItem("wv-stage") || "{}");
  if (savedStage && typeof savedStage === "object") Object.assign(STAGE.changes, savedStage);
} catch (_e) { /* a corrupt saved stage is not worth a broken console */ }

function persistStage() {
  try {
    if (Object.keys(STAGE.changes).length) {
      window.sessionStorage.setItem("wv-stage", JSON.stringify(STAGE.changes));
    } else {
      window.sessionStorage.removeItem("wv-stage");
    }
  } catch (_e) { /* private mode: the stage simply does not survive a reload */ }
  renderStagePill();
}

/** The header chip: how many settings changes are staged, visible from EVERY tab. */
function renderStagePill() {
  const n = Object.keys(STAGE.changes).length;
  const pill = document.getElementById("stage-pill");
  if (pill) {
    pill.classList.toggle("hidden", n === 0);
    pill.textContent = n ? `${n} staged` : "";
  }
  // THE SETTINGS HEADER CARRIES THE SAME FACT, as a jump, because a long card stack can leave
  // the pending set below the fold. It is the one STAGE; this is a second way to reach it.
  const jump = document.getElementById("st-stage-jump");
  const count = document.getElementById("st-stage-jump-count");
  if (jump) jump.hidden = n === 0;
  if (count) count.textContent = n ? `(${n})` : "";
}

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
  // A NAME FOR EVERY CONTROL (QA-1-D4, WCAG 4.1.2). The visible label is a SIBLING of the
  // control, so assistive tech announced "spin button" with no name. The row's own label is the
  // name; the range hint is associated rather than merely adjacent.
  const label = String(row.label || key);
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
    // A VALUED TOGGLE (netflow, 2026-10-17): some switches stage a domain value rather than a
    // boolean -- "off" / "upstream" for the flow probe. The spec carries the two values; the
    // checkbox stays one box, and everything OFF-spelled ("off", "", "0") reads as unchecked.
    const onV = s.on_value !== undefined ? String(s.on_value) : "true";
    const offV = s.off_value !== undefined ? String(s.off_value) : "false";
    const valued = s.on_value !== undefined || s.off_value !== undefined;
    const on = valued ? (String(shown).toLowerCase() !== offV
                         && String(shown).toLowerCase() !== "off"
                         && String(shown) !== "")
                      : canon(shown) === "true";
    // The state word beside the box: "checked means enabled, right?" must not be a guess, so the
    // switch says on/off in words and the word follows the box.
    const stateWord = el("span", { class: "setting-toggle-state", text: on ? "on" : "off" });
    const box = el("input", {
      class: "setting-toggle",
      attrs: { type: "checkbox", "data-key": key, "aria-label": label },
      on: { change: (ev) => {
        const now = ev.target.checked;
        stateWord.textContent = now ? "on" : "off";
        stageChange(key, now ? onV : offV, valued ? String(row.value) : canon(row.value));
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
      attrs: { "data-key": key, "aria-label": label },
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
               autocomplete: "off", "aria-label": label },
      on: { input: (ev) => stage(ev.target.value) },
    });
    if (s.min !== undefined) input.setAttribute("min", String(s.min));
    if (s.max !== undefined) input.setAttribute("max", String(s.max));
    if (s.step !== undefined) input.setAttribute("step", String(s.step));
    const range = (s.min !== undefined && s.max !== undefined)
      ? `${s.min}–${s.max}${s.unit ? " " + s.unit : ""}` : "";
    let hint = null;
    if (range) {
      hint = el("span", { class: "setting-unit", text: range, attrs: { id: `hint-${key}` } });
      input.setAttribute("aria-describedby", `hint-${key}`);
    }
    return el("span", { class: "setting-ctl-group" }, [input, hint]);
  }

  // text -- the deliberate free-text keys. data-key kept so the DOM harness and any other
  // selector can find it by key regardless of control kind.
  return el("input", {
    class: "setting-input", value: shown,
    attrs: { type: "text", "data-key": key, spellcheck: "false", autocomplete: "off",
               "aria-label": label },
    on: { input: (ev) => stage(ev.target.value) },
  });
}

/** The value an Apply would write for a key: a staged override, else the running value. */
function effectiveValue(key) {
  const staged = STAGE.changes[key];
  if (staged !== undefined) return String(staged);
  const row = SETTINGS_ROWS[key];
  return row ? String(row.value) : "";
}

function stageChange(key, value, original) {
  // A new edit supersedes the previous apply's message: leaving a stale "saved" line next to a
  // fresh staged change would claim a state that no longer holds.
  LAST_APPLY.text = "";
  LAST_APPLY.results = null;
  STAGE.from = STAGE.from || {};
  if (value === original) { delete STAGE.changes[key]; delete STAGE.from[key]; }
  else { STAGE.changes[key] = value; STAGE.from[key] = String(original); }
  STAGE.plan = null;   // any edit invalidates a previously fetched plan
  persistStage();
  renderStage();
}

/** ONE PENDING SET, TWO SURFACES (WSM-2). The note follows the controls: Settings' Pending
 *  changes card and the weirling sheet's. Two messages would be two truths. */
function setStageNote(text) {
  for (const id of ["st-stage-note", "wl-stage-note"]) {
    const n = document.getElementById(id);
    if (n) n.textContent = text;
  }
}

/** The sheet's mirror of the same STAGE: the keys and their staged values, never a copy of
 *  them. Includes Detection changes staged on Settings, because Apply here writes them too. */
function renderStageMirror(keys) {
  const box = document.getElementById("wl-stage");
  if (!box) return;
  const count = document.getElementById("wl-stage-count");
  const apply = document.getElementById("wl-stage-apply");
  const discard = document.getElementById("wl-stage-discard");
  const list = document.getElementById("wl-stage-list");
  box.classList.toggle("hidden", !keys.length);
  if (count) count.textContent = keys.length ? `${keys.length} staged` : "";
  if (apply) apply.disabled = keys.length === 0;
  if (discard) discard.disabled = keys.length === 0;
  if (!list) return;
  // IN A NIC'S SETTINGS, SHOW THAT NIC'S EFFECT, NOT THE WHOLE BOX'S LIST (operator,
  // 2026-10-19: "If I am configuring eth1 ... there should be no reference of eth2"). The
  // backend stores Zeek capture as one list, so the diff used to print `eth1,eth2` while the
  // operator was editing only eth1. The stored value stays global; the sentence here is local.
  const nicBox = document.getElementById("wl-nic-settings");
  const nic = nicBox && !nicBox.classList.contains("hidden") ? nicBox.dataset.nic : "";
  const localValue = (key, value) => {
    if (!nic) return value;
    if (key === "zeek_ifaces") {
      const list = String(value || "").split(",").map((s) => s.trim()).filter(Boolean);
      return list.includes(nic) || (!list.length && typeof wlCfgValue === "function"
        && wlCfgValue("zeek_iface") === nic)
        ? "on" : "off";
    }
    if (key === "capture_iface") return String(value) === nic ? "on" : "off";
    if (key === "netflow_iface") {
      const list = String(value || "").split(",").map((s) => s.trim()).filter(Boolean);
      return list.includes(nic) ? "on" : "off";
    }
    if (key === "sensor_mode") return String(value || "");
    if (key === "netflow_mode") return String(value || "");
    if (key === "interface_networks") {
      return typeof wlIfaceNames === "function" ? (wlIfaceNames(value)[nic] || "") : value;
    }
    return value;
  };
  const localKey = (key) => {
    if (!nic) return key;
    if (key === "zeek_ifaces") return `Zeek capture · ${nic}`;
    if (key === "capture_iface") return `siphon capture · ${nic}`;
    if (key === "netflow_iface") return `active NetFlow · ${nic}`;
    if (key === "channel_upstream") return "channel upstream";
    if (key === "channel_downstream") return "channel downstream";
    if (key === "sensor_mode") return `mode · ${nic}`;
    if (key === "netflow_mode") return `NetFlow source · ${nic}`;
    if (key === "interface_networks") return `network name · ${nic}`;
    return key;
  };
  list.replaceChildren();
  for (const key of keys) {
    const value = localValue(key, STAGE.changes[key] || "");
    list.appendChild(el("div", { class: "stage-row" }, [
      el("span", { class: "stage-key mono", text: localKey(key) }),
      el("span", { class: "stage-arrow", text: "→" }),
      el("span", { class: "stage-val mono", text: value || "(empty)" }),
    ]));
  }
}

function discardStage() {
  STAGE.changes = {};
  STAGE.from = {};
  STAGE.plan = null;
  // THE WAY OUT CLEARS THE MESSAGE TOO (QA-1-D1). A refused apply writes "BLOCKED — ..." into
  // LAST_APPLY, which this card re-renders on every load; clearing the stage without clearing
  // the verdict left the operator reading a refusal for a plan that no longer existed, with
  // nothing left to click. Discarding is a complete answer, so it resets both halves.
  LAST_APPLY.text = "";
  LAST_APPLY.results = null;
  persistStage();
  renderStage();          // immediately: no list, no note, Apply disabled
  // Re-render from the server's values so the inputs and the table agree again.
  loadSettings().catch(showError);
}

/** The outcome of the last apply, shown until the next apply. Survives a settings reload. */
const LAST_APPLY = { text: "", results: null };

function renderStage() {
  const keys = Object.keys(STAGE.changes);
  // THE SHEET SEES THE SAME SET (WSM-2). Rendered before the early return so the mirror is
  // never stale just because Settings' list host is absent.
  renderStageMirror(keys);
  const count = document.getElementById("st-stage-count");
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
    setStageNote(LAST_APPLY.text || "No changes staged. Edit a value above to stage one.");
    return;
  }
  setStageNote("Staged, not applied. Apply will write the cluster configuration and "
    + "restart whatever reads it.");

  // A staged edit whose value the server would reject is shown BEFORE apply, so nobody discovers
  // a typo by pressing the button.
  const bad = [];
  for (const key of keys) {
    const row = el("div", { class: "stage-row" }, [
      el("span", { class: "stage-key mono", text: key }),
      el("span", { class: "stage-arrow", text: "→" }),
      el("span", { class: "stage-val mono", text: STAGE.changes[key] || "(empty)" }),
    ]);
    // WHAT IT REPLACES, not just what it becomes: a diff the operator cannot read is not a review.
    // The from-value comes from the plan when there is one and from the running settings otherwise,
    // so a fresh stage reads "0.35 -> 0.36" immediately rather than only after a plan has run
    // (QA-1-D1).
    {
      const p = (STAGE.plan && (STAGE.plan.proposals || []).find((x) => x.key === key)) || null;
      const was = (STAGE.from && STAGE.from[key] !== undefined)
        ? STAGE.from[key]
        : (p && p.current !== undefined
            ? p.current
            : (SETTINGS_ROWS[key] ? SETTINGS_ROWS[key].value : ""));
      if (was !== "" && was !== undefined && was !== null) {
        row.appendChild(el("span", { class: "stage-was", text: `(was ${was})` }));
      }
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
  renderApplyResults();
}

/** The after-apply receipt: every key it tried -- the value, applied at HH:MM, or FAILED with
 * the server's own reason -- and, when anything failed, one button that stages the failed items
 * again and applies just those. "It said error" is not a result; this is. */
function renderApplyResults() {
  // THE RECEIPT FOLLOWS THE CONTROLS (WSM-2): the same LAST_APPLY renders on Settings and in
  // the weirling sheet, so an apply from the sheet is not a result the operator has to go
  // looking for on another tab.
  for (const id of ["st-apply-results", "wl-apply-results"]) {
    const host = document.getElementById(id);
    if (host) renderApplyInto(host);
  }
}

/** Server timestamps are UTC ISO strings; show them in the browser's own zone. */
function localStamp(iso) {
  const raw = String(iso || "");
  if (!raw) return "";
  const d = new Date(raw);
  if (Number.isNaN(d.getTime())) return raw;
  return d.toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
    timeZoneName: "short",
  });
}

function renderApplyInto(out) {
  out.replaceChildren();
  const R = LAST_APPLY.results;
  if (!R) return;
  const stamp = localStamp(R.at);
  const failed = [];
  for (const item of (R.items || [])) {
    const row = el("div", { class: "stage-res-item", attrs: { "data-key": item.key } }, [
      el("span", { class: "mono", text: item.key }),
      el("span", { text: " = " + (item.value || "(empty)") }),
    ]);
    if (item.ok) {
      row.appendChild(el("span", { class: "muted", text: "\u2014 applied" + (stamp ? " " + stamp : "") }));
    } else {
      row.appendChild(el("span", { class: "fail", text: "\u2014 FAILED: " + (item.error || "unknown reason") }));
      failed.push(item);
    }
    out.appendChild(row);
  }
  for (const t of (R.restarted || [])) {
    out.appendChild(el("div", { class: "stage-res-item muted", text: "restarted " + t }));
  }
  // THE APPLY-TIME CHECKS, REPORTED THE WAY THE RESEARCH ASKS (BF-14): the summary line
  // answers "how many passed and what was skipped", and the hover names every check with
  // its verdict and reason -- a skip nobody can explain is a skip nobody trusts.
  if (R.tests && R.tests.length) {
    const passed = R.tests.filter((t) => t.status === "pass").length;
    const skipped = R.tests.filter((t) => t.status === "skip").length;
    const failedT = R.tests.filter((t) => t.status === "fail");
    const detail = R.tests.map((t) => `${t.name} \u2014 ${t.status}: ${t.detail || ""}`)
      .join("\n");
    out.appendChild(el("div", {
      class: "stage-res-item" + (failedT.length ? " fail" : " muted"),
      text: (failedT.length ? "BLOCKED \u2014 " : "apply-time checks: ") +
            `${passed} passed, ${skipped} skipped` +
            (failedT.length ? `, ${failedT.length} failed` : "") +
            (skipped ? " \u2014 why? hover" : ""),
      attrs: { title: detail },
    }));
  }
  for (const e of (R.restart_errors || [])) {
    out.appendChild(el("div", { class: "stage-res-item fail", text: "restart failed \u2014 " + e }));
  }
  if (R.blocked) {
    // A refused plan is still a plan. The receipt says so and offers the one verb that ends it,
    // so the card can never be a dead end (the reason the QA walk filed this).
    const dismiss = el("button", {
      class: "quiet", text: "Clear this plan", attrs: { type: "button" },
      title: "discard the staged change and the refusal together",
      on: { click: () => discardStage() },
    });
    out.appendChild(el("div", { class: "stage-res-item" }, [dismiss]));
  }
  if (failed.length) {
    const btn = el("button", {
      class: "review-act", text: "Re-apply failed", attrs: { type: "button" },
      title: "stage the failed items again and apply just those",
      on: { click: async () => {
        btn.disabled = true;
        for (const item of failed) STAGE.changes[item.key] = item.value;
        persistStage();
        renderStage();
        await applyStage();
      } },
    });
    out.appendChild(el("div", { class: "stage-res-item" }, [btn]));
  }
}

/** Ask the server what the staged changes would do. Touches nothing. */
async function planStage() {
  const body = { changes: STAGE.changes };
  STAGE.plan = await postJSON("/api/settings/plan", body);
  renderStage();
  return STAGE.plan;
}

/** Apply, then report exactly what happened.
 *
 * skipWarnConfirm is for the ONE-CLICK enable (operator, 2026-10-17: the user just enables
 * it): the enable already IS the confirmation -- the button says what it does. The manual
 * Apply keeps its warned-change dialog. */
async function applyStage(skipWarnConfirm, opts = {}) {
  const keys = Object.keys(STAGE.changes);
  if (!keys.length) return;
  setStageNote("applying…");
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
    if (warns.length && !skipWarnConfirm) {
      const ok = window.confirm(
        "This change is allowed but costly:\n\n" +
        warns.map((p) => `${p.key}: ${p.warning}`).join("\n\n") +
        "\n\nApply anyway?");
      if (!ok) { setStageNote("not applied — you declined the warning"); return; }
    }
    // BF-9: a staged set that puts this deployment in path gets the echo first -- target,
    // blast radius, and a reason that is recorded with the actor and the time.
    let applyReason = "";
    const siphonStaged = Object.entries(STAGE.changes || {}).some(
      ([k, v]) => String(k).toLowerCase() === "sensor_mode" && String(v).toLowerCase() === "siphon");
    if (siphonStaged && !opts.skipSiphonConfirm) {
      const verdict = await confirmDestructive({
        title: "Enabling siphon puts this deployment IN THE TRAFFIC PATH.",
        target: "sensor_mode = siphon",
        blast: "the capture host becomes a cut point for its segment; while enabled, an outage "
               + "or a bad rule takes that segment's traffic down with it. The gate's own "
               + "checks still run at apply time.",
        reasonHint: "why this box is going in-path",
      });
      if (!verdict.ok) {
        setStageNote("not applied — you declined the siphon confirmation");
        return;
      }
      applyReason = verdict.reason;
    }
    const res = await postJSON("/api/settings/apply", {
      changes: STAGE.changes, confirmed: true,
      // THE WEIRLINGS SHEET APPLIES WITHOUT A SECOND REASON PROMPT (operator, 2026-10-19:
      // "Once I hit apply in wierlings don't do the secondary pop up for a reason"). The
      // ordinary Settings tab keeps the BF-9 echo. The sheet records its own origin so the
      // write trail still says where the decision came from.
      reason: applyReason || opts.reason || "",
    });

    // Report the outcome in the server's terms. A saved-but-not-restarted change is INERT, so it
    // is shown as a problem rather than folded into a success line.
    STAGE.changes = {};
    STAGE.from = {};
    STAGE.plan = null;
    persistStage();
    LAST_APPLY.results = {
      at: res.at || "", items: res.items || [],
      restarted: res.restarted || [], restart_errors: res.restart_errors || [],
      tests: res.tests || [], blocked: false,
    };
    renderApplyResults();
    const parts = ["saved: " + Object.entries(res.applied || {}).map(([k, v]) => `${k}=${v || "(empty)"}`).join(", ")];
    if ((res.restarted || []).length) parts.push("restarted " + res.restarted.join(", "));
    if ((res.restart_errors || []).length) {
      parts.push("NOT APPLIED — " + res.restart_errors.join("; "));
    }
    LAST_APPLY.text = parts.join(" · ");
    setStageNote(LAST_APPLY.text);
    await loadSettings();
  } catch (err) {
    // A refused write states the server's reason: a missing token, an RBAC gap, a bad value.
    setStageNote("not applied — " + (err.message || err));
    if (err.status === 401) { setToken(""); await refreshAuthNote(); }
    // A REFUSED WRITE STILL GETS ITS RECEIPT: the server's per-item verdicts ride the refusal,
    // and the failed items can be re-staged in one click.
    const p = err.payload;
    if (p && p.blocked) {
      // AN APPLY-TIME CHECK REFUSED THE WRITE (BF-14): the failed assertion is the headline,
      // every check that ran (and every skip with its reason) is one hover away, and the
      // stage is deliberately NOT cleared -- the fix is to adjust the staged value.
      LAST_APPLY.text = "BLOCKED \u2014 " + (p.error || "an apply-time check refused this change");
      setStageNote(LAST_APPLY.text);
      LAST_APPLY.results = { at: "", items: [], restarted: [], restart_errors: [],
                             tests: p.tests || [], blocked: true };
      renderApplyResults();
      return;
    }
    if (p && Array.isArray(p.items)) {
      LAST_APPLY.results = { at: p.at || "", items: p.items,
                             restarted: p.restarted || [], restart_errors: p.restart_errors || [] };
    }
    renderApplyResults();
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

async function runSonar(opts = {}) {
  const btn = document.getElementById("st-sonar");
  const note = document.getElementById("st-sonar-note");
  if (SONAR_STATE.running) return null;
  SONAR_STATE.running = true;
  SONAR_STATE.error = "";
  if (btn) { btn.disabled = true; btn.textContent = "Surveying…"; }
  if (note) note.textContent = "Surveying: DHCP, then passive capture, then an ARP probe. "
    + "Nothing is changed — this can take a few seconds.";

  try {
    // The caller may name the interface to survey. The Weirlings sheet is per-NIC and must
    // measure the port it is open on, not the global capture default (operator, 2026-10-19).
    const body = opts && opts.interface ? { interface: String(opts.interface) } : {};
    const progress = typeof opts.onProgress === "function" ? opts.onProgress : (p) => {
      if (note && p && p.text) note.textContent = p.text;
    };
    const res = await postNDJSON("/api/settings/sonar", body, progress);
    SONAR_STATE.result = res;
    renderSonarNote(res);
    // SONAR IS A SURVEY, NOT A WRITE, but its measured answer belongs in the fields the
    // operator is about to review. Stage it through the ordinary dedupe (so an unchanged
    // recommendation stages nothing) and show the value in the control -- the note promised
    // "staged as pending changes below" while the fields stayed blank.
    // A per-NIC caller owns where the measurement is staged. Staging the legacy global
    // INTERCEPT_* keys here was how a survey of eth2 overwrote eth1's segment.
    if (res && res.ok === true && opts.stage !== false) stageSonarRecommendations(res);
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
    // Show the recommendation in the control itself, not only in the pending list. The
    // setting rows carry their key lowercased in the DOM even when the registry key is
    // uppercase; query the lowercase form, as the NIC click does.
    const input = document.querySelector(
      `#st-sensor .setting[data-key="${String(key).toLowerCase()}"] input`);
    if (input) input.value = String(value);
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
    `Interface ${res.interface} is on ${res.segment}`
      + (res.address ? ` (${res.address})` : " (no address of its own)") + ".",
  ];
  if (res.swept === null || res.swept === undefined) {
    lines.push(`No ARP sweep ran: ${res.hosts_seen || 0} host(s) were seen speaking, `
      + `but a quiet host cannot be found without an address to sweep from.`);
  } else {
    lines.push(`${res.hosts_answered} host(s) answered an ARP sweep of ${res.swept} addresses; `
      + `${(res.free_addresses || []).length} free address(es) were found.`);
  }
  if (res.gateway) {
    lines.push(`Gateway ${res.gateway}${res.gateway_mac ? " (" + res.gateway_mac + ")" : ""}`
      + ` — ${res.gateway_source}.`);
  }
  note.appendChild(el("div", { text: lines.join(" ") }));
  for (const n of (res.notes || [])) {
    note.appendChild(el("div", { class: "sonar-note-item", text: "• " + n }));
  }
  // HONEST COUNTS (live report 2026-10-17). This used to claim one staged change PER
  // RECOMMENDATION -- but staging goes through the same dedupe as the manual controls, so a
  // recommendation that already matches the running value stages NOTHING. Measured live: 5
  // recommendations, 2 staged, and the panel read "Staged 5" over a two-row list. Say what
  // actually happened, and say it plainly when nothing did.
  const rec = (res.recommended) || {};
  const keys = Object.keys(rec);
  const changed = keys.filter((k) => {
    const row = SETTINGS_ROWS[k];
    return String(rec[k]) !== (row ? String(row.value) : "");
  });
  if (keys.length) {
    if (changed.length) {
      const same = keys.length - changed.length;
      note.appendChild(el("div", { class: "sonar-note-item",
        text: `Staged ${changed.length} change(s) as pending changes below`
          + (same ? ` (${same} recommendation(s) already match what is running and were not `
                    + `staged again)` : "")
          + ` — review, edit or discard them, then Apply. Nothing has been written yet.` }));
    } else {
      note.appendChild(el("div", { class: "sonar-note-item",
        text: "Every recommendation already matches what is running — nothing to stage." }));
    }
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

async function loadUpdateStatus(force = false) {
  const state = document.getElementById("st-update-state");
  const note = document.getElementById("st-update-note");
  const link = document.getElementById("st-update-link");
  const button = document.getElementById("st-update-check");
  if (!state || !note) return;
  if (button) button.disabled = true;
  state.textContent = "checking…";
  note.textContent = "Reading the release channel…";
  try {
    const data = await getJSON("/api/update" + (force ? "?refresh=1" : ""));
    if (!data || data.available === false) {
      state.textContent = data && data.private ? "private feed" : "not checked";
      note.textContent = (data && data.reason) ||
        "The release feed could not be read. This does not change the running deployment.";
      if (link) link.classList.add("hidden");
      return;
    }
    const current = data.current || "unknown";
    const latest = data.latest || current;
    if (data.update_available) {
      state.textContent = `v${latest} available`;
      note.textContent = `Running v${current}. The newer release is ${data.release_url ? "linked below" : "available on GitHub"}.`;
    } else {
      state.textContent = `v${current} · current`;
      note.textContent = `This deployment is current${data.published_at ? ` (latest release ${data.published_at.slice(0, 10)})` : ""}.`;
    }
    if (link && data.release_url) {
      link.href = data.release_url;
      link.classList.remove("hidden");
    } else if (link) {
      link.classList.add("hidden");
    }
    if (data.notes) note.title = data.notes;
  } catch (err) {
    state.textContent = "not checked";
    note.textContent = "Release check failed: " + (err && err.message ? err.message : err);
  } finally {
    if (button) button.disabled = false;
  }
}

async function loadSettings() {
  scheduleURLSync();
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
    for (const id of ["st-detect", "st-sensor", "st-dns", "st-runtime"]) {
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
  // The blocklist pane lives on this tab now (moved 2026-10-16); keep it fresh whenever
  // Settings loads. A no-op on builds where the card is absent.
  if (typeof loadBlocklistPane === "function") loadBlocklistPane().catch(() => {});
  // SONAR is a write-gated action (it creates a job on the sensor node), so for a viewer
  // or a signed-out browser it is disabled with the same honesty as the other controls:
  // present and explainable, not vanished. THE TEST RUN is write-gated for the same reason
  // and one more: while it runs, the sensor is genuinely in the traffic path.
  const sonarBtn = document.getElementById("st-sonar");
  if (sonarBtn) sonarBtn.disabled = !Boolean(data.writes && data.writes.enabled);
  const testBtn = document.getElementById("st-test");
  if (testBtn) testBtn.disabled = !Boolean(data.writes && data.writes.enabled);
  // THE MODE SELECT IS A SETTINGS CONTROL (it stages sensor_mode through the ordinary plan).
  // Its row is skipped in the grid below -- one control, one value -- so the select carries it.
  const modeRow = (groups.sensor || []).find((r) => r.key === "sensor_mode");
  const modeSel = document.getElementById("wl-mode-select");
  if (modeSel) {
    if (modeRow) {
      modeSel.value = String(modeRow.value).toLowerCase() === "siphon" ? "siphon" : "loch";
    }
    modeSel.disabled = !Boolean(data.writes && data.writes.enabled);
  }
  // NO "N SETTINGS IN EFFECT" (operator, 2026-10-19: "this tells me nothing"). The count was
  // decoration; the rows themselves are the answer. The element still carries the unavailable
  // reason above, which is information.
  if (sum) sum.textContent = "";
  window.SETTINGS_WRITES = Boolean(data.writes && data.writes.enabled);

  // Network scopes live beside the other settings; the card owns its own read/write because
  // a CIDR declaration is not a ConfigMap key and must not be staged as one. Loaded AFTER
  // SETTINGS_WRITES so its controls render in the caller's actual write state.
  if (typeof loadNetworks === "function") loadNetworks().catch(() => {});
  // Software update is a read-only release check. It deliberately runs beside Settings rather
  // than inside the ConfigMap payload: a slow GitHub request must not delay the settings rows.
  if (typeof loadUpdateStatus === "function") loadUpdateStatus().catch(() => {});

  for (const key of ["detect", "sensor", "dns", "runtime"]) {
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
      // The mode's control is the weirlings drill-down's selector; a raw row here would be a
      // second, differently-named control for one value.
      if (r.key === "sensor_mode") continue;
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

      // THE "i" IN A CIRCLE IS ON EVERY ROW, editable or not — one glyph for ONE habit, across
      // the whole console ("use i in a circle ... users can click and get more information").
      // A value whose meaning has to be guessed is a value that gets misconfigured, and the
      // explanation is where an operator new to the product learns what a setting does without
      // reading the source.
      const help = el("div", {
        class: "setting-help hidden",
        text: r.help || "No explanation is recorded for this setting.",
      });
      const helpBtn = el("button", {
        class: "setting-help-btn", text: "i",
        attrs: { type: "button", "aria-label": `explain ${r.label}`,
                 "aria-expanded": "false", title: "what this setting does" },
        on: { click: (ev) => {
          // stopPropagation so a click on the "i" can never be read as a click on the row.
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
          // HOW IT APPLIES (BF-5): no control leaves the operator guessing whether their
          // change took effect. The sentence is the PAYLOAD's (derived from the writer's own
          // restart table); the CSS keeps it small and quiet.
          isEditable ? el("span", {
            class: "setting-applies",
            text: String(r.applies || "").replace("applies with Apply — ", "applies with Apply · "),
            title: r.applies || "",
          }) : null,
        ]),
        el("span", { class: "setting-ctl" }, [valueNode, helpBtn]),
        help,
        // US-10: WHERE THIS VALUE CAME FROM. The apply path records who/when/why and the value
        // it replaced; the row says so, and both verbs are one click away.
        (data.provenance || {})[r.key] ? (() => {
          const prov = data.provenance[r.key];
          return el("div", { class: "setting-prov" }, [
            el("span", { text: `set via GUI ${prov.at ? localStamp(prov.at) : "?"}` + (prov.by ? ` by ${prov.by}` : "") }),
            prov.reason ? el("span", { text: ` \u00b7 ${prov.reason}` }) : null,
            el("button", { class: "link", text: "trail", attrs: { type: "button",
              title: "where did this value come from \u2014 jump to its write-trail entries" },
              on: { click: (ev) => { ev.stopPropagation(); openSettingTrail(r.key); } } }),
            prov.prev_value !== undefined && canWrite ? el("button", { class: "link",
              text: "revert", attrs: { type: "button",
                title: `revert to ${String(prov.prev_value) || "(empty)"} \u2014 through the confirm echo` },
              on: { click: (ev) => { ev.stopPropagation(); revertSetting(r.key, prov).catch(showError); } } })
              : null,
          ]);
        })() : null,
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

/**
 * ONE definition of "reviewed" for a row (issue #20).
 *
 * A grouped row holds several occurrences, each with its own review state. Three surfaces
 * describe it -- the chip, the count tooltip and the unreviewed-only filter -- and they used
 * to disagree: the chip echoed only the NEWEST occurrence, so acking the newest read as done
 * while the filter (correctly) still listed the row, and the older occurrences could not be
 * dispositioned at all. The tooltip's "N occurrence(s), K unreviewed" was the honest sentence;
 * this helper is now its single source, read by BOTH the tooltip and the chip, so they cannot
 * drift apart: a row is reviewed when EVERY occurrence is (left === 0), and while any are
 * left the chip carries "K unreviewed" -- literally the tooltip's words.
 */
function anReviewSummary(a) {
  const n = Number(a.n || 1);
  const left = Number(a.unreviewed_n || 0);
  return {
    n, left,
    title: `${n} occurrence(s)` + (left > 0 ? `, ${left} unreviewed` : ""),
    remaining: left > 0 ? `${left} unreviewed` : "",
  };
}

/** The state chip for one occurrence (or a whole row): the state, its label, and WHEN. */
function reviewChip(state, reviewedAt) {
  return el("span", {
    class: "review-chip " + reviewClass(state),
    text: REVIEW_LABELS[state] !== undefined ? REVIEW_LABELS[state] : state,
    title: reviewedAt ? "reviewed " + fmtTime(reviewedAt) : "not reviewed yet",
  });
}

/** The dispositions a target can be moved to, minus the one it already has.
 *  No actions while the review store is unreadable: a write against a store we cannot read
 *  would fail after the click, and offering it anyway would advertise a control that cannot
 *  work. */
function reviewActs(target, state) {
  if (state === "unavailable") return null;
  return el("div", { class: "review-acts" }, [
    ...[["ack", "Acknowledge"], ["resolved", "Resolve"], ["false_positive", "Ignore"]]
      .filter(([st]) => st !== state)
      .map(([st, label]) => el("button", {
        class: "review-act", text: label, attrs: { type: "button" },
        title: `mark this anomaly as ${st.replace("_", " ")}`,
        on: { click: (e) => { e.stopPropagation(); postReview(target, st); } },
      })),
    state
      ? el("button", {
          class: "review-act", text: "clear", attrs: { type: "button" },
          title: "back to unreviewed",
          on: { click: (e) => { e.stopPropagation(); postReview(target, ""); } },
        })
      : null,
  ]);
}

/** One review cell: the state chip, the row's remaining count while any occurrence is
 *  unreviewed, then the actions that are not the current state. */
function reviewCell(a) {
  const state = a.review_state || "";
  const summary = anReviewSummary(a);
  const wrap = el("div", {});
  wrap.appendChild(reviewChip(state, a.reviewed_at));
  if (a.review_adjustment) {
    const adj = a.review_adjustment;
    wrap.appendChild(el("span", {
      class: "review-adjust",
      text: `${adj.metric} ${Number(adj.before_value)} \u2192 ${Number(adj.after_value)}`,
      attrs: {"aria-label": `${adj.scope} ${adj.subject}: ${adj.reason}`
        + (adj.effective ? "" : " (expired or reverted)")
        + (adj.reviewer ? ` \u00b7 ${adj.reviewer}` : "")},
    }));
  }
  if (summary.remaining) {
    wrap.appendChild(el("span", {
      class: "review-remain", text: summary.remaining,
      title: `${summary.remaining} of ${summary.n} occurrences \u2014 the count cell lists them`,
    }));
  }
  return wrap;
}

/**
 * A2 · THE ROW'S VERBS LIVE BEHIND ONE DISCLOSURE.
 *
 * The table used to carry seven buttons per row -- Evidence, Block, Watch, Tune and every
 * disposition that was not the current state. At ~90 rows that is 630 controls, all 28px tall:
 * a wall of misses on touch and, in the audit's words, 632 controls under the 44px line.
 *
 * The row itself is still the way into the evidence. The verbs sit one level down, behind a
 * native <details> disclosure: closed at rest (so the list is a list, not a button matrix),
 * one 44px target per row on a phone, and the same keyboard behaviour a summary always has.
 * Nothing was removed -- every verb is still one click away, on the row it belongs to.
 */
function rowMore(a, state) {
  const box = el("details", { class: "row-more" });
  // The summary needs a NAME of its own: "..." is decoration, and a title attribute would be a
  // fact only a mouse can reach -- the exact defect class this console keeps re-learning.
  const summary = el("summary", { attrs: { "aria-label": "actions for this alert" },
                                  text: "\u22ef" });
  box.appendChild(summary);
  const body = el("div", { class: "row-more-body" });
  // THE ROW IS A READING LINE; THE DISCLOSURE OWNS THE FULL PROSE. The matched rule and why
  // sentence are clamped at rest so 100 rows remain a table, not a 42,000px page.
  if (a.matched_rule) {
    body.appendChild(el("div", { class: "row-more-full", text: "Matched rule: " + a.matched_rule }));
  }
  if (a.detected_by_models) {
    body.appendChild(el("div", { class: "row-more-full", text: "Models: " + a.detected_by_models }));
  }
  if (a.baseline_comparison) {
    body.appendChild(el("div", { class: "row-more-full", text: a.baseline_comparison }));
  }
  body.appendChild(anActions(a));
  const acts = reviewActs(a, state);
  if (acts) body.appendChild(acts);
  box.appendChild(body);
  // A click inside the disclosure must not fall through to the row, which opens Evidence.
  box.addEventListener("click", (e) => e.stopPropagation());
  return box;
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
  // THE EVIDENCE PAGE REFRESHES ITSELF after a disposition. Re-rendering the anomalies
  // table behind a page the operator is still reading would leave the evidence showing the
  // old ruling, which is the exact place the decision is supposed to be visible.
  if (document.getElementById("view-evidence").classList.contains("active")) {
    await openEvidence(a);
  } else {
    await loadAnomalies();
  }
}

function anToggleOccurrences(tr, a) {
  const cell = tr.querySelector("td.expander");
  const next = tr.nextElementSibling;
  if (next && next.classList && next.classList.contains("an-exp")) {
    next.remove();
    if (cell) cell.setAttribute("aria-expanded", "false");
    return;
  }
  if (cell) cell.setAttribute("aria-expanded", "true");
  const occ = (a.windows && a.windows.length) ? a.windows
    : [{ window: a.window_start, review_state: a.review_state, review_note: a.review_note,
         reviewed_at: a.reviewed_at }];
  const box = el("div", { class: "occ-list" });
  for (const w of occ) {
    // EACH OCCURRENCE IS DISPOSITIONED ON ITS OWN (issue #20). The collapsed row can only
    // post its newest window, so a group whose older occurrences still said "unreviewed"
    // was untriageable from the UI. This cell reuses the same chip and action builders and
    // the same postReview path, so every write still lands as the server's answer.
    const target = { window_start: w.window, src_addr: a.src_addr,
                     review_state: w.review_state, review_note: w.review_note,
                     reviewed_at: w.reviewed_at };
    box.appendChild(el("div", { class: "occ" }, [
      el("span", { class: "mono", text: w.window ? fmtTime(new Date(w.window)) : "\u2014" }),
      reviewChip(target.review_state || "", target.reviewed_at),
      reviewActs(target, target.review_state || ""),
      w.review_note ? el("span", { class: "muted", text: "\u2014 " + w.review_note }) : null,
    ].filter(Boolean)));
  }
  if (Number(a.n || 1) > occ.length) {
    box.appendChild(el("div", { class: "muted",
      text: `\u2026and ${Number(a.n) - occ.length} more; the newest ${occ.length} are listed.` }));
  }
  const exp = el("tr", { class: "an-exp" }, [
    el("td", { class: "muted", text: "occurrences" }),
    el("td", { attrs: { colspan: "8" } }, [box]),
  ]);
  tr.parentNode.insertBefore(exp, tr.nextSibling);
}

/**
 * THE DASHBOARD-WIDE FILTER for the triage queue (the operator, 2026-10-16: "if i click in any
 * dashboard it should filter that entire dashboard"). A click on a row's host or severity
 * becomes the queue's filter; the chips remove themselves. SERVER-SIDE on purpose: the handler
 * binds both into the anomalies query, so the list and its counts are the filtered truth --
 * never a smaller list the browser worked out by hiding rows it had already received.
 */
const AN_FILTERS = { host: "", severity: "", model: "", feature: "" };

function anQuery() {
  let q = "";
  if (AN_FILTERS.host) q += "&host=" + encodeURIComponent(AN_FILTERS.host);
  if (AN_FILTERS.severity) q += "&severity=" + encodeURIComponent(AN_FILTERS.severity);
  if (AN_FILTERS.model) q += "&model=" + encodeURIComponent(AN_FILTERS.model);
  if (AN_FILTERS.feature) q += "&feature=" + encodeURIComponent(AN_FILTERS.feature);
  return q;
}

function anRenderChips() {
  const box = document.getElementById("an-filters");
  if (!box) return;
  box.replaceChildren();
  // US-6: ARRIVED THROUGH A LINK. These filters were not chosen on this screen -- they came in
  // the URL -- so the reason is said out loud, and one click shows everything again.
  if (ARRIVED_FROM_LINK && (AN_FILTERS.host || AN_FILTERS.severity || AN_FILTERS.model
      || AN_FILTERS.feature)) {
    const arrival = el("button", { class: "dc-chip",
      attrs: { title: "these filters arrived with the link; click to show everything" },
      text: "arrived with filters \u2014 show everything \u00d7" });
    arrival.addEventListener("click", () => { ARRIVED_FROM_LINK = false; anClearAllFilters(); });
    box.appendChild(arrival);
  }
  for (const field of ["host", "severity", "model", "feature"]) {
    if (!AN_FILTERS[field]) continue;
    const chip = el("button", { class: "dc-chip", attrs: { title: "remove this filter" },
      text: `${field} = ${AN_FILTERS[field]} \u00d7` });
    chip.addEventListener("click", () => {
      AN_FILTERS[field] = "";
      anRenderChips();
      loadAnomalies().catch(showError);
    });
    box.appendChild(chip);
  }
}

/**
 * THE CRITICALITY TILES (the operator, 2026-10-16: "add across the top the number of each
 * criticality level and make it clickable to filter the page"). One tile per severity with the
 * count under the page's current min-score and host filters; clicking filters the page to that
 * severity, clicking again removes it. The counts come from the server beside the rows, NOT
 * from counting what the browser received -- the list is capped by its limit and a browser-side
 * count would quietly under-count the page it claims to describe.
 */
/* FIRED VS ACTED ON (BF-12; SRE workbook: the alert budget). Fired counts the occurrences
 * under the page's score/host filters; acted-on counts disposed occurrences from the review
 * history. The two are the same unit (one review exists per occurrence), so their difference
 * is the open queue and is said out loud. */
/* ── THE PIPELINE'S SELF-AUDIT (BF-13) ──────────────────────────────────────────────────────
 * The findings are the SERVER's -- classes, details, and the fix spec all come from
 * /api/audit, because the checks and the console reading them must not be able to drift.
 * This renderer's whole job is presenting the fix as one click. */
const AUDIT_CLASS_LABELS = {
  silent_sensor: "silent sensor",
  expired_rule: "expired rule",
  stuck_rule: "stuck rule",
  unowned_detector: "unowned detector",
  // WL-2: the facts that left the weirling sheet's fact list land here, where issues live.
  capture_loss: "capture loss",
  segment_mismatch: "segment mismatch",
};

function anAgeShort(sec) {
  if (sec == null || !isFinite(sec)) return "—";
  const s = Math.max(0, Number(sec));
  if (s < 90) return `${Math.round(s)}s`;
  if (s < 5400) return `${Math.round(s / 60)}m`;
  if (s < 129600) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86400)}d`;
}

function auditGo(fix) {
  if (!fix || !fix.view) return;
  showView(fix.view);
  if (fix.sensor && typeof openWeirling === "function") {
    openWeirling(fix.sensor).catch(() => {});
  }
  // US-3: the fix KEEPS ITS ID. A rule fix lands on the RULE -- the blocked rule card, or its
  // row in the sluice table -- and a registry fix lands on the detector's own row. Every one
  // of these used to land at the top of a page, leaving the operator to search for the thing
  // the button had just named.
  if (fix.rule_id) {
    if (fix.view === "blocked" && typeof blOpenRuleById === "function") {
      blOpenRuleById(fix.rule_id).catch(() => {});
    } else if (typeof sluiceHighlightRule === "function") {
      sluiceHighlightRule(fix.rule_id);
    }
  }
  if (fix.detector && typeof registryHighlight === "function") {
    registryHighlight(fix.detector);
  }
}

async function loadAudit() {
  const tbody = document.querySelector("#audit-table tbody");
  const note = document.getElementById("audit-note");
  if (!tbody) return;
  let d;
  try {
    d = await getJSON("/api/audit");
  } catch (err) {
    if (note) note.textContent =
      `The self-audit could not be read: ${err && err.message ? err.message : err}`;
    return;
  }
  tbody.replaceChildren();
  if (note) note.textContent = "";
  if (!d || d.available !== true) {
    if (note) note.textContent =
      `The self-audit is unavailable \u2014 ${(d && d.reason) || "the read did not run"}.`;
    return;
  }
  const findings = d.findings || [];
  if (!findings.length) {
    tbody.appendChild(el("tr", {}, [
      el("td", { attrs: { colspan: "4" } }, [
        el("span", { class: "muted",
          text: "The pipeline passes its own checks \u2014 no silent sensors, expired rules, " +
                "stuck rules, or unowned detectors." }),
      ]),
    ]));
  }
  for (const f of findings) {
    tbody.appendChild(el("tr", {}, [
      el("td", {}, [
        el("span", { class: "chip " + (f.severity === "warn" ? "warn" : "muted"),
                     text: AUDIT_CLASS_LABELS[f.class] || f.class }),
      ]),
      el("td", {}, [
        el("span", { class: "mono", text: f.subject || "" }),
        el("div", { class: "muted", text: f.detail || "" }),
      ]),
      el("td", { class: "num", text: anAgeShort(f.elapsed_s) }),
      el("td", {}, [
        el("button", { class: "quiet", text: f.fix && f.fix.label ? f.fix.label : "open",
                       attrs: { type: "button", title: "go to the surface that fixes this" },
                       on: { click: () => auditGo(f.fix) } }),
      ]),
    ]));
  }
  const errs = d.errors || {};
  if (note && Object.keys(errs).length) {
    // A CLASS THAT DID NOT RUN IS SAID SO (BF-13): "nothing found" and "the check did not
    // run" must never look alike.
    note.textContent = "Checks that could not run: " +
      Object.entries(errs).map(([k, v]) => `${k} (${v})`).join(", ") + ".";
  }
}

function anRenderDiscipline(d) {
  const box = document.getElementById("an-discipline");
  if (!box) return;
  if (!d || !d.available) {
    box.textContent = d && d.reason
      ? `Fired / acted-on counts unavailable \u2014 ${d.reason}.` : "";
    return;
  }
  const open = Number(d.fired || 0) - Number(d.acted || 0);
  box.textContent = `${d.fired} fired \u00b7 ${d.acted} acted on` +
    (open > 0 ? ` \u00b7 ${open} still open` : "");
}

/** US-3: a registry fix lands ON the detector's row -- scrolled to and said once. The pending
 *  id survives the re-render showView() fires on selection (see sluiceApplyFlash). */
let REG_FLASH_PENDING = "";
let REG_FLASH_TIMER = null;
function registryHighlight(name) {
  REG_FLASH_PENDING = String(name);
  registryFlashRow(REG_FLASH_PENDING);
  if (REG_FLASH_TIMER) clearTimeout(REG_FLASH_TIMER);
  REG_FLASH_TIMER = setTimeout(() => { REG_FLASH_PENDING = ""; }, 2500);
}
function registryFlashRow(name) {
  const tr = [...document.querySelectorAll("#detectors-table tbody tr")]
    .find((r) => r.getAttribute("data-detector") === String(name));
  if (!tr) return false;
  if (typeof tr.scrollIntoView === "function") {
    try { tr.scrollIntoView({ block: "center" }); } catch (_e) { /* fine without it */ }
  }
  tr.classList.remove("flash-hit");
  void tr.offsetWidth;
  tr.classList.add("flash-hit");
  return true;
}
function registryApplyFlash() {
  if (!REG_FLASH_PENDING) return;
  if (registryFlashRow(REG_FLASH_PENDING)) {
    REG_FLASH_PENDING = "";
    if (REG_FLASH_TIMER) { clearTimeout(REG_FLASH_TIMER); REG_FLASH_TIMER = null; }
  }
}

/** The registry strip: who owns each detector and who may page, with its catch counts. */
async function loadDetectors() {
  const tbody = document.querySelector("#detectors-table tbody");
  const note = document.getElementById("an-detectors-note");
  if (!tbody) return;
  let d;
  try {
    d = await getJSON("/api/detectors");
  } catch (err) {
    if (note) note.textContent = `The detector registry could not be read: ${err && err.message ? err.message : err}`;
    return;
  }
  tbody.replaceChildren();
  if (note) note.textContent = "";
  if (!d || d.available !== true) {
    if (note) note.textContent = `The detector registry is unavailable \u2014 ` +
      `${(d && d.reason) || "the read did not run"}.`;
    return;
  }
  for (const det of d.detectors || []) {
    tbody.appendChild(el("tr", { attrs: { "data-detector": det.name } }, [
      el("td", {}, [
        // US-5: the registry row answers "show me what this detector found" in one click.
        el("span", { class: "mono dcell", attrs: { title: "show only this detector's alerts" },
                     on: { click: () => anSetFilter("model", det.name) } },
           [el("span", { text: det.name })]),
        det.known ? null : el("span", { class: "chip warn", text: " unregistered",
          attrs: { title: "nobody has registered this detector: it cannot page until an owner and runbook exist" } }),
      ]),
      el("td", { text: det.owner || "—" }),
      el("td", {}, [
        el("span", { class: "chip " + (det.loud ? "pages" : "quiet"),
                     text: det.loud ? "pages" : "quiet",
                     attrs: { title: det.loud
                       ? `may page a phone; runbook: ${det.runbook || "none recorded"}`
                       : `console-only until it has an owner and runbook${det.runbook ? " — " + det.runbook : ""}` } }),
      ]),
      el("td", { class: "num", text: String(det.fired ?? "—") }),
      el("td", { class: "num", text: String(det.acted ?? "—") }),
    ]));
  }
  // US-3: a fix that named a detector fires its flash on THIS fresh render.
  registryApplyFlash();
}

function anRenderSeverity(sc) {
  const box = document.getElementById("an-sev");
  if (!box) return;
  box.replaceChildren();
  const counts = (sc && sc.available) ? (sc.counts || []) : [];
  if (!counts.length) {
    box.appendChild(el("span", { class: "muted", text: sc && !sc.available
      ? `Severity counts unavailable \u2014 ${sc.reason || "the read did not run"}.`
      : "No anomalies in this window to split by severity." }));
    return;
  }
  for (const c of counts) {
    const sev = String(c.severity || "unknown");
    const active = AN_FILTERS.severity === sev;
    const tile = el("button", { class: "tile" + (active ? " active" : ""),
      attrs: { title: active ? "click to remove this filter" : `filter the page to ${sev}` } },
      statCells(sev, String(c.count), { vClass: "sev-" + sev }));
    tile.addEventListener("click", () => anSetFilter("severity", active ? "" : sev));
    box.appendChild(tile);
  }
}

function anSetFilter(field, value) {
  AN_FILTERS[field] = String(value || "");
  anRenderChips();
  loadAnomalies().catch(showError);
}

function anClearAllFilters() {
  AN_FILTERS.host = "";
  AN_FILTERS.severity = "";
  AN_FILTERS.model = "";
  AN_FILTERS.feature = "";
  ARRIVED_FROM_LINK = false;
  const min = document.getElementById("f-min-score");
  if (min) min.value = "0";
  for (const id of ["f-unreviewed", "f-watched"]) {
    const box = document.getElementById(id);
    if (box) box.checked = false;
  }
  loadAnomalies().then(clearError).catch(showError);
}

async function loadAnomalies() {
    scheduleURLSync();
  // THE DEFAULT IS THE OBSERVATION LIST, matching the Network graph's alerted badge. Incidents
  // and Leads are explicit queue views over the same evidence; they are opt-in so the map and
  // the list cannot appear to describe different networks. The raw table has its own filters,
  // so the episode branch must not pretend those filters apply to episodes.
  const queueMode = (document.getElementById("f-queue-mode") || {}).value || "raw";
  if (queueMode !== "raw") {
    await loadEpisodeQueue(queueMode);
    return;
  }
  const episodesTable = document.getElementById("episodes-table");
  if (episodesTable) episodesTable.classList.add("hidden");
  const anomaliesTable = document.getElementById("anomalies-table");
  if (anomaliesTable) anomaliesTable.classList.remove("hidden");
  const sevBox = document.getElementById("an-sev");
  if (sevBox) sevBox.classList.remove("hidden");
  const note = document.getElementById("an-queue-note");
  if (note) note.textContent = "";
  // The gate's state rides along with the list, so every row's block control can say whether it
  // would do anything. Fetched BEFORE the rows render: a control that appears and then changes
  // shape is worse than one that appears a beat late.
  await loadGateState();
  const min = document.getElementById("f-min-score").value || "0";
  const limit = document.getElementById("f-limit").value || "100";
  const unrev = document.getElementById("f-unreviewed");
  const unreviewedOnly = !!(unrev && unrev.checked);
  const wchk = document.getElementById("f-watched");
  const watchedOnly = !!(wchk && wchk.checked);
  anRenderChips();
  const payload = await getJSON(API.anomalies(min, limit, unreviewedOnly) + anQuery()
    + (watchedOnly ? "&watched=1" : ""));
  anRenderSeverity(payload.severity_counts);
  anRenderDiscipline(payload.discipline);
  await loadDetectors();
  // THE FILTER'S HONESTY RIDES THE PAYLOAD: when the watch store could not be read, the
  // checkbox turns itself off, says why, and never filters on a state nobody read.
  if (wchk) {
    const watchErr = payload.watch_error;
    wchk.disabled = !!watchErr;
    if (watchErr) wchk.checked = false;
    wchk.title = watchErr ? "the watch list is unavailable: " + watchErr
                          : "only hosts on the watch list";
  }
  const rows = payload.rows || [];

  const tbody = document.querySelector("#anomalies-table tbody");
  tbody.replaceChildren();
  if (!rows.length) {
    const filtered = !!(AN_FILTERS.host || AN_FILTERS.severity || AN_FILTERS.model
                        || AN_FILTERS.feature || Number(min) > 0 || unreviewedOnly || watchedOnly);
    const note = unreviewedOnly
      ? (Number(min) > 0
          ? `No unreviewed anomalies at or above score ${min}.`
          : "No unreviewed anomalies — everything has been triaged.")
      : (Number(min) > 0
          ? `No anomalies at or above score ${min}.`
          : "No anomalies recorded yet — rows land as scan windows complete.");
    emptyRow(tbody, 12, note, filtered
      ? { label: "Clear filters", fn: () => anClearAllFilters() }
      : null);
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
      el("td", { class: "mono an-stamp", text: fmtCompactTime(a.detected_at) }),
      el("td", { class: "mono an-stamp", text: fmtCompactTime(a.window_start) }),
      // US-4: the expansion cue rides the cell at rest (chevron + aria-expanded), and the
      // handler exists for EVERY n -- with n==1 the cell used to be inert while a chip beside
      // it pointed at it as the target, a dead end for the server's single-occurrence case.
      el("td", { class: "num dcell expander",
                 attrs: { title: anReviewSummary(a).title + " \u2014 click to list them",
                          "aria-expanded": "false" },
                 on: { click: (e) => {
                   e.stopPropagation();
                   anToggleOccurrences(e.target.closest("tr"), a);
                 } } }, [
        el("span", { class: "an-count", text: String(a.n || 1) }),
      ]),
      el("td", { class: "dcell", attrs: { "aria-label": "open this host's view" },
                 on: { click: (e) => { e.stopPropagation(); openHost(a.src_addr); } } },
         [hostCell(a.src_addr, ""),
          a.watched ? el("span", { class: "watch-mark", text: " \u25cf",
                                   title: "on the watch list" }) : null]),
      el("td", { class: "mono an-hostname", text: a.hostname || "—" }),
      el("td", { class: "mono", text: (a.anomaly_score ?? 0).toFixed(3) }),
      el("td", { class: "dcell", attrs: { title: "filter the queue to this severity" },
                 on: { click: (e) => { e.stopPropagation(); anSetFilter("severity", a.severity); } } },
         [sevCell(a.severity)]),
      // US-5: each name in the models cell is an entity -- clicking one filters the queue to
      // that detector (the quiet-a-noisy-detector job's entry, beside the registry strip's).
      el("td", { class: "mono" }, [
        el("div", { class: "an-models-clamp" }, String(a.detected_by_models || "—").split(",")
          .flatMap((nm, i, arr) => {
            const clean = nm.trim();
            const parts = [];
            if (clean) {
              const piece = el("span", { class: "dcell",
                                         attrs: { title: "show only this detector's alerts" },
                                         text: clean });
              piece.addEventListener("click", (e) => {
                e.stopPropagation();
                anSetFilter("model", clean);
              });
              parts.push(piece);
            }
            if (i < arr.length - 1) parts.push(el("span", { text: ", " }));
            return parts;
          })),
      ]),
      // WHERE IT HAPPENED (operator, 2026-10-19: "replace owner with location: weirling
      // name and network"). The server resolves it from the fleet's declared segments; a host
      // outside every segment says "unplaced" rather than naming a sensor that cannot see it.
      el("td", { class: a.location ? "mono" : "muted",
                 text: a.location
                   ? `${a.location.weirling} · ${a.location.network_name || a.location.network}`
                   : "unplaced",
                 attrs: { title: a.location
                   ? `${a.location.weirling} sees ${a.location.network_name
                       ? `${a.location.network_name} (${a.location.network})` : a.location.network
                     }, which contains this host`
                   : "no weirling declares a network containing this address" } }),
      el("td", { class: "muted an-rule", text: a.matched_rule || "—",
                 attrs: { title: "what matched, from the detector registry" } }),
      el("td", {}, [
        el("div", { class: "an-why-clamp" }, [
          el("div", { text: a.baseline_comparison || "—" }),
          a.primary_deviation_feature ? el("div", { class: "dcell mono",
            text: "feature: " + a.primary_deviation_feature,
            on: { click: (e) => { e.stopPropagation();
              anSetFilter("feature", a.primary_deviation_feature); } } }) : null,
          a.severity_basis ? el("div", { class: "muted", text: "severity: " + a.severity_basis }) : null,
          contributing ? el("div", { class: "muted mono", text: contributing }) : null,
          // US-9: the STABLE reason code. The why-sentence reads; this one is greppable.
          a.reason_code ? el("div", { class: "reason-code mono",
            attrs: { title: "stable reason code: detector initials + the measurement that moved" },
            text: a.reason_code }) : null,
        ]),
      ]),
      el("td", {}, [el("div", { class: "an-actions-row" }, [
        reviewCell(a), rowMore(a, a.review_state || ""),
      ])]),
    ]));
  }

  // US-6: "showing X of Y" -- the header says WHY the list may look short. X counts the
  // occurrences on screen (grouped rows carry n); Y is the unfiltered count under the same
  // min-score, from the server. When filters are off the line just states the count.
  const countLine = document.getElementById("an-count-line");
  if (countLine) {
    const x = rows.reduce((s, r) => s + Number(r.n || 1), 0);
    const y = Number(payload.total_unfiltered);
    const filtered = !!(AN_FILTERS.host || AN_FILTERS.severity || AN_FILTERS.model
                        || AN_FILTERS.feature);
    countLine.textContent = (filtered && Number.isFinite(y))
      ? `showing ${x} of ${y} alerts \u2014 filters are on`
      : `${x} alert${x === 1 ? "" : "s"} on screen`;
  }
}

/* THE INCIDENT QUEUE. One row per episode; the raw window list stays under All anomalies.
 *
 * The server decides what is an incident: high/critical, pageable, and backed by either a named
 * primary deviation or at least one independent strong family. A model-only episode is a lead,
 * not work that can page a human. The table deliberately carries the measured signal so the
 * operator does not have to open every row to learn whether there is anything to read.
 */
async function loadEpisodeQueue(mode) {
  const payload = await getJSON(`${API.episodes}?hours=${encodeURIComponent(trHours())}&limit=200`);
  const table = document.getElementById("episodes-table");
  const anomalies = document.getElementById("anomalies-table");
  const sevBox = document.getElementById("an-sev");
  const note = document.getElementById("an-queue-note");
  if (table) table.classList.remove("hidden");
  if (anomalies) anomalies.classList.add("hidden");
  if (sevBox) sevBox.classList.add("hidden");
  const tbody = document.querySelector("#episodes-table tbody");
  if (!tbody) return;
  tbody.replaceChildren();
  const counts = payload.counts || {};
  const countLine = document.getElementById("an-count-line");
  if (payload.available !== true) {
    const why = payload.reason || "the episode view is unavailable";
    emptyRow(tbody, 11, `The queue cannot be read: ${why}. Raw anomalies remain available.`);
    if (note) note.textContent = "";
    if (countLine) countLine.textContent = "";
    return;
  }
  const rows = Array.isArray(payload[mode]) ? payload[mode] : [];
  if (note) {
    note.textContent = mode === "incidents"
      ? "Incidents: high/critical, pageable episodes with measured evidence. Leads stay one selection away; All anomalies keeps every scored window."
      : "Leads: low/medium observations and high/critical episodes without a named feature or independent family. They are evidence to hunt, not a page.";
  }
  if (countLine) {
    countLine.textContent = `${counts.incidents ?? 0} incident${counts.incidents === 1 ? "" : "s"} · `
      + `${counts.leads ?? 0} lead${counts.leads === 1 ? "" : "s"} · ${counts.episodes ?? 0} episode`
      + `${counts.episodes === 1 ? "" : "s"} in the window`
      + (payload.evidence_error ? " · evidence read failed" : "");
  }
  if (!rows.length) {
    emptyRow(tbody, 11, mode === "incidents"
      ? "No incident episodes in this window. Leads and raw anomalies are still available."
      : "No leads in this window.");
    return;
  }
  for (const e of rows) {
    const feature = e.primary_feature
      ? `${e.primary_feature}${e.strong_families ? ` · ${e.strong_families} families` : ""}`
      : (e.strong_families ? `${e.strong_families} independent families` : "no measured signal");
    const page = e.pageable ? "pageable" : "not pageable";
    const reason = `${page}${e.page_reason ? ` · ${e.page_reason}` : ""}`
      + (e.queue_reason ? ` · ${e.queue_reason}` : "");
    tbody.appendChild(el("tr", {
      class: "clickable",
      attrs: { "aria-label": "Open the raw evidence for this episode's page window" },
      on: { click: () => openEvidence({
        src_addr: e.src_addr,
        window_start: e.page_window || e.episode_start,
        window_end: e.episode_end,
      }) },
    }, [
      el("td", { class: "mono", text: fmtTime(e.last_detected) }),
      el("td", { class: "mono", text: fmtTime(e.episode_start) }),
      el("td", { class: "num", text: String(e.window_count ?? e.occurrences ?? "—") }),
      el("td", { class: "dcell", attrs: { "aria-label": "open this host's view" },
                 on: { click: (ev) => { ev.stopPropagation(); openHost(e.src_addr); } } },
         [hostCell(e.src_addr, "")]),
      el("td", { class: "mono", text: e.hostname || "—" }),
      el("td", {}, [sevCell(e.severity)]),
      el("td", { class: "mono", text: Number(e.max_score ?? 0).toFixed(3) }),
      el("td", { class: e.primary_feature ? "" : "muted", text: feature }),
      el("td", { class: "muted", text: reason }),
      el("td", { class: "mono", text: e.role || "unknown" }),
      el("td", { class: "mono", text: "open" }),
    ]));
  }
}

/* ── host drill-down ────────────────────────────────────────────────────── */

// ── THE METRIC-TILE RECIPE (TH-5) ────────────────────────────────────────────────────────────
// Label ABOVE the value: the label is what the eye scans for, the number is what it reads.
// Values are tabular (CSS), and a number with a series behind it gets a MICRO SPARKLINE -- the
// current bucket in accent, the past in --chart-area. A number with no series gets no
// sparkline: a made-up shape would be a lie told at twenty pixels tall.
function sparkSvg(points, opts) {
  const o = opts || {};
  const w = o.w || 92, h = o.h || 20;
  const vals = (points || []).map((p) => Number(p) || 0);
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("class", "spark");
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.setAttribute("width", String(w));
  svg.setAttribute("height", String(h));
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-hidden", "true");
  const max = Math.max(1, ...vals);
  const n = Math.max(1, vals.length);
  const bw = w / n;
  vals.forEach((v, i) => {
    const r = document.createElementNS(ns, "rect");
    // A zero bucket keeps a 1.5px stub: a gap must read as "nothing happened", not as a
    // missing element (the host timeline's own rule, at sparkline scale).
    const bh = v === 0 ? 1.5 : Math.max(2, (v / max) * (h - 2));
    r.setAttribute("x", String(i * bw + 0.5));
    r.setAttribute("y", String(h - bh));
    r.setAttribute("width", String(Math.max(1, bw - 1.5)));
    r.setAttribute("height", String(bh));
    r.setAttribute("class", i === vals.length - 1 ? "cur" : "rest");
    svg.appendChild(r);
  });
  return svg;
}

/** The children of one stat cell, in reading order: label, value, sparkline (when earned).
 *  opts: { vClass, series, sparkTitle }. */
function statCells(k, v, opts) {
  const o = opts || {};
  const cells = [
    el("div", { class: "k", text: String(k) }),
    el("div", { class: "v" + (o.vClass ? " " + o.vClass : ""), text: String(v) }),
  ];
  if (o.series && o.series.length) cells.push(sparkSvg(o.series, { title: o.sparkTitle }));
  return cells;
}

/* ── FINDINGS: the scanner's recorded evidence ─────────────────────────────────────────────── */
/* A drill, not a tab. The Assets exposure cell and the host scanner card open it; the Assets
 * tab stays lit behind it. Findings are historical, so the global time window deliberately does
 * not hide them -- a finding from last week is still a fact about the host today. */
const FINDINGS_STATE = { ip: "", severity: "", data: null };

async function loadFindings() {
  scheduleURLSync();
  const data = await getJSON(API.findings(FINDINGS_STATE.ip, FINDINGS_STATE.severity));
  FINDINGS_STATE.data = data;
  renderFindings();
}

function renderFindings() {
  const tbody = document.querySelector("#fd-table tbody");
  const summary = document.getElementById("fd-summary");
  const stats = document.getElementById("fd-stats");
  const note = document.getElementById("fd-note");
  const empty = document.getElementById("fd-empty");
  const hostFilter = document.getElementById("fd-host-filter");
  const sev = document.getElementById("fd-severity");
  if (!tbody || !summary || !stats || !note || !empty) return;

  const view = document.getElementById("view-findings");
  if (view) view.dataset.loaded = "1";
  const title = document.getElementById("fd-title");
  if (title) title.textContent = "Findings";
  const d = FINDINGS_STATE.data || {};
  tbody.replaceChildren();
  note.replaceChildren();
  empty.textContent = "";
  if (sev && sev.value !== FINDINGS_STATE.severity) sev.value = FINDINGS_STATE.severity;
  if (hostFilter) {
    hostFilter.replaceChildren();
    hostFilter.classList.toggle("hidden", !FINDINGS_STATE.ip);
    if (FINDINGS_STATE.ip) {
      hostFilter.appendChild(el("span", { text: `host: ${FINDINGS_STATE.ip}` }));
      const clear = el("button", { class: "quiet", text: "clear", attrs: { type: "button" } });
      clear.addEventListener("click", () => { FINDINGS_STATE.ip = ""; loadFindings().catch(showError); });
      hostFilter.appendChild(clear);
    }
  }
  if (d.available === false) {
    summary.textContent = "unavailable";
    stats.replaceChildren();
    note.appendChild(el("p", { class: "warn",
      text: `Findings could not be read: ${d.reason || "unknown error"}. This is not a clean result.` }));
    return;
  }
  const rows = d.findings || [];
  const counts = d.counts || {};
  summary.textContent = `${rows.length} finding${rows.length === 1 ? "" : "s"}` +
    (FINDINGS_STATE.ip ? ` for ${FINDINGS_STATE.ip}` : "") +
    (FINDINGS_STATE.severity ? ` at ${FINDINGS_STATE.severity}` : "");
  stats.replaceChildren(...[
    ["findings", String(counts.total || rows.length)],
    ["critical", String(counts.critical || 0)],
    ["high", String(counts.high || 0)],
    ["medium", String(counts.medium || 0)],
    ["low", String(counts.low || 0)],
  ].map(([k, v]) => el("div", { class: "stat" }, [
    el("div", { class: "k", text: k }), el("div", { class: "v", text: v }),
  ])));
  if (!rows.length) {
    empty.textContent = FINDINGS_STATE.ip || FINDINGS_STATE.severity
      ? "No recorded findings match this filter. A clear finding set is not proof the host is patched."
      : "No recorded findings. A clear finding set is not proof the host is patched.";
    return;
  }
  for (const f of rows) {
    const tr = el("tr", { class: "clickable", attrs: { title: `open ${f.ip} on the host page` } }, [
      el("td", {}, [sevCell(f.severity)]),
      el("td", {}, [el("span", { class: "mono", text: f.ip || "—" }),
                    f.hostname ? el("span", { class: "muted", text: ` · ${f.hostname}` }) : null]),
      el("td", { text: f.name || "—", attrs: { title: f.remediation || "" } }),
      el("td", { class: "mono muted", text: f.template_id || "—" }),
      el("td", { class: "mono muted", text: f.last_seen ? fmtTime(f.last_seen) : "—" }),
    ]);
    tr.addEventListener("click", () => openHost(f.ip));
    tbody.appendChild(tr);
  }
}

function openFindings(ip = "") {
  FINDINGS_STATE.ip = String(ip || "").trim();
  FINDINGS_STATE.severity = "";
  showView("findings");
}

// One wiring pass: the controls exist after the markup is parsed, and a second listener would
// fire the same query twice on every change.
const FD_BACK = document.getElementById("fd-back");
if (FD_BACK) FD_BACK.addEventListener("click", () => showView("assets"));
const FD_SEVERITY = document.getElementById("fd-severity");
if (FD_SEVERITY) {
  FD_SEVERITY.addEventListener("change", () => {
    FINDINGS_STATE.severity = String(FD_SEVERITY.value || "");
    loadFindings().catch(showError);
  });
}

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
    // bytes and flows have a series behind them (the timeline); the rest do not and get no
    // sparkline. The series rides the tile the number belongs to, never a second query.
    const tl = d.timeline || [];
    const items = [
      ["bytes", fmtBytes(t.bytes), tl.map((b) => b.bytes)],
      ["packets", String(t.packets ?? "—")],
      ["flows", String(t.flows ?? "—"), tl.map((b) => b.flows)],
      ["destinations", String(t.unique_destinations ?? "—")],
      ["dest ports", String(t.unique_ports ?? "—")],
      ["last seen", fmtTime(t.last_seen)],
    ];
    for (const [k, v, series] of items) {
      stats.appendChild(el("div", { class: "stat" }, statCells(k, v, { series })));
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
  if (!d.top_destinations.length) emptyRow(dests, 4, "No destinations recorded in this window — an empty window is not zero traffic.");
  for (const x of d.top_destinations) {
    dests.appendChild(el("tr", {}, [
      el("td", { class: "dcell", attrs: { title: "open this destination's host view" },
                 on: x.dst_addr === d.src_addr ? {} : { click: () => openHost(x.dst_addr) } },
         [hostCell(x.dst_addr, x.hostname, d.src_addr)]),
      el("td", { class: "mono", text: fmtBytes(x.bytes) }),
      el("td", { class: "mono", text: String(x.flows ?? "—") }),
      el("td", { class: "mono", text: String(x.ports ?? "—") }),
    ]));
  }

  const ports = document.querySelector("#h-ports tbody");
  ports.replaceChildren();
  if (!d.top_ports.length) emptyRow(ports, 4, "No ports recorded in this window — an empty window is not zero traffic.");
  for (const x of d.top_ports) {
    ports.appendChild(el("tr", { class: "clickable",
                                 attrs: { title: "show flows to this port in the Netflow view" },
                                 on: { click: () => {
                                   showView("netflow");
                                   if (typeof nfSetFilter === "function") {
                                     nfSetFilter("dport", x.dst_port, ":" + x.dst_port);
                                   }
                                 } } }, [
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
    emptyRow(zeek, 3, "No Zeek service data in this window (the sensor may be disabled) — an empty window is not zero traffic.");
  } else {
    for (const s of d.zeek_services) {
      zeek.appendChild(el("tr", { class: "clickable",
                                  attrs: { title: "open this service's log in the Zeek view" },
                                  on: { click: () => {
                                    showView("zeek");
                                    if (typeof loadZeekLog === "function") {
                                      loadZeekLog(s.service).catch(showError);
                                    }
                                  } } }, [
        el("td", { text: s.service }),
        el("td", { class: "mono", text: String(s.conns ?? "—") }),
        el("td", { class: "mono", text: fmtBytes(s.bytes) }),
      ]));
    }
  }

  const anoms = document.querySelector("#h-anoms tbody");
  anoms.replaceChildren();
  if (!d.anomalies.length) {
    emptyRow(anoms, 5, `No anomalies for this host in the last ${d.hours}h — an empty window is not zero traffic.`);
  }
  for (const a of d.anomalies) {
    anoms.appendChild(el("tr", { class: "clickable",
                                 attrs: { title: "open the evidence for this anomaly" },
                                 on: { click: () => openEvidence(Object.assign({}, a,
                                                                              { src_addr: d.src_addr })) } }, [
      el("td", { class: "mono", text: fmtTime(a.detected_at) }),
      el("td", { class: "mono", text: (a.anomaly_score ?? 0).toFixed(3) }),
      el("td", {}, [sevCell(a.severity)]),
      el("td", { class: "mono", text: a.detected_by_models || "—" }),
      el("td", { text: a.baseline_comparison || a.primary_deviation_feature || "—" }),
    ]));
  }

  // US-6: the labeled exit, only for JOURNEYS (openHost) -- a fresh lookup in the box is not
  // somewhere you came from. The label names the DESTINATION, not "back". The visible button
  // is the one exit; no blue crumb duplicates it.
  if (CURRENT_VIEW === "assets" || CURRENT_VIEW === "host") {
    HOST_RETURN.pending = false;
    const back = document.getElementById("hp-back");
    if (back) back.textContent = evidenceBackLabel(HOST_RETURN.view || "assets");
  }
}

const HP_BACK = document.getElementById("hp-back");
if (HP_BACK) {
  HP_BACK.addEventListener("click", () => {
    if (HOST_RETURN && HOST_RETURN.view === "host" && HOST_RETURN.addr) {
      // A peer opened from a host page: go back to the prior host, then let THAT host's
      // parent (the view the first host was opened from) own its own Back label.
      const previous = HOST_RETURN;
      HOST_RETURN = previous.parent || { pending: false, view: "assets", scroll: 0 };
      showView("host");
      loadHost(previous.addr, String(trHours())).catch(showError);
      loadHostPage(previous.addr).catch(showError);
      return;
    }
    if (HOST_RETURN && HOST_RETURN.view) {
      returnWithScroll(HOST_RETURN.view, HOST_RETURN.scroll);
    } else {
      showView("assets");
    }
  });
}

function openHost(addr) {
  if (!addr) return;
  if (CURRENT_VIEW === "host" && HP_ADDR && String(HP_ADDR) !== String(addr)) {
    // A peer opened FROM a host page. Keep the previous host as the parent so Back returns
    // to the host the analyst was reading, not all the way out to Assets. The first host's
    // own parent (the view it was opened from) rides along unchanged.
    HOST_RETURN = { pending: true, view: "host", addr: HP_ADDR,
                    scroll: Number(window.scrollY || 0), parent: HOST_RETURN };
  } else if (CURRENT_VIEW && CURRENT_VIEW !== "assets" && CURRENT_VIEW !== "host") {
    // Remember where the jump started -- the labeled way back needs it, and so does the scroll.
    HOST_RETURN = { pending: true, view: CURRENT_VIEW, scroll: Number(window.scrollY || 0) };
  } else {
    // A fresh lookup is not a journey; the way back is the Assets tab itself. Keep the
    // destination explicit so the visible Back button never falls through to a dead end.
    HOST_RETURN = { pending: false, view: "assets", scroll: 0 };
  }
  showView("host");
  // The legacy drill-down still renders (its DOM lives in Assets) so every existing pivot and
  // test that reads it keeps working while the new page is the surface an operator sees.
  loadHost(addr, String(trHours())).catch(showError);
  loadHostPage(addr).catch(showError);
}

/* ── THE HOST PAGE (operator, 2026-10-19) ──────────────────────────────────────────────────
 * One address per page: who it is, what it talked to, and the four evidence families the
 * operator named -- network connections, NetFlow, DNS, Zeek -- each with its own panel. The
 * Assets tab is an inventory; this is the investigation surface an alert's host click needs.
 */
let HP_ADDR = "";

async function loadHostPage(addr) {
  HP_ADDR = String(addr || "").trim();
  // THE HOST IS A LOCATION. Write it as soon as it is known, not after a successful read:
  // a slow/empty host page must still be reloadable and shareable.
  scheduleURLSync();
  const hostView = document.getElementById("view-host");
  if (hostView) hostView.dataset.addr = HP_ADDR;
  const title = document.getElementById("hp-title");
  const sub = document.getElementById("hp-sub");
  if (!HP_ADDR) return;
  if (title) title.textContent = HP_ADDR;
  if (sub) sub.textContent = "loading…";
  const hours = String(trHours());
  let d;
  try {
    d = await getJSON(`/api/host?addr=${encodeURIComponent(HP_ADDR)}&hours=${encodeURIComponent(hours)}`);
  } catch (err) {
    if (sub) sub.textContent = `could not read this host: ${err && err.message ? err.message : err}`;
    return;
  }
  if (sub) sub.textContent = `${d.hostname || "no name observed"} · last ${hours}h`;
  document.getElementById("h-addr").value = HP_ADDR;

  const tot = d.totals || {};
  const stats = document.getElementById("hp-stats");
  if (stats) {
    stats.replaceChildren();
    const cells = [
      ["bytes", fmtBytes(tot.bytes || 0)],
      ["flows", String(tot.flows || 0)],
      ["destinations", String(tot.unique_destinations || 0)],
      ["ports", String(tot.unique_ports || 0)],
      ["last seen", tot.last_seen ? fmtTime(tot.last_seen) : "—"],
    ];
    for (const [k, v] of cells) {
      stats.appendChild(el("div", { class: "stat" }, [
        el("div", { class: "k", text: k }), el("div", { class: "v", text: v }),
      ]));
    }
  }
  hpRenderExternal(d.external);
  hpRenderScanExposure(d.exposure);
  hpRenderGraph(d.top_destinations || []);
  hpRenderFlow(d.timeline || []);
  hpRenderDns(d.dns_queries || []);
  hpRenderZeek(d.zeek_services || []);
  hpRenderDests(d.top_destinations || []);
  hpRenderAnoms(d.anomalies || []);
}

function hpRenderExternal(ext) {
  const card = document.getElementById("hp-external-card");
  const box = document.getElementById("hp-external");
  if (!card || !box) return;
  box.replaceChildren();
  if (!ext || !ext.available) {
    card.classList.add("hidden");
    return;
  }
  card.classList.remove("hidden");
  const n = (v) => (v === null || v === undefined ? "\u2014" : Number(v).toLocaleString());
  const pct = (v) => (v === null || v === undefined ? "\u2014" : `${Math.round(Number(v) * 100)}%`);
  const bytes = (v) => (v === null || v === undefined ? "\u2014" : fmtBytes(Number(v) || 0));
  const direction = (label, d) => {
    const data = d || {};
    const prefixes = Array.isArray(data.top_prefixes) ? data.top_prefixes.slice(0, 3) : [];
    return el("div", { class: "ext-card" }, [
      el("div", { class: "ext-k", text: label }),
      el("div", { class: "ext-v", text: `${n(data.peers)} peer address${data.peers === 1 ? "" : "es"}` }),
      el("div", { class: "ext-m muted",
        text: `${bytes(data.bytes)} · ${n(data.flows)} flow(s) · top peer ${pct(data.top_peer_share)}` }),
      prefixes.length ? el("div", { class: "ext-prefix-list" },
        prefixes.map((p) => el("div", { class: "ext-prefix-row" }, [
          el("span", { class: "mono", text: p.prefix || "\u2014" }),
          el("span", { class: "muted", text: `${n(p.peers)} peer(s) · ${bytes(p.bytes)}` }),
        ]))) : null,
    ].filter(Boolean));
  };
  const grid = el("div", { class: "ext-grid" });
  grid.appendChild(direction("Inbound from external", ext.inbound));
  grid.appendChild(direction("Outbound to external", ext.outbound));
  box.appendChild(grid);
  if (ext.errors && ext.errors.length) {
    box.appendChild(el("div", { class: "ext-error muted",
      text: `Some readings are unavailable: ${ext.errors.join("; ")}` }));
  }
}

/** The host page's scanner card: the services Nmap saw and the findings recorded against them.
 *
 * THE THREE STATES MUST STAY SEPARATE. No registry row/`pending` is "not scanned"; a done scan
 * with no findings is "clear"; a failed scan is "failed". None of them is proof the host is
 * patched -- Nmap banners are hints, and the findings table is historical (Nuclei is off).
 */
function hpRenderScanExposure(exp) {
  const card = document.getElementById("hp-scan-card");
  const box = document.getElementById("hp-scan");
  if (!card || !box) return;
  box.replaceChildren();
  if (!exp) {
    card.classList.add("hidden");
    return;
  }
  card.classList.remove("hidden");
  if (exp.available === false) {
    box.appendChild(el("p", { class: "muted",
      text: `Scanned exposure is unavailable: ${exp.reason || "the scanner read failed"}. ` +
            "This is not a clean result." }));
    return;
  }
  const band = String(exp.exposure || "unknown");
  const cls = ["critical", "high"].includes(band) ? "bad"
    : band === "medium" ? "warn" : "muted";
  const counts = exp.counts || {};
  const total = Number(counts.total || 0);
  // A done scan that observed no service is a measured zero. A host with no scanner record
  // is not measured, so it keeps the em dash.
  const serviceCount = exp.registered === false ? null
    : (Array.isArray(exp.services) ? exp.services.length : null);
  const stats = el("div", { class: "stats" }, [
    el("div", { class: "stat" }, [
      el("div", { class: "k", text: "exposure" }),
      el("div", { class: "v" }, [el("span", { class: `chip ${cls}`, text: band })]),
    ]),
    el("div", { class: "stat" }, [
      el("div", { class: "k", text: "services" }),
      el("div", { class: "v", text: serviceCount === null ? "—" : String(serviceCount) }),
    ]),
    el("div", { class: "stat" }, [
      el("div", { class: "k", text: "findings" }),
      el("div", { class: "v", text: total ? String(total) : "0" }),
    ]),
    el("div", { class: "stat" }, [
      el("div", { class: "k", text: "last scan" }),
      el("div", { class: "v", text: exp.last_scan ? fmtTime(exp.last_scan) : "—" }),
    ]),
  ]);
  box.appendChild(stats);

  if (exp.registered === false) {
    box.appendChild(el("p", { class: "muted",
      text: "No scanner record for this address. It has not been scanned — that is not the same " +
            "as clear." }));
  } else {
    box.appendChild(el("p", { class: "muted",
      text: `Scan state: ${exp.state || "unknown"}${exp.last_scan ? ` · last completed ${fmtTime(exp.last_scan)}` : ""}. ` +
            "Nmap service banners are hints, not proof of patch level." }));
    if (exp.error) {
      box.appendChild(el("p", { class: "muted", text: `Last scan error: ${exp.error}` }));
    }
  }

  const services = exp.services || [];
  if (services.length) {
    const table = el("table", {}, [
      el("thead", {}, [el("tr", {}, [
        el("th", { text: "port" }), el("th", { text: "proto" }), el("th", { text: "service" }),
        el("th", { text: "product / version" }),
      ])]),
      el("tbody", {}, services.slice(0, 30).map((x) => el("tr", {}, [
        el("td", { class: "mono", text: String(x.port ?? "—") }),
        el("td", { class: "mono", text: x.protocol || "—" }),
        el("td", { text: x.service || "—" }),
        el("td", { class: "muted",
          text: [x.product, x.version].filter(Boolean).join(" ") || "—" }),
      ]))),
    ]);
    if (services.length > 30) {
      box.appendChild(el("p", { class: "muted",
        text: `Showing 30 of ${services.length} observed services.` }));
    }
    box.appendChild(table);
  } else {
    box.appendChild(el("p", { class: "muted",
      text: exp.registered === false ? "No services recorded — the host has not been scanned."
        : "No open services recorded by the last successful scan." }));
  }

  const findings = exp.findings || [];
  if (findings.length) {
    const table = el("table", {}, [
      el("thead", {}, [el("tr", {}, [
        el("th", { text: "severity" }), el("th", { text: "finding" }),
        el("th", { text: "template" }), el("th", { text: "last seen" }),
      ])]),
      el("tbody", {}, findings.slice(0, 30).map((f) => el("tr", {}, [
        el("td", {}, [sevCell(f.severity)]),
        el("td", { text: f.name || "—", attrs: { title: f.remediation || "" } }),
        el("td", { class: "mono muted", text: f.template_id || "—" }),
        el("td", { class: "mono muted", text: f.last_seen ? fmtTime(f.last_seen) : "—" }),
      ]))),
    ]);
    if (findings.length > 30) {
      box.appendChild(el("p", { class: "muted",
        text: `Showing 30 of ${findings.length} recorded findings.` }));
    }
    box.appendChild(table);
  } else if (exp.registered !== false) {
    box.appendChild(el("p", { class: "muted",
      text: "No recorded findings for this host. A clear finding set is not proof the host is patched." }));
  }

  if (exp.registered !== false) {
    const scan = el("button", { class: "quiet", text: "Scan now", attrs: { type: "button" } });
    scan.addEventListener("click", () => requestScan(HP_ADDR, scan));
    const findings = el("button", { class: "quiet", text: "Open findings", attrs: { type: "button" } });
    findings.addEventListener("click", () => openFindings(HP_ADDR));
    box.appendChild(el("div", { class: "controls" }, [scan, findings]));
  }
}

/** A host-page measurement becomes a filtered destination view, keeping the global range. */
function hpPivot(view, apply) {
  // Set the destination's filter BEFORE switching: the switch issues the load that must carry
  // it. The reverse order lets the unfiltered load land after the filtered one.
  if (typeof apply === "function") apply();
  showView(view);
}

function hpPivotNetflow(field, value, label) {
  hpPivot("netflow", () => {
    if (typeof nfSetFilter === "function") nfSetFilter(field, value, label || value);
  });
}

function hpPivotDns(query) {
  hpPivot("dns", () => {
    if (typeof dnApply === "function") {
      dnApply([["dn-client", HP_ADDR], ["dn-domain", query]]);
    }
  });
}

function hpPivotZeek(service) {
  hpPivot("zeek", () => {
    if (typeof zkSetFilters !== "function" || !service) return;
    // KEEP THE HOST. "ssl on this host" and "ssl anywhere on the fleet" are different
    // investigations; the host page owns the former. One read for the complete state.
    zkSetFilters([["host", HP_ADDR, HP_ADDR], ["service", service, service]]);
  });
}

function hpPivotEvidence(anomaly) {
  if (typeof openEvidence === "function") {
    openEvidence(Object.assign({}, anomaly, { src_addr: HP_ADDR }));
  }
}

/** Evidence rows are doors too: DNS name -> host+name filter, Zeek service -> host+service,
 *  JA4 -> the fingerprint lookup. Each target is made visible before the pivot applies. */
function evidencePivotDns(addr, query) {
  if (!query) return;
  if (typeof dnApply === "function") {
    dnApply([["dn-client", addr], ["dn-domain", query]]);
  }
  showView("dns");
}

function evidencePivotZeek(addr, service) {
  if (!service) return;
  if (typeof zkSetFilters === "function") {
    zkSetFilters([["host", addr, addr], ["service", service, service]]);
  }
  showView("zeek");
}

function evidencePivotJa4(ja4) {
  if (!ja4) return;
  showView("assets");
  const input = document.getElementById("fp-input");
  const go = document.getElementById("fp-go");
  if (input) input.value = ja4;
  if (go) go.click();
}

function hpRenderGraph(dests) {
  const box = document.getElementById("hp-graph");
  if (!box) return;
  box.replaceChildren();
  const list = (dests || []).slice(0, 12);
  if (!list.length) {
    box.appendChild(el("p", { class: "muted", text: "No conversations observed for this host in the window." }));
    return;
  }
  const NS = "http://www.w3.org/2000/svg";
  const w = 640, h = 300, cx = w / 2, cy = h / 2;
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.setAttribute("class", "hp-network");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", `connections from ${HP_ADDR} to ${list.length} peers`);
  const maxB = Math.max(1, ...list.map((x) => Number(x.bytes) || 0));
  list.forEach((dst, i) => {
    const ang = (Math.PI * 2 * i) / list.length - Math.PI / 2;
    const x = cx + Math.cos(ang) * 190, y = cy + Math.sin(ang) * 120;
    const line = document.createElementNS(NS, "line");
    line.setAttribute("x1", cx); line.setAttribute("y1", cy);
    line.setAttribute("x2", x); line.setAttribute("y2", y);
    line.setAttribute("stroke", "var(--border)");
    line.setAttribute("stroke-width", String(1 + 4 * (Number(dst.bytes) || 0) / maxB));
    svg.appendChild(line);
    const node = document.createElementNS(NS, "circle");
    node.setAttribute("cx", x); node.setAttribute("cy", y);
    node.setAttribute("r", String(4 + 8 * (Number(dst.bytes) || 0) / maxB));
    node.setAttribute("class", "hp-node");
    const ttl = document.createElementNS(NS, "title");
    ttl.textContent = `${dst.dst_addr}${dst.hostname ? " (" + dst.hostname + ")" : ""} — ${fmtBytes(dst.bytes || 0)}, ${dst.flows || 0} flows — click to open this host`;
    node.appendChild(ttl);
    node.setAttribute("class", "hp-node clickable");
    node.setAttribute("role", "button");
    node.setAttribute("tabindex", "0");
    node.addEventListener("click", (event) => {
      event.stopPropagation();
      openHost(dst.dst_addr);
    });
    node.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openHost(dst.dst_addr);
      }
    });
    svg.appendChild(node);
    const label = document.createElementNS(NS, "text");
    label.setAttribute("x", String(x + (x >= cx ? 10 : -10)));
    label.setAttribute("y", String(y + 4));
    label.setAttribute("text-anchor", x >= cx ? "start" : "end");
    label.setAttribute("class", "hp-label clickable");
    label.setAttribute("role", "button");
    label.setAttribute("tabindex", "0");
    label.textContent = dst.hostname || dst.dst_addr;
    label.addEventListener("click", (event) => {
      event.stopPropagation();
      openHost(dst.dst_addr);
    });
    label.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openHost(dst.dst_addr);
      }
    });
    svg.appendChild(label);
  });
  const center = document.createElementNS(NS, "circle");
  center.setAttribute("cx", cx); center.setAttribute("cy", cy); center.setAttribute("r", "12");
  center.setAttribute("class", "hp-center");
  svg.appendChild(center);
  const clabel = document.createElementNS(NS, "text");
  clabel.setAttribute("x", cx); clabel.setAttribute("y", cy + 28);
  clabel.setAttribute("text-anchor", "middle");
  clabel.setAttribute("class", "hp-label");
  clabel.textContent = HP_ADDR;
  svg.appendChild(clabel);
  box.appendChild(svg);
}

function hpRenderFlow(timeline) {
  const box = document.getElementById("hp-flow");
  if (!box) return;
  box.replaceChildren();
  const rows = timeline || [];
  if (!rows.length) {
    box.appendChild(el("p", { class: "muted", text: "No NetFlow records for this host in the window." }));
    return;
  }
  const max = Math.max(1, ...rows.map((r) => Number(r.bytes) || 0));
  const bars = el("div", { class: "hp-bar-row" });
  for (const r of rows) {
    const v = Number(r.bytes) || 0;
    bars.appendChild(el("div", {
      class: "hp-bar" + (v ? " clickable" : " zero"),
      attrs: {
        "aria-label": v
          ? `${r.hour} — ${fmtBytes(v)}, ${r.flows || 0} flows — open NetFlow filtered to this host`
          : `${r.hour} — no traffic in this bucket`,
        role: v ? "button" : "presentation",
        tabindex: v ? "0" : null,
        style: `height:${Math.max(2, Math.round((v / max) * 100))}%`,
      },
      on: v ? {
        click: () => hpPivotNetflow("src", HP_ADDR, HP_ADDR),
        keydown: (event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            hpPivotNetflow("src", HP_ADDR, HP_ADDR);
          }
        },
      } : {},
    }));
  }
  box.appendChild(bars);
}

function hpRenderDns(queries) {
  const body = document.querySelector("#hp-dns tbody");
  if (!body) return;
  body.replaceChildren();
  if (!queries.length) {
    emptyRow(body, 4, "No DNS queries observed for this host in the window.");
    return;
  }
  for (const q of queries) {
    body.appendChild(el("tr", {
      class: "clickable",
      attrs: { "aria-label": `filter DNS to ${q.query || "this name"} for ${HP_ADDR}` },
      on: { click: () => hpPivotDns(q.query) },
    }, [
      el("td", { class: "mono link", text: q.query || "—" }),
      el("td", { class: "mono", text: q.qtype || "—" }),
      el("td", { class: "num", text: String(q.asks || 0) }),
      el("td", { class: "num", text: String(q.resolvers || 0) }),
    ]));
  }
}

function hpRenderZeek(services) {
  const body = document.querySelector("#hp-zeek tbody");
  if (!body) return;
  body.replaceChildren();
  if (!services.length) {
    emptyRow(body, 3, "No Zeek sessions observed for this host in the window.");
    return;
  }
  for (const s of services) {
    body.appendChild(el("tr", {
      class: "clickable",
      attrs: { "aria-label": `filter Zeek to ${s.service || "this service"}` },
      on: { click: () => hpPivotZeek(s.service) },
    }, [
      el("td", { class: "mono link", text: s.service || "—" }),
      el("td", { class: "num", text: String(s.conns || 0) }),
      el("td", { class: "num", text: fmtBytes(s.bytes || 0) }),
    ]));
  }
}

function hpRenderDests(dests) {
  const body = document.querySelector("#hp-dests tbody");
  if (!body) return;
  body.replaceChildren();
  if (!dests.length) {
    emptyRow(body, 4, "No destinations observed for this host in the window.");
    return;
  }
  for (const x of dests) {
    body.appendChild(el("tr", {
      class: "clickable",
      attrs: { "aria-label": `show every host talking to ${x.dst_addr} in NetFlow` },
      on: { click: () => hpPivotNetflow("dst", x.dst_addr, x.hostname || x.dst_addr) },
    }, [
      el("td", { class: "mono link", text: x.dst_addr || "—" }),
      el("td", { class: "num", text: fmtBytes(x.bytes || 0) }),
      el("td", { class: "num", text: String(x.flows || 0) }),
      el("td", { class: "num", text: String(x.ports || 0) }),
    ]));
  }
}

function hpRenderAnoms(anoms) {
  const body = document.querySelector("#hp-anoms tbody");
  if (!body) return;
  body.replaceChildren();
  if (!anoms.length) {
    emptyRow(body, 4, "No anomalies recorded for this host in the window.");
    return;
  }
  for (const a of anoms) {
    body.appendChild(el("tr", {
      class: "clickable",
      attrs: { "aria-label": "open the evidence chain for this anomaly" },
      on: { click: () => hpPivotEvidence(a) },
    }, [
      el("td", { class: "mono link", text: fmtTime(a.detected_at) }),
      el("td", { class: "mono", text: (a.anomaly_score ?? 0).toFixed(3) }),
      el("td", {}, [sevCell(a.severity)]),
      el("td", { text: a.baseline_comparison || "—" }),
    ]));
  }
}

/* ── sending an alert to the Sluice Gate ─────────────────────────────────── */

/*
 * THE OPERATOR'S OWN PIVOT: from an alert they are reading to a block on the gate. Two rules
 * shape it, and both come from this project's own failures:
 *
 *  - The action is OFFERED only when it would DO something. A block stops traffic only when the
 *    box is actually in the path (a verified channel, or a live siphon intercept); filing one in
 *    plain loch compiles, counts its own drops and changes nothing. So the control reads the
 *    gate's own state and, when it is not active, STATES WHY instead of offering a button. A
 *    disabled button still reads as "this is possible" to someone skimming a table.
 *  - A block without a reason is unanswerable three weeks later, so the reason is PRE-FILLED
 *    from the alert (score, host, window). It is still OPTIONAL -- an operator who knows why they
 *    are blocking can leave it alone or clear it -- and a blank one is stored blank rather than
 *    replaced by a placeholder.
 *
 * The vocabulary is the Gate view's own manual form (src_cidr / protocol / dst_port / direction
 * / ttl_minutes / reason), so a rule filed from an alert is indistinguishable from one filed by
 * hand -- same store, same ledger, same revoke path.
 */
let GATE_STATE = null;

async function loadGateState() {
  try {
    GATE_STATE = await getJSON(API.sluice);
  } catch (err) {
    // "Unavailable" is a state this UI must render AS unavailable, never as "off" -- the same
    // distinction the status views make between a dead query and a quiet network.
    GATE_STATE = null;
  }
  return GATE_STATE;
}

/** Why a block from here would not stop traffic, or "" when the gate is active. */
function gateBlockableReason() {
  if (!GATE_STATE || !GATE_STATE.available) return "the gate's state is unavailable";
  if (!GATE_STATE.enabled) return "the Sluice Gate is off";
  const enforcement = (GATE_STATE.gate && GATE_STATE.gate.enforcement) || "";
  if (enforcement === "channel" || enforcement === "siphon") return "";
  return "nothing is enforcing: loch with no verified channel or live intercept means a block " +
         "would compile and stop nothing";
}

/* ── the row's action cell ────────────────────────────────────────────────────────────────
 * At most three one-click actions per row, the shape the research converged on: Evidence
 * opens the raw records, Block... is the gate form, Watch toggles this host on the
 * operator's tracking list. The Review chip stays its own control -- a disposition is a
 * STATE, not an action -- and the row click remains a quiet shortcut to Evidence.
 */
function anActions(a) {
  return el("div", { class: "an-actions" }, [
    el("button", { class: "review-act ev-open", text: "Evidence", attrs: { type: "button" },
      title: "show the raw records behind this alert",
      on: { click: (e) => { e.stopPropagation(); openEvidence(a); } } }),
    gateAction(a),
    watchAction(a),
    // US-9: TUNE DETECTION, PER ROW -- where the detector is shown, not a page-level dial.
    el("button", { class: "review-act", text: "Tune", attrs: { type: "button" },
      title: "tune detection \u2014 open the settings that decide what fires",
      on: { click: (e) => {
        e.stopPropagation();
        if (typeof openSettingKey === "function") openSettingKey("base_threshold");
      } } }),
  ]);
}

/** The watch toggle for one alert's host: a button, or the reason there is none. */
function watchAction(a) {
  const wrap = el("div", { class: "watch-act" });
  if (a.watched === null || a.watched === undefined) {
    // The store could not be read (schema not migrated yet): say THAT, never an off
    // state that claims nothing is being watched.
    wrap.appendChild(el("span", { class: "gate-off",
      title: "the watch list could not be read from the store",
      text: "Watch unavailable" }));
    return wrap;
  }
  const btn = el("button", {
    class: "review-act" + (a.watched ? " watched" : ""),
    text: a.watched ? "Watching \u2713" : "Watch",
    attrs: { type: "button", "aria-pressed": a.watched ? "true" : "false" },
    title: a.watched
      ? "stop tracking this host"
      : "track this host \u2014 find it again with the watched-only filter",
    on: { click: async (e) => {
      e.stopPropagation();
      btn.disabled = true;
      try {
        await postJSON(API.watch, { src_addr: a.src_addr, on: !a.watched });
        await loadAnomalies();
      } catch (err) {
        // The list reloads from the server on success; on failure the button returns
        // to its server-known state and the error is said out loud -- an optimistic
        // flip would show a watch a failed write never recorded.
        btn.disabled = false;
        showError(err);
      }
    } },
  });
  wrap.appendChild(btn);
  return wrap;
}

/** The block control for one alert: a button, or the reason there is none. */
function gateAction(a, opts = {}) {
  const wrap = el("div", { class: "gate-act" });
  const reason = gateBlockableReason();
  if (reason) {
    // US-4: plain text in an action cell -- it must not wear the row's pointer or navigate:
    // a span that opens the Evidence drill when clicked reads as an action and is not one.
    wrap.appendChild(el("span", { class: "gate-off", title: reason,
                                  on: { click: (e) => e.stopPropagation() },
                                  text: `Block unavailable \u2014 ${reason}` }));
    return wrap;
  }
  wrap.appendChild(el("button", {
    class: "review-act gate-open", text: "Block\u2026", attrs: { type: "button" },
    title: "open the Sluice Gate rule composer for this host",
    on: { click: (e) => {
      e.stopPropagation();
      // THE ALERT SHORTCUT IS THE SLUICE COMPOSER (operator, 2026-10-20). On the evidence
      // page — where the alert is actually read — use the SAME sheet the Sluice Gate uses.
      // The compact inline form remains for the anomalies table only, so its row workflow is
      // unchanged; the evidence pivot gets the full source/destination/direction composer.
      if (opts.popout && typeof openRuleComposer === "function") {
        openRuleComposer("", {
          src_cidr: a.src_addr,
          dst_cidr: "",
          mode: "block",
          direction: "forward",
          ttl_minutes: 60,
          reason: `alert score ${(a.anomaly_score ?? 0).toFixed(3)} on ${a.src_addr}, ` +
                  `window ${fmtTime(a.window_start)}`,
          focus: "sl-src",
        });
      } else {
        toggleGateForm(wrap, a);
      }
    } },
  }));
  return wrap;
}

function toggleGateForm(wrap, a) {
  // The reference is held on the wrapper instead of being found with a selector: the bundle is
  // checked by a test that every querySelector target exists in the MARKUP, and a form built at
  // runtime is not in the markup. A selector here would be a false positive that check would
  // have to be taught to except -- a held reference says the same thing without widening it.
  if (wrap._gateForm) { wrap._gateForm.remove(); wrap._gateForm = null; return; }
  wrap._gateForm = gateForm(a);
  wrap.appendChild(wrap._gateForm);
}

/** The form: all traffic from the host, or one service (port + protocol). */
function gateForm(a) {
  const form = el("div", { class: "gate-form" });
  // US-1: a click inside the form belongs to the form. Without this the row's own click
  // handler swallows it and the Evidence drill opens mid-edit (measured).
  form.addEventListener("click", (e) => e.stopPropagation());
  // SOURCE, DESTINATION AND DIRECTION ARE PART OF THE RULE (operator, 2026-10-20: "i need
  // more options, source, destination etc"). The quick block used to hard-code the alert's
  // source and no destination; the full rule composer already had these fields. Keep the
  // quick form focused, but let the operator name the other end of the rule.
  const src = el("input", { attrs: { type: "text", "aria-label": "source address or CIDR",
                                     placeholder: "source address or CIDR" } });
  src.value = String(a.src_addr || "");
  const dst = el("input", { attrs: { type: "text",
                                     "aria-label": "destination address or CIDR (optional)",
                                     placeholder: "destination (optional)" } });
  const direction = el("select", { attrs: { "aria-label": "direction" } }, [
    el("option", { value: "forward", text: "forwarded", selected: true }),
    el("option", { value: "in", text: "inbound to this weirling" }),
  ]);
  const scope = el("select", { attrs: { "aria-label": "what to block" } }, [
    el("option", { value: "all", text: "all traffic", selected: true }),
    el("option", { value: "port", text: "only one service" }),
  ]);
  const port = el("input", { attrs: { type: "number", min: "1", max: "65535",
                                      placeholder: "port", "aria-label": "port" } });
  const proto = el("select", { attrs: { "aria-label": "protocol" } },
    ["tcp", "udp"].map((p) => el("option", { value: p, text: p })));
  const ttl = el("select", { attrs: { "aria-label": "how long to block" } },
    [5, 15, 30, 60, 240, 0].map((m) => el("option", {
      value: String(m), text: m === 0 ? "until revoked" : `${m} min`, selected: m === 60 })));
  // THE BLAST RADIUS, COMPUTED FROM STATE THE PAGE ALREADY HOLDS. The research asked for a
  // confirmation that states exactly what the rule will cover -- the target, the scope, the
  // duration, and the surface the gate enforces on. A confirmation that cannot state its own
  // blast radius is decoration.
  const blast = el("p", { class: "muted gate-blast" });
  const refreshBlast = () => {
    const g = (GATE_STATE && GATE_STATE.gate) || {};
    const scopeTxt = scope.value === "port"
      ? `${proto.value} port ${Number(port.value) || "\u2026"}`
      : "all traffic";
    const srcTxt = String(src.value || "").trim() || "(missing source)";
    const dstTxt = String(dst.value || "").trim();
    const dirTxt = direction.value === "in" ? " inbound" : "";
    const dur = ttl.value === "0" ? "until revoked" : `${ttl.value} min`;
    blast.textContent = `Blast radius: ${scopeTxt}${dirTxt} from ${srcTxt}`
      + (dstTxt ? ` to ${dstTxt}` : "") + ` \u2014 enforced at the `
      + `gate${g.iface ? ` on ${g.iface}` : ""} (${g.rules_active || 0} rule(s) active) \u2014 `
      + `for ${dur}.`;
  };
  [scope, port, proto, ttl, direction].forEach((c) => {
    c.addEventListener("change", refreshBlast);
  });
  [src, dst, port].forEach((c) => {
    c.addEventListener("input", refreshBlast);
  });
  form.appendChild(el("div", { class: "gate-line" }, [
    el("label", { text: "source" }, [src]),
    el("label", { text: "destination" }, [dst]),
    el("label", { text: "direction" }, [direction]),
  ]));
  form.appendChild(el("div", { class: "gate-line" }, [
    el("label", { text: "what" }, [scope]),
    el("label", { text: "protocol" }, [proto]),
    el("label", { text: "port" }, [port]),
    el("label", { text: "for" }, [ttl]),
  ]));
  refreshBlast();
  const why = el("input", { class: "gate-why", attrs: { type: "text", "aria-label": "reason" },
    value: `alert score ${(a.anomaly_score ?? 0).toFixed(3)} on ${a.src_addr}, ` +
           `window ${fmtTime(a.window_start)}` });
  const note = el("span", { class: "muted gate-note" });
  const submit = el("button", {
    class: "review-act", text: "File block", attrs: { type: "button" },
    on: { click: async (e) => {
      e.stopPropagation();
      const portMode = scope.value === "port";
      if (portMode && !Number(port.value)) {
        note.textContent = "enter a port, or switch to all traffic";
        return;
      }
      // The reason is optional; a blank field posts as an empty string and the row records it.
      const body = {
        src_cidr: src.value.trim(), dst_cidr: dst.value.trim(),
        protocol: portMode ? proto.value : "",
        dst_port: portMode ? Number(port.value) : 0,
        direction: direction.value || "forward",
        ttl_minutes: Number(ttl.value), reason: why.value.trim(),
      };
      submit.disabled = true;
      note.textContent = "recording\u2026";
      try {
        const out = await postJSON(API.sluiceBlock, body);
        // The server's refusal text is the deliverable: it names the fix (the management
        // interface, a port with no protocol, a missing reason, an unknown host).
        note.textContent = (out && (out.ok ? (out.note || "recorded") : out.error))
          || "the rule was refused";
        if (out && out.ok && out.rule_id) {
          // US-3: the receipt KEEPS ITS ID -- one click lands on the rule card this block
          // just created, on the Blocked page, with the card saying "you are here" once.
          note.appendChild(document.createTextNode(" "));
          note.appendChild(el("button", {
            class: "quiet", text: "Open the filed rule \u2192", attrs: { type: "button" },
            title: "the rule this block created",
            on: { click: () => {
              showView("blocked");
              if (typeof blOpenRuleById === "function") blOpenRuleById(out.rule_id).catch(() => {});
            } },
          }));
        }
      } catch (err) {
        note.textContent = String(err.message || err);
      } finally {
        submit.disabled = false;
      }
    } },
  });
  form.appendChild(el("div", { class: "gate-line" }, [blast]));
  form.appendChild(el("div", { class: "gate-line" }, [why]));
  form.appendChild(el("div", { class: "gate-line" }, [submit, note]));
  // Show the port fields only in "one service" mode: a control that can never be used is the
  // dead-control defect this project keeps refusing to ship.
  const sync = () => {
    const on = scope.value === "port";
    port.style.display = on ? "" : "none";
    proto.style.display = on ? "" : "none";
  };
  scope.addEventListener("change", sync);
  sync();
  return form;
}

/* ── the fingerprint lookup (identity view) ───────────────────────────────── */

/* The OTHER direction from the identity card. The card shows one host's fingerprints; the
 * question an analyst arrives with is "who else presents this stack?", and this is that lookup.
 * A lookup that found nothing says nothing FOUND in the window -- not "no such fingerprint":
 * the records only cover what the sensor retained. */
async function lookupFingerprint(ja4) {
  const note = document.getElementById("fp-note");
  const out = document.getElementById("fp-results");
  const token = (ja4 || "").trim();
  out.replaceChildren();
  if (!token) { note.textContent = "paste a JA4 fingerprint first"; return; }
  note.textContent = "looking up\u2026";
  const d = await getJSON(API.fingerprints(token));
  if (d.reason) { note.textContent = d.reason; return; }
  note.textContent = d.count
    ? `${d.count} host(s) presented this fingerprint in the last 7 days`
    : "no host presented this fingerprint in the last 7 days";
  if (!d.count) return;
  const tb = el("tbody", {});
  for (const h of d.hosts) {
    const tr = el("tr", { class: "clickable", attrs: { title: "open this host" },
                          on: { click: () => openHost(h.src_addr) } }, [
      el("td", { class: "mono", text: h.src_addr }),
      el("td", { class: "mono", text: String(h.sessions) }),
      el("td", { class: "mono", text: fmtTime(h.first_seen) }),
      el("td", { class: "mono", text: fmtTime(h.last_seen) }),
      el("td", { class: "mono", text: String(h.peers) }),
    ]);
    tb.appendChild(tr);
  }
  out.appendChild(el("table", { class: "fp-table" }, [
    el("thead", {}, [el("tr", {}, ["Host", "Sessions", "First seen", "Last seen", "Peers"]
      .map((h) => el("th", { text: h })))]),
    tb,
  ]));
}

/* ── alert evidence (the pivot) ─────────────────────────────────────────── */

/* Show the RAW records inside one alert's detection window. This is the answer to
 * "why did the model flag this" that the aggregate host view cannot give: the host
 * view says what the host has done over 24h; this says what it did in the five
 * minutes the detector scored, which is the only thing that verdict is about. */
/* ONE BACK CONTROL PER DRILL. The evidence page used to carry both a blue underlined
 * "Anomalies" crumb AND this quiet button; two controls for one job looked like two different
 * navigation systems. The button is now the only exit, and the crumb trail is left to surfaces
 * that do not already have a labeled button. */
function evidenceBackLabel(view) {
  const named = { anomalies: "Back to alerts", assets: "Back to assets", host: "Back to host",
                   evidence: "Back to evidence" };
  if (named[view]) return named[view];
  const tab = [...document.querySelectorAll(".tab")].find((t) => t.dataset.view === view);
  return tab ? `Back to ${tab.textContent.trim().toLowerCase()}` : "Back";
}

function showEvidenceBack() {
  const back = document.getElementById("ev-back");
  if (!back) return;
  back.textContent = evidenceBackLabel(EVIDENCE_FROM || "anomalies");
  back.hidden = false;
}

function openEvidence(a) {
  if (!a || !a.src_addr) return;
  EVIDENCE_FROM = CURRENT_VIEW || "anomalies";
  EVIDENCE_SCROLL = Number(window.scrollY || 0);
  showView("evidence");
  const start = a.window_start || a.detected_at;
  loadEvidence(a.src_addr, start, a.window_end).catch(showError);
}

/** The evidence page's labeled way back (issue #52). Wired once, at boot. */
function wireEvidenceBack() {
  const back = document.getElementById("ev-back");
  if (back) {
    back.addEventListener("click", () => {
      const fromView = EVIDENCE_FROM || "anomalies";
      returnWithScroll(fromView, EVIDENCE_SCROLL);
    });
  }
}

/** The incident object above the raw rows: actor, asset, window, families, source coverage,
 * model version and review provenance. The evidence section already answers "what happened";
 * this says which incident the window belongs to and whether a decision is owed. */
function renderIncidentContext(inc) {
  const box = document.getElementById("ev-incident");
  if (!box) return;
  box.replaceChildren();
  if (!inc || inc.available !== true || !inc.incident) {
    const why = (inc && inc.reason) || "no incident contains this window";
    box.appendChild(el("p", { class: "muted", text: `Incident context unavailable: ${why}.` }));
    return;
  }
  const i = inc.incident;
  const asset = i.asset || {};
  const role = `${asset.role || "unknown"}${asset.scope ? ` (${asset.scope})` : ""}`;
  const families = (i.families || []).length ? i.families.join(", ") : "none recorded";
  const coverage = Object.entries(i.source_coverage || {})
    .filter(([, n]) => Number(n) > 0)
    .map(([k, n]) => `${k} ${n}`).join(" · ") || "no raw records";
  const versions = (i.model_versions || []).length ? i.model_versions.join(", ") : "not recorded";
  const review = i.review || {};
  const reviewed = review.state
    ? `${review.state}${review.reviewed_by ? ` by ${review.reviewed_by}` : ""}` +
      `${review.reviewed_at ? ` at ${fmtTime(review.reviewed_at)}` : ""}` +
      `${review.expires_at ? ` · expires ${fmtTime(review.expires_at)}` : ""}`
    : "not reviewed — a decision is owed";
  const line = (label, value) => el("p", { class: "muted" }, [
    el("strong", { text: `${label}: ` }), el("span", { text: value }),
  ]);
  box.appendChild(el("div", { class: "incident-context" }, [
    line("Incident", `${i.actor || "—"} · ${role} · ${fmtTime(i.window && i.window.start)} → ` +
      `${fmtTime(i.window && i.window.end)} · ${i.occurrences || 0} occurrences · ` +
      `${sevText(i.severity) || "severity unknown"}`),
    line("Families", families),
    line("Source coverage", coverage),
    line("Model version", versions),
    line("Review", reviewed),
    line("Page budget", i.pageable ? `pageable${i.page_reason ? ` · ${i.page_reason}` : ""}` :
      `not pageable${i.page_reason ? ` · ${i.page_reason}` : ""}`),
  ]));
  if (asset.error) {
    box.appendChild(el("p", { class: "muted", text: `Asset context unavailable: ${asset.error}.` }));
  }
  if (review.error) {
    box.appendChild(el("p", { class: "muted", text: `Review provenance unavailable: ${review.error}.` }));
  }
  if (inc.evidence_error) {
    const err = typeof inc.evidence_error === "string" ? inc.evidence_error :
      Object.entries(inc.evidence_error).map(([k, v]) => `${k}: ${v}`).join(" | ");
    box.appendChild(el("p", { class: "muted", text: `Evidence read incomplete: ${err}.` }));
  }
}

async function loadEvidence(addr, start, end) {
  scheduleURLSync();
  CURRENT_EVIDENCE = { addr, start, end };
  const d = await getJSON(API.evidence(addr, start, end));
  showDataError(d.errors ? Object.entries(d.errors).map(([k, v]) => `${k}: ${v}`).join(" | ") : null);
  let incident = null;
  try {
    incident = await getJSON(API.incident(addr, start));
  } catch (exc) {
    incident = { available: false, reason: `incident request failed: ${exc.message || exc}` };
  }
  renderIncidentContext(incident);

  document.getElementById("ev-title").textContent =
    d.hostname ? `${d.hostname} (${d.src_addr})` : d.src_addr;
  document.getElementById("ev-sub").textContent =
    `Detection window ${fmtTime(d.window_start)} → ${fmtTime(d.window_end)}. ` +
    `These are the individual records the detector scored — not aggregates.`;
  const evHost = document.getElementById("ev-host");
  if (evHost) {
    evHost.classList.remove("hidden");
    evHost.onclick = () => openHost(d.src_addr);
  }
  // US-3: the way back. Evidence is a drill, not a destination. The quiet button names
  // the destination; there is deliberately no second breadcrumb for the same exit.
  clearCrumbs();
  EVIDENCE_FROM = EVIDENCE_FROM || "anomalies";
  showEvidenceBack();

  // ── THE EVIDENCE CHAIN (US-D1) ─────────────────────────────────────────────────────────────
  // Five stages, each with its own state. The rule from the vision: an unknown is drawn as an
  // unknown, never as an absence -- so a stage with no record says "not recorded" in words.
  {
    const box = document.getElementById("ev-chain");
    if (box) {
      box.replaceChildren();
      const s = d.flow_summary || null;
      const a = d.anomaly || null;
      const state = (a && a.review_state) || "";
      const reviewed = {
        resolved: ["closed", "resolved"],
        false_positive: ["closed", "false positive"],
        ack: ["open", "acknowledged"],
        unavailable: ["unknown", "review state could not be read"],
      }[state] || ["open", "not reviewed yet"];
      // Source freshness is part of the evidence, not a footer. A verdict built on a stale or
      // unreadable source must say so in the same chain as the detection, and "not measured" is
      // a state of its own -- never zero flows and never a green check.
      const sf = d.source_freshness || {};
      const sfRows = Object.entries(sf).map(([name, v]) => {
        const state = (v && v.state) || "unknown";
        return `${name}: ${state}${v && v.reason ? ` (${v.reason})` : ""}`;
      });
      const sfState = Object.values(sf).some((v) => v && (v.state === "failed" || v.state === "unknown"))
        ? "unknown"
        : (Object.values(sf).some((v) => v && v.state === "stale") ? "open" : "known");
      const stages = [
        ["observed", "observed", s
          ? `${Number(s.flows || 0).toLocaleString()} flows \u00b7 ${fmtBytes(s.bytes)} \u00b7 ` +
            `${s.unique_destinations ?? "\u2014"} destinations in this window`
          : "unknown \u2014 no flow record was read for this window", s ? "known" : "unknown"],
        ["sources", "sources", sfRows.length ? sfRows.join(" \u00b7 ")
          : "not measured \u2014 no source freshness was returned", sfState],
        ["detected", "detected", a
          ? `${sevText(a.severity) || "\u2014"} \u00b7 score ` +
            `${Number(a.anomaly_score ?? 0).toFixed(3)} \u00b7 ${a.detected_by_models || "\u2014"}` +
            (a.severity_basis ? ` \u00b7 ${a.severity_basis}` : "")
          : "no verdict stored for this window", a ? "known" : "unknown"],
        ["explained", "explained",
          (a && (a.baseline_comparison || a.primary_deviation_feature))
            ? String(a.baseline_comparison || `primary deviation: ${a.primary_deviation_feature}`)
            : "no explanation recorded",
          (a && (a.baseline_comparison || a.primary_deviation_feature)) ? "known" : "unknown"],
        // RULED IS THE RULE, NOT THE REVIEW STATE. "acknowledged" is what happened to the
        // alert; the rule that matched (or the fact that none did) is the ruling. The review
        // state belongs to DONE, where the decision is recorded.
        ["ruled", "ruled",
          a ? (a.matched_rule ? `rule: ${a.matched_rule}` : "no rule \u2014 alert only")
            : "no verdict stored for this window",
          a ? "known" : "unknown"],
        ["done", "done",
          reviewed[0] === "closed" ? `closed \u00b7 ${reviewed[1]}`
            : (reviewed[0] === "open"
              ? `${reviewed[1]} \u00b7 still open \u2014 a decision is owed`
              : reviewed[1]),
          reviewed[0]],
      ];
      for (const [id, label, text, st] of stages) {
        box.appendChild(el("li", { class: `chain-step chain-${st}`,
          attrs: { "data-stage": id } }, [
          el("span", { class: "chain-label", text: label }),
          el("span", { class: "chain-text", text: text }),
          el("span", { class: "chain-state", text: st }),
        ]));
      }
    }
  }

  // The verdict, so the evidence is read in context rather than cold.
  const verdict = document.getElementById("ev-verdict");
  verdict.replaceChildren();
  if (d.anomaly) {
    verdict.appendChild(el("p", { class: "muted" }, [
      el("span", {}, [sevCell(d.anomaly.severity)]),
      el("span", { text: `  score ${(d.anomaly.anomaly_score ?? 0).toFixed(3)}` }),
      el("span", { text: `  · decision value, not a probability` }),
      el("span", { text: `  · models: ${d.anomaly.detected_by_models || "—"}` }),
    ]));
    if (d.anomaly.baseline_comparison) {
      verdict.appendChild(el("p", { text: d.anomaly.baseline_comparison }));
    }
    // The operator's pivot, on the page where the alert is actually read. Same gate-state check
    // as the anomalies row: offered only when a block would DO something, with the reason stated
    // when it would not. ACKNOWLEDGE AND IGNORE SIT BESIDE BLOCK (operator, 2026-10-20):
    // the dispositions existed only inside the anomalies row's disclosure, which is not where
    // the alert is actually read. The reviewActs builder owns the same API calls.
    await loadGateState();
    const target = Object.assign({}, d.anomaly,
      { src_addr: d.src_addr, window_start: d.window_start });
    const acts = el("div", { class: "ev-actions" });
    acts.appendChild(gateAction(target, { popout: true }));
    const dispositions = reviewActs(target, target.review_state || "");
    if (dispositions) acts.appendChild(dispositions);
    verdict.appendChild(acts);
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
      stats.appendChild(el("div", { class: "stat" }, statCells(k, v)));
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
        el("td", { class: "dcell", attrs: { title: "open this destination's host view" },
                   on: { click: () => openHost(f.dst_addr) } },
           [hostCell(f.dst_addr, f.hostname, d.src_addr)]),
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
      const serviceCell = el("td", { class: z.service ? "dcell" : "",
        text: z.service || z.dst_port || "—" });
      if (z.service) {
        serviceCell.addEventListener("click", (e) => {
          e.stopPropagation();
          evidencePivotZeek(d.src_addr, z.service);
        });
      }
      zk.appendChild(el("tr", {}, [
        el("td", { class: "mono", text: fmtTime(z.ts) }),
        el("td", {}, [hostCell(z.dst_addr, z.hostname, d.src_addr)]),
        serviceCell,
        el("td", { class: "mono", text: fmtBytes((z.orig_bytes ?? 0) + (z.resp_bytes ?? 0)) }),
      ]));
    }
  }

  // TLS sessions WITH THEIR FINGERPRINTS. The models score zeek_ja4_novelty, so without this
  // table a JA4-driven alert had no pivot to the sessions that carried the new stack -- the
  // analyst could read the score and not the evidence.
  const tl = document.querySelector("#ev-tls tbody");
  tl.replaceChildren();
  if (!(d.zeek_ssl || []).length) {
    emptyRow(tl, 5, "No TLS sessions in this window.");
  } else {
    for (const s of d.zeek_ssl) {
      const ja4Cell = el("td", { class: s.ja4 ? "mono dcell" : "mono", text: s.ja4 || "—" });
      if (s.ja4) {
        ja4Cell.addEventListener("click", (e) => {
          e.stopPropagation();
          evidencePivotJa4(s.ja4);
        });
      }
      tl.appendChild(el("tr", {}, [
        el("td", { class: "mono", text: fmtTime(s.ts) }),
        el("td", {}, [hostCell(s.dst_addr, s.hostname, d.src_addr)]),
        el("td", { class: "mono", text: String(s.dst_port ?? "—") }),
        el("td", { text: s.server_name || "—" }),
        ja4Cell,
      ]));
    }
  }

  const dn = document.querySelector("#ev-dns tbody");
  dn.replaceChildren();
  if (!d.zeek_dns.length) {
    emptyRow(dn, 3, "No DNS queries in this window.");
  } else {
    for (const q of d.zeek_dns) {
      const queryCell = el("td", { class: q.query ? "mono dcell" : "mono",
        text: q.query || "—" });
      if (q.query) {
        queryCell.addEventListener("click", (e) => {
          e.stopPropagation();
          evidencePivotDns(d.src_addr, q.query);
        });
      }
      dn.appendChild(el("tr", {}, [
        el("td", { class: "mono", text: fmtTime(q.ts) }),
        queryCell,
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

/**
 * Wire every "i" button that is NOT a settings-row control: the view-level explainers, whose
 * text lives in the markup beside them (`.info-text`, hidden by default). One click opens the
 * panel, the glyph marks itself open, and aria-expanded follows -- the same interaction the
 * settings rows use, so "click the circle for more" is one habit everywhere. Idempotent (a
 * second boot must not double-toggle the panels).
 */
function wireInfoButtons() {
  for (const btn of document.querySelectorAll(".info-btn")) {
    if (btn.dataset.wired) continue;
    btn.dataset.wired = "1";
    const panel = document.getElementById(btn.dataset.info || "");
    if (!panel) continue;
    btn.addEventListener("click", () => {
      const stillHidden = panel.classList.toggle("hidden");
      btn.classList.toggle("open", !stillHidden);
      btn.setAttribute("aria-expanded", stillHidden ? "false" : "true");
    });
  }
}

/* SHOW ALL HELP -- one key ("?") or one click reveals every i-circle panel at once; the same
 * toggle puts them away. "Any open" means close: the key is a state switch, not a stack, and
 * the state is named in the pill (aria-pressed) and on the body (help-all). */
/* ── THE FIRST RUN WALKS ITSELF THROUGH THE REAL FLOW ───────────────────────────────────────
 * (BF-8; research: pfSense's wizard, escapable, batched into one apply.) Shown only while the
 * fleet has never had a live sensor. Three steps; step two edits REAL settings through the
 * REAL staging path -- so by step three the operator has already used the model the whole
 * console runs on, and everything the wizard touched waits in the same reviewable plan as any
 * other change. Skippable at every step; the skip rides sessionStorage, like the stage it
 * protects: it dies with the tab and is never a server state. */
const FIRSTRUN = { step: 1 };
const FIRSTRUN_KEYS = [
  { key: "BASE_THRESHOLD", why: "how far from normal a window must score before the ensemble may alert" },
  { key: "DETECT_INTERVAL_S", why: "how often the ensemble scores the newest traffic" },
];

function firstrunDismissed() {
  try { return window.sessionStorage.getItem("wv-firstrun") === "skip"; } catch (_e) { return false; }
}
function firstrunHide() {
  const c = document.getElementById("firstrun-card");
  if (c) c.classList.add("hidden");
}
function firstrunSkip() {
  try { window.sessionStorage.setItem("wv-firstrun", "skip"); } catch (_e) { /* private mode */ }
  firstrunHide();
}
function firstrunShow(step) {
  const card = document.getElementById("firstrun-card");
  if (!card) return;
  FIRSTRUN.step = step || FIRSTRUN.step;
  const stepper = document.getElementById("firstrun-step");
  if (stepper) stepper.textContent = `step ${FIRSTRUN.step} of 3`;
  card.classList.remove("hidden");
  const body = document.getElementById("firstrun-body");
  if (!body) return;
  body.replaceChildren();
  const para = (text) => el("p", { class: "muted", text });
  const skipBtn = () => {
    const b = el("button", { class: "firstrun-skip", text: "Skip for now", attrs: { type: "button" } });
    b.addEventListener("click", () => firstrunSkip());
    return b;
  };
  if (FIRSTRUN.step === 1) {
    body.appendChild(para("A weirling is the sensor that watches your network: it captures " +
      "traffic (or receives flows) and feeds this hub. Nothing here is watching yet — the rest " +
      "of this console fills the moment one reports."));
    body.appendChild(para("This walk-through sets up the two numbers worth setting on day one. " +
      "Nothing is written until you apply — you will see every change first."));
    const next = el("button", { class: "firstrun-next", text: "Next", attrs: { type: "button" } });
    next.addEventListener("click", () => {
      loadSettings().catch(() => {}).finally(() => firstrunShow(2));
    });
    body.appendChild(el("p", {}, [next, document.createTextNode(" "), skipBtn()]));
  } else if (FIRSTRUN.step === 2) {
    body.appendChild(para("Two settings, edited right here the same way every other setting " +
      "is edited: change what you like — it is staged, not saved, until you apply."));
    for (const spec of FIRSTRUN_KEYS) {
      const row = SETTINGS_ROWS[spec.key] || {};
      const input = el("input", { attrs: { type: "number", value: String(row.value || ""),
                                           "aria-label": spec.key } });
      input.addEventListener("change", () => {
        stageChange(spec.key, input.value, row.value);
      });
      body.appendChild(el("label", {}, [
        el("span", { text: spec.key + " — " + spec.why }),
        el("br"),
        input,
      ]));
    }
    const next = el("button", { class: "firstrun-next", text: "Next", attrs: { type: "button" } });
    next.addEventListener("click", () => firstrunShow(3));
    body.appendChild(el("p", {}, [next, document.createTextNode(" "), skipBtn()]));
  } else {
    body.appendChild(para("Done. Anything you changed is staged like every other edit — " +
      "the header chip counts it, the plan shows old → new, and nothing touches the deployment " +
      "until you press Apply."));
    const review = el("button", { class: "firstrun-review", text: "Review the plan",
                                  attrs: { type: "button" } });
    review.addEventListener("click", () => { firstrunHide(); showView("settings"); });
    body.appendChild(el("p", {}, [review, document.createTextNode(" "), skipBtn()]));
  }
}

function openHelpPanel(id) {
  const panel = document.getElementById(id);
  const btn = panel ? document.querySelector('[data-info="' + id + '"]') : null;
  if (!panel || !btn) return;
  panel.classList.remove("hidden");
  btn.classList.add("open");
  btn.setAttribute("aria-expanded", "true");
}

function toggleAllHelp(force) {
  const panels = [...document.querySelectorAll(".info-text")];
  const anyOpen = panels.some((p) => !p.classList.contains("hidden"));
  const open = typeof force === "boolean" ? force : !anyOpen;
  for (const btn of document.querySelectorAll(".info-btn")) {
    const panel = document.getElementById(btn.dataset.info || "");
    if (!panel) continue;
    panel.classList.toggle("hidden", !open);
    btn.classList.toggle("open", open);
    btn.setAttribute("aria-expanded", open ? "true" : "false");
  }
  document.body.classList.toggle("help-all", open);
  const pill = document.getElementById("all-help");
  if (pill) pill.setAttribute("aria-pressed", open ? "true" : "false");
}

/**
 * Give every table in <main> its own horizontal scroll box (the responsive section in
 * style.css explains why). The table elements are static markup, so once at boot is enough:
 * every live update replaces <tbody> content, never the table element itself. Idempotent,
 * because boot may run more than once (the harness re-boots by design).
 */
/**
 * LOCK THE TAB BAR TO THE TOP (the operator, 2026-10-16: "this bar should stay locked at the
 * top"). The CSS makes #tabs sticky at --header-h; this measures the header's LIVE height into
 * that variable, because it wraps to two or three rows at narrow widths and a stale offset
 * would leave the strip floating mid-page or hidden behind the header. Measured, not guessed --
 * and re-measured on resize and whenever the header itself changes size.
 */
/**
 * SETTINGS SECTIONS OPEN ON DEMAND (the operator, 2026-10-16: "make the sections expandable so
 * you just open what you want to edit"). Every card in the Settings view collapses to its
 * heading; the heading toggles it. THE PENDING-CHANGES CARD IS EXEMPT: it holds the Apply
 * button, and a surface that can be accidentally collapsed is a new way to lose it. The info
 * button inside a heading is not a toggle target.
 */
/**
 * THE MODAL (the operator, 2026-10-16: "any time we click to edit or see a rule or block or allow
 * dns, clicking that button should generate a popup something. not just added to the bottom of
 * the screen or in the middle of the current screen between rows"). One dialog shell; openModal
 * MOVES a node into it and remembers where the node lived; closeModal puts it back. Moving --
 * not cloning -- is what keeps ONE editor with ONE set of ids and listeners; a second copy would
 * drift from the first the day someone edits one of them. Esc, the backdrop and the X all close.
 *
 * THE DIALOG CONTRACT (HD-17, GitHub #17; docs/design/sheets.md decides what is a sheet):
 * the shell is a labelled dialog (`aria-labelledby` -> the moved node's own heading), focus moves
 * INTO it on open, Tab cannot leave it, and focus returns to the control that opened it. A dialog
 * that cannot be left by keyboard, or that drops the reader at the top of the page on close, is a
 * trap; this was the shell's defect before HD-17.
 */
const MODAL_HOME = new WeakMap();
let MODAL_RETURN = null;
let MODAL_TITLE_SEQ = 0;

function modalFocusables() {
  const body = document.getElementById("modal-body");
  if (!body) return [];
  const nodes = [...body.querySelectorAll(
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), '
    + 'textarea:not([disabled]), [tabindex]:not([tabindex="-1"])')];
  return nodes.filter((n) => !n.closest(".hidden"));
}

function openModal(node) {
  const shell = document.getElementById("modal");
  const body = document.getElementById("modal-body");
  if (!shell || !body || !node) return;
  const wasHidden = shell.classList.contains("hidden");
  if (wasHidden) MODAL_RETURN = document.activeElement;
  if (!MODAL_HOME.has(node)) MODAL_HOME.set(node, node.parentNode);
  body.appendChild(node);
  node.classList.remove("hidden");
  shell.classList.remove("hidden");
  document.body.classList.add("modal-open");
  // THE LABEL IS THE NODE'S OWN HEADING, not a generic "dialog": a screen reader should hear
  // "Block this domain, dialog" rather than "dialog".
  const heading = node.querySelector("h1, h2, h3, [data-modal-title]");
  if (heading) {
    if (!heading.id) heading.id = `modal-title-${++MODAL_TITLE_SEQ}`;
    shell.setAttribute("aria-labelledby", heading.id);
  } else {
    shell.removeAttribute("aria-labelledby");
  }
  const target = modalFocusables()[0] || node;
  if (typeof node.focus === "function" && target === node
      && !node.hasAttribute("tabindex")) node.setAttribute("tabindex", "-1");
  if (typeof target.focus === "function") target.focus();
}

function closeModal(node) {
  const shell = document.getElementById("modal");
  if (node) {
    node.classList.add("hidden");
    const home = MODAL_HOME.get(node);
    if (home) home.appendChild(node);
  }
  if (shell) shell.classList.add("hidden");
  document.body.classList.remove("modal-open");
  const back = MODAL_RETURN;
  MODAL_RETURN = null;
  if (back && document.contains(back) && typeof back.focus === "function") back.focus();
}

function modalWiring() {
  const shell = document.getElementById("modal");
  if (!shell || shell.dataset.wired === "1") return;
  shell.dataset.wired = "1";
  const closeTop = () => {
    const body = document.getElementById("modal-body");
    if (body) for (const node of [...body.children]) closeModal(node);
  };
  const x = document.getElementById("modal-close");
  if (x) x.addEventListener("click", closeTop);
  const back = document.getElementById("modal-backdrop");
  if (back) back.addEventListener("click", closeTop);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeTop(); });
  // TAB STAYS IN THE DIALOG (HD-17). A sheet opened over the modal owns the keyboard instead
  // (sheets.js handles that case), so this trap only runs while the dialog is the top surface.
  document.addEventListener("keydown", (e) => {
    if (e.key !== "Tab" || shell.classList.contains("hidden")) return;
    if (document.querySelector(".sheet:not(.hidden)")) return;
    const focusable = modalFocusables();
    if (!focusable.length) { e.preventDefault(); return; }
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
  // The evidence drill's labeled way back (issue #52); wired with the rest of the one-time
  // chrome so boot stays the short, legible sequence its pin measures.
  wireEvidenceBack();
}

// ── FILTER CELLS ARE KEYBOARD-OPERABLE (HD-17) ──────────────────────────────────────────────
// A `.dcell` is a click-to-filter affordance drawn inside a table cell or a chart bar. Before
// this, it existed only for a mouse: no tabindex, no role, no key handler. The cells are created
// in a dozen renderers, so they are marked where they appear rather than at each call site -- and
// an Enter/Space on a focused cell performs exactly the click a mouse would.
function markFilterCells() {
  for (const cell of document.querySelectorAll(".dcell:not([data-kb])")) {
    cell.dataset.kb = "1";
    cell.setAttribute("tabindex", "0");
    if (!cell.getAttribute("role")) cell.setAttribute("role", "button");
    const title = cell.getAttribute("title");
    if (title && !cell.getAttribute("aria-label")) cell.setAttribute("aria-label", title);
  }
  // ── ROW OPENERS TOO (WV1-10) ──────────────────────────────────────────────────────────────
  //
  // `tr.clickable` opens a hit's detail or a DNS row's answers, and there was no keyboard path to
  // it anywhere in this directory: `.clickable` had no handler and a <tr> is not focusable, so
  // reviewing a hit without a mouse was impossible. The filter cells INSIDE those rows were already
  // fine, which is why the gap survived review -- the row looked wired.
  //
  // Deliberately NOT role="button": a <tr> is a table row, and overriding that role breaks table
  // navigation for a screen reader (row and column counts, cell reading). `tabindex` plus the
  // delegated Enter/Space in filterCellWiring makes it reachable and operable while leaving the
  // semantics alone. The better long-term shape is a real <button> in the first cell, the way the
  // Sluice rule rows do it; that is a per-view change, and this covers every row that exists now.
  for (const row of document.querySelectorAll("tr.clickable:not([data-kb])")) {
    row.dataset.kb = "1";
    row.setAttribute("tabindex", "0");
    const rowTitle = row.getAttribute("title");
    if (rowTitle && !row.getAttribute("aria-label")) row.setAttribute("aria-label", rowTitle);
  }
}

function filterCellWiring() {
  if (document.body.dataset.filterCells === "1") return;
  document.body.dataset.filterCells = "1";
  markFilterCells();
  const main = document.querySelector("main") || document.body;
  let queued = false;
  new MutationObserver(() => {
    if (queued) return;
    queued = true;
    queueMicrotask(() => { queued = false; markFilterCells(); });
  }).observe(main, { childList: true, subtree: true });
  document.addEventListener("keydown", (e) => {
    if (!(e.key === "Enter" || e.key === " " || e.key === "Spacebar")) return;
    if (!(e.target && e.target.closest)) return;
    // A filter cell first, then a row opener. Both are activated the same way.
    const cell = e.target.closest(".dcell");
    if (cell) {
      e.preventDefault();
      cell.click();
      return;
    }
    const row = e.target.closest("tr.clickable");
    if (row) {
      e.preventDefault();
      row.click();
    }
  });
}

// ── DESTRUCTIVE ACTIONS: THE ECHO AND THE READ-BACK (BF-9) ───────────────────────────────────
// WHENCE: the containment_pending lesson -- a console that says "done" before the world says
// so is a console that lies during the one minute it matters. Three rules, one dialog:
//   1. the confirm names the EXACT TARGET and the computed BLAST RADIUS -- not "are you sure?"
//   2. the reason is REQUIRED and is recorded with the actor and the time (the write trail)
//   3. afterwards the surface says pending, then APPLIED AT HH:MM once a READ-BACK agrees --
//      or NOT APPLIED, which is a different word on purpose.
// Type-the-target appears only for the truly irreversible (blocklist replace); dialogs stay
// rare for everything else.
function confirmDestructive(opts) {
  const o = opts || {};
  return new Promise((resolve) => {
    const reason = el("input", { class: "dest-reason", attrs: { type: "text",
      placeholder: o.reasonHint || "why — recorded with your name and the time" } });
    const typeBox = o.typeToConfirm ? el("input", { class: "dest-type", attrs: { type: "text",
      placeholder: `type ${o.target} to confirm` } }) : null;
    const go = el("button", { class: "primary", text: o.confirmLabel || "Do it", attrs: { disabled: "1" } });
    const cancel = el("button", { text: "Cancel" });
    const sync = () => {
      const hasReason = reason.value.trim().length > 0;
      const typed = !typeBox || typeBox.value.trim() === String(o.target);
      if (hasReason && typed) go.removeAttribute("disabled");
      else go.setAttribute("disabled", "1");
    };
    reason.addEventListener("input", sync);
    if (typeBox) typeBox.addEventListener("input", sync);
    const box = el("div", { class: "dest-confirm" }, [
      el("p", { text: o.title || "This action is destructive." }),
      el("p", { class: "muted" }, [el("span", { text: "target: " }),
        el("span", { class: "mono", text: String(o.target || "?") })]),
      el("p", { class: "muted" }, [el("span", { text: "blast radius: " }),
        el("span", { text: o.blast || "unknown" })]),
      el("label", { class: "dest-field" }, [
        el("span", { class: "muted", text: "reason" }), reason]),
    ]);
    if (typeBox) {
      box.appendChild(el("label", { class: "dest-field" }, [
        el("span", { class: "muted", text: "confirmation" }), typeBox]));
    }
    box.appendChild(el("div", { class: "dest-acts" }, [cancel, go]));
    const done = (ok) => { closeModal(box); box.remove(); resolve(ok ? { ok: true, reason: reason.value.trim() } : { ok: false }); };
    cancel.addEventListener("click", () => done(false));
    go.addEventListener("click", () => done(true));
    openModal(box);
    reason.focus();
  });
}

/** pending -> APPLIED AT HH:MM (read-back) or NOT APPLIED. The note element is where the
 *  operator is already looking; the label names what was applied. */
async function withReadBack(opts) {
  const o = opts || {};
  const note = o.note || null;
  const carry = o.carry ? ` — ${o.carry}` : "";
  const say = (text) => { if (note) note.textContent = text; };
  say(carry ? `pending — ${o.carry}` : "pending…");
  for (let i = 0; i < (o.tries || 5); i++) {
    await new Promise((r) => setTimeout(r, (o.delayMs || 800)));
    try {
      const d = await o.read();
      if (o.ok(d)) {
        const t = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
        say(`${o.label || "applied"} at ${t}${carry}`);
        return true;
      }
    } catch (_e) { /* a failed read inside the window is just a retry */ }
  }
  say(`NOT APPLIED — ${o.check || "check the sensor"}`);
  return false;
}

function settingsAccordion() {
  const view = document.getElementById("view-settings");
  if (!view) return;
  // The find control is an input event, not a click; wire it here because it operates on the
  // same card set as the accordion.
  const settingsFind = document.getElementById("st-filter");
  if (settingsFind && !settingsFind.dataset.wired) {
    settingsFind.dataset.wired = "1";
    settingsFind.addEventListener("input", () => settingsFilter(settingsFind.value));
  }
  for (const card of view.querySelectorAll(":scope > .card")) {
    if (card.dataset.acc === "1" || card.id === "st-stage-card") continue;
    const h2 = card.querySelector(":scope > h2");
    if (!h2) continue;
    card.dataset.acc = "1";
    card.classList.add("collapsed");
    h2.classList.add("acc");
    h2.addEventListener("click", (e) => {
      if (e.target.closest("button, a, input, select")) return;
      card.classList.toggle("collapsed");
    });
  }
}

/** Expand or collapse every settings card from the view header, one action. */
function settingsSetAll(open) {
  const view = document.getElementById("view-settings");
  if (!view) return;
  for (const card of view.querySelectorAll(":scope > .card")) {
    if (card.id === "st-stage-card") continue;
    card.classList.toggle("collapsed", !open);
  }
}

/** Find a setting by its visible name or its help text, then open the card that holds it. */
function settingsFilter(query) {
  const view = document.getElementById("view-settings");
  if (!view) return;
  const q = String(query || "").trim().toLowerCase();
  for (const card of view.querySelectorAll(":scope > .card")) {
    const text = (card.textContent || "").toLowerCase();
    const hit = !q || text.includes(q);
    card.classList.toggle("hidden", !hit);
    if (q && hit) card.classList.remove("collapsed");
  }
}

/** Jump from the header to the one staged set, without a second copy of its state. */
function settingsJumpToStage() {
  const card = document.getElementById("st-stage-card");
  if (!card) return;
  card.classList.remove("collapsed");
  card.scrollIntoView({ block: "nearest", behavior: "smooth" });
  const heading = card.querySelector("h2, h3");
  if (heading) {
    heading.setAttribute("tabindex", "-1");
    heading.focus({ preventScroll: true });
  }
}

function lockTabsToTop() {
  const header = document.querySelector("header");
  if (!header) return;
  const set = () => {
    document.documentElement.style.setProperty(
      "--header-h", Math.round(header.getBoundingClientRect().height) + "px");
  };
  set();
  if (typeof ResizeObserver !== "undefined") {
    new ResizeObserver(set).observe(header);
  }
  window.addEventListener("resize", set);
}

function wrapTables() {
  for (const table of document.querySelectorAll("main table")) {
    const parent = table.parentElement;
    if (!parent || parent.classList.contains("tablewrap")) continue;
    const box = document.createElement("div");
    box.className = "tablewrap";
    parent.insertBefore(box, table);
    box.appendChild(table);
  }
}

// ── breadcrumbs (TH-3) ──────────────────────────────────────────────────────────────────────
// A drill-down must carry its path back out (the studied consoles' regression was a detail
// view that ate the way home). Crumbs are SET by the drill-down itself and CLEARED by any
// view change; the non-final segments that carry a `run` are the way back.
let CRUMBS = [];
function setCrumbs(items) {
  CRUMBS = items || [];
  const host = document.getElementById("crumbs");
  if (!host) return;
  host.replaceChildren();
  host.classList.toggle("hidden", !CRUMBS.length);
  CRUMBS.forEach((c, i) => {
    if (i) host.appendChild(el("span", { class: "crumb-sep", text: "\u203a" }));
    const isLast = i === CRUMBS.length - 1;
    // US-6 FIX (found by driving the exit): a drill's crumb is usually the ONLY crumb, and the
    // old rule ("last crumb never carries a handler") rendered it as an inert span -- the
    // labeled way back existed and did nothing. A last crumb with a run is a button when it is
    // the whole trail; in a longer trail the last entry is where you already are.
    if (c.run && (!isLast || CRUMBS.length === 1)) {
      host.appendChild(el("button", {
        class: "crumb", text: c.label, attrs: { type: "button", title: c.title || "back" },
        on: { click: c.run },
      }));
    } else {
      host.appendChild(el("span", { class: "crumb muted" + (isLast ? " current" : ""), text: c.label }));
    }
  });
}
function clearCrumbs() { setCrumbs([]); }

/* US-6: the return trip. showView fires the origin view's loader, which replaces the DOM a
 * beat later, so the scroll is applied after that render (twice: cheap insurance for slow
 * loads -- the second call is a no-op once the first has consumed PENDING_SCROLL). */
/** US-10: THE WRITE TRAIL. One renderer serves both mounts (the fleet's card and Settings');
 *  the cards differ only in their default scope. Filters ride the URL (au.scope / au.action),
 *  so "show me the settings writes" is a shareable link. */
const WTL_STATE = { scope: "", action: "", target: "" };

function wtlQuery() {
  const q = ["limit=50"];
  if (WTL_STATE.scope) q.push("scope=" + encodeURIComponent(WTL_STATE.scope));
  if (WTL_STATE.action) q.push("action=" + encodeURIComponent(WTL_STATE.action));
  if (WTL_STATE.target) q.push("target=" + encodeURIComponent(WTL_STATE.target));
  return q.join("&");
}

function refreshWriteTrails() {
  // US-10's two in-view cards are gone (the operator, 2026-10-18: the trail has its own tab);
  // one mount, the Logs tab's Setting-changes card.
  for (const [id, def] of [["lg-changes", ""]]) {
    if (document.getElementById(id)) {
      loadWriteTrail(id, def).catch(showError);
    }
  }
}

async function loadWriteTrail(mountId, defaultScope) {
  const box = document.getElementById(mountId);
  if (!box) return;
  box.replaceChildren();
  let d;
  try {
    d = await getJSON("/api/write-trail?" + wtlQuery());
  } catch (exc) {
    box.appendChild(el("p", { class: "muted",
      text: "The trail cannot be read: " + (exc && exc.message ? exc.message : String(exc)) }));
    return;
  }
  // The select's own value: the shared filter when one is set, else this mount's default --
  // a card on Settings opens on the settings writes, the fleet's on the fleet's.
  const scopeShown = WTL_STATE.scope || defaultScope || "";
  const head = el("div", { class: "controls" });
  const scopeSel = el("select", { attrs: { title: "filter the trail by scope" } });
  for (const s of [""].concat(d.scopes || [])) {
    scopeSel.appendChild(el("option", { value: s, text: s || "any scope" }));
  }
  scopeSel.value = scopeShown;
  scopeSel.addEventListener("change", () => {
    WTL_STATE.scope = scopeSel.value;
    scheduleURLSync();
    refreshWriteTrails();
  });
  const actSel = el("select", { attrs: { title: "filter the trail by action" } });
  for (const a of [""].concat(d.actions || [])) {
    actSel.appendChild(el("option", { value: a, text: a || "any action" }));
  }
  actSel.value = WTL_STATE.action || "";
  actSel.addEventListener("change", () => {
    WTL_STATE.action = actSel.value;
    scheduleURLSync();
    refreshWriteTrails();
  });
  head.append(scopeSel, actSel);
  head.appendChild(el("span", { class: "wtl-chip" }, [el("span", { class: "muted",
    text: WTL_STATE.target ? "target " : "" })]));
  if (WTL_STATE.target) {
    const targetChip = el("button", { class: "dc-chip", text: WTL_STATE.target + " \u00d7",
      attrs: { type: "button", title: "stop filtering by this target" } });
    targetChip.addEventListener("click", () => {
      WTL_STATE.target = "";
      scheduleURLSync();
      refreshWriteTrails();
    });
    head.appendChild(targetChip);
  }
  box.appendChild(head);

  const rows = d.rows || [];
  box.appendChild(el("p", { class: "muted wtl-note", text: d.available === false
    ? "The trail cannot be read: " + (d.reason || "the store did not answer")
    : `${rows.length} entr${rows.length === 1 ? "y" : "ies"} — newest first`
      + (WTL_STATE.target ? ` · target ${WTL_STATE.target}` : "") }));

  const tbody = el("tbody");
  if (!rows.length && d.available !== false) {
    emptyRow(tbody, 6, "No writes have been recorded yet.");
  }
  for (const r of rows) {
    tbody.appendChild(el("tr", { class: WTL_STATE.target && r.target === WTL_STATE.target
                                   ? "clickable wtl-hit" : "",
      on: { click: () => { if (r.target) { WTL_STATE.target = r.target; scheduleURLSync();
                                            refreshWriteTrails(); } } } }, [
      el("td", { class: "mono", text: fmtTime(r.at) }),
      el("td", { class: "mono muted", text: r.scope || "" }),
      el("td", { text: r.action || "" }),
      el("td", { class: "mono", text: r.target || "" }),
      el("td", { text: r.reason || "\u2014" }),
      el("td", { class: "mono muted", text: r.actor || "" }),
    ]));
  }
  // A 50-entry write trail is a scrollable log, not a page-length table. Keep the newest
  // rows readable without making the Logs tab a 2,000px document; the header stays visible
  // while the reader scans.
  box.appendChild(el("div", { class: "tablewrap lg-trail-wrap" }, [
    el("table", {}, [
      el("thead", {}, [el("tr", {}, [
        el("th", { text: "when" }), el("th", { text: "scope" }), el("th", { text: "action" }),
        el("th", { text: "target" }), el("th", { text: "why" }), el("th", { text: "who" }),
      ])]),
      tbody,
    ]),
  ]));
}

/** US-10: "where did this value come from" -- ONE click from a settings row to its entries.
 *  Lands on the trail with the target pinned, and flashes the card so the eye finds it. */
function openSettingTrail(key) {
  WTL_STATE.scope = "settings";
  WTL_STATE.action = "";
  WTL_STATE.target = key;
  scheduleURLSync();
  // The trail lives on its own tab now: the link travels there, then filters and flashes.
  showView("logs");
  refreshWriteTrails();
  const card = document.getElementById("lg-changes");
  if (card) {
    if (typeof card.scrollIntoView === "function") {
      try { card.scrollIntoView({ block: "center" }); } catch (_e) { /* fine without it */ }
    }
    card.classList.add("row-flash");
    setTimeout(() => card.classList.remove("row-flash"), 1600);
  }
}

/** US-10: REVERT a GUI-written value to the version its write replaced. The BF-9 echo is the
 *  gate (a REQUIRED reason), and the revert is an audited write of its own (action=revert). */
async function revertSetting(key, prov) {
  const row = SETTINGS_ROWS[key] || {};
  const from = String(prov.value === undefined ? "" : prov.value);
  const to = String(prov.prev_value === undefined ? "" : prov.prev_value);
  const res = await confirmDestructive({
    title: `Revert ${row.label || key} to its previous value`,
    target: key,
    blast: `${key}: ${from || "(empty)"} \u2192 ${to || "(empty)"}` +
      (prov.at ? ` — the version replaced ${prov.at}` : ""),
    reasonHint: "why revert \u2014 required, recorded with your name and the time",
    confirmLabel: "Revert",
  });
  if (!res || !res.ok) return;
  const out = await postJSON("/api/settings/apply", {
    changes: { [key]: to },
    reason: res.reason,
    revert: true,
    confirmed: true,
  });
  if (!out || out.ok === false) {
    showError(new Error((out && out.error) || "the revert was refused"));
    return;
  }
  await loadSettings();
  refreshWriteTrails();
}

/** US-9 (with US-8): LAND ON a settings row. Every settings card boots collapsed, so this
 *  expands the row's own card FIRST, then scrolls and flashes. ONE implementation -- the
 *  palette and the per-row Tune verb both call it (a second copy would drift). */
function openSettingKey(key) {
  showView("settings");
  setTimeout(() => {
    const row = document.querySelector(`#view-settings [data-key="${key}"]`);
    if (!row) return;
    const card = row.closest(".card");
    if (card && card.classList.contains("collapsed")) {
      const head = card.querySelector(":scope > h2.acc, :scope > h3.acc");
      if (head) head.click();
    }
    if (typeof row.scrollIntoView === "function") {
      try { row.scrollIntoView({ block: "center" }); } catch (_e) { /* fine without it */ }
    }
    row.classList.add("row-flash");
    setTimeout(() => row.classList.remove("row-flash"), 1600);
  }, 160);
}

function returnWithScroll(view, scroll) {
  PENDING_SCROLL = Number(scroll) || 0;
  showView(view || "health");
  const apply = () => {
    if (PENDING_SCROLL === null) return;
    try { window.scrollTo(0, PENDING_SCROLL); } catch (_e) { /* jsdom / ancient engines */ }
    PENDING_SCROLL = null;
  };
  setTimeout(apply, 350);
  setTimeout(apply, 900);
}

/* US-3: a DRILL VIEW keeps its family's tab lit (Evidence belongs to Anomalies), and the URL
 * follows the VIEW NAME rather than whichever tab happens to match: `v=evidence` was
 * previously unwritable because no tab carried it, so a shared link lost the drill. */
const TAB_FOR_DRILL = { evidence: "anomalies", blocked: "sluice", findings: "assets" };
let CURRENT_VIEW = "";
// ONE ASSETS TAB, ONE NETWORK SCOPE (operator, 2026-10-19). "monitored" means a private or
// link-local address -- the networks this deployment's sensors actually sit on; "external" is
// a global address. A value that is not an address at all (a MAC, a hostname) is a host on the
// monitored side by construction: it was learned from that network's own traffic.
window.NET_SCOPE = "all";
function netScope(addr) {
  const a = String(addr || "").split("%")[0].trim().toLowerCase();
  if (!a) return "monitored";
  const v4 = a.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (v4) {
    const [o1, o2] = [Number(v4[1]), Number(v4[2])];
    return (o1 === 10 || o1 === 127 || (o1 === 172 && o2 >= 16 && o2 <= 31)
      || (o1 === 192 && o2 === 168) || (o1 === 169 && o2 === 254)) ? "monitored" : "external";
  }
  if (a.includes(":")) {
    return (a === "::1" || /^f[cd][0-9a-f]{2}:/.test(a) || /^fe[89ab][0-9a-f]:/.test(a))
      ? "monitored" : "external";
  }
  return "monitored";
}
function showView(name) {
  // HOST IS ITS OWN SURFACE (operator, 2026-10-19). It has no tab (it is reached from a host),
  // and it must not be folded back into Assets: that was the defect that made an alert's host
  // click land on the whole inventory.
  // IDENTITY IS PART OF ASSETS NOW (operator, 2026-10-19: "Combine assets and identity").
  // Old links and any palette entry that still says identity land on the combined tab.
  if (name === "identity") name = "assets";
  CURRENT_VIEW = name;
  // US-8: the session's last views become palette recents, however they were reached.
  if (typeof paletteNoteView === "function") paletteNoteView(name);
  clearCrumbs();       // a view change always leaves every drill-down behind
  scheduleURLSync();   // the URL follows the view; the timer lets this call finish first
  const tabName = TAB_FOR_DRILL[name] || name;
  for (const t of document.querySelectorAll(".tab")) {
    t.classList.toggle("active", t.dataset.view === tabName);
  }
  for (const v of document.querySelectorAll(".view")) {
    v.classList.toggle("active", v.id === "view-" + name);
  }
  // On a narrow screen the tab strip is a scrolling strip, and a view change that came from
  // clicking a row (Evidence, a drill-down) can leave the active tab scrolled out of view.
  // Desktop is untouched: the strip only scrolls below the 720px breakpoint.
  const activeTab = document.querySelector(".tab.active");
  if (activeTab && typeof window.matchMedia === "function" &&
      window.matchMedia("(max-width: 720px)").matches &&
      typeof activeTab.scrollIntoView === "function") {
    try { activeTab.scrollIntoView({ block: "nearest", inline: "nearest" }); }
    catch (_e) { /* older browsers: the tab stays wherever it is */ }
  }
  if (name === "logs") {
    // THE LOGS TAB: every alerting decision at the top, then the write trail and the
    // pipeline's self-audit. The audit rides the deep-health payload, so load it here too;
    // opening Logs must never show an empty audit because Health was not visited first.
    if (typeof refreshWriteTrails === "function") refreshWriteTrails();
    loadAudit().then(clearError).catch(showError);
    loadHealthDeep().then(clearError).catch(showError);
  }
  if (name === "anomalies") loadAnomalies().then(clearError).catch(showError);
  if (name === "models") {
    loadModels().then(clearError).catch(showError);
    loadRetrain().catch(showError);
  }
  if (name === "settings") {
    loadSettings().then(clearError).catch(showError);
  }
  // The Assets inventory loads on demand for the same reason the SOC views do: it runs a
  // query per Zeek host table, and firing that every 15s in the background would put load on
  // ClickHouse for a panel nobody is looking at.
  if (name === "assets") {
    loadAssets().then(clearError).catch(showError);
    loadIdentity().then(clearError).catch(showError);
  }
  if (name === "findings") loadFindings().then(clearError).catch(showError);
  if (name === "network") loadNetwork().then(clearError).catch(showError);
  // The SOC views load on demand rather than on every refresh cycle: they run several
  // aggregate queries each, and firing them every 15s in the background would put load on
  // ClickHouse for panels nobody is looking at.
  if (name === "netflow") loadNetflow().then(clearError).catch(showError);
  if (name === "zeek") loadZeek().then(clearError).catch(showError);
  // Discover loads on selection and on every filter change; like the SOC views it is not on
  // the refresh timer, because it is a reading surface, not a status surface.
  if (name === "discover") loadDiscover().then(clearError).catch(showError);
  if (name === "dns") loadDns().then(clearError).catch(showError);
  if (name === "blocked") loadBlocked().then(clearError).catch(showError);
  // The Sluice Gate loads on demand for the same reason as Identity: it reads two tables and the
  // gate's state row, and firing that in the background every 15s would query ClickHouse for a
  // panel nobody is looking at.
  if (name === "sluice") loadSluice().then(clearError).catch(showError);
  // WEIRLINGS. Loaded on tab selection like the other expensive views, and it is the one view
  // whose EMPTY state is a real answer ("nothing is registered"), so it must be loaded on
  // selection rather than left to a refresh timer.
  if (name === "weirlings") loadWeirlings().then(clearError).catch(showError);
  if (name === "health") loadHealthDeep().then(clearError).catch(showError);
}

/* THE VIEW YOU ARE LOOKING AT IS WHAT AUTO-REFRESH REFRESHES (the comment always claimed
 * this; the body previously reloaded only the health pill). Settings and drill-downs are
 * never auto-touched: churning a form under a reader is the rudest thing an auto-refresh can
 * do. The statusline carries the honesty: "updating…" while any of it is in flight, the
 * finish time when it is whole, "paused" when the operator has paused it. */
const VIEW_LOADERS = {
  health: () => loadHealthDeep(), anomalies: () => loadAnomalies(),
  logs: () => Promise.all([refreshWriteTrails(), loadAudit(), loadHealthDeep()]),
  netflow: () => loadNetflow(), dns: () => loadDns(), zeek: () => loadZeek(),
  discover: () => loadDiscover(), sluice: () => loadSluice(), blocked: () => loadBlocked(),
  weirlings: () => loadWeirlings(), models: () => loadModels(), identity: () => loadIdentity(),
  assets: () => loadAssets(), findings: () => loadFindings(),
  // US-3: Evidence joins the refreshable views -- it is the view most likely to be re-read
  // while an operator watches a live incident.
  evidence: () => (CURRENT_EVIDENCE && CURRENT_EVIDENCE.addr
    ? loadEvidence(CURRENT_EVIDENCE.addr, CURRENT_EVIDENCE.start, CURRENT_EVIDENCE.end)
    : Promise.resolve()),
};
let AUTO_PAUSED = false;

/* THE AUTO-BLOCK IS LOUD WHEREVER THE FLEET IS (BF-3). The threshold that can stop traffic
 * by itself gets a header pill that exists only while it is armed, carries the exact score,
 * and lands on the controls that pause it. The value rides the settings payload; the sluice
 * controls pass it in directly so the two surfaces can never disagree. */
function refreshAutoBlockPill(autoScore) {
  const pill = document.getElementById("auto-block-pill");
  if (!pill) return;
  if (autoScore == null) {
    getJSON("/api/settings").then((d) => {
      let found = "";
      for (const rs of Object.values((d && d.groups) || {})) {
        for (const r of rs || []) {
          if (r && String(r.key).toUpperCase() === "SLUICE_AUTO_SCORE") {
            found = String(r.value != null ? r.value : (r.current != null ? r.current : ""));
          }
        }
      }
      refreshAutoBlockPill(Number(found || "0") || 0);
    }).catch(() => { /* the pill simply stays as it was; nothing claims a value nobody read */ });
    return;
  }
  const v = Number(autoScore) || 0;
  const on = v > 0;
  pill.classList.toggle("hidden", !on);
  pill.textContent = on ? `auto-block \u2265 ${v.toFixed(2)}` : "";
  pill.setAttribute("aria-pressed", on ? "true" : "false");
}

function setAutoNote(text) {
  const n = document.getElementById("fetched");
  if (n) n.textContent = text;
}

function setAutoPaused(paused) {
  AUTO_PAUSED = !!paused;
  if (AUTO_PAUSED) {
    if (timer) { clearInterval(timer); timer = null; }
    setAutoNote("auto-refresh paused");
  } else {
    startAuto(15);
    setAutoNote("");
  }
  const pill = document.getElementById("auto-toggle");
  if (pill) {
    // LIVE / PAUSED, said plainly (BF-12): the pill is the answer to "is this page still
    // updating itself?" and nothing else on it competes with that question.
    pill.textContent = AUTO_PAUSED ? "paused" : "live · 15s";
    pill.title = AUTO_PAUSED
      ? "auto-refresh is paused — click to resume"
      : "auto-refresh is live (every 15s) — click to pause";
    pill.setAttribute("aria-pressed", AUTO_PAUSED ? "true" : "false");
  }
}

async function refreshAll(opts = {}) {
  if (AUTO_PAUSED) return;
  clearGetCache();
  setAutoNote("updating…");
  try {
    await loadHealthDeep();
    const active = document.querySelector(".tab.active");
    // US-3: follow the VIEW, not the tab -- Evidence has no tab and used to be skipped by
    // auto-refresh without a word.
    const viewName = CURRENT_VIEW || (active && active.dataset.view);
    const loader = viewName && VIEW_LOADERS[viewName];
    // BOOT WITH A DEEP LINK: applyURLState() already called showView(), whose loader is
    // already fetching the selected view. Calling it again here doubled the view's API calls
    // (and the duplicate settings/users/system reads behind it). The header health read still
    // runs; only the view's second load is skipped.
    if (loader && !opts.skipView) await loader();
    clearError();
    const now = new Date();
    const p = (n) => String(n).padStart(2, "0");
    setAutoNote("updated " + p(now.getHours()) + ":" + p(now.getMinutes()) + ":" +
                p(now.getSeconds()));
  } catch (err) {
    showError(err);
    setAutoNote("update failed — see the banner");
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
  const stagePill = document.getElementById("stage-pill");
  if (stagePill) {
    stagePill.addEventListener("click", () => {
      // THE CHIP IS A DOOR TO THE REVIEW, NEVER A COMMIT BUTTON: it lands on the same staged
      // list every other path uses. Nothing here can write.
      showView("settings");
      const card = document.getElementById("st-stage-card");
      if (card && card.scrollIntoView) {
        try { card.scrollIntoView({ block: "center" }); } catch (_e) { /* jsdom has none */ }
      }
    });
  }
  renderStagePill();
  const abPill = document.getElementById("auto-block-pill");
  if (abPill && !window.__abWired) {
    window.__abWired = true;
    abPill.addEventListener("click", () => {
      showView("sluice");
      loadBlockingControls().catch(() => {});
      // The score field moved to Settings with the duplicate card; land the operator on the
      // state line instead, and on the pause when the threshold is actually armed.
      const pause = document.querySelector("#sl2-auto button");
      const line = document.getElementById("sl2-auto");
      const target = (pause && !pause.classList.contains("hidden")) ? pause : line;
      if (target && target.focus) { target.setAttribute("tabindex", "-1"); target.focus(); }
    });
  }
  const autoPill = document.getElementById("auto-toggle");
  if (autoPill && !window.__autoWired) {
    window.__autoWired = true;
    autoPill.addEventListener("click", () => setAutoPaused(!AUTO_PAUSED));
  }
  const helpPill = document.getElementById("all-help");
  if (helpPill && !window.__allHelpWired) {
    window.__allHelpWired = true;
    helpPill.addEventListener("click", () => toggleAllHelp());
    document.addEventListener("keydown", (e) => {
      if (e.key !== "?" && !(e.key === "/" && e.shiftKey)) return;
      const t = e.target;
      if (t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA" ||
                t.tagName === "SELECT" || t.isContentEditable)) {
        return;   // a question mark typed into a field is just a question mark
      }
      e.preventDefault();
      toggleAllHelp();
    });
  }
  document.getElementById("refresh").addEventListener("click", refreshAll);
  const updateCheck = document.getElementById("st-update-check");
  if (updateCheck && !window.__updateWired) {
    window.__updateWired = true;
    updateCheck.addEventListener("click", () => loadUpdateStatus(true).catch(showError));
  }
  document.getElementById("h-go").addEventListener("click", () => {
    const a = document.getElementById("h-addr").value.trim();
    if (a) loadHost(a, String(trHours())).then(clearError).catch(showError);
  });
  document.getElementById("h-addr").addEventListener("keydown", (e) => {
    if (e.key === "Enter") document.getElementById("h-go").click();
  });
  // US-3: the drill-down DISMISSES. The lookup stays in the box, so "close" hides the panel
  // without throwing away the address that was just used.
  const hClose = document.getElementById("h-close");
  if (hClose) {
    hClose.addEventListener("click", () => {
      document.getElementById("h-results").classList.add("hidden");
    });
  }
  const idClose = document.getElementById("id-detail-close");
  if (idClose) {
    idClose.addEventListener("click", () => {
      const card = document.getElementById("id-detail-card");
      if (typeof closeSheet === "function") closeSheet(card);
      else card.classList.add("hidden");
    });
  }
  const idOpen = document.getElementById("id-detail-open");
  if (idOpen) {
    idOpen.addEventListener("click", () => {
      // The sheet is a layer, not a card: leaving it open behind the host view would leave
      // two surfaces claiming the same screen.
      const detailCard = document.getElementById("id-detail-card");
      if (typeof closeSheet === "function") closeSheet(detailCard);
      if (CURRENT_ID_HOST) openHost(CURRENT_ID_HOST);
    });
  }
  for (const id of ["f-queue-mode", "f-min-score", "f-limit", "f-unreviewed", "f-watched"]) {
    document.getElementById(id).addEventListener("change", () => {
      loadAnomalies().then(clearError).catch(showError);
    });
  }
  // SOC view controls. Each reload is explicit rather than automatic for the reason given
  // in showView: these run aggregate queries and should not fire on a background timer.
  for (const [id, fn] of [
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
    ["st-stage-discard", async () => discardStage()],
    ["st-expand", async () => settingsSetAll(true)],
    ["st-collapse", async () => settingsSetAll(false)],
    ["st-stage-jump", async () => settingsJumpToStage()],
    // THE SHEET'S APPLY IS THE SAME APPLY (WSM-2): same STAGE, same plan, same write route,
    // same receipt. Nothing here is a second settings mechanism.
    ["wl-stage-apply", () => applyStage(true, {
      skipSiphonConfirm: true,
      reason: "applied from the Weirlings sheet",
    }).catch(showError)],
    ["wl-stage-discard", async () => discardStage()],
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
    scheduleURLSync();   // US-7: the search rides the URL
  });
  const asSort = document.getElementById("as-sort");
  if (asSort) asSort.addEventListener("change", (e) => {
    ASSETS_STATE.sort = e.target.value;
    // Reordering moves every row, so holding the page number would show a different set of
    // hosts than the one the reader was looking at.
    ASSETS_STATE.page = 1;
    renderAssets();
  });
  // A COLUMN HEADER SORTS (operator, 2026-10-19: inventory review). The select stays for
  // discoverability; the headers are the fast path an operator reaches for.
  for (const th of document.querySelectorAll("#as-table th[data-sort]")) {
    th.addEventListener("click", () => {
      ASSETS_STATE.sort = th.dataset.sort;
      ASSETS_STATE.page = 1;
      const sel = document.getElementById("as-sort");
      if (sel) sel.value = ASSETS_STATE.sort;
      renderAssets();
    });
  }
  const asScope = document.getElementById("as-scope");
  if (asScope) asScope.addEventListener("change", (e) => {
    window.NET_SCOPE = e.target.value;
    ASSETS_STATE.page = 1;
    renderAssets();
    // The identity table is filtered by the same value; re-read it so the two panels cannot
    // disagree about which network is on screen.
    if (typeof loadIdentity === "function") loadIdentity().catch(showError);
  });
  // ── Network graph controls ─────────────────────────────────────────────────
  const nwClear = document.getElementById("nw-clear");
  if (nwClear) nwClear.addEventListener("click", () => {
    ASSETS_STATE.tracked = [];
    // Clearing the selection also releases the tracked-only filter: leaving it on would point
    // the graph at an empty set and read as "no traffic".
    ASSETS_STATE.trackedOnly = false;
    const only = document.getElementById("nw-only-tracked");
    if (only) only.setAttribute("aria-pressed", "false");
    loadNetwork().then(clearError).catch(showError);
  });
  // The edge filter re-renders from the cached payload; it is a view control, not a query.
  const nwMin = document.getElementById("nw-min");
  if (nwMin) nwMin.addEventListener("input", (e) => {
    ASSETS_STATE.minEdges = Number(e.target.value) || 1;
    renderNetwork();
    scheduleURLSync();   // US-7
  });
  const nwLabels = document.getElementById("nw-labels");
  if (nwLabels) nwLabels.addEventListener("change", (e) => {
    ASSETS_STATE.showNames = e.target.checked;
    renderNetwork();
    scheduleURLSync();   // US-7
  });
  // All / Blocked / Alerted: a reading of the cached graph, not a refetch. The buttons carry
  // aria-pressed and the filter rides the URL with the other Network controls. Look each one up
  // by id: the orphan audit proves every control in the HTML has a consumer in the JS.
  for (const [id, status] of [["nw-status-all", "all"], ["nw-status-blocked", "blocked"],
                              ["nw-status-alerted", "alerted"]]) {
    const btn = document.getElementById(id);
    if (!btn) continue;
    btn.addEventListener("click", () => {
      ASSETS_STATE.status = status;
      renderNetwork();
      scheduleURLSync();
    });
  }
  // US-7: the tracked-only chip. A real filter over the cached graph (no refetch), pressed when
  // it holds the filter, and carrying its state in the URL.
  const nwOnly = document.getElementById("nw-only-tracked");
  if (nwOnly) nwOnly.addEventListener("click", () => {
    ASSETS_STATE.trackedOnly = !ASSETS_STATE.trackedOnly;
    nwOnly.setAttribute("aria-pressed", ASSETS_STATE.trackedOnly ? "true" : "false");
    renderNetwork();
    scheduleURLSync();
  });
  // Re-settle: re-run the deterministic layout, discarding any hand-dragged arrangement --
  // the way back to the comparable view without a reload.
  const nwSettle = document.getElementById("nw-settle");
  if (nwSettle) nwSettle.addEventListener("click", () => settleGraph());

  // ── the forced retrain (models view) ────────────────────────────────────────
  // Guarded like the other wirings: a missing control costs one button, not every listener
  // registered after this point.
  const mrForce = document.getElementById("mr-force");
  if (mrForce) mrForce.addEventListener("click", () => retrainAction("retrain").catch(showError));
  const mrKeep = document.getElementById("mr-keep");
  if (mrKeep) mrKeep.addEventListener("click", () => retrainAction("keep").catch(showError));
  const mrTrash = document.getElementById("mr-trash");
  if (mrTrash) mrTrash.addEventListener("click", () => retrainAction("trash").catch(showError));

  // ── fingerprint lookup (identity view) ─────────────────────────────────────
  // Guarded like the module wirings below: if the markup is absent the page should lose one
  // lookup, not every listener registered after this point.
  const fpGo = document.getElementById("fp-go");
  const fpInput = document.getElementById("fp-input");
  if (fpGo && fpInput) {
    const run = () => lookupFingerprint(fpInput.value).catch(showError);
    fpGo.addEventListener("click", run);
    fpInput.addEventListener("keydown", (e) => { if (e.key === "Enter") run(); });
  }

  // ── Sluice Gate controls ───────────────────────────────────────────────────
  // Wired from HERE rather than from sluice.js so that every listener in this application is
  // registered in one place -- a file that wires itself on load makes "what is bound to this
  // button" a search across the whole bundle.
  //
  // GUARDED because sluice.js is a separate file: if it failed to load, an unguarded call would
  // throw during bootstrap and leave EVERY other view unwired. A missing module should cost one
  // tab, not the dashboard.
  if (typeof wireSluice === "function") wireSluice();

  // ── Weirlings controls ──────────────────────────────────────────────────────
  // The detail panel's buttons -- close, enable / switch off / revoke, and the
  // register-from-observation action -- plus the register form's own Save. Same one-place
  // convention and the same guard as sluice above.
  //
  // MEASURED at the first deployment: this call was MISSING, so every one of those buttons
  // rendered and did nothing. The harness never noticed because it asserted on labels, not on
  // clicks -- the first click assertion ("registering the undeclared sensor posts its observed
  // id") failed on a button that looked perfect. A control that renders and does nothing is the
  // project's most-repeated defect class wearing its most convincing costume.
  if (typeof wireWeirlings === "function") wireWeirlings();

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

// ── ONE VIEW HEADER (VR-HDR) ─────────────────────────────────────────────────────────────────
// Every view opens with one title, one count and one primary verb. The console has many cards
// that once used <h2>; they are sub-blocks and are demoted to <h3> at boot. The header itself is
// the only <h2> in the view, and its count is copied from the view's own summary line whenever
// that line is re-rendered.
const VH_COUNTS = Object.create(null);
const VIEW_HEADER_META = {
  health: { heading: "Health", count: "hp-summary" },
  anomalies: { heading: "All anomalies", count: "an-count-line" },
  network: { heading: "Network", count: "nw-caption" },
  netflow: { heading: "Netflow", count: "nf-summary" },
  discover: { heading: "Flows", count: "dc-summary" },
  dns: { heading: "DNS", count: "dn-summary" },
  zeek: { heading: "Zeek", count: "zk-summary" },
  sluice: { heading: "Sluice Gate", count: "sl2-count" },
  weirlings: { heading: "Weirlings", count: "wl-count" },
  assets: { heading: "Assets", count: "as-summary" },
  models: { heading: "Models", count: "m-summary" },
  settings: { heading: "Settings", count: "st-summary" },
  logs: { heading: "Logs", count: "hp-alerts-note" },
  evidence: { heading: "Evidence", count: "ev-sub" },
  host: { heading: "Host", count: "hp-sub" },
  blocked: { heading: "Blocks", count: "bl-summary" },
  findings: { heading: "Findings", count: "fd-summary" },
};

function vhDemote(h2) {
  if (!h2 || h2.classList.contains("view-title")) return;
  const h3 = document.createElement("h3");
  for (const attr of [...h2.attributes]) h3.setAttribute(attr.name, attr.value);
  while (h2.firstChild) h3.appendChild(h2.firstChild);
  h2.replaceWith(h3);
}

function installViewHeaders() {
  for (const view of document.querySelectorAll(".view")) {
    const key = String(view.id || "").replace(/^view-/, "");
    const meta = VIEW_HEADER_META[key];
    if (!meta) continue;
    let head = view.querySelector(":scope > .view-head");
    if (!head) {
      head = el("div", { class: "view-head view-header" });
      view.prepend(head);
    }
    let title = head.querySelector("h2");
    if (!title) {
      title = el("h2", { class: "view-title", text: meta.heading });
      head.prepend(title);
    } else {
      title.classList.add("view-title");
    }
    if (!VH_COUNTS[key]) {
      VH_COUNTS[key] = el("span", { class: "muted view-count", text: "—" });
      title.appendChild(VH_COUNTS[key]);
    }
    // One primary verb: move the view's existing primary into the header (it keeps its id and
    // listeners), or add Refresh for a reading-only view. Never clone: two controls for one job
    // is the duplicate this header exists to remove.
    const existing = [...view.querySelectorAll("button.primary")].find((b) =>
      b !== title && !b.closest(".hidden, .sheet, .modal, [role='dialog'], [hidden]"));
    if (existing && existing.parentElement !== head) {
      head.appendChild(existing);
    } else if (!existing && !head.querySelector("button.primary")) {
      const refresh = el("button", { class: "primary", text: "Refresh" });
      refresh.addEventListener("click", () => refreshAll());
      head.appendChild(refresh);
    }
    for (const h2 of view.querySelectorAll("h2")) vhDemote(h2);
    // settingsAccordion() wired the card headings before they were demoted; its listeners
    // stayed on the removed <h2>. Re-wire the settings h3.acc headings it created.
    if (key === "settings") {
      for (const h3 of view.querySelectorAll(":scope > .card > h3.acc")) {
        if (h3.dataset.accWired) continue;
        h3.dataset.accWired = "1";
        h3.addEventListener("click", (e) => {
          if (e.target.closest("button, a, input, select")) return;
          h3.closest(".card")?.classList.toggle("collapsed");
        });
      }
    }
    // The header title was the ONE h2 we kept; demote any h2 in sheets/modals outside views too.
    for (const h2 of document.querySelectorAll("h2:not(.view-title)")) vhDemote(h2);
    title.classList.add("view-title");
  }
  syncViewHeaderCounts();
}

function syncViewHeaderCounts() {
  for (const [key, meta] of Object.entries(VIEW_HEADER_META)) {
    const out = VH_COUNTS[key];
    if (!out || !meta.count) continue;
    const src = document.getElementById(meta.count);
    if (!src) continue;
    let text = String(src.innerText || src.textContent || "").replace(/\s+/g, " ").trim();
    if (!text && key === "settings") {
      text = `${document.querySelectorAll("#view-settings > .card").length} sections`;
    } else if (!text && key === "evidence") {
      text = `${document.querySelectorAll("#ev-chain .chain-step").length} stages`;
    }
    if (text && text !== out.textContent) out.textContent = text;
  }
}

let VH_SYNC_TIMER = null;
function scheduleViewHeaderSync() {
  if (VH_SYNC_TIMER) return;
  VH_SYNC_TIMER = setTimeout(() => {
    VH_SYNC_TIMER = null;
    syncViewHeaderCounts();
  }, 40);
}

async function boot() {
  // THE RESPONSIVE PASS, before anything renders: a table wider than the screen must scroll
  // inside its own box rather than widen the page (see wrapTables and style.css).
  wrapTables();
  lockTabsToTop();
  settingsAccordion();
  modalWiring();
  filterCellWiring();
  // The "i" affordances: every view's explainer is one click from the header it explains.
  wireInfoButtons();
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

/**
 * Show the server's own `/api/session` note when the console is running without accounts (WV1-17).
 *
 * The note says things like "the user store could not be read; no accounts were created this
 * startup". It reached the screen from exactly one place: the sign-in gate's text. But the gate is
 * only shown when accounts EXIST and the visitor is not signed in, so the one state that produces
 * the note -- no readable store -- was the one state that never displayed it. Measured live:
 * /api/session returned that note and the console showed no trace of it, while Settings said "This
 * deployment has no accounts provisioned", which describes a benign first run.
 *
 * WHY IT MATTERS, and it is not cosmetic: with no readable store `_accounts_on` is False, so
 * `_require_read` serves every READ without a session (writes stay token-gated). Measured:
 * /api/settings, /api/system and /api/sluice all returned 200 unauthenticated; /api/users returned
 * 403. Failing open for reads is a defensible trade only if the operator is told it is happening.
 */
function showSessionNote() {
  if (AUTH.accounts) return;  // there is a gate, and the note belongs to its prompt
  const note = String(AUTH.note || "").trim();
  if (!note) return;  // a genuine first run has nothing to report
  if (document.getElementById("auth-note-banner")) return;
  const main = document.querySelector("main");
  if (!main) return;
  main.prepend(el("div", {
    class: "banner",
    attrs: { id: "auth-note-banner", role: "status" },
    text: "No account store: reads are open. " + note
      + " Every view on this dashboard can be read without signing in; changing anything still "
      + "requires the operator token.",
  }));
}

/** What runs once there is (or may be) a usable identity: the pre-accounts posture or a
 *  signed-in account, with the forced-change gate in between. */
async function bootAuthed() {
  showSessionNote();
  installViewHeaders();
  if (window.MutationObserver && !window.__vhObserver) {
    window.__vhObserver = new MutationObserver(scheduleViewHeaderSync);
    window.__vhObserver.observe(document.body, { subtree: true, childList: true, characterData: true });
  }
  if (!window.__vhTimer) window.__vhTimer = setInterval(syncViewHeaderCounts, 1000);
  refreshChrome();
  refreshAccountCard();
  if (AUTH.authenticated && AUTH.must_change) {
    showGate("pw");
    return;
  }
  showGate("");
  const fromURL = applyURLState();
  wireHistoryNavigation();
  // A URL-selected view has already started its own loader inside applyURLState. Let the
  // boot refresh load the shared health/status data without issuing the same view request
  // a second time.
  refreshAll({ skipView: Boolean(fromURL) });
  refreshAutoBlockPill();   // quiet read; the pill appears only if the threshold is armed
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
  "Isolation Forest": "var(--series-1)",
  "Gradient Boosting": "var(--series-2)",
  "DBSCAN": "var(--series-3)",
  "Adaptive Baseline": "var(--series-4)",
  "Ensemble": "var(--series-5)",
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
/** AB-1: the adaptive baseline's own read + card. */
async function loadBaselinesCard() {
  let bl = null;
  try {
    bl = await getJSON("/api/baselines");
  } catch (err) {
    bl = { available: false, reason: (err && err.message) || String(err) };
  }
  renderBaselines(bl);
}

/** Volume formatting for the baseline table; local so this file stands alone under the gate's
 *  call scan (a bare call to another web file's helper would fail it). */
function mbBytes(n) {
  const v = Number(n) || 0;
  if (v >= 1048576) return (v / 1048576).toFixed(1) + " MB";
  if (v >= 1024) return (v / 1024).toFixed(1) + " KB";
  return Math.round(v) + " B";
}

/** Seconds -> the words a person reads. The SERVER computes the age, so the card reads the
 *  same in a check as it does in a browser. */
function mbAgeText(s) {
  if (s === null || s === undefined || s === "") return null;
  const v = Number(s);
  if (!Number.isFinite(v)) return null;
  if (v < 90) return Math.round(v) + "s";
  if (v < 5400) return Math.round(v / 60) + " min";
  return Math.round(v / 3600) + "h";
}

function renderBaselines(bl) {
  const note = document.getElementById("mb-note");
  const sum = document.getElementById("mb-summary");
  const fired = document.getElementById("mb-fired");
  const win = document.getElementById("mb-window");
  const body = document.querySelector("#mb-hosts tbody");
  if (!body || !note) return;
  body.innerHTML = "";
  if (win) win.textContent = "";
  if (!bl || !bl.available) {
    note.textContent = "Unavailable: "
      + ((bl && bl.reason) || "the baseline store could not be read")
      + " \u2014 this is a read failure, not an empty baseline.";
    if (sum) sum.textContent = "";
    if (fired) fired.textContent = "";
    return;
  }
  const age = mbAgeText(bl.refreshed_age_s);
  note.textContent = age === null
    ? "No snapshot time recorded."
    : "Newest snapshot " + age + " ago \u2014 refreshed every detection cycle.";
  const n = Number(bl.host_count || 0);
  const parts = [n + " host" + (n === 1 ? "" : "s") + " carr" + (n === 1 ? "ies" : "y")
                 + " a learned baseline"];
  if (bl.behavioural_hosts !== null && bl.behavioural_hosts !== undefined) {
    parts.push(bl.behavioural_hosts + " with behavioural (Zeek) baselines");
  }
  if (bl.fingerprint_hosts !== null && bl.fingerprint_hosts !== undefined) {
    parts.push(bl.fingerprint_hosts + " with fingerprint history");
  }
  if (sum) sum.textContent = parts.join(" \u00b7 ") + ".";
  if (fired) {
    const err = bl.errors && bl.errors.fired;
    if (err) fired.textContent = "Could not read what it flagged: " + err + ".";
    else if (bl.fired_24h === null || bl.fired_24h === undefined) {
      fired.textContent = "What it flagged could not be read.";
    } else if (bl.fired_24h === 0) {
      fired.textContent = "Nothing flagged in the last 24h of scored windows \u2014 a quiet "
        + "baseline, stated as a fact, not rendered as an empty box.";
    } else {
      fired.textContent = "Flagged " + bl.fired_24h + " row" + (bl.fired_24h === 1 ? "" : "s")
        + " in the last 24h" + (bl.last_fired ? " \u2014 most recently " + bl.last_fired : "") + ".";
    }
  }
  const hosts = bl.hosts || [];
  if (!hosts.length) {
    body.appendChild(el("tr", {}, [
      el("td", { class: "muted", attrs: { colspan: 8 },
                 text: "No host has a baseline yet \u2014 the first training window has not "
                       + "filled. This says the store is EMPTY, not that the read failed." }),
    ]));
    return;
  }
  if (win) win.textContent = (Number(hosts[0].window_hours) || 24) + "h windows";
  const show = hosts.slice(0, 12);
  for (const h of show) {
    body.appendChild(el("tr", {}, [
      el("td", { class: "dcell", attrs: { "aria-label": "open this host's view" },
                 on: { click: () => { openHost(h.src_addr); } } },
         [hostCell(h.src_addr, h.hostname)]),
      el("td", { class: "num", text: mbBytes(h.avg_bytes) }),
      el("td", { class: "num", text: mbBytes(h.p95_bytes) }),
      el("td", { class: "num", text: mbBytes(h.p99_bytes) }),
      el("td", { class: "num", text: Math.round(Number(h.avg_packets) || 0).toLocaleString() }),
      el("td", { class: "num", text: String(Math.round((Number(h.avg_unique_dsts) || 0) * 10) / 10) }),
      el("td", { class: "muted", text: (Number(h.window_hours) || 0) + "h of traffic" }),
      el("td", { class: "muted", text: h.computed_at ? fmtTime(h.computed_at) : "\u2014" }),
    ]));
  }
  if (hosts.length > show.length) {
    body.appendChild(el("tr", {}, [
      el("td", { class: "muted", attrs: { colspan: 8 },
                 text: "and " + (hosts.length - show.length) + " more host(s)" }),
    ]));
  }
}

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
      el("td", { class: "muted", attrs: { colspan: "5" },
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
      // LAST USABLE IS NOT LAST RETRAINED (GitHub #60): a DBSCAN run with zero clusters
      // completes and saves an artifact, but it cannot score. Saying "current" beside that
      // date was the lie this column exists to stop.
      el("td", { class: "mono muted", text: r.last_usable ? fmtTime(r.last_usable) : "—" }),
      el("td", {}, [age]),
      el("td", {}, [
        r.never_trained
          ? el("span", { class: "sev-medium", text: "never trained" })
          : r.usable === false
            ? el("span", { class: "sev-medium", text: "not scoring" })
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
    const colour = MODEL_COLORS[name] || "var(--muted)";
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
  // THE SCALE IS THE GLOBAL MAX STACK, THE SAME FOR EVERY BAND (issue #6 landed stack scaling;
  // issue #35 resolved the ambiguity it left). Every segment used to draw against the global
  // per-detector max, so a band where several detectors each scored near that max stacked to
  // k x the plot height and painted over the card above. The #6 fix scaled each band against its
  // OWN stack total -- which drew EVERY non-empty band full height: a one-score band rendered
  // identically to a ten-score band, and the count axis over-read the short one. Under the
  // global max stack the tallest band exactly fills the plot, every other non-empty band tops
  // out proportionally, and the axis (the largest stack) reads honestly for all of them.
  const stackTotal = new Array(BANDS).fill(0);
  for (let i = 0; i < BANDS; i++) {
    for (const n of names) stackTotal[i] += counts[n][i];
  }
  const max = Math.max(1, ...stackTotal);
  // A WIDE, SHORT viewBox ON PURPOSE (the operator, 2026-10-16: "this graph is larger than the
  // chart bounds"). The chart is width:100%/height:auto, so its RATIO decides its height: at
  // 440x200 (2.2) a half-width card on a wide screen rendered it ~800px tall, dwarfing every
  // sibling. At 760x220 (3.45) it sits at the same visual weight as the other model charts.
  const W = 760, H = 220, PAD = { l: 34, r: 10, t: 10, b: 30 };
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
        fill: MODEL_COLORS[n] || "var(--muted)", opacity: 0.85,
      }));
      y -= h;
    }
    axisLabel(svg, plot.l + i * bw + bw / 2, H - 10, (i / 10).toFixed(1));
  }
  svg.appendChild(svgEl("line", { x1: plot.l, y1: plot.b, x2: plot.r, y2: plot.b, class: "axis" }));
  axisLabel(svg, plot.l - 6, plot.t + 10, String(max), "end");
  axisLabel(svg, plot.l - 6, plot.b, "0", "end");
  host.appendChild(svg);
  host.appendChild(el("p", { class: "muted", text: `max stack ${max} per band, over ${total} score(s)` }));
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
    const colour = MODEL_COLORS[name] || "var(--muted)";
    const pct = (c / max) * 100;
    host.appendChild(el("div", { class: "bar-row" }, [
      el("span", { class: "bar-name", text: name }),
      el("span", { class: "bar-track" }, [
        el("span", { class: "bar-fill", attrs: { style: `width:${pct}%;background:${colour}` } }),
      ]),
      el("span", { class: "bar-val", text: String(c) }),
    ]));
  }
  host.appendChild(el("p", { class: "muted", text:
    "A detector missing here fired on nothing, which is itself worth knowing." }));
}

/** Baseline deviations: mean |z| per baseline-backed measurement, against a z=1/2/3 guide. */
function renderFeatureDeviations(rows, coverage) {
  const host = document.getElementById("m-features");
  host.innerHTML = "";
  if (!rows || !rows.length) {
    host.appendChild(chartEmpty(
      "No baseline deviations recorded. These are written from feature_contributions, " +
      "so they appear once an anomaly carries one."));
    return;
  }
  const max = Math.max(1, ...rows.map((r) => r.mean_abs_z), ...rows.map((r) => r.max_abs_z));
  for (const r of rows) {
    const w = (r.mean_abs_z / max) * 100;
    const wMax = (r.max_abs_z / max) * 100;
    const alerts = el("button", { class: "link", text: "alerts",
      attrs: { "aria-label": `show anomalies whose primary feature is ${r.feature}` } });
    alerts.addEventListener("click", (e) => {
      e.stopPropagation();
      // Set the state before the view switch: the switch issues the load that must carry it.
      anSetFilter("feature", r.feature);
      showView("anomalies");
    });
    host.appendChild(el("div", { class: "bar-row dcell",
      attrs: { title: `${r.feature}: click to filter the points table to this feature` },
      on: { click: () => mSetFilter("feature", r.feature) } }, [
      el("span", { class: "bar-name", text: r.feature,
                   title: `${r.feature}: mean |z| ${r.mean_abs_z.toFixed(2)}, peak ${r.max_abs_z.toFixed(2)}, n=${r.n}` }),
      el("span", { class: "bar-track" }, [
        el("span", { class: "bar-fill ghost", attrs: { style: `width:${wMax}%` } }),
        el("span", { class: "bar-fill", attrs: { style: `width:${w}%;background:var(--series-1)` } }),
      ]),
      el("span", { class: "bar-val", text: r.mean_abs_z.toFixed(2) }),
      alerts,
    ]));
  }
  const inputs = coverage && Number(coverage.model_inputs);
  host.appendChild(el("p", { class: "muted", text:
    `${rows.length}${inputs ? " of " + inputs : ""} model inputs have a per-host baseline. ` +
    "The rest feed the models but do not have a z-score; filled bar is the mean deviation, " +
    "the pale extension is the peak. z around 1 is normal noise, 3+ is unusual for that host." }));
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
  const allRows = data.near_misses || [];
  const rows = allRows.filter((nm) => !M_FILTERS.host || String(nm.src_addr || "") === M_FILTERS.host);
  if (!rows.length) {
    body.appendChild(el("tr", {}, [
      el("td", { class: "muted",
                 text: allRows.length
                   ? "No near miss matches the host filter."
                   : "No near misses in this window — nothing scored close to the bar.",
                 attrs: { colspan: 6 } }),
    ]));
    return;
  }
  note.appendChild(el("p", { class: "muted", text:
    `${rows.length} window(s) within reach of the bar. Raising the threshold would `
    + `reclassify the below-threshold rows; lowering it would surface the gate rows.`
    + (M_FILTERS.feature
        ? " The feature filter does not reach these rows: they carry no feature column." : "") }));
  for (const nm of rows) {
    body.appendChild(el("tr", {}, [
      el("td", { class: "mono", text: fmtTime(nm.window_start) }),
      el("td", { class: "dcell", attrs: { title: "filter this view to this host" },
                 on: { click: (e) => { e.stopPropagation(); mSetFilter("host", nm.src_addr); } } },
         [hostCell(nm.src_addr, nm.hostname)]),
      el("td", { class: "num", text: Number(nm.score || 0).toFixed(3) }),
      el("td", { class: "num", text: Number(nm.threshold || 0).toFixed(3) }),
      el("td", { text: nm.reason === "agreement-gate"
                   ? "agreement gate (too few models agreed)"
                   : "below threshold" }),
      el("td", { text: (nm.models || []).join(", ") || "—" }),
    ]));
  }
}

/**
 * CLICK-TO-FILTER for the models view (the operator, 2026-10-16: "if i click in any dashboard it
 * should filter that entire dashboard"). Same contract as the identity list, and the same
 * reason it is client-side: these tables render the window's full set -- no pagination -- so
 * the filter cannot hide a match the browser never received.
 *
 * WHAT EACH FILTER REACHES, stated where a reader needs it: HOST narrows both row tables (the
 * points and the near misses); FEATURE narrows the points table, the only one with a feature
 * column -- when it is active the near-miss caption SAYS SO, because a filter a panel silently
 * ignores would make the view agree with itself only by accident.
 */
const M_FILTERS = { host: "", feature: "" };

function mRenderChips() {
  const box = document.getElementById("m-filters");
  if (!box) return;
  box.replaceChildren();
  for (const field of ["host", "feature"]) {
    if (!M_FILTERS[field]) continue;
    const chip = el("button", { class: "dc-chip", attrs: { title: "remove this filter" },
      text: `${field} = ${M_FILTERS[field]} \u00d7` });
    chip.addEventListener("click", () => {
      M_FILTERS[field] = "";
      mRenderChips();
      loadModels().catch(showError);
    });
    box.appendChild(chip);
  }
}

function mSetFilter(field, value) {
  M_FILTERS[field] = String(value || "");
  mRenderChips();
  loadModels().catch(showError);
}

function mKeepPoint(pt) {
  if (M_FILTERS.host && String(pt.src_addr || "") !== M_FILTERS.host) return false;
  if (M_FILTERS.feature && String(pt.primary || "") !== M_FILTERS.feature) return false;
  return true;
}

function renderCalibration(data) {
  const note = document.getElementById("m-cal-note");
  const body = document.querySelector("#m-cal tbody");
  if (!note || !body) return;
  body.replaceChildren();
  if (!data || !data.available) {
    note.textContent = "Calibration unavailable: " + ((data && data.reason) || "the read failed");
    body.appendChild(el("tr", {}, [el("td", { class: "muted", attrs: { colspan: 8 },
      text: "No calibration rows were read." })]));
    return;
  }
  const rows = data.rows || [];
  if (!rows.length) {
    note.textContent = "No calibration rows yet. The worker's shadow pass has not written a " +
      "reference with enough samples; this is not a zero false-alarm rate.";
    body.appendChild(el("tr", {}, [el("td", { class: "muted", attrs: { colspan: 8 },
      text: "Nothing calibrated yet — the detector scores are still uncalibrated." })]));
    return;
  }
  const within = rows.filter((r) => r.verdict === "within budget" || r.verdict === "eligible")
    .map((r) => r.model_name);
  note.textContent = "Shadow calibration: the target is a requested false-alarm fraction " +
    "of every scored host-window when the population is available, or the named fallback " +
    "tail; it is not controlling alerts yet." +
    (within.length ? " Within budget: " + within.join(", ") + "." : "");
  for (const r of rows) {
    const pct = (v) => Number.isFinite(Number(v)) ? (Number(v) * 100).toFixed(2) + "%" : "—";
    body.appendChild(el("tr", {}, [
      el("td", { text: r.model_name || "—" }),
      el("td", { class: "muted", text: (r.scope || "—") + " · " + (r.subject || "") }),
      el("td", { class: "num", text: pct(r.target_far) }),
      el("td", { class: "num mono", text: Number(r.threshold || 0).toFixed(3) }),
      el("td", { class: "num", text: pct(r.observed_far) }),
      el("td", { class: "muted", text: r.verdict || "—" }),
      el("td", { class: "num", text: Number(r.sample_count || 0).toLocaleString() }),
      el("td", { class: "mono", text: fmtTime(r.computed_at) }),
    ]));
  }
}

function renderShadow(data) {
  const note = document.getElementById("m-shadow-note");
  const body = document.querySelector("#m-shadow tbody");
  if (!note || !body) return;
  body.replaceChildren();
  if (!data || !data.available) {
    note.textContent = "Shadow channels unavailable: " + ((data && data.reason) || "the read failed");
    body.appendChild(el("tr", {}, [el("td", { class: "muted", attrs: { colspan: 5 },
      text: "No shadow rows were read." })]));
    return;
  }
  const rows = data.rows || [];
  note.textContent = "These channels record evidence only. None of them can create, raise or "
    + "change an alert; an empty channel is not a healthy one until its first row arrives.";
  if (!rows.length) {
    body.appendChild(el("tr", {}, [el("td", { class: "muted", attrs: { colspan: 5 },
      text: "No shadow channels reported." })]));
    return;
  }
  for (const r of rows) {
    const state = r.available ? (r.state || "collecting") : "unavailable";
    const detail = Number(r.detail || 0).toLocaleString() + " " + (r.detail_label || "");
    body.appendChild(el("tr", {}, [
      el("td", { text: r.label || r.key || "—" }),
      el("td", { class: "muted", text: state + (r.reason ? " — " + r.reason : "") }),
      el("td", { class: "num mono", text: Number(r.rows || 0).toLocaleString() }),
      el("td", { class: "muted", text: detail.trim() }),
      el("td", { class: "mono muted", text: r.latest ? fmtTime(r.latest) : "—" }),
    ]));
  }
}

function renderAssetPosture(data) {
  const note = document.getElementById("m-posture-note");
  const stats = document.getElementById("m-posture-stats");
  if (!note || !stats) return;
  if (!data || !data.available) {
    note.textContent = "Asset posture unavailable: " +
      ((data && data.reason) || "the read failed");
    stats.textContent = "";
    return;
  }
  const bands = data.bands || {};
  const scored = Number(data.scored || 0);
  const total = Number(data.total_changes || 0);
  note.textContent = "The shadow scorer is " + (data.model_version || "asset-posture-1") +
    ". It scores observed service changes and never blocks traffic or writes a detection score.";
  if (!scored) {
    stats.textContent = "No service change has been scored yet. " +
      `${total.toLocaleString()} change(s) in the ledger; the scorer runs when the next real ` +
      "change is observed.";
  } else {
    stats.textContent = `${scored.toLocaleString()} scored change(s) of ${total.toLocaleString()}; ` +
      `expected ${Number(bands.expected || 0)}, watch ${Number(bands.watch || 0)}, ` +
      `suspicious ${Number(bands.suspicious || 0)}, high ${Number(bands.high || 0)}` +
      (data.last_scored ? `; last scored ${fmtTime(data.last_scored)}` : "") + ".";
  }
}

/* ── model cards (PR-1) ─────────────────────────────────────────────────────────────────────
 * A CARD IS THE ANSWER TO "WHAT EXACTLY IS SCORING?". The name in a row is not enough: the
 * artifact hash, feature and calibration versions, evaluation and rollback reference are the
 * identity. A status that is not `production` means the name must not contribute to the fused
 * score; the worker enforces that, and this table says so in words.
 */
function renderModelCards(data) {
  const note = document.getElementById("m-cards-note");
  const body = document.querySelector("#m-cards tbody");
  if (!note || !body) return;
  body.replaceChildren();
  const cards = (data && data.model_cards) || [];
  if (!data || data.model_cards_available === false) {
    note.textContent = "Unavailable: " + ((data && data.model_cards_reason) || "the model registry was not read");
    body.appendChild(el("tr", {}, [
      el("td", { class: "muted", attrs: { colspan: 9 }, text: "No card can be shown, so no model is represented as registered." }),
    ]));
    return;
  }
  if (!cards.length) {
    note.textContent = "No model card is registered. No model may contribute to the fused score.";
    body.appendChild(el("tr", {}, [
      el("td", { class: "muted", attrs: { colspan: 9 }, text: "The registry is empty." }),
    ]));
    return;
  }
  note.textContent = `${cards.length} card(s); only a production card may contribute to the fused score.`;
  for (const c of cards) {
    const status = String(c.status || "unknown");
    const shortHash = c.artifact_hash ? String(c.artifact_hash).slice(0, 12) + "…" : "not recorded";
    const approved = (c.approved_by ? String(c.approved_by) : "not recorded") +
      (c.approved_at ? " · " + fmtTime(c.approved_at) : "");
    body.appendChild(el("tr", {}, [
      el("td", { text: c.model_name || c.model_id || "—" }),
      el("td", {}, [el("span", { class: "card-status" + (status === "production" ? " production" : ""), text: status })]),
      el("td", { text: c.version || "—" }),
      el("td", { class: "mono", attrs: { title: c.artifact_hash || "" }, text: shortHash }),
      el("td", { text: c.feature_version || "—" }),
      el("td", { text: c.calibration_version || "—" }),
      el("td", { text: c.eval_report_id || "not measured" }),
      el("td", { text: approved }),
      el("td", { text: c.rollback_ref || "—" }),
    ]));
  }
}

/* CE-2: every channel has one disposition; no blank and no automatic promote. */
function renderDispositions(r) {
  const note = document.getElementById("m-dispositions");
  if (!note) return;
  const rows = r.channels || [];
  if (!rows.length) { note.textContent = "No shadow-channel inventory."; return; }
  const counts = {};
  for (const row of rows) counts[row.disposition] = (counts[row.disposition] || 0) + 1;
  note.textContent = rows.length + " channels: " +
    Object.entries(counts).map(([k, v]) => `${k} ${v}`).join(" · ") +
    ". No channel is promoted without a generated-ground-truth fixed-budget win.";
}

/* PR-2/PR-3: the policy and the append-only ledger. */
function renderPromotionLedger(policy, ledger) {
  const note = document.getElementById("m-ledger");
  if (!note) return;
  const rows = ledger.rows || [];
  note.textContent = `Policy ${policy.policy_version || "not measured"} · max in flight ` +
    `${policy.max_in_flight ?? "not measured"} · shadow ${policy.shadow_min_days ?? "not measured"} d. ` +
    (rows.length ? `Last decision: ${rows[rows.length - 1].action || "—"} at ${rows[rows.length - 1].recorded_at || "—"}.`
                 : "No decision ledger archive; no automatic promotion has been recorded.");
}

/* CE-3: last fixed-budget report; an absent report is not a pass. */
function renderEvalReport(r) {
  const note = document.getElementById("m-eval");
  if (!note) return;
  if (!r || r.available === false) {
    note.textContent = "No archived evaluation: " + ((r && r.reason) || "not run") +
      ". Live precision is not measured without a canary or oracle.";
    return;
  }
  const c = r.candidate || {};
  note.textContent = `Status: ${r.status || "unknown"} · report ${r.report_id || "—"} · ` +
    `precision ${c.precision ?? "not measured"} · detection ${c.detection_rate ?? "not measured"} · ` +
    `live precision: ${r.live_precision || "not measured"} · generator ${r.generator_version || "not recorded"}.`;
}

/* OP-3: the archive is the decision record. A failed review names every blocked phase card. */
function renderReview(r) {
  const note = document.getElementById("m-review");
  if (!note) return;
  if (!r || r.available === false) {
    note.textContent = "No archived review: " + ((r && r.reason) || "not run") +
      ". A missing review is not a passing review.";
    return;
  }
  const failures = (r.blocked_cards || []).map((c) => `${c.id} ${c.title} (${c.status})`);
  note.textContent = `Status: ${r.status || "unknown"} · next: ${r.next_review || "not scheduled"} · ` +
    `decision: ${r.decision || "not recorded"}.` +
    (failures.length ? ` Blocked: ${failures.join("; ")}` : "");
}

/* CE-4: verified evidence is synthetic/canary/background; weak and unknown are named. */
function renderVerification(v) {
  const note = document.getElementById("m-verify");
  if (!note) return;
  if (!v || v.available === false) {
    note.textContent = "Not measured: " + ((v && v.reason) || "no verification report") +
      ". Weak labels are not counted as verified; live precision is not measured without an oracle.";
    return;
  }
  const fmt = (x) => (x === null || x === undefined ? "not measured" : String(x));
  note.textContent = `Verified attacks: ${fmt(v.verified_attack_windows)} · verified negative hours: ` +
    `${fmt(v.verified_negative_hours)} · coverage: ${fmt(v.verification_coverage)} · ` +
    `live precision: ${v.live_precision || "not measured"}`;
}

/* OP-1: one row per metric, one column per window. A metric absent from a window says
 * "not measured" in that cell; it never becomes a zero. */
function renderMlSlo(data) {
  const note = document.getElementById("m-slo-note");
  const body = document.querySelector("#m-slo tbody");
  if (!note || !body) return;
  body.replaceChildren();
  if (!data || data.available === false) {
    note.textContent = "Unavailable: " + ((data && data.reason) || "the SLO report was not read");
    body.appendChild(el("tr", {}, [el("td", { class: "muted", attrs: { colspan: 7 },
      text: "No metric can be represented as measured." })]));
    return;
  }
  const windows = data.windows || [];
  const names = [];
  for (const w of windows) for (const m of (w.metrics || [])) if (!names.includes(m.name)) names.push(m.name);
  note.textContent = "Live precision: " + (data.live_precision || "not measured") +
    ". Missing labels, dead sources and absent channels are named in the cell, not shown as zero.";
  for (const name of names) {
    const cells = windows.map((w) => (w.metrics || []).find((m) => m.name === name));
    const first = cells.find(Boolean) || {};
    const fmt = (v) => (v === null || v === undefined ? "not measured" : String(v));
    body.appendChild(el("tr", {}, [
      el("td", { text: name }),
      ...cells.map((m) => el("td", { class: "num", text: fmt(m && m.value) })),
      el("td", { class: "muted", text: fmt(first.target) }),
      el("td", { text: first.state || "not measured" }),
      el("td", { class: "muted", text: first.source || "—" }),
    ]));
  }
}

/* GT-3: the source/role truth card. An empty source is NOT a quiet network; it is either
 * `not measured` (zero rows) or `unknown` (a failed read), and the card says which. Unknown-role
 * hosts are named as a configuration gap. */
function renderSourceCoverage(data) {
  const note = document.getElementById("m-cov-note");
  const body = document.querySelector("#m-cov tbody");
  const roles = document.getElementById("m-roles");
  if (!note || !body) return;
  body.replaceChildren();
  if (!data || data.available === false) {
    note.textContent = "Unavailable: " + ((data && data.reason) || "source coverage was not read");
    if (roles) roles.textContent = "";
    body.appendChild(el("tr", {}, [el("td", { class: "muted", attrs: { colspan: 6 },
      text: "No source can be represented as covered." })]));
    return;
  }
  const sources = data.sources || [];
  note.textContent = (data.promotion_ok ? "All required sources usable. " : "Promotion blocked: required source missing. ") +
    sources.length + " source(s) measured; zero rows, failed reads and stale data are named, not shown as clear.";
  for (const src of sources) {
    const state = String(src.state || "unknown");
    body.appendChild(el("tr", {}, [
      el("td", { text: src.name || "—" }),
      el("td", { class: "num", text: src.rows == null ? "not measured" : Number(src.rows).toLocaleString() }),
      el("td", { text: src.last ? fmtTime(src.last) : "not measured" }),
      el("td", { text: state }),
      el("td", { text: src.usable ? "yes" : "no" }),
      el("td", { class: "muted", text: src.reason || "—" }),
    ]));
  }
  if (roles) {
    const r = data.roles || {};
    const counts = (r.counts || []).map((x) => `${x.role} ${x.count}`).join(" · ");
    const top = (r.top_unknown || []).join(", ");
    roles.textContent = "Roles: " + (counts || "not measured") +
      (r.unknown == null ? " · unknown count not measured" : ` · unknown ${r.unknown}`) +
      (top ? ` · top unknown: ${top}` : "");
  }
}

function renderRipple(data) {
  const note = document.getElementById("m-ripple-note");
  const body = document.querySelector("#m-ripple tbody");
  if (!note || !body) return;
  body.replaceChildren();
  if (!data || !data.available) {
    note.textContent = "Ripple evidence unavailable: " +
      ((data && data.reason) || "the read failed") +
      " — that is not the same as a quiet network.";
    body.appendChild(el("tr", {}, [el("td", { class: "muted", attrs: { colspan: 7 },
      text: "No fusion result was read." })]));
    return;
  }
  const counts = data.counts || {};
  const age = Number(data.age_s);
  note.textContent = "Last fusion " + fmtTime(data.evaluated_at) +
    (Number.isFinite(age) ? " (" + Math.max(0, Math.round(age / 60)) + " min ago)" : "") +
    ": " + (counts.ripple || 0) + " ripple, " + (counts.observation || 0) +
    " observation, " + (counts.unknown || 0) + " unknown across " +
    (counts.hosts || 0) + " host(s). " +
    (data.status === "ripple"
      ? "Fired on " + (data.src_addr || "the segment") + ": " + (data.headline_reason || "") + "."
      : "Not a ripple: " + (data.headline_reason || data.reason || "no reason recorded") + ".") +
    " Pageable: no — the page decision is separate." +
    (data.stale ? " This answer is older than two passes." : "");
  const rows = data.rows || [];
  if (!rows.length) {
    body.appendChild(el("tr", {}, [el("td", { class: "muted", attrs: { colspan: 7 },
      text: "Nothing was fused in the last evaluation." })]));
    return;
  }
  for (const r of rows) {
    const unknown = r.unknown || [];
    const unknownText = unknown.length
      ? unknown.slice(0, 3).map((u) => (u.channel || "?") + " (" + (u.reason || "unknown") + ")")
          .join(", ") + (unknown.length > 3 ? " +" + (unknown.length - 3) + " more" : "")
      : "none";
    const top = (r.contributors || [])[0];
    const pct = Number(r.confidence);
    body.appendChild(el("tr", {}, [
      el("td", { class: "mono", text: r.src_addr || "segment" }),
      el("td", {}, [el("strong", { text: r.status || "unknown" }),
                    el("div", { class: "muted", text: r.reason || "" })]),
      el("td", { class: "num", text: Number.isFinite(pct) ? (pct * 100).toFixed(1) + "%" : "—" }),
      el("td", { class: "muted", text: (r.families || []).join(" / ") + " · " +
                                        (r.scales || []).join(" / ") }),
      el("td", { class: "muted mono", text: top
        ? top.channel + " p=" + Number(top.pvalue).toFixed(3) : "—" }),
      el("td", { class: "muted", text: unknownText }),
      el("td", { class: "num", text: Number(r.channel_count || 0) }),
    ]));
  }
}

async function loadModels() {
  scheduleURLSync();
  const hours = String(trHours());
  // AB-1: the baseline card is its own read -- a models payload that failed must not take
  // it down, and vice versa.
  loadBaselinesCard().catch(showError);
  // Calibration is a separate read for the same reason: a broken models query must not hide a
  // working budget, and a broken calibration must not hide the training history.
  const calPromise = getJSON("/api/models/calibration")
    .catch((e) => ({ available: false, reason: String(e && e.message || e), rows: [] }));
  const shadowPromise = getJSON("/api/models/shadow")
    .catch((e) => ({ available: false, reason: String(e && e.message || e), rows: [] }));
  // RIP-5's fusion is its own read: a broken ripple store must not take down the shadow
  // channel inventory, and a dead channel must not hide the fused answer.
  const ripplePromise = getJSON("/api/ml/ripple")
    .catch((e) => ({ available: false, reason: String(e && e.message || e), rows: [] }));
  // The asset-posture scorer is its own read: it scores the CHANGE ledger, not the flow model,
  // so a failure here must not take the production model view down.
  const posturePromise = getJSON("/api/asset-posture")
    .catch((e) => ({ available: false, reason: String(e && e.message || e) }));
  const coveragePromise = getJSON("/api/ml/coverage")
    .catch((e) => ({ available: false, reason: String(e && e.message || e),
                     sources: [], roles: {}, models: [], promotion_ok: false }));
  const sloPromise = getJSON("/api/ml/slo")
    .catch((e) => ({ available: false, reason: String(e && e.message || e), windows: [] }));
  const data = await getJSON("/api/models?hours=" + encodeURIComponent(hours));
  renderMlSlo(await sloPromise);
  renderSourceCoverage(await coveragePromise);
  renderCalibration(await calPromise);
  renderShadow(await shadowPromise);
  renderRipple(await ripplePromise);
  renderAssetPosture(await posturePromise);
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

  mRenderChips();
  renderModelCards(data);
  renderDispositions(data.dispositions || {});
  renderPromotionLedger(data.promotion_policy || {}, data.ledger || {});
  renderEvalReport(data.eval_report || {});
  renderReview(data.review || {});
  renderVerification(data.verification || {});
  renderStaleness(data.staleness || [], data.retrain_interval_h);
  renderTrainingHistory(data.training_history || {});
  renderScoreDistribution(data.scores || {});
  renderAgreement(data.model_counts || {});
  renderFeatureDeviations(data.feature_deviations || [], data.feature_coverage || {});
  renderNearMisses(data);

  const body = document.querySelector("#m-points tbody");
  body.innerHTML = "";
  const allPts = data.points || [];
  const pts = allPts.filter(mKeepPoint);
  if (!pts.length) {
    // A FILTER THAT MATCHES NOTHING AND A WINDOW THAT HELD NOTHING ARE DIFFERENT FACTS.
    body.appendChild(el("tr", {}, [
      el("td", { class: "muted", attrs: { colspan: 7 },
                 text: allPts.length
                   ? "No row matches the filter. Remove a chip to see the window again."
                   : "No anomalies in this window." }),
    ]));
    return;
  }
  // THE TABLE IS A WORKLIST, NOT AN EXPORT (US-A4). The window can hold thousands of points;
  // rendering every one put this view at 8,650 elements against a 6,000 budget, and the operator
  // reads the top of the list first anyway. Render a page of rows, say how many are held back,
  // and offer the rest in one click -- never a silent truncation.
  const PAGE = 100;
  const renderPoint = (pt) => {
    const tr = el("tr", { class: "clickable" }, [
      el("td", { class: "num", text: Number(pt.score || 0).toFixed(3) }),
      el("td", { class: "num", text: Number(pt.agreement || 0).toFixed(2) }),
      el("td", {}, [el("span", { class: "sev-" + (pt.severity || "low"),
                              text: pt.severity ? sevText(pt.severity) : "\u2014" })]),
      el("td", { text: (pt.models || []).join(", ") || "—" }),
      el("td", { text: pt.primary || "—" }),
      el("td", { class: "num", text: Number(pt.magnitude || 0).toFixed(2) }),
      el("td", { class: "dcell", attrs: { title: "filter this view to this host" },
                 on: { click: (e) => { e.stopPropagation(); mSetFilter("host", pt.src_addr); } } },
         [hostCell(pt.src_addr, pt.hostname)]),
    ]);
    if (pt.src_addr) {
      tr.addEventListener("click", () => { openHost(pt.src_addr); });
    }
    return tr;
  };
  for (const pt of pts.slice(0, PAGE)) body.appendChild(renderPoint(pt));
  if (pts.length > PAGE) {
    const held = pts.length - PAGE;
    const more = el("button", { class: "quiet",
      text: `Show all ${pts.length} rows (${held} more)`, attrs: { type: "button" } });
    more.addEventListener("click", () => {
      for (const pt of pts.slice(PAGE)) body.appendChild(renderPoint(pt));
      footer.remove();
    });
    const footer = el("tr", { class: "show-more" }, [
      el("td", { attrs: { colspan: 7 }, class: "muted" }, [
        el("span", { text: `Showing the first ${PAGE} of ${pts.length} rows. ` }),
        more,
      ]),
    ]);
    body.appendChild(footer);
  }
}

/* ── the operator's forced retrain ───────────────────────────────────────────────────────── */

/*
 * A FORCED RETRAIN IS A REHEARSAL, NOT A REPLACEMENT. The worker trains a CANDIDATE on the last
 * window's traffic and reports it; nothing scoring traffic changes until Keep.
 *
 * The panel's whole job is to make that visible before the decision: what trained, on how much,
 * whether the training window contained detections this deployment already recorded (a retrain
 * learns those as NORMAL -- that is what a model is for, and exactly the wrong thing here), and
 * then two buttons. Keep installs the candidate over the live artifacts (archiving them); Trash
 * deletes it and the running models were never touched.
 *
 * Keep is only offered when the candidate actually built something: a retrain that found no data
 * has nothing to install, and a Keep button there would be an offer to replace working models with
 * an empty set.
 */
let RETRAIN_STATE = null;

async function loadRetrain() {
  const state = document.getElementById("mr-state");
  const note = document.getElementById("mr-note");
  const body = document.querySelector("#mr-report tbody");
  const force = document.getElementById("mr-force");
  const keep = document.getElementById("mr-keep");
  const trash = document.getElementById("mr-trash");
  if (!state || !note || !body || !force || !keep || !trash) return;

  const d = await getJSON("/api/models/retrain");
  RETRAIN_STATE = d;
  body.replaceChildren();
  keep.classList.toggle("hidden", !d.can_keep);
  trash.classList.toggle("hidden", !d.can_keep);
  // WHY THE BUTTONS ARE NOT THERE (the operator, 2026-10-16: "forcing a retrain doesn't allow me
  // to keep or trash it"). Keep/Trash need a FINISHED candidate; every other state gets a
  // sentence -- waiting, training, trained-nothing, failed -- instead of a control that
  // silently vanishes.
  const stand = document.getElementById("mr-stand");
  if (stand) {
    const st = String(d.state || "none");
    stand.textContent = {
      none: "No forced retrain has been filed.",
      requested: "Filed \u2014 waiting for the worker to pick it up.",
      running: "Training the candidate now; this takes minutes. A worker restart cancels it.",
      done: d.can_keep
        ? "Candidate ready: Keep installs it over the live models, Trash discards it."
        : "The candidate trained nothing (no data in its window), so there is nothing to keep "
          + "or trash. File it again once traffic has accumulated.",
      failed: `Failed: ${d.note || "no reason recorded"} \u2014 file it again to retry.`,
    }[st] || st;
    if ((st === "requested" || st === "running") && d.requested_at) {
      // HOW LONG IT HAS BEEN WAITING, said out loud: a request that sits there must be able to
      // say since when, or "waiting" and "stuck" look alike.
      const t = new Date(d.requested_at);
      if (!Number.isNaN(t.getTime())) {
        stand.textContent += ` Filed ${fmtAge(Math.max(0, (Date.now() - t.getTime()) / 1000))}.`;
      }
    }
  }
  force.disabled = d.state === "requested" || d.state === "running";

  if (!d.available) {
    state.textContent = "";
    note.textContent = `The retrain state could not be read — ${d.reason}. This says nothing `
      + "about whether a candidate exists.";
    return;
  }
  if (d.state === "none") {
    state.textContent = "never run";
    note.textContent = "No forced retrain has been run. One trains a candidate on the last "
      + "training window and reports it here; the models currently scoring are not touched.";
    return;
  }
  state.textContent = d.state + (d.requested_by ? ` (${d.requested_by})` : "");
  note.textContent = d.summary || "";

  const rep = d.report || {};
  for (const det of rep.detectors || []) {
    body.appendChild(el("tr", {}, [
      el("td", { text: det.name || "?" }),
      el("td", {}, [el("span", { class: det.trained ? "ok" : "muted",
                                text: det.trained ? "trained" : "no data" })]),
      el("td", { class: "num", text: String(det.sample_count ?? "—") }),
      el("td", { class: "muted mono",
                 text: `${fmtTime(rep.window_start)} → ${fmtTime(rep.window_end)}` }),
    ]));
  }
  if (!(rep.detectors || []).length && d.state !== "requested" && d.state !== "running") {
    body.appendChild(el("tr", {}, [el("td", {
      class: "muted", attrs: { colspan: 4 },
      text: rep.error ? `the retrain failed: ${rep.error}` : "no report",
    })]));
  }
  if (d.decision && d.decision.state) {
    // AN EARLIER CANDIDATE'S FATE, LABELLED AS SUCH (the operator, 2026-10-16: "Retraining
    // requested (operator) \u2014 decision: discarded ... this doesnt make sense"). The decision on
    // record judges the candidate that produced it; without the label, "requested" beside
    // "discarded" read as this request being discarded.
    note.textContent += ` \u2014 last decision on record (an earlier candidate): ${d.decision.state}`;
  }
}

async function retrainAction(action) {
  const note = document.getElementById("mr-note");
  // BF-9: keep and trash decide what this deployment SERVES; they echo the target and require
  // the note the server records on the action row (with the actor and the time).
  let why = "";
  if (action === "keep" || action === "trash") {
    const cand = (RETRAIN_STATE && (RETRAIN_STATE.candidate_id || RETRAIN_STATE.action_id)) || "this candidate";
    const verdict = await confirmDestructive({
      title: action === "trash"
        ? "Trash this candidate: it is discarded and the model in service keeps running."
        : "Keep this candidate: it becomes the model this deployment serves.",
      target: String(cand),
      blast: action === "trash"
        ? "the candidate's artifacts are discarded; scoring continues on the current model set"
        : "the candidate's artifacts become the served model; the previous candidate is retired",
      reasonHint: action === "trash" ? "why this candidate is not wanted" : "why this one is",
    });
    if (!verdict.ok) { note.textContent = "not filed — you declined the confirmation"; return; }
    why = verdict.reason;
  }
  const body = action === "retrain"
    ? { action }
    : { action, target_id: (RETRAIN_STATE && RETRAIN_STATE.action_id) || "", note: why };
  note.textContent = "filing…";
  try {
    const out = await postJSON("/api/models/retrain", body);
    note.textContent = (out && (out.ok ? (out.note || "filed") : out.error)) || "filed";
  } catch (err) {
    note.textContent = String(err.message || err);
  }
  await loadRetrain();
}

/* ── Passive host identification ────────────────────────────────────────────────────────── */
/**
 * CLICK-TO-FILTER for the identity list (the operator, 2026-10-16: "if i click in any dashboard
 * it should filter that entire dashboard"). A click on a host's OS or confidence narrows the
 * LIST; the chips remove themselves.
 *
 * WHY CLIENT-SIDE HERE, DELIBERATELY, where the other views filter server-side: the identity
 * payload IS the view's full set -- every identified host in the window, no pagination, no
 * LIMIT -- so the filter cannot hide a match the browser never received. That claim is kept
 * checkable: the counter reads "showing X of Y", so the relationship between the filtered list
 * and the window's total is on screen rather than implied. The coverage stats above the list
 * stay whole-window on purpose: they describe the segment, not the list.
 */
const ID_FILTERS = { os: "", confidence: "" };

function idRenderChips() {
  const box = document.getElementById("id-filters");
  if (!box) return;
  box.replaceChildren();
  for (const field of ["os", "confidence"]) {
    if (!ID_FILTERS[field]) continue;
    const chip = el("button", { class: "dc-chip", attrs: { title: "remove this filter" },
      text: `${field} = ${ID_FILTERS[field]} \u00d7` });
    chip.addEventListener("click", () => {
      ID_FILTERS[field] = "";
      idRenderChips();
      loadIdentity().catch(showError);
    });
    box.appendChild(chip);
  }
}

function idSetFilter(field, value) {
  ID_FILTERS[field] = String(value || "");
  idRenderChips();
  loadIdentity().catch(showError);
}

function idKeep(h) {
  if (window.NET_SCOPE !== "all" && netScope(h.host || h.addr) !== window.NET_SCOPE) return false;
  if (ID_FILTERS.os && String(h.os_label || h.os || "unknown") !== ID_FILTERS.os) return false;
  if (ID_FILTERS.confidence && String(h.confidence || "") !== ID_FILTERS.confidence) return false;
  return true;
}

async function loadIdentity() {
  scheduleURLSync();
  // The Hosts table is retired from Assets; keep the compatibility node out of the way even if
  // an older link or a future test mounts it.
  const legacyHosts = document.getElementById("id-hosts-card");
  if (legacyHosts) legacyHosts.classList.add("hidden");
  // NO `hours` HERE (issue #63). Identity is a CURRENT SNAPSHOT with its own 7-day observation
  // window, not a windowed read. Sending the header's range implied a filter the route never
  // applied, so the header could say 15 minutes while this view answered seven days.
  const d = await getJSON("/api/identity");

  // AN EMPTY LIST AND A FAILED QUERY MUST NOT LOOK ALIKE. A read failure names its cause; an
  // empty list says nothing has been identified yet, which is a legitimate answer.
  if (!d.available) {
    showDataError(d.reason || "host identity is unavailable");
  } else {
    showDataError(null);
  }

  const cov = d.coverage || {};
  const covBox = document.getElementById("id-coverage");
  covBox.replaceChildren();
  if (!cov.available) {
    covBox.appendChild(el("p", { class: "empty",
      text: `Coverage unknown — ${cov.reason || "the coverage query did not run"}.` }));
  } else {
    const pct = cov.coverage_pct == null ? "—" : `${cov.coverage_pct}%`;
    const items = [
      ["identified", String(cov.hosts_classified ?? "—")],
      ["hosts seen", String(cov.hosts_seen ?? "—")],
      ["coverage", pct],
      ["high", String(cov.high_confidence ?? "—")],
      ["medium", String(cov.medium_confidence ?? "—")],
      ["unknown", String(cov.unknown ?? "—")],
    ];
    for (const [k, v] of items) {
      covBox.appendChild(el("div", { class: "stat" }, statCells(k, v)));
    }
  }
  // A FOLDED SPELLING IS NAMED, NOT SILENTLY DROPPED (QA-1-D2): the operator saw two rows and
  // is owed the reason there is now one.
  const folded = Number(d.merged || 0);
  const idWindow = document.getElementById("id-window");
  if (idWindow) {
    idWindow.textContent = cov.available
      ? `current snapshot · ${cov.window_days}-day observation window`
      : "current snapshot";
  }
  document.getElementById("id-coverage-note").textContent = cov.available
    ? `Current snapshot: ${cov.hosts_seen} hosts observed in the last ${cov.window_days} days, ${cov.hosts_classified} have an identity. The rest have produced no identifying signal yet. The header range does not apply to this identity card; identity is a current verdict, not a windowed read.`
      + (folded ? ` ${folded} duplicate spelling${folded === 1 ? "" : "s"} folded into the host it belongs to.` : "")
    : "";

  idRenderChips();
  const hosts = d.hosts || [];
  const shown = hosts.filter(idKeep);
  document.getElementById("id-count").textContent = hosts.length
    ? (shown.length === hosts.length ? `(${hosts.length})` : `(showing ${shown.length} of ${hosts.length})`)
    : "";
  const tbody = document.querySelector("#id-table tbody");
  tbody.replaceChildren();

  const empty = document.getElementById("id-empty");
  if (!shown.length) {
    // THREE DIFFERENT EMPTINESSES, three different sentences: a failed read, a filter that
    // matches nothing, and a segment that has produced no identity at all. Conflating them is
    // this project's named failure mode.
    empty.textContent = !d.available
      ? ""
      : (hosts.length
          ? "No host matches the filter. Remove it to see the whole list."
          : "No host has been identified yet. Identity comes from application banners, DHCP leases and TLS fingerprints, so a segment with none of those produces nothing here.");
    return;
  }
  empty.textContent = "";

  for (const h of shown) {
    const strongest = (h.signals && h.signals.length) ? h.signals[0].detail : "";
    const tr = el("tr", { class: "clickable" }, [
      // US-2: the host is an ENTITY -- its cell opens the host's own view (traffic,
      // destinations, anomalies together); the row's own click still opens the identity detail.
      el("td", { class: "mono dcell", attrs: { title: "open this host's view" },
                 on: { click: (e) => { e.stopPropagation(); openHost(h.host); } } },
         [el("span", { text: h.hostname ? `${h.hostname} (${h.host})` : h.host }),
          ...((h.aliases || []).length
            ? [el("span", { class: "muted", text: ` \u00b7 also seen as ${h.aliases.join(", ")}` })]
            : [])]),
      el("td", { class: "dcell", attrs: { title: "filter the list to this identity" },
                 on: { click: (e) => { e.stopPropagation();
                   idSetFilter("os", h.os_label || h.os || "unknown"); } } },
         [el("span", { text: h.os_label || h.os || "unknown" })]),
      el("td", { class: "dcell", attrs: { title: "filter the list to this confidence" },
                 on: { click: (e) => { e.stopPropagation(); idSetFilter("confidence", h.confidence); } } },
         [confidenceChip(h.confidence)]),
      el("td", { text: String(h.agreeing_sources ?? "—") }),
      el("td", { class: "muted", text: strongest }),
      el("td", { class: "muted", text: h.age_s != null ? fmtAge(h.age_s) : "—" }),
    ]);
    tr.addEventListener("click", () => showIdentityDetail(h));
    tbody.appendChild(tr);
  }
}

/* A confidence chip, so "low" and "high" are distinguishable at a glance rather than by reading
 * a word in a column of similar-looking words. */
function confidenceChip(conf) {
  const c = String(conf || "unknown");
  const cls = `conf conf-${c}`;
  return el("span", { class: cls, text: c });
}

/** The host the identity detail is showing RIGHT NOW (the escalate button reads it). */
let CURRENT_ID_HOST = "";

function showIdentityDetail(h) {
  CURRENT_ID_HOST = h.host || "";
  const card = document.getElementById("id-detail-card");
  if (!card) return;
  // Dotted calls keep this file's bare-call audit clean: the sheet helpers live in
  // sheets.js, not app.js, and the scanner only treats `foo(` as ours.
  if (typeof window.wireSheet === "function") {
    window.wireSheet(card, { scrimId: "id-detail-scrim", initialFocus: "id-detail-close" });
  }
  if (typeof window.openSheet === "function") {
    window.openSheet(card, { scrimId: "id-detail-scrim", initialFocus: "id-detail-close" });
  } else {
    card.classList.remove("hidden");
  }
  const detailTitle = document.getElementById("id-detail-title");
  if (detailTitle) detailTitle.setAttribute("data-host", h.host || "");
  document.getElementById("id-detail-host").textContent = h.hostname
    ? `${h.hostname} (${h.host})` : h.host;

  const box = document.getElementById("id-detail");
  box.replaceChildren();

  const strongest = (h.signals && h.signals.length) ? h.signals[0].detail : "—";
  const updated = h.updated_at ? fmtTime(h.updated_at)
    : (h.age_s != null ? `${fmtAge(h.age_s)} ago` : "—");
  const metrics = [
    ["Identity", h.os_label || h.os || "unknown", h.os && h.os_label ? h.os : ""],
    ["Confidence", String(h.confidence || "unknown"),
      h.score != null ? `score ${h.score}` : ""],
    ["Sources", `${h.agreeing_sources ?? "—"} agreeing`, ""],
    ["Last updated", updated, ""],
  ];
  const grid = el("div", { class: "id-metrics" });
  for (const [label, value, sub] of metrics) {
    grid.appendChild(el("div", { class: "id-metric" }, [
      el("div", { class: "id-label", text: label }),
      el("div", { class: "id-value", text: String(value) }),
      sub ? el("div", { class: "id-sub", text: sub }) : null,
    ].filter(Boolean)));
  }
  box.appendChild(grid);
  box.appendChild(el("div", { class: "id-strongest" }, [
    el("div", { class: "id-label", text: "Strongest evidence" }),
    el("div", { class: "id-value", text: String(strongest) }),
  ]));

  // The remaining mechanical facts, not the dashboard's four headline numbers.
  const facts = [];
  if (h.mac) facts.push(["MAC", h.mac]);
  if (h.ja4_structure) {
    const j = h.ja4_structure;
    facts.push(["TLS", `${j.transport || "?"} ${j.tls_version || ""}, ` +
                        `${j.cipher_count ?? "?"} ciphers, ALPN ${j.alpn || "none"}`]);
  }
  if (facts.length) {
    box.appendChild(el("h3", { text: "Host facts" }));
    const table = el("table");
    const tb = el("tbody");
    for (const [k, v] of facts) {
      tb.appendChild(el("tr", {}, [
        el("td", { class: "muted", text: k }), el("td", { class: "mono", text: String(v) }),
      ]));
    }
    table.appendChild(tb);
    box.appendChild(table);
  }

  // The evidence, with its source and weight, so the label can be CHECKED rather than trusted.
  if (h.signals && h.signals.length) {
    box.appendChild(el("h3", { text: "Evidence" }));
    const ul = el("ul");
    for (const s of h.signals) {
      ul.appendChild(el("li", {
        text: `${s.os_label} — ${s.detail} (source: ${s.source}, weight ${s.weight})`,
      }));
    }
    box.appendChild(ul);
  }

  // Disagreement is shown, not hidden: it is the most interesting thing about such a host.
  if (h.disagreement && h.disagreement.length) {
    box.appendChild(el("h3", { text: "Contradicting signals" }));
    const ul = el("ul");
    for (const s of h.disagreement) {
      ul.appendChild(el("li", { text: `${s.os_label} — ${s.detail} (source: ${s.source})` }));
    }
    box.appendChild(ul);
  }

  const raw = [];
  if (h.software_seen && h.software_seen.length) raw.push(["software", h.software_seen]);
  if (h.hostnames_seen && h.hostnames_seen.length) raw.push(["hostnames", h.hostnames_seen]);
  if (h.ja4_seen && h.ja4_seen.length) raw.push(["JA4", h.ja4_seen]);
  for (const [label, values] of raw) {
    box.appendChild(el("h3", { text: `Observed ${label}` }));
    const ul = el("ul");
    for (const v of values) {
      if (label === "JA4") {
        // US-2: a fingerprint is an ENTITY with a home right here -- the lookup panel this
        // view already has. One click runs it for this value and shows which hosts wear it.
        const li = el("li", { class: "mono dcell",
                              attrs: { title: "look this fingerprint up" } },
                      [el("span", { text: String(v) })]);
        li.addEventListener("click", () => {
          const inp = document.getElementById("fp-input");
          if (inp) inp.value = String(v);
          lookupFingerprint(String(v)).catch(showError);
        });
        ul.appendChild(li);
      } else {
        ul.appendChild(el("li", { class: "mono", text: String(v) }));
      }
    }
    box.appendChild(ul);
  }
}

// ── THE GLOBAL TIME RANGE ─────────────────────────────────────────────────────────────────────
// THE OPERATOR'S ASK (2026-10-16): "a better time search like kibana uses throughout the
// project". Kibana's time filter is GLOBAL -- presets, free text, a custom absolute range --
// and every panel answers to it. This is that shape: one control, every tab.
//
// A relative range travels as `hours`. An ABSOLUTE range additionally travels as `from`/`to`,
// which the server honours exactly (weirvern/admin/timewindow.py). In absolute mode each
// panel's little `hours` box is a DISPLAY fallback only -- the window itself comes from
// from/to, so no panel can silently widen what was asked for.
const TIME_RANGE = { mode: "relative", hours: 24, from: "", to: "" };

/* ── THE VIEW IS IN THE URL ──────────────────────────────────────────────────────────────────
 * The #1 cross-cutting finding of the console research: every product studied keeps the view
 * in the URL (Grafana, Kibana, the SOC consoles) and ours kept it nowhere -- a filtered queue
 * or an open drill-down could not be sent to anyone, bookmarked, or survive an accidental
 * reload. The grammar is flat and readable: #v=<tab>&tr=<hours|from~to>&an.sev=high&an.unrev=1
 * &ev.host=<addr>. Every state change writes it (replacing, not pushing history: a filter
 * tweak is not a navigation); opening a link restores exactly that view through the SAME
 * setters the UI uses. */
let urlSyncTimer = null;
let CURRENT_EVIDENCE = null;
// US-3: the view Evidence was OPENED FROM -- the crumb goes back there, and its filters are
// untouched because nothing ever resets them (the controls still hold what was set).
let EVIDENCE_FROM = "";
let EVIDENCE_SCROLL = 0;   // US-6: the return trip to Evidence's origin restores its scroll
/* US-6: where a HOST drill was opened from, and the scroll to return to. Captured BEFORE
 * showView("host") runs, because showView rewrites CURRENT_VIEW. `pending` marks a JOURNEY
 * (openHost) rather than a fresh lookup in the address box (h-go) -- only journeys get a way
 * back. */
let HOST_RETURN = { pending: false, view: "", scroll: 0 };
/* US-6: the scroll a labeled exit must restore. Set by the exit BEFORE showView triggers the
 * destination's loader; applied AFTER that loader has rendered -- the return trip re-renders
 * the origin view, so scrolling immediately would land on a page that is about to be replaced. */
let PENDING_SCROLL = null;
/* US-6: true when the current filters arrived through the URL (a shared link), so the chips
 * can say WHY the list looks short and offer the way out. */
let ARRIVED_FROM_LINK = false;
let PENDING_WL = "";   // a sensor drill-down a link asked for, opened once the fleet loads
// BROWSER BACK/FORWARD (operator, 2026-10-20). Every view change used to replaceState, so the
// browser had one history entry for the whole session. A PAGE change now pushes; filter and
// time-range edits within that page still replace, or a slider would fill the history stack.
let LAST_HISTORY_VIEW = "";
let HISTORY_NAVIGATING = false;

function scheduleURLSync() {
  if (urlSyncTimer) clearTimeout(urlSyncTimer);
  urlSyncTimer = setTimeout(syncURL, 150);
}

function syncURL() {
  if (urlSyncTimer) { clearTimeout(urlSyncTimer); urlSyncTimer = null; }
  const p = new URLSearchParams();
  const active = document.querySelector(".tab.active");
  // US-3: the view NAME is the source of truth (a tab may be lit for a drill view's family);
  // the tab is only a fallback for the first sync before any view has been shown.
  const viewForURL = CURRENT_VIEW || (active && active.dataset.view);
  if (viewForURL) p.set("v", viewForURL);
  if (TIME_RANGE.mode === "absolute" && TIME_RANGE.from) {
    p.set("tr", TIME_RANGE.from + "~" + (TIME_RANGE.to || "now"));
  } else if (Number(TIME_RANGE.hours) !== 24) {
    p.set("tr", String(trHours()));
  }
  if (AN_FILTERS.host) p.set("an.host", AN_FILTERS.host);
  if (AN_FILTERS.severity) p.set("an.sev", AN_FILTERS.severity);
  if (AN_FILTERS.model) p.set("an.model", AN_FILTERS.model);
  if (AN_FILTERS.feature) p.set("an.feature", AN_FILTERS.feature);
  // US-10: the write trail's filters ride the URL too.
  if (WTL_STATE.scope) p.set("au.scope", WTL_STATE.scope);
  if (WTL_STATE.action) p.set("au.action", WTL_STATE.action);
  if (WTL_STATE.target) p.set("au.target", WTL_STATE.target);
  // US-7: the LAST views without URL state. Assets' search and service facet, the graph's
  // filters, and Discover's feed/selects/chips -- the URL now carries the screen, and a
  // reload returns to it.
  if (ASSETS_STATE.search) p.set("as.q", ASSETS_STATE.search);
  if (ASSETS_STATE.svc) p.set("as.svc", ASSETS_STATE.svc);
  if (Number(ASSETS_STATE.minEdges) > 1) p.set("nw.min", String(ASSETS_STATE.minEdges));
  if (ASSETS_STATE.showNames) p.set("nw.labels", "1");
  if (ASSETS_STATE.trackedOnly) p.set("nw.tracked", "1");
  if (ASSETS_STATE.status && ASSETS_STATE.status !== "all") p.set("nw.status", ASSETS_STATE.status);
  const dcFeedSel = document.getElementById("dc-feed");
  if (dcFeedSel && dcFeedSel.value && dcFeedSel.value !== "netflow") {
    p.set("dc.feed", dcFeedSel.value);
  }
  for (const [id, key] of [["dc-sensor", "dc.sensor"], ["dc-proto", "dc.proto"],
                           ["dc-addr", "dc.addr"], ["dc-port", "dc.port"]]) {
    const elx = document.getElementById(id);
    if (elx && elx.value) p.set(key, elx.value);
  }
  (DC_STATE.filters || []).forEach((f) => p.append("dc.f", `${f.field}=${f.value}`));
  const unrev = document.getElementById("f-unreviewed");
  const watched = document.getElementById("f-watched");
  const min = document.getElementById("f-min-score");
  if (unrev && unrev.checked) p.set("an.unrev", "1");
  if (watched && watched.checked) p.set("an.watched", "1");
  if (min && String(min.value || "0") !== "0") p.set("an.min", String(min.value));
  if (M_FILTERS.host) p.set("m.host", M_FILTERS.host);
  if (M_FILTERS.feature) p.set("m.feature", M_FILTERS.feature);
  if (ID_FILTERS.os) p.set("id.os", ID_FILTERS.os);
  if (ID_FILTERS.confidence) p.set("id.conf", ID_FILTERS.confidence);
  if (typeof NF_FILTERS !== "undefined") {
    for (const f of NF_FILTERS) p.append("nf", f.field + ":" + f.value);
  }
  if (typeof ZEEK_FILTERS !== "undefined") {
    for (const f of ZEEK_FILTERS) p.append("zk", f.field + ":" + f.value);
  }
  // `wl` IS A WEIRLINGS DEEP LINK, NOT GLOBAL STATE (operator, 2026-10-19: why does an
  // anomalies URL carry wl=weirvern-eth2?). It used to be written whenever a weirling sheet had
  // ever been opened, so the parameter survived a tab switch and then FORCED the next reload
  // back to Weirlings. Emit it only while that sheet is actually open on its own view.
  const wlCard = document.getElementById("wl-detail-card");
  if (viewForURL === "weirlings" && typeof wlDetail !== "undefined" && wlDetail
      && wlCard && !wlCard.classList.contains("hidden")) {
    p.set("wl", String(wlDetail.sensor_id || ""));
  }
  if (typeof WL_FILTERS !== "undefined" && WL_FILTERS.state) p.set("wl.f", WL_FILTERS.state);
  const dv = (id) => {
    const e = document.getElementById(id);
    return e ? String(e.value || "").trim() : "";
  };
  if (dv("dc-addr")) p.set("dc.addr", dv("dc-addr"));
  if (dv("dc-port")) p.set("dc.port", dv("dc-port"));
  if (dv("bl-domain")) p.set("bl.domain", dv("bl-domain"));
  if (dv("bl-client")) p.set("bl.client", dv("bl-client"));
  for (const id of ["dn-qtype", "dn-rcode", "dn-domain", "dn-client"]) {
    if (dv(id)) p.set(id.replace("dn-", "dn."), dv(id));
  }
  if (viewForURL === "evidence" && CURRENT_EVIDENCE) {
    if (CURRENT_EVIDENCE.addr) p.set("ev.host", CURRENT_EVIDENCE.addr);
    if (CURRENT_EVIDENCE.start) p.set("ev.start", String(CURRENT_EVIDENCE.start));
    if (CURRENT_EVIDENCE.end) p.set("ev.end", String(CURRENT_EVIDENCE.end));
  }
  // The host page is a view with an address, not a transient modal. Without this key a
  // reload/back/shared link lands on Assets; see applyURLState's explicit fallback.
  if (viewForURL === "host" && HP_ADDR) p.set("h.addr", HP_ADDR);
  if (viewForURL === "findings") {
    if (FINDINGS_STATE.ip) p.set("fd.ip", FINDINGS_STATE.ip);
    if (FINDINGS_STATE.severity) p.set("fd.sev", FINDINGS_STATE.severity);
  }
  const qs = p.toString();
  const target = location.pathname + location.search + (qs ? "#" + qs : "");
  const viewChanged = viewForURL && LAST_HISTORY_VIEW && viewForURL !== LAST_HISTORY_VIEW;
  try {
    if (viewChanged && !HISTORY_NAVIGATING) {
      history.pushState({ view: viewForURL }, "", target);
    } else {
      history.replaceState({ view: viewForURL }, "", target);
    }
  } catch (_e) {
    // A browser that refuses pushState (or a file:// surface) still gets a usable URL; the
    // hash assignment makes its own history entry, which is the fallback browser behavior.
    location.hash = qs;
  }
  LAST_HISTORY_VIEW = viewForURL || "";
}

function applyURLState() {
  const raw = (location.hash || "").replace(/^#/, "");
  if (!raw) return false;
  const p = new URLSearchParams(raw);
  // LET, not const: the identity/host aliases below retarget an old link to Assets.
  let v = p.get("v") || "";
  const tr = p.get("tr") || "";
  if (/^\d+$/.test(tr)) {
    TIME_RANGE.mode = "relative"; TIME_RANGE.hours = Number(tr);
    TIME_RANGE.from = ""; TIME_RANGE.to = "";
    try { trPersist(); } catch (_e) { /* label below is best-effort too */ }
    const btn = document.getElementById("tr-open");
    if (btn) btn.textContent = trLabel();
  } else if (tr.includes("~")) {
    const parts = tr.split("~");
    TIME_RANGE.mode = "absolute"; TIME_RANGE.from = parts[0];
    TIME_RANGE.to = (parts[1] && parts[1] !== "now") ? parts[1] : trFormat(new Date());
    try { trPersist(); } catch (_e) { /* label below is best-effort too */ }
    const btn = document.getElementById("tr-open");
    if (btn) btn.textContent = trLabel();
  }
  if (p.get("an.host")) AN_FILTERS.host = p.get("an.host");
  if (p.get("an.sev")) AN_FILTERS.severity = p.get("an.sev");
  if (p.get("an.model")) AN_FILTERS.model = p.get("an.model");
  if (p.get("an.feature")) AN_FILTERS.feature = p.get("an.feature");
  // US-6: filters that came from the URL are not this screen's choices -- say so.
  ARRIVED_FROM_LINK = !!(p.get("an.host") || p.get("an.sev") || p.get("an.model"));
  // US-10: the trail's filters (the cards re-read them on load).
  if (p.get("au.scope")) WTL_STATE.scope = p.get("au.scope");
  if (p.get("au.action")) WTL_STATE.action = p.get("au.action");
  if (p.get("au.target")) WTL_STATE.target = p.get("au.target");
  // US-7: Assets / Network / Discover state, restored the same way (control values AND state).
  if (p.get("as.q")) ASSETS_STATE.search = p.get("as.q");
  if (p.get("as.svc")) ASSETS_STATE.svc = p.get("as.svc");
  const asSearchEl = document.getElementById("as-search");
  if (asSearchEl) asSearchEl.value = ASSETS_STATE.search;
  if (p.get("nw.min")) ASSETS_STATE.minEdges = Number(p.get("nw.min")) || 1;
  const nwMinEl = document.getElementById("nw-min");
  if (nwMinEl) nwMinEl.value = String(ASSETS_STATE.minEdges);
  ASSETS_STATE.showNames = p.get("nw.labels") === "1";
  const nwLblEl = document.getElementById("nw-labels");
  if (nwLblEl) nwLblEl.checked = ASSETS_STATE.showNames;
  ASSETS_STATE.trackedOnly = p.get("nw.tracked") === "1";
  const nwOnlyEl = document.getElementById("nw-only-tracked");
  if (nwOnlyEl) nwOnlyEl.setAttribute("aria-pressed", ASSETS_STATE.trackedOnly ? "true" : "false");
  const nwStatus = p.get("nw.status");
  ASSETS_STATE.status = ["all", "blocked", "alerted"].includes(nwStatus) ? nwStatus : "all";
  for (const btn of document.querySelectorAll("#nw-status [data-nw-status]")) {
    btn.setAttribute("aria-pressed", btn.dataset.nwStatus === ASSETS_STATE.status ? "true" : "false");
  }
  if (p.get("dc.feed")) {
    const feedEl = document.getElementById("dc-feed");
    if (feedEl) feedEl.value = p.get("dc.feed");
  }
  for (const [key, id] of [["dc.sensor", "dc-sensor"], ["dc.proto", "dc-proto"],
                           ["dc.addr", "dc-addr"], ["dc.port", "dc-port"]]) {
    if (p.get(key)) {
      const elx = document.getElementById(id);
      if (elx) elx.value = p.get(key);
    }
  }
  const dcChips = p.getAll("dc.f");
  if (dcChips.length) {
    DC_STATE.filters = dcChips.map((s) => {
      const i = s.indexOf("=");
      return { field: i >= 0 ? s.slice(0, i) : s, value: i >= 0 ? s.slice(i + 1) : "" };
    }).filter((f) => f.field && f.value);
  }
  const unrev = document.getElementById("f-unreviewed");
  const watched = document.getElementById("f-watched");
  const min = document.getElementById("f-min-score");
  if (unrev && p.get("an.unrev") === "1") unrev.checked = true;
  if (watched && p.get("an.watched") === "1") watched.checked = true;
  if (min && p.get("an.min")) min.value = p.get("an.min");
  if (p.get("m.host")) M_FILTERS.host = p.get("m.host");
  if (p.get("m.feature")) M_FILTERS.feature = p.get("m.feature");
  if (p.get("id.os")) ID_FILTERS.os = p.get("id.os");
  if (p.get("id.conf")) ID_FILTERS.confidence = p.get("id.conf");
  const nfPairs = p.getAll("nf");
  if (nfPairs.length && typeof NF_FILTERS !== "undefined") {
    NF_FILTERS.splice(0, NF_FILTERS.length);
    for (const pair of nfPairs) {
      const i = pair.indexOf(":");
      if (i > 0) {
        NF_FILTERS.push({ field: pair.slice(0, i), value: pair.slice(i + 1),
                          label: pair.slice(i + 1) });
      }
    }
  }
  const zkPairs = p.getAll("zk");
  if (zkPairs.length && typeof ZEEK_FILTERS !== "undefined") {
    ZEEK_FILTERS.splice(0, ZEEK_FILTERS.length);
    for (const pair of zkPairs) {
      const i = pair.indexOf(":");
      if (i > 0) {
        ZEEK_FILTERS.push({ field: pair.slice(0, i), value: pair.slice(i + 1),
                            label: pair.slice(i + 1) });
      }
    }
  }
  const dv = (id, v) => { const e = document.getElementById(id); if (e) e.value = v; };
  if (p.get("dc.addr")) dv("dc-addr", p.get("dc.addr"));
  if (p.get("dc.port")) dv("dc-port", p.get("dc.port"));
  if (p.get("bl.domain")) dv("bl-domain", p.get("bl.domain"));
  if (p.get("bl.client")) dv("bl-client", p.get("bl.client"));
  for (const id of ["dn-qtype", "dn-rcode", "dn-domain", "dn-client"]) {
    if (p.get(id.replace("dn-", "dn."))) dv(id, p.get(id.replace("dn-", "dn.")));
  }
  if (p.get("wl") && v === "weirlings") {
    // Only a Weirlings URL may open a sensor; a stray wl= on another view is ignored rather
    // than hijacking the view the operator asked for.
    PENDING_WL = p.get("wl");
    if (typeof WL_FILTERS !== "undefined") {
      WL_FILTERS.state = p.get("wl.f") || "";
    }
  }
  // The most specific target first: an evidence drill-down outranks its plain tab.
  if (v === "evidence" || p.get("ev.host")) {
    const host = p.get("ev.host");
    if (host) {
      showView("evidence");
      loadEvidence(host, p.get("ev.start") || "", p.get("ev.end") || "").catch(showError);
      return true;
    }
  }
  // BLOCKS IS A DRILL, NOT A TAB (ledger: blocked, tab=false), so `v=blocked` must be handled
  // before the tab lookup below: a drill has no .tab[data-view] to match, and the old code
  // silently fell through to Health on a fresh load. The tab stays lit on Sluice through
  // TAB_FOR_DRILL, and `showView` loads /api/blocked.
  if (v === "blocked") {
    showView("blocked");
    return true;
  }
  // FINDINGS IS A DRILL, NOT A TAB (the Assets tab stays lit behind it). Handle it before
  // the tab lookup, or a shared finding link silently falls through to Health.
  if (v === "findings") {
    FINDINGS_STATE.ip = String(p.get("fd.ip") || "").trim();
    FINDINGS_STATE.severity = String(p.get("fd.sev") || "").trim();
    showView("findings");
    return true;
  }
  // #v=identity is an old alias of the merged Assets surface (the name still appears in
  // bookmarks and palette history). A host URL with an address restores the actual host page;
  // without one it is not an investigation, so it falls back to the inventory.
  if (v === "identity") v = "assets";
  if (v === "host") {
    const hostAddr = (p.get("h.addr") || p.get("hp.addr") || "").trim();
    if (hostAddr) {
      HOST_RETURN = { pending: false, view: "assets", scroll: 0 };
      showView("host");
      loadHost(hostAddr, String(trHours())).catch(showError);
      loadHostPage(hostAddr).catch(showError);
      return true;
    }
    v = "assets";
  }
  if (v) {
    const tab = [...document.querySelectorAll(".tab")].find((t) => t.dataset.view === v);
    if (tab) showView(v);
  }
  return true;
}
/** Back/forward restores the PAGE the operator left, not just its filters. */
function wireHistoryNavigation() {
  const restore = () => {
    HISTORY_NAVIGATING = true;
    try { applyURLState(); } catch (err) { showError(err); }
    // The showView/loaders schedule their own URL sync; keep this turn's writes replacing,
    // then release the flag for the next real click.
    setTimeout(() => { HISTORY_NAVIGATING = false; }, 450);
  };
  window.addEventListener("popstate", restore);
  // A manual hash edit is a navigation too; popstate is not guaranteed for every browser's
  // hash-only move, and the two events must not restore the same entry twice.
  window.addEventListener("hashchange", () => {
    if (!HISTORY_NAVIGATING) restore();
  });
}

// THE PER-VIEW TIME CONTROLS AND RELOAD BUTTONS ARE GONE (the operator's instruction,
// 2026-10-16, twice over): "remove any redundant time controls" ... "That needs removed I
// think. We should use universal time filters through out." One control owns the range; a
// range change re-fetches each view by calling its LOADER directly -- there is no per-view
// time text and no per-view refresh button left to disagree with the header.
const TR_RELOAD_LOADERS = () => [
  window.loadAnomalies, window.loadAssets, window.loadHealthDeep, window.loadIdentity,
  window.loadModels, window.loadNetflow, window.loadNetwork, window.loadSluice,
  window.loadSettings, window.loadWeirlings, window.loadZeek,
  // THE THREE THAT WERE MISSING (issue #30). Discover, DNS and Blocked read trHours() only
  // at fetch time, so a range change left the data on screen -- and Discover's own window
  // pill -- on the OLD window while the header already read the new one: two windows on one
  // screen, with nothing saying which the rows belonged to. There is no per-view reason for
  // any of them to sit the control out; they are the same loaders the tab switcher calls.
  window.loadDiscover, window.loadDns, window.loadBlocked,
].filter((fn) => typeof fn === "function");

function trHours() {
  const h = Number(TIME_RANGE.hours);
  return Math.max(1, Math.ceil(Number.isFinite(h) && h > 0 ? h : 24));
}
function trReloadViews() {
  // .then(loader) passes the function instead of calling a bare identifier: same effect, and
  // it keeps the "every function the console calls is defined" scan honest (an arrow param
  // called by name reads as an undefined function to that check). One broken view rejects its
  // own promise and cannot stop the refresh of the others.
  TR_RELOAD_LOADERS().forEach((loader) => { Promise.resolve().then(loader).catch(() => {}); });
}

function trInit() {
  try {
    const held = JSON.parse(sessionStorage.getItem("weirvern-timerange") || "null");
    if (held && (held.mode === "relative" || held.mode === "absolute")) Object.assign(TIME_RANGE, held);
  } catch (e) { /* a corrupt record must not break the console */ }
}
function trPersist() {
  try { sessionStorage.setItem("weirvern-timerange", JSON.stringify(TIME_RANGE)); } catch (e) {}
}
function trLabel() {
  if (TIME_RANGE.mode === "absolute") return TIME_RANGE.from + " → " + (TIME_RANGE.to || "now") + " · frozen";
  const h = TIME_RANGE.hours;
  if (h < 1) return "Last " + Math.round(h * 60) + " minutes";
  if (h === 1) return "Last 1 hour";
  if (h < 48) return "Last " + h + " hours";
  return "Last " + Math.round(h / 24) + " days";
}
function trWindowSuffix() {
  return "from=" + encodeURIComponent(TIME_RANGE.from) + "&to=" + encodeURIComponent(TIME_RANGE.to || "");
}
function trNote(text, isError) {
  const el = document.getElementById("tr-note");
  if (el) { el.textContent = text; el.style.color = isError ? "var(--bad)" : ""; }
}
function trApply(range) {
  TIME_RANGE.mode = range.mode || "relative";
  TIME_RANGE.hours = Number(range.hours) > 0 ? Number(range.hours) : 24;
  TIME_RANGE.from = range.from || "";
  TIME_RANGE.to = range.to || "";
  // AN ABSOLUTE RANGE IS FROZEN AT THE MOMENT IT IS APPLIED (research: Grafana's picker).
  // "now" in the to-slot would keep sliding the window under the reader's cursor -- the
  // opposite of what "absolute" promises -- so it becomes the concrete minute now.
  if (TIME_RANGE.mode === "absolute" && (!TIME_RANGE.to || TIME_RANGE.to === "now")) {
    TIME_RANGE.to = trFormat(new Date());
  }
  trPersist();
  const btn = document.getElementById("tr-open");
  if (btn) btn.textContent = trLabel();
  trPushRecent();
  trReloadViews();
  scheduleURLSync();
}
function trFormat(d) {
  const p = (n) => String(n).padStart(2, "0");
  return d.getFullYear() + "-" + p(d.getMonth() + 1) + "-" + p(d.getDate()) + " " + p(d.getHours()) + ":" + p(d.getMinutes());
}
function trMoment(text, nowMs) {
  const raw = String(text || "").trim().toLowerCase();
  if (raw === "now") return new Date(nowMs);
  const rel = raw.match(/^-(\d+(?:\.\d+)?)\s*(m|h|d|w)?$/);
  if (rel) {
    const n = parseFloat(rel[1]); const unit = rel[2] || "h";
    const ms = n * (unit === "m" ? 60e3 : unit === "h" ? 3600e3 : unit === "d" ? 864e5 : 6048e5);
    return new Date(nowMs - ms);
  }
  const iso = raw.match(/^(\d{4}-\d{2}-\d{2})(?:[ t](\d{2}:\d{2}(?::\d{2})?))?$/);
  if (iso) return new Date(iso[1] + "T" + (iso[2] || "00:00") + ":00");
  throw new Error("cannot read the time " + JSON.stringify(text) + " (want 2026-10-16 or 2026-10-16 05:00)");
}
function trParseText(text) {
  const raw = String(text || "").trim().toLowerCase();
  if (!raw) throw new Error("type a range first");
  const quick = raw.match(/^(?:last|past)\s+(\d+(?:\.\d+)?)\s*(m|min|mins|minute|minutes|h|hr|hrs|hour|hours|d|day|days|w|week|weeks)$/);
  if (quick) {
    const n = parseFloat(quick[1]); const unit = quick[2][0];
    return { mode: "relative", hours: unit === "m" ? n / 60 : unit === "h" ? n : unit === "d" ? n * 24 : n * 168 };
  }
  const short = raw.match(/^-(\d+(?:\.\d+)?)\s*(m|h|d|w)$/);
  if (short) {
    const n = parseFloat(short[1]); const u = short[2];
    return { mode: "relative", hours: u === "m" ? n / 60 : u === "h" ? n : u === "d" ? n * 24 : n * 168 };
  }
  const pair = raw.split(/\s+(?:to|until)\s+/);
  if (pair.length === 2) {
    const nowMs = Date.now();
    const fromD = trMoment(pair[0], nowMs);
    if (pair[1] === "now") return { mode: "relative", hours: Math.max(1 / 60, (nowMs - fromD.getTime()) / 36e5) };
    const toD = trMoment(pair[1], nowMs);
    if (fromD.getTime() >= toD.getTime()) throw new Error("the start must be before the end");
    return { mode: "absolute", from: trFormat(fromD), to: trFormat(toD), hours: (toD - fromD) / 36e5 };
  }
  throw new Error('cannot read that range — try "last 1 hour", "-12h to now", or two times');
}
function trPushRecent() {
  try {
    const list = JSON.parse(sessionStorage.getItem("weirvern-timerange-recent") || "[]");
    const label = trLabel();
    const next = [{ label, range: { mode: TIME_RANGE.mode, hours: TIME_RANGE.hours, from: TIME_RANGE.from, to: TIME_RANGE.to } }]
      .concat(list.filter((r) => r.label !== label)).slice(0, 5);
    sessionStorage.setItem("weirvern-timerange-recent", JSON.stringify(next));
    trRenderRecent(next);
  } catch (e) {}
}
function trRenderRecent(list) {
  const box = document.getElementById("tr-recent");
  const sec = document.getElementById("tr-recent-sec");
  if (!box || !sec) return;
  box.innerHTML = "";
  if (!list || !list.length) { sec.hidden = true; return; }
  sec.hidden = false;
  list.forEach((r) => {
    const b = document.createElement("button");
    b.textContent = r.label;
    b.addEventListener("click", () => trApply(r.range));
    box.appendChild(b);
  });
}
function trZoneName() {
  try {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone || "local time";
    const short = new Intl.DateTimeFormat(undefined, { timeZoneName: "short" })
      .formatToParts(new Date()).find((p) => p.type === "timeZoneName");
    return tz + (short && short.value ? " (" + short.value + ")" : "");
  } catch (_e) { return "local time"; }
}

function trBoot() {
  trInit();
  const btn = document.getElementById("tr-open");
  const panel = document.getElementById("tr-panel");
  if (!btn || !panel) return;
  btn.textContent = trLabel();
  btn.addEventListener("click", () => {
    panel.hidden = !panel.hidden;
    btn.setAttribute("aria-expanded", String(!panel.hidden));
  });
  const presets = document.getElementById("tr-presets");
  if (presets) presets.addEventListener("click", (e) => {
    const b = e.target.closest && e.target.closest("button[data-hours]");
    if (b) trApply({ mode: "relative", hours: Number(b.dataset.hours) });
  });
  const input = document.getElementById("tr-text");
  const applyText = () => {
    if (!input) return;
    try { trApply(trParseText(input.value)); trNote("applied: " + trLabel()); }
    catch (err) { trNote(String((err && err.message) || err), true); }
  };
  const ta = document.getElementById("tr-text-apply");
  if (ta) ta.addEventListener("click", applyText);
  if (input) input.addEventListener("keydown", (e) => { if (e.key === "Enter") applyText(); });
  const abs = document.getElementById("tr-abs-apply");
  if (abs) abs.addEventListener("click", () => {
    const fEl = document.getElementById("tr-from");
    const tEl = document.getElementById("tr-to");
    const f = fEl ? fEl.value : "";
    if (!f) return trNote("pick a start time first", true);
    const toS = tEl && tEl.value ? String(tEl.value).replace("T", " ").slice(0, 16) : "now";
    try { trApply(trParseText(String(f).replace("T", " ").slice(0, 16) + " to " + toS)); trNote("applied: " + trLabel()); }
    catch (err) { trNote(String((err && err.message) || err), true); }
  });
  try { trRenderRecent(JSON.parse(sessionStorage.getItem("weirvern-timerange-recent") || "[]")); } catch (e) {}
  // THE RANGE CONTROL NAMES ITS TIMEZONE (research: Grafana's picker) -- every timestamp in
  // the console is rendered in the browser's own zone, and saying so removes the one
  // ambiguity an operator on a call cannot resolve by looking harder.
  const tzNote = document.getElementById("tr-tz");
  if (tzNote) tzNote.textContent = "Times everywhere are shown in " + trZoneName() +
    " \u2014 your browser's timezone.";
}
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", trBoot);
} else {
  trBoot();
}

/* INSTALLED WEB APP. The manifest supplies the logo and standalone shell; the service worker
 * is network-only so installing never freezes a dashboard at yesterday's state. Registration
 * is best-effort: an HTTP origin or a browser without support must still boot the console. */
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/sw.js").catch(() => {});
  });
}

/* ── NETWORK SCOPES (Settings) ─────────────────────────────────────────────────────────────
 * The operator declares what a network IS and whether its hosts are alertable. The server
 * validates CIDRs, resolves overlaps by longest prefix and reports unclassified traffic; this
 * card only renders and edits those declarations. It never invents an internal/external
 * distinction from an address. */
let NETWORK_SCOPES = [];
let NETWORK_EDIT_ID = "";
let NETWORKS_WIRED = false;
let NETWORK_SUGGESTED = [];

function networkPolicyLabel(policy) {
  // The stored/API value stays `full`; the operator-facing vocabulary says what it does.
  return policy === "full" ? "per-host" : (policy || "");
}

function networkScopeRow(scope, writable) {
  const monitored = Boolean(scope.monitored) && ["full", "aggregate"].includes(scope.policy);
  return el("tr", {}, [
    el("td", { class: "mono", text: scope.cidr + (scope.warning ? " (catch-all)" : ""),
              attrs: { title: scope.warning || "" } }),
    el("td", { text: scope.label }),
    el("td", { text: networkPolicyLabel(scope.policy) }),
    el("td", { text: monitored ? "yes" : "observed" }),
    el("td", { class: "num", text: scope.hosts === null || scope.hosts === undefined ? "—" : String(scope.hosts) }),
    el("td", { class: "num", text: scope.alerts === null || scope.alerts === undefined ? "—" : String(scope.alerts) }),
    el("td", {}, [
      el("button", { class: "quiet", type: "button", attrs: { "data-net-edit": scope.id, disabled: writable ? null : "disabled" }, text: "Edit" }),
      el("button", { class: "quiet danger", type: "button", attrs: { "data-net-delete": scope.id, disabled: writable ? null : "disabled" }, text: "Delete" }),
    ]),
  ]);
}

function renderNetworks(data) {
  const note = document.getElementById("st-networks-note");
  const state = document.getElementById("st-networks-state");
  const body = document.querySelector("#st-networks-table tbody");
  const writable = Boolean(window.SETTINGS_WRITES);
  if (!note || !body) return;
  const summary = data.summary || {};
  if (state) {
    state.textContent = data.unconfigured ? "not configured" :
      `${summary.monitored || 0} monitored · ${summary.observed || 0} observed`;
  }
  if (!data.available) {
    note.textContent = "Network scopes unavailable: " + (data.reason || "the read did not run");
    body.replaceChildren();
    return;
  }
  NETWORK_SUGGESTED = data.suggested_scopes || [];
  const autofill = document.getElementById("st-net-autofill");
  if (autofill) {
    autofill.classList.toggle("hidden", !NETWORK_SUGGESTED.length || !writable);
  }
  if (data.unconfigured) {
    note.textContent = NETWORK_SUGGESTED.length
      ? `${NETWORK_SUGGESTED.length} monitored network(s) are configured on the sensor but not ` +
        "declared here. Auto-fill proposes those exact segments; external traffic stays observed."
      : "No networks are declared yet. Detection is still running unscoped, so " +
        "every source address is treated as a host. Add the internal, VPN or DMZ ranges this " +
        "deployment should monitor — and leave external traffic observed unless you deliberately " +
        "want per-host external alerts.";
  } else {
    const bits = ["Longest prefix wins on overlap."];
    if (data.summary.unclassified_hosts !== null && data.summary.unclassified_hosts !== undefined) {
      bits.push(`${data.summary.unclassified_hosts} source address(es) in the last 24h fall ` +
        "outside every declaration.");
    }
    if (!data.counts_available) bits.push("Some counts could not be read; — means unknown, not zero.");
    const warned = (data.scopes || []).filter((s) => s.warning);
    if (warned.length) bits.push("Catch-all scope flagged: " + warned.map((s) => s.cidr).join(", ") +
      ". Monitoring a /0 recreates the flood this feature exists to prevent.");
    note.textContent = bits.join(" ");
  }
  body.replaceChildren();
  if (!(data.scopes || []).length) {
    body.appendChild(el("tr", {}, [el("td", { class: "muted", attrs: { colspan: 7 }, text: "No networks declared." })]));
    return;
  }
  for (const scope of data.scopes || []) body.appendChild(networkScopeRow(scope, writable));
}

async function loadNetworks() {
  const note = document.getElementById("st-networks-note");
  let data;
  try {
    data = await getJSON("/api/networks");
  } catch (err) {
    if (note) note.textContent = "Network scopes could not be read: " + (err && err.message ? err.message : err);
    return;
  }
  NETWORK_SCOPES = data.scopes || [];
  renderNetworks(data);
  if (!NETWORKS_WIRED) {
    NETWORKS_WIRED = true;
    const save = document.getElementById("st-net-save");
    const cancel = document.getElementById("st-net-cancel");
    const label = document.getElementById("st-net-label");
    const card = document.getElementById("st-networks-card");
    if (label) {
      label.addEventListener("change", () => {
        const policy = document.getElementById("st-net-policy");
        if (policy && label.value === "external" && policy.value === "full") policy.value = "observe";
      });
    }
    if (cancel) cancel.addEventListener("click", () => networkResetForm());
    if (save) {
      save.addEventListener("click", async () => {
        const cidr = String((document.getElementById("st-net-cidr") || {}).value || "").trim();
        if (!cidr) { showNetworkResult("A CIDR is required.", true); return; }
        const body = {
          cidr,
          label: (document.getElementById("st-net-label") || {}).value || "internal",
          policy: (document.getElementById("st-net-policy") || {}).value || "observe",
          monitored: Boolean((document.getElementById("st-net-monitored") || {}).checked),
          description: (document.getElementById("st-net-desc") || {}).value || "",
        };
        if (NETWORK_EDIT_ID) body.id = NETWORK_EDIT_ID;
        save.disabled = true;
        try {
          const res = await postJSON("/api/networks/save", body);
          if (res && res.ok === false) throw new Error(res.error || "the server rejected the scope");
          networkResetForm();
          showNetworkResult("Saved. The worker applies scopes on its next sweep.", false);
          await loadNetworks();
        } catch (err) {
          showNetworkResult("Could not save: " + (err && err.message ? err.message : err), true);
        } finally { save.disabled = false; }
      });
    }
    if (card) {
      card.addEventListener("click", async (ev) => {
        if (ev.target && ev.target.id === "st-net-autofill") {
          ev.preventDefault();
          await networkAutoFill();
          return;
        }
        const edit = ev.target && ev.target.getAttribute && ev.target.getAttribute("data-net-edit");
        const del = ev.target && ev.target.getAttribute && ev.target.getAttribute("data-net-delete");
        if (edit) {
          const scope = NETWORK_SCOPES.find((s) => s.id === edit);
          if (scope) networkEdit(scope);
        } else if (del) {
          if (!window.confirm("Delete this network declaration? Traffic remains collected; it becomes unclassified.")) return;
          try {
            const res = await postJSON("/api/networks/delete", { id: del });
            if (res && res.ok === false) throw new Error(res.error || "the server rejected the delete");
            showNetworkResult("Deleted. The worker applies scopes on its next sweep.", false);
            await loadNetworks();
          } catch (err) {
            showNetworkResult("Could not delete: " + (err && err.message ? err.message : err), true);
          }
        }
      });
    }
  }
}

function networkEdit(scope) {
  NETWORK_EDIT_ID = scope.id;
  const set = (id, value) => { const n = document.getElementById(id); if (n) n.value = value; };
  set("st-net-cidr", scope.cidr);
  set("st-net-label", scope.label);
  set("st-net-policy", scope.policy);
  set("st-net-desc", scope.description || "");
  const mon = document.getElementById("st-net-monitored");
  if (mon) mon.checked = Boolean(scope.monitored);
  const save = document.getElementById("st-net-save");
  if (save) save.textContent = "Save network";
  const cancel = document.getElementById("st-net-cancel");
  if (cancel) cancel.classList.remove("hidden");
  showNetworkResult("Editing " + scope.cidr + ".", false);
}

async function networkAutoFill() {
  if (!window.SETTINGS_WRITES) return;
  const result = document.getElementById("st-net-result");
  if (result) { result.className = "muted"; result.textContent = "Creating scopes from monitored networks…"; }
  try {
    const data = await postJSON("/api/networks/autofill", {});
    if (result) {
      result.className = "ok";
      result.textContent = `Created ${data.created || 0} scope(s). The worker applies them on its next sweep.`;
    }
    await loadNetworks();
  } catch (err) {
    if (result) { result.className = "bad"; result.textContent = "Auto-fill failed: " + (err && err.message ? err.message : err); }
  }
}

function networkResetForm() {
  NETWORK_EDIT_ID = "";
  for (const id of ["st-net-cidr", "st-net-desc"]) {
    const n = document.getElementById(id); if (n) n.value = "";
  }
  const save = document.getElementById("st-net-save");
  if (save) save.textContent = "Add network";
  const cancel = document.getElementById("st-net-cancel");
  if (cancel) cancel.classList.add("hidden");
  const mon = document.getElementById("st-net-monitored");
  if (mon) mon.checked = true;
}

function showNetworkResult(text, bad) {
  const n = document.getElementById("st-net-result");
  if (!n) return;
  n.textContent = text;
  n.className = "muted" + (bad ? " bad" : "");
}
