// ── Sluice Gate, rebuilt 2026-11-06 ──────────────────────────────────────────────────────────
//
// ONE SURFACE: state, rules, one rule sheet.
//
// The old page repeated the gate state in an overview card, kept a second composer in the Rules
// card, showed bulk-selection checkboxes at rest, and put blocklist management in the middle of
// enforcement. This file is deliberately smaller: the gate's state is read once, the rule table
// is a list of sentences, and the only write surface is the sheet.
//
// THE GATE FAILS OPEN ON PURPOSE. "Disarmed" is a choice, not an error; "degraded" is a fault and
// must name its reason. A failed query is never rendered as an empty rule list.

let SL2_STATE = { data: null, settings: null, filter: "all", showRevoked: false, current: null };

function sluiceDuration(seconds) {
  if (seconds === null || seconds === undefined) return "until revoked";
  const past = seconds < 0;
  const s = Math.abs(seconds);
  let text;
  if (s < 60) text = `${s}s`;
  else if (s < 3600) text = `${Math.round(s / 60)}m`;
  else if (s < 86400) text = `${(s / 3600).toFixed(1)}h`;
  else text = `${(s / 86400).toFixed(1)}d`;
  return past ? `${text} ago` : `in ${text}`;
}

function sl2Setting(key) {
  const rows = {};
  for (const group of Object.values((SL2_STATE.settings && SL2_STATE.settings.groups) || {})) {
    for (const row of group || []) if (row && row.key) rows[String(row.key).toLowerCase()] = row;
  }
  const row = rows[String(key).toLowerCase()];
  if (!row) return "";
  return String(row.value != null ? row.value : (row.current != null ? row.current : ""));
}

function sl2On(key) {
  return /^(1|true|on|yes|enabled|armed)$/i.test(sl2Setting(key));
}

/* ── Evidence primitives ─────────────────────────────────────────────────────────────────────
 *
 * THE STATE CHIP IS THE ALERTS CHIP. Same `.bubble state` shape, same `sev-*` ramp, same
 * colour+glyph+word grammar: a red chip means the same thing on this tab as on Alerts. Four
 * states, and every one of them is derived from what the gate reports or from what is actually
 * loaded -- never from the setting alone.
 */
const SL2_STATE_SEV = { enforcing: "low", monitoring: "medium", off: "low", degraded: "critical",
                        stale: "high", unknown: "low" };

function sl2StateWord(kind) {
  return { enforcing: "enforcing", monitoring: "monitoring", off: "off",
           degraded: "degraded", stale: "stale", unknown: "unknown" }[kind] || "unknown";
}

function sl2StateChip(kind, extra) {
  const sev = SL2_STATE_SEV[kind] || "low";
  const glyph = (typeof SEVERITY_GLYPHS !== "undefined" && SEVERITY_GLYPHS[sev]) || "";
  const text = `${glyph ? glyph + " " : ""}${sl2StateWord(kind)}${extra ? " · " + extra : ""}`;
  // STATE IS A PILL, ACTION IS A BUTTON. The pill's capsule shape and filled tint are the
  // vocabulary that keeps a revoked rule from reading like a disabled control.
  return el("span", { class: `bubble state sev-${sev}`, text });
}

/** Replace the chip in place, keeping its id: the markup owns one element, and the renderer
 *  cannot leave the previous severity class behind on a re-render. */
function sl2SetStateChip(id, kind) {
  const old = document.getElementById(id);
  if (!old) return;
  const chip = sl2StateChip(kind);
  chip.id = id;
  old.replaceWith(chip);
}

/** A count with its noun, so a number never appears bare. */
function sl2Count(n, one, many) {
  const v = Number(n) || 0;
  return `${v.toLocaleString()} ${v === 1 ? one : (many || one + "s")}`;
}

/** Ages come from the server as SECONDS. A null age is "not measured", never "just now". */
function sl2Ago(seconds) {
  if (seconds === null || seconds === undefined || Number.isNaN(Number(seconds))) return "";
  const s = Math.max(0, Number(seconds));
  if (s < 10) return "just now";
  if (s < 90) return `${Math.round(s)}s ago`;
  if (s < 5400) return `${Math.round(s / 60)}m ago`;
  if (s < 172800) return `${(s / 3600).toFixed(1)}h ago`;
  return `${(s / 86400).toFixed(1)}d ago`;
}

/** The window, in the reader's words: "24h" is a number, "the last 24h" is a sentence. */
function sl2Window(hours) {
  const h = Number(hours) || 24;
  return h === 24 ? "the last 24h" : (h % 24 === 0 ? `the last ${h / 24}d` : `the last ${h}h`);
}

/** One rule's firing record, in the window that is on screen. */
function sl2RuleEvidence(rule, d) {
  const hours = Number((d && d.hits_hours) || 24);
  const ev = rule && rule.evidence;
  if (d && d.evidence_available === false) {
    return "match evidence unavailable — the event table could not be read";
  }
  if (!ev || !Number(ev.events)) {
    return rule && rule.domain
      ? `no DNS matches in ${sl2Window(hours)}`
      : `no packet matches in ${sl2Window(hours)}`;
  }
  const when = sl2Ago(ev.last_age_s);
  if (rule && rule.domain) {
    return `${sl2Count(ev.dns || 0, "DNS match", "DNS matches")} in ${sl2Window(hours)}`
      + (when ? ` · last ${when}` : "");
  }
  const packets = Number(ev.packets || 0);
  return `${sl2Count(ev.flow || 0, "flow match", "flow matches")} in ${sl2Window(hours)}`
    + (packets ? ` · ${sl2Count(packets, "packet")} dropped` : "")
    + (when ? ` · last ${when}` : "");
}

/** Is this rule currently in the enforcement set? A parked, revoked or lapsed rule is not. */
function sl2Enforces(rule) {
  return Boolean(rule && rule.live && !rule.revoked && !rule.disabled);
}

function sl2GateOf(rule) {
  return rule && rule.domain ? "Domain" : "Traffic";
}

function sl2StateOf(rule) {
  if (!rule) return { text: "unknown", sev: "low", kind: "unknown" };
  if (rule.revoked) return { text: "revoked", sev: "low", kind: "off" };
  if (rule.disabled) return { text: "parked", sev: "medium", kind: "off" };
  if (rule.expires_in_s !== null && rule.expires_in_s !== undefined && rule.expires_in_s < 0) {
    return { text: "expired", sev: "low", kind: "off" };
  }
  if (rule.live) return { text: rule.mode === "alert" ? "live · alert only" : "live · blocking",
                          sev: rule.mode === "alert" ? "medium" : "low", kind: "enforcing" };
  return { text: "not live", sev: "low", kind: "off" };
}

function sl2Visible(rule) {
  if (!rule) return false;
  if (rule.revoked && !SL2_STATE.showRevoked) return false;
  if (SL2_STATE.filter === "domain" && !rule.domain) return false;
  if (SL2_STATE.filter === "traffic" && rule.domain) return false;
  return true;
}

/** ONE WAY TO SET THE RULES FILTER. The chips, the gate tiles and anything added later all
 *  come through here, so the pressed state and the rows cannot disagree. */
function sl2SetGate(gate) {
  SL2_STATE.filter = gate || "all";
  // Published for app.js's URL writer, which is evaluated before this module's `let` exists.
  window.SL2_GATE_FILTER = SL2_STATE.filter;
  const filters = document.getElementById("sl2-filters");
  if (filters) {
    for (const button of filters.querySelectorAll("[data-gate]")) {
      const on = (button.getAttribute("data-gate") || "all") === SL2_STATE.filter;
      button.classList.toggle("active", on);
      button.setAttribute("aria-pressed", on ? "true" : "false");
    }
  }
  renderSluiceRules(SL2_STATE.data || { available: false, reason: "not loaded" });
  const card = document.getElementById("sl2-rules");
  if (card && card.scrollIntoView) {
    try { card.scrollIntoView({ block: "center", behavior: "smooth" }); } catch (_e) { /* optional */ }
  }
}

function sl2Chip(text, cls) {
  return el("span", { class: `bubble state ${cls || "muted"}`, text });
}

async function loadSluice() {
  if (typeof scheduleURLSync === "function") scheduleURLSync();
  // THE PENDING GATE IS app.js's, AND app.js IS NOT ALWAYS LOADED WITH US. `let` at the top
  // level of another script is a lexical binding, not a window property: it is visible in the
  // browser (one global scope for classic scripts) but absent when this file is executed on its
  // own -- as the loader check in tests/test_sluice.py does. Reading it unguarded threw
  // ReferenceError before the fetch, so a failed gate query reported nothing at all. Guard the
  // read, and only write it back inside the branch that proved it exists.
  const pendingGate = typeof PENDING_SL_GATE === "string" ? PENDING_SL_GATE : "";
  if (pendingGate) {
    SL2_STATE.filter = ["all", "domain", "traffic"].includes(pendingGate)
      ? pendingGate : "all";
    PENDING_SL_GATE = "";
  }
  window.SL2_GATE_FILTER = SL2_STATE.filter;
  let d;
  // SETTINGS ARE INDEPENDENT OF THE GATE QUERY. Sequentially awaiting them made a 2.3s
  // gate read plus another round trip before the view could render; start the settings
  // read alongside it and join only when both are needed.
  const settingsPromise = getJSON("/api/settings")
    .catch(() => null);
  try {
    const slHours = typeof trHours === "function" ? trHours() : 24;
    d = await getJSON(`/api/sluice?hours=${slHours}`);
  } catch (err) {
    showDataError(`the gate query failed: ${(err && err.message) || err}`);
    return;
  }
  SL2_STATE.data = d;
  SL2_STATE.settings = await settingsPromise;
  if (!d.available) showDataError(d.reason || "the gate state is unavailable");
  renderSluiceGates(d);
  renderSluiceRules(d);
}

/** Whether THIS caller may write, and why not. The settings read carries the server's answer;
 *  a failed read must not silently ENABLE controls the server would refuse. */
function sl2Writes() {
  const w = SL2_STATE.settings && SL2_STATE.settings.writes;
  if (w && typeof w.enabled === "boolean") {
    return { enabled: w.enabled, reason: String(w.reason || "") };
  }
  if (typeof AUTH !== "undefined" && AUTH && !AUTH.accounts) return { enabled: true, reason: "" };
  return { enabled: false,
           reason: "write access could not be established; sign in as an admin" };
}

function sl2ApplyControls() {
  const w = sl2Writes();
  const note = document.getElementById("sl2-readonly");
  if (note) {
    note.classList.toggle("hidden", w.enabled);
    note.textContent = w.enabled ? ""
      : `Read-only — ${w.reason || "this account can read the gate but not change it."}`;
  }
  for (const id of ["sl2-dom-toggle", "sl2-traf-toggle", "sl2-new"]) {
    const b = document.getElementById(id);
    if (!b) continue;
    // A control that appears and then refuses is worse than a disabled one that says why.
    if (id === "sl2-new") { b.disabled = !w.enabled; } else { b.dataset.readonly = w.enabled ? "" : "1"; }
  }
  for (const id of ["sl2-create-submit", "sl2-mode-save", "sl2-park", "sl-rule-delete"]) {
    const b = document.getElementById(id);
    if (b && !w.enabled) b.disabled = true;
  }
  return w;
}

function sl2SetReceipt(text, bad) {
  const box = document.getElementById("sl2-receipt");
  if (!box) return;
  box.textContent = text || "";
  box.classList.toggle("hidden", !text);
  box.classList.toggle("bad", Boolean(bad));
  if (text) box.dataset.at = new Date().toISOString();
}

/** The Domain Gate's enforcement set and its measured record. */
function sl2DomainFacts(d) {
  const lists = (d.blocklists || []).filter((s) => s && s.enabled);
  const names = lists.reduce((n, s) => n + (Number(s.domain_count) || 0), 0);
  const rules = (d.rules || []).filter(
    (r) => r.domain && sl2Enforces(r) && String(r.mode || "block") === "block");
  const all = Object.values(d.evidence || {});
  const dnsHits = all.reduce((n, e) => n + Number((e && e.dns) || 0), 0);
  const ages = all.map((e) => e && e.last_age_s).filter((v) => v !== null && v !== undefined);
  return {
    lists, names, rules, dnsHits,
    lastAge: ages.length ? Math.min.apply(null, ages) : null,
    known: d.blocklists_available !== false,
    reason: String(d.blocklists_reason || "").trim(),
  };
}

/** The Traffic Gate's measured state. The supervisor's row is the evidence; the setting is only
 *  a claim about it, and a disagreement is surfaced rather than smoothed over. */
function sl2TrafficKind(gate, settingsOn) {
  const state = String((gate && gate.state) || "").toLowerCase();
  if (!gate || gate.available === false) return { kind: "unknown", mismatch: "" };
  if (gate.stale) return { kind: "stale", mismatch: "" };
  if (state === "degraded") return { kind: "degraded", mismatch: "" };
  const live = Number(gate.rules_active || 0);
  const measured = state === "armed" ? (live > 0 ? "enforcing" : "monitoring")
    : (state === "disarmed" ? "off" : "unknown");
  if (settingsOn !== null && (settingsOn === true) !== (state === "armed")
      && measured !== "unknown") {
    return {
      kind: "degraded",
      mismatch: `The setting says the gate is ${settingsOn ? "enabled" : "disabled"}, but the `
        + `supervisor reports it ${state || "without a state"}. The measurement wins here.`,
    };
  }
  return { kind: measured, mismatch: "" };
}

/* ── The fault line, in the console's own vocabulary ────────────────────────────────────────
 *
 * A fault is a severity chip and the measured sentence beside it -- the same pair an Alerts row
 * carries. There is no full-bleed band and no page-level attention strip: the card that owns
 * the fault states it, and every card uses the same chip geometry and the same type scale.
 */
function sl2BandSet(bandId, word, why, since, sev) {
  const band = document.getElementById(bandId);
  if (!band) return;
  const show = Boolean(String(why || "").trim());
  band.classList.toggle("hidden", !show);
  const chip = band.querySelector(".sl2-fault-bubble");
  if (chip) {
    chip.className = `bubble state sl2-fault-bubble sev-${sev || "critical"}`;
    chip.textContent = word || "Degraded";
  }
  const whyEl = band.querySelector(".sl2-fault-why");
  if (whyEl) whyEl.textContent = why || "";
  const sinceEl = band.querySelector(".sl2-fault-since");
  if (sinceEl) sinceEl.textContent = since || "";
}

/* ── Gate state ─────────────────────────────────────────────────────────────────────────────── */
function renderSluiceGates(d) {
  // ── A FAILED READ MUST NOT RENDER AS "off" (WV1-07) ─────────────────────────────────────────
  //
  // MEASURED LIVE with no database: /api/sluice answered
  // {"available": false, "reason": "cannot read the gate: FileNotFoundError"} and this card still
  // rendered chip "off" with the sentence "The packet gate is off. Rules still record hits, but no
  // packet is dropped." -- while the Rules panel ON THE SAME SCREEN said "Reach unavailable". One
  // screen claiming both that the gate is off and that its state is unknown.
  //
  // So a failed read gets its own state word, no numbers, and disabled controls: there is no
  // measurement here to act on.
  const settingsLoaded = Boolean(SL2_STATE.settings);
  sl2ApplyControls();
  if (d.available === false) {
    const why = String(d.reason || "").trim() || "the gate state could not be read";
    sl2SetStateChip("sl2-traf-chip", "unknown");
    sl2SetStateChip("sl2-dom-chip", "unknown");
    const trafLine = document.getElementById("sl2-traf-line");
    if (trafLine) trafLine.textContent = `Cannot read the gate state: ${why}`;
    const trafEv = document.getElementById("sl2-traf-ev");
    if (trafEv) trafEv.textContent = "This card makes no claim about whether traffic is being blocked.";
    const domLine = document.getElementById("sl2-dom-line");
    if (domLine) domLine.textContent = "Cannot read the rule and blocklist store; no claim is made about DNS blocking.";
    const domEv = document.getElementById("sl2-dom-ev");
    if (domEv) domEv.textContent = why;
    sl2BandSet("sl2-traf-band", "Unavailable", `Cannot read the gate state: ${why}`, "", "critical");
    sl2BandSet("sl2-dom-band", "Unavailable",
      "Cannot read the rule and blocklist store; no claim is made about DNS blocking.", "", "critical");
    for (const id of ["sl2-traf-toggle", "sl2-dom-toggle"]) {
      const btn = document.getElementById(id);
      if (btn) { btn.disabled = true; btn.title = "the gate state could not be read, so this control would act blind"; }
    }
    for (const id of ["sl2-auto", "sl2-receipt"]) {
      const n = document.getElementById(id);
      if (n) n.classList.add("hidden");
    }
    renderSluiceFleet(d.gates || [], d);
    renderSluiceReach(d);
    return;
  }

  const gate = d.gate || {};
  const gateOnSetting = settingsLoaded ? sl2On("SLUICE_ENABLED") : null;
  const domOnSetting = settingsLoaded ? sl2On("SLUICE_BLOCK_DOMAINS") : null;
  const live = Number(gate.rules_active || 0) || 0;
  const total = Number(gate.rules_total || 0) || 0;
  const windowText = sl2Window(d.hits_hours);

  // ── DOMAIN GATE ────────────────────────────────────────────────────────────────────────────
  const dom = sl2DomainFacts(d);
  let domKind = "off";
  let domLine;
  let domEv;
  if (!dom.known) {
    domKind = "degraded";
    domLine = "Cannot read the blocklists, so no claim is made about what DNS is answering.";
    domEv = dom.reason ? `The blocklist read failed: ${dom.reason}` : "The blocklist read failed.";
  } else if (!domOnSetting) {
    domKind = "off";
    domLine = "Domain blocking is off: domain rules record matches, but DNS answers are not blocked.";
    domEv = `${sl2Count(dom.names, "name")} would be covered by ${sl2Count(dom.lists.length, "enabled list")}`
      + ` · ${sl2Count(dom.dnsHits, "DNS match", "DNS matches")} recorded in ${windowText}`;
  } else if (dom.lists.length + dom.rules.length > 0) {
    domKind = "enforcing";
    domLine = `Names on ${sl2Count(dom.lists.length, "enabled blocklist")} and `
      + `${sl2Count(dom.rules.length, "block-mode domain rule")} are answered with a block answer.`;
    domEv = `${sl2Count(dom.names, "name")} covered`
      + (dom.dnsHits
        ? ` · ${sl2Count(dom.dnsHits, "DNS match", "DNS matches")} in ${windowText}`
          + (dom.lastAge !== null ? ` · last ${sl2Ago(dom.lastAge)}` : "")
        : ` · nothing has matched in ${windowText}`);
  } else {
    domKind = "monitoring";
    domLine = "Domain blocking is on, but nothing is being blocked: there is no enabled blocklist "
      + "and no block-mode domain rule.";
    domEv = `0 names covered · ${sl2Count(dom.dnsHits, "DNS match", "DNS matches")} recorded in ${windowText}`;
  }
  sl2SetStateChip("sl2-dom-chip", domKind);
  // ONE STATE CHIP PER CARD. When the card is faulted the fault line's chip is the state; a
  // second, identical chip in the title would be the duplicate this convergence removes.
  const domChip = document.getElementById("sl2-dom-chip");
  if (domChip) domChip.classList.toggle("hidden", domKind === "degraded");
  if (domKind === "degraded") {
    sl2BandSet("sl2-dom-band", "Degraded", domEv, "", "critical");
  } else {
    sl2BandSet("sl2-dom-band", "", "", "", "critical");
  }
  const domLineEl = document.getElementById("sl2-dom-line");
  if (domLineEl) domLineEl.textContent = domLine;
  const domEvEl = document.getElementById("sl2-dom-ev");
  if (domEvEl) domEvEl.textContent = domEv;
  const domBtn = document.getElementById("sl2-dom-toggle");
  if (domBtn) {
    const on = Boolean(domOnSetting);
    domBtn.textContent = on ? "Turn domain blocking off" : "Turn domain blocking on";
    domBtn.onclick = () => sl2AskSetting({
      key: "SLUICE_BLOCK_DOMAINS", value: on ? "0" : "1",
      heading: on ? "Turn domain blocking off?" : "Turn domain blocking on?",
      what: on
        ? "DNS answers for listed and block-mode domain rules stop being blocked. The rules stay "
          + "and keep recording matches."
        : "DNS answers for listed names and block-mode domain rules are blocked again.",
      cost: "This changes what the Domain Gate does for every device using this resolver.",
      verb: on ? "Turn it off" : "Turn it on",
    });
    domBtn.disabled = domBtn.dataset.readonly === "1";
  }

  // ── TRAFFIC GATE ───────────────────────────────────────────────────────────────────────────
  const traf = sl2TrafficKind(gate, gateOnSetting);
  sl2SetStateChip("sl2-traf-chip", traf.kind);
  const trafChip = document.getElementById("sl2-traf-chip");
  if (trafChip) trafChip.classList.toggle("hidden", traf.kind === "degraded" || traf.kind === "stale");
  const iface = ifaceList(gate.iface);
  const trafLineEl = document.getElementById("sl2-traf-line");
  const warning = document.getElementById("sl-gate-warning");
  const why = String(gate.warning || gate.detail || "").trim();
  let trafLine = "";
  let showWhy = "";
  if (traf.kind === "unknown") {
    trafLine = "The gate has not reported a state yet, so no claim is made about whether packets are dropped.";
  } else if (traf.kind === "degraded" || traf.kind === "stale") {
    // ONE STATEMENT OF THE FAULT. When the setting and the supervisor disagree, the line says
    // so and the callout carries both readings; the "could not install" sentence would be a
    // second, possibly wrong explanation of the same state.
    trafLine = traf.mismatch
      ? "Not enforcing: the setting and the supervisor disagree about whether this gate is armed."
      : (traf.kind === "stale"
        ? "Not enforcing: this gate stopped reporting, so its last measured state is stale."
        : "Not enforcing: the gate could not install its rules and has opened, so traffic on this "
          + "segment is not being blocked.");
    showWhy = traf.mismatch || why;
  } else if (traf.kind === "off") {
    trafLine = "Disarmed: no packet is being dropped. Rules still record matches.";
  } else if (traf.kind === "enforcing") {
    trafLine = `Armed on ${iface}: the supervisor installed its packet rules and is dropping traffic.`;
  } else {
    trafLine = `Armed on ${iface}, but no packet rules are installed — nothing can be dropped.`;
  }
  if (trafLineEl) trafLineEl.textContent = trafLine;
  const since = gate.age_s === null || gate.age_s === undefined
    ? "no report time" : `last reported ${sl2Ago(gate.age_s)}`;
  if (traf.kind === "degraded" || traf.kind === "stale") {
    const sev = traf.kind === "stale" ? "high" : "critical";
    const word = traf.kind === "stale" ? "Stale" : "Degraded";
    sl2BandSet("sl2-traf-band", word, showWhy, since, sev);
  } else {
    sl2BandSet("sl2-traf-band", "", "", "", "critical");
  }
  if (warning) {
    // ONE REASON PER LINE. The supervisor joins the per-interface refusals with "; "; a single
    // wall of text hides the second interface's failure behind the first.
    warning.textContent = showWhy ? showWhy.split(/;\s*/).filter(Boolean).join("\n") : "";
  }

  const ev = d.evidence || {};
  const flowMatches = Object.values(ev).reduce((n, e) => n + Number((e && e.flow) || 0), 0);
  const ages = Object.values(ev).map((e) => e && e.last_age_s)
    .filter((v) => v !== null && v !== undefined);
  const lastAge = ages.length ? Math.min.apply(null, ages) : null;
  const pkts = Number(gate.packets_blocked || 0);
  const reported = gate.age_s === null || gate.age_s === undefined
    ? "no report time" : `last reported ${sl2Ago(gate.age_s)}`;
  let trafEv = "";
  if (traf.kind === "unknown") {
    trafEv = "No gate state has been recorded for this sensor.";
  } else if (traf.kind === "degraded" || traf.kind === "stale") {
    // The severity band already carries the report time; repeating it here would state the same
    // measurement twice inside one card.
    trafEv = (total ? `${live} of ${sl2Count(total, "stored packet rule")} installed`
                   : "no packet rules stored")
      + ` · ${sl2Count(pkts, "packet")} dropped as of the last report`;
  } else if (traf.kind === "off") {
    trafEv = `${sl2Count(total, "packet rule")} stored · ${sl2Count(pkts, "packet")} dropped as of `
      + `the last report · ${reported}`;
  } else {
    trafEv = (total ? `${live} of ${sl2Count(total, "stored packet rule")} installed`
                   : "no packet rules stored")
      + ` · ${sl2Count(pkts, "packet")} dropped since the gate started`
      + (flowMatches
        ? ` · ${sl2Count(flowMatches, "rule match", "rule matches")} in ${windowText}`
          + (lastAge !== null ? ` · last ${sl2Ago(lastAge)}` : "")
        : ` · no rule matches in ${windowText}`)
      + ` · ${reported}`;
  }
  const trafEvEl = document.getElementById("sl2-traf-ev");
  if (trafEvEl) trafEvEl.textContent = trafEv;

  const note = document.getElementById("sl2-traf-note");
  const trafBtn = document.getElementById("sl2-traf-toggle");
  if (trafBtn) {
    const on = traf.kind === "enforcing" || traf.kind === "monitoring";
    const backend = String(gate.backend || "").toLowerCase();
    const canArm = on || (backend && backend !== "none" && total > 0);
    trafBtn.textContent = on ? "Disarm the gate" : "Arm the gate";
    trafBtn.disabled = trafBtn.dataset.readonly === "1" || (!on && !canArm);
    trafBtn.title = !on && !canArm
      ? (backend === "none" || !backend ? "No nft backend is running" : "File a rule before arming the gate")
      : "";
    const blocked = trafBtn.disabled && !on && !canArm;
    if (note) {
      note.textContent = blocked
        ? (backend === "none" || !backend
          ? "Arming is unavailable: no nft backend is running on this sensor."
          : "Arming is unavailable: file a packet rule first.")
        : "";
      note.classList.toggle("hidden", !blocked);
    }
    trafBtn.onclick = () => sl2AskSetting({
      key: "SLUICE_ENABLED", value: on ? "0" : "1",
      heading: on ? "Disarm the packet gate?" : "Arm the packet gate?",
      what: on
        ? "Packets stop being dropped on this sensor. The rules stay in the store and keep recording."
        : "The supervisor installs the live packet rules and starts dropping matching traffic.",
      cost: on
        ? "Whatever this gate is blocking becomes reachable again until it is armed."
        : "Arming restarts the worker and puts the packet rules in the path.",
      verb: on ? "Disarm the gate" : "Arm the gate",
    });
  }

  // The one automatic enforcement threshold; visible and stoppable.
  const auto = Number(sl2Setting("SLUICE_AUTO_SCORE") || 0) || 0;
  if (typeof refreshAutoBlockPill === "function") refreshAutoBlockPill(auto);
  const autoEl = document.getElementById("sl2-auto");
  if (autoEl) {
    autoEl.classList.toggle("hidden", !(auto > 0));
    if (auto > 0) {
      const pause = el("button", { class: "quiet", attrs: { type: "button" },
                                   text: "Pause auto-block" });
      pause.onclick = () => sl2AskSetting({
        key: "SLUICE_AUTO_SCORE", value: "0",
        heading: "Pause automatic blocking?",
        what: `Detections at or above ${auto.toFixed(2)} stop being blocked without review.`,
        cost: "The detections still alert; only the automatic block stops.",
        verb: "Pause auto-block",
      });
      autoEl.replaceChildren(
        el("span", { class: "bubble state sev-high", text: "▲ auto-block on" }),
        el("span", { class: "muted", text: `detections at or above ${auto.toFixed(2)} are blocked without review` }),
        pause,
      );
    } else {
      autoEl.replaceChildren();
    }
  }
  renderSluiceFleet(d.gates || [], d);
  renderSluiceReach(d);
}


/** A NIC list, normalised: "eth1,eth2" and "eth1, eth2" are the same two interfaces. */
function ifaceList(value) {
  const parts = Array.isArray(value) ? value : String(value || "").split(",");
  const names = parts.map((v) => String(v).trim()).filter(Boolean);
  return names.length ? names.join(", ") : "—";
}

/** Every recorded gate row, one card per sensor. Honest when there is nothing to list. */
function renderSluiceFleet(gates, d) {
  const host = document.getElementById("sl2-fleet");
  const note = document.getElementById("sl2-fleet-note");
  if (!host) return;
  const available = !d || d.gates_available !== false;
  host.replaceChildren();
  if (!available) {
    if (note) note.textContent = "";
    host.appendChild(emptyState({
      state: "failed",
      message: `The fleet's gate state could not be read${d && d.gates_reason ? `: ${d.gates_reason}` : ""}. `
        + "This is not a claim that no sensor is enforcing." }));
    return;
  }
  if (!gates.length) {
    if (note) note.textContent = "";
    host.appendChild(emptyState({
      state: "none",
      message: "No sensor has reported a packet gate yet. A gate row is written on every enforcement "
        + "pass; until one arrives, no segment is known to be filtered." }));
    return;
  }
  const stale = gates.filter((g) => g.stale).length;
  const enforcing = gates.filter((g) => !g.stale
    && String(g.state || "").toLowerCase() === "armed"
    && Number(g.rules_active || 0) > 0).length;
  if (note) {
    note.textContent = `${sl2Count(gates.length, "sensor")} · ${enforcing} enforcing`
      + (stale ? ` · ${stale} stale` : "");
  }
  for (const g of gates) {
    const state = String(g.state || "unknown").toLowerCase();
    const live = Number(g.rules_active || 0) || 0;
    const total = Number(g.rules_total || 0) || 0;
    const pkts = Number(g.packets_blocked || 0) || 0;
    let kind = "unknown";
    if (g.stale) kind = "stale";
    else if (state === "degraded") kind = "degraded";
    else if (state === "armed") kind = live > 0 ? "enforcing" : "monitoring";
    else if (state === "disarmed") kind = "off";

    let what;
    if (kind === "stale") {
      what = "Nothing here is being enforced.";
    } else if (kind === "degraded") {
      what = "This segment is not filtered.";
    } else if (kind === "off") {
      what = "Open by choice: no packet is being dropped on this sensor.";
    } else if (kind === "monitoring") {
      what = "Armed, but no packet rules are installed: nothing can be dropped.";
    } else if (kind === "enforcing") {
      what = "Dropping packets for the rules it installed.";
    } else {
      what = "No state has been recorded for this sensor.";
    }
    const bits = [];
    if (g.iface) bits.push(ifaceList(g.iface));
    if (g.enforcement && g.enforcement !== "none") bits.push(`${g.enforcement} path`);
    else bits.push("no verified path");
    if (!g.stale) {
      bits.push(g.age_s === null || g.age_s === undefined
        ? "no report time" : `last reported ${sl2Ago(g.age_s)}`);
    } else {
      bits.push("stale");
    }
    const ev = [
      total ? `${live} of ${sl2Count(total, "stored packet rule")} installed`
            : "no packet rules stored",
      pkts ? `${sl2Count(pkts, "packet")} dropped since it started` : "no packets matched since it started",
    ].join(" · ");

    const ago = g.age_s === null || g.age_s === undefined ? "some time ago" : sl2Ago(g.age_s);
    const band = (kind === "stale" || kind === "degraded")
      ? el("div", { class: "chips sl2-fault", attrs: { role: "status" } }, [
          el("span", { class: `bubble state sl2-fault-bubble sev-${SL2_STATE_SEV[kind]}`,
                       text: kind === "stale" ? "Stale" : "Degraded" }),
          el("span", { class: "sl2-fault-why", text: kind === "stale"
            ? `Stopped reporting ${ago}; its last report said ${state || "degraded"}.`
            : "Its rules are not installed and the gate has opened." }),
          el("span", { class: "muted sl2-fault-since", text: `last reported ${ago}` }),
        ])
      : null;

    const card = el("div", {
      class: g.sensor && typeof openWeirling === "function" ? "sl2-sensor clickable" : "sl2-sensor",
      attrs: g.sensor ? { role: "button", tabindex: "0", "aria-label": `open ${g.sensor}` } : {},
    }, [
      el("div", { class: "sl2-sensor-head" }, [
        el("span", { class: "sl2-sensor-name", text: g.sensor || "unnamed sensor" }),
        g.local ? el("span", { class: "muted", text: "· this hub" }) : null,
        // The fault line below carries the state chip when there is one; a second chip here
        // would state the same severity twice.
        band ? null : sl2StateChip(kind),
      ].filter(Boolean)),
      band,
      el("div", { class: "sl2-sensor-meta", text: bits.join(" · ") }),
      el("div", { class: "sl2-sensor-ev", text: what }),
      el("div", { class: "sl2-sensor-meta", text: ev }),
      g.sensor && typeof openWeirling === "function"
        ? el("span", { class: "sl2-sensor-cue", text: "Open sensor \u203a" }) : null,
    ].filter(Boolean));
    if (g.sensor && typeof openWeirling === "function") {
      const open = () => openWeirling(g.sensor);
      card.addEventListener("click", open);
      card.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); }
      });
    }
    host.appendChild(card);
  }
}

/** WHERE A PACKET RULE CAN ACTUALLY BITE. Not "every registered weirling": a sensor with no
 *  verified in-path channel cannot drop anything, and saying otherwise is the reassuring lie. */
function renderSluiceReach(d) {
  const box = document.getElementById("sl-reach");
  if (!box) return;
  box.replaceChildren();
  if (d.gates_available === false) {
    box.appendChild(el("span", { class: "muted",
      text: "Reach unavailable — the fleet's gate state could not be read." }));
    return;
  }
  const reach = (d.gates || []).filter((g) => g.enforcement && !g.stale).map((g) => g.sensor);
  if (!reach.length) {
    box.appendChild(el("span", { class: "muted",
      text: "Packet rules can act on 0 sensors — no sensor has a verified in-path channel." }));
    return;
  }
  box.appendChild(el("span", { class: "muted",
    text: `Packet rules can act on ${reach.length} sensor${reach.length === 1 ? "" : "s"}: ` }));
  for (const sen of reach) {
    const chip = el("button", { class: "bubble filter", text: sen, attrs: { type: "button" } });
    chip.addEventListener("click", () => {
      if (typeof openWeirling === "function") openWeirling(sen);
    });
    box.appendChild(chip);
  }
}

/* ── Confirm + reason, then a read-back that proves the write landed ───────────────────────── */
let SL2_PENDING = null;

function sl2AskSetting(spec) {
  const w = sl2Writes();
  if (!w.enabled) {
    sl2SetReceipt(`Read-only — ${w.reason || "this account cannot change the gate."}`, true);
    return;
  }
  const node = document.getElementById("sl2-confirm");
  if (!node || typeof openModal !== "function") return;
  SL2_PENDING = spec;
  const set = (id, text) => { const e = document.getElementById(id); if (e) e.textContent = text; };
  set("sl2-confirm-title", spec.heading || "Change the gate?");
  set("sl2-confirm-what", spec.what || "");
  set("sl2-confirm-cost", spec.cost || "");
  set("sl2-confirm-note", "");
  const reason = document.getElementById("sl2-confirm-reason");
  if (reason) reason.value = "";
  const go = document.getElementById("sl2-confirm-go");
  if (go) { go.textContent = `Confirm: ${spec.verb || "apply"}`; go.disabled = false; }
  openModal(node);
  if (reason) setTimeout(() => reason.focus(), 30);
}

function sl2CancelSetting() {
  SL2_PENDING = null;
  const node = document.getElementById("sl2-confirm");
  if (node && typeof closeModal === "function") closeModal(node);
}

async function sl2ApplyPending() {
  const spec = SL2_PENDING;
  if (!spec) return;
  const reasonEl = document.getElementById("sl2-confirm-reason");
  const note = document.getElementById("sl2-confirm-note");
  const go = document.getElementById("sl2-confirm-go");
  const reason = reasonEl ? reasonEl.value.trim() : "";
  if (!reason) {
    if (note) note.textContent = "A reason is required: it is recorded with your name and the time.";
    if (reasonEl) reasonEl.focus();
    return;
  }
  const label = go ? go.textContent : "Confirm";
  if (go) { go.disabled = true; go.textContent = "Applying…"; }
  try {
    const out = await postJSON("/api/settings/apply", {
      changes: { [spec.key]: String(spec.value) }, confirmed: true, reason,
    });
    if (out && out.ok === false && !out.applied) {
      if (note) note.textContent = out.error || "the server refused the change";
      if (go) { go.disabled = false; go.textContent = label; }
      return;
    }
    const applied = out && out.applied && Object.prototype.hasOwnProperty.call(out.applied, spec.key)
      ? String(out.applied[spec.key]) : "";
    const node = document.getElementById("sl2-confirm");
    if (node && typeof closeModal === "function") closeModal(node);
    SL2_PENDING = null;
    await loadSluice();
    // THE READ-BACK IS THE PROOF. A 200 from the apply route is not the same statement as
    // "the store now holds this value"; both are checked and the receipt says which one failed.
    const readBack = sl2Setting(spec.key);
    const landed = String(readBack) === String(spec.value);
    const gate = (SL2_STATE.data && SL2_STATE.data.gate) || {};
    const measured = String(gate.state || "unknown");
    const at = new Date().toLocaleTimeString();
    sl2SetReceipt(
      `Applied ${spec.key}=${spec.value}`
      + (applied !== "" ? `; the store writes ${applied}` : "")
      + `; read back as ${readBack === "" ? "unknown" : readBack} at ${at}. `
      + (landed
        ? `The write landed. The gate's last measurement is "${measured}".`
        : "THE RE-READ DOES NOT MATCH — treat the change as unconfirmed."),
      !landed);
  } catch (err) {
    if (note) note.textContent = (err && err.message) || String(err);
    if (go) { go.disabled = false; go.textContent = label; }
  }
}

/* ── Rules ──────────────────────────────────────────────────────────────────────────────────── */
/** A link into the surface that owns the evidence behind this rule. */
function sl2RuleLinks(rule) {
  const links = [];
  if (rule.domain) {
    links.push({ href: `#v=blocked&bl.domain=${encodeURIComponent(rule.domain)}`,
                 text: "View blocks", label: `view blocks for ${rule.domain}` });
  } else {
    const addr = String(rule.src_cidr || rule.dst_cidr || "").split("/")[0].trim();
    if (addr) {
      links.push({ href: `#v=discover&dc.addr=${encodeURIComponent(addr)}`,
                   text: "View flows", label: `view flows for ${addr}` });
    }
  }
  return links;
}

/** A rule that can never match is a record, not a rule: no domain, address, port or protocol. */
function sl2HasPredicate(rule) {
  if (!rule) return false;
  const described = String(rule.describes || "").trim();
  if (described && described !== "(no predicate)") return true;
  return Boolean(String(rule.domain || "").trim()
    || String(rule.src_cidr || "").trim()
    || String(rule.dst_cidr || "").trim()
    || Number(rule.dst_port || 0) > 0
    || String(rule.protocol || "").trim());
}

/** One disclosure, one explanation: the empty rows stay findable without becoming the list. */
function renderSluiceOrphans(list) {
  const host = document.getElementById("sl2-orphans");
  if (!host) return;
  host.replaceChildren();
  if (!list.length) return;
  const details = el("details", { class: "sl2-orphans" });
  details.appendChild(el("summary", { class: "sl2-orphans-summary" }, [
    el("span", { class: "sl2-orphans-title",
      text: `Rules that match nothing (${list.length})` }),
  ]));
  details.appendChild(el("p", { class: "sl2-orphans-why",
    text: "These records have no predicate — no domain, address, port or protocol — so they can "
      + "never match traffic. They are kept for the audit trail; open one to inspect or revoke it." }));
  const rows = el("div", { class: "sl2-orphan-list" });
  for (const rule of list) {
    const state = sl2StateOf(rule);
    const btn = el("button", { class: "sl2-orphan-btn", attrs: { type: "button" } }, [
      el("span", { class: "sl2-orphan-id", text: rule.rule_id || "unknown rule" }),
      el("span", { class: "sl2-orphan-note", text: "no predicate — matches nothing" }),
    ]);
    btn.addEventListener("click", () => openRuleSheet(rule));
    const chip = sl2StateChip(state.kind);
    chip.textContent = `${(typeof SEVERITY_GLYPHS !== "undefined" && SEVERITY_GLYPHS[state.sev]) || ""} ${state.text}`.trim();
    chip.className = `bubble state sev-${state.sev}`;
    rows.appendChild(el("div", { class: "sl2-orphan" }, [btn, chip]));
  }
  details.appendChild(rows);
  host.appendChild(details);
}

function renderSluiceRules(d) {
  const rules = Array.isArray(d.rules) ? d.rules : [];
  const shown = rules.filter(sl2Visible);
  const live = rules.filter((r) => sl2Enforces(r) && String(r.mode || "block") === "block").length;
  const emptyTotal = rules.filter((r) => !sl2HasPredicate(r)).length;
  const count = document.getElementById("sl2-count");
  if (count) count.textContent = `${live} live · ${rules.length} total`
    + (emptyTotal ? ` · ${emptyTotal} empty` : "");
  const note = document.getElementById("sl2-rules-note");
  const hiddenRevoked = rules.filter((r) => r.revoked && !SL2_STATE.showRevoked).length;
  if (note) {
    note.textContent = hiddenRevoked
      ? `${sl2Count(hiddenRevoked, "revoked rule")} hidden` : "";
  }

  const tbody = document.querySelector("#sl2-rules tbody");
  const empty = document.getElementById("sl2-empty");
  if (!tbody || !empty) return;
  tbody.replaceChildren();
  const real = shown.filter(sl2HasPredicate);
  const empties = shown.filter((r) => !sl2HasPredicate(r));
  if (!real.length) {
    let state = "none";
    let message;
    let filters = [];
    if (!d.available) {
      state = "failed";
      message = d.reason || "The rule store could not be read.";
    } else if (!rules.length) {
      message = "No rule has been filed. The gates have nothing to enforce; "
        + "New rule files the first one.";
    } else if (SL2_STATE.filter !== "all") {
      const other = rules.filter((r) => (SL2_STATE.filter === "domain" ? !r.domain : r.domain)).length;
      state = "filtered";
      filters = [`gate = ${SL2_STATE.filter}`];
      message = `No ${SL2_STATE.filter} rule exists yet. `
        + `${sl2Count(other, "rule")} in the other gate ${other === 1 ? "is" : "are"} still listed.`;
    } else if (empties.length) {
      state = "filtered";
      message = "No rule with a predicate matches this view. The rules that can never "
        + "match are listed below.";
    } else {
      message = "No rule matches this view.";
    }
    if (hiddenRevoked && d.available) {
      message += ` ${sl2Count(hiddenRevoked, "revoked rule")} hidden; tick "show revoked" to read them.`;
    }
    empty.replaceChildren(emptyState({ state, message, filters }));
    empty.classList.remove("hidden");
    renderSluiceOrphans(empties);
    return;
  }
  empty.classList.add("hidden");
  for (const rule of real) {
    const state = sl2StateOf(rule);
    const sentence = el("button", {
      class: "sl2-rule-btn", attrs: { type: "button" },
      text: rule.describes || (rule.domain ? `block ${rule.domain}` : `rule ${rule.rule_id || "unknown"}`),
    });
    sentence.addEventListener("click", () => openRuleSheet(rule));
    const evidence = el("div", { class: "sl2-rule-ev", text: sl2RuleEvidence(rule, d) });
    const links = el("div", { class: "sl2-rule-links" });
    for (const link of sl2RuleLinks(rule)) {
      const a = el("a", { class: "link", text: link.text,
        attrs: { href: link.href, "aria-label": link.label || link.text } });
      // THE ROW OPENS THE RULE; THE LINK LEAVES THE TAB. Without this the click did both.
      a.addEventListener("click", (e) => e.stopPropagation());
      links.appendChild(a);
    }
    const stateChip = sl2StateChip(state.kind);
    stateChip.textContent = `${(typeof SEVERITY_GLYPHS !== "undefined" && SEVERITY_GLYPHS[state.sev]) || ""} ${state.text}`.trim();
    stateChip.className = `bubble state sev-${state.sev}`;
    const tr = el("tr", {
      class: "clickable sl2-rule-row",
      attrs: { "data-rule-id": rule.rule_id },
    }, [
      el("td", {}, [sentence, evidence, links.children.length ? links : null].filter(Boolean)),
      el("td", {}, [el("div", { class: "sl2-rule-state" }, [
        el("span", { class: "sl2-rule-gate", text: sl2GateOf(rule) }),
        stateChip,
      ])]),
    ]);
    tr.addEventListener("click", (event) => {
      if (event.target !== sentence && !event.target.closest(".sl2-rule-links")) openRuleSheet(rule);
    });
    tbody.appendChild(tr);
  }
  renderSluiceOrphans(empties);
  sluiceApplyFlash();
}

/** US-3: an audit receipt or palette result lands on the rule row. */
let SL2_FLASH_PENDING = "";
let SL2_FLASH_TIMER = null;
function sluiceHighlightRule(ruleId) {
  SL2_FLASH_PENDING = String(ruleId);
  sluiceApplyFlash();
  // A RELOAD CAN LAND AFTER THIS CALL and replace the rows, so the id has to outlive the render
  // that will consume it. It used to be dropped after 2.5s whether or not a row had been
  // painted, so a fix clicked from the audit could visibly do nothing: the highlight landed on
  // rows that a load already in flight then replaced.
  if (SL2_FLASH_TIMER) clearTimeout(SL2_FLASH_TIMER);
  SL2_FLASH_TIMER = setTimeout(() => { SL2_FLASH_PENDING = ""; }, 8000);
}

function sluiceApplyFlash() {
  if (!SL2_FLASH_PENDING) return;
  const all = [...document.querySelectorAll("#sl2-rules tbody tr.sl2-rule-row")];
  const row = all.find((tr) => tr.getAttribute("data-rule-id") === SL2_FLASH_PENDING);
  if (!row) return;
  row.classList.add("flash-hit");
  try { row.scrollIntoView({ block: "center" }); } catch (_e) { /* optional */ }
  // THE PENDING ID SURVIVES THE PAINT. Clearing it here was the defect: the class went onto one
  // set of rows, and the reload already in flight replaced them with no id left for the new
  // rows to inherit.
  if (SL2_FLASH_TIMER) clearTimeout(SL2_FLASH_TIMER);
  SL2_FLASH_TIMER = setTimeout(() => {
    SL2_FLASH_PENDING = "";
    row.classList.remove("flash-hit");
  }, 1800);
}

/* ── Rule sheet ─────────────────────────────────────────────────────────────────────────────── */
function sl2Sheet() { return document.getElementById("sl-rule-sheet"); }

function sl2CloseSheet() {
  const sheet = sl2Sheet();
  if (!sheet) return;
  closeSheet(sheet);
  SL2_STATE.current = null;
}

function sl2OpenSheet(initialFocus) {
  const sheet = sl2Sheet();
  if (!sheet) return;
  openSheet(sheet, { scrimId: "sl-rule-scrim", initialFocus });
}

function sl2SyncKind() {
  const kind = document.getElementById("sl-target-type");
  const domainFields = document.getElementById("sl2-domain-fields");
  const trafficFields = document.getElementById("sl2-traffic-fields");
  const hint = document.getElementById("sl-gate-hint");
  if (!kind) return;
  const isDomain = kind.value === "domain";
  if (domainFields) domainFields.classList.toggle("hidden", !isDomain);
  if (trafficFields) trafficFields.classList.toggle("hidden", isDomain);
  if (hint) {
    hint.textContent = isDomain
      ? "Domain rules are answered by the Domain Gate (DNS answer); they do not write packet rules."
      : "Address rules are dropped by the Traffic Gate (packet drop). A rule with no address is refused.";
  }
  if (isDomain) {
    for (const id of ["sl2-src", "sl2-dst", "sl2-port"]) {
      const field = document.getElementById(id);
      if (field) field.value = "";
    }
  } else {
    const domain = document.getElementById("sl2-domain");
    if (domain) domain.value = "";
  }
}

let SL_CREATE_ARM_TIMER = null;
// One per two-step action, so arming one control cannot disarm another (WV1-12, WV1-14).
let SL_PARK_ARM_TIMER = null;
let SL_BL_ARM_TIMER = null;
function slCreateDisarm() {
  if (SL_CREATE_ARM_TIMER) { clearTimeout(SL_CREATE_ARM_TIMER); SL_CREATE_ARM_TIMER = null; }
  const btn = document.getElementById("sl2-create-submit");
  if (btn) { delete btn.dataset.confirm; btn.textContent = "Create rule"; }
}

function sl2OpenCreate(domain, prefill) {
  SL2_STATE.current = null;
  const sheet = sl2Sheet();
  if (!sheet) return;
  const pre = prefill && typeof prefill === "object" ? prefill : {};
  document.getElementById("sl2-create").classList.remove("hidden");
  document.getElementById("sl2-detail").classList.add("hidden");
  document.getElementById("sl-rule-title").textContent = "New rule";
  document.getElementById("sl2-sheet-id").textContent = "";
  const kind = document.getElementById("sl-target-type");
  const hasAddress = Boolean(pre.src_cidr || pre.dst_cidr);
  if (kind) kind.value = (domain || pre.domain || !hasAddress) ? "domain" : "traffic";
  sl2SyncKind();
  const set = (id, value) => {
    const field = document.getElementById(id);
    if (field && value !== undefined && value !== null) field.value = String(value);
  };
  set("sl2-domain", domain || pre.domain || "");
  set("sl2-src", pre.src_cidr || "");
  set("sl2-dst", pre.dst_cidr || "");
  set("sl2-mode", pre.mode || "block");
  set("sl2-proto", pre.protocol || "");
  set("sl2-port", pre.dst_port || "");
  set("sl2-direction", pre.direction || "forward");
  set("sl2-ttl", pre.ttl_minutes === undefined ? 60 : pre.ttl_minutes);
  set("sl2-reason", pre.reason || "");
  const note = document.getElementById("sl2-create-note");
  if (note) note.textContent = "";
  const btn = document.getElementById("sl2-create-submit");
  if (btn) { delete btn.dataset.confirm; btn.textContent = "Create rule";
    btn.disabled = !sl2Writes().enabled; }
  sl2OpenSheet();
  const focus = document.getElementById(kind && kind.value === "traffic" ? "sl2-src" : "sl2-domain");
  if (focus) focus.focus();
}

function sl2Facts(rule) {
  const host = document.getElementById("sl2-facts");
  if (!host) return;
  const windowText = sl2Window((SL2_STATE.data && SL2_STATE.data.hits_hours) || 24);
  const facts = [
    ["Rule", rule.describes || rule.rule_id || "—"],
    ["Gate", sl2GateOf(rule)],
    ["State", sl2StateOf(rule).text],
    ["Mode", rule.mode === "alert" ? "alert — records, blocks nothing" : "block"],
    ["Origin", rule.origin || "manual"],
    ["Expires", sluiceDuration(rule.expires_in_s)],
    ["Firing evidence", sl2RuleEvidence(rule, SL2_STATE.data || {})],
    ["Reason", rule.reason || "no reason was recorded"],
    ["Rule id", rule.rule_id || "—"],
  ];
  host.replaceChildren();
  const dl = el("dl", { class: "sl2-facts" });
  for (const [k, v] of facts) {
    dl.appendChild(el("dt", { text: k }));
    dl.appendChild(el("dd", { text: String(v) }));
  }
  host.appendChild(dl);
  // ONE DOOR FROM THE SHEET INTO THE RECORDED EVIDENCE. The row carried a link that repeated
  // the address already in its sentence; this is where that door lives now.
  for (const link of sl2RuleLinks(rule)) {
    const a = el("a", { class: "link sl2-sheet-link", text: `Open ${link.text.toLowerCase()}`,
      attrs: { href: link.href, "aria-label": link.label || link.text } });
    host.appendChild(a);
  }
  const note = el("p", { class: "muted",
    text: `Matches are counted in ${windowText}, the same window as the Blocks ledger.` });
  host.appendChild(note);
}

function sl2OpenDetail(rule) {
  SL2_STATE.current = rule;
  document.getElementById("sl2-create").classList.add("hidden");
  document.getElementById("sl2-detail").classList.remove("hidden");
  document.getElementById("sl-rule-title").textContent = "Rule";
  document.getElementById("sl2-sheet-id").textContent = rule.rule_id || "";
  sl2Facts(rule);
  const mode = document.getElementById("sl2-detail-mode");
  if (mode) mode.value = rule.mode === "block" ? "block" : "alert";
  const park = document.getElementById("sl2-park");
  if (park) {
    park.textContent = rule.disabled ? "Restore rule" : "Park rule";
    park.disabled = Boolean(rule.revoked || rule.not_live);
    // A pending confirm belongs to the sheet it was armed in. Without this, opening another rule
    // shows "Park rule" while the button is still armed, so the next click would post (WV1-12).
    delete park.dataset.confirm;
    if (SL_PARK_ARM_TIMER) { clearTimeout(SL_PARK_ARM_TIMER); SL_PARK_ARM_TIMER = null; }
  }
  const note = document.getElementById("sl2-detail-note");
  if (note) {
    // ── A FAILED LOOKUP MUST NOT BE SHOWN AS A REVOCATION (WV1-08) ──────────────────────────
    //
    // `blocked.js:blOpenRuleById` opens this sheet for a rule id it could not find in the lists
    // the page holds, and it used to set `revoked: true` on that fabricated record. So a transient
    // read failure, or a rule simply absent from a capped list, told the operator "This rule is
    // revoked ... it cannot be edited" -- i.e. that enforcement had ended, when the rule may have
    // been live and blocking.
    //
    // The failed state is checked FIRST, because it is the only one of the three that is a
    // statement about our knowledge rather than about the rule.
    note.textContent = rule.lookup_failed
      ? "Cannot confirm this rule's state: the rule list could not be read, or this rule is not "
        + "in the list the page holds. Nothing is being claimed about whether it is live. This "
        + "sheet is read-only because there is no record to edit."
      : (rule.revoked
        ? "This rule is revoked. Its record is kept for audit; it cannot be edited."
        : (rule.not_live ? "This rule is not in the live store; it is shown as a record only." : ""));
  }
  // A VIEWER'S SHEET IS READ-ONLY TOO. The server refuses the write either way, but a control
  // that looks live and then fails teaches the operator nothing.
  const mayWrite = sl2Writes().enabled;
  for (const id of ["sl2-mode-save", "sl-rule-delete", "sl-rule-delete-reason", "sl2-detail-mode"]) {
    const field = document.getElementById(id);
    if (field) field.disabled = !mayWrite || Boolean(rule.revoked || rule.not_live);
  }
  const delReason = document.getElementById("sl-rule-delete-reason");
  if (delReason) delReason.value = "";
  const del = document.getElementById("sl-rule-delete");
  if (del) { delete del.dataset.confirm; del.textContent = "Delete rule"; }
  sl2OpenSheet();
}

function openRuleSheet(rule) {
  if (typeof rule === "string") return sl2OpenCreate(rule);
  if (!rule || !rule.rule_id) return sl2OpenCreate(rule && rule.domain);
  return sl2OpenDetail(rule);
}

function openRuleComposer(domain, prefill) {
  // THE RULE SHEET LIVES INSIDE THE SLUICE VIEW. Opening it from DNS or Alerts while that
  // section was `display:none` produced a 0x0 sheet: the button looked dead. Switch first.
  showView("sluice");
  sl2OpenCreate(domain || "", prefill || {});
}

async function sl2Create() {
  const btn = document.getElementById("sl2-create-submit");
  const note = document.getElementById("sl2-create-note");
  const kind = document.getElementById("sl-target-type").value;
  const mode = document.getElementById("sl2-mode").value;
  const body = {
    mode,
    ttl_minutes: Number(document.getElementById("sl2-ttl").value || 0),
    reason: document.getElementById("sl2-reason").value.trim(),
    direction: "forward", protocol: "", dst_port: 0, src_cidr: "", dst_cidr: "", domain: "",
  };
  if (kind === "domain") {
    body.domain = document.getElementById("sl2-domain").value.trim();
    if (!body.domain) { note.textContent = "A domain is required."; return; }
  } else {
    body.src_cidr = document.getElementById("sl2-src").value.trim();
    body.dst_cidr = document.getElementById("sl2-dst").value.trim();
    body.protocol = document.getElementById("sl2-proto").value;
    body.dst_port = Number(document.getElementById("sl2-port").value || 0);
    body.direction = document.getElementById("sl2-direction").value;
    if (!body.src_cidr && !body.dst_cidr) {
      note.textContent = "An address or CIDR is required for a traffic rule.";
      return;
    }
  }
  if (mode === "block" && !btn.dataset.confirm) {
    btn.dataset.confirm = "1";
    btn.textContent = "Confirm: create block rule";
    note.textContent = "A block rule changes what the gate drops. Click again to create it.";
    if (SL_CREATE_ARM_TIMER) clearTimeout(SL_CREATE_ARM_TIMER);
    SL_CREATE_ARM_TIMER = setTimeout(slCreateDisarm, 6000);
    return;
  }
  delete btn.dataset.confirm;
  btn.disabled = true;
  btn.textContent = "Creating…";
  try {
    const out = await postJSON("/api/sluice/block", body);
    if (out && out.ok === false) {
      note.textContent = out.error || "the gate refused the rule";
      return;
    }
    sl2CloseSheet();
    await loadSluice();
  } catch (err) {
    note.textContent = (err && err.message) || String(err);
  } finally {
    btn.disabled = false;
    btn.textContent = "Create rule";
  }
}

async function sl2SaveMode() {
  const rule = SL2_STATE.current;
  if (!rule) return;
  const btn = document.getElementById("sl2-mode-save");
  const note = document.getElementById("sl2-detail-note");
  const mode = document.getElementById("sl2-detail-mode").value;
  if (mode === "block" && !btn.dataset.confirm) {
    btn.dataset.confirm = "1";
    btn.textContent = "Confirm: move to block";
    note.textContent = "Moving to block changes what the kernel drops. Click again to confirm.";
    return;
  }
  delete btn.dataset.confirm;
  btn.disabled = true;
  try {
    const out = await postJSON("/api/sluice/rule/mode", { rule_id: rule.rule_id, mode, confirmed: true });
    if (out && out.ok === false) note.textContent = out.error || "the mode was not changed";
    else { sl2CloseSheet(); await loadSluice(); }
  } catch (err) {
    note.textContent = (err && err.message) || String(err);
  } finally {
    btn.disabled = false;
    btn.textContent = "Save mode";
  }
}

async function sl2Park() {
  const rule = SL2_STATE.current;
  if (!rule) return;
  const btn = document.getElementById("sl2-park");
  const note = document.getElementById("sl2-detail-note");
  // ── TWO STEP (WV1-12) ─────────────────────────────────────────────────────────────────────
  //
  // One click here flipped a rule's enforcement. Parking a live block rule RE-OPENS the path it
  // was blocking, and restoring re-arms it, so this was the most consequential single click in the
  // sheet and the only destructive one without a confirm -- `sl2Create` (block mode) and
  // `sl2Delete` both had one. Worse, the button sits next to Delete and reads like a status chip.
  const parking = !rule.disabled;
  if (!btn.dataset.confirm) {
    btn.dataset.confirm = "1";
    btn.textContent = parking ? "Confirm: park rule" : "Confirm: restore rule";
    note.textContent = parking
      ? "Parking stops this rule's enforcement: whatever it blocks becomes reachable again until "
        + "you restore it. The rule is kept and still records. Click again to confirm."
      : "Restoring re-arms this rule and whatever it blocks is blocked again. Click again to "
        + "confirm.";
    if (SL_PARK_ARM_TIMER) clearTimeout(SL_PARK_ARM_TIMER);
    SL_PARK_ARM_TIMER = setTimeout(() => {
      if (SL_PARK_ARM_TIMER === null) return;
      SL_PARK_ARM_TIMER = null;
      delete btn.dataset.confirm;
      btn.textContent = parking ? "Park rule" : "Restore rule";
    }, 6000);
    return;
  }
  delete btn.dataset.confirm;
  if (SL_PARK_ARM_TIMER) { clearTimeout(SL_PARK_ARM_TIMER); SL_PARK_ARM_TIMER = null; }
  btn.disabled = true;
  try {
    const out = await postJSON("/api/sluice/rule/disabled", { rule_id: rule.rule_id, disabled: !rule.disabled });
    if (out && out.ok === false) note.textContent = out.error || "the rule was not changed";
    else { sl2CloseSheet(); await loadSluice(); }
  } catch (err) {
    note.textContent = (err && err.message) || String(err);
  } finally {
    btn.disabled = false;
  }
}

async function slRuleRevoke(rule, reason) {
  if (!rule) return;
  const out = await postJSON("/api/sluice/revoke", { rule_id: rule.rule_id, reason: reason || "" });
  if (out && out.ok) await loadSluice();
  return out;
}

async function sl2Delete() {
  const rule = SL2_STATE.current;
  if (!rule) return;
  const btn = document.getElementById("sl-rule-delete");
  const note = document.getElementById("sl2-detail-note");
  const reason = document.getElementById("sl-rule-delete-reason").value.trim();
  if (!reason) { note.textContent = "A reason is required to delete a rule."; return; }
  if (!btn.dataset.confirm) {
    btn.dataset.confirm = "1";
    btn.textContent = "Confirm: delete rule";
    note.textContent = "Deleting revokes the rule but keeps its audit record. Click again to confirm.";
    return;
  }
  delete btn.dataset.confirm;
  btn.disabled = true;
  try {
    const out = await postJSON("/api/sluice/revoke", { rule_id: rule.rule_id, reason });
    if (out && out.ok === false) note.textContent = out.error || "the rule was not revoked";
    else { sl2CloseSheet(); await loadSluice(); }
  } catch (err) {
    note.textContent = (err && err.message) || String(err);
  } finally {
    btn.disabled = false;
    btn.textContent = "Delete rule";
  }
}

/* ── Blocklists live in Settings. Kept here because Settings and the DNS view load
      this file; the old Sluice tab no longer renders them. ─────────────────────────────────── */
function renderBlocklists(d) {
  const body = document.getElementById("sl-bl-rows");
  if (!body) return;
  body.replaceChildren();
  const sources = d.blocklists || [];
  if (!sources.length) {
    const tr = el("tr", {});
    tr.appendChild(el("td", { class: "muted", attrs: { colspan: "5" },
      text: "No sources yet — Sync now seeds the defaults (HaGeZi LIGHT on, PRO listed and off)." }));
    body.appendChild(tr);
  }
  for (const s of sources) {
    const state = s.last_error
      ? el("span", { class: "bubble state bad", text: "last sync failed" })
      : (s.fetched_at ? el("span", { class: "bubble state ok", text: "ok" }) : el("span", { class: "bubble state muted", text: "never fetched" }));
    // ── THE ROW IS INERT; A BUTTON CARRIES THE TOGGLE (WV1-14) ──────────────────────────────
    //
    // The whole <tr> used to be the toggle, and one of its cells is `s.last_error.slice(0, 90)`.
    // Clicking that error text to READ it, or to select it for a bug report, silently disabled a
    // DNS blocklist and changed enforcement. The hover title was the only warning, which does not
    // exist on touch and was not announced for keyboard.
    //
    // Extending `tr.clickable` keyboard activation to these rows made it worse rather than better:
    // tabbing through this pane and pressing Enter would toggle a list. A row whose whole surface
    // performs a state change cannot be made safe by adding a key handler; the action has to move
    // into a control that says what it does.
    const toggle = el("button", { class: "quiet", attrs: { type: "button" },
      text: s.enabled ? "Turn off" : "Turn on" });
    toggle.addEventListener("click", () => slToggleSource(s, toggle).catch(showError));
    const tr = el("tr", {}, [
      el("td", {}, [el("span", { class: "bubble state " + (s.enabled ? "ok" : "muted"), text: s.enabled ? "on" : "off" }),
        el("span", { text: " " + s.name })]),
      el("td", {}, [state, el("span", { text: " " }), toggle]),
      el("td", { class: "mono", text: String(s.domain_count || 0) }),
      el("td", { class: "muted", text: s.fetched_at ? fmtTime(new Date(s.fetched_at)) : "—" }),
      el("td", { class: "muted", text: s.last_error ? s.last_error.slice(0, 90) : "—" }),
    ]);
    body.appendChild(tr);
  }
}

async function loadBlocklistPane() {
  if (!document.getElementById("sl-bl-rows")) return;
  let d;
  try {
    d = await getJSON("/api/blocklists");
  } catch (err) {
    const note = document.getElementById("sl-bl-note");
    if (note) note.textContent = "the blocklist read failed: " + ((err && err.message) || err);
    return;
  }
  const note = document.getElementById("sl-bl-note");
  if (d && d.available === false) {
    if (note) note.textContent = "the blocklists could not be read: " + (d.reason || "no reason given");
    return;
  }
  renderBlocklists({ blocklists: (d && d.sources) || [] });
}

async function slToggleSource(s, btn) {
  const note = document.getElementById("sl-bl-note");
  const want = !s.enabled;
  // TWO STEP (WV1-14). Enabling or disabling a source changes which names get answered from the
  // block list, so it names the effect before it happens.
  if (btn && !btn.dataset.confirm) {
    btn.dataset.confirm = "1";
    const label = btn.textContent;
    btn.textContent = want ? "Confirm: on" : "Confirm: off";
    if (note) {
      note.textContent = want
        ? `Turning ${s.name} on adds its names to the watch set. Click again to confirm.`
        : `Turning ${s.name} off removes its names from the watch set, so queries for them stop `
          + "being answered from this list. Click again to confirm.";
    }
    if (SL_BL_ARM_TIMER) clearTimeout(SL_BL_ARM_TIMER);
    SL_BL_ARM_TIMER = setTimeout(() => {
      SL_BL_ARM_TIMER = null;
      delete btn.dataset.confirm;
      btn.textContent = label;
    }, 6000);
    return;
  }
  if (btn) {
    delete btn.dataset.confirm;
    if (SL_BL_ARM_TIMER) { clearTimeout(SL_BL_ARM_TIMER); SL_BL_ARM_TIMER = null; }
  }
  if (note) note.textContent = `${want ? "enabling" : "disabling"} ${s.name}…`;
  try {
    const out = await postJSON("/api/blocklists/enable", { source_id: s.source_id, enabled: want });
    if (note) note.textContent = (out && (out.note || out.error)) || "done";
  } catch (err) {
    if (note) note.textContent = String((err && err.message) || err);
  }
  loadBlocklistPane().catch(showError);
}

/* ── Wiring ─────────────────────────────────────────────────────────────────────────────────── */
document.addEventListener("DOMContentLoaded", () => {
  const kind = document.getElementById("sl-target-type");
  if (kind) kind.addEventListener("change", sl2SyncKind);
  for (const field of document.querySelectorAll("#sl2-create input, #sl2-create select")) {
    field.addEventListener("input", slCreateDisarm);
    field.addEventListener("change", slCreateDisarm);
  }
  const newRule = document.getElementById("sl2-new");
  if (newRule) newRule.addEventListener("click", () => sl2OpenCreate(""));
  const sheet = sl2Sheet();
  if (sheet) wireSheet(sheet, { scrimId: "sl-rule-scrim" });
  const dnBlock = document.getElementById("dn-block");
  if (dnBlock) dnBlock.addEventListener("click", () => {
    const field = document.getElementById("dn-domain");
    sl2OpenCreate(String((field && field.value) || "").trim());
  });
  // A DEEP LINK TO #v=sluice SKIPS THE BOOT REFRESH (refreshAll({skipView:true})), because
  // applyURLState already called showView. If that call raced this file's definition, the view
  // would sit at "loading" forever. Load it once here when it is the active view.
  // The app's own boot is async (it waits for /api/session), so the 0ms attempt can run before
  // applyURLState makes the view active. Retry once after boot settles; the active check makes
  // this a no-op on every other landing view.
  const bootLoad = () => {
    const active = document.getElementById("view-sluice");
    if (active && active.classList.contains("active")) loadSluice().catch(() => {});
  };
  setTimeout(bootLoad, 0);
  setTimeout(bootLoad, 600);
  // The definitive signal is the view becoming active, however late the async boot gets there.
  const view = document.getElementById("view-sluice");
  if (view && window.MutationObserver) {
    const observer = new MutationObserver(() => {
      if (view.classList.contains("active")) { bootLoad(); observer.disconnect(); }
    });
    observer.observe(view, { attributes: true, attributeFilter: ["class"] });
    if (view.classList.contains("active")) bootLoad();
  }
  const submit = document.getElementById("sl2-create-submit");
  if (submit) submit.addEventListener("click", () => sl2Create().catch(showError));
  const modeSave = document.getElementById("sl2-mode-save");
  if (modeSave) modeSave.addEventListener("click", () => sl2SaveMode().catch(showError));
  const park = document.getElementById("sl2-park");
  if (park) park.addEventListener("click", () => sl2Park().catch(showError));
  const del = document.getElementById("sl-rule-delete");
  if (del) del.addEventListener("click", () => sl2Delete().catch(showError));
  const filters = document.getElementById("sl2-filters");
  if (filters) {
    for (const button of filters.querySelectorAll("[data-gate]")) {
      button.addEventListener("click", () => sl2SetGate(button.getAttribute("data-gate") || "all"));
    }
  }
  const showRevoked = document.getElementById("sl2-show-revoked");
  if (showRevoked) showRevoked.addEventListener("change", () => {
    SL2_STATE.showRevoked = Boolean(showRevoked.checked);
    renderSluiceRules(SL2_STATE.data || { available: false, reason: "not loaded" });
  });
  // The one confirm surface for arming, disarming and pausing. Every path into it carries the
  // consequence and a required reason; the write then re-reads and reports what landed.
  const cancel = document.getElementById("sl2-confirm-cancel");
  if (cancel) cancel.addEventListener("click", sl2CancelSetting);
  const go = document.getElementById("sl2-confirm-go");
  if (go) go.addEventListener("click", () => sl2ApplyPending().catch(showError));
  const why = document.getElementById("sl2-confirm-reason");
  if (why) why.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); sl2ApplyPending().catch(showError); }
  });
});

// Settings' blocklist controls still call these functions through app.js; the card lives there.
document.addEventListener("DOMContentLoaded", () => {
  const sync = document.getElementById("sl-bl-sync");
  if (sync) sync.addEventListener("click", async () => {
    const note = document.getElementById("sl-bl-note");
    if (note) note.textContent = "syncing… (fetches the lists; a few seconds)";
    try {
      const r = await postJSON("/api/blocklists/sync", {});
      const ok = (r.results || []).filter((x) => x.ok).length;
      if (note) note.textContent = `synced ${ok} source(s)`;
    } catch (err) {
      if (note) note.textContent = `sync failed: ${(err && err.message) || err}`;
    }
    // THE TABLE HAS ITS OWN READ. loadSluice() refreshes settings and rules, not
    // /api/blocklists, so the pane still said "never fetched / 0" after a successful sync.
    loadBlocklistPane().catch(showError);
    loadSluice().catch(showError);
  });
  const addSource = document.getElementById("sl-bl-source-add");
  if (addSource) addSource.addEventListener("click", async () => {
    const note = document.getElementById("sl-bl-note");
    const url = (document.getElementById("sl-bl-url") || {}).value || "";
    const name = (document.getElementById("sl-bl-name") || {}).value || "";
    const format = (document.getElementById("sl-bl-format") || {}).value || "domains";
    if (!url.trim()) { if (note) note.textContent = "give the list URL first"; return; }
    try {
      const out = await postJSON("/api/blocklists/source", { url: url.trim(), name: name.trim(), format });
      if (note) note.textContent = (out && out.note) || "added";
      const field = document.getElementById("sl-bl-url"); if (field) field.value = "";
      const nfield = document.getElementById("sl-bl-name"); if (nfield) nfield.value = "";
    } catch (err) {
      if (note) note.textContent = String((err && err.message) || err);
    }
    loadBlocklistPane().catch(showError);
  });
  const add = document.getElementById("sl-bl-add");
  if (add) add.addEventListener("click", async () => {
    const note = document.getElementById("sl-bl-note");
    const field = document.getElementById("sl-bl-custom");
    const domain = field ? field.value.trim() : "";
    if (!domain) { if (note) note.textContent = "give a domain first"; return; }
    try {
      await postJSON("/api/blocklists/custom", { action: "add", domain });
      if (field) field.value = "";
      if (note) note.textContent = `added ${domain}`;
    } catch (err) {
      if (note) note.textContent = (err && err.message) || String(err);
    }
    loadSluice().catch(showError);
  });
});

// Compatibility with the rest of the console: these names were part of the old file's surface.
function wireSluice() {}
function loadBlockingControls() { return loadSluice(); }
function closeRuleSheet() { sl2CloseSheet(); }
