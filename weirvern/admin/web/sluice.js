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

function sl2Stat(label, value) {
  return el("div", { class: "stat" }, [
    el("div", { class: "k", text: label }),
    el("div", { class: "v", text: String(value === null || value === undefined || value === "" ? "—" : value) }),
  ]);
}

function sl2GateOf(rule) {
  return rule && rule.domain ? "Domain" : "Traffic";
}

function sl2StateOf(rule) {
  if (!rule) return { text: "unknown", cls: "muted" };
  if (rule.revoked) return { text: "revoked", cls: "muted" };
  if (rule.disabled) return { text: "parked", cls: "warn" };
  if (rule.expires_in_s !== null && rule.expires_in_s !== undefined && rule.expires_in_s < 0) {
    return { text: "expired", cls: "muted" };
  }
  if (rule.live) return { text: "live", cls: "ok" };
  return { text: "not live", cls: "muted" };
}

function sl2Visible(rule) {
  if (!rule) return false;
  if (rule.revoked && !SL2_STATE.showRevoked) return false;
  if (SL2_STATE.filter === "domain" && !rule.domain) return false;
  if (SL2_STATE.filter === "traffic" && rule.domain) return false;
  return true;
}

function sl2Chip(text, cls) {
  return el("span", { class: `chip ${cls || "muted"}`, text });
}

function sluiceStateChip(state, stale) {
  const labels = { armed: "armed", disarmed: "open · no packet rules", degraded: "degraded", off: "off" };
  const cls = state === "armed" ? "ok" : (state === "degraded" ? "bad" : "muted");
  return sl2Chip(`${labels[state] || state || "unknown"}${stale ? " · stale" : ""}`, cls);
}

async function loadSluice() {
  if (typeof scheduleURLSync === "function") scheduleURLSync();
  let d;
  try {
    const slHours = typeof trHours === "function" ? trHours() : 24;
    d = await getJSON(`/api/sluice?hours=${slHours}`);
  } catch (err) {
    showDataError(`the gate query failed: ${(err && err.message) || err}`);
    return;
  }
  SL2_STATE.data = d;
  try {
    SL2_STATE.settings = await getJSON("/api/settings");
  } catch (_err) {
    SL2_STATE.settings = null;
  }
  if (!d.available) showDataError(d.reason || "the gate state is unavailable");
  renderSluiceGates(d);
  renderSluiceRules(d);
}

/* ── Gate state ─────────────────────────────────────────────────────────────────────────────── */
function renderSluiceGates(d) {
  const gate = d.gate || {};
  const gateOn = sl2On("SLUICE_ENABLED");
  const domOn = sl2On("SLUICE_BLOCK_DOMAINS");
  const live = Number(gate.rules_active || 0) || 0;
  const total = Number(gate.rules_total || 0) || 0;
  const state = String(gate.state || "").toLowerCase();
  const stale = Boolean(gate.stale);
  const degraded = state === "degraded" || stale;
  const openByChoice = state === "disarmed";

  // Domain Gate. Blocklist switches live in Settings; this card states what they add up to.
  const lists = (d.blocklists || []).filter((s) => s && s.enabled);
  const domains = lists.reduce((n, s) => n + (Number(s.domain_count) || 0), 0);
  const domChip = document.getElementById("sl2-dom-chip");
  if (domChip) {
    domChip.className = `chip ${domOn ? "ok" : "muted"}`;
    domChip.textContent = domOn ? "on" : "off";
  }
  const domLine = document.getElementById("sl2-dom-line");
  if (domLine) {
    domLine.textContent = domOn
      ? "Names on an enabled blocklist and block-mode domain rules are answered with a block answer in DNS. The traffic gate is separate."
      : "Domain blocking is off: domain rules record and alert, but DNS answers are not blocked. The traffic gate is separate.";
  }
  const domStats = document.getElementById("sl2-dom-stats");
  if (domStats) {
    const hitHours = Number(d.hits_hours || 24);
    const hits = Array.isArray(d.hits) ? d.hits.length : 0;
    domStats.replaceChildren(
      sl2Stat("enabled lists", lists.length),
      sl2Stat("domains covered", domains ? domains.toLocaleString() : "0"),
      sl2Stat(`DNS hits in ${hitHours}h`, hits),
    );
  }
  const domBtn = document.getElementById("sl2-dom-toggle");
  if (domBtn) {
    domBtn.textContent = domOn ? "Disable domain blocking" : "Enable domain blocking";
    domBtn.onclick = () => applySluiceSetting("SLUICE_BLOCK_DOMAINS", domOn ? "0" : "1", domBtn,
      document.getElementById("sl2-dom-line"));
  }

  // Traffic Gate.
  const trafChip = document.getElementById("sl2-traf-chip");
  if (trafChip) {
    let text = gateOn ? (live > 0 ? "armed" : "armed · no rules") : "off";
    if (degraded && !openByChoice) text = "degraded";
    trafChip.className = `chip ${degraded && !openByChoice ? "bad" : (gateOn && live ? "ok" : "muted")}`;
    trafChip.textContent = text;
  }
  const trafLine = document.getElementById("sl2-traf-line");
  if (trafLine) {
    const backend = String(gate.backend || "").toLowerCase();
    const why = String(gate.warning || gate.detail || "").trim();
    if (!gateOn) {
      trafLine.textContent = "The packet gate is off. Rules still record hits, but no packet is dropped.";
    } else if (live > 0) {
      trafLine.textContent = `${live} packet rule${live === 1 ? "" : "s"} installed on ${gate.iface || "this weirling"}.`;
    } else {
      trafLine.textContent = "The gate is armed, but no live packet rules exist; nothing is being dropped.";
    }
    if (degraded && !openByChoice && why) trafLine.textContent = why;
    if (backend && backend !== "none" && gateOn) trafLine.textContent += ` Enforcement backend: ${backend}.`;
    const warning = document.getElementById("sl-gate-warning");
    if (warning) {
      warning.textContent = degraded && !openByChoice ? why : "";
      warning.classList.toggle("hidden", !(degraded && !openByChoice && why));
    }
  }
  const trafStats = document.getElementById("sl2-traf-stats");
  if (trafStats) {
    trafStats.replaceChildren(
      sl2Stat("live packet rules", live),
      sl2Stat("rules in store", total),
      sl2Stat("packets blocked", Number(gate.packets_blocked || 0).toLocaleString()),
    );
  }
  const note = document.getElementById("sl2-traf-note");
  const trafBtn = document.getElementById("sl2-traf-toggle");
  if (trafBtn) {
    const backend = String(gate.backend || "").toLowerCase();
    const canArm = gateOn || (backend && backend !== "none" && total > 0);
    trafBtn.textContent = gateOn ? "Disarm the gate" : "Arm the gate";
    trafBtn.disabled = !canArm;
    trafBtn.title = !gateOn && !canArm
      ? (backend === "none" || !backend ? "No nft backend is running" : "File a rule before arming the gate")
      : "";
    trafBtn.onclick = () => applySluiceSetting("SLUICE_ENABLED", gateOn ? "0" : "1", trafBtn, note);
  }
  if (note) note.textContent = !gateOn ? "Arming applies the packet rules and restarts the worker." : "";

  // The one automatic enforcement threshold; visible and stoppable.
  const auto = Number(sl2Setting("SLUICE_AUTO_SCORE") || 0) || 0;
  const autoEl = document.getElementById("sl2-auto");
  if (autoEl) {
    autoEl.classList.toggle("hidden", !(auto > 0));
    if (auto > 0) {
      autoEl.replaceChildren(
        el("span", { class: "chip bad", text: "auto-block on" }),
        el("span", { class: "muted", text: `detections at or above ${auto.toFixed(2)} are blocked without review` }),
      );
      const pause = el("button", { class: "quiet", attrs: { type: "button" }, text: "Pause auto-block" });
      pause.onclick = () => applySluiceSetting("SLUICE_AUTO_SCORE", "0", pause, autoEl);
      autoEl.appendChild(pause);
    }
  }
  renderSluiceFleet(d.gates || []);
}

function renderSluiceFleet(gates) {
  const host = document.getElementById("sl2-fleet");
  const card = document.getElementById("sl2-fleet-card");
  if (!host) return;
  if (!gates.length) {
    if (card) card.classList.add("hidden");
    host.replaceChildren();
    return;
  }
  if (card) card.classList.toggle("hidden", false);
  host.replaceChildren();
  host.appendChild(el("h3", { class: "gate-subhead", text: "Fleet packet gates" }));
  const table = el("table", { class: "sl2-fleet-table" });
  table.appendChild(el("thead", {}, [el("tr", {}, [
    el("th", { text: "Weirling" }), el("th", { text: "State" }), el("th", { text: "Interfaces" }),
    el("th", { text: "Rules" }), el("th", { text: "Last check" }),
  ])]));
  const body = el("tbody");
  for (const g of gates) {
    const state = String(g.state || "unknown");
    body.appendChild(el("tr", {}, [
      el("td", {}, [el("span", { class: "mono", text: g.sensor || "—" }),
        g.local ? el("span", { class: "muted", text: " · hub" }) : null].filter(Boolean)),
      el("td", {}, [sluiceStateChip(g.state, g.stale)]),
      el("td", { class: "mono", text: g.iface || "—" }),
      el("td", { text: `${Number(g.rules_active || 0)} / ${Number(g.rules_total || 0)}` }),
      el("td", { class: "muted", text: g.age_s == null ? "—" : `${fmtAge(g.age_s)} ago` }),
    ]));
  }
  table.appendChild(body);
  // The fleet table scrolls inside its card on a phone instead of widening the document.
  const wrap = el("div", { class: "tablewrap" });
  wrap.appendChild(table);
  host.appendChild(wrap);
}

async function applySluiceSetting(key, value, btn, note) {
  if (btn && !btn.dataset.confirm) {
    btn.dataset.confirm = "1";
    const previous = btn.textContent;
    btn.textContent = "Confirm: apply";
    if (note && note.tagName !== "DIV") note.textContent = `Changing ${key} restarts the worker. Click again to confirm.`;
    setTimeout(() => {
      if (document.body.contains(btn) && btn.textContent === "Confirm: apply") {
        delete btn.dataset.confirm;
        btn.textContent = previous;
      }
    }, 6000);
    return;
  }
  if (btn) { delete btn.dataset.confirm; btn.disabled = true; }
  try {
    const out = await postJSON("/api/settings/apply", { changes: { [key]: String(value) }, confirmed: true });
    if (note && note.tagName !== "DIV") {
      note.textContent = (out && (out.ok === false ? out.error : (out.note || "applied."))) || "applied.";
    }
    await loadSluice();
  } catch (err) {
    if (note && note.tagName !== "DIV") note.textContent = (err && err.message) || String(err);
  } finally {
    if (btn) btn.disabled = false;
  }
}

/* ── Rules ──────────────────────────────────────────────────────────────────────────────────── */
function renderSluiceRules(d) {
  const rules = Array.isArray(d.rules) ? d.rules : [];
  const shown = rules.filter(sl2Visible);
  const live = rules.filter((r) => r.live && !r.revoked && !r.disabled).length;
  const count = document.getElementById("sl2-count");
  if (count) count.textContent = `${live} live · ${rules.length} total`;
  const note = document.getElementById("sl2-rules-note");
  if (note) note.textContent = `${shown.length} shown`;

  // Where a packet rule can actually bite: a sensor with a verified in-path channel, not every
  // registered weirling. Each chip opens that sensor's fleet sheet.
  const reachBox = document.getElementById("sl-reach");
  if (reachBox) {
    reachBox.replaceChildren();
    if (!d.gates_available) {
      reachBox.appendChild(el("span", { class: "muted",
        text: "Reach unavailable — the fleet's gate state could not be read." }));
    } else {
      const reach = (d.gates || [])
        .filter((g) => g.enforcement && !g.stale).map((g) => g.sensor);
      if (reach.length) {
        reachBox.appendChild(el("span", { class: "muted",
          text: `can act on ${reach.length} sensor${reach.length === 1 ? "" : "s"}: ` }));
        for (const sen of reach) {
          const chip = el("button", { class: "dc-chip", text: sen, attrs: { type: "button" } });
          chip.addEventListener("click", () => {
            if (typeof openWeirling === "function") openWeirling(sen);
          });
          reachBox.appendChild(chip);
        }
      } else {
        reachBox.appendChild(el("span", { class: "muted",
          text: "can act on 0 sensors — no sensor has a verified in-path channel." }));
      }
    }
  }

  const tbody = document.querySelector("#sl2-rules tbody");
  const empty = document.getElementById("sl2-empty");
  if (!tbody || !empty) return;
  tbody.replaceChildren();
  if (!shown.length) {
    if (!d.available) {
      empty.textContent = d.reason || "The rule store could not be read.";
    } else {
      const hiddenRevoked = rules.filter((r) => r.revoked).length;
      const parts = [SL2_STATE.showRevoked
        ? "No rules match this filter."
        : "No live rules match this filter."];
      if (hiddenRevoked) {
        parts.push(`${hiddenRevoked} revoked rule${hiddenRevoked === 1 ? "" : "s"} hidden; tick 'show revoked' to see them.`);
      }
      parts.push("Domain blocking is a separate gate; read its state above.");
      empty.textContent = parts.join(" ");
    }
    empty.classList.remove("hidden");
    return;
  }
  empty.classList.add("hidden");
  for (const rule of shown) {
    const state = sl2StateOf(rule);
    const sentence = el("button", {
      class: "sl2-rule-btn", attrs: { type: "button" },
      text: rule.describes || rule.domain || rule.rule_id || "unnamed rule",
    });
    sentence.addEventListener("click", () => openRuleSheet(rule));
    const tr = el("tr", {
      class: "sl2-rule-row",
      attrs: { "data-rule-id": rule.rule_id },
    }, [
      el("td", {}, [sentence]),
      el("td", {}, [sl2Chip(sl2GateOf(rule), rule.domain ? "ok" : "muted")]),
      el("td", {}, [sl2Chip(state.text, state.cls)]),
      el("td", { class: "muted", text: sluiceDuration(rule.expires_in_s) }),
      el("td", { class: "muted", text: rule.origin || "manual" }),
      el("td", { class: "muted", text: rule.reason || "" }),
    ]);
    tr.addEventListener("click", (event) => {
      if (event.target !== sentence) openRuleSheet(rule);
    });
    tbody.appendChild(tr);
  }
  sluiceApplyFlash();
}

/** US-3: an audit receipt or palette result lands on the rule row. */
let SL2_FLASH_PENDING = "";
function sluiceHighlightRule(ruleId) {
  SL2_FLASH_PENDING = String(ruleId);
  sluiceApplyFlash();
  setTimeout(() => { if (SL2_FLASH_PENDING === String(ruleId)) SL2_FLASH_PENDING = ""; }, 2500);
}

function sluiceApplyFlash() {
  if (!SL2_FLASH_PENDING) return;
  const row = [...document.querySelectorAll("#sl2-rules tbody tr.sl2-rule-row")]
    .find((tr) => tr.getAttribute("data-rule-id") === SL2_FLASH_PENDING);
  if (!row) return;
  row.classList.add("flash-hit");
  try { row.scrollIntoView({ block: "center" }); } catch (_e) { /* optional */ }
  setTimeout(() => row.classList.remove("flash-hit"), 1800);
  SL2_FLASH_PENDING = "";
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
  if (btn) { delete btn.dataset.confirm; btn.textContent = "Create rule"; btn.disabled = false; }
  sl2OpenSheet();
  const focus = document.getElementById(kind && kind.value === "traffic" ? "sl2-src" : "sl2-domain");
  if (focus) focus.focus();
}

function sl2Facts(rule) {
  const host = document.getElementById("sl2-facts");
  if (!host) return;
  const facts = [
    ["Rule", rule.describes || rule.rule_id || "—"],
    ["Gate", sl2GateOf(rule)],
    ["State", sl2StateOf(rule).text],
    ["Origin", rule.origin || "—"],
    ["Expires", sluiceDuration(rule.expires_in_s)],
    ["Reason", rule.reason || "—"],
    ["Rule id", rule.rule_id || "—"],
  ];
  host.replaceChildren();
  const stats = el("div", { class: "stats" });
  for (const [k, v] of facts) stats.appendChild(sl2Stat(k, v));
  host.appendChild(stats);
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
  }
  const note = document.getElementById("sl2-detail-note");
  if (note) {
    note.textContent = rule.revoked
      ? "This rule is revoked. Its record is kept for audit; it cannot be edited."
      : (rule.not_live ? "This rule is not in the live store; it is shown as a record only." : "");
  }
  for (const id of ["sl2-mode-save", "sl-rule-delete", "sl-rule-delete-reason", "sl2-detail-mode"]) {
    const field = document.getElementById(id);
    if (field) field.disabled = Boolean(rule.revoked || rule.not_live);
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
      ? el("span", { class: "chip bad", text: "last sync failed" })
      : (s.fetched_at ? el("span", { class: "chip ok", text: "ok" }) : el("span", { class: "chip muted", text: "never fetched" }));
    const tr = el("tr", { class: "clickable", attrs: { title: s.enabled
      ? "click to turn this list off — its names leave the watch set"
      : "click to turn this list on — its names join the watch set" } }, [
      el("td", {}, [el("span", { class: "chip " + (s.enabled ? "ok" : "muted"), text: s.enabled ? "on" : "off" }),
        el("span", { text: " " + s.name })]),
      el("td", {}, [state]),
      el("td", { class: "mono", text: String(s.domain_count || 0) }),
      el("td", { class: "muted", text: s.fetched_at ? fmtTime(new Date(s.fetched_at)) : "—" }),
      el("td", { class: "muted", text: s.last_error ? s.last_error.slice(0, 90) : "—" }),
    ]);
    tr.addEventListener("click", () => slToggleSource(s));
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

async function slToggleSource(s) {
  const note = document.getElementById("sl-bl-note");
  const want = !s.enabled;
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
      button.addEventListener("click", () => {
        SL2_STATE.filter = button.getAttribute("data-gate") || "all";
        for (const other of filters.querySelectorAll("[data-gate]")) {
          const active = other === button;
          other.classList.toggle("active", active);
          other.setAttribute("aria-pressed", active ? "true" : "false");
        }
        renderSluiceRules(SL2_STATE.data || { available: false, reason: "not loaded" });
      });
    }
  }
  const showRevoked = document.getElementById("sl2-show-revoked");
  if (showRevoked) showRevoked.addEventListener("change", () => {
    SL2_STATE.showRevoked = Boolean(showRevoked.checked);
    renderSluiceRules(SL2_STATE.data || { available: false, reason: "not loaded" });
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
