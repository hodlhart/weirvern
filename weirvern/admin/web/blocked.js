/**
 * Blocks: the recorded-block ledger, reached from Sluice Gate.
 *
 * THE OPERATOR'S DECISION (2026-10-21). Sluice Gate is the one enforcement surface. `Blocked`
 * was a peer tab with its own rule tables and its own rule editor, so the two surfaces
 * disagreed about the same rules. This file is now the drill, in the shape the Anomalies queue
 * already uses: a row opens the detail behind one block, and rule editing belongs to the
 * Sluice rule sheet.
 *
 * A hit is still not a block: a watched name was asked for, and the row says whether a rule or
 * an imported list matched. The detail card states the action actually taken.
 */
const BLOCKED_STATE = { offset: 0, limit: 200, data: null };

function blParams() {
  const q = ["hours=" + trHours(), "limit=" + BLOCKED_STATE.limit, "offset=" + BLOCKED_STATE.offset];
  const d = document.getElementById("bl-domain");
  if (d && d.value.trim()) q.push("domain=" + encodeURIComponent(d.value.trim()));
  const c = document.getElementById("bl-client");
  if (c && c.value.trim()) q.push("client=" + encodeURIComponent(c.value.trim()));
  return q.join("&");
}

function blCell(text, cls) { return el("td", { class: cls || "", text: String(text) }); }

/** Fetch the live rule sets ONCE, on demand. A hit carries only a rule id; the rule sheet
 * needs the full object, and a fresh console must not fabricate "expired or revoked" from a
 * payload it never read. */
let blLiveSets = null;

async function blEnsureLiveSets() {
  if (BLOCKED_STATE.data) return BLOCKED_STATE.data;
  if (!blLiveSets) {
    blLiveSets = loadBlocked().catch(() => {}).finally(() => { blLiveSets = null; });
  }
  await blLiveSets;
  return BLOCKED_STATE.data;
}

/** The Blocked's REASON, in the reader's words. Detection-derived rules are stamped by the
 * derivation path; "dns" is a rule pushed from the DNS tab; anything else is an operator's own
 * rule, with their note when one was written. */
function blReason(r) {
  const origin = String(r.origin || "manual");
  let label;
  if (origin === "detection") label = "ML" + (r.severity ? ` (${r.severity})` : "");
  else if (origin === "dns") label = "dns";
  else if (origin === "installer") label = "installer";
  else label = "custom";
  return r.reason ? `${label} \u2014 ${String(r.reason).slice(0, 60)}` : label;
}

function blFilterTo(field, value) {
  const input = document.getElementById("bl-" + field);
  if (input) input.value = value;
  BLOCKED_STATE.offset = 0;
  loadBlocked().then(clearError).catch(showError);
}

function blEmptyRow(body, span, text, action) {
  const tr = el("tr", {});
  const cell = el("td", { class: "muted", attrs: { colspan: String(span) }, text });
  if (action && action.label && typeof action.fn === "function") {
    const fix = el("button", { class: "empty-act", text: action.label, attrs: { type: "button" } });
    fix.addEventListener("click", action.fn);
    cell.appendChild(fix);
  }
  tr.appendChild(cell);
  body.appendChild(tr);
}

function blRenderSummary(d) {
  const node = document.getElementById("bl-summary");
  if (!node) return;
  if (d.available === false) {
    node.textContent = `Blocks unavailable \u2014 ${d.reason || "the query did not run"}.`;
    return;
  }
  const g = d.gate || {};
  const bits = [`${Number(d.total || 0).toLocaleString()} recorded hit${d.total === 1 ? "" : "s"}`,
                `${(d.blocks || []).length} blocking rule(s)`, `${(d.alerts || []).length} alerting rule(s)`];
  bits.push(`gate ${g.state || "unknown"}${g.enforcement ? " via " + g.enforcement : ""}` +
            (g.packets_blocked != null
              ? `, ${Number(g.packets_blocked).toLocaleString()} packet(s) dropped` : ""));
  bits.push("rules are edited in Sluice Gate");
  node.textContent = bits.join(" \u00b7 ");
}

/** A row opens the detail card, like an anomaly row opens Evidence. The domain/client cells
 * still filter the ledger; they stop the row click so one gesture cannot do two jobs. */
function blRenderHits(d) {
  const body = document.getElementById("bl-hit-rows");
  if (!body) return;
  body.replaceChildren();
  if (d.available === false) {
    blEmptyRow(body, 5, `Cannot list these: ${d.reason || "the query did not run"}.`);
    return;
  }
  const hits = d.hits || [];
  if (!hits.length) {
    blEmptyRow(body, 5, "Nothing recorded in this window. A hit appears when a device asks " +
      "for a name a rule or a list watches \u2014 recording blocks nothing.",
      { label: "How hits work", fn: () => openHelpPanel("bl-info") });
    return;
  }
  for (const h of hits) {
    const tr = el("tr", { class: "clickable",
      on: { click: () => blOpenHit(h) } }, [
      blCell(fmtTime(new Date(h.ts)), "muted"),
      (() => {
        const td = el("td", {}, [el("span", { class: "chip " + (h.rule_id ? "ok" : "muted"),
                                            text: h.rule_id ? "rule" : "list" })]);
        if (h.rule_id) {
          td.classList.add("dcell");
          td.addEventListener("click", (e) => { e.stopPropagation(); blOpenRuleById(h.rule_id, h); });
        }
        return td;
      })(),
      (() => { const td = blCell(h.domain, "mono dcell");
        td.title = "filter the hits to this domain: " + h.domain;
        td.addEventListener("click", (e) => { e.stopPropagation(); blFilterTo("domain", h.domain); });
        return td; })(),
      blCell(h.query),
      (() => { const td = blCell(h.client, "muted dcell");
        td.title = "filter the hits to this client: " + h.client;
        td.addEventListener("click", (e) => { e.stopPropagation(); blFilterTo("client", h.client); });
        return td; })(),
    ]);
    body.appendChild(tr);
  }
}

function blDetailEls() {
  return {
    card: document.getElementById("bl-detail-card"),
    id: document.getElementById("bl-detail-id"),
    body: document.getElementById("bl-detail-body"),
    rule: document.getElementById("bl-detail-rule"),
    note: document.getElementById("bl-detail-note"),
    close: document.getElementById("bl-detail-close"),
  };
}

function blFindRule(ruleId) {
  const d = BLOCKED_STATE.data || {};
  return [...(d.blocks || []), ...(d.alerts || [])].find((r) => r.rule_id === ruleId) || null;
}

function blOpenHit(h) {
  const els = blDetailEls();
  if (!els.card) return;
  const rule = h.rule_id ? blFindRule(h.rule_id) : null;
  const action = !rule ? "blocklist match \u2014 no editable rule"
    : (String(rule.mode).toLowerCase() === "alert"
        ? "alert only \u2014 the DNS answer was recorded, not blocked"
        : "DNS answered with a block answer");
  const gate = (BLOCKED_STATE.data && BLOCKED_STATE.data.gate) || {};
  els.id.textContent = h.rule_id || "list";
  els.body.replaceChildren();
  const rows = [
    ["time", fmtTime(new Date(h.ts))],
    ["what", h.rule_id ? "rule" : "blocklist / imported list"],
    ["domain", h.domain || "\u2014"],
    ["query", h.query || "\u2014"],
    ["client", h.client || "\u2014"],
    ["rule", rule ? `${rule.describes || rule.rule_id} (${rule.rule_id})` : (h.rule_id || "no rule object")],
    ["reason", rule ? blReason(rule) : "list match"],
    ["mode", rule ? (rule.mode || "unknown") : "list"],
    ["action", action],
    ["gate", `${gate.state || "unknown"}${gate.enforcement ? " via " + gate.enforcement : ""}`],
  ];
  for (const [k, v] of rows) {
    els.body.appendChild(el("div", { class: "rl-row" }, [
      el("span", { class: "rl-k", text: k }),
      el("span", { class: "rl-v", text: String(v) }),
    ]));
  }
  els.rule.disabled = !h.rule_id;
  els.note.textContent = rule ? "" : "The rule behind this hit is not in the live set; the record remains readable.";
  if (els.close) els.close.onclick = () => closeModal(els.card);
  if (els.rule) els.rule.onclick = () => {
    closeModal(els.card);
    blOpenRuleById(h.rule_id, h);
  };
  openModal(els.card);
}

/** A rule hit's chip, or a fix from another view, opens the SAME Sluice rule sheet. The
 * Blocked page no longer owns a second rule editor. */
async function blOpenRuleById(ruleId, hit) {
  let d = BLOCKED_STATE.data;
  if (!d) {
    await blEnsureLiveSets();
    d = BLOCKED_STATE.data;
  }
  const found = blFindRule(ruleId);
  if (found) {
    if (typeof openRuleSheet === "function") return openRuleSheet(found);
    if (typeof showView === "function") showView("sluice");
    return;
  }
  // A genuinely absent rule is a record with no live editor. Open the sheet in its non-live
  // state rather than inventing a second edit surface -- the lookup_failed wording is the
  // signal that the set could not be read, not that the decision ended.
  if (typeof openRuleSheet === "function") {
    return openRuleSheet({
      rule_id: ruleId, describes: (hit && hit.domain) || ruleId,
      // NOT revoked. A rule we could not find is a rule whose state we do not know; marking it
      // revoked told the operator enforcement had ended (WV1-08). `not_live` alone keeps the sheet
      // read-only, which is the only thing this record actually licenses.
      domain: (hit && hit.domain) || "", mode: "", live: false, revoked: false,
      origin: "", expires_at: "", resolved_count: 0, resolved: [],
      lookup_failed: !d, not_live: true,
    });
  }
  if (typeof showView === "function") showView("sluice");
}

async function loadBlocked() {
  if (typeof scheduleURLSync === "function") scheduleURLSync();
  if (typeof setCrumbs === "function") {
    setCrumbs([{ label: "Sluice Gate", run: () => showView("sluice"),
                 title: "back to the rules that made these blocks" }]);
  }
  const d = await getJSON(`${API.blocked}?${blParams()}`);
  BLOCKED_STATE.data = d;
  if (d.data_error) showError(new Error(d.data_error)); else clearError();
  const win = document.getElementById("bl-window");
  if (win) win.textContent = `${trHours()}h window`;
  blRenderSummary(d);
  blRenderHits(d);
  const page = document.getElementById("bl-page");
  if (page) {
    const from = d.total ? Number(d.offset || 0) + 1 : 0;
    const to = Number(d.offset || 0) + (d.hits || []).length;
    page.textContent = `${from}\u2013${to} of ${Number(d.total || 0).toLocaleString()}`;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const go = document.getElementById("bl-go");
  if (go) go.addEventListener("click", () => {
    BLOCKED_STATE.offset = 0;
    loadBlocked().then(clearError).catch(showError);
  });
  const clear = document.getElementById("bl-clear");
  if (clear) clear.addEventListener("click", () => {
    for (const id of ["bl-domain", "bl-client"]) {
      const f = document.getElementById(id);
      if (f) f.value = "";
    }
    BLOCKED_STATE.offset = 0;
    loadBlocked().then(clearError).catch(showError);
  });
  const back = document.getElementById("bl-back-rules");
  if (back) back.addEventListener("click", () => showView("sluice"));
  const newer = document.getElementById("bl-newer");
  if (newer) newer.addEventListener("click", () => {
    BLOCKED_STATE.offset = Math.max(0, BLOCKED_STATE.offset - BLOCKED_STATE.limit);
    loadBlocked().then(clearError).catch(showError);
  });
  const older = document.getElementById("bl-older");
  if (older) older.addEventListener("click", () => {
    BLOCKED_STATE.offset += BLOCKED_STATE.limit;
    loadBlocked().then(clearError).catch(showError);
  });
  const field = document.getElementById("bl-domain");
  if (field) field.addEventListener("keydown", (e) => {
    if (e.key === "Enter") document.getElementById("bl-go").click();
  });
});
