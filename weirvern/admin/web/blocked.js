/**
 * The Blocked tab: what has been caught, and what is doing the catching (the operator's ask:
 * "We need a blocked tab too").
 *
 * TWO QUESTIONS, ONE SCREEN. "Has anything been stopped" is the gate's counters plus the live
 * BLOCK-mode rules and the addresses they currently cover; "what did the watches see" is the
 * recorded hits -- a device asked for a name a rule or a list watches. A hit is NOT a block,
 * which is why the mode is a column the reader can see, not a colour they must infer.
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

/**
 * CLICK-TO-FILTER (the operator, 2026-10-16): a value clicked anywhere in this tab becomes the
 * tab's filter and the WHOLE tab re-reads with it -- server-side, so the count in the summary is
 * the filtered truth, not a number the browser worked out by hiding rows.
 */
/**
 * THE RULE CARD (the operator, 2026-10-16: "if i click on the rule button it should open the
 * rule and allow me to see it or modify it"). Filled from the payload row the click came from;
 * a hit's chip finds its rule by id in the last payload, and when the rule is no longer among
 * the live sets the card SAYS that instead of pretending: a revoked rule is a decision that
 * ended, and the ledger of its hits is why it is still reachable from here.
 */
function blRuleEls() {
  return {
    card: document.getElementById("bl-rule-card"),
    id: document.getElementById("bl-rule-id"),
    body: document.getElementById("bl-rule-body"),
    mode: document.getElementById("bl-rule-mode"),
    apply: document.getElementById("bl-rule-apply"),
    revoke: document.getElementById("bl-rule-revoke"),
    close: document.getElementById("bl-rule-close"),
    note: document.getElementById("bl-rule-note"),
  };
}

function blOpenRuleById(ruleId, hit) {
  const d = BLOCKED_STATE.data || {};
  const all = [...(d.blocks || []), ...(d.alerts || [])];
  const found = all.find((x) => x.rule_id === ruleId);
  if (found) return blOpenRule(found);
  blOpenRule({ rule_id: ruleId, describes: (hit && hit.domain) || ruleId, mode: "",
               resolved_count: 0, resolved: [], origin: "", expires_at: null,
               not_live: true });
}

function blOpenRule(r) {
  const els = blRuleEls();
  if (!els.card) return;
  els.id.textContent = r.rule_id || "";
  els.body.replaceChildren();
  const covers = r.resolved_error
    ? `lookup failed — ${r.resolved_error}`
    : `${r.resolved_count || 0} address(es) now` +
      ((r.resolved || []).length ? `: ${r.resolved.slice(0, 6).join(", ")}` +
        (r.resolved.length > 6 ? " …" : "") : "");
  const rows = [
    ["name", r.domain || "(addresses, not a name)"],
    ["mode", r.mode ? (r.mode === "alert" ? "alert \u2014 records hits, does not block"
                                          : "block \u2014 enforced in the kernel") : "unknown"],
    ["origin", r.origin || "manual"],
    ["expires", r.expires_at ? fmtTime(new Date(r.expires_at)) : "until revoked"],
    ["covers", covers],
  ];
  for (const [k, v] of rows) {
    els.body.appendChild(el("div", { class: "rl-row" }, [
      el("span", { class: "rl-k", text: k }),
      el("span", { class: "rl-v", text: String(v) }),
    ]));
  }
  const editable = !r.not_live && !!r.mode;
  // The NAME is editable too ("modify it like adding a *"): a `*.` marker is accepted and stored
  // as typed; a name already covers its subdomains, the marker is how operators say it.
  const domInput = document.getElementById("bl-rule-domain");
  const domSave = document.getElementById("bl-rule-save-domain");
  if (domInput) {
    domInput.value = r.domain || "";
    domInput.disabled = !editable || !r.domain;
    if (domSave) domSave.disabled = !editable || !r.domain;
  }
  els.mode.value = r.mode === "block" ? "block" : "alert";
  els.mode.disabled = !editable;
  els.apply.disabled = !editable;
  els.revoke.disabled = !editable;
  els.note.textContent = r.not_live
    ? "This rule is not among the live rules — it has expired or was revoked. That is why the "
      + "card has no controls: revoking a decision that already ended, or re-arming it, would "
      + "both be new decisions. Create a new rule if you want one."
    : "";
  els.apply.textContent = "Apply mode";
  delete els.apply.dataset.armed;

  els.apply.onclick = async () => {
    const want = els.mode.value;
    if (want === "block" && !els.apply.dataset.armed) {
      els.apply.dataset.armed = "1";
      els.apply.textContent = "Confirm: enforce in kernel";
      els.note.textContent = "Moving to block changes what the kernel drops. Click again to "
        + "confirm.";
      return;
    }
    delete els.apply.dataset.armed;
    els.apply.disabled = true;
    try {
      const out = await postJSON("/api/sluice/rule/mode",
        Object.assign({ rule_id: r.rule_id, mode: want }, want === "block" ? { confirmed: true } : {}));
      els.note.textContent = out && out.ok
        ? `Mode changed to ${want}. The gate re-reads rules on its own cycle.`
        : ((out && out.error) || "the change was refused");
      await loadBlocked();
    } catch (err) {
      els.note.textContent = String(err.message || err);
    } finally {
      els.apply.disabled = false;
      els.apply.textContent = "Apply mode";
    }
  };
  els.revoke.onclick = async () => {
    els.revoke.disabled = true;
    try {
      const out = await postJSON("/api/sluice/revoke", { rule_id: r.rule_id });
      els.note.textContent = (out && out.ok === false)
        ? ((out.error) || "the revoke was refused")
        : "Revoked. The record stays readable; enforcement stops at the next gate cycle.";
      await loadBlocked();
    } catch (err) {
      els.note.textContent = String(err.message || err);
    } finally {
      els.revoke.disabled = false;
    }
  };
  const domSave2 = document.getElementById("bl-rule-save-domain");
  if (domSave2) domSave2.onclick = async () => {
    const domInput2 = document.getElementById("bl-rule-domain");
    const want = String((domInput2 && domInput2.value) || "").trim();
    if (!want) { els.note.textContent = "a name is required."; return; }
    domSave2.disabled = true;
    try {
      const out = await postJSON("/api/sluice/rule/domain", { rule_id: r.rule_id, domain: want });
      els.note.textContent = (out && out.ok)
        ? `name saved as ${(out.rule && out.rule.domain) || want}.`
        : ((out && out.error) || "the edit was refused");
      await loadBlocked();
    } catch (err) {
      els.note.textContent = String((err && err.message) || err);
    } finally {
      domSave2.disabled = false;
    }
  };
  els.close.onclick = () => closeModal(els.card);
  openModal(els.card);
}

/** The block's REASON, in the reader's words (the operator, 2026-10-16: "the reason in the
 * table, like ML, custom, dns"). Detection-derived rules are stamped by the derivation path;
 * "dns" is a rule pushed from the DNS tab; anything else is an operator's own rule, with their
 * note when one was written. */
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

function blEmptyRow(body, span, text) {
  const tr = el("tr", {});
  tr.appendChild(el("td", { class: "muted", attrs: { colspan: String(span) }, text }));
  body.appendChild(tr);
}

function blRenderSummary(d) {
  const node = document.getElementById("bl-summary");
  if (!node) return;
  const g = d.gate || {};
  const covered = (d.blocks || []).reduce((a, r) => a + (r.resolved_count || 0), 0);
  const bits = [`${Number(d.total || 0).toLocaleString()} recorded hit${d.total === 1 ? "" : "s"}`];
  bits.push(`${(d.blocks || []).length} blocking rule(s) covering ${covered} address(es)`);
  if ((d.alerts || []).length) bits.push(`${d.alerts.length} alerting`);
  bits.push(`gate ${g.state || "unknown"}${g.enforcement ? " via " + g.enforcement : ""}` +
            (g.packets_blocked != null
              ? `, ${Number(g.packets_blocked).toLocaleString()} packet(s) dropped` : ""));
  node.textContent = bits.join(" \u00b7 ");
}

function blRenderHits(d) {
  const body = document.getElementById("bl-hit-rows");
  if (!body) return;
  body.replaceChildren();
  const hits = d.hits || [];
  if (!hits.length) {
    blEmptyRow(body, 5, "Nothing recorded in this window. A hit appears when a device asks " +
      "for a name a rule or a list watches \u2014 recording blocks nothing.");
    return;
  }
  for (const h of hits) {
    const tr = el("tr", {}, [
      blCell(fmtTime(new Date(h.ts)), "muted"),
      (() => {
        const td = el("td", {}, [el("span", { class: "chip " + (h.rule_id ? "ok" : "muted"),
                                            text: h.rule_id ? "rule" : "list" })]);
        if (h.rule_id) {
          // The "rule" chip is the rule's door (the operator, 2026-10-16). A LIST hit has no
          // rule to open -- the list is not an object this view can edit -- so its chip stays
          // inert rather than opening an empty card.
          td.classList.add("dcell");
          td.title = "open this rule";
          td.addEventListener("click", () => blOpenRuleById(h.rule_id, h));
        }
        return td;
      })(),
      (() => { const td = blCell(h.domain, "mono dcell");
        td.title = "filter the hits to this domain: " + h.domain;
        td.addEventListener("click", () => blFilterTo("domain", h.domain));
        return td; })(),
      blCell(h.query),
      (() => { const td = blCell(h.client, "muted dcell");
        td.title = "filter the hits to this client: " + h.client;
        td.addEventListener("click", () => blFilterTo("client", h.client));
        return td; })(),
    ]);
    body.appendChild(tr);
  }
}

function blRenderRules(d) {
  for (const [id, rows] of [["bl-block-rows", d.blocks || []],
                            ["bl-alert-rows", d.alerts || []]]) {
    const body = document.getElementById(id);
    if (!body) continue;
    body.replaceChildren();
    if (!rows.length) {
      blEmptyRow(body, 4, id === "bl-block-rows"
        ? "No blocking rules. Create one in Sluice Gate; a domain rule blocks what its name " +
          "resolves to."
        : "No alert rules.");
      continue;
    }
    for (const r of rows) {
      const addr = r.resolved_error
        ? el("span", { class: "chip bad", text: "lookup failed" })
        : el("span", { class: "mono",
            text: `${r.resolved_count || 0} now` +
                  ((r.resolved || []).length ? ` (${r.resolved.slice(0, 3).join(", ")}` +
                    (r.resolved.length > 3 ? "\u2026)" : ")") : "") });
      const nameCell = blCell(r.describes || r.rule_id, "mono dcell");
      nameCell.title = "open this rule";
      nameCell.addEventListener("click", () => blOpenRule(r));
      body.appendChild(el("tr", {}, [
        nameCell,
        blCell(blReason(r), "muted"),
        el("td", {}, [addr]),
        blCell(r.origin || "manual", "muted"),
        blCell(r.expires_at ? fmtTime(new Date(r.expires_at)) : "until revoked", "muted"),
      ]));
    }
  }
}

async function loadBlocked() {
  const d = await getJSON(`${API.blocked}?${blParams()}`);
  // Kept so a click can find the FULL rule behind a row or a hit's chip (the hit itself carries
  // only the id) without a second fetch.
  BLOCKED_STATE.data = d;
  if (d.data_error) showError(new Error(d.data_error)); else clearError();
  blRenderSummary(d);
  blRenderHits(d);
  blRenderRules(d);
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
