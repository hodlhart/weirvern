/**
 * The Blocked tab: what has been caught, and what is doing the catching (the operator's ask:
 * "We need a blocked tab too").
 *
 * TWO QUESTIONS, ONE SCREEN. "Has anything been stopped" is the gate's counters plus the live
 * BLOCK-mode rules and the addresses they currently cover; "what did the watches see" is the
 * recorded hits -- a device asked for a name a rule or a list watches. A hit is NOT a block,
 * which is why the mode is a column the reader can see, not a colour they must infer.
 */
const BLOCKED_STATE = { offset: 0, limit: 200 };

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
      el("td", {}, [el("span", { class: "chip " + (h.rule_id ? "ok" : "muted"),
                                text: h.rule_id ? "rule" : "list" })]),
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
      body.appendChild(el("tr", {}, [
        blCell(r.describes || r.rule_id, "mono"),
        el("td", {}, [addr]),
        blCell(r.origin || "manual", "muted"),
        blCell(r.expires_at ? fmtTime(new Date(r.expires_at)) : "until revoked", "muted"),
      ]));
    }
  }
}

async function loadBlocked() {
  const d = await getJSON(`${API.blocked}?${blParams()}`);
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
