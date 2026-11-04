/**
 * The DNS view: port 53 made readable -- who asked what, what came back, and what the answers
 * pointed at (the operator's ask: "for domain blocks can we view dns on port 53").
 *
 * WHY IT EXISTS AND WHAT IT FEEDS. Zeek has been writing dns.log into `zeek_dns` all along;
 * this view is the read path, and the reverse reveal (an answer address -> the names that have
 * pointed at it, out of the materialized map in schema/016) is the same cache domain rules
 * resolve through. So the view is both an instrument and the explanation of how a domain
 * block will see the network.
 *
 * FILTERS ARE OPTIONAL, EVERY ONE: "show me the whole window" is a legitimate first look. The
 * server refuses an unreadable value with a sentence; this file never silently drops one.
 */
const DNS_STATE = { offset: 0, limit: 100, total: 0 };

function dnVal(id) {
  const el2 = document.getElementById(id);
  return el2 ? String(el2.value || "").trim() : "";
}

function dnsParams() {
  const q = ["hours=" + trHours()];
  const domain = dnVal("dn-domain");
  const client = dnVal("dn-client");
  const qtype = dnVal("dn-qtype");
  const rcode = dnVal("dn-rcode");
  if (domain) q.push("domain=" + encodeURIComponent(domain));
  if (client) q.push("client=" + encodeURIComponent(client));
  if (qtype) q.push("qtype=" + encodeURIComponent(qtype));
  if (rcode) q.push("rcode=" + encodeURIComponent(rcode));
  q.push("limit=" + DNS_STATE.limit);
  q.push("offset=" + DNS_STATE.offset);
  return q.join("&");
}

function dnApply(pairs) {
  for (const [id, value] of pairs) {
    const el2 = document.getElementById(id);
    if (el2) el2.value = value;
  }
  DNS_STATE.offset = 0;
  loadDns().then(clearError).catch(showError);
}

function dnClear() {
  ["dn-domain", "dn-client"].forEach((id) => { const e = document.getElementById(id); if (e) e.value = ""; });
  ["dn-qtype", "dn-rcode"].forEach((id) => { const e = document.getElementById(id); if (e) e.value = ""; });
  DNS_STATE.offset = 0;
  loadDns().then(clearError).catch(showError);
}

function dnCell(text, cls) { return el("td", { class: cls || "", text: String(text) }); }

function dnRenderSummary(d) {
  const node = document.getElementById("dn-summary");
  if (!node) return;
  // A FAILED READ IS NOT A MEASUREMENT (issue #38). The panels below say why they cannot
  // draw or list; this line used to contradict them with "0 queries \u00b7 showing 1\u20130",
  // which reads as "we looked and found none" -- the exact conflation #13 removed
  // everywhere else. When the read failed, say so and stop there.
  if (d.available === false) {
    node.textContent = `DNS records unavailable: ${d.reason || "the query did not run"}`;
    return;
  }
  const n = d.total != null ? Number(d.total).toLocaleString() : "0";
  const nx = ((d.facets || {}).rcodes || []).find((r) => r.value === 3);
  const top = ((d.facets || {}).domains || [])[0];
  const bits = [`${n} quer${d.total === 1 ? "y" : "ies"}`];
  if (nx) bits.push(`${Number(nx.count).toLocaleString()} NXDOMAIN`);
  if (top) bits.push(`busiest ${top.value}`);
  // The range carries the same guard as blocked.js's pager: nothing shown reads 0\u20130,
  // never the impossible "1\u20130".
  const from = d.total ? Number(d.offset || 0) + 1 : 0;
  const to = Number(d.offset || 0) + (d.rows || []).length;
  node.textContent = bits.join(" \u00b7 ") + ` \u00b7 showing ${from}\u2013${to}`;
}

function dnRenderHistogram(d) {
  const host = document.getElementById("dn-volume");
  if (!host) return;
  host.replaceChildren();
  if (d.available === false) {
    host.appendChild(el("p", { class: "muted",
      text: `Cannot draw this: ${d.reason || "the query did not run"}.` }));
    return;
  }
  const pts = d.histogram || [];
  if (!pts.length) {
    host.appendChild(el("p", { class: "muted", text: "No DNS records in this window — an empty window is not zero traffic." }));
    return;
  }
  const W = 900, H = 90, pad = 4;
  const max = Math.max(1, ...pts.map((p) => p.n));
  const bw = (W - 2 * pad) / pts.length;
  const svg = svgEl("svg", { viewBox: `0 0 ${W} ${H}`, class: "svg-chart",
                             preserveAspectRatio: "none" });
  pts.forEach((p, i) => {
    const h = Math.max(1, (p.n / max) * (H - 2 * pad));
    const bar = svgEl("rect", {
      x: (pad + i * bw).toFixed(1), y: (H - pad - h).toFixed(1),
      width: Math.max(1, bw - 1).toFixed(1), height: h.toFixed(1), fill: "currentColor",
      opacity: 0.55,
    });
    const t = el("title", { text: `${fmtTime(new Date(p.t))} \u00b7 ${p.n}` });
    bar.appendChild(t);
    svg.appendChild(bar);
  });
  host.appendChild(svg);
}

/** THE TOP TEN, THEN AN "others" THAT OPENS (the operator, 2026-10-16).
 *
 * The payload carries up to 200 per facet plus the DISTINCT total, so the first click is
 * instant and the label is a real count. If the total runs past what the payload holds, the
 * note says so instead of pretending the list ended. */
const DN_FACET_SHOWN = 10;

function dnFacetChips(box, rows, shown, total, applyField, title) {
  for (const row of rows.slice(0, shown)) {
    const chip = el("button", { class: "dc-chip", text: `${row.value} \u00b7 ${row.count}`,
                                attrs: { title } });
    chip.addEventListener("click", () => dnApply([[applyField, row.value]]));
    box.appendChild(chip);
  }
  if (rows.length <= shown && total <= rows.length) return;
  const rest = rows.slice(shown);
  const others = Math.max(total - shown, rest.length);
  const chip = el("button", { class: "dc-chip", text: `others (+${others})`,
                              attrs: { title: "show the rest" } });
  chip.addEventListener("click", () => {
    chip.remove();
    dnFacetChips(box, rows, rows.length, total, applyField, title);
    if (total > rows.length) {
      box.appendChild(el("span", { class: "muted",
        text: `showing the top ${rows.length} of ${total}` }));
    }
  });
  box.appendChild(chip);
}

function dnRenderFacets(d) {
  const box = document.getElementById("dn-facets");
  if (!box) return;
  box.replaceChildren();
  const f = d.facets || {};
  dnFacetChips(box, f.domains || [], DN_FACET_SHOWN, Number(f.domains_total || 0),
               "dn-domain", "filter to this domain");
  dnFacetChips(box, f.clients || [], DN_FACET_SHOWN, (f.clients || []).length,
               "dn-client", "filter to this client");
}

function dnReverseInto(container, ip) {
  container.replaceChildren(el("span", { class: "muted", text: "looking up\u2026" }));
  getJSON(`/api/dns/reverse?ip=${encodeURIComponent(ip)}&hours=${trHours()}`)
    .then((d) => {
      container.replaceChildren();
      if (d.available === false) {
        container.appendChild(el("span", { class: "muted",
          text: `Cannot look this up: ${d.reason || "the query did not run"}.` }));
        return;
      }
      if (!(d.domains || []).length) {
        container.appendChild(el("span", { class: "muted",
          text: `${ip}: no names in this window` }));
        return;
      }
      container.appendChild(el("span", { class: "muted", text: `${ip} \u2190 ` }));
      d.domains.forEach((r, i) => {
        if (i) container.appendChild(el("span", { class: "muted", text: ", " }));
        const b = el("button", { class: "dc-chip", text: r.domain,
                                 attrs: { title: "filter to this domain" } });
        b.addEventListener("click", (e) => { e.stopPropagation(); dnApply([["dn-domain", r.domain]]); });
        container.appendChild(b);
      });
    })
    .catch(() => container.replaceChildren(el("span", { class: "muted",
      text: `${ip}: the reverse lookup failed` })));
}

function dnToggleDetail(tr, r) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains("dn-detail")) { next.remove(); return; }
  const td = el("td", { attrs: { colspan: "6" } });
  const box = el("div", { class: "dn-detail-box" });
  box.appendChild(el("p", { class: "muted",
    text: `full answers: ${r.answers || "(none recorded)"}` }));
  if ((r.answer_ips || []).length) {
    const line = el("div", { class: "dn-rev" });
    box.appendChild(line);
    // The FIRST address answers immediately; a second one replaces the line on click.
    dnReverseInto(line, r.answer_ips[0]);
    if (r.answer_ips.length > 1) {
      const more = el("div", { class: "dc-chips" });
      r.answer_ips.slice(1).forEach((ip) => {
        const b = el("button", { class: "dc-chip", text: ip,
                                 attrs: { title: "reverse-look this address" } });
        b.addEventListener("click", (e) => { e.stopPropagation(); dnReverseInto(line, ip); });
        more.appendChild(b);
      });
      box.appendChild(more);
    }
  }
  const actions = el("div", { class: "dc-chips" });
  const act = (label, pairs) => {
    const b = el("button", { class: "dc-chip", text: label });
    b.addEventListener("click", (e) => { e.stopPropagation(); dnApply(pairs); });
    actions.appendChild(b);
  };
  act("+ domain " + r.query, [["dn-domain", r.query]]);
  act("+ client " + r.client, [["dn-client", r.client]]);
  act("+ type " + r.qtype_label, [["dn-qtype", String(r.qtype)]]);
  box.appendChild(actions);
  td.appendChild(box);
  const row = el("tr", { class: "dn-detail" });
  row.appendChild(td);
  tr.after(row);
}

function dnRenderRows(d) {
  const body = document.getElementById("dn-rows");
  if (!body) return;
  body.replaceChildren();
  if (d.available === false) {
    const tr = el("tr", {});
    tr.appendChild(el("td", { class: "muted", attrs: { colspan: "7" },
                              text: `Cannot list these: ${d.reason || "the query did not run"}.` }));
    body.appendChild(tr);
    return;
  }
  const rows = d.rows || [];
  if (!rows.length) {
    const tr = el("tr", {});
    const cell = el("td", { class: "muted", attrs: { colspan: "7" },
                            text: "No DNS records matched. Widen the window or clear a filter." });
    const fix = el("button", { class: "empty-act", text: "Clear filters", attrs: { type: "button" } });
    fix.addEventListener("click", () => {
      for (const id of ["dn-qtype", "dn-rcode", "dn-domain", "dn-client"]) {
        const e = document.getElementById(id);
        if (e) e.value = "";
      }
      loadDns().then(clearError).catch(showError);
    });
    cell.appendChild(fix);
    tr.appendChild(cell);
    body.appendChild(tr);
    return;
  }
  for (const r of rows) {
    const tr = el("tr", { class: "dc-row" });
    tr.appendChild(dnCell(fmtTime(new Date(r.ts)), "muted"));
    const cl = dnCell(r.client, "muted");
    cl.classList.add("dcell");
    cl.title = "filter to this client: " + r.client;
    cl.addEventListener("click", (e) => { e.stopPropagation(); dnApply([["dn-client", r.client]]); });
    tr.appendChild(cl);
    const q = dnCell(r.query);
    q.classList.add("dcell");
    q.title = "add to the filter: domain = " + r.query;
    q.addEventListener("click", (e) => { e.stopPropagation(); dnApply([["dn-domain", r.query]]); });
    tr.appendChild(q);
    const qt = dnCell(r.qtype_label, "dcell");
    if (r.qtype != null) {
      qt.title = "filter to this record type";
      qt.addEventListener("click", (e) => { e.stopPropagation(); dnApply([["dn-qtype", String(r.qtype)]]); });
    }
    tr.appendChild(qt);
    const rc = dnCell(r.rcode_label);
    if (r.rcode === 3) rc.classList.add("sev-high");
    else if (r.rcode !== 0) rc.classList.add("sev-medium");
    rc.classList.add("dcell");
    rc.title = "filter to this response code";
    rc.addEventListener("click", (e) => { e.stopPropagation(); dnApply([["dn-rcode", String(r.rcode)]]); });
    tr.appendChild(rc);
    const ans = (r.answer_ips || []);
    const ax = dnCell("", "mono");
    if (ans.length) {
      // An answer address is an ENTITY, not a string. Each address opens its host page; the
      // row click still opens the DNS detail because every span stops propagation.
      ans.forEach((ip, i) => {
        const link = el("span", { class: "dcell", text: ip,
          attrs: { "aria-label": `open ${ip} host page` } });
        link.addEventListener("click", (e) => { e.stopPropagation(); openHost(ip); });
        ax.appendChild(link);
        if (i < ans.length - 1) ax.appendChild(el("span", { text: ", " }));
      });
    } else {
      ax.textContent = (r.answers || "\u2014").slice(0, 40);
    }
    tr.appendChild(ax);
    // PUSH THE NAME TO A RULE (the operator: "from dns tab i should be able to push a domain to
    // a block rule"; then: "put the block or allow button in its own column on the far right").
    // The action lives in its OWN trailing column now, never inside the query cell -- the
    // composer opens in the modal, prefilled, and the filter-click on the cell is unchanged.
    const act = dnCell("");
    act.className = "dn-actions";
    const blk = el("button", { class: "link", text: "Block\u2026",
      attrs: { title: "turn this name into a rule" } });
    blk.addEventListener("click", (e) => { e.stopPropagation(); openRuleComposer(r.query); });
    act.appendChild(blk);
    tr.appendChild(act);
    tr.title = "click for the full answers and the reverse lookup";
    tr.addEventListener("click", () => dnToggleDetail(tr, r));
    body.appendChild(tr);
  }
}

function dnRenderPager(d) {
  const page = document.getElementById("dn-page");
  if (!page) return;
  const from = d.total ? Number(d.offset || 0) + 1 : 0;
  const to = Number(d.offset || 0) + (d.rows || []).length;
  page.textContent = `${from}\u2013${to} of ${Number(d.total || 0).toLocaleString()}`;
  const newer = document.getElementById("dn-newer");
  const older = document.getElementById("dn-older");
  if (newer) newer.disabled = (d.offset || 0) <= 0;
  if (older) older.disabled = to >= Number(d.total || 0);
}

async function loadDns() {
  if (typeof scheduleURLSync === "function") scheduleURLSync();
  const d = await getJSON(`${API.dns}?${dnsParams()}`);
  if (d.data_error) showError(new Error(d.data_error)); else clearError();
  dnRenderSummary(d);
  dnRenderHistogram(d);
  dnRenderFacets(d);
  dnRenderRows(d);
  dnRenderPager(d);
}

document.addEventListener("DOMContentLoaded", () => {
  const go = document.getElementById("dn-go");
  if (go) go.addEventListener("click", () => {
    DNS_STATE.offset = 0;
    loadDns().then(clearError).catch(showError);
  });
  const clear = document.getElementById("dn-clear");
  if (clear) clear.addEventListener("click", dnClear);
  const newer = document.getElementById("dn-newer");
  if (newer) newer.addEventListener("click", () => {
    DNS_STATE.offset = Math.max(0, DNS_STATE.offset - DNS_STATE.limit);
    loadDns().then(clearError).catch(showError);
  });
  const older = document.getElementById("dn-older");
  if (older) older.addEventListener("click", () => {
    DNS_STATE.offset += DNS_STATE.limit;
    loadDns().then(clearError).catch(showError);
  });
  for (const id of ["dn-domain", "dn-client"]) {
    const e = document.getElementById(id);
    if (e) e.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") document.getElementById("dn-go").click();
    });
  }
});
