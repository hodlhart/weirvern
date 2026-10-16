// ── DISCOVER ─────────────────────────────────────────────────────────────────────────────────
// The operator's ask (2026-10-16): "a discover like tab found in kibana. The ability to select
// flow types or weirling and see all traffic."
//
// Kibana's Discover is the raw document browser: a histogram of the result set, a filter bar,
// and the rows themselves, each expandable. This is that over `weirvern.flows`. Two rules it
// keeps from the rest of this console:
//   1. Every empty state says WHY (no rows vs no data vs the query failed).
//   2. A filter with a value the server cannot read is refused with a sentence -- never
//      silently dropped, which would show MORE traffic than was asked for.
const DC_STATE = { offset: 0, limit: 100, total: 0, last: null };

function dcParams() {
  const sensor = (document.getElementById("dc-sensor") || {}).value || "";
  const proto = (document.getElementById("dc-proto") || {}).value || "";
  const addr = ((document.getElementById("dc-addr") || {}).value || "").trim();
  const port = ((document.getElementById("dc-port") || {}).value || "").trim();
  const q = ["hours=" + trHours()];
  if (sensor) q.push("sensor=" + encodeURIComponent(sensor));
  if (proto) q.push("proto=" + encodeURIComponent(proto));
  if (addr) q.push("addr=" + encodeURIComponent(addr));
  if (port) q.push("port=" + encodeURIComponent(port));
  q.push("limit=" + DC_STATE.limit);
  q.push("offset=" + DC_STATE.offset);
  return q.join("&");
}

async function loadDiscover() {
  const d = await getJSON("/api/discover?" + dcParams());
  DC_STATE.last = d;
  DC_STATE.total = d.total || 0;
  const win = document.getElementById("dc-window");
  if (win) win.textContent = trLabel().toLowerCase() + " window";
  const summary = document.getElementById("dc-summary");
  const rows = d.rows || [];
  if (summary) {
    summary.textContent = d.available === false
      ? "Cannot read flows: " + (d.reason || "the query did not run") + "."
      : (DC_STATE.total === 0
          ? "No flows match this filter in this window."
          : DC_STATE.total + " flow(s) match; showing " + (DC_STATE.offset + 1) + "\u2013" +
            (DC_STATE.offset + rows.length) + ".");
  }
  dcRenderHistogram(d);
  dcRenderFacets(d);
  dcRenderRows(d);
  dcRenderPager(d);
}

function dcRenderHistogram(d) {
  const host = document.getElementById("dc-volume");
  if (!host) return;
  renderTimeline("dc-volume", {
    available: d.available !== false,
    reason: d.reason,
    series: { flows: (d.histogram || []).map((p) => ({ t: p.t, n: p.n })) },
  }, {
    emptyText: "Nothing recorded in this window.",
    // THE CLICKABLE RULE: a bucket is a window. Clicking one narrows the range to that bucket
    // and stays on Discover -- the same drill-down the Netflow volume chart offers.
    onPoint: (pt) => {
      if (!d.bucket_s) return;
      const from = new Date(pt.t);
      const to = new Date(from.getTime() + d.bucket_s * 1000);
      trApply({ mode: "absolute", from: trFormat(from), to: trFormat(to), hours: Math.max(1, Math.round(d.bucket_s / 3600) || 1) });
      loadDiscover().then(clearError).catch(showError);
    },
  });
}

function dcRenderFacets(d) {
  const facets = d.facets || {};
  const protoSel = document.getElementById("dc-proto");
  if (protoSel) {
    const keep = protoSel.value;
    protoSel.replaceChildren(el("option", { value: "", text: "any flow type" }));
    ((facets.protos) || []).forEach((p) => {
      protoSel.appendChild(el("option", {
        value: String(p.value), text: p.label + " \u00b7 " + Number(p.count).toLocaleString() }));
    });
    protoSel.value = keep;
  }
  const sensorSel = document.getElementById("dc-sensor");
  if (sensorSel) {
    const keep = sensorSel.value;
    sensorSel.replaceChildren(el("option", { value: "", text: "all sensors" }));
    ((facets.sensors) || []).forEach((s) => {
      sensorSel.appendChild(el("option", {
        value: s.value, text: s.value + " \u00b7 " + Number(s.count).toLocaleString() }));
    });
    sensorSel.value = keep;
  }
}

function dcCell(text, cls) { return el("td", { class: cls || "", text: String(text) }); }

function dcRenderRows(d) {
  const body = document.getElementById("dc-rows");
  if (!body) return;
  body.replaceChildren();
  (d.rows || []).forEach((r) => {
    const tr = el("tr", { class: "dc-row" });
    tr.appendChild(dcCell(fmtTime(new Date(r.timestamp)), "muted"));
    tr.appendChild(dcCell(r.sensor, "muted"));
    tr.appendChild(dcCell(r.src_addr));
    tr.appendChild(dcCell(r.src_port || "\u00b7"));
    tr.appendChild(dcCell("\u2192"));
    tr.appendChild(dcCell(r.dst_addr));
    tr.appendChild(dcCell(r.dst_port || "\u00b7"));
    tr.appendChild(dcCell(r.proto_label));
    tr.appendChild(dcCell(fmtBytes(r.bytes)));
    tr.appendChild(dcCell(Number(r.packets).toLocaleString()));
    tr.title = "click for every field, and to filter on this host, port or flow type";
    tr.addEventListener("click", () => dcToggleDetail(tr, r));
    body.appendChild(tr);
  });
}

function dcToggleDetail(tr, r) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains("dc-detail")) { next.remove(); return; }
  const cols = 10;
  const td = el("td", { attrs: { colspan: String(cols) } });
  const dl = el("div", { class: "dc-detail" });
  [["flow started", r.timestamp], ["sensor", r.sensor], ["source", r.src_addr + ":" + r.src_port],
   ["destination", r.dst_addr + ":" + r.dst_port], ["flow type", r.proto_label + " (" + r.proto + ")"],
   ["bytes / packets", fmtBytes(r.bytes) + " / " + Number(r.packets).toLocaleString()],
   ["TTL", r.ip_ttl || "not measured"], ["next hop", r.next_hop || "not measured"],
   ["AS (src \u2192 dst)", (r.src_as || 0) + " \u2192 " + (r.dst_as || 0)],
   ["TCP flags", r.tcp_flags || 0]].forEach(([k, v]) => {
    dl.appendChild(el("span", { class: "muted", text: k + ": " }));
    dl.appendChild(el("span", { text: String(v) + "  " }));
  });
  const acts = el("div", { class: "dc-actions" });
  const addFilter = (label, fn) => {
    const b = el("button", { text: label });
    b.addEventListener("click", (e) => { e.stopPropagation(); fn(); loadDiscover().then(clearError).catch(showError); });
    acts.appendChild(b);
  };
  addFilter("only " + r.src_addr, () => { document.getElementById("dc-addr").value = r.src_addr; });
  addFilter("only " + r.dst_addr, () => { document.getElementById("dc-addr").value = r.dst_addr; });
  if (r.dst_port) addFilter("only port " + r.dst_port, () => { document.getElementById("dc-port").value = String(r.dst_port); });
  addFilter("only " + r.proto_label, () => { document.getElementById("dc-proto").value = String(r.proto); });
  const host = el("button", { text: "open host " + r.src_addr });
  host.addEventListener("click", (e) => { e.stopPropagation(); showView("host"); openHost(r.src_addr); });
  acts.appendChild(host);
  dl.appendChild(acts);
  td.appendChild(dl);
  const detailTr = el("tr", { class: "dc-detail" });
  detailTr.appendChild(td);
  tr.after(detailTr);
}

function dcRenderPager(d) {
  const page = document.getElementById("dc-page");
  const showing = (d.rows || []).length;
  if (page) {
    page.textContent = DC_STATE.total
      ? "page " + (Math.floor(DC_STATE.offset / DC_STATE.limit) + 1) + " \u00b7 " + showing + " of " + DC_STATE.total
      : "";
  }
  const prev = document.getElementById("dc-prev");
  const next = document.getElementById("dc-next");
  if (prev) prev.disabled = DC_STATE.offset <= 0;
  if (next) next.disabled = DC_STATE.offset + showing >= DC_STATE.total;
}

function discoverDrill(opts) {
  // Chart -> rows. A bucket, a bar, a talker: the click says "show me the traffic behind
  // this", which is the clickable-usability rule this console is built on.
  if (opts.from && opts.to) {
    trApply({ mode: "absolute", from: opts.from, to: opts.to, hours: opts.hours || 1 });
  }
  const set = (id, v) => { const e = document.getElementById(id); if (e && v !== undefined) e.value = String(v); };
  set("dc-addr", opts.addr);
  set("dc-port", opts.port);
  set("dc-proto", opts.proto);
  DC_STATE.offset = 0;
  showView("discover");
  loadDiscover().then(clearError).catch(showError);
}

function dcClear() {
  ["dc-addr", "dc-port"].forEach((id) => { const e = document.getElementById(id); if (e) e.value = ""; });
  ["dc-sensor", "dc-proto"].forEach((id) => { const e = document.getElementById(id); if (e) e.value = ""; });
  DC_STATE.offset = 0;
  loadDiscover().then(clearError).catch(showError);
}

document.addEventListener("DOMContentLoaded", () => {
  const apply = document.getElementById("dc-apply");
  if (apply) apply.addEventListener("click", () => {
    DC_STATE.offset = 0;
    loadDiscover().then(clearError).catch(showError);
  });
  const clear = document.getElementById("dc-clear");
  if (clear) clear.addEventListener("click", dcClear);
  const prev = document.getElementById("dc-prev");
  if (prev) prev.addEventListener("click", () => {
    DC_STATE.offset = Math.max(0, DC_STATE.offset - DC_STATE.limit);
    loadDiscover().then(clearError).catch(showError);
  });
  const next = document.getElementById("dc-next");
  if (next) next.addEventListener("click", () => {
    DC_STATE.offset = DC_STATE.offset + DC_STATE.limit;
    loadDiscover().then(clearError).catch(showError);
  });
  const addr = document.getElementById("dc-addr");
  if (addr) addr.addEventListener("keydown", (e) => { if (e.key === "Enter") document.getElementById("dc-apply").click(); });
  const port = document.getElementById("dc-port");
  if (port) port.addEventListener("keydown", (e) => { if (e.key === "Enter") document.getElementById("dc-apply").click(); });
});
