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
const DC_STATE = { offset: 0, limit: 100, total: 0, last: null, filters: [] };

// THE CHIPS. "Click a source and it is added to the filter" -- the operator's words. A chip is
// {field, value, label}: same-field chips are OR'd by the server (click two sources, see both),
// different fields AND together. The free-text box stays a "contains" filter; chips are exact.
function dcAddChip(field, value, label) {
  const v = String(value);
  if (!v) return;
  if (DC_STATE.filters.some((f) => f.field === field && f.value === v)) return;
  DC_STATE.filters.push({ field, value: v, label: label || field + " = " + v });
  DC_STATE.offset = 0;
  loadDiscover().then(clearError).catch(showError);
}
function dcRemoveChip(index) {
  DC_STATE.filters.splice(index, 1);
  DC_STATE.offset = 0;
  loadDiscover().then(clearError).catch(showError);
}
function dcRenderChips() {
  const box = document.getElementById("dc-chips");
  if (!box) return;
  box.replaceChildren();
  if (!DC_STATE.filters.length) {
    box.appendChild(el("span", { class: "muted",
      text: "no value filters \u2014 click any address, port or type in a row to add one" }));
    return;
  }
  DC_STATE.filters.forEach((f, i) => {
    const chip = el("span", { class: "dc-chip" });
    chip.appendChild(el("span", { text: f.label }));
    const x = el("button", { class: "dc-chip-x", text: "\u00d7",
                             attrs: { title: "remove this filter" } });
    x.addEventListener("click", (e) => { e.stopPropagation(); dcRemoveChip(i); });
    chip.appendChild(x);
    box.appendChild(chip);
  });
}

function dcParams() {
  const sensor = (document.getElementById("dc-sensor") || {}).value || "";
  const proto = (document.getElementById("dc-proto") || {}).value || "";
  const addr = ((document.getElementById("dc-addr") || {}).value || "").trim();
  const port = ((document.getElementById("dc-port") || {}).value || "").trim();
  const feed = (document.getElementById("dc-feed") || {}).value || "netflow";
  const q = ["hours=" + trHours(), "feed=" + encodeURIComponent(feed)];
  if (sensor) q.push("sensor=" + encodeURIComponent(sensor));
  if (proto) q.push("proto=" + encodeURIComponent(proto));
  if (addr) q.push("addr=" + encodeURIComponent(addr));
  if (port) q.push("port=" + encodeURIComponent(port));
  DC_STATE.filters.forEach((f) => q.push(f.field + "=" + encodeURIComponent(f.value)));
  q.push("limit=" + DC_STATE.limit);
  q.push("offset=" + DC_STATE.offset);
  return q.join("&");
}

async function loadDiscover() {
  if (typeof scheduleURLSync === "function") scheduleURLSync();
  // The header trends are independent of the feed filters: one request answers all three,
  // and it must not hold up the rows if it fails.
  loadFlowTrends().catch(() => {});
  const d = await getJSON("/api/discover?" + dcParams());
  DC_STATE.last = d;
  DC_STATE.total = d.total || 0;
  dcApplyFeedChrome(d);
  const win = document.getElementById("dc-window");
  if (win) win.textContent = trLabel().toLowerCase() + " window";
  const summary = document.getElementById("dc-summary");
  const rows = d.rows || [];
  const noun = d.feed === "dns" ? "DNS record" : (d.feed === "zeek" ? "log" : "flow");
  if (summary) {
    summary.textContent = d.available === false
      ? "Cannot read " + (d.feed === "dns" ? "DNS records" : d.feed === "zeek" ? "the logs" : "flows")
        + ": " + (d.reason || "the query did not run") + "."
      : (d.feed === "zeek"
          ? (DC_STATE.total === 0
              ? "No Zeek log reported a row in this window."
              : DC_STATE.total.toLocaleString() + " record(s) across " + (d.logs || []).length
                + " log(s) in this window \u2014 click a bar or a row for the log itself.")
          : (DC_STATE.total === 0
              ? "No " + noun + "(s) match this filter in this window."
              : DC_STATE.total + " " + noun + "(s) match; showing " + (DC_STATE.offset + 1)
                + "\u2013" + (DC_STATE.offset + rows.length) + "."));
  }
  dcRenderChips();
  dcRenderHistogram(d);
  dcRenderFacets(d);
  dcRenderRows(d);
  dcRenderPager(d);
}

/** A tiny line sparkline -- 28px tall, no axes, no library. */
function dcTrendSvg(points) {
  const ns = "http://www.w3.org/2000/svg";
  const w = 120, h = 28;
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-hidden", "true");
  const vals = (points || []).map((p) => Number(p.n) || 0);
  if (!vals.length) return svg;
  const max = Math.max(1, ...vals);
  const step = vals.length > 1 ? w / (vals.length - 1) : w;
  const x = (i) => (vals.length > 1 ? i * step : w / 2);
  const y = (v) => h - 2 - (v / max) * (h - 4);
  const line = vals.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const area = document.createElementNS(ns, "path");
  area.setAttribute("class", "trend-area");
  area.setAttribute("d", `${line} L${w},${h} L0,${h} Z`);
  svg.appendChild(area);
  const path = document.createElementNS(ns, "path");
  path.setAttribute("class", "trend-line");
  path.setAttribute("d", line);
  svg.appendChild(path);
  return svg;
}

async function loadFlowTrends() {
  const host = document.getElementById("dc-trends");
  if (!host) return;
  const hours = typeof trHours === "function" ? trHours() : 24;
  // A range change is the only thing that can change these; do not re-fetch on every filter.
  if (host.dataset.hours === String(hours) && host.dataset.loaded === "1") return;
  const d = await getJSON("/api/discover/trends?hours=" + encodeURIComponent(hours));
  host.dataset.hours = String(hours);
  host.dataset.loaded = "1";
  host.replaceChildren();
  const labels = { netflow: "Netflow", zeek: "Zeek", dns: "DNS" };
  for (const name of ["netflow", "zeek", "dns"]) {
    const feed = (d.feeds || {})[name] || { available: false, reason: "no answer" };
    const box = el("button", {
      class: "trend-box", attrs: { type: "button", title: feed.available
        ? `open the ${labels[name]} feed in this window`
        : (feed.reason || "this feed could not be read") },
      on: { click: () => {
        const sel = document.getElementById("dc-feed");
        if (sel) sel.value = name;
        DC_STATE.offset = 0;
        loadDiscover().then(clearError).catch(showError);
      } },
    }, [
      el("span", { class: "k", text: labels[name] }),
      el("span", { class: "v", text: feed.available
        ? Number(feed.total || 0).toLocaleString()
        : "unavailable" }),
    ]);
    if (feed.available) box.appendChild(dcTrendSvg(feed.points || []));
    else box.appendChild(el("span", { class: "trend-empty", text: "query failed" }));
    host.appendChild(box);
  }
}

function dcRenderHistogram(d) {
  const host = document.getElementById("dc-volume");
  if (!host) return;
  if (d.feed === "zeek") { dcRenderZeekBars(d); return; }
  renderTimeline("dc-volume", {
    available: d.available !== false,
    reason: d.reason,
    series: { flows: (d.histogram || []).map((p) => ({ t: p.t, n: p.n })) },
  }, {
    emptyText: "Nothing recorded in this window — widen the range or clear a filter.",
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
    sensorSel.replaceChildren(el("option", { value: "", text: "all weirlings" }));
    // The VALUE stays the raw exporter address (that is what the server filters on); the LABEL
    // is the registered weirling's name -- the operator's rule: a weirling is named, not an IP.
    ((facets.weirlings) || []).forEach((s) => {
      sensorSel.appendChild(el("option", {
        value: s.value, text: (s.label || s.value) + " \u00b7 " + Number(s.count).toLocaleString() }));
    });
    // US-2: a selection SET BY A CALLER (the sensor sheet's "its flows") must survive this
    // rebuild. The facet only carries sensors with flows in the window; a sensor whose rows
    // aged out of the window is exactly the one being investigating, and silently
    // un-selecting it would be the filter-drop this console bans.
    if (keep && ![...sensorSel.options].some((o) => o.value === keep)) {
      sensorSel.appendChild(el("option", { value: keep, text: keep }));
    }
    sensorSel.value = keep;
  }
}

/**
 * THE FEED CHROME (the operator, 2026-10-16: "flow type in discover should be DNS, Zeek, or
 * Netflow with the charts updating to reflect. This is our view to see the data feeds being
 * collected"). The flow-type selector swaps the whole view: the table header, the controls
 * that no longer apply, and the chart -- DNS records and Zeek logs are not flows, and hiding
 * a control that does nothing beats leaving it set and silently ignored.
 */
function dcFeedColumns(feed) {
  if (feed === "dns") return ["time", "client", "type", "rcode", "query", "answers"];
  if (feed === "zeek") return ["log", "rows in window", "all time", "last row"];
  return ["time", "weirling", "source", "sport", "", "destination", "dport", "type", "bytes",
          "packets"];
}

function dcSetHeader(cols) {
  const tr = document.querySelector("#view-discover table thead tr");
  if (!tr || tr.dataset.feed === cols.join("|")) return;
  tr.dataset.feed = cols.join("|");
  tr.replaceChildren(...cols.map((c) => el("th", { text: c })));
}

function dcApplyFeedChrome(d) {
  const feed = (d && d.feed) || "netflow";
  const net = feed === "netflow";
  const show = (id, on) => { const e = document.getElementById(id); if (e) e.classList.toggle("hidden", !on); };
  show("dc-lab-sensor", net);
  show("dc-lab-proto", net);
  show("dc-lab-port", net);
  const lab = document.getElementById("dc-lab-addr");
  if (lab && lab.firstChild && lab.firstChild.nodeType === 3) {
    lab.firstChild.textContent = net ? "address " : "client ";
  }
  const addr = document.getElementById("dc-addr");
  if (addr) addr.placeholder = net ? "198.51.100.194" : "client address";
  dcSetHeader(dcFeedColumns(feed));
}

function dcRenderZeekBars(d) {
  const host = document.getElementById("dc-volume");
  if (!host) return;
  host.replaceChildren();
  const rows = (d.logs || []).map((row) => ({
    log: row.log || row.label || "?", n: Number(row.rows || row.in_window || 0),
    total: Number(row.total || 0), last: row.last_ts || row.last || null,
  }));
  const live = rows.filter((r) => r.n > 0).sort((a, b) => b.n - a.n);
  if (!live.length) {
    host.appendChild(el("p", { class: "muted",
      text: "No Zeek log produced a row in this window; the table below says when each last did." }));
    return;
  }
  const max = Math.max(...live.map((r) => r.n));
  live.forEach((r) => {
    const bar = el("div", { class: "zk-bar" }, [
      el("span", { class: "muted zk-name", text: r.log }),
      el("div", { class: "zk-bar-fill", attrs: { style: "width:" + Math.max(2, Math.round(100 * r.n / max)) + "%" } }),
      el("span", { class: "muted", text: " " + r.n.toLocaleString() }),
    ]);
    bar.title = "open the Zeek tab";
    bar.addEventListener("click", () => showView("zeek"));
    host.appendChild(bar);
  });
}

function dcCell(text, cls) { return el("td", { class: cls || "", text: String(text) }); }

function dcRenderRows(d) {
  const body = document.getElementById("dc-rows");
  if (!body) return;
  body.replaceChildren();
  if (d.feed === "dns") {
    (d.rows || []).forEach((r) => {
      const tr = el("tr", { class: "dc-row" });
      tr.appendChild(dcCell(fmtTime(new Date(r.ts)), "muted"));
      const cl = dcCell(r.client, "dcell");
      cl.title = "filter the feed to this client";
      cl.addEventListener("click", (e) => {
        e.stopPropagation();
        const box = document.getElementById("dc-addr");
        if (box) box.value = r.client;
        DC_STATE.offset = 0;
        loadDiscover().then(clearError).catch(showError);
      });
      tr.appendChild(cl);
      tr.appendChild(dcCell(r.qtype_label || r.qtype));
      tr.appendChild(dcCell(r.rcode_label || r.rcode));
      tr.appendChild(dcCell(r.query));
      tr.appendChild(dcCell((r.answer_ips || []).length));
      tr.title = "click the client to filter by it \u00b7 click the row for the record";
      tr.addEventListener("click", () => dcToggleDetail(tr, r));
      body.appendChild(tr);
    });
    return;
  }
  if (d.feed === "zeek") {
    (d.logs || []).forEach((row) => {
      const tr = el("tr", { class: "dc-row" });
      const name = row.log || row.label || "?";
      const nm = dcCell(name, "dcell");
      nm.title = "open this log's rows in the Zeek view";
      nm.addEventListener("click", (e) => {
        e.stopPropagation();
        showView("zeek");
        // US-2: the Zeek view already owns the per-log drill; a log WITH rows drills straight
        // into them (assets.js's loadZeekLog). A zero-row log just opens the tab -- a drill
        // offered into nothing is the dead end the Zeek view's own bars refuse.
        if (Number(row.rows || row.in_window || 0) > 0 && typeof loadZeekLog === "function") {
          loadZeekLog(name).catch(showError);
        }
      });
      tr.appendChild(nm);
      tr.appendChild(dcCell(Number(row.rows || row.in_window || 0).toLocaleString()));
      tr.appendChild(dcCell(Number(row.total || 0).toLocaleString()));
      tr.appendChild(dcCell(row.last_ts || row.last ? fmtTime(new Date(row.last_ts || row.last)) : "never"));
      tr.title = "a log with zero this window but a recent last row is quiet, not broken";
      body.appendChild(tr);
    });
    return;
  }
  (d.rows || []).forEach((r) => {
    const tr = el("tr", { class: "dc-row" });
    tr.appendChild(dcCell(fmtTime(new Date(r.timestamp)), "muted"));
    const cell = (value, field, label, cls) => {
      const td = dcCell(value, cls);
      if (field) {
        td.classList.add("dcell");
        td.title = "add to the filter: " + (label || field + " = " + value);
        td.addEventListener("click", (e) => {
          e.stopPropagation();
          if (field === "proto") {
            document.getElementById("dc-proto").value = String(r.proto);
            DC_STATE.offset = 0; loadDiscover().then(clearError).catch(showError); return;
          }
          if (field === "sensor") {
            document.getElementById("dc-sensor").value = r.sensor;
            DC_STATE.offset = 0; loadDiscover().then(clearError).catch(showError); return;
          }
          dcAddChip(field, value, label);
        });
      }
      return td;
    };
    tr.appendChild(cell((r.weirling || r.sensor), "sensor",
                        "weirling = " + (r.weirling || r.sensor), "muted"));
    tr.appendChild(cell(r.src_addr, "src", "src = " + r.src_addr));
    tr.appendChild(cell(r.src_port || "\u00b7", r.src_port ? "sport" : "", r.src_port ? "sport = " + r.src_port : ""));
    tr.appendChild(dcCell("\u2192"));
    tr.appendChild(cell(r.dst_addr, "dst", "dst = " + r.dst_addr));
    tr.appendChild(cell(r.dst_port || "\u00b7", r.dst_port ? "dport" : "", r.dst_port ? "dport = " + r.dst_port : ""));
    tr.appendChild(cell(r.proto_label, "proto", "type = " + r.proto_label));
    tr.appendChild(dcCell(fmtBytes(r.bytes)));
    tr.appendChild(dcCell(Number(r.packets).toLocaleString()));
    tr.title = "click a value to add it to the filter \u00b7 click the row for every field";
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
  // A DNS record and a flow share none of their fields; the detail panel asks the row which it is.
  const dnsRow = r && (r.query !== undefined);
  (dnsRow ? [["time", r.ts], ["client", r.client], ["query", r.query],
             ["type", r.qtype_label || r.qtype], ["rcode", r.rcode_label || r.rcode],
             ["answers", (r.answer_ips || []).join(", ") || "none recorded"]]
          : [["flow started", r.timestamp], ["sensor", r.sensor], ["source", r.src_addr + ":" + r.src_port],
             ["destination", r.dst_addr + ":" + r.dst_port], ["flow type", r.proto_label + " (" + r.proto + ")"],
             ["bytes / packets", fmtBytes(r.bytes) + " / " + Number(r.packets).toLocaleString()],
             ["TTL", r.ip_ttl || "not measured"], ["next hop", r.next_hop || "not measured"],
             ["AS (src \u2192 dst)", (r.src_as || 0) + " \u2192 " + (r.dst_as || 0)],
             ["TCP flags", r.tcp_flags || 0]]).forEach(([k, v]) => {
    dl.appendChild(el("span", { class: "muted", text: k + ": " }));
    dl.appendChild(el("span", { text: String(v) + "  " }));
  });
  const acts = el("div", { class: "dc-actions" });
  const addFilter = (label, fn) => {
    const b = el("button", { text: label });
    b.addEventListener("click", (e) => { e.stopPropagation(); fn(); loadDiscover().then(clearError).catch(showError); });
    acts.appendChild(b);
  };
  const openHostBtn = (addr) => {
    const host = el("button", { text: "open host " + addr });
    host.addEventListener("click", (e) => { e.stopPropagation(); openHost(addr); });
    acts.appendChild(host);
  };
  if (dnsRow) {
    // US-1: a DNS record has a client and a query, not a src/dst pair -- and the DNS feed
    // ignores the chip filters server-side, so offering them added chips that filtered
    // nothing. The record's own client is the one host worth a jump.
    if (r.client) openHostBtn(r.client);
  } else {
    // Every value is offered only when it EXISTS -- a button labelled "+ src undefined" is a
    // click that lies, which is the defect this replaces.
    if (r.src_addr) addFilter("+ src " + r.src_addr, () => dcAddChip("src", r.src_addr));
    if (r.dst_addr) addFilter("+ dst " + r.dst_addr, () => dcAddChip("dst", r.dst_addr));
    if (r.src_port) addFilter("+ sport " + r.src_port, () => dcAddChip("sport", r.src_port));
    if (r.dst_port) addFilter("+ dport " + r.dst_port, () => dcAddChip("dport", r.dst_port));
    if (r.src_addr) openHostBtn(r.src_addr);
  }
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
  // US-2: drill to ONE SENSOR (a weirling's sheet says "show me this sensor's flows"). The
  // option is ensured first: selecting a value that is not in the list yet silently selects
  // nothing, which is the filter-drop this console bans.
  if (opts.sensor !== undefined) {
    const sel = document.getElementById("dc-sensor");
    if (sel) {
      if (![...sel.options].some((o) => o.value === String(opts.sensor))) {
        sel.appendChild(el("option", { value: String(opts.sensor), text: String(opts.sensor) }));
      }
      sel.value = String(opts.sensor);
    }
  }
  DC_STATE.offset = 0;
  showView("discover");
  loadDiscover().then(clearError).catch(showError);
}

function dcClear() {
  ["dc-addr", "dc-port"].forEach((id) => { const e = document.getElementById(id); if (e) e.value = ""; });
  ["dc-sensor", "dc-proto"].forEach((id) => { const e = document.getElementById(id); if (e) e.value = ""; });
  DC_STATE.filters = [];
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
  // US-1: the feed select had NO listener -- picking DNS or Zeek changed nothing, the biggest
  // "click that lies" this console had. Switching feeds reloads; leaving netflow also drops the
  // value chips, because the DNS and Zeek feeds ignore them and a chip that filters nothing is
  // the same lie one layer down.
  const feed = document.getElementById("dc-feed");
  if (feed) feed.addEventListener("change", () => {
    if (feed.value !== "netflow") DC_STATE.filters = [];
    DC_STATE.offset = 0;
    loadDiscover().then(clearError).catch(showError);
  });
  const addr = document.getElementById("dc-addr");
  if (addr) addr.addEventListener("keydown", (e) => { if (e.key === "Enter") document.getElementById("dc-apply").click(); });
  const port = document.getElementById("dc-port");
  if (port) port.addEventListener("keydown", (e) => { if (e.key === "Enter") document.getElementById("dc-apply").click(); });
});
