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
  anomalies: (min, limit) => `/api/anomalies?min_score=${min}&limit=${limit}`,
  host: (addr, hours) => `/api/host?addr=${encodeURIComponent(addr)}&hours=${hours}`,
  evidence: (addr, start, end) =>
    `/api/evidence?addr=${encodeURIComponent(addr)}&start=${encodeURIComponent(start)}` +
    (end ? `&end=${encodeURIComponent(end)}` : ""),
};

let timer = null;

/* ── small helpers ──────────────────────────────────────────────────────── */

function el(tag, opts = {}, children = []) {
  const node = document.createElement(tag);
  if (opts.class) node.className = opts.class;
  if (opts.text !== undefined) node.textContent = String(opts.text);
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

function fmtTime(v) {
  if (!v) return "—";
  const d = new Date(v);
  if (isNaN(d)) return String(v);
  // Local, short. An operator correlating with a firewall uses wall-clock time.
  return d.toLocaleString(undefined, { month: "short", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/* A host cell shows the name prominently with the IP beneath, rather than
 * replacing one with the other: the name is convenient, the IP is the fact that
 * lets an operator search a DHCP lease or a firewall rule. */
function hostCell(addr, hostname) {
  if (!addr) return el("span", { class: "muted", text: "—" });
  if (!hostname) return el("span", { class: "host", text: addr });
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

async function getJSON(url) {
  const res = await fetch(url, { headers: { Accept: "application/json" } });
  const body = await res.json().catch(() => null);
  if (!res.ok) throw new Error((body && body.error) || `HTTP ${res.status}`);
  return body;
}

/* ── overview ───────────────────────────────────────────────────────────── */

async function loadOverview() {
  const data = await getJSON(API.overview);

  // Show the API's own data error, if any. This is separate from a transport
  // failure: the page loaded, but the panels could not be filled.
  showDataError(data.data_error);

  const pill = document.getElementById("health-pill");
  const checks = (data.health && data.health.checks) || [];
  const passing = checks.filter((c) => c.ok).length;
  if (!data.health) {
    pill.textContent = "no database";
    pill.className = "pill bad";
  } else {
    pill.textContent = `${passing}/${checks.length} checks passing`;
    pill.className = "pill " + (data.health.ok ? "ok" : "bad");
  }
  document.getElementById("fetched").textContent =
    data.health ? "as of " + fmtTime(data.health.fetched_at) : "";

  const ht = document.querySelector("#health-table tbody");
  ht.replaceChildren();
  if (!checks.length) {
    emptyRow(ht, 2, "No health data — is ClickHouse reachable?");
  } else {
    for (const c of checks) {
      ht.appendChild(el("tr", {}, [
        el("td", { class: c.ok ? "ok" : "bad", text: c.ok ? "✓" : "✗" }),
        el("td", {}, [
          el("strong", { text: c.name }),
          el("div", { class: "muted mono", text: c.detail || "" }),
        ]),
      ]));
    }
  }

  const wt = document.querySelector("#workloads-table tbody");
  wt.replaceChildren();
  if (!data.workloads.length) {
    emptyRow(wt, 2, data.capabilities && data.capabilities.reason
      ? "No workloads: " + data.capabilities.reason
      : "No workloads reported.");
  } else {
    for (const w of data.workloads) {
      wt.appendChild(el("tr", {}, [
        el("td", {}, [
          el("strong", { text: w.name }),
          el("div", { class: "muted mono", text: w.detail || "" }),
        ]),
        el("td", { class: w.state === "running" ? "ok" : "muted",
                   text: w.state + (w.health ? " · " + w.health : "") }),
      ]));
    }
  }

  const at = document.querySelector("#overview-anomalies tbody");
  at.replaceChildren();
  if (!data.anomalies.length) {
    emptyRow(at, 5, "No anomalies yet. Detection needs a baseline — expect a few hours of traffic first.");
  } else {
    for (const a of data.anomalies) {
      const tr = el("tr", { class: "clickable",
                            on: { click: () => openHost(a.src_addr) } }, [
        el("td", { class: "mono", text: fmtTime(a.detected_at) }),
        el("td", {}, [hostCell(a.src_addr, a.hostname)]),
        el("td", { class: "mono", text: (a.anomaly_score ?? 0).toFixed(3) }),
        el("td", {}, [sevCell(a.severity)]),
        el("td", { class: "mono", text: a.baseline_comparison || a.primary_deviation_feature || "—" }),
      ]);
      at.appendChild(tr);
    }
  }

  const tt = document.querySelector("#talkers-table tbody");
  tt.replaceChildren();
  const known = new Set();
  if (!data.top_talkers.length) {
    emptyRow(tt, 4, "No flow volume in the last 24h — check the collector is receiving.");
  } else {
    for (const t of data.top_talkers) {
      known.add(t.src_addr);
      tt.appendChild(el("tr", { class: "clickable",
                                on: { click: () => openHost(t.src_addr) } }, [
        el("td", {}, [hostCell(t.src_addr, t.hostname)]),
        el("td", { class: "mono", text: fmtBytes(t.bytes) }),
        el("td", { class: "mono", text: String(t.flows ?? "—") }),
        el("td", { class: "mono", text: String(t.destinations ?? "—") }),
      ]));
    }
  }
  for (const a of data.anomalies) known.add(a.src_addr);
  const dl = document.getElementById("known-hosts");
  dl.replaceChildren(...[...known].map((h) => el("option", { attrs: { value: h } })));
}

/* ── anomalies ──────────────────────────────────────────────────────────── */

async function loadAnomalies() {
  const min = document.getElementById("f-min-score").value || "0";
  const limit = document.getElementById("f-limit").value || "100";
  const rows = await getJSON(API.anomalies(min, limit));

  const tbody = document.querySelector("#anomalies-table tbody");
  tbody.replaceChildren();
  if (!rows.length) {
    const note = Number(min) > 0
      ? `No anomalies at or above score ${min}.`
      : "No anomalies recorded yet.";
    emptyRow(tbody, 7, note);
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
  const t = d.totals;
  if (!t) {
    stats.appendChild(el("p", { class: "empty",
      text: `No flows from ${d.src_addr} in the last ${d.hours}h.` }));
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
      el("td", {}, [hostCell(x.dst_addr, x.hostname)]),
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
        el("td", {}, [hostCell(f.dst_addr, null)]),
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
        el("td", {}, [hostCell(z.dst_addr, null)]),
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
  const b = document.getElementById("err-banner");
  if (b) b.remove();
}

function showView(name) {
  for (const t of document.querySelectorAll(".tab")) {
    t.classList.toggle("active", t.dataset.view === name);
  }
  for (const v of document.querySelectorAll(".view")) {
    v.classList.toggle("active", v.id === "view-" + name);
  }
  if (name === "anomalies") loadAnomalies().then(clearError).catch(showError);
}

async function refreshAll() {
  try {
    await loadOverview();
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
  for (const id of ["f-min-score", "f-limit"]) {
    document.getElementById(id).addEventListener("change", () => {
      loadAnomalies().then(clearError).catch(showError);
    });
  }
  refreshAll();
  startAuto(15);
});
