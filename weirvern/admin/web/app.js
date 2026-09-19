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
  // The SOC views. `health` is the DEEP check (reads ClickHouse), NOT /api/healthz, which
  // is the Kubernetes liveness probe and answers a bare {"ok":true} without touching the
  // database so a slow database cannot restart the GUI.
  netflow: "/api/netflow",
  zeek: "/api/zeek",
  health: "/api/health",
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

/**
 * A duration in seconds as a compact age. Mirrors status._human_age in the backend so
 * the same figure does not render two different ways in the TUI and the GUI.
 */
// Techniques arrive as JSON in one column. Parsed defensively: a malformed value must
// degrade the technique block, not blank the whole evidence view -- the evidence is what the
// analyst came for.
function parseTechniques(raw) {
  if (!raw) return [];
  if (Array.isArray(raw)) return raw;
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v : [];
  } catch (e) {
    return [];
  }
}

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

/* ── sensor ─────────────────────────────────────────────────────────────── */

/**
 * What the SENSOR says it is doing -- which is not its configured mode.
 *
 * The configured SENSOR_MODE lives in the ConfigMap and survives the sensor dying, so
 * showing it as the current state would display "intercepting 2 hosts" for a process
 * that stopped hours ago. The backend reports a stale heartbeat as not-running, and this
 * must render that as plainly as it renders a healthy sensor -- the failure mode being
 * guarded against is a green panel over a dead sensor.
 */
function renderSensor(s) {
  const box = document.getElementById("sensor-body");
  if (!box) return;
  box.replaceChildren();
  if (!s) { box.appendChild(el("p", { class: "muted", text: "no sensor information" })); return; }

  // The headline fact: running or not, and in which mode.
  const mode = s.mode || "unknown";
  const state = s.running ? "running" : (s.reported ? "NOT running" : "never reported");
  const pill = el("span", {
    class: "pill " + (s.running ? "ok" : "bad"),
    text: mode,
  });

  box.appendChild(el("p", {}, [
    el("strong", { text: "Mode: " }), pill,
    el("span", { class: "muted", text: "  " + state }),
    s.age_s != null
      ? el("span", { class: "muted", text: `  · last heartbeat ${fmtAge(s.age_s)} ago` })
      : el("span", { class: "muted", text: "  · no heartbeat received" }),
  ]));

  if (s.error) {
    box.appendChild(el("p", { class: "banner", text: s.error }));
  }

  // Intercept detail only exists in weir mode. An empty value there means "not
  // applicable", not "unknown", so it is stated rather than left blank.
  if (mode === "weir" && s.reported) {
    box.appendChild(el("p", { class: "muted", text:
      `In-path intercept on ${s.iface || "?"} (${s.segment || "?"}): ` +
      `${s.hosts} host(s), ${s.mappings} ARP mapping(s), up ${fmtAge(s.uptime_s)}` }));
    box.appendChild(el("p", { class: "muted", text:
      `watchdog: ${s.restores} restore(s), ${s.refreshes} refresh(es)` }));
    for (const f of (s.failures || [])) {
      box.appendChild(el("p", { class: "banner", text: "watchdog: " + f }));
    }
  } else if (mode === "loch" && s.reported) {
    box.appendChild(el("p", { class: "muted", text:
      `Passive capture on ${s.iface || "?"} — Weirvern observes only and cannot ` +
      `affect traffic. Nothing is intercepted, so there is nothing to show here.` }));
  }

  // AN INTERCEPT THAT STOPPED IS NOT THE SAME AS NO INTERCEPT.
  //
  // The reader falls back to this passive row once an intercept's heartbeat goes stale, which is
  // right — a stale row must never beat a live one. But it means the panel says "Weirvern cannot
  // affect traffic" about a node where an intercept ran and stopped, and whether the restore
  // happened is exactly what this reader cannot see. If the process was killed before its watchdog
  // restored, the forged ARP mappings are still in the neighbours' caches: the box is in the path
  // and this panel would say it is not.
  //
  // Stated as uncertainty, not as danger. A banner that cries wolf gets ignored, and then the real
  // one is ignored too.
  if (s.intercept_stopped) {
    box.appendChild(el("p", { class: "banner", text:
      "an intercept ran on this sensor and has stopped without reporting a clean restore. " +
      "The mode above describes what is running NOW, not what the node was left in — confirm " +
      "the mappings were withdrawn before trusting this segment's traffic." }));
  }

  // THE OTHER MODES ARE REPORTED, NOT HIDDEN.
  //
  // A sensor can legitimately do both at once: the worker keeps publishing its configured
  // capture mode while an intercept publishes its own row. Showing only the higher-ranked one
  // would be a panel that is silently half the truth -- the same class of wrong as a green
  // panel over a dead sensor.
  for (const o of (s.others || [])) {
    box.appendChild(el("p", { class: "muted", text:
      `also reporting: ${o.mode} on ${o.iface || "?"}` +
      (o.hosts ? ` (${o.hosts} host(s))` : "") +
      ` · heartbeat ${fmtAge(o.age_s)} ago` }));
  }
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

  renderSensor(data.sensor);

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

  const at = document.querySelector("#overview-anomalies tbody");
  at.replaceChildren();
  if (!data.anomalies.length) {
    emptyRow(at, 6, "No anomalies yet. Detection needs a baseline — expect a few hours of traffic first.");
  } else {
    for (const a of data.anomalies) {
      const tr = el("tr", { class: "clickable",
                            on: { click: () => openHost(a.src_addr) } }, [
        el("td", { class: "mono", text: fmtTime(a.detected_at) }),
        el("td", {}, [hostCell(a.src_addr, a.hostname)]),
        el("td", { class: "mono", text: (a.anomaly_score ?? 0).toFixed(3) }),
        el("td", {}, [sevCell(a.severity)]),
        el("td", { class: "mono", text: a.baseline_comparison || a.primary_deviation_feature || "—" }),
        el("td", { class: "mono attack-cell", text: a.attack_label || "—" }),
      ]);
      at.appendChild(tr);
    }
  }

  const tt = document.querySelector("#talkers-table tbody");
  tt.replaceChildren();
  const known = new Set();

  // A BAR CHART BESIDE THE TABLE, not instead of it. The table carries the exact figures an
  // analyst may quote; the bars carry the comparison the table makes you compute. Both read
  // the same rows, so they cannot disagree.
  renderBars("talkers-chart", {
    available: true,
    points: (data.top_talkers || []).map((t) => ({ ...t, label: t.src_addr, value: t.bytes })),
  }, {
    label: (r) => r.src_addr,
    value: (r) => r.bytes,
    format: fmtBytes,
    limit: 10,
    onClick: (r) => openHost(r.src_addr),
    title: (r) => `${r.src_addr} — ${fmtBytes(r.bytes)} / ${r.flows} flows. Click to drill down.`,
    emptyText: "No flow volume in the last 24h — check the collector is receiving.",
  });

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
      el("td", {}, [hostCell(x.dst_addr, x.hostname, d.src_addr)]),
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
    // ── ATT&CK techniques ────────────────────────────────────────────────────
    //
    // Rendered with the evidence and the confidence, never as a bare ID. "T1046" alone
    // reads as a finding; "consistent with T1046 (high) -- 300 distinct destination ports
    // (threshold 100)" can be checked, argued with, and dismissed. Only the second is
    // usable, and only the second is honest.
    //
    // NOTHING is rendered when no technique matched. An empty frame or an explicit "no
    // technique" line would read as a clearance, and absence of a mapping is not that.
    const techs = parseTechniques(d.anomaly.attack_techniques);
    if (techs.length) {
      const box = el("div", { class: "attack" }, [
        el("div", { class: "muted", text: "MITRE ATT&CK — hypotheses supported by these measurements" }),
      ]);
      for (const t of techs) {
        box.appendChild(el("div", { class: "attack-row" }, [
          el("span", { class: "mono attack-id", text: t.id }),
          el("span", { text: t.name }),
          el("span", { class: "attack-meta", text: `${t.tactic} · ${t.confidence} confidence` }),
        ]));
        if (t.evidence && t.evidence.length) {
          box.appendChild(el("ul", { class: "attack-evidence" },
            t.evidence.map((e) => el("li", { class: "muted", text: e }))));
        }
        if (t.network_visibility) {
          box.appendChild(el("div", {
            class: "muted attack-vis",
            text: `network visibility: ${t.network_visibility}`,
            }));
          }
        }
        verdict.appendChild(box);
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
        el("td", {}, [hostCell(f.dst_addr, f.hostname, d.src_addr)]),
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
        el("td", {}, [hostCell(z.dst_addr, z.hostname, d.src_addr)]),
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
  if (name === "models") loadModels().then(clearError).catch(showError);
  // The Assets inventory loads on demand for the same reason the SOC views do: it runs a
  // query per Zeek host table, and firing that every 15s in the background would put load on
  // ClickHouse for a panel nobody is looking at.
  if (name === "host") loadAssets().then(clearError).catch(showError);
  if (name === "network") loadNetwork().then(clearError).catch(showError);
  // The SOC views load on demand rather than on every refresh cycle: they run several
  // aggregate queries each, and firing them every 15s in the background would put load on
  // ClickHouse for panels nobody is looking at.
  if (name === "netflow") loadNetflow().then(clearError).catch(showError);
  if (name === "zeek") loadZeek().then(clearError).catch(showError);
  if (name === "health") loadHealthDeep().then(clearError).catch(showError);
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
  // Onchange rather than a Reload click for a <select>: an operator who picks 24h and
  // then has to press a button has been given a two-step control for a one-step intent.
  const mHours = document.getElementById("m-hours");
  if (mHours) mHours.addEventListener("change", () => loadModels().then(clearError).catch(showError));
  const mReload = document.getElementById("m-reload");
  if (mReload) mReload.addEventListener("click", () => loadModels().then(clearError).catch(showError));
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
  // SOC view controls. Each reload is explicit rather than automatic for the reason given
  // in showView: these run aggregate queries and should not fire on a background timer.
  for (const [id, fn] of [
    ["nf-reload", loadNetflow], ["zk-reload", loadZeek], ["hp-reload", loadHealthDeep],
  ]) {
    const b = document.getElementById(id);
    if (b) b.addEventListener("click", () => fn().then(clearError).catch(showError));
  }
  for (const [id, fn] of [
    ["nf-hours", loadNetflow], ["zk-hours", loadZeek], ["hp-hours", loadHealthDeep],
  ]) {
    const i = document.getElementById(id);
    // onchange rather than a button: picking 24h and then pressing Reload is a two-step
    // control for a one-step intent, which the Models view already settled for this codebase.
    if (i) i.addEventListener("change", () => fn().then(clearError).catch(showError));
  }

  // ── Assets inventory controls ──────────────────────────────────────────────
  // The search filters the CACHED payload rather than refetching: a ClickHouse aggregate
  // behind every keystroke makes typing laggy on a busy segment, and the inventory for one
  // window does not change between keystrokes.
  const asSearch = document.getElementById("as-search");
  if (asSearch) asSearch.addEventListener("input", (e) => {
    ASSETS_STATE.search = e.target.value;
    renderAssets();
  });
  const asSort = document.getElementById("as-sort");
  if (asSort) asSort.addEventListener("change", (e) => {
    ASSETS_STATE.sort = e.target.value;
    renderAssets();
  });
  const asHours = document.getElementById("as-hours");
  if (asHours) asHours.addEventListener("change", (e) => {
    ASSETS_STATE.hours = Number(e.target.value) || 24;
    loadAssets().then(clearError).catch(showError);
  });
  const asReload = document.getElementById("as-reload");
  if (asReload) asReload.addEventListener("click", () => loadAssets().then(clearError).catch(showError));

  // ── Network graph controls ─────────────────────────────────────────────────
  const nwHours = document.getElementById("nw-hours");
  if (nwHours) nwHours.addEventListener("change", (e) => {
    ASSETS_STATE.hours = Number(e.target.value) || 24;
    loadNetwork().then(clearError).catch(showError);
  });
  const nwReload = document.getElementById("nw-reload");
  if (nwReload) nwReload.addEventListener("click", () => loadNetwork().then(clearError).catch(showError));
  const nwClear = document.getElementById("nw-clear");
  if (nwClear) nwClear.addEventListener("click", () => {
    ASSETS_STATE.tracked = [];
    loadNetwork().then(clearError).catch(showError);
  });
  // The edge filter re-renders from the cached payload; it is a view control, not a query.
  const nwMin = document.getElementById("nw-min");
  if (nwMin) nwMin.addEventListener("input", (e) => {
    ASSETS_STATE.minEdges = Number(e.target.value) || 1;
    renderNetwork();
  });
  const nwLabels = document.getElementById("nw-labels");
  if (nwLabels) nwLabels.addEventListener("change", (e) => {
    ASSETS_STATE.showNames = e.target.checked;
    renderNetwork();
  });

  refreshAll();
  startAuto(15);
});

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
  "Isolation Forest": "#4ea1ff",
  "Gradient Boosting": "#5ec26a",
  "DBSCAN": "#e0a34a",
  "Adaptive Baseline": "#c07ad6",
  "Ensemble": "#e05c5c",
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
 * The server computes `stale` so the TUI and the GUI cannot disagree, and the words here state
 * the remedy rather than only the verdict.
 */
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
      el("td", { class: "muted", attrs: { colspan: "4" },
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
      el("td", {}, [age]),
      el("td", {}, [
        r.never_trained
          ? el("span", { class: "sev-medium", text: "never trained" })
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
    const colour = MODEL_COLORS[name] || "#888";
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
  const max = Math.max(1, ...names.flatMap((n) => counts[n]));
  const W = 440, H = 200, PAD = { l: 34, r: 10, t: 10, b: 30 };
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
        fill: MODEL_COLORS[n] || "#888", opacity: 0.85,
      }));
      y -= h;
    }
    axisLabel(svg, plot.l + i * bw + bw / 2, H - 10, (i / 10).toFixed(1));
  }
  svg.appendChild(svgEl("line", { x1: plot.l, y1: plot.b, x2: plot.r, y2: plot.b, class: "axis" }));
  axisLabel(svg, plot.l - 6, plot.t + 10, String(max), "end");
  axisLabel(svg, plot.l - 6, plot.b, "0", "end");
  host.appendChild(svg);
  host.appendChild(el("p", { class: "muted", text: `max ${max} per band, over ${total} score(s)` }));
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
    const colour = MODEL_COLORS[name] || "#888";
    const pct = (c / max) * 100;
    host.appendChild(el("div", { class: "bar-row" }, [
      el("span", { class: "bar-name", text: name, title: name }),
      el("span", { class: "bar-track" }, [
        el("span", { class: "bar-fill", attrs: { style: `width:${pct}%;background:${colour}` } }),
      ]),
      el("span", { class: "bar-val", text: String(c) }),
    ]));
  }
  host.appendChild(el("p", { class: "muted", text:
    "A detector missing here fired on nothing, which is itself worth knowing." }));
}

/** Feature deviations: mean |z| per feature, as horizontal bars against a z=1/2/3 guide. */
function renderFeatureDeviations(rows) {
  const host = document.getElementById("m-features");
  host.innerHTML = "";
  if (!rows || !rows.length) {
    host.appendChild(chartEmpty(
      "No per-feature deviations recorded. These are written from feature_contributions, " +
      "so they appear once an anomaly carries one."));
    return;
  }
  const max = Math.max(1, ...rows.map((r) => r.mean_abs_z), ...rows.map((r) => r.max_abs_z));
  for (const r of rows) {
    const w = (r.mean_abs_z / max) * 100;
    const wMax = (r.max_abs_z / max) * 100;
    host.appendChild(el("div", { class: "bar-row" }, [
      el("span", { class: "bar-name", text: r.feature,
                   title: `${r.feature}: mean |z| ${r.mean_abs_z.toFixed(2)}, peak ${r.max_abs_z.toFixed(2)}, n=${r.n}` }),
      el("span", { class: "bar-track" }, [
        el("span", { class: "bar-fill ghost", attrs: { style: `width:${wMax}%` } }),
        el("span", { class: "bar-fill", attrs: { style: `width:${w}%;background:#4ea1ff` } }),
      ]),
      el("span", { class: "bar-val", text: r.mean_abs_z.toFixed(2) }),
    ]));
  }
  host.appendChild(el("p", { class: "muted", text:
    "Filled bar is the mean deviation; the pale extension is the peak seen. " +
    "z around 1 is normal noise, 3+ is genuinely unusual for that host." }));
}

async function loadModels() {
  const hours = (document.getElementById("m-hours") || {}).value || "72";
  const data = await getJSON("/api/models?hours=" + encodeURIComponent(hours));
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

  renderStaleness(data.staleness || [], data.retrain_interval_h);
  renderTrainingHistory(data.training_history || {});
  renderScoreDistribution(data.scores || {});
  renderAgreement(data.model_counts || {});
  renderFeatureDeviations(data.feature_deviations || []);

  const body = document.querySelector("#m-points tbody");
  body.innerHTML = "";
  if (!(data.points || []).length) {
    body.appendChild(el("tr", {}, [
      el("td", { class: "muted", text: "No anomalies in this window.", attrs: { colspan: 7 } }),
    ]));
    return;
  }
  for (const pt of data.points) {
    const tr = el("tr", { class: "clickable" }, [
      el("td", { class: "num", text: Number(pt.score || 0).toFixed(3) }),
      el("td", { class: "num", text: Number(pt.agreement || 0).toFixed(2) }),
      el("td", {}, [el("span", { class: "sev-" + (pt.severity || "low"), text: pt.severity || "—" })]),
      el("td", { text: (pt.models || []).join(", ") || "—" }),
      el("td", { text: pt.primary || "—" }),
      el("td", { class: "num", text: Number(pt.magnitude || 0).toFixed(2) }),
      el("td", {}, [hostCell(pt.src_addr, pt.hostname)]),
    ]);
    if (pt.src_addr) {
      tr.addEventListener("click", () => { showView("host"); loadHost(pt.src_addr, 24); });
    }
    body.appendChild(tr);
  }
}
