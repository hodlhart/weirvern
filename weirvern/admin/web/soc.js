/* SOC views: Netflow, Zeek, Health.
 *
 * WHY THESE ARE CHARTS AND NOT TABLES. An analyst's first question is shape -- is traffic
 * rising, is one host an outlier, did a log stop arriving -- and a table of numbers makes
 * that question cost a mental diff between two screenshots. A chart answers it in one look.
 *
 * NO LIBRARY, AND THAT IS A HARD REQUIREMENT, NOT A PREFERENCE. The existing Models view
 * explains why: this runs on an isolated sensor network, so "a charting library fetched
 * from the internet is a chart that does not render in the environment this is built for".
 * Everything here is hand-rolled SVG on top of the existing chartFrame/svgEl/axisLabel
 * helpers, sharing the same colour dictionary so the two views agree.
 *
 * EVERY PANEL DISTINGUISHES THREE STATES, because they need different actions:
 *
 *   data           -> draw it
 *   available=false -> "the query failed: <reason>"     (something is broken)
 *   no points       -> "nothing recorded in this window" (nothing has happened yet)
 *
 * Collapsing the last two into one empty box is the defect this project has shipped
 * repeatedly: a permanently-empty panel looks exactly like a quiet network.
 */

// Shares MODEL_COLORS where the series are the same things (models), and adds its own for
// log families. Kept separate from MODEL_COLORS so a colour change to one cannot silently
// recolour the other.
const SOC_COLORS = {
  conn: "#4ea1ff", dns: "#5ec26a", ssl: "#e0a34a", http: "#c07ad6",
  ssh: "#e05c5c", notice: "#8899aa",
  flows: "#4ea1ff", windows: "#5ec26a", anomalies: "#e05c5c", models: "#c07ad6",
};

const SOC_PALETTE = ["#4ea1ff", "#5ec26a", "#e0a34a", "#c07ad6", "#e05c5c", "#8899aa",
                     "#6fd3c7", "#d98cb3", "#a8b545", "#7f8cff"];

/** A panel that states which of the three states it is in, in words. */
function socPanel(hostId, res, emptyText) {
  const host = document.getElementById(hostId);
  if (!host) return null;
  host.replaceChildren();
  if (!res || res.available === false) {
    const why = (res && res.reason) ? res.reason : "the query did not run";
    host.appendChild(chartEmpty(`Cannot draw this: ${why}.`));
    return null;
  }
  if (!(res.points || []).length) {
    host.appendChild(chartEmpty(emptyText || "Nothing recorded in this window."));
    return null;
  }
  return host;
}

/** Horizontal bars, one per row, with a value axis implied by bar length.
 *
 * Horizontal rather than vertical because every series here has TEXT labels (host
 * addresses, service names, DNS names, table names) and rotated vertical labels are
 * unreadable at 15+ characters. Bars are proportional to the max, and the top bar is
 * always full width -- a chart scaled to something other than its own maximum would show
 * differences that are not there.
 *
 * USES THE EXISTING .bar-row/.bar-name/.bar-track/.bar-fill/.bar-val CLASSES, which the
 * Models view already styles. Inventing parallel class names would have meant either a
 * second set of near-identical CSS rules or -- worse -- bars that render unstyled and look
 * like a layout bug.
 *
 * `onClick(value)` makes rows drillable. That is the SOC requirement: a bar is not a
 * decoration, it is the way into the next question.
 */
function renderBars(hostId, res, opts = {}) {
  const host = socPanel(hostId, res, opts.emptyText);
  if (!host) return;

  const rows = res.points.slice(0, opts.limit || 12);
  const label = opts.label || ((r) => String(r.label ?? r.host ?? r.name ?? ""));
  const value = opts.value || ((r) => Number(r.bytes ?? r.n ?? r.value ?? 0));
  const fmt = opts.format || ((v) => String(v));
  const max = Math.max(1, ...rows.map((r) => value(r)));

  rows.forEach((r, idx) => {
    const v = value(r);
    const pct = Math.max(2, Math.round((v / max) * 100));
    const colour = opts.colour ? opts.colour(r, idx) : SOC_PALETTE[idx % SOC_PALETTE.length];
    const row = el("div", { class: "bar-row" + (opts.onClick ? " clickable" : "") }, [
      el("span", { class: "bar-name", text: label(r), title: label(r) }),
      el("span", { class: "bar-track" }, [
        el("span", { class: "bar-fill", attrs: { style: `width:${pct}%;background:${colour}` } }),
      ]),
      el("span", { class: "bar-val", text: fmt(v) }),
    ]);
    if (opts.onClick) {
      row.addEventListener("click", () => opts.onClick(r));
      row.setAttribute("title", opts.title ? opts.title(r) : `drill into ${label(r)}`);
    }
    host.appendChild(row);
  });
}

/** Stacked line chart: several series on one time axis, each its own colour.
 *
 * LOG-SCALE Y BY DEFAULT, because the series in these views differ by orders of magnitude
 * (conn.log against notice.log, raw flows against anomalies). On a linear axis everything
 * small is a flat line on the floor -- technically correct and useless, which is why the
 * Models training-history chart made the same choice for the same reason.
 */
function renderTimeline(hostId, res, opts = {}) {
  const host = document.getElementById(hostId);
  if (!host) return;
  host.replaceChildren();

  if (!res || res.available === false) {
    host.appendChild(chartEmpty(`Cannot draw this: ${(res && res.reason) || "the query did not run"}.`));
    return;
  }
  const series = Object.entries((res && res.series) || {}).filter(([, p]) => p && p.length);
  if (!series.length) {
    host.appendChild(chartEmpty(opts.emptyText || "Nothing recorded in this window."));
    return;
  }

  const W = 900, H = 220, PAD = { l: 60, r: 14, t: 12, b: 30 };
  const { svg, plot } = chartFrame(W, H, PAD);

  const allT = series.flatMap(([, p]) => p.map((x) => new Date(x.t).getTime()));
  const tMin = Math.min(...allT), tMax = Math.max(...allT);
  const span = Math.max(1, tMax - tMin);
  const maxN = Math.max(1, ...series.flatMap(([, p]) => p.map((x) => Number(x.n) || 0)));

  const xOf = (t) => plot.l + ((t - tMin) / span) * (plot.r - plot.l);
  const lmax = Math.log10(Math.max(10, maxN));
  const yOf = (n) => plot.b - (Math.log10(Math.max(1, n)) / lmax) * (plot.b - plot.t);

  for (let d = 0; d <= Math.floor(lmax); d++) {
    const y = plot.b - (d / lmax) * (plot.b - plot.t);
    svg.appendChild(svgEl("line", { x1: plot.l, y1: y, x2: plot.r, y2: y, class: "grid" }));
    const v = Math.pow(10, d);
    axisLabel(svg, plot.l - 6, y + 4, v >= 1000 ? `${v / 1000}k` : String(v), "end");
  }
  svg.appendChild(svgEl("line", { x1: plot.l, y1: plot.b, x2: plot.r, y2: plot.b, class: "axis" }));
  svg.appendChild(svgEl("line", { x1: plot.l, y1: plot.t, x2: plot.l, y2: plot.b, class: "axis" }));
  axisLabel(svg, plot.l, H - 8, fmtTime(new Date(tMin)), "start");
  axisLabel(svg, plot.r, H - 8, fmtTime(new Date(tMax)), "end");

  const legend = el("div", { class: "legend" }, []);
  series.forEach(([name, pts], idx) => {
    const colour = SOC_COLORS[name] || SOC_PALETTE[idx % SOC_PALETTE.length];
    const d = pts.map((p, i) =>
      `${i ? "L" : "M"}${xOf(new Date(p.t).getTime()).toFixed(1)},${yOf(Number(p.n) || 0).toFixed(1)}`
    ).join(" ");
    svg.appendChild(svgEl("path", { d, fill: "none", stroke: colour, "stroke-width": 1.7 }));
    const total = pts.reduce((a, p) => a + (Number(p.n) || 0), 0);
    legend.appendChild(el("span", { class: "legend-item" }, [
      el("span", { class: "legend-swatch", attrs: { style: `background:${colour}` } }),
      el("span", { text: `${name} — ${total.toLocaleString()} row(s) in window` }),
    ]));
  });
  host.appendChild(svg);
  host.appendChild(legend);
}

/* ── Netflow ────────────────────────────────────────────────────────────────────────── */

async function loadNetflow() {
  const hours = document.getElementById("nf-hours").value || "24";
  const d = await getJSON(`${API.netflow}?hours=${hours}`);
  if (d.data_error) showError(new Error(d.data_error)); else clearError();

  document.getElementById("nf-window").textContent =
    `${hours}h window, ${d.volume && d.volume.bucket_s ? Math.round(d.volume.bucket_s / 60) + "m buckets" : ""}`;
  const totalBytes = ((d.volume && d.volume.points) || []).reduce((a, p) => a + p.bytes, 0);
  const totalFlows = ((d.volume && d.volume.points) || []).reduce((a, p) => a + p.flows, 0);
  document.getElementById("nf-summary").textContent = (d.volume && d.volume.available)
    ? `${fmtBytes(totalBytes)} across ${totalFlows.toLocaleString()} flows in the last ${hours}h.`
    : "Flow volume is unavailable — see the panel below.";

  // Volume as a line: bytes per bucket.
  const volSeries = { flows: (((d.volume || {}).points) || []).map((p) => ({ t: p.t, n: p.bytes })) };
  renderTimeline("nf-volume", { available: (d.volume || {}).available !== false,
                                reason: (d.volume || {}).reason, series: volSeries },
                 { emptyText: "No flow windows recorded — NetFlow may not be arriving." });

  renderBars("nf-talkers", { available: true, points: (d.talkers || []).map((t) => ({ ...t, label: t.src_addr, value: t.bytes })) },
             { label: (r) => r.src_addr, value: (r) => r.bytes, format: fmtBytes,
               onClick: (r) => openHost(r.src_addr),
               title: (r) => `${r.src_addr} — ${fmtBytes(r.bytes)} / ${r.flows} flows. Click to drill down.`,
               emptyText: "No talkers in this window." });

  renderBars("nf-proto", d.protocols,
             { label: (r) => r.label, value: (r) => r.bytes, format: fmtBytes,
               emptyText: "No protocol records in this window." });

  renderBars("nf-ports", d.ports,
             { label: (r) => `:${r.port}`, value: (r) => r.bytes, format: fmtBytes,
               title: (r) => `port ${r.port}, proto ${r.proto} — ${r.flows} flows`,
               emptyText: "No destination ports recorded in this window." });

  renderBars("nf-spread", d.spread,
             { label: (r) => r.src_addr, value: (r) => r.destinations,
               format: (v) => `${v} dst`,
               onClick: (r) => openHost(r.src_addr),
               title: (r) => `${r.src_addr} talked to ${r.destinations} distinct destinations`,
               emptyText: "No fan-out recorded in this window." });
}

/* ── Zeek ───────────────────────────────────────────────────────────────────────────── */

async function loadZeek() {
  const hours = document.getElementById("zk-hours").value || "24";
  const d = await getJSON(`${API.zeek}?hours=${hours}`);
  if (d.data_error) showError(new Error(d.data_error)); else clearError();

  const counts = d.counts || {};
  document.getElementById("zk-window").textContent = `${hours}h window`;
  const total = (counts.points || []).reduce((a, p) => a + p.rows, 0);
  const written = (counts.points || []).filter((p) => p.rows > 0).length;
  document.getElementById("zk-summary").textContent = counts.available === false
    ? "Zeek counts are unavailable — the sensor may not be running."
    : `${total.toLocaleString()} rows from ${written} of ${(counts.points || []).length} configured logs in the last ${hours}h.`;

  renderTimeline("zk-timeline", d.timeline,
                 { emptyText: "No Zeek records in this window — is the sensor capturing?" });

  // Log volume: which logs are actually arriving. Bars rather than a table so "one log has
  // stopped" is visible at a glance.
  //
  // CLICKING A BAR DRILLS IN, which is what makes this a SOC view rather than a report: the
  // bar answers "is ssl.log busy" and the next question is always "busy with whom". The
  // handler lives in assets.js because the drill-down needs the same address validation and
  // the same host click-through the other views use.
  const logRows = (counts.points || []).map((p, i) => ({
    label: p.log, value: p.rows, idx: i, table: p.table,
  }));
  renderBars("zk-counts", { available: counts.available !== false, reason: counts.reason, points: logRows },
             { label: (r) => r.log, value: (r) => r.rows, format: (v) => v.toLocaleString(),
               colour: (r) => SOC_PALETTE[r.idx % SOC_PALETTE.length],
               limit: 18,
               title: (r) => `${r.log} -> weirvern.${r.table}: ${r.rows} row(s) — click to see the hosts`,
               emptyText: "No Zeek log has written a row in this window.",
               // A log with zero rows has nothing to drill into; offering the click would be a
               // dead end that looks like a broken feature.
               onClick: (r) => {
                 if (r.rows > 0 && typeof loadZeekLog === "function") {
                   loadZeekLog(r.label).catch(showError);
                 }
               } });
  // A ZERO NEEDS ITS REASON. The bar chart shows what is in the window; this line explains the
  // bars that are zero, which is the question an operator is actually asking. Before this, a
  // wall of zeros read as a broken dashboard when the truth was that http/ssh/files had rows
  // from ~40h earlier and simply none inside the default 24h window.
  const zeroed = (counts.points || []).filter((p) => p.rows === 0 && (p.total || 0) > 0);
  const never = (counts.points || []).filter((p) => (p.total || 0) === 0 && p.rows === 0);
  if (zeroed.length) {
    const oldest = zeroed
      .map((p) => p.last_ts)
      .filter(Boolean)
      .sort()[0];
    document.getElementById("zk-counts").appendChild(chartEmpty(
      `${zeroed.length} log${zeroed.length === 1 ? "" : "s"} recorded nothing in this window but `
      + `have rows from earlier: ${zeroed.map((p) => p.log).join(", ")}. The newest of those rows `
      + `is ${oldest ? fmtTime(oldest) : "unknown"} — widen the window to see them.`));
  }
  if (never.length) {
    document.getElementById("zk-counts").appendChild(chartEmpty(
      `${never.length} log${never.length === 1 ? "" : "s"} have NEVER produced a row `
      + `(${never.map((p) => p.log).join(", ")}). That is a different fact from a quiet window: `
      + `either the traffic does not exist on this segment or the analyzer is not enabled.`));
  }
  if ((counts.unreadable || []).length) {
    document.getElementById("zk-counts").appendChild(chartEmpty(
      `Could not count: ${counts.unreadable.join(", ")} — these are unreadable, which is not the same as empty.`));
  }

  renderBars("zk-services", d.services,
             { label: (r) => r.service, value: (r) => r.n, format: (v) => v.toLocaleString(),
               emptyText: "No services observed — conn.log has no service values in this window." });

  renderBars("zk-dns", d.dns,
             { label: (r) => r.query, value: (r) => r.n, format: (v) => v.toLocaleString(),
               limit: 20,
               title: (r) => `${r.query} — ${r.n} queries from ${r.askers} host(s)`,
               emptyText: "No multi-label DNS queries in this window." });
  if (d.dns && d.dns.filtered) {
    document.getElementById("zk-dns").appendChild(chartEmpty(d.dns.filtered));
  }
}

/* ── Health (deep) ──────────────────────────────────────────────────────────────────── */

async function loadHealthDeep() {
  const hours = document.getElementById("hp-hours").value || "24";
  const d = await getJSON(`${API.health}?hours=${hours}`);
  if (d.data_error) showError(new Error(d.data_error)); else clearError();

  document.getElementById("hp-window").textContent = `${hours}h window`;
  const h = d.health || {};
  const checks = (h && h.checks) || [];
  const bad = checks.filter((c) => !c.ok).length;
  document.getElementById("hp-summary").textContent = d.health
    ? (bad === 0 ? `All ${checks.length} checks passing.` : `${bad} of ${checks.length} checks FAILING — see below.`)
    : "Health checks are unavailable — cannot reach ClickHouse.";

  renderTimeline("hp-ingest", d.ingest,
                 { emptyText: "No pipeline activity in this window — nothing is being ingested." });

  const tbody = document.querySelector("#hp-checks tbody");
  tbody.replaceChildren();
  for (const c of checks) {
    tbody.appendChild(el("tr", {}, [
      el("td", { text: c.name }),
      el("td", {}, [el("span", { class: c.ok ? "sev low" : "sev high", text: c.ok ? "ok" : "FAIL" })]),
      el("td", { class: "mono", text: String(c.value ?? "") }),
      el("td", { text: c.latency_ms != null ? `${c.latency_ms} ms` : "" }),
    ]));
  }
  if (!checks.length) {
    tbody.appendChild(el("tr", {}, [el("td", { attrs: { colspan: "4" },
      text: d.health ? "no checks reported" : "health unavailable" })]));
  }

  const stbody = document.querySelector("#hp-tables tbody");
  stbody.replaceChildren();
  for (const t of ((d.tables || {}).points || [])) {
    stbody.appendChild(el("tr", {}, [
      el("td", { class: "mono", text: t.table }),
      el("td", { text: t.rows.toLocaleString() }),
      el("td", { text: fmtBytes(t.bytes) }),
    ]));
  }
  if (!((d.tables || {}).points || []).length) {
    stbody.appendChild(el("tr", {}, [el("td", { attrs: { colspan: "3" },
      text: (d.tables || {}).available === false ? `unavailable: ${d.tables.reason}` : "no tables" })]));
  }

  // The sensor block reuses the Overview renderer so the two agree by construction -- they
  // read the same payload field and must not drift into two different stories. `renderSensor`
  // targets #sensor-body by design (one sensor panel, one renderer); the Health view shows the
  // same facts inline, so it reuses the SAME function with the same target rather than
  // duplicating the logic and risking two versions of the sensor's story.
  if (d.sensor && Object.keys(d.sensor).length) {
    const host = document.getElementById("hp-sensor");
    host.replaceChildren(el("p", { class: "muted", text: sensorLine(d.sensor) }));
  } else {
    document.getElementById("hp-sensor").replaceChildren(
      el("p", { class: "muted", text: "The sensor has not reported." }));
  }
}

/** One sentence of sensor state, from the fields the heartbeat actually carries.
 *
 * Deliberately a summary rather than a second renderer: the Overview view owns the full
 * sensor panel, and the point of repeating it here is a one-line cross-check, not a rival
 * account of the same facts.
 */
function sensorLine(s) {
  const state = s.running ? "running" : (s.reported ? "NOT running" : "never reported");
  const bits = [`mode ${s.mode || "unknown"}`, state];
  if (s.iface) bits.push(`on ${s.iface}`);
  if (s.hosts) bits.push(`${s.hosts} host(s) intercepted`);
  if (s.age_s != null) bits.push(`heartbeat ${fmtAge(s.age_s)} ago`);
  // An intercept that ran and stopped: the node may still be in-path, and this is the field
  // that says so rather than letting a passive row imply the segment is untouched.
  if (s.intercept_stopped) bits.push("an intercept ran and stopped — confirm the node was restored");
  return bits.join(" · ");
}



