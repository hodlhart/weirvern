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
               title: (r) => `${r.hostname ? r.hostname + " · " : ""}${r.src_addr} — ${fmtBytes(r.bytes)} / ${r.flows} flows. Click to drill down.`,
               emptyText: "No talkers in this window." });

  renderBars("nf-proto", d.protocols,
             { label: (r) => r.label, value: (r) => r.bytes, format: fmtBytes,
               // Clicking a protocol drills into the hosts behind it. A chart that cannot be
               // entered is a report; the SOC requirement is that every bar leads somewhere.
               onClick: (r) => loadFlowDetail({ proto: r.proto, name: r.label }).catch(showError),
               title: (r) => `${r.label}: ${fmtBytes(r.bytes)} across ${r.flows} flows — click for the hosts`,
               emptyText: "No protocol records in this window." });

  renderBars("nf-ports", d.ports,
             { label: (r) => `:${r.port}`, value: (r) => r.bytes, format: fmtBytes,
               onClick: (r) => loadFlowDetail({ port: r.port, name: `port ${r.port}` }).catch(showError),
               title: (r) => `port ${r.port}, proto ${r.proto} — ${r.flows} flows. Click for the hosts.`,
               emptyText: "No destination ports recorded in this window." });

  renderBars("nf-spread", d.spread,
             { label: (r) => r.src_addr, value: (r) => r.destinations,
               format: (v) => `${v} dst`,
               onClick: (r) => openHost(r.src_addr),
               title: (r) => `${r.hostname ? r.hostname + " · " : ""}${r.src_addr} talked to ${r.destinations} distinct destinations`,
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
  // THE ROWS CARRY THE FIELDS THE ACCESSORS READ. Previously this mapped to
  // `{label, value, idx, table}` and then passed accessors reading `r.log` and `r.rows` -- neither
  // of which exists on the mapped object. So label() returned undefined, value() returned
  // undefined, and `format(undefined).toLocaleString()` threw, taking the whole panel down. The
  // Zeek tab rendered a summary and an empty bar chart, which is exactly what "not fully showing
  // data" looked like.
  const logRows = (counts.points || []).map((p, i) => ({
    log: p.log, rows: p.rows, idx: i, table: p.table,
    total: p.total, last_ts: p.last_ts, state: p.state,
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
                   // `r.log`, not `r.label`: the row carries `log` (the Zeek log's name) and
                   // loadZeekLog expects that label, which it validates against ZEEK_LOGS.
                   loadZeekLog(r.log).catch(showError);
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

/** A probe's readable line: its detail, or a compact rendering of its value as a fallback.
 *
 * The server sends both -- `detail` is the sentence ("9/9 present"), `value` is the datum
 * ({"flows": 20, ...}). The panel exists so a person can answer "why is this red"; a cell that
 * shows the datum instead of the sentence cannot, and it was rendering `String(c.value ?? "")`,
 * so the reasons for every failure were dropped on the floor and object values printed as the
 * literal string "[object Object]". Objects and arrays are COUNTED, never stringified.
 */
function probeText(c) {
  const detail = c.detail == null ? "" : String(c.detail);
  if (detail) return detail;
  const v = c.value;
  if (v == null || v === "") return "";
  if (Array.isArray(v)) return `${v.length} item(s)`;
  if (typeof v === "object") {
    const keys = Object.keys(v);
    return keys.length ? `${keys.length} field(s): ${keys.slice(0, 4).join(", ")}` : "{}";
  }
  return String(v);
}

async function loadHealthDeep() {
  const hours = document.getElementById("hp-hours").value || "24";
  const d = await getJSON(`${API.health}?hours=${hours}`);
  if (d.data_error) showError(new Error(d.data_error)); else clearError();

  document.getElementById("hp-window").textContent = `${hours}h window`;
  const h = d.health || {};
  const checks = (h && h.checks) || [];
  // ── THREE STATES, NOT TWO (audit F081) ───────────────────────────────────────────────────────
  //
  // `ok` is tri-state: true, false, or null for NOT APPLICABLE -- a check that ran and had nothing
  // to measure, because the thing it measures is not deployed here. A NetFlow-only cluster has no
  // capture sensor, so Zeek freshness is neither healthy nor broken.
  //
  // `checks.filter((c) => !c.ok)` counted a null as FAILING, and the renderer below painted it red
  // with the text "FAIL". So the very probe added to STOP a missing row reading as healthy would
  // have appeared as a failure in the GUI -- an always-failing check is one an operator stops
  // reading, which is the outcome the tri-state exists to avoid.
  //
  // `n/a` rows are EXCLUDED from the counts rather than shown as passing: they are not evidence
  // either way, and counting them as passing would overstate how much was measured.
  const measurable = checks.filter((c) => c.ok !== null && c.ok !== undefined);
  const bad = measurable.filter((c) => !c.ok).length;
  const notApplicable = checks.length - measurable.length;
  const naSuffix = notApplicable ? `, ${notApplicable} not applicable` : "";
  document.getElementById("hp-summary").textContent = d.health
    ? (bad === 0
        ? `All ${measurable.length} checks passing${naSuffix}.`
        : `${bad} of ${measurable.length} checks FAILING — see below${naSuffix}.`)
    : "Health checks are unavailable — cannot reach ClickHouse.";

  // The header pill. It was populated by the removed Overview loader, so without this it read
  // "loading…" forever -- an element that looks like it is still working when it is not. Health
  // is the view that owns this fact now, so it sets the pill as well as the summary.
  const pill = document.getElementById("health-pill");
  if (pill) {
    if (!d.health) {
      pill.textContent = "no database";
      pill.className = "pill bad";
    } else {
      pill.textContent = `${measurable.length - bad}/${measurable.length} checks passing${naSuffix}`;
      pill.className = "pill " + (h.ok ? "ok" : "bad");
    }
  }
  const fetched = document.getElementById("fetched");
  if (fetched) fetched.textContent = d.health ? "as of " + fmtTime(h.fetched_at) : "";

  renderTimeline("hp-ingest", d.ingest,
                 { emptyText: "No pipeline activity in this window — nothing is being ingested." });

  const tbody = document.querySelector("#hp-checks tbody");
  tbody.replaceChildren();
  for (const c of checks) {
    // THREE STATES RENDERED AS THREE. `c.ok ? ... : ...` put null in the failure branch.
    const notApplicable = c.ok === null || c.ok === undefined;
    const state = notApplicable
      ? el("span", { class: "sev low", text: "n/a" })
      : el("span", { class: c.ok ? "sev low" : "sev high", text: c.ok ? "ok" : "FAIL" });
    tbody.appendChild(el("tr", {}, [
      el("td", { text: c.name }),
      el("td", {}, [state]),
      // THE REASON, NOT THE RAW VALUE. This cell used to render `c.value`, which meant every
      // failure explanation the server sends was thrown away -- the panel said "see below" and
      // then showed an empty cell -- while object values rendered as the literal string
      // "[object Object]". The detail is the sentence an operator reads; the value is a fallback.
      el("td", { class: "mono", text: probeText(c), attrs: { title: probeText(c) } }),
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

  // The sensor block renders INLINE from the same /api/health payload the rest of this view
  // uses. It previously delegated to app.js's renderSensor, which targeted the Overview tab's
  // #sensor-body -- that tab is gone and the function with it, so the sensor's story is told
  // here, once, from the payload already in hand.
  if (d.sensor && Object.keys(d.sensor).length) {
    const host = document.getElementById("hp-sensor");
    host.replaceChildren(el("p", { class: "muted", text: sensorLine(d.sensor) }));
  } else {
    document.getElementById("hp-sensor").replaceChildren(
      el("p", { class: "muted", text: "The sensor has not reported." }));
  }

  // SOC-8: the alert audit. "Nothing fired" and "it fired and was withheld" look identical
  // on every other surface, so the suppressed count is stated in the note rather than left
  // for the reader to infer from a table of outcome rows.
  renderAlertAudit(d.alerts || {});
}

/* The alert audit tables. `reason` is the worker's outcome vocabulary: sent, cooldown,
 * cap, log-only, pushover-error. The note deliberately distinguishes SUPPRESSED (cooldown
 * or cap -- the system chose not to deliver) from LOG-ONLY (nothing was configured to
 * deliver): the second is a configuration state, not a withheld alert, and calling it
 * suppressed would overstate what the system did.
 *
 * BOTH TABLES PAGE 15 AT A TIME, like the Assets inventory. This is the same argument the
 * inventory makes and it applies harder here: an audit trail read as one scroll is skimmed
 * rather than read, and the outcome breakdown can hold a row per reason-per-sent-state while
 * the event list holds up to the fetch cap. Paging state lives in ALERTS_STATE so a re-render
 * (the 15s auto-refresh, or a click on either pager) does not reset the operator's place.
 */
const ALERTS_PAGE_SIZE = 15;
const ALERTS_STATE = {
  reasonsPage: 1,
  recentPage: 1,
  audit: null,   // the last payload, so a pager click re-renders without refetching
};

function renderAlertAudit(a) {
  const note = document.getElementById("hp-alerts-note");
  const rbody = document.querySelector("#hp-alerts-reasons tbody");
  const tbody = document.querySelector("#hp-alerts-recent tbody");
  if (!note || !rbody || !tbody) return;
  note.replaceChildren();
  rbody.replaceChildren();
  tbody.replaceChildren();
  ALERTS_STATE.audit = a;

  if (!a.available) {
    note.appendChild(el("p", { class: "muted", text:
      "Alert audit unavailable — " + (a.reason || "cannot reach ClickHouse") + "." }));
    rbody.appendChild(el("tr", {}, [el("td", { class: "muted", attrs: { colspan: 3 },
                                              text: "—" })]));
    tbody.appendChild(el("tr", {}, [el("td", { class: "muted", attrs: { colspan: 6 },
                                               text: "—" })]));
    // The pagers are cleared rather than left showing the PREVIOUS payload's range: a range
    // line above an unavailable table describes a window that is no longer on screen.
    for (const id of ["hp-alerts-reasons-pager", "hp-alerts-recent-pager"]) {
      const host = document.getElementById(id);
      if (host) host.replaceChildren();
    }
    return;
  }

  const rows = a.by_reason || [];
  const recent = a.recent || [];
  if (!rows.length && !recent.length) {
    note.appendChild(el("p", { class: "muted",
      text: "No alert decisions in this window — nothing fired at all." }));
  } else {
    const suppressed = a.suppressed || 0;
    const logOnly = rows.filter((r) => r.reason === "log-only" && !r.sent)
      .reduce((n, r) => n + r.count, 0);
    const bits = [`${rows.reduce((n, r) => n + r.count, 0)} decision(s) recorded`];
    if (suppressed) bits.push(`${suppressed} suppressed (cooldown or cap)`);
    if (logOnly) {
      bits.push(`${logOnly} log-only — Pushover is not configured, so these were `
        + "recorded, not withheld");
    }
    // A truncated fetch is stated where the count is, because a full page of rows with no
    // note reads as "this is everything". The list is newest-first, so what a cap hides is
    // the OLDER end of the window.
    if (a.truncated) {
      bits.push(`showing the newest ${recent.length} of ${a.total} — older decisions in `
        + "this window are not listed");
    }
    note.appendChild(el("p", { class: "muted", text: bits.join("; ") + "." }));
  }

  // ── the outcome breakdown, paged ─────────────────────────────────────────────────────────
  const rpages = Math.max(1, Math.ceil(rows.length / ALERTS_PAGE_SIZE));
  if (ALERTS_STATE.reasonsPage > rpages) ALERTS_STATE.reasonsPage = rpages;
  if (ALERTS_STATE.reasonsPage < 1) ALERTS_STATE.reasonsPage = 1;
  const rfrom = (ALERTS_STATE.reasonsPage - 1) * ALERTS_PAGE_SIZE;
  for (const r of rows.slice(rfrom, rfrom + ALERTS_PAGE_SIZE)) {
    const label = r.reason === "log-only"
      ? "log-only (not configured)"
      : (r.sent ? "sent" : `${r.reason} (suppressed)`);
    rbody.appendChild(el("tr", {}, [
      el("td", { text: label }),
      el("td", { class: "num", text: String(r.count) }),
      el("td", { class: "mono", text: fmtTime(r.last_at) }),
    ]));
  }
  if (!rows.length) {
    emptyRow(rbody, 3, "no decisions in this window");
  }
  renderPager("hp-alerts-reasons-pager", rows.length, ALERTS_STATE.reasonsPage, rpages,
    (next) => { ALERTS_STATE.reasonsPage = next; renderAlertAudit(ALERTS_STATE.audit); },
    ALERTS_PAGE_SIZE);

  // ── the events themselves, paged ─────────────────────────────────────────────────────────
  const names = a.names || {};
  const pages = Math.max(1, Math.ceil(recent.length / ALERTS_PAGE_SIZE));
  if (ALERTS_STATE.recentPage > pages) ALERTS_STATE.recentPage = pages;
  if (ALERTS_STATE.recentPage < 1) ALERTS_STATE.recentPage = 1;
  const from = (ALERTS_STATE.recentPage - 1) * ALERTS_PAGE_SIZE;
  for (const ev of recent.slice(from, from + ALERTS_PAGE_SIZE)) {
    tbody.appendChild(el("tr", {}, [
      el("td", { class: "mono", text: fmtTime(ev.sent_at) }),
      el("td", {}, [hostCell(ev.src_addr, names[ev.src_addr])]),
      el("td", {}, [el("span", { class: "sev " + (ev.severity || "low"),
                                 text: ev.severity || "" })]),
      el("td", { class: "num", text: Number(ev.score || 0).toFixed(2) }),
      el("td", { text: ev.sent ? "sent" : ev.reason }),
      // The message the worker WOULD have sent, or did. It was already in the payload and
      // never rendered -- so an operator could see that a decision was made without seeing
      // what it was about, which is the half of the audit that makes a suppression
      // reviewable. Shortened: this is a table cell, and the full text belongs in the title.
      el("td", { class: "muted", title: ev.message || "",
                 text: (ev.message || "").split("\n")[0].slice(0, 80) }),
    ]));
  }
  if (!recent.length) {
    emptyRow(tbody, 6, "no decisions in this window");
  }
  renderPager("hp-alerts-recent-pager", recent.length, ALERTS_STATE.recentPage, pages,
    (next) => { ALERTS_STATE.recentPage = next; renderAlertAudit(ALERTS_STATE.audit); },
    ALERTS_PAGE_SIZE);
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



