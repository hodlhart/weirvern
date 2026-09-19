/* Assets (inventory) and Network (connection graph).
 *
 * WHY A THIRD SCRIPT. `app.js` owns the original views and the shared helpers; `soc.js` owns
 * the traffic-shape views. These two are a third kind of question -- "which hosts EXIST" and
 * "how are they CONNECTED" -- and they need a force layout that neither of the others has.
 * Keeping them separate means the graph code can be read on its own, and a bug in the layout
 * cannot take the anomaly table down with it.
 *
 * EVERYTHING IS HAND-ROLLED SVG, for the reason stated at the top of app.js: the GUI is
 * deliberately dependency-free because it has to work on an isolated sensor network, and a
 * charting library fetched from a CDN is a chart that does not render there.
 *
 * BOTH VIEWS STATE WHAT IS ABSENT. Every panel either draws real data or says in words what is
 * missing and why. A short asset list and a failed query look identical on screen otherwise --
 * and this codebase has shipped that bug more than once.
 */

const ASSET_API = {
  assets: (hours) => `/api/assets?hours=${hours}`,
  graph: (hours, hosts) =>
    `/api/graph?hours=${hours}` +
    (hosts && hosts.length ? hosts.map((h) => `&host=${encodeURIComponent(h)}`).join("") : ""),
  zeeklog: (log, hours) => `/api/zeeklog?log=${encodeURIComponent(log)}&hours=${hours}`,
};

/* State kept in one place: the hosts the operator has chosen to track, and the raw payload so
 * a re-render (a sort, a filter keystroke) does not refetch. Re-querying on every keystroke
 * would put a ClickHouse aggregate behind a text input. */
const ASSETS_STATE = {
  hours: 24,
  inventory: null,   // the /api/assets payload
  graph: null,       // the /api/graph payload
  tracked: [],       // addresses the operator selected on the Network view
  sort: "anomalies",
  search: "",
  minEdges: 1,
  showNames: false,
};

async function getJSON(url) {
  const r = await fetch(url, { headers: { Accept: "application/json" } });
  if (!r.ok) {
    let detail = "";
    try { detail = (await r.json()).error || ""; } catch (_) { /* non-JSON error body */ }
    throw new Error(detail || `${r.status} ${r.statusText}`);
  }
  return r.json();
}

/* ── Assets: the inventory ─────────────────────────────────────────────────── */

function loadAssets() {
  const hours = ASSETS_STATE.hours;
  return getJSON(ASSET_API.assets(hours))
    .then((d) => {
      ASSETS_STATE.inventory = d;
      renderAssets();
    })
    .catch((err) => {
      ASSETS_STATE.inventory = {
        available: false, hosts: [], reason: err.message,
      };
      renderAssets();
    });
}

/** Sort + filter + render the inventory, from the cached payload. */
function renderAssets() {
  const tbody = document.querySelector("#as-table tbody");
  const note = document.getElementById("as-note");
  const empty = document.getElementById("as-empty");
  const summary = document.getElementById("as-summary");
  if (!tbody) return;

  const d = ASSETS_STATE.inventory || {};
  note.replaceChildren();
  empty.textContent = "";

  if (d.available === false) {
    summary.textContent = "";
    tbody.replaceChildren();
    note.appendChild(el("p", { class: "muted", text: `Cannot list assets: ${d.reason}.` }));
    return;
  }

  const all = d.hosts || [];
  // Search matches the address, the reverse-DNS name, or a service -- an analyst looking for
  // "everything that spoke smb" has a service name, not an address.
  const q = ASSETS_STATE.search.trim().toLowerCase();
  const rows = q
    ? all.filter((h) =>
        h.addr.toLowerCase().includes(q) ||
        (h.name || "").toLowerCase().includes(q) ||
        (h.services || []).some((s) => s.toLowerCase().includes(q)))
    : all;

  const sorters = {
    anomalies: (a, b) => (b.anomalies - a.anomalies) || (b.bytes - a.bytes),
    bytes: (a, b) => b.bytes - a.bytes,
    flows: (a, b) => b.flows - a.flows,
    addr: (a, b) => a.addr.localeCompare(b.addr),
    name: (a, b) => (a.name || "~").localeCompare(b.name || "~"),
  };
  rows.sort(sorters[ASSETS_STATE.sort] || sorters.anomalies);

  summary.textContent = q
    ? `${rows.length} of ${all.length} hosts matching “${ASSETS_STATE.search}”`
    : `${all.length} hosts in the last ${d.hours}h`;

  // The unreadable sources are named, because a short list must never be mistaken for a
  // quiet network.
  if ((d.unreadable || []).length) {
    note.appendChild(el("p", {
      class: "muted",
      text: `Not counted: ${d.unreadable.join(", ")} could not be read. Hosts that appear only ` +
            `in those logs are missing from this list.`,
    }));
  }
  if ((d.sources_failed || []).length) {
    note.appendChild(el("p", {
      class: "muted",
      text: `Some figures are incomplete: the ${d.sources_failed.join(", ")} query did not run.`,
    }));
  }

  tbody.replaceChildren();
  if (!rows.length) {
    tbody.replaceChildren(el("tr", {}, [
      el("td", {
        class: "empty", attrs: { colspan: "9" },
        text: q ? `No host matches “${ASSETS_STATE.search}”.`
                : "No host has been seen in this window.",
      }),
    ]));
    return;
  }

  // Only the first N rows are drawn. A /24 is ~250 rows and a busy segment far more; past a
  // few hundred the table stops being readable and starts being a scroll test.
  const LIMIT = 250;
  for (const h of rows.slice(0, LIMIT)) {
    const tr = el("tr", { class: "clickable" }, [
      el("td", { class: "link", text: h.addr, title: `drill into ${h.addr}` }),
      el("td", { class: "muted", text: h.name || "—" }),
      el("td", { class: "mono", text: fmtBytes(h.bytes) }),
      el("td", {
        class: "mono",
        // The direction split is unavailable if the raw-flows query failed; showing "0 / 0"
        // would claim a measurement that was never made.
        text: (h.bytes_out === undefined && h.bytes_in === undefined)
          ? "—"
          : `${fmtBytes(h.bytes_out)} / ${fmtBytes(h.bytes_in)}`,
      }),
      el("td", { class: "mono", text: String(h.flows) }),
      el("td", { class: "mono", text: String(h.dst_count) }),
      el("td", { class: "muted", text: (h.services || []).join(", ") || "—" }),
      el("td", {
        class: h.anomalies ? "mono" : "mono muted",
        text: h.anomalies ? String(h.anomalies) : "0",
      }),
      el("td", { class: "mono muted", text: fmtTime(h.last_seen) }),
    ]);
    tr.addEventListener("click", (ev) => {
      // Shift-click tracks instead of drilling, so the inventory feeds the graph without a
      // round trip through the Network tab's own controls.
      if (ev.shiftKey) { ev.preventDefault(); toggleTracked(h.addr); return; }
      openHost(h.addr);
    });
    tr.title = "click to drill down · shift-click to track on the Network graph";
    tbody.appendChild(tr);
  }

  if (rows.length > LIMIT) {
    empty.textContent =
      `Showing the first ${LIMIT} of ${rows.length}. Narrow the search or window to see the rest.`;
  }

  // Feed the drill-down datalist, so typing an address is a suggestion not a memory test.
  const dl = document.getElementById("known-hosts");
  if (dl) {
    dl.replaceChildren(...all.slice(0, 300).map((h) =>
      el("option", { attrs: { value: h.addr, label: h.name || h.addr } })));
  }
}

/* ── Network: the connection graph ─────────────────────────────────────────── */

function loadNetwork() {
  const hosts = ASSETS_STATE.tracked;
  return getJSON(ASSET_API.graph(ASSETS_STATE.hours, hosts))
    .then((d) => {
      ASSETS_STATE.graph = d;
      renderNetwork();
    })
    .catch((err) => {
      ASSETS_STATE.graph = { available: false, nodes: [], edges: [], reason: err.message };
      renderNetwork();
    });
}

function toggleTracked(addr) {
  const i = ASSETS_STATE.tracked.indexOf(addr);
  if (i >= 0) ASSETS_STATE.tracked.splice(i, 1);
  else if (ASSETS_STATE.tracked.length < 64) ASSETS_STATE.tracked.push(addr);
  renderChips();
  loadNetwork();
}

function renderChips() {
  const box = document.getElementById("nw-selected");
  if (!box) return;
  box.replaceChildren();
  if (!ASSETS_STATE.tracked.length) {
    box.appendChild(el("span", {
      class: "muted",
      text: "No hosts selected — showing every connection. Click a node or a bar to track specific hosts.",
    }));
    return;
  }
  box.appendChild(el("span", { class: "muted", text: "Tracking:" }));
  for (const addr of ASSETS_STATE.tracked) {
    const chip = el("span", { class: "chip", title: "click to stop tracking this host" }, [
      el("span", { text: addr }),
      el("span", { class: "x", text: "×" }),
    ]);
    chip.addEventListener("click", () => toggleTracked(addr));
    box.appendChild(chip);
  }
}

function renderNetwork() {
  const host = document.getElementById("nw-graph");
  const caption = document.getElementById("nw-caption");
  const table = document.querySelector("#nw-table tbody");
  const d = ASSETS_STATE.graph || {};
  if (!host) return;

  renderChips();
  host.replaceChildren();
  table.replaceChildren();

  if (d.available === false) {
    caption.textContent = "";
    host.appendChild(chartEmpty(`Cannot draw the graph: ${d.reason}.`));
    emptyRow(table, 5, "No edges to show.");
    return;
  }

  // The window the graph covers. Every sibling view states this; leaving it blank made the
  // heading read as a panel that had failed to load.
  const win = document.getElementById("nw-window");
  if (win) {
    const h = d.hours || ASSETS_STATE.hours;
    win.textContent = `${h}h window` + (d.truncated ? `, ${d.total_edges} total edges` : "");
  }

  const nodes = d.nodes || [];
  const edges = (d.edges || []).filter((e) => e.flows >= ASSETS_STATE.minEdges);
  if (!nodes.length || !edges.length) {
    caption.textContent = ASSETS_STATE.tracked.length
      ? `No connections among the tracked hosts in the last ${d.hours || ASSETS_STATE.hours}h.`
      : `No host-to-host traffic in the last ${d.hours || ASSETS_STATE.hours}h.`;
    host.appendChild(chartEmpty(
      ASSETS_STATE.tracked.length
        ? "These hosts did not talk to each other in this window. Widen the window or clear the selection."
        : "No host-to-host traffic was recorded. Broadcast and self-directed traffic is excluded."));
    emptyRow(table, 5, "No edges to show.");
    return;
  }

  // The caption reports what was actually drawn, and says so when the edge cap truncated the
  // set -- a graph silently missing hosts looks complete.
  const bits = [`${nodes.length} hosts`, `${edges.length} connections`];
  if (ASSETS_STATE.tracked.length) bits.push(`filtered to ${ASSETS_STATE.tracked.length} tracked`);
  if (d.truncated) bits.push(`of ${d.total_edges} total edges (capped)`);
  caption.textContent = bits.join(" · ");

  drawGraph(host, nodes, edges, d.truncated);

  // The busiest edges, clickable to track either endpoint.
  renderBars("nw-edges", {
    available: true, points: edges.slice(0, 12).map((e) => ({
      label: `${e.source} → ${e.target}`, value: e.bytes, edge: e,
    })),
  }, {
    onClick: (r) => { toggleTracked(r.edge.source); },
    colour: () => "#4ea1ff",
    format: (v) => fmtBytes(v),
    title: (r) => `track ${r.edge.source}`,
  });

  // Most connected hosts, clickable to track.
  renderBars("nw-nodes", {
    available: true, points: nodes.slice(0, 12).map((n) => ({
      label: n.name || n.id, value: n.degree, node: n,
    })),
  }, {
    onClick: (r) => toggleTracked(r.node.id),
    colour: (r) => (ASSETS_STATE.tracked.includes(r.node.id) ? "#5ec26a" : "#8899aa"),
    format: (v) => `${v} peers`,
    title: (r) => (ASSETS_STATE.tracked.includes(r.node.id)
      ? `stop tracking ${r.node.id}` : `track ${r.node.id}`),
  });

  for (const e of edges.slice(0, 200)) {
    const tr = el("tr", {}, [
      el("td", { class: "link mono", text: e.source }),
      el("td", { class: "link mono", text: e.target }),
      el("td", { class: "mono", text: fmtBytes(e.bytes) }),
      el("td", { class: "mono", text: String(e.flows) }),
      el("td", {}, [el("span", { class: "muted", text: "track →" })]),
    ]);
    tr.addEventListener("click", () => toggleTracked(e.source));
    tr.title = `track ${e.source}`;
    table.appendChild(tr);
  }
}

/** A deterministic circular layout, sized by degree.
 *
 * WHY NOT A FORCE SIMULATION. A force layout is an animation that settles to a different
 * picture on every load, and two people looking at the same data cannot compare screens. It
 * also has no fixed cost: a busy segment means hundreds of iterations per frame.
 *
 * A CIRCLE IS NOT A COMPROMISE HERE, it is the better read for this data. Every edge in this
 * graph is a host-to-host pair with no hierarchy, so there is no structure for a force layout
 * to uncover -- the information is in the DEGREE and the BYTES, which is what node size and
 * edge width encode. The backend ships a normalised degree so the browser does no scaling
 * maths and two clients cannot disagree about the layout.
 *
 * Nodes are ordered by degree before placement, so the busiest hosts land together rather than
 * in whatever order the query returned.
 */
function drawGraph(host, nodes, edges, truncated) {
  const W = 1000;
  const H = 460;
  const { svg, plot } = chartFrame(W, H, { l: 20, r: 20, t: 20, b: 20 });
  const cx = (plot.l + plot.r) / 2;
  const cy = (plot.t + plot.b) / 2;
  const radius = Math.min(plot.r - plot.l, plot.b - plot.t) / 2 - 26;

  const ordered = nodes.slice().sort((a, b) => b.degree - a.degree);
  const pos = new Map();
  ordered.forEach((n, i) => {
    const angle = (i / ordered.length) * Math.PI * 2 - Math.PI / 2;
    pos.set(n.id, {
      x: cx + radius * Math.cos(angle),
      y: cy + radius * Math.sin(angle),
    });
  });

  // Edges first so nodes draw over them.
  const maxEdge = Math.max(1, ...edges.map((e) => e.bytes));
  for (const e of edges) {
    const a = pos.get(e.source);
    const b = pos.get(e.target);
    if (!a || !b) continue;
    // Width is log-scaled: byte volumes span orders of magnitude, and a linear scale makes
    // every edge but the largest a hairline.
    const w = 0.6 + 2.4 * (Math.log10(1 + e.bytes) / Math.log10(1 + maxEdge));
    const involved = ASSETS_STATE.tracked.length === 0 ||
      ASSETS_STATE.tracked.includes(e.source) || ASSETS_STATE.tracked.includes(e.target);
    svg.appendChild(svgEl("line", {
      x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "edge",
      "stroke-width": w.toFixed(2),
      opacity: involved ? "0.85" : "0.18",
    }));
  }

  const maxBytes = Math.max(1, ...nodes.map((n) => n.bytes || 0));
  for (const n of ordered) {
    const p = pos.get(n.id);
    const selected = ASSETS_STATE.tracked.includes(n.id);
    const r = 5 + 9 * Math.sqrt((n.bytes || 0) / maxBytes);
    const g = svgEl("g", { class: "node" + (selected ? " selected" : ""), transform: `translate(${p.x},${p.y})` });
    g.appendChild(svgEl("circle", {
      r: r.toFixed(1),
      fill: selected ? "#5ec26a" : "#4ea1ff",
      opacity: selected ? "1" : "0.78",
    }));
    // Labels only when asked for, or for a selected node: 250 labels in a circle is a smear.
    if (ASSETS_STATE.showNames || selected) {
      g.appendChild(svgEl("text", {
        x: 0, y: -(r + 4), "text-anchor": "middle",
        text: n.name || n.id,
      }));
    }
    g.appendChild(svgEl("title", {}, `${n.name ? n.name + " · " : ""}${n.id}\n${n.degree} peers\n${fmtBytes(n.bytes)}`));
    g.addEventListener("click", () => toggleTracked(n.id));
    g.style.cursor = "pointer";
    svg.appendChild(g);
  }

  host.appendChild(svg);

  const legend = document.getElementById("nw-legend");
  if (legend) {
    legend.replaceChildren();
    const items = [
      ["#4ea1ff", "host (size = bytes)"],
      ["#5ec26a", "tracked"],
      ["edge width", "log of bytes"],
    ];
    for (const [colour, label] of items) {
      legend.appendChild(el("span", { class: "legend-item" }, [
        colour.startsWith("#")
          ? el("span", { class: "legend-swatch", attrs: { style: `background:${colour}` } })
          : el("span", { class: "legend-swatch", attrs: { style: "background:var(--border)" } }),
        el("span", { text: label }),
      ]));
    }
    if (truncated) {
      legend.appendChild(el("span", {
        class: "legend-item muted",
        text: "the edge cap was reached — some connections are not drawn",
      }));
    }
  }
}

/* The window the Zeek view is currently showing, from its own control. */
function zeekWindow() {
  const sel = document.getElementById("zk-hours");
  const n = sel ? Number(sel.value) : NaN;
  return Number.isFinite(n) && n > 0 ? n : ASSETS_STATE.hours;
}

/* ── Zeek: the per-log drill-down ──────────────────────────────────────────── */

function loadZeekLog(log) {
  const host = document.getElementById("zk-hosts");
  const table = document.querySelector("#zk-hosts-table tbody");
  const title = document.getElementById("zk-drill-title");
  const note = document.getElementById("zk-drill-note");
  if (!host) return;
  title.textContent = `${log}.log`;
  note.textContent = `Hosts appearing in ${log}.log over the selected window.`;
  host.replaceChildren();
  table.replaceChildren();

  // The Zeek view has its OWN window selector (zk-hours), and the drill-down must use the same
  // window as the bars that were clicked. Reading ASSETS_STATE.hours here would silently
  // drill into a different period than the chart above it, which is the sort of mismatch that
  // reads as "the numbers are wrong".
  return getJSON(ASSET_API.zeeklog(log, zeekWindow()))
    .then((d) => {
      if (d.available === false) {
        host.appendChild(chartEmpty(`Cannot read ${log}.log: ${d.reason}.`));
        emptyRow(table, 3, "Nothing to show.");
        return;
      }
      const rows = d.points || [];
      if (!rows.length) {
        // "the log is empty" and "the query failed" are different facts and are stated
        // differently -- the distinction the Zeek view exists to keep.
        host.appendChild(chartEmpty(
          `${log}.log has no rows in this window. That is an empty log, not a failed query.`));
        emptyRow(table, 3, "No rows.");
        return;
      }
      renderBars("zk-hosts", {
        available: true, points: rows.map((r) => ({ label: r.addr, value: r.n, addr: r.addr })),
      }, {
        onClick: (r) => openHost(r.addr),
        format: (v) => String(v),
        title: (r) => `drill into ${r.addr}`,
      });
      table.replaceChildren(...rows.map((r) => {
        const tr = el("tr", { class: "clickable" }, [
          el("td", { class: "link mono", text: r.addr }),
          el("td", { class: "mono", text: String(r.n) }),
          el("td", {}, [el("span", { class: "muted", text: "drill down →" })]),
        ]);
        tr.addEventListener("click", () => openHost(r.addr));
        return tr;
      }));
    })
    .catch((err) => {
      host.appendChild(chartEmpty(`Cannot read ${log}.log: ${err.message}.`));
      emptyRow(table, 3, "Nothing to show.");
    });
}
