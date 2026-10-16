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
  flows: (params, hours) => `/api/flows?hours=${hours}` +
    (params.port !== undefined ? `&port=${params.port}` : "") +
    (params.proto !== undefined ? `&proto=${params.proto}` : ""),
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
  // Pagination for the inventory. 15 per page by default (the user's number): a segment with
  // 245 hosts is unreadable as one scroll, and a table you have to scroll is a table you skim
  // rather than read.
  page: 1,
  pageSize: 15,
};

/* getJSON lives in app.js -- ONE definition for the whole page. The duplicate that used to
 * sit here silently overrode app.js's version for every call site (scripts share one scope,
 * later declaration wins), so the effective error semantics depended on load order. */

/* ── Assets: the inventory ─────────────────────────────────────────────────── */

function loadAssets() {
  const hours = trHours();  // the global time control is the range (one control, every view)
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
    // NUMERIC, not lexicographic. `localeCompare` puts "…​.10" before "…​.2" because it compares
    // character by character, and an address column that reads 1, 10, 11, 2, 20 looks broken to
    // anyone scanning it. IPv4 is compared octet-by-octet; anything else (a hostname, an IPv6
    // address) falls back to the string comparison, which is the best available ordering.
    addr: (a, b) => compareAddr(a.addr, b.addr),
    name: (a, b) => (a.name || "~").localeCompare(b.name || "~"),
  };
  rows.sort(sorters[ASSETS_STATE.sort] || sorters.anomalies);

  // PAGINATED, because a segment with 245 hosts is unreadable as one scroll and a table you
  // scroll is a table you skim. The page is clamped to the real range: a filter can shrink the
  // result below the current page, and leaving the page number where it was would render an
  // empty table with no explanation.
  const size = ASSETS_STATE.pageSize;
  const pages = Math.max(1, Math.ceil(rows.length / size));
  if (ASSETS_STATE.page > pages) ASSETS_STATE.page = pages;
  if (ASSETS_STATE.page < 1) ASSETS_STATE.page = 1;
  const from = (ASSETS_STATE.page - 1) * size;
  const pageRows = rows.slice(from, from + size);

  renderPager("as-pager", rows.length, ASSETS_STATE.page, pages, (next) => {
    ASSETS_STATE.page = next;
    renderAssets();
  });

  const range = rows.length
    ? ` (showing ${from + 1}\u2013${Math.min(from + size, rows.length)})`
    : "";
  summary.textContent = (q
    ? `${rows.length} of ${all.length} hosts matching “${ASSETS_STATE.search}”`
    : `${all.length} hosts in the last ${d.hours}h`) + range;

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

  for (const h of pageRows) {
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

  // The range is stated by the pager, but the summary line repeats it because it is the line an
  // analyst reads first -- and a paged table that does not say "of 245" is the same
  // silent-truncation problem as the graph's edge cap.
  empty.textContent = "";

  // Feed the drill-down datalist, so typing an address is a suggestion not a memory test.
  const dl = document.getElementById("known-hosts");
  if (dl) {
    dl.replaceChildren(...all.slice(0, 300).map((h) =>
      el("option", { attrs: { value: h.addr, label: h.name || h.addr } })));
  }
}

/** Page controls for a long table: prev/next arrows, a page indicator, and the range.
 *
 * WHY ARROWS RATHER THAN A SCROLL. The inventory reached 245 hosts on one page, which is a
 * scroll rather than a table -- you skim it and lose your place. Pages of 15 give a stable
 * viewport and a bounded number of rows to read at once.
 *
 * THE RANGE IS ALWAYS STATED ("showing 16-30 of 245"). A paged list that shows only "page 2 of
 * 17" makes the total invisible, which is the same silent-truncation problem as the connection
 * graph's edge cap: the reader cannot tell a complete list from a partial one.
 *
 * The arrows are DISABLED at the ends rather than hidden, so the control does not reflow and
 * the reader can see that they are at the boundary.
 */
/** Compare two addresses numerically when both are IPv4, else as strings.
 *
 * An asset inventory is scanned, and "…​.10" sorting before "…​.2" makes the column unreadable.
 * IPv6 and hostnames are left to string comparison rather than half-parsed into something wrong.
 */
function compareAddr(a, b) {
  const octets = (s) => {
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(s || ""));
    return m ? m.slice(1).map(Number) : null;
  };
  const x = octets(a), y = octets(b);
  if (x && y) {
    for (let i = 0; i < 4; i++) if (x[i] !== y[i]) return x[i] - y[i];
    return 0;
  }
  return String(a || "").localeCompare(String(b || ""));
}

function renderPager(hostId, total, page, pages, onGo, size = ASSETS_STATE.pageSize) {
  const host = document.getElementById(hostId);
  if (!host) return;
  host.replaceChildren();
  if (total === 0) return;

  // `size` is a PARAMETER, not a module constant. It used to read ASSETS_STATE.pageSize
  // directly, which silently made this helper single-purpose: a second table passing its own
  // page size would render the Assets range while claiming to describe itself (the range line
  // below is computed from `size`, so the two tables would disagree about what "showing 1-15"
  // meant). Both tables page at 15 today, which is exactly why the bug would have gone unnoticed
  // until one of them changed.
  const first = (page - 1) * size + 1;
  const last = Math.min(page * size, total);

  const btn = (label, target, disabled, title) => {
    const b = el("button", { class: "pager-btn", text: label, title });
    b.disabled = !!disabled;
    if (!disabled) b.addEventListener("click", () => onGo(target));
    return b;
  };

  host.appendChild(btn("‹", page - 1, page <= 1, "previous page"));
  host.appendChild(el("span", {
    class: "pager-info",
    text: `${first}\u2013${last} of ${total}   \u00b7   page ${page} of ${pages}`,
  }));
  host.appendChild(btn("›", page + 1, page >= pages, "next page"));

  // Jump-to-first/last only earn their space when there are enough pages to make them useful.
  if (pages > 3) {
    host.appendChild(btn("\u00ab first", 1, page <= 1, "first page"));
    host.appendChild(btn("last \u00bb", pages, page >= pages, "last page"));
  }
}

/* ── Network: the connection graph ─────────────────────────────────────────── */

function loadNetwork() {
  const hosts = ASSETS_STATE.tracked;
  return getJSON(ASSET_API.graph(trHours(), hosts))
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
  const allEdges = d.edges || [];
  const edges = allEdges.filter((e) => e.flows >= ASSETS_STATE.minEdges);
  if (!nodes.length || !edges.length) {
    // THREE states, not two (review round 2026-10-15). This branch used to collapse "the
    // filter removed every edge" into "No host-to-host traffic was recorded" -- a panel
    // HIDING data it held, while blaming the network for the absence. The filtered case
    // now names the filter and its count; the quiet case keeps its old wording (the jsdom
    // harness pins it, and it was correct for what it described).
    const hidden = nodes.length ? allEdges.length : 0;
    caption.textContent = hidden
      ? `${hidden} connection${hidden === 1 ? "" : "s"} below the flows filter (${ASSETS_STATE.minEdges}+ flows), in the last ${d.hours || ASSETS_STATE.hours}h.`
      : ASSETS_STATE.tracked.length
        ? `No connections among the tracked hosts in the last ${d.hours || ASSETS_STATE.hours}h.`
        : `No host-to-host traffic in the last ${d.hours || ASSETS_STATE.hours}h.`;
    host.appendChild(chartEmpty(
      hidden
        ? `The flows filter is hiding ${hidden} connection${hidden === 1 ? "" : "s"} (fewer than ${ASSETS_STATE.minEdges} flows each). Lower the filter to see them.`
        : ASSETS_STATE.tracked.length
          ? "These hosts did not talk to each other in this window. Widen the window or clear the selection."
          : "No host-to-host traffic was recorded. Broadcast and self-directed traffic is excluded."));
    emptyRow(table, 5, hidden ? "No edges above the flows filter." : "No edges to show.");
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

/** The layout's physics, in fixed numbers -- no random source anywhere: same data, same map.
 *
 * WHY THIS IS A FORCE LAYOUT NOW, and how each objection that kept the old view a fixed
 * circle is answered rather than ignored:
 *
 *   1. "It settles to a different picture on every load; two people cannot compare screens."
 *      The solver below has NO randomness and a FIXED tick count. The start positions are the
 *      old degree-ordered circle, every step is deterministic arithmetic, so one window of
 *      data always settles to the same map -- what animates is the path to it, never the map.
 *   2. "It has no fixed cost: hundreds of iterations per frame." The solve runs ONCE per
 *      render, and then the picture is frozen; a drag re-runs a bounded warm start, and
 *      nothing iterates per frame once the map has settled. The bound is per RENDER, not
 *      per node count: the repulsion loop visits every pair, so cost scales with
 *      nodes² × ticks. The measured 12 ms is the demo graph (20 nodes / 63 edges); the
 *      payload's 400-edge cap puts the worst case (~800 nodes) at roughly 800x the demo's
 *      pair evaluations -- seconds, not milliseconds. That class is fine to accept (the
 *      solve still completes and freezes), but it is NOT covered by the 12 ms number.
 *   3. "There is no structure for a force layout to uncover." That was true of edges alone --
 *      and it stopped being true when the ingest started carrying IP TTL. A host's observed
 *      TTL is its hop distance from the sensor, and the radial pull below turns that into
 *      distance rings: same-segment hosts inside, routed hosts outside. Where an export does
 *      not carry TTL the rings are simply absent and the links alone shape the map.
 */
const FORCE = {
  ticks: 320,       // fixed: the final map must not depend on how long a browser waited
  repel: 5000,      // pairwise push, 1/d^2 falloff
  repelCut: 360,    // beyond this two nodes do not feel each other -- bounds the FORCE, not
                    // the loop: the pairwise distance test still runs for every pair (above)
  linkDist: 112,    // the spring length an edge wants
  linkK: 0.045,     // spring stiffness
  centerK: 0.005,   // gently pulls islands back toward the middle
  ringK: 0.12,      // pull toward the host's hop ring (only where TTL was measured) --
                    // measured on the demo dataset: at gentler values (0.02-0.05) the springs
                    // through the shared servers smear the two classes together and the
                    // structure stops being readable; at 0.12 the classes hold apart
  ringBase: 74,     // the same-segment ring's radius; deeper classes step outward
  ringMax: 178,     // the outermost ring stays inside the frame at any hop count
  damp: 0.85,
  maxSpeed: 14,
  animateMs: 750,
};

/** Which hop classes exist, and how far apart their rings sit (visual cap: class 3).
 *
 * Only nodes with a MEASURED reading count -- `hops` is absent, not zero, for hosts whose
 * records carried no TTL, and those hosts float on the links alone. */
function ringPlan(nodes) {
  const classes = new Set();
  for (const n of nodes) {
    if (n.hops === null || n.hops === undefined) continue;
    classes.add(Math.min(3, Math.max(0, Number(n.hops) || 0)));
  }
  const list = [...classes].sort((a, b) => a - b);
  const maxH = list.length ? list[list.length - 1] : 0;
  return { classes: list, dr: maxH > 0 ? (FORCE.ringMax - FORCE.ringBase) / maxH : 0 };
}

/** The positions the graph settles to -- pure and deterministic: same data in, same map out.
 *
 * Returns {start, end, rings}: `start` is the degree-ordered circle the view used to draw at
 * (the settle animation's first frame), `end` the settled map it freezes at. `warmStart`
 * (a Map of id -> {x, y}) continues from a dragged arrangement instead of the circle and
 * keeps the previous scale, so a hand-arranged map never jumps between sizes; it is used
 * only by the re-settle after a drag. `pinned` (a Set of ids) holds those hosts at their
 * DROPPED positions while the rest of the map re-arranges -- the pin belongs in the solver,
 * not in the drawing: the springs would otherwise drag the host straight back and the
 * gesture would read as having done nothing. Only Re-settle clears the pins.
 */
function computeLayout(nodes, edges, box, warmStart, pinned) {
  const n = nodes.length;
  const cx = box.cx, cy = box.cy;
  const radius = Math.min(box.w, box.h) / 2 - 26;

  const ordered = nodes.slice().sort((a, b) => (b.degree || 0) - (a.degree || 0));
  const start = new Map();
  ordered.forEach((nd, i) => {
    const from = warmStart && warmStart.get(nd.id);
    if (from) {
      start.set(nd.id, { x: from.x, y: from.y });
    } else {
      const angle = (i / Math.max(1, ordered.length)) * Math.PI * 2 - Math.PI / 2;
      start.set(nd.id, { x: cx + radius * Math.cos(angle), y: cy + radius * Math.sin(angle) });
    }
  });

  const idx = new Map(ordered.map((nd, i) => [nd.id, i]));
  const xs = ordered.map((nd) => start.get(nd.id).x);
  const ys = ordered.map((nd) => start.get(nd.id).y);
  const vx = ordered.map(() => 0);
  const vy = ordered.map(() => 0);
  const ring = ringPlan(ordered);
  const classOf = ordered.map((nd) => {
    if (nd.hops === null || nd.hops === undefined) return null;
    return Math.min(3, Math.max(0, Number(nd.hops) || 0));
  });

  const maxBytes = Math.max(1, ...ordered.map((nd) => nd.bytes || 0));
  const links = [];
  for (const e of edges) {
    const a = idx.get(e.source), b = idx.get(e.target);
    if (a === undefined || b === undefined || a === b) continue;
    // Heavier observed pairs sit closer (log-normalised), so the tightest knots on the map
    // read as the busiest relationships.
    const w = Math.min(1, Math.log10(1 + (e.bytes || 0)) / Math.log10(1 + maxBytes ** 2));
    links.push({ a: a, b: b, len: FORCE.linkDist + 52 * (1 - w) });
  }

  const ticks = n > 300 ? 150 : n > 150 ? 220 : FORCE.ticks;
  const cut2 = FORCE.repelCut * FORCE.repelCut;
  for (let t = 0; t < ticks; t++) {
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const dx = xs[i] - xs[j], dy = ys[i] - ys[j];
        const d2 = dx * dx + dy * dy;
        if (d2 > cut2 || d2 < 1e-6) continue;
        const d = Math.sqrt(d2);
        const f = FORCE.repel / d2;
        const fx = (f * dx) / d, fy = (f * dy) / d;
        vx[i] += fx; vy[i] += fy;
        vx[j] -= fx; vy[j] -= fy;
      }
    }
    for (const L of links) {
      const dx = xs[L.b] - xs[L.a], dy = ys[L.b] - ys[L.a];
      const d = Math.hypot(dx, dy) || 1e-6;
      const f = FORCE.linkK * (d - L.len);
      const fx = (f * dx) / d, fy = (f * dy) / d;
      vx[L.a] += fx; vy[L.a] += fy;
      vx[L.b] -= fx; vy[L.b] -= fy;
    }
    for (let i = 0; i < n; i++) {
      if (pinned && pinned.has(ordered[i].id)) {
        // A host the operator dragged holds exactly where it was dropped; the rest of the
        // map settles AROUND it (see the pinned note in the docstring).
        xs[i] = start.get(ordered[i].id).x;
        ys[i] = start.get(ordered[i].id).y;
        vx[i] = 0; vy[i] = 0;
        continue;
      }
      vx[i] += (cx - xs[i]) * FORCE.centerK;
      vy[i] += (cy - ys[i]) * FORCE.centerK;
      if (classOf[i] !== null) {
        const target = FORCE.ringBase + ring.dr * classOf[i];
        const rx = xs[i] - cx, ry = ys[i] - cy;
        const rd = Math.hypot(rx, ry);
        if (rd > 1e-6) {
          const pull = (FORCE.ringK * (rd - target)) / rd;
          vx[i] -= rx * pull; vy[i] -= ry * pull;
        }
      }
      vx[i] *= FORCE.damp; vy[i] *= FORCE.damp;
      const sp = Math.hypot(vx[i], vy[i]);
      if (sp > FORCE.maxSpeed) { vx[i] *= FORCE.maxSpeed / sp; vy[i] *= FORCE.maxSpeed / sp; }
      xs[i] += vx[i]; ys[i] += vy[i];
    }
  }

  // Recentre the settled mass on the frame, when this is a fresh layout: the forces pull
  // toward the middle, but an asymmetric link structure (all spokes through a few hubs)
  // leaves the cloud visibly off to one side, and an off-centre map reads as a fault. A
  // warm start skips this -- it would fight the operator's own arrangement.
  if (!warmStart && n) {
    let cmx = 0, cmy = 0;
    for (let i = 0; i < n; i++) { cmx += xs[i]; cmy += ys[i]; }
    cmx /= n; cmy /= n;
    for (let i = 0; i < n; i++) { xs[i] += cx - cmx; ys[i] += cy - cmy; }
  }

  // Fit the settle into the frame by SCALING (never distorting), using the 95th-percentile
  // radius so one drifting node cannot shrink the whole picture. A warm start keeps the
  // previous scale so a dragged map does not jump between sizes.
  const radials = [];
  for (let i = 0; i < n; i++) radials.push(Math.hypot(xs[i] - cx, ys[i] - cy));
  radials.sort((a, b) => a - b);
  const fitR = radials[Math.min(radials.length - 1, Math.floor(radials.length * 0.95))] || 1;
  const room = Math.min(box.w / 2 - 14, box.h / 2 - 14);
  let s = warmStart ? 1 : Math.min(1.35, Math.max(0.55, (room - 12) / fitR));
  const end = new Map();
  ordered.forEach((nd, i) => {
    end.set(nd.id, {
      x: Math.min(cx + room, Math.max(cx - room, cx + (xs[i] - cx) * s)),
      y: Math.min(cy + room, Math.max(cy - room, cy + (ys[i] - cy) * s)),
    });
  });
  // Rings are drawn only when TTL produced more than one class: a single circle around
  // everything would read as a frame, not a measurement. Each circle sits at the radius its
  // class ACTUALLY settled at (the mean), not at the nominal target -- a circle drawn at
  // the target while the cluster settles elsewhere is a diagram of an intention.
  const rings = [];
  if (ring.classes.length > 1) {
    for (const h of ring.classes) {
      let sum = 0, cnt = 0, capped = false;
      ordered.forEach((nd, i) => {
        if (classOf[i] !== h) return;
        const p = end.get(nd.id);
        sum += Math.hypot(p.x - cx, p.y - cy);
        cnt += 1;
        // The geometry caps at class 3; a member further out than that must make the LABEL
        // say so, or the ring prints a capped class as if it were a measured hop count.
        if (Number(nd.hops) > h) capped = true;
      });
      if (cnt) rings.push({ hops: h, radius: sum / cnt, capped: capped });
    }
  }
  return { start: start, end: end, rings: rings };
}

/** The hover card for a host: address, activity, and -- when measured -- where it sits.
 *
 * A hop reading is always shown WITH the TTL it came from: the ring position is a
 * measurement, and a measurement without its evidence is a conclusion. */
function nodeTitle(n) {
  const out = [`${n.name ? n.name + " · " : ""}${n.id}`, `${n.degree} peers`, fmtBytes(n.bytes)];
  if (n.hops !== null && n.hops !== undefined) {
    out.push(`${n.hops} ${n.hops === 1 ? "hop" : "hops"} from the sensor (ttl ${n.ttl})`);
  }
  return out.join("\n");
}

/** The hover card for one connection: the pair, the volume, and the TTL range when carried. */
function edgeTitle(e) {
  const out = [`${e.source} → ${e.target}`, fmtBytes(e.bytes)];
  if (e.ttl_max > 0) {
    out.push(e.ttl_min === e.ttl_max ? `ttl ${e.ttl_max}` : `ttl ${e.ttl_min}–${e.ttl_max}`);
  }
  return out.join("\n");
}

/** Draw the connection graph: a settled force map with hop rings where TTL allows.
 *
 * All the interactions the view already had are unchanged -- clicks open the same detail
 * panels, the tracking selection is the same ClickHouse-side filter. What the map adds: a
 * short settle animation on load, hop-distance rings drawn from the measured TTL, and a
 * drag that carries a host and re-settles its neighbours (the interaction Obsidian's graph
 * is known for, and the reason a map is worth arranging by hand). */
function drawGraph(host, nodes, edges, truncated) {
  const W = 1000;
  const H = 460;
  const { svg, plot } = chartFrame(W, H, { l: 20, r: 20, t: 20, b: 20 });
  const cx = (plot.l + plot.r) / 2;
  const cy = (plot.t + plot.b) / 2;
  const box = { cx: cx, cy: cy, w: plot.r - plot.l, h: plot.b - plot.t };
  const layout = computeLayout(nodes, edges, box);
  const pos = new Map(layout.start);
  const pinned = new Set();  // hosts the operator has dragged; they hold until Re-settle

  // Faint hop rings under everything; their LABELS are appended after the nodes instead
  // (see below) so a node can never sit on top of the label that explains the ring.
  const ringLabels = [];
  for (const ring of layout.rings) {
    svg.appendChild(svgEl("circle", {
      cx: cx, cy: cy, r: ring.radius.toFixed(1), class: "ring", fill: "none",
    }));
    ringLabels.push({ x: cx, y: (cy - ring.radius + 11).toFixed(1),
                      text: (ring.capped ? "3+" : ring.hops) +
                            (ring.hops === 1 ? " hop" : " hops") });
  }

  // Position writers: one list applied to a Map of id -> {x, y}, so "draw at start", "draw
  // mid-animation" and "draw mid-drag" are the same code path.
  const edgeEls = [];
  const nodeEls = [];
  function applyPositions(cur) {
    for (const ee of edgeEls) {
      const a = cur.get(ee.source), b = cur.get(ee.target);
      if (!a || !b) continue;
      for (const el2 of ee.els) {
        el2.setAttribute("x1", a.x.toFixed(1)); el2.setAttribute("y1", a.y.toFixed(1));
        el2.setAttribute("x2", b.x.toFixed(1)); el2.setAttribute("y2", b.y.toFixed(1));
      }
    }
    for (const ne of nodeEls) {
      const p = cur.get(ne.id);
      if (p) ne.g.setAttribute("transform", `translate(${p.x.toFixed(1)},${p.y.toFixed(1)})`);
    }
  }

  // ── the settle: circle -> map, once, bounded ──────────────────────────────────────────────
  // The FINAL state is applied by `finish` no matter what happens to the frames: a stalled
  // animation frame (a backgrounded tab, a throttled renderer) must cost the ANIMATION, not
  // the map -- and a map silently stuck at the circle would also poison the next drag's warm
  // re-settle, which reads `pos`. The watchdog timer guarantees the settled state; the frames
  // are only how a visible tab watches it get there.
  let animSeq = 0;
  function settleTo(target, ms) {
    const seq = ++animSeq;
    const finish = () => {
      if (seq !== animSeq) return;
      for (const [id, p1] of target) pos.set(id, p1);
      applyPositions(target);
    };
    const reduce = typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const raf = typeof requestAnimationFrame === "function" ? requestAnimationFrame : null;
    if (!raf || reduce || document.hidden) {
      finish();
      return;
    }
    const from = new Map(pos);
    const t0 = performance.now();
    const watchdog = setTimeout(finish, ms + 300);
    function frame(now) {
      if (seq !== animSeq) {
        clearTimeout(watchdog);
        return;  // superseded by a drag or a re-render
      }
      const t = Math.min(1, (now - t0) / ms);
      const e = 1 - Math.pow(1 - t, 3);
      const cur = new Map();
      for (const [id, p1] of target) {
        const p0 = from.get(id) || p1;
        cur.set(id, { x: p0.x + (p1.x - p0.x) * e, y: p0.y + (p1.y - p0.y) * e });
      }
      // `pos` tracks the animation, not just the final state: a pointer that grabs a host
      // mid-flight must drag from where the host VISIBLY is, and a warm re-settle after an
      // interrupted animation must start from the picture on screen, not the start circle.
      for (const [id2, p2] of cur) pos.set(id2, p2);
      applyPositions(cur);
      if (t < 1) {
        raf(frame);
      } else {
        clearTimeout(watchdog);
        finish();
      }
    }
    raf(frame);
  }

  // Drag a node: the node carries its edges live, and on release a bounded warm re-settle
  // lets the springs respond to where the operator put it.
  function wireDrag(g, id) {
    const state = { moved: false };
    g.addEventListener("pointerdown", (ev) => {
      if (ev.button !== undefined && ev.button !== 0) return;
      ev.preventDefault();
      ev.stopPropagation();
      // The in-flight settle animation is NOT cancelled here. A plain click mid-settle is a
      // selection, not an interruption -- and cancelling at PRESS left the map frozen at
      // whatever frame the click caught, for good: measured on the demo map, a click 250 ms
      // into the 750 ms settle froze it 185 px short of the settled picture, and only a
      // re-render ever moved it again. The drag cancels the animation on its first real
      // move instead (see `onMove`), where the gesture has actually taken the map over.
      state.moved = false;
      const rect = typeof svg.getBoundingClientRect === "function" ? svg.getBoundingClientRect() : null;
      const scaleX = rect && rect.width > 0 ? W / rect.width : 1;
      const scaleY = rect && rect.height > 0 ? H / rect.height : 1;
      const toLocal = (e2) => ({
        x: (e2.clientX - (rect ? rect.left : 0)) * scaleX,
        y: (e2.clientY - (rect ? rect.top : 0)) * scaleY,
      });
      const onMove = (e2) => {
        const p = toLocal(e2);
        const cur = pos.get(id);
        if (!cur) return;
        const nx = Math.min(cx + box.w / 2 - 8, Math.max(cx - box.w / 2 + 8, p.x));
        const ny = Math.min(cy + box.h / 2 - 8, Math.max(cy - box.h / 2 + 8, p.y));
        if (!state.moved && Math.abs(nx - cur.x) + Math.abs(ny - cur.y) > 2) {
          state.moved = true;
          animSeq++;  // the drag owns the map now; any in-flight settle animation stops
        }
        cur.x = nx; cur.y = ny;
        applyPositions(pos);
      };
      const onUp = () => {
        window.removeEventListener("pointermove", onMove);
        window.removeEventListener("pointerup", onUp);
        window.removeEventListener("pointercancel", onUp);
        if (!state.moved) return;
        pinned.add(id);
        const re = computeLayout(nodes, edges, box, pos, pinned);
        settleTo(re.end, 260);
      };
      window.addEventListener("pointermove", onMove);
      window.addEventListener("pointerup", onUp);
      // A cancelled pointer (OS gesture takeover, a browser action) must end the gesture HERE.
      // Without this listener the move handler stayed armed: after a cancel, the host kept
      // following bare mouse motion and pinned itself wherever the next stray press landed.
      window.addEventListener("pointercancel", onUp);
    });
    return state;
  }

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
    const shown = involved ? "0.85" : "0.18";
    // A WIDE TRANSPARENT LINE UNDER EACH EDGE IS THE CLICK TARGET. The drawn line is 0.6-3px,
    // which is not a realistic pointer target, so an invisible 12px stroke sits beneath it and
    // carries the click. Without this the edges would be decorative -- and an analyst pointing
    // at a specific connection is exactly the interaction this view is for.
    const hit = svgEl("line", {
      x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "edge-hit",
      "stroke-width": "12", stroke: "transparent", "pointer-events": "stroke",
    });
    hit.addEventListener("click", (ev) => {
      ev.stopPropagation();
      showEdgeDetail(e);
    });
    hit.appendChild(svgEl("title", {}, edgeTitle(e)));
    svg.appendChild(hit);
    const line = svgEl("line", {
      x1: a.x, y1: a.y, x2: b.x, y2: b.y, class: "edge",
      "stroke-width": w.toFixed(2),
      opacity: shown, "pointer-events": "none",
    });
    svg.appendChild(line);
    edgeEls.push({ source: e.source, target: e.target, els: [hit, line] });
  }

  const maxBytes = Math.max(1, ...nodes.map((n) => n.bytes || 0));
  const ordered = nodes.slice().sort((a, b) => (b.degree || 0) - (a.degree || 0));
  for (const n of ordered) {
    const p = pos.get(n.id);
    const selected = ASSETS_STATE.tracked.includes(n.id);
    const r = 5 + 9 * Math.sqrt((n.bytes || 0) / maxBytes);
    const g = svgEl("g", {
      class: "node" + (selected ? " selected" : ""),
      transform: `translate(${p.x.toFixed(1)},${p.y.toFixed(1)})`,
    });
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
    g.appendChild(svgEl("title", {}, nodeTitle(n)));
    // CLICK LEADS WITH DATA. It used to toggle tracking only, which the user could not infer
    // from anything on screen -- "i dont understand what clicking down". The detail panel now
    // opens on the host's connections, and tracking is an explicit button inside it.
    const drag = wireDrag(g, n.id);
    g.addEventListener("click", () => {
      if (drag.moved) return;  // a drag is not a click
      showNodeDetail(n);
    });
    nodeEls.push({ id: n.id, g: g });
    svg.appendChild(g);
  }

  host.appendChild(svg);
  // Ring labels ride ON TOP of the map (with a halo in CSS): drawn underneath, the 0-hop
  // label sat behind a node on the settled demo map and read as "hops".
  for (const rl of ringLabels) {
    svg.appendChild(svgEl("text", {
      x: rl.x, y: rl.y, "text-anchor": "middle", class: "ring-label",
    }, rl.text));
  }
  settleTo(layout.end, FORCE.animateMs);

  const legend = document.getElementById("nw-legend");
  if (legend) {
    legend.replaceChildren();
    const items = [
      ["#4ea1ff", "host (size = bytes)"],
      ["#5ec26a", "tracked"],
      ["edge width", "log of bytes"],
    ];
    if (layout.rings.length) {
      items.push(["ring", "ring = hop distance from the sensor (IP TTL)"]);
    }
    for (const [colour, label] of items) {
      const swatch = colour === "ring"
        ? el("span", { class: "legend-swatch ring" })
        : el("span", {
            class: "legend-swatch",
            attrs: { style: `background:${colour.startsWith("#") ? colour : "var(--border)"}` },
          });
      legend.appendChild(el("span", { class: "legend-item" }, [
        swatch,
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

/** Re-run the layout from its deterministic start, discarding any hand-dragged arrangement.
 *
 * The counterpart to dragging a node somewhere unhelpful: the map returns to the exact
 * picture the data settles to, so there is always a way back to the comparable view. */
function settleGraph() {
  const d = ASSETS_STATE.graph;
  if (!d || d.available === false) return;
  renderNetwork();
}

/* The window the Zeek view is showing. The GLOBAL time control is the range -- the per-view
   hours boxes were removed on the operator's instruction (2026-10-16): one control, every tab. */
function zeekWindow() {
  return trHours();
}

/* ── Network: what a click on the graph actually means ─────────────────────── */

/** One connection's source and destination, in words and numbers.
 *
 * WHY THIS EXISTS: the user clicked the graph and could not tell what had happened. A node click
 * only toggled a filter, so the click looked inert and the graph looked unreadable -- you could
 * see that two hosts were joined but not what the join WAS.
 *
 * Every line shows the address AND the name, never the name alone: a name is a convenience that
 * can be wrong, shared, or absent, and the address is the fact.
 */
function showEdgeDetail(edge) {
  const host = document.getElementById("nw-detail");
  const table = document.querySelector("#nw-detail-table tbody");
  const title = document.getElementById("nw-detail-title");
  const note = document.getElementById("nw-detail-note");
  if (!host) return;
  host.replaceChildren();
  table.replaceChildren();

  title.textContent = "one connection";
  const ports = (edge.ports || []).length ? edge.ports.join(", ") : "—";
  // The TTL range is the evidence a ring position rests on, so it shows when the records
  // carried the field -- and says nothing when they did not.
  const ttl = edge.ttl_max > 0
    ? ` Observed TTL ${edge.ttl_min === edge.ttl_max ? edge.ttl_max : `${edge.ttl_min}–${edge.ttl_max}`}.`
    : "";
  note.textContent =
    `${label(edge.source_name, edge.source)} → ${label(edge.target_name, edge.target)}` +
    ` on port${(edge.ports || []).length === 1 ? "" : "s"} ${ports}.${ttl}`;

  // The pair, as a single prominent row, because "source and destination" is the question.
  host.appendChild(el("div", { class: "pair" }, [
    el("div", { class: "pair-side" }, [
      el("div", { class: "pair-label", text: "source" }),
      el("div", { class: "pair-addr", text: edge.source }),
      edge.source_name ? el("div", { class: "muted", text: edge.source_name }) : null,
    ]),
    el("div", { class: "pair-arrow", text: "→" }),
    el("div", { class: "pair-side" }, [
      el("div", { class: "pair-label", text: "destination" }),
      // The port belongs on the destination card: "host :443" is one fact, and splitting it
      // across a card and a note makes the reader assemble it. Several ports are listed in
      // descending-count order (topK), so a host on many ports reads as a short list.
      el("div", { class: "pair-addr", text: (edge.ports || []).length === 1
        ? `${edge.target}:${edge.ports[0]}`
        : edge.target }),
      (edge.ports || []).length > 1
        ? el("div", { class: "muted", text: `ports ${edge.ports.join(", ")}` })
        : null,
      edge.target_name ? el("div", { class: "muted", text: edge.target_name }) : null,
    ]),
  ]));
  host.appendChild(el("div", { class: "muted", text:
    `${fmtBytes(edge.bytes)} across ${edge.flows} flow${edge.flows === 1 ? "" : "s"}` +
    (edge.first_seen ? ` · first seen ${fmtTime(edge.first_seen)}` : "") +
    (edge.last_seen ? ` · last seen ${fmtTime(edge.last_seen)}` : "") }));

  const tr = el("tr", {}, [
    el("td", { class: "link mono", text: edge.source }),
    el("td", { class: "link mono", text: edge.target }),
    el("td", { class: "mono", text: ports }),
    el("td", { class: "mono", text: fmtBytes(edge.bytes) }),
    el("td", { class: "mono", text: String(edge.flows) }),
    el("td", {}, [el("span", { class: "muted", text: "drill into source →" })]),
  ]);
  tr.addEventListener("click", () => openHost(edge.source));
  table.appendChild(tr);
}

/** Everything one host talked to, from the graph already in memory.
 *
 * NO REFETCH: the graph payload holds every drawn edge, so the answer is filtered locally. A
 * click that runs a query is a click that can be slow, and this view is meant to be explorable.
 */
function showNodeDetail(node) {
  const host = document.getElementById("nw-detail");
  const table = document.querySelector("#nw-detail-table tbody");
  const title = document.getElementById("nw-detail-title");
  const note = document.getElementById("nw-detail-note");
  if (!host) return;
  host.replaceChildren();
  table.replaceChildren();

  const all = (ASSETS_STATE.graph && ASSETS_STATE.graph.edges) || [];
  const touching = all.filter((e) => e.source === node.id || e.target === node.id);
  // Sorted so the heaviest conversation is first -- an analyst asking "what does this host
  // talk to" wants the answer ordered by significance, not by query order.
  const outbound = touching.filter((e) => e.source === node.id)
                           .sort((a, b) => b.bytes - a.bytes);
  const inbound = touching.filter((e) => e.target === node.id)
                          .sort((a, b) => b.bytes - a.bytes);

  title.textContent = label(node.name, node.id);
  const dist = (node.hops === null || node.hops === undefined)
    ? ""
    : ` · ${node.hops} ${node.hops === 1 ? "hop" : "hops"} from the sensor (ttl ${node.ttl})`;
  note.replaceChildren(el("span", { text:
    `${node.degree} peer${node.degree === 1 ? "" : "s"} · ${fmtBytes(node.bytes)} · ` +
    `${outbound.length} outbound, ${inbound.length} inbound${dist}` }));

  // Tracking stays available, but as an explicit ACTION inside the panel rather than the thing
  // a click silently did.
  const tracking = ASSETS_STATE.tracked.includes(node.id);
  const btn = el("button", {
    class: "pager-btn",
    text: tracking ? "stop tracking this host" : "track only this host's connections",
  });
  btn.addEventListener("click", () => { toggleTracked(node.id); showNodeDetail(node); });
  host.appendChild(el("div", { class: "pair-side" }, [
    el("div", { class: "pair-label", text: "host" }),
    el("div", { class: "pair-addr", text: node.id }),
    node.name ? el("div", { class: "muted", text: node.name }) : null,
  ]));
  host.appendChild(el("div", { class: "chips" }, [btn]));

  if (!touching.length) {
    table.appendChild(el("tr", {}, [
      el("td", { class: "empty", attrs: { colspan: "6" },
                 text: "This host has no drawn connections in the current selection." }),
    ]));
    return;
  }

  // Outbound first: "who does this host talk TO" is the usual question, and separating the
  // directions means a server answering everything does not bury its own few outbound flows.
  const rows = [];
  if (outbound.length) {
    rows.push(el("tr", {}, [el("td", {
      class: "muted", attrs: { colspan: "6" }, text: `outbound (${outbound.length})` })]));
    rows.push(...outbound.map(edgeRow));
  }
  if (inbound.length) {
    rows.push(el("tr", {}, [el("td", {
      class: "muted", attrs: { colspan: "6" }, text: `inbound (${inbound.length})` })]));
    rows.push(...inbound.map(edgeRow));
  }
  table.replaceChildren(...rows);
}

/** One edge as a table row: who → who, on which ports, how much. */
function edgeRow(e) {
  const ports = (e.ports || []).length ? e.ports.join(", ") : "—";
  const tr = el("tr", { class: "clickable" }, [
    el("td", { class: "mono", text: e.source }),
    el("td", { class: "mono", text: e.target }),
    el("td", { class: "mono", text: ports }),
    el("td", { class: "mono", text: fmtBytes(e.bytes) }),
    el("td", { class: "mono", text: String(e.flows) }),
    el("td", {}, [el("span", { class: "muted", text: "details →" })]),
  ]);
  tr.addEventListener("click", () => showEdgeDetail(e));
  return tr;
}

/** An address with its name in front, when there is one. Never a name INSTEAD of an address. */
function label(name, addr) {
  return name ? `${name} (${addr})` : String(addr || "");
}

/* ── Netflow: the port/protocol drill-down ─────────────────────────────────── */

/* "Top ports" answers which ports carry the most bytes and stops there; the next question is
 * always which hosts and to where. This is the way in from both the protocol and the port
 * charts. `params` carries whichever filter was clicked -- a port, a protocol, or both. */
function loadFlowDetail(params) {
  const host = document.getElementById("nf-detail");
  const table = document.querySelector("#nf-detail-table tbody");
  const title = document.getElementById("nf-detail-title");
  const note = document.getElementById("nf-detail-note");
  if (!host) return Promise.resolve();
  title.textContent = params.name || "flow detail";
  note.textContent = "Host-to-host pairs behind this bar, busiest first.";
  host.replaceChildren();
  table.replaceChildren();

  const url = (typeof ASSET_API !== "undefined" && ASSET_API.flows)
    ? ASSET_API.flows(params, ASSETS_STATE.hours)
    : `/api/flows?hours=${ASSETS_STATE.hours}` +
      (params.port !== undefined ? `&port=${params.port}` : "") +
      (params.proto !== undefined ? `&proto=${params.proto}` : "");

  return getJSON(url)
    .then((d) => {
      if (d.available === false) {
        host.appendChild(chartEmpty(`Cannot read the flows: ${d.reason}.`));
        emptyRow(table, 6, "Nothing to show.");
        return;
      }
      const rows = d.points || [];
      if (!rows.length) {
        host.appendChild(chartEmpty("No flows matched in this window."));
        emptyRow(table, 6, "No rows.");
        return;
      }
      // Say when the list is capped: a truncated list that does not mention it looks complete.
      if (d.truncated) {
        note.textContent =
          `Showing the ${rows.length} busiest of ${d.total_pairs} host pairs ` +
          `(${d.total_flows} flows total).`;
      } else {
        note.textContent = `${rows.length} host pair(s), ${d.total_flows} flows.`;
      }
      renderBars("nf-detail", {
        available: true,
        points: rows.map((r) => ({
          label: `${r.src_addr} → ${r.dst_addr}`, value: r.bytes, row: r,
        })),
      }, {
        onClick: (r) => openHost(r.row.src_addr),
        format: (v) => fmtBytes(v),
        colour: () => "#4ea1ff",
        title: (r) => `drill into ${r.row.src_addr}`,
      });
      table.replaceChildren(...rows.map((r) => {
        const tr = el("tr", { class: "clickable" }, [
          el("td", { class: "link mono", text: r.src_addr }),
          el("td", { class: "mono", text: r.dst_addr }),
          el("td", { class: "mono", text: String(r.dst_port) }),
          el("td", { class: "mono", text: fmtBytes(r.bytes) }),
          el("td", { class: "mono", text: String(r.flows) }),
          el("td", {}, [el("span", { class: "muted", text: "drill down →" })]),
        ]);
        tr.addEventListener("click", () => openHost(r.src_addr));
        return tr;
      }));
    })
    .catch((err) => {
      host.appendChild(chartEmpty(`Cannot read the flows: ${err.message}.`));
      emptyRow(table, 6, "Nothing to show.");
    });
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
        // The NAME when one exists, with the address beside it -- same rule as every other
        // host list (the IP is the fact; the name is the convenience, never a replacement).
        const tr = el("tr", { class: "clickable" }, [
          el("td", { class: "link mono", text: r.name ? `${r.name} (${r.addr})` : r.addr }),
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
