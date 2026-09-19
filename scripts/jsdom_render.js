/* Render the GUI's real JavaScript against the real HTML in jsdom, and report what appears.
 *
 * WHY THIS AND NOT A BROWSER SCREENSHOT. A headless browser would be better, but this runs in
 * CI without one, and it catches the failures that matter for these two views: a helper that
 * throws, an element id that does not exist, a payload key read under the wrong name, a
 * click handler that never fires. Those are exactly the defects that make a view render EMPTY,
 * which on this project looks identical to a quiet network.
 *
 * It is not a substitute for looking at the page -- it asserts structure, not aesthetics. Its
 * value is that it EXECUTES the shipping code rather than pattern-matching its source.
 *
 * Usage: node jsdom_render.js <base-url>
 */
const fs = require("fs");
const path = require("path");
const { JSDOM, VirtualConsole } = require("/tmp/node_modules/jsdom");

const BASE = process.argv[2] || "http://127.0.0.1:8099";
const WEB = "/home/hart/Documents/flowforge/weirvern/admin/web";

const failures = [];
const notes = [];
function check(label, ok, detail) {
  if (ok) notes.push(`  PASS  ${label}`);
  else failures.push(`  FAIL  ${label}${detail ? " -- " + detail : ""}`);
}

async function main() {
  const html = fs.readFileSync(path.join(WEB, "index.html"), "utf8");

  // Capture page errors: a TypeError inside a render function is invisible on screen -- the
  // panel just stays empty -- so it has to be collected here.
  const errors = [];
  const vc = new VirtualConsole();
  vc.on("jsdomError", (e) => errors.push(String(e.detail || e.message || e)));
  vc.on("error", (...a) => errors.push("console.error: " + a.join(" ")));

  const dom = new JSDOM(html, {
    runScripts: "dangerously",
    resources: undefined,
    url: BASE + "/",
    virtualConsole: vc,
    pretendToBeVisual: true,
  });
  const { window } = dom;
  const doc = window.document;

  // Load the three scripts in the SAME ORDER index.html declares, reading them from disk so
  // this tests the shipping files rather than a copy.
  const order = [];
  doc.querySelectorAll("script[src]").forEach((s) => order.push(s.getAttribute("src")));
  check("index.html loads the scripts in the required order",
        JSON.stringify(order) === JSON.stringify(["/app.js", "/soc.js", "/assets.js"]),
        JSON.stringify(order));

  // EVALUATE THE THREE FILES AS ONE UNIT, which is what a browser effectively does: <script>
  // tags share one global lexical scope, so a `const` in app.js is visible to assets.js.
  // Evaluating them separately (one window.eval per file) gives each its own scope, and the
  // cross-file references then look like undefined identifiers -- a harness artefact that
  // would send me hunting for a bug in the shipping code.
  //
  // An epilogue then publishes the bindings the assertions below need. `const` at the top level
  // of a script is a global LEXICAL binding, not a property of `window`, so `H.ASSETS_STATE`
  // is undefined in a real browser too -- reaching it from outside needs this explicit handle.
  const bundle = order.map((src) => fs.readFileSync(path.join(WEB, path.basename(src)), "utf8"))
                      .join("\n;\n");
  const epilogue = `
    window.__H = { ASSETS_STATE, renderAssets, renderNetwork, renderChips, loadAssets,
                   loadNetwork, drawGraph, toggleTracked, loadZeekLog, loadFlowDetail, openHost,
                   chartFrame, svgEl, fmtBytes, el, renderStaleness, renderPager };
  `;
  try {
    window.eval(bundle + epilogue);
  } catch (e) {
    failures.push(`  FAIL  the bundle threw at load: ${e.message}`);
  }
  check("all three scripts evaluated without a load-time throw", errors.length === 0,
        errors.slice(0, 3).join(" | "));

  // Stub fetch BEFORE anything calls it. `toggleTracked` and `loadNetwork` refetch, and in
  // jsdom an unstubbed fetch rejects -- which would set the graph to "unavailable" and
  // re-render over the state each assertion is about to inspect. Stubbing it keeps the
  // click-to-track path testable end to end.
  const FLOWS_PAYLOAD = {
    available: true, reason: "", port: 443, proto: null, hours: 24,
    points: [
      { src_addr: "192.0.2.10", dst_addr: "203.0.113.15", dst_port: 443,
        bytes: 271422406, flows: 374 },
      { src_addr: "192.0.2.10", dst_addr: "192.0.2.1", dst_port: 443, bytes: 900000, flows: 40 },
    ],
    total_flows: 414, total_pairs: 276, truncated: true,
  };
  const GRAPH_PAYLOAD = {
    available: true, hours: 24,
    nodes: [
      { id: "203.0.113.42", name: "workstation.lan", degree: 38, bytes: 7153288 },
      { id: "192.0.2.40", name: "vault", degree: 6, bytes: 182400000 },
      { id: "203.0.113.1", name: "gateway", degree: 4, bytes: 900000 },
    ],
    edges: [
      { source: "203.0.113.42", target: "203.0.113.1", bytes: 5000000, flows: 900 },
      { source: "203.0.113.42", target: "192.0.2.40", bytes: 400000, flows: 60 },
    ],
    total_edges: 25, truncated: true, reason: "",
  };
  window.fetch = async (url) => ({
    ok: true, status: 200, statusText: "OK",
    json: async () => (String(url).includes("/api/graph") ? GRAPH_PAYLOAD
                     : String(url).includes("/api/assets")
                       ? { available: true, hours: 24, hosts: [], unreadable: [],
                           sources_read: [], sources_failed: [], reason: "" }
                     : String(url).includes("/api/flows")
                       ? FLOWS_PAYLOAD
                       : String(url).includes("/api/models")
                         ? { available: true, hours: 72, run_count: 0, training_history: {},
                             scores: {}, model_counts: {}, feature_deviations: [], points: [],
                             staleness: [], retrain_interval_h: 6 }
                         : { available: true, reason: "", log: "ssl", points: [] }),
  });

  const H = window.__H;
  if (!H) {
    console.log("  FATAL: the harness epilogue did not run -- cannot assert anything");
    process.exit(2);
  }

  // Let DOMContentLoaded handlers run.
  await new Promise((r) => setTimeout(r, 100));

  // ── the new views exist ────────────────────────────────────────────────────────────────
  for (const id of ["view-host", "view-network"]) {
    check(`#${id} exists`, !!doc.getElementById(id));
  }
  check("the About view is gone", !doc.getElementById("view-about"));
  check("no About tab in the nav",
        !Array.from(doc.querySelectorAll(".tab")).some((t) => t.dataset.view === "about"));
  check("Assets and Network tabs exist",
        !!doc.querySelector('.tab[data-view="host"]') &&
        !!doc.querySelector('.tab[data-view="network"]'));

  // ── the helpers the new code calls are defined ─────────────────────────────────────────
  for (const fn of ["loadAssets", "renderAssets", "loadNetwork", "renderNetwork",
                    "drawGraph", "toggleTracked", "renderChips", "loadZeekLog"]) {
    check(`${fn}() is defined`, typeof H[fn] === "function",
          `typeof = ${typeof H[fn]}`);
  }

  // ── feed real-shaped payloads and render ───────────────────────────────────────────────
  const HOSTS = [
    { addr: "203.0.113.42", name: "workstation.lan", bytes: 7153288, flows: 105190,
      dst_count: 37, services: ["conn", "http", "ssh"], anomalies: 3,
      last_seen: "2026-09-19T07:40:00", bytes_out: 6100000, bytes_in: 1053288 },
    { addr: "192.0.2.20", name: "", bytes: 2210000, flows: 41000, dst_count: 12,
      services: ["conn", "dns"], anomalies: 0, last_seen: "2026-09-19T07:39:10",
      bytes_out: 900000, bytes_in: 1310000 },
  ];
  const NODES = [
    { id: "203.0.113.42", name: "workstation.lan", degree: 38, bytes: 7153288 },
    { id: "192.0.2.40", name: "vault", degree: 6, bytes: 182400000 },
    { id: "203.0.113.1", name: "gateway", degree: 4, bytes: 900000 },
  ];
  const EDGES = [
    { source: "203.0.113.42", target: "203.0.113.1", bytes: 5000000, flows: 900 },
    { source: "203.0.113.42", target: "192.0.2.40", bytes: 400000, flows: 60 },
  ];

  H.ASSETS_STATE.inventory = {
    available: true, hours: 24, count: HOSTS.length, hosts: HOSTS,
    unreadable: ["zeek_quic"], sources_read: ["aggregate", "direction"],
    sources_failed: [], reason: "",
  };
  H.renderAssets();

  const rows = doc.querySelectorAll("#as-table tbody tr");
  check("the inventory rendered one row per host", rows.length === 2, `rows=${rows.length}`);
  const firstRow = rows[0];
  check("the address cell is clickable", !!firstRow && !!firstRow.querySelector("td.link"));
  check("the name column shows the resolved name",
        !!firstRow && firstRow.textContent.includes("workstation.lan"));
  check("the address is shown ALONGSIDE the name, not replaced by it",
        !!firstRow && firstRow.textContent.includes("203.0.113.42"));
  check("a zero-anomaly host is shown, not hidden",
        !!rows[1] && doc.querySelectorAll("#as-table tbody tr").length === 2);
  check("unreadable sources are named, not silently dropped",
        doc.getElementById("as-note").textContent.includes("zeek_quic"));

  // Search filters the cached payload.
  H.ASSETS_STATE.search = "vault";
  H.renderAssets();
  check("search narrows the inventory",
        doc.querySelectorAll("#as-table tbody tr").length <= 2);
  H.ASSETS_STATE.search = "";

  // Shift-click must track rather than drill.
  let drilled = null;
  // A top-level `function openHost(){}` becomes a property of the global object, so replacing
  // it there is visible to assets.js. Assigning to H.openHost only changed the harness object
  // and the real function still ran -- which is why the first attempt saw drilled=null.
  const realOpenHost = window.openHost;
  check("openHost is reachable as a global (so the stub can intercept it)",
        typeof realOpenHost === "function", `typeof = ${typeof realOpenHost}`);
  window.openHost = (a) => { drilled = a; };
  H.ASSETS_STATE.tracked = [];
  const ev = new window.MouseEvent("click", { bubbles: true, shiftKey: true });
  rows[0].dispatchEvent(ev);
  check("shift-click on a row TRACKS instead of drilling",
        drilled === null && H.ASSETS_STATE.tracked[0] === "203.0.113.42",
        `drilled=${drilled} tracked=${JSON.stringify(H.ASSETS_STATE.tracked)}`);

  // A plain click drills down.
  // Re-render so the row's click handler closes over the STUB: the handler captured the
  // openHost that existed at render time, so replacing it afterwards is not observable.
  H.renderAssets();
  doc.querySelectorAll("#as-table tbody tr")[0]
     .dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  check("a plain click on a row drills down", drilled === "203.0.113.42", `drilled=${drilled}`);
  H.openHost = realOpenHost;

  // ── the asset inventory pager ──────────────────────────────────────────────────────────
  // The bug this guards: 245 hosts rendered as one scroll. Pages of 15 give a stable viewport,
  // and the range must be stated -- "page 2 of 17" alone hides the total.
  const manyHosts = [];
  for (let i = 1; i <= 47; i++) {
    manyHosts.push({ addr: "192.0.2." + i, name: "", bytes: i * 1000, flows: i,
      dst_count: 1, services: [], anomalies: 0, last_seen: "2026-01-01T00:00:00" });
  }
  H.ASSETS_STATE.inventory = {
    available: true, hours: 24, count: manyHosts.length, hosts: manyHosts,
    unreadable: [], sources_read: [], sources_failed: [], reason: "",
  };
  H.ASSETS_STATE.page = 1;
  H.ASSETS_STATE.search = "";
  H.renderAssets();

  check("the inventory shows only one page of rows at a time",
        doc.querySelectorAll("#as-table tbody tr").length === 15,
        `${doc.querySelectorAll("#as-table tbody tr").length} rows`);
  check("the pager states the range AND the total",
        doc.getElementById("as-pager").textContent.includes("1\u201315 of 47"),
        doc.getElementById("as-pager").textContent);
  check("the pager states which page of how many",
        doc.getElementById("as-pager").textContent.includes("page 1 of 4"),
        doc.getElementById("as-pager").textContent);
  check("'previous' is disabled on the first page",
        doc.querySelector("#as-pager .pager-btn").disabled === true);

  // The next arrow must advance, and the rows must change.
  const nextBtn = Array.from(doc.querySelectorAll("#as-pager .pager-btn")).find(
    (b) => b.textContent.includes("\u203a"));
  check("a next arrow exists", !!nextBtn);
  nextBtn.dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  check("clicking next advances to page 2",
        doc.getElementById("as-pager").textContent.includes("page 2 of 4"),
        doc.getElementById("as-pager").textContent);
  check("page 2 shows the NEXT range of hosts",
        doc.getElementById("as-pager").textContent.includes("16\u201330 of 47"),
        doc.getElementById("as-pager").textContent);
  check("page 2 still shows exactly 15 rows",
        doc.querySelectorAll("#as-table tbody tr").length === 15);
  // Assert the rows CHANGED, not a specific address: the default sort is by anomalies then
  // bytes, so page 1 holds the highest-byte hosts and pinning a literal would encode an
  // assumption about the sort rather than about pagination (which is what is under test here).
  const pageTwoFirst = doc.querySelector("#as-table tbody tr td").textContent;
  check("the rows on page 2 differ from page 1",
        pageTwoFirst !== "192.0.2.47", `page2 first row = ${pageTwoFirst}`);

  // The last page holds the remainder, not a full slice.
  H.ASSETS_STATE.page = 4;
  H.renderAssets();
  check("the final page holds only the remaining rows",
        doc.querySelectorAll("#as-table tbody tr").length === 2,
        `${doc.querySelectorAll("#as-table tbody tr").length} rows`);
  check("the final page's range stops at the total",
        doc.getElementById("as-pager").textContent.includes("46\u201347 of 47"),
        doc.getElementById("as-pager").textContent);
  check("'next' is disabled on the last page",
        Array.from(doc.querySelectorAll("#as-pager .pager-btn"))
          .find((b) => b.textContent.includes("\u203a")).disabled === true);

  // Sorting by address must be NUMERIC: "…​.10" before "…​.2" looks broken in an IP column.
  H.ASSETS_STATE.page = 1;
  H.ASSETS_STATE.sort = "addr";
  H.renderAssets();
  const addrCells = Array.from(doc.querySelectorAll("#as-table tbody tr"))
    .map((tr) => tr.querySelector("td").textContent);
  const numeric = addrCells.every((v, i) =>
    i === 0 || Number(v.split(".")[3]) >= Number(addrCells[i - 1].split(".")[3]));
  check("sorting by address is NUMERIC, not lexicographic", numeric,
        `first page: ${addrCells.slice(0, 5).join(", ")}`);
  H.ASSETS_STATE.sort = "anomalies";

  // A filter that shrinks the set must not leave the reader stranded past the end.
  H.ASSETS_STATE.page = 4;
  H.ASSETS_STATE.search = "192.0.2.3";
  H.renderAssets();
  check("a search RESETS to page 1 rather than stranding on an empty page",
        H.ASSETS_STATE.page === 1 && doc.querySelectorAll("#as-table tbody tr").length > 0,
        `page=${H.ASSETS_STATE.page} rows=${doc.querySelectorAll("#as-table tbody tr").length}`);
  H.ASSETS_STATE.search = "";
  H.ASSETS_STATE.page = 1;
  H.renderAssets();

  // ── the graph ──────────────────────────────────────────────────────────────────────────
  // Clear the selection first: the shift-click test above deliberately leaves 203.0.113.42
  // tracked, and that host is the highest-degree node -- so clicking node[0] would TOGGLE IT
  // OFF instead of adding it, and the failures would look like broken click handling.
  H.ASSETS_STATE.tracked = [];
  H.ASSETS_STATE.graph = {
    available: true, hours: 24, nodes: NODES, edges: EDGES,
    total_edges: 25, truncated: true, reason: "",
  };
  H.renderNetwork();
  const svg = doc.querySelector("#nw-graph svg");
  check("the graph drew an <svg>", !!svg);
  check("the graph drew one group per node",
        !!svg && svg.querySelectorAll("g.node").length === NODES.length,
        svg ? `nodes=${svg.querySelectorAll("g.node").length}` : "no svg");
  check("the graph drew one line per edge",
        !!svg && svg.querySelectorAll("line.edge").length === EDGES.length);
  check("truncation is stated in the caption",
        doc.getElementById("nw-caption").textContent.includes("capped"),
        doc.getElementById("nw-caption").textContent);
  check("the chips area explains the empty selection",
        doc.getElementById("nw-selected").textContent.includes("every connection"),
        doc.getElementById("nw-selected").textContent.slice(0, 80));

  // Clicking a node tracks it -- the multi-host selection requirement.
  const groups = svg.querySelectorAll("g.node");
  groups[0].dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  check("clicking a node adds it to the tracked set",
        H.ASSETS_STATE.tracked.length >= 1,
        JSON.stringify(H.ASSETS_STATE.tracked));
  // Clicking a node triggers loadNetwork(), which is async: the re-render that marks the node
  // as selected happens in a later tick. Asserting synchronously measures the clock, not the
  // code -- and that is exactly what produced the earlier false failure.
  await new Promise((r) => setTimeout(r, 60));
  check("the tracked host appears as a removable chip",
        doc.querySelectorAll("#nw-selected .chip").length >= 1,
        `${doc.querySelectorAll("#nw-selected .chip").length} chip(s)`);
  check("the selected node is marked in the DOM",
        doc.querySelectorAll("#nw-graph g.node.selected").length >= 1,
        `${doc.querySelectorAll("#nw-graph g.node.selected").length} selected of ` +
        `${doc.querySelectorAll("#nw-graph g.node").length}`);
  check("the node's circle is recoloured to show it is tracked",
        (() => {
          const c = doc.querySelector("#nw-graph g.node.selected circle");
          return !!c && c.getAttribute("fill") === "#5ec26a";
        })());

  // Two hosts tracked at once -- "select any number".
  H.ASSETS_STATE.tracked = [];
  H.renderNetwork();
  const g2 = doc.querySelectorAll("#nw-graph g.node");
  g2[0].dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  g2[1].dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await new Promise((r) => setTimeout(r, 60));
  check("two hosts can be tracked at once",
        H.ASSETS_STATE.tracked.length === 2,
        JSON.stringify(H.ASSETS_STATE.tracked));
  check("both tracked hosts are listed as chips",
        doc.querySelectorAll("#nw-selected .chip").length === 2);
  check("a chip removes its host when clicked",
        (() => {
          doc.querySelector("#nw-selected .chip")
             .dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
          return H.ASSETS_STATE.tracked.length === 1;
        })(), JSON.stringify(H.ASSETS_STATE.tracked));

  // Clearing restores the whole graph.
  H.ASSETS_STATE.tracked = ["203.0.113.42", "192.0.2.40"];
  H.renderNetwork();
  doc.getElementById("nw-clear").dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  await new Promise((r) => setTimeout(r, 30));
  await new Promise((r) => setTimeout(r, 60));
  check("Clear selection empties the tracked set", H.ASSETS_STATE.tracked.length === 0,
        JSON.stringify(H.ASSETS_STATE.tracked));

  // ── honest failure states ──────────────────────────────────────────────────────────────
  H.ASSETS_STATE.graph = { available: false, nodes: [], edges: [],
                               reason: "the connection query failed" };
  H.renderNetwork();
  check("a failed graph query names the reason rather than drawing an empty canvas",
        doc.getElementById("nw-graph").textContent.includes("connection query failed"),
        doc.getElementById("nw-graph").textContent.slice(0, 90));

  H.ASSETS_STATE.graph = { available: true, nodes: [], edges: [], total_edges: 0 };
  H.renderNetwork();
  check("an empty graph says nothing was recorded, not that it failed",
        doc.getElementById("nw-graph").textContent.includes("No host-to-host traffic"),
        doc.getElementById("nw-graph").textContent.slice(0, 90));

  H.ASSETS_STATE.inventory = { available: false, hosts: [], reason: "cannot reach ClickHouse" };
  H.renderAssets();
  check("a failed inventory query names the reason",
        doc.getElementById("as-note").textContent.includes("cannot reach ClickHouse"));

  // ── the Netflow click-through ──────────────────────────────────────────────────────────
  check("loadFlowDetail() is defined and reachable as a global",
        typeof window.loadFlowDetail === "function", `typeof = ${typeof window.loadFlowDetail}`);

  await window.loadFlowDetail({ port: 443, name: "port 443" });
  await new Promise((r) => setTimeout(r, 40));
  const fdRows = doc.querySelectorAll("#nf-detail-table tbody tr");
  check("the flow drill-down renders one row per host pair", fdRows.length === 2,
        `rows=${fdRows.length}`);
  check("the drill-down names the bar that was clicked",
        doc.getElementById("nf-detail-title").textContent.includes("443"),
        doc.getElementById("nf-detail-title").textContent);
  check("the drill-down states that the list was CAPPED",
        doc.getElementById("nf-detail-note").textContent.includes("busiest of"),
        doc.getElementById("nf-detail-note").textContent);
  check("the drill-down draws a bar chart too", !!doc.querySelector("#nf-detail .bar-row"));
  check("a drill-down row is clickable through to the host",
        !!fdRows[0] && fdRows[0].className.includes("clickable"));

  // A failed query must say so, not render an empty panel.
  window.fetch = async (url) => ({
    ok: true, status: 200, statusText: "OK",
    json: async () => (String(url).includes("/api/flows")
      ? { available: false, points: [], reason: "the flow drill-down failed" }
      : { available: true, hours: 24, hosts: [], unreadable: [], sources_read: [],
          sources_failed: [], reason: "" }),
  });
  await window.loadFlowDetail({ proto: 6, name: "TCP" });
  await new Promise((r) => setTimeout(r, 40));
  check("a failed flow drill-down names the reason",
        doc.getElementById("nf-detail").textContent.includes("flow drill-down failed"),
        doc.getElementById("nf-detail").textContent.slice(0, 90));

  // ── the Models staleness panel ─────────────────────────────────────────────────────────
  // The bug this guards: three detectors were 16h overdue against a 6h interval and the Models
  // view drew them as healthy lines, because it plotted run COUNT rather than RECENCY.
  H.renderStaleness([
    { model: "Isolation Forest", last_trained: "2026-01-01T00:00:00", age_h: 16.0,
      stale: true, never_trained: false },
    { model: "DBSCAN", last_trained: "", age_h: null, stale: true, never_trained: true },
    { model: "Gradient Boosting", last_trained: "2026-01-02T00:00:00", age_h: 0.4,
      stale: false, never_trained: false },
  ], 6);
  const staleRows = doc.querySelectorAll("#m-stale tbody tr");
  check("the staleness table renders one row per detector", staleRows.length === 3,
        `rows=${staleRows.length}`);
  check("an overdue detector is visibly marked",
        doc.querySelectorAll("#m-stale tbody tr.stale-row").length === 2,
        `${doc.querySelectorAll("#m-stale tbody tr.stale-row").length} tinted`);
  check("the overdue detector's age is shown in hours",
        doc.getElementById("m-stale").textContent.includes("16.0h"));
  check("a never-trained detector says so rather than showing an age",
        doc.getElementById("m-stale").textContent.includes("never"));
  check("the interval is stated in the heading",
        doc.getElementById("m-stale-window").textContent.includes("6"),
        doc.getElementById("m-stale-window").textContent);
  check("the note explains what an overdue model means for its scores",
        doc.getElementById("m-stale-note").textContent.includes("older traffic mix"),
        doc.getElementById("m-stale-note").textContent.slice(0, 100));
  check("the note distinguishes never-trained from merely overdue",
        doc.getElementById("m-stale-note").textContent.includes("never trained"));

  // ── no page errors accumulated ─────────────────────────────────────────────────────────
  check("no JavaScript errors during any of the above", errors.length === 0,
        errors.slice(0, 3).join(" | "));

  console.log(notes.join("\n"));
  if (failures.length) {
    console.log("\n" + failures.join("\n"));
    console.log(`\n  ${failures.length} FAILED, ${notes.length} passed`);
    process.exit(1);
  }
  console.log(`\n  all ${notes.length} checks passed`);
}

main().catch((e) => { console.error("harness error:", e); process.exit(2); });
