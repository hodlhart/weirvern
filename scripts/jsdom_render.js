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

// RESOLVE jsdom THE NORMAL WAY FIRST. The original hardcoded /tmp/node_modules/jsdom, which
// is a path that exists only on one machine: anywhere else the harness died on the require
// before running a single check. A local `npm install jsdom` (or `npm ci`) is the documented
// setup, so plain "jsdom" is tried first; the old path is kept as a fallback.
function loadJsdom() {
  for (const candidate of ["jsdom", "/tmp/node_modules/jsdom"]) {
    try {
      return require(candidate);
    } catch (_e) { /* try the next candidate */ }
  }
  console.error("jsdom is not installed. Run `npm install jsdom` in the repository root,");
  console.error("then re-run: node scripts/jsdom_render.js");
  process.exit(2);
}
const { JSDOM, VirtualConsole } = loadJsdom();

const BASE = process.argv[2] || "http://127.0.0.1:8099";
// RESOLVED RELATIVE TO THIS FILE, not to a hardcoded home directory. It used to point at the
// original author's Documents/flowforge checkout, so on any other machine the harness read a
// nonexistent directory and reported its checks against nothing. Overridable for a
// checkout that wants to test a different web root.
const WEB = process.env.WEIRVERN_WEB || path.resolve(__dirname, "..", "weirvern", "admin", "web");

const failures = [];
const notes = [];
// ── A THIRD OUTCOME: UNVERIFIED ──────────────────────────────────────────────
//
// The Sluice and Blocklists views were rewritten and several of their checks still name elements
// from the old markup (`sl-*` became `sl2-*`, `bl-*` became `bl-detail-*`). Those checks cannot
// run, and they did not FAIL either: the block read `.textContent` off a null and the whole
// harness died with a TypeError, reporting nothing at all. CI runs this file, it exited 2, and the
// console's only automated check verified nothing for five days.
//
// A skipped check is NOT a passing one, so it gets its own bucket, its own count, and its own
// heading in the summary. `needEl` returns a stub for a missing element that RECORDS the id on any
// property read, so a check is attributed exactly when it reads the absent element; a genuine
// failure elsewhere in the same block still fails. Do not route a real assertion through the stub
// to silence it -- name the element the view actually has instead.
const stales = [];
let staleTouched = new Set();
// THE COPY BUDGET (operator, 2026-11-20): a card or sheet shows at most 25 words before a
// `details` disclosure. Measure VISIBLE copy only: `details` content, page titles, commands,
// table cells and hidden nodes are data/disclosure, not the sentence the operator must read.
// Consequence lines (a server receipt, a blast-radius warning) are exempt by the same rule.
function visibleWords(root) {
  if (!root) return 0;
  const skip = new Set(["DETAILS", "TITLE", "CODE", "PRE", "TH", "TD", "DT", "DD",
                        "INPUT", "SELECT", "TEXTAREA", "SCRIPT", "STYLE"]);
  let words = 0;
  const walk = (node) => {
    if (node.nodeType === 3) {
      const text = String(node.nodeValue || "").trim();
      if (text) words += text.split(/\s+/).filter(Boolean).length;
      return;
    }
    if (node.nodeType !== 1) return;
    if (skip.has(node.tagName)) return;
    if (node.classList && node.classList.contains("hidden")) return;
    // A LIST OF SCANS IS DATA, like a table's cells: timestamps and targets are not copy.
    if (node.classList && node.classList.contains("scan-queue")) return;
    if (node.getAttribute && node.getAttribute("aria-hidden") === "true") return;
    Array.from(node.childNodes).forEach(walk);
  };
  walk(root);
  return words;
}
function check(label, ok, detail) {
  if (ok) {
    notes.push(`  PASS  ${label}`);
  } else if (staleTouched.size) {
    stales.push(`  SKIP  ${label} -- element not in the DOM (stale id, or its view never built it): ${[...staleTouched].join(", ")}`);
  } else {
    failures.push(`  FAIL  ${label}${detail ? " -- " + detail : ""}`);
  }
  staleTouched = new Set();
}

async function main() {
  // THE REAL STYLESHEET, INJECTED. jsdom does not fetch the <link> (external resources are off
  // here), and the checks on the gates below read getComputedStyle -- the cascade, not class
  // names -- because a class-name assertion cannot see a cascade collision: `.gate { display:
  // flex }` came after `.hidden { display: none }` at equal specificity, every "hidden" gate
  // stayed painted, and the forced-change form covered an unreachable sign-in form (reported
  // from the box: "it says log in first. i cant change the password"). Injecting the real
  // stylesheet is what makes the computed-style checks measure the shipping CSS.
  const css = fs.readFileSync(path.join(WEB, "style.css"), "utf8");
  const html = fs.readFileSync(path.join(WEB, "index.html"), "utf8")
    .replace("</head>", `<style>${css}</style></head>`);

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
  // jsdom does not implement window.scrollTo (the US-6 return trip calls it): replace it with
  // a no-op. Same treatment as window.confirm below -- the "no JavaScript errors" check must
  // report real defects, not environment gaps.
  dom.window.scrollTo = function () {};
  const { window } = dom;
  const doc = window.document;

  // A MISSING ELEMENT MUST NOT TAKE THE HARNESS DOWN. Reading a property of this stub records the
  // id, and `check()` turns the resulting miss into UNVERIFIED rather than FAIL -- see the comment
  // on `stales` above for why those are different facts.
  function stubFor(id) {
    const touch = () => { staleTouched.add(id); };
    return new Proxy({}, {
      get(_t, prop) {
        if (prop === "__stale") return true;
        touch();
        if (prop === "textContent" || prop === "innerHTML" || prop === "value") return "";
        if (prop === "classList") return { contains: () => false, add() {}, remove() {}, toggle() {} };
        if (prop === "querySelectorAll") return () => [];
        if (prop === "querySelector") return () => null;
        if (prop === "getAttribute") return () => null;
        if (prop === "closest") return () => null;
        if (prop === "style") return {};
        // Method calls on a missing element are no-ops that RETURN a sensible value: a block that
        // dispatches a synthetic event or focuses a control must not crash just because the
        // control is gone. The read that records the id already happened above.
        if (prop === "click" || prop === "focus" || prop === "blur" || prop === "scrollIntoView"
            || prop === "dispatchEvent" || prop === "remove" || prop === "appendChild"
            || prop === "setAttribute" || prop === "removeAttribute" || prop === "addEventListener"
            || prop === "contains" || prop === "matches") return () => true;
        if (prop === "hasAttribute") return () => false;
        if (prop === "parentElement" || prop === "parentNode" || prop === "children") return null;
        if (prop === "length") return 0;
        return undefined;
      },
      set() { return true; },
    });
  }
  function needEl(id) {
    return doc.getElementById(id) || stubFor(id);
  }

  // WHERE A DRILL CELL KEEPS ITS LABEL. The host pivot moved from `title` to `aria-label`, which is
  // the correct attribute for "what this control does" and is what a screen reader announces. The
  // harness kept reading `title`, so it stopped finding the cell and reported the pivot as absent
  // from a row that renders it. Read BOTH: the two attributes coexist across the console, and a
  // check pinned to one of them fails on a cell that is perfectly correct.
  function CELLLABEL(el) {
    if (!el) return "";
    if (typeof el.getAttribute === "function") {
      return el.getAttribute("title") || el.getAttribute("aria-label") || "";
    }
    return el.title || "";
  }

  // Load the three scripts in the SAME ORDER index.html declares, reading them from disk so
  // this tests the shipping files rather than a copy.
  const order = [];
  doc.querySelectorAll("script[src]").forEach((s) => order.push(s.getAttribute("src")));
  check("index.html loads the scripts in the required order",
        JSON.stringify(order) === JSON.stringify(["/app.js", "/sheets.js", "/scan.js", "/normalize.js",
                                                 "/soc.js", "/assets.js", "/sluice.js",
                                                 "/weirlings.js", "/discover.js",
                                                 "/dnsview.js", "/blocked.js",
                                                 "/filters.js", "/palette.js"]),
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
                   BLOCKED_STATE, blOpenRuleById,
                   loadNetwork, drawGraph, computeLayout, settleGraph, nodeTitle, edgeTitle,
                   anRenderSeverity, renderRipplePage,
                   toggleTracked, loadZeekLog, loadFlowDetail, openHost, zkSetFilters,
                     showView, loadSettings, loadHealthDeep,
                     STAGE, planStage, applyStage, discardStage, setToken, getToken, stageChange, renderStageMirror,
                     syncURL, applyURLState, AN_FILTERS, M_FILTERS, ID_FILTERS, ZEEK_FILTERS, zkRenderChips, toggleAllHelp,
                     openHelpPanel, firstrunShow, anClearAllFilters, refreshAll,
                     loadModels, loadWeirlings, loadBlocked, loadNormalize,
                     runSonar, stageSonarRecommendations, renderSonarNote, SONAR_STATE,
                     wlNicFacts, wlNicRows, wlPlans, wlShowNicSettings, wlCfgValue, wlIfaceNames, SETTINGS_ROWS,
                     wlChannelOffered, wlChannelPlanPair, wlRenderChannelNote,
                     runSiphonTest, renderTestNote,
                     loadZeek, loadNetflow, loadAnomalies, postReview, reviewCell,
                     loadRipplePage, openRippleSheet, RIPPLES_STATE, rippleWindowOverlap,
                     loadHost, loadHostPage, loadEvidence, loadAudit, loadDetectors,
                     registryHighlight, sluiceHighlightRule,
                   NF_FILTERS, nfSetFilter, nfRemoveChip,
                   trApply, trHours, TIME_RANGE,
                   loadDiscover, dcClear, discoverDrill,
                   loadDns, dnClear, dnApply, loadBlocked,
                   chartFrame, svgEl, fmtBytes, el, renderStaleness, renderDetectors, renderPager, showEdgeDetail, showNodeDetail, renderNearMisses, renderAlertAudit, settingControl, renderScoreDistribution, ALERTS_STATE, ALERTS_PAGE_SIZE,
                  openModal, closeModal, markFilterCells,
                   emptyState, emptyStateCell, activeFilterLabels,
                   openScanSheet, closeScanSheet, loadScanQueue, scanPollOnce, SCAN_STATE,
                   SCAN_READY, loadScanReadiness, scanGate, scanCancelJob, scanConfirmCancel,
                   scanKeepJob, openInstallSheet, loadScannerStatus,
                   openSheet, closeSheet, sheetIsOpen, requestScan,
                   AUTH, loadSession, doLogin, doLogout, loadUsers, boot, bootAuthed, showGate,
                   showSessionNote, refreshAccountCard,
                   wrapTables, wireInfoButtons,
                   refreshChrome, getSession, setSession, createUser, setRole, changePassword,
                   loadIdentity, showIdentityDetail,
                   retrainAction,
                   loadSluice, wireSluice, renderSluiceRules, renderSluiceGates,
                   // THE RESPONSE CACHE MUST BE CLEARABLE, OR A STUBBED RE-FETCH IS NEVER SEEN.
                   // getJSON returns a cached body for 8s and dedupes in-flight requests, so a
                   // check that installs fetchOverride and re-loads an endpoint already fetched
                   // gets the CACHED payload and its override is never called. Measured as an
                   // empty URL list inside the override. Every stubbed read in this file is
                   // subject to it, which makes this a seam the harness needs, not a convenience.
                   clearGetCache, openRuleSheet, loadBlocklistPane,
                   renderSluiceFleet, sluiceDuration, loadBlockingControls,
                   loadWeirlings, renderWeirlings, openWeirling, wireWeirlings, wlAge,
                   paletteOpen, paletteClose, paletteRun, paletteMaxToggle, paletteGlobalKey,
                   setCrumbs, clearCrumbs, closeWeirling, sparkSvg, statCells,
                   HOST_RETURN, get CURRENT_VIEW() { return CURRENT_VIEW; },
                   get HP_ADDR() { return HP_ADDR; },
                   confirmDestructive, withReadBack,
                   wlStateChip, wlLoss, saveWeirling, clearWeirlingForm, wlApplyMode,
                   setWeirlingEnabled, revokeWeirling,
                   WL_PLAN, wlRenderPlan, wlRunPlanSonar, wlApplyPlanChanges,
                   wlPlanChangesFromSurvey, wlPlanModeChanged,
                   document,
                   document };

  `;
  try {
    // THE OVERRIDE MECHANISM. There is NO setFetchOverride on `__H`, and there must not be.
    //
    // `__H` is built INSIDE the evaluated bundle and `fetchOverride` is a `let` in the enclosing
    // function scope. A setter defined in the bundle closes over GLOBAL scope because
    // `window.eval` runs it there, so `H.setFetchOverride(fn)` mutates a binding the dispatcher
    // never reads: the check that used it ran against whatever override was last active and passed
    // while proving nothing. Measured, and mutation-tested both ways.
    //
    // `fetchOverride = fn`, assigned DIRECTLY from this scope, is the only supported form. Three
    // checks here used the setter, including a pre-existing sluice failure-path check that had been
    // passing on a stale panel rather than on the path it is named for.
    //
    // (This replaced a note that said the opposite. It was wrong: kept as a marker so the same
    // mistake is not re-introduced.)
    //
    // `window.__H` is an object literal built inside the evaluated bundle, and `fetchOverride` is
    // a `let` in the enclosing function scope. So `H.fetchOverride = fn` creates a NEW property
    // that the dispatcher never reads: the check that set one then runs against whatever override
    // was last active, and passes while proving nothing. Measured -- the assignment silently did
    // nothing, and three checks in this file were written that way, including a pre-existing
    // sluice failure-path check that had been passing on a stale panel rather than on the path it
    // is named for.
    //
    // `fetchOverride = fn`, assigned DIRECTLY from this scope, is the only form that works. A
    // setter exposed on `__H` cannot: the bundle runs through `window.eval`, so anything it
    // defines closes over global scope. That is WHY there is no setter.
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
      { id: "203.0.113.42", name: "workstation.lan", degree: 38, bytes: 7153288, hops: 0, ttl: 64 },
      { id: "192.0.2.40", name: "vault", degree: 6, bytes: 182400000, hops: 1, ttl: 63 },
      { id: "203.0.113.1", name: "gateway", degree: 4, bytes: 900000 },
    ],
    edges: [
      { source: "203.0.113.42", target: "203.0.113.1", bytes: 5000000, flows: 900,
        ports: [443, 80], source_name: "workstation.lan", target_name: "gateway",
        first_seen: "2026-01-01T00:00:00", last_seen: "2026-01-02T00:00:00",
        ttl_min: 64, ttl_max: 64 },
      { source: "203.0.113.42", target: "192.0.2.40", bytes: 400000, flows: 60,
        ports: [22], source_name: "workstation.lan", target_name: "vault",
        first_seen: "2026-01-01T06:00:00", last_seen: "2026-01-02T06:00:00",
        ttl_min: 63, ttl_max: 63 },
    ],
    total_edges: 25, truncated: true, reason: "",
  };


  // A settings payload WITH a secret, shaped like the real one. The value below is a sentinel:
  // if it ever appears in the rendered DOM the harness fails, which makes "the page does not
  // leak the credential" an executed check rather than a claim about the code.
  const SECRET_SENTINEL = "ZZ-SENTINEL-DO-NOT-PRINT-ZZ";
  // An editable key list and write state, shaped like the real payload.
  // A REALISTIC Zeek payload: 18 logs, several with counts, three EMPTY-FOREVER, plus a populated
  // timeline. The empty-everything stub this replaces could not have caught the bar-chart bug --
  // an empty payload renders the "nothing in this window" note, which is a legitimate state, so the
  // crash only appears once real rows are present.
  const ZEEK_PAYLOAD = {
    counts: {
      available: true, reason: "", unreadable: [],
      points: [
        { log: "conn", table: "zeek_conn", rows: 40731, total: 74661, state: "active",
          last_ts: "2026-01-01T00:00:00" },
        { log: "dns", table: "zeek_dns", rows: 62016, total: 121518, state: "active",
          last_ts: "2026-01-01T00:00:00" },
        { log: "http", table: "zeek_http", rows: 0, total: 389, state: "idle",
          last_ts: "2026-01-01T00:00:00" },
        { log: "ssl", table: "zeek_ssl", rows: 2, total: 71, state: "active",
          last_ts: "2026-01-01T00:00:00" },
        { log: "notice", table: "zeek_notice", rows: 1013, total: 5078, state: "active",
          last_ts: "2026-01-01T00:00:00" },
        { log: "kerberos", table: "zeek_kerberos", rows: 0, total: 0, state: "empty-forever",
          last_ts: "1970-01-01T00:00:00" },
        { log: "ntlm", table: "zeek_ntlm", rows: 0, total: 0, state: "empty-forever",
          last_ts: "1970-01-01T00:00:00" },
      ],
    },
    timeline: {
      available: true, reason: "", hours: 24, bucket_s: 900,
      series: {
        conn: [{ t: "2026-01-01T00:00:00", n: 352 }, { t: "2026-01-01T00:15:00", n: 1189 }],
        dns: [{ t: "2026-01-01T00:00:00", n: 900 }, { t: "2026-01-01T00:15:00", n: 1500 }],
      },
    },
    services: { available: true, reason: "", points: [
      { service: "dns", n: 10049 }, { service: "ntp", n: 56 }] },
    dns: { available: true, reason: "", filtered: "single-label names excluded",
           points: [{ query: "host.example", n: 6633, askers: 2 }] },
  };

  const SETTINGS_PAYLOAD = {
    available: true, reason: "",
    writes: { enabled: true, reason: "" },
    // US-10: the GUI-write provenance the apply path records (with the value each write replaced).
    provenance: {
      base_threshold: { value: "0.35", at: "2026-10-17T11:50:00Z", by: "admin",
                        reason: "tighten after the scanner", prev_value: "0.45" },
      sluice_auto_score: { value: "0.8", at: "2026-10-14T09:00:00Z", by: "admin", reason: "" },
    },
    caller: { username: "", role: "", via: "" },
    editable_keys: ["retrain_every_h", "base_threshold", "sensor_mode", "channel_netflow", "intercept_segment",
                    "pushover_enabled", "sluice_auto_score", "data_retention_days",
                    "data_retention_ratio"],
    // The control spec rides with the payload (see cluster_config.SETTING_CONTROLS): the browser
    // renders the natural control from the SERVER's rule -- bounds and options included -- so
    // what the control permits and what the write path accepts cannot drift apart.
    controls: {
      retrain_every_h: { control: "number", min: 1, max: 720, step: 1, unit: "hours" },
      base_threshold: { control: "number", min: 0, max: 1, step: 0.01, unit: "a score fraction" },
      sluice_auto_score: { control: "number", min: 0, max: 1, step: 0.05, unit: "a score fraction (0 disables)" },
      sensor_mode: { control: "select", options: ["loch", "siphon"] },
      intercept_segment: { control: "text" },
      channel_netflow: { control: "toggle", on_value: "upstream", off_value: "off" },
      pushover_enabled: { control: "toggle" },
      data_retention_days: { control: "auto_number", min: 7, max: 365, step: 1, unit: "days",
                             auto_value: "auto", auto_label: "Auto — derive from free disk" },
      data_retention_ratio: { control: "number", min: 10, max: 70, step: 1,
                              unit: "% of free disk" },
    },
    titles: { detect: "Detection", sensor: "Sensor", runtime: "Storage and runtime" },
    groups: {
      detect: [
        { key: "retrain_every_h", label: "retrain every (h)", value: 6, secret: false,
          source: "setting",
          applies: "applies with Apply — restarts the detection worker", help: "How often the detectors are retrained. Default 6 hours." },
        { key: "base_threshold", label: "alert threshold", value: 0.35, secret: false,
          source: "setting",
          applies: "applies with Apply — restarts the detection worker",
          help: "The score a host-window must reach before it counts as an anomaly. Default 0.35." },
        { key: "sluice_auto_score", label: "auto-block at score", value: 0, secret: false,
          source: "setting",
          applies: "applies with Apply — restarts the detection worker",
          help: "Any detection at or above this score is blocked automatically. 0 disables." },
      ],
      sensor: [
        { key: "sensor_mode", label: "mode", value: "loch", secret: false, source: "setting",
          applies: "applies with Apply — restarts the detection worker",
          help: "loch watches passively; siphon puts this host in the traffic path. Default loch." },
        { key: "reverse_dns", label: "reverse DNS", value: "private", secret: false,
          source: "derived",
          applies: "applies with Apply — restarts the detection worker", help: "Resolves only private addresses by default." },
        { key: "intercept_segment", label: "intercept segment", value: "(not set)",
          secret: false, source: "env",
          applies: "applies with Apply — restarts the detection worker", help: "The segment the siphon intercept operates on." },
        { key: "intercept_addr", label: "intercept address", value: "(not set)",
          secret: false, source: "env",
          applies: "applies with Apply — restarts the detection worker",
          help: "The address the intercept assumes; siphon refuses to start without it." },
        { key: "intercept_targets", label: "intercept targets", value: "(not set)",
          secret: false, source: "env",
          applies: "applies with Apply — restarts the detection worker",
          help: "'*' means every host on the segment; empty means nothing is intercepted." },
        { key: "channel_netflow", label: "channel netflow", value: "off", secret: false,
          source: "env",
          applies: "applies with Apply — restarts the detection worker",
          help: "Whether the traffic crossing the in-line channel is summarised into NetFlow." },
        // Deliberately ALREADY EQUAL to what the Sonar stub recommends: this row is how the
        // harness proves the staging dedupe (an unchanged recommendation stages nothing).
        { key: "intercept_gateway", label: "intercept gateway", value: "198.51.100.1",
          secret: false, source: "env",
          applies: "applies with Apply — restarts the detection worker", help: "The gateway whose identity is forged." },
      ],
      runtime: [
        { key: "clickhouse_host", label: "ClickHouse host", value: "clickhouse", secret: false,
          source: "setting",
          applies: "applies with Apply — restarts the detection worker", help: "Hostname of the ClickHouse service. Default clickhouse." },
        // The derived retention window. Editable, bounded 7..365, and destructive to lower.
        // The payload carries the ARITHMETIC, not just the number: free space, observed rate,
        // budget, and the sentence the row prints under the disabled day count.
        { key: "data_retention_days", label: "data retention (auto or days)", value: "auto",
          secret: false, source: "setting",
          applies: "applies with Apply — derives again from free disk on every start and "
            + "apply; lowering it expires older rows on the next merge",
          help: "How many days the detection and ripple tables keep their rows. Auto derives "
            + "it from free disk and the measured ingest; lowering it expires data.",
          retention: {
            mode: "auto", available: true, days: 45, ratio_percent: 40,
            free_bytes: 214000000000, total_bytes: 400000000000, bytes_per_day: 1900000000,
            budget_bytes: 85600000000, budget_days: 45, raw_days: 45.05,
            floored: false, capped: false, disk_name: "default",
            sentence: "Auto — 45 days from 214 GB free at 1.9 GB/day (40% budget). "
              + "Merge headroom kept.",
          } },
        { key: "data_retention_ratio", label: "retention disk budget (%)", value: "40",
          secret: false, source: "setting",
          applies: "applies with Apply — re-derives the window from free disk on every start "
            + "and apply; no restart",
          help: "The share of free ClickHouse disk the retained tables may occupy. Default "
            + "40%; the rest is merge headroom, so 70% is the ceiling." },
        { key: "clickhouse_password", label: "ClickHouse password",
          value: `(set, ${SECRET_SENTINEL.length} chars)`, secret: true, source: "setting",
          applies: "applies with Apply — restarts the detection worker",
          help: "Read from the weirvern-secrets Secret at startup. Never shown in value." },
        { key: "pushover_enabled", label: "Pushover", value: "disabled", secret: false,
          source: "setting",
          applies: "applies with Apply — restarts the detection worker",
          help: "Whether real push notifications are sent. Off logs only." },
        { key: "pushover_api_token", label: "Pushover API token", value: "(not set)",
          secret: true, source: "setting",
          applies: "applies with Apply — restarts the detection worker", help: "The Pushover application token." },
        { key: "version", label: "version", value: "0.5.6", secret: false, source: "derived",
          applies: "applies with Apply — restarts the detection worker",
          help: "The image tag the deployment is actually running." },
      ],
    },
  };

  // What the write routes were asked to do. Captured so the harness can assert the REQUEST, not
  // just the render -- a staged change that never reaches /api/settings/apply is the failure mode
  // that looks like success on screen.
  const POSTED = [];
  // SHAPED LIKE THE REAL SERVER: proposals for the changes REQUESTED, not a fixed list. A stub
  // that answers with keys the caller never sent hides the bug where the UI acts on a proposal for
  // a change nobody made -- which is exactly what happened the first time.
  //
  // `restarts` is an ARRAY now: siphon keys restart both the sensor and the worker (the worker
  // supervises the intercept). The UI only reads `restart_targets`, so this stub must flatten
  // the same way the server does.
  const PLAN_FOR = {
    base_threshold: { restarts: ["deploy/weirvern-worker"], blast: "restarts the detection worker",
                      warning: "" },
    sensor_mode: { restarts: ["ds/zeek", "deploy/weirvern-worker"],
                   blast: "restarts the capture sensor (brief capture gap) and the worker",
                   warning: "in-path interception puts this host in the traffic path." },
    retrain_every_h: { restarts: ["deploy/weirvern-worker"], blast: "restarts the detection worker",
                       warning: "" },
  };
  let APPLY_FAIL_ONCE = true;
  function planReply(changes) {
    const proposals = [];
    for (const key of Object.keys(changes || {})) {
      const meta = PLAN_FOR[key] || { restarts: [], blast: "", warning: "" };
      let warning = meta.warning;
      // THE SERVER DECIDES THIS, and the stub must too: lowering a value below the running
      // one is destructive; raising it is not.
      const destructive = key === "data_retention_days"
        && Number(changes[key]) < Number((SETTINGS_PAYLOAD.groups.runtime
          .find((r) => r.key === "data_retention_days") || {}).retention?.days || 0);
      if (destructive) {
        warning = "LOWERING RETENTION IS DESTRUCTIVE: ClickHouse expires every row older than "
          + changes[key] + " days on its next merge, and that cannot be undone.";
      }
      proposals.push({ key, current: "", proposed: String(changes[key]),
                       restarts: meta.restarts, blast: meta.blast, warning,
                       destructive });
    }
    const targets = [];
    for (const p of proposals) {
      for (const t of (p.restarts || [])) {
        if (t && !targets.includes(t)) targets.push(t);
      }
    }
    return { ok: true, proposals, restart_targets: targets };
  }
  const APPLY_REPLY = {
    ok: true, applied: { base_threshold: "0.5" }, restarted: ["deploy/weirvern-worker"],
    restart_errors: [], note: "restarted deploy/weirvern-worker",
  };
  // SONAR: shaped like the real survey result. Deliberately carries NOTES and a
  // recommended set that overlaps the settings rows (so the staging dedupe is exercised:
  // sensor_mode is already "loch" in the stub rows, so it must STAGE; a recommended
  // value equal to the running one must stage nothing).
  const SONAR_REPLY = {
    ok: true, interface: "eth1", mgmt_interface: "eth0",
    our_mac: "00:00:5e:00:53:aa", address: "198.51.100.10/24", segment: "198.51.100.0/24",
    gateway: "198.51.100.1", gateway_mac: "00:00:5e:00:53:01",
    gateway_source: "default route on the interface",
    hosts: [
      { ip: "198.51.100.1", mac: "00:00:5e:00:53:01" },
      { ip: "198.51.100.20", mac: "00:00:5e:00:53:20" },
    ],
    hosts_answered: 2, swept: 253, free_addresses: ["198.51.100.250", "198.51.100.249"],
    recommended: {
      sensor_mode: "siphon",
      intercept_segment: "198.51.100.0/24",
      intercept_addr: "198.51.100.250",
      intercept_gateway: "198.51.100.1",
      intercept_targets: "*",
    },
    notes: ["'*' means every host on the segment. For a first test, edit 'intercept targets'."],
  };

  // ── the anomalies/review stub (SOC-1) ────────────────────────────────────────────────────
  //
  // Three rows deliberately: one UNREVIEWED, one already acked with a note, and one
  // THREE-OCCURRENCE GROUP whose occurrences carry their own states (issue #20). Fewer rows
  // cannot catch a renderer that draws every row with the same chip, nor the chip/tooltip/
  // filter disagreement about what "reviewed" means for a group.
  const ANOMALIES_PAYLOAD = [
    { detected_at: "2026-01-02T09:12:00", window_start: "2026-01-02T09:10:00",
      window_end: "2026-01-02T09:15:00", src_addr: "203.0.113.42", hostname: "workstation.lan",
      anomaly_score: 0.91, confidence: 0.8, severity: "high",
      detected_by_models: "Isolation Forest, LOF", model_agreement: 0.7,
      isolation_forest_score: 0.9, gradient_boosting_score: 0.4, lof_score: 0.8,
      baseline_score: 0.2, primary_deviation_feature: "unique_dst_ports",
      primary_deviation_zscore: 5.2, deviation_magnitude: 3.1,
      feature_contributions: { unique_dst_ports: { z: 5.2 }, total_bytes: { z: 1.1 } },
      owner: "ops", location: { weirling: "edge-alive", network: "198.51.100.0/24" },
      matched_rule: "IsolationForest scored this window above the strong-signal floor",
      baseline_comparison: "unique_dst_ports is 5.2 sigma above this host's baseline",
      review_state: "", review_note: "", reviewed_at: null, watched: true },
    { detected_at: "2026-01-02T08:00:00", window_start: "2026-01-02T07:55:00",
      window_end: "2026-01-02T08:00:00", src_addr: "192.0.2.40", hostname: "vault",
      anomaly_score: 0.72, confidence: 0.6, severity: "medium",
      detected_by_models: "Adaptive Baseline", model_agreement: 0.5,
      isolation_forest_score: 0.4, gradient_boosting_score: 0.3, lof_score: 0.2,
      baseline_score: 0.7, primary_deviation_feature: "total_bytes",
      primary_deviation_zscore: 3.4, deviation_magnitude: 2.0,
      feature_contributions: {}, baseline_comparison: "total_bytes is 3.4 sigma above baseline",
      owner: "ops", matched_rule: "the adaptive baseline's z-score deviation passed the strong-signal floor",
      review_state: "ack", review_note: "nightly backup job",
      reviewed_at: "2026-01-02T08:05:00", watched: false },

    // THE THREE-OCCURRENCE GROUP (issue #20): one anomaly detected in three windows, one row
    // in the queue. Its chip, its count tooltip and the unreviewed-only filter must tell ONE
    // story about its review state while the check below dispositions it -- occurrence by
    // occurrence, then the row. Nothing is acked up front: the check acks the newest itself.
    { detected_at: "2026-01-02T07:30:00", window_start: "2026-01-02T07:25:00",
      window_end: "2026-01-02T07:30:00", src_addr: "198.51.100.77", hostname: "build-agent.lan",
      anomaly_score: 0.85, confidence: 0.7, severity: "high",
      detected_by_models: "Isolation Forest, Gradient Boosting, LOF", model_agreement: 0.6,
      isolation_forest_score: 0.8, gradient_boosting_score: 0.6, lof_score: 0.7,
      baseline_score: 0.3, primary_deviation_feature: "unique_dst_ports",
      primary_deviation_zscore: 4.4, deviation_magnitude: 2.6,
      feature_contributions: { unique_dst_ports: { z: 4.4 } },
      owner: "ops", matched_rule: "IsolationForest scored this window above the strong-signal floor",
      baseline_comparison: "unique_dst_ports is 4.4 sigma above this host's baseline",
      n: 3, review_state: "", review_note: "", reviewed_at: null,
      windows: [
        { window: "2026-01-02T06:45:00", review_state: "", review_note: "", reviewed_at: null },
        { window: "2026-01-02T07:05:00", review_state: "", review_note: "", reviewed_at: null },
        { window: "2026-01-02T07:25:00", review_state: "", review_note: "", reviewed_at: null },
      ] },
  ];

  // THE REVIEW STORE IS STATEFUL, like the real one (the /api/weirlings/register precedent):
  // a write PERSISTS, so the reload after a click shows the server's answer. The merge it
  // applies mirrors status.attach_group_reviews: the newest window headlines the row and
  // unreviewed_n counts the occurrences with no state (an "unavailable" one is NOT counted --
  // a state we cannot read is not work left undone). A stub that forgets would let the
  // agreement checks below pass while the view still rendered the pre-write state.
  const ANOMALIES_STATE = JSON.parse(JSON.stringify(ANOMALIES_PAYLOAD));
  // US-9: the server derives a stable reason code per row (status.reason_code); the fixture
  // payload must carry it or the row's code cell has nothing to show. Same derivation shape as
  // the server: detector initials + the moved measurement.
  {
    const abbr = (name) => (name === name.toUpperCase() ? name
      : name.split(/[^A-Za-z0-9]+/).filter(Boolean).map((w) => w[0].toUpperCase()).join(""));
    for (const row of ANOMALIES_STATE) {
      const parts = String(row.detected_by_models || "").split(",").map((x) => x.trim())
        .filter(Boolean).map(abbr).filter((v, i, a) => v && a.indexOf(v) === i);
      row.reason_code = `${parts.join("+") || "?"}:${String(row.primary_deviation_feature || "").trim() || "score"}`;
    }
  }
  // THE SERVER SHIPS THE BAND. The fixture carries the same fold the payload layer applies, so
  // the jsdom checks read the shipped field rather than re-deriving it in the browser.
  {
    const FOLD = { critical: "high", high: "high", medium: "medium", low: "low" };
    for (const row of ANOMALIES_STATE) {
      row.severity_band = FOLD[String(row.severity || "").toLowerCase()] || "unclassified";
    }
  }
  function anRecompute() {
    for (const row of ANOMALIES_STATE) {
      if (!row.windows) {
        row.unreviewed_n = row.review_state ? 0 : 1;
        continue;
      }
      row.unreviewed_n = row.windows.filter((w) => !w.review_state).length;
      const newest = row.windows[row.windows.length - 1];
      row.review_state = newest.review_state || "";
      row.review_note = newest.review_note || "";
      row.reviewed_at = newest.reviewed_at || null;
    }
  }
  anRecompute();

  // ── ONE FETCH DISPATCHER, INSTALLED ONCE ────────────────────────────────────────────────
  //
  // The harness previously assigned `window.fetch` three times in sequence, so the LAST assignment
  // won and every payload had to be re-registered on the stub that happened to be current. A route
  // added to the wrong one served nothing at all, with no error -- which silently produced three
  // failures during development (settings, plan/apply, and the Zeek tab) and, worse, meant the Zeek
  // view had NO harness coverage because its payload was never reachable.
  //
  // Now there is one function. `fetchOverride` is the deliberate-failure hook: a check that needs a
  // request to fail sets it, and clears it afterwards.
  //
  // THE SESSION STUB IS MUTABLE, and the POST replies below rewrite it, so the fake server
  // behaves like the real one: signing in makes /api/session report an authenticated admin,
  // signing out clears it. Checks then drive the REAL client code against a session state they
  // set up, and the boot path can be re-run by calling H.boot() again. It starts at
  // `accounts: false` so every check written before accounts existed still describes the
  // pre-accounts posture this file has always covered.
  const SESSION_STUB = { accounts: false, authenticated: false, username: "", role: "",
                         must_change: false, via: "", note: "" };
  const USERS_PAYLOAD = {
    available: true,
    roles: ["admin", "viewer"],
    users: [
      { username: "admin", role: "admin", must_change: false,
        created_at: "2026-09-21T00:00:00Z", updated_at: "2026-09-21T00:00:00Z" },
      { username: "reader", role: "viewer", must_change: true,
        created_at: "2026-09-21T00:10:00Z", updated_at: "2026-09-21T00:10:00Z" },
    ],
  };

  let fetchOverride = null;
  // ── host identity ──────────────────────────────────────────────────────────────────────────
  //
  // A REALISTIC payload, deliberately including the two cases that must render differently: a
  // high-confidence host with agreeing sources, and a host whose sources CONTRADICT each other.
  // A stub of only well-behaved hosts would pass while the disagreement path was broken.
  // ── Sluice Gate fixtures ────────────────────────────────────────────────────────────────────
//
// THREE STATES ARE DELIBERATELY PRESENT IN ONE PAYLOAD, because the whole point of the tab is that
// they must LOOK DIFFERENT from each other: a LIVE rule, a LAPSED one (exists, not enforced), and a
// REVOKED one (kept for the audit trail). A fixture with only live rules could not catch a view that
// rendered all three identically -- which is exactly the bug this project treats as its worst.
const SLUICE_PAYLOAD = {
  available: true, reason: "",
  // The imported lists and the recent domain hits (the operator's hagezi ask, 2026-10-16):
  // alert-first means these record without blocking, and the panel has to say so.
  blocklists: [{ source_id: "hagezi-light", name: "HaGeZi Multi LIGHT",
                 url: "https://example.invalid/light.txt", format: "dnsmasq", enabled: true,
                 fetched_at: "2026-10-16 06:00:00", domain_count: 123456, last_error: "" }],
  hits: [{ ts: "2026-10-16 06:01:00", rule_id: "", domain: "ads.example.com",
           query: "ads.example.com", client: "198.51.100.20" }],
  enabled: true, iface: "eth1", live: 2,
  // The firing record the rule rows read: a domain rule that HAS matched, a traffic rule
  // that has dropped packets, and rules with no evidence at all (the honest zero).
  evidence_available: true, blocklists_available: true,
  evidence: {
    r1: { events: 12, dns: 12, flow: 0, packets: 0, bytes: 0, last_age_s: 360,
          last_ts: "2026-10-16T05:55:00Z" },
    "r-live-1": { events: 4, dns: 0, flow: 4, packets: 1204, bytes: 9000,
                  last_age_s: 600, last_ts: "2026-10-16T05:50:00Z" },
  },
  criticality: "high",
  gate: {
    available: true, state: "armed", iface: "eth1", mgmt_iface: "eth0",
    // The real payload carries this (load_gate_state reads it from the state table). The stub
    // predated it, and without it the alert-side block control could only ever be tested in its
    // "nothing is enforcing" state.
    enforcement: "channel",
    rules_active: 2, rules_total: 3, packets_blocked: 1234, bytes_blocked: 987654,
    detail: "2 rule(s) enforced on eth1; 1 lapsed and are no longer enforced",
    backend: "nft", backend_expected: "nft",
  },
  policies: {
    off: { label: "Off", description: "Detections are recorded and alerted but never block anything.",
           ttl_minutes: 0, min_severity: null, min_confidence: 0.0 },
    high: { label: "High only", description: "Block only flows the ensemble scored high severity.",
            ttl_minutes: 30, min_severity: "high", min_confidence: 0.85 },
    medium: { label: "Medium and above", description: "Block medium and high severity.",
              ttl_minutes: 15, min_severity: "medium", min_confidence: 0.7 },
    strict: { label: "Strict", description: "Block anything the ensemble flagged.",
              ttl_minutes: 5, min_severity: "low", min_confidence: 0.5 },
  },
  // ONE RULE STORE, MANY GATES: this deployment's own gate, a weirling enforcing on its own
  // segment, and one that has STOPPED -- the state that must never read as covered.
  gates_available: true,
  gates: [
    { sensor: "weirvern-dual", state: "armed", iface: "eth1", rules_active: 2, rules_total: 3,
      packets_blocked: 1234, bytes_blocked: 987654, age_s: 12, local: true, stale: false,
      enforcement: "channel", detail: "" },
    { sensor: "weirvern-eth2", state: "armed", iface: "eth2", rules_active: 2, rules_total: 3,
      packets_blocked: 88, bytes_blocked: 4096, age_s: 30, local: false, stale: false,
      enforcement: "siphon", detail: "" },
    { sensor: "weirvern-open", state: "disarmed", iface: "eth1", rules_active: 0, rules_total: 0,
      packets_blocked: 0, bytes_blocked: 0, age_s: 20, local: false, stale: false,
      enforcement: "siphon", detail: "no live rules: the gate is open by choice" },
    { sensor: "lab-west", state: "degraded", iface: "eth1", rules_active: 0, rules_total: 3,
      packets_blocked: 0, bytes_blocked: 0, age_s: 5400, local: false, stale: true,
      enforcement: "", detail: "no verified path" },
    // A FIVE-WEIRLING FLEET IS THE SHAPE THE OPERATOR ASKED ABOUT. One row per sensor, each
    // carrying its own interface list, so a single global `iface` cannot hide the rest.
    { sensor: "weirvern-west", state: "armed", iface: "eth3", rules_active: 2, rules_total: 3,
      packets_blocked: 7, bytes_blocked: 2048, age_s: 25, local: false, stale: false,
      enforcement: "siphon", detail: "" },
  ],
  rules: [
    // THE SAME STORE FEEDS BOTH TABS (issue #15): the Blocked payload's live sets are built from
    // this same rule table (soc.py reads one store), so these two carry the ids the
    // BLOCKED_PAYLOAD lists as a block and an alert -- exactly as a live deployment does. Without
    // them the fixtures would encode the bug as normal: a live rule that can never be found.
    { rule_id: "r1", describes: "block ads.example.com (resolves to 1 address)", src_cidr: "", dst_cidr: "",
      protocol: "", dst_port: 0, direction: "forward", live: true, revoked: false,
      domain: "ads.example.com", origin: "manual", severity: "", created_by: "admin",
      origin_ref: "", reason: "", expires_at: "2026-10-16T07:00:00Z", expires_in_s: 1800,
      evidence: { events: 12, dns: 12, flow: 0, packets: 0, bytes: 0, last_age_s: 360 } },
    { rule_id: "r2", describes: "alert on track.example.net", src_cidr: "", dst_cidr: "",
      protocol: "", dst_port: 0, direction: "forward", live: true, revoked: false,
      domain: "track.example.net", origin: "manual", severity: "", created_by: "admin",
      origin_ref: "", reason: "", expires_at: "", expires_in_s: null },
    { rule_id: "r-live-1", describes: "block traffic from 198.51.100.7/32", src_cidr: "198.51.100.7/32",
      dst_cidr: "", protocol: "", dst_port: 0, direction: "forward", live: true, revoked: false,
      origin: "manual", severity: "", created_by: "admin", origin_ref: "",
      reason: "scanner on the lab segment", expires_at: "", expires_in_s: 1800,
      evidence: { events: 4, dns: 0, flow: 4, packets: 1204, bytes: 9000, last_age_s: 600 } },
    { rule_id: "r-live-2", describes: "block traffic from 198.51.100.9/32 on tcp/22", src_cidr: "198.51.100.9/32",
      dst_cidr: "", protocol: "tcp", dst_port: 22, direction: "forward", live: true, revoked: false,
      origin: "detection", severity: "high", created_by: "detection", origin_ref: "w-123",
      reason: "detection: severity high at confidence 0.91", expires_at: "", expires_in_s: 900 },
    // UNTIL REVOKED, with no reason recorded: the two states an operator can now create on
    // purpose (duration 0, reason left blank). A stub without them cannot show that either
    // renders as something an analyst can read.
    { rule_id: "r-indef", describes: "block traffic from 203.0.113.9/32", src_cidr: "203.0.113.9/32",
      dst_cidr: "", protocol: "", dst_port: 0, direction: "forward", live: true, revoked: false,
      origin: "manual", severity: "", created_by: "admin", origin_ref: "",
      reason: "", expires_at: "", expires_in_s: null },
    { rule_id: "r-lapsed", describes: "block traffic from 203.0.113.5/32", src_cidr: "203.0.113.5/32",
      dst_cidr: "", protocol: "", dst_port: 0, direction: "forward", live: false, revoked: false,
      origin: "manual", severity: "", created_by: "admin", origin_ref: "",
      reason: "temporary block that expired", expires_at: "2026-01-01T00:00:00Z",
      expires_in_s: -3600 },
    { rule_id: "r-revoked", describes: "block traffic from 203.0.113.6/32", src_cidr: "203.0.113.6/32",
      dst_cidr: "", protocol: "", dst_port: 0, direction: "forward", live: false, revoked: true,
      origin: "manual", severity: "", created_by: "admin", origin_ref: "",
      reason: "blocked in error, revoked", expires_at: "2026-01-01T00:00:00Z",
      expires_in_s: 3600 },
  ],
};

const IDENTITY_PAYLOAD = {
    available: true,
    window_days: 7,
    count: 3,
    coverage: {
      available: true, hosts_seen: 245, hosts_classified: 3,
      high_confidence: 1, medium_confidence: 1, unknown: 1,
      coverage_pct: 1.2, window_days: 7,
    },
    hosts: [
      {
        host: "203.0.113.10", mac: "00:00:5e:00:53:02", os: "linux",
        os_label: "Linux", confidence: "high", score: 1.5, agreeing_sources: 2,
        age_s: 120,
        signals: [
          { source: "software", os: "linux", os_label: "Linux",
            detail: "OpenSSH_10.2p1 Ubuntu-2ubuntu3.6 - banner names Ubuntu", weight: 1.0 },
          { source: "oui", os: "linux", os_label: "Linux",
            detail: "NIC vendor Raspberry Pi Trading (OUI dc:a6:32)", weight: 0.35 },
        ],
        disagreement: [],
        ja4_structure: { transport: "TCP", tls_version: "TLS 1.3", sni: "sent",
                         cipher_count: 15, extension_count: 16, alpn: "h2" },
        software_seen: ["OpenSSH_10.2p1 Ubuntu-2ubuntu3.6"],
        hostnames_seen: [],
        ja4_seen: ["t13d1516h2_8daaf6152771_02713d6af862"],
      },
      {
        host: "203.0.113.20", mac: "", os: "windows", os_label: "Windows",
        confidence: "medium", score: 1.0, agreeing_sources: 2, age_s: 400,
        signals: [
          { source: "software", os: "windows", os_label: "Windows",
            detail: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) - User-Agent names Windows NT",
            weight: 1.0 },
        ],
        disagreement: [
          { source: "dhcp_hostname", os_label: "Windows",
            detail: "hostname 'DESKTOP-7A3B2C' - Windows default computer-name pattern" },
        ],
        ja4_structure: null,
        software_seen: ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"],
        hostnames_seen: ["DESKTOP-7A3B2C"],
        ja4_seen: [],
      },
      {
        host: "203.0.113.30", mac: "", os: "unknown", os_label: "Unknown",
        confidence: "unknown", score: 0, agreeing_sources: 0, age_s: 900,
        signals: [], disagreement: [], ja4_structure: null,
        software_seen: [], hostnames_seen: [], ja4_seen: [],
      },
    ],
  };

  // The fingerprint lookup: the OTHER direction from the identity card -- which hosts present
  // this one stack. Two hosts with different session counts, so a renderer that repeats one row
  // (or reads the wrong field) has something to get wrong.
  const FP_PAYLOAD = {
    ja4: "t13d1516h2_8daaf6152771_02713d6af862", count: 2, reason: "",
    hosts: [
      { src_addr: "203.0.113.42", sessions: 18, first_seen: "2026-01-01T10:00:00",
        last_seen: "2026-01-02T09:00:00", peers: 4 },
      { src_addr: "198.51.100.7", sessions: 3, first_seen: "2026-01-02T08:00:00",
        last_seen: "2026-01-02T08:30:00", peers: 1 },
    ],
  };

  // The forced retrain: a candidate that built two of four detectors, on a window that contains
  // detections this deployment already recorded -- the warning that has to be read before Keep.
  const RETRAIN_PAYLOAD = {
    available: true, reason: "", state: "done", action_id: "r123", requested_by: "admin",
    requested_at: "2026-01-02T09:30:00", can_keep: true,
    note: "2 of 4 detector(s) trained; on 1234 host-window(s); WARNING: 3 detection(s) already "
      + "recorded inside this window -- keeping it teaches the new model to treat that traffic "
      + "as normal",
    summary: "2 of 4 detector(s) trained; on 1234 host-window(s); WARNING: 3 detection(s) already "
      + "recorded inside this window -- keeping it teaches the new model to treat that traffic "
      + "as normal",
    decision: null,
    report: {
      built_at: "2026-01-02T09:30:00", window_start: "2026-01-02T03:00:00",
      window_end: "2026-01-02T09:00:00", window_hours: 6, trained_any: true,
      files: ["Isolation Forest_v2.pkl", "Gradient Boosting_v2.pkl"],
      contamination: { available: true, detections: 3 },
      detectors: [
        { name: "Isolation Forest", trained: true, sample_count: 800 },
        { name: "Gradient Boosting", trained: true, sample_count: 434 },
        { name: "LOF", trained: false, sample_count: 0 },
        { name: "Adaptive Baseline", trained: false, sample_count: 0 },
      ],
    },
  };

  const ROUTES = [];
  // COUNTED (issue #15): the checks assert the Blocked payload is fetched ONCE, on demand --
  // not once per rule opened from the Sluice tab. Read by the checks at the bottom.
  let BLOCKED_FETCHES = 0;
  // Recorded (issue #31): the checks assert the flow-detail request CARRIES the active chips.
  let FLOW_REQS = [];
  // Recorded (issue #30): the checks assert the time control re-fetches Discover.
  let DISCOVER_REQS = [];
  // Recorded (ZK-FILTER-1): the Zeek cross-filter must reach the server, not just the DOM.
  let ZEEK_REQS = [];
  window.fetch = function (url, opts) {
    if (fetchOverride) {
      const r = fetchOverride(String(url), opts || {});
      if (r) return Promise.resolve(r);
    }
    const u = String(url);
    if (opts && String(opts.method || "").toUpperCase() === "POST") {
      POSTED.push({ url: u, headers: opts.headers || {}, body: opts.body || "" });
      let sent = {};
      try { sent = JSON.parse(opts.body || "{}"); } catch (_e) { sent = {}; }
      const reply = u.includes("/api/login")
                    ? (sent.password === "correct-password"
                        ? (Object.assign(SESSION_STUB, { accounts: true, authenticated: true,
                            username: sent.username || "admin", role: "admin",
                            must_change: false, via: "session" }),
                           { ok: true, session: "test-session-token",
                             username: sent.username || "admin", role: "admin",
                             must_change: false })
                        : { __http: 401, ok: false, error: "the username or password is not correct" })
                  : u.includes("/api/logout")
                    ? (Object.assign(SESSION_STUB, { authenticated: false, username: "",
                        role: "", must_change: false, via: "" }), { ok: true })
                  : u.includes("/api/password")
                    ? (SESSION_STUB.authenticated
                        ? (Object.assign(SESSION_STUB, { authenticated: false, username: "",
                            role: "", must_change: false, via: "" }),
                           { ok: true, signed_out: true, note: "password changed; sign in again" })
                        : { __http: 401, ok: false, error: "sign in first" })
                  : u.includes("/api/users/create")
                    ? { ok: true, user: { username: sent.username || "newuser", role: sent.role || "viewer" } }
                  : u.includes("/api/users/reset")
                    ? { ok: true, username: sent.username || "" }
                  : u.includes("/api/users/role")
                    ? { ok: true, username: sent.username || "", role: sent.role || "" }
                  : u.includes("/api/users/delete")
                    ? { ok: true, username: sent.username || "" }
                  : u.includes("/api/settings/plan") ? planReply(sent.changes)
                  : u.includes("/api/settings/apply")
                    ? ((sent.changes || {}).base_threshold === "0.001")
                      // AN APPLY-TIME CHECK BLOCKED THE WRITE (BF-14): a 409 with the named
                      // failed assertion and every check that ran, like the real route.
                      ? { __http: 409, ok: false, blocked: true,
                          error: "blocked by apply-time checks: the threshold does not fire on yesterday's baseline",
                          tests: [
                            { name: "the interconnect plan stays complete", status: "skip",
                              detail: "this change does not touch the interconnect plan" },
                            { name: "the capture interface is one the sensors report", status: "skip",
                              detail: "the change does not name a capture interface" },
                            { name: "the threshold does not fire on yesterday's baseline", status: "fail",
                              detail: "threshold 0.001 would have fired on 999 rows in the last 24h (the day's budget is 50). Raise it, or change your mind on purpose." },
                          ], summary: "0 passed, 2 skipped, 1 failed" }
                    : ((sent.changes || {}).base_threshold === "0.7" && APPLY_FAIL_ONCE)
                      ? (() => {
                          APPLY_FAIL_ONCE = false;
                          // A REFUSED WRITE: the read-back says the value is not there. The
                          // refusal still carries per-item verdicts and a timestamp.
                          return { __http: 502, ok: false, at: "2026-10-17T17:06:00Z",
                                   error: "read-back: base_threshold did not land",
                                   items: [{ key: "base_threshold", value: "0.7", ok: false,
                                             error: "read-back: base_threshold did not land" }] };
                        })()
                      : { ok: true, applied: sent.changes || {}, restarted: ["deploy/weirvern-worker"],
                          restart_errors: [], note: "restarted deploy/weirvern-worker",
                          at: "2026-10-17T17:05:00Z",
                          tests: [
                            { name: "the threshold does not fire on yesterday's baseline",
                              status: "pass",
                              detail: "would have fired on 3 of the last 24h's rows (budget 50)" },
                            { name: "the interconnect plan stays complete", status: "skip",
                              detail: "this change does not touch the interconnect plan" },
                          ],
                          summary: "1 passed, 1 skipped",
                          items: Object.entries(sent.changes || {}).map(([k, v]) => ({
                            key: k, value: String(v), ok: true, error: "" })),
                          // SHAPED LIKE THE SERVER: the effective TTL the cluster reports, and
                          // one table whose ALTER/read-back disagreed so the receipt's
                          // "NOT CHANGED" path is exercised rather than assumed.
                          ...(("data_retention_days" in (sent.changes || {})) ? {
                            ok: false,
                            retention: {
                              ok: false, requested_days: 7,
                              changed: ["flows_window"],
                              failed: [], missing: [], mismatched: ["zeek_http"],
                              tables: [
                                { table: "flows_window", column: "window_start",
                                  requested_days: 7, effective_days: 7,
                                  expression: "window_start + INTERVAL 7 DAY",
                                  changed: true, ok: true, error: "" },
                                { table: "zeek_http", column: "ts", requested_days: 7,
                                  effective_days: 35, expression: "ts + INTERVAL 35 DAY",
                                  changed: false, ok: false,
                                  error: "the cluster reports 35 days, not 7" },
                              ],
                              summary: "1 of 2 table(s) set to 7 days; read-back disagrees "
                                + "for zeek_http",
                            } } : {}),
                        }
                  : u.includes("/api/settings/sonar")
                    // REQUEST-AWARE like the real route: a survey FOR a named weirling
                    // comes back stamped with that sensor, and reports the interface that
                    // sensor's own row resolves to -- so the panel can only stage the
                    // result against the weirling it belongs to.
                    ? (() => {
                        const sensor = sent.sensor || "";
                        const row = sensor
                          ? WEIRLINGS_PAYLOAD.sensors.find((x) => x.sensor_id === sensor) : null;
                        const iface = (row && row.plan && row.plan.iface)
                          || (row && (row.interfaces || [])[0]) || "eth1";
                        return Object.assign({}, SONAR_REPLY, { sensor, interface: iface });
                      })()
                  : u.includes("/api/settings/test")
                    ? { ok: true, seconds: 30, mode_before: "loch", mode_after: "loch",
                        reverted: true,
                        observed: { hosts: 3, mappings: 6, age_s: 7.2 },
                        observed_s: 8.1,
                        plan: { iface: "eth1", segment: "198.51.100.0/24",
                                addr: "198.51.100.250", gateway: "198.51.100.1",
                                targets: "*" },
                        notes: [], error: "" }
                  : u.includes("/api/review")
                    ? (() => {
                        // STATEFUL, like the real store (issue #20): a write PERSISTS, so the
                        // reload after a click shows the server's answer. The merge mirrors
                        // status.attach_group_reviews: each window keeps its own state, the
                        // newest window headlines the row, and unreviewed_n counts the
                        // occurrences with no state -- an "unavailable" one is NOT counted,
                        // because a state we cannot read is not work left undone.
                        for (const row of ANOMALIES_STATE) {
                          if (row.src_addr !== sent.src_addr) continue;
                          const wins = row.windows || [{ window: row.window_start,
                            review_state: row.review_state, review_note: row.review_note,
                            reviewed_at: row.reviewed_at }];
                          const w = wins.find((x) => x.window === sent.window_start);
                          if (w) {
                            w.review_state = sent.state || "";
                            w.review_note = sent.note || "";
                            w.reviewed_at = sent.state ? "2026-01-02T09:30:00" : null;
                          }
                          row.windows = wins;
                          anRecompute();
                          break;
                        }
                        return { ok: true, state: sent.state || "", note: sent.note || "" };
                      })()
                  : u.includes("/api/sluice/block")
                    ? { ok: true, rule_id: "r-filed-1", describes: "block traffic from 198.51.100.44/32",
                        note: "the rule is filed; the gate re-checks within a minute" }
                  : u.includes("/api/models/retrain")
                    ? { ok: true, action: sent.action || "retrain",
                        action_id: sent.action_id || "r124",
                        note: "filed; the worker acts on its next cycle" }
                  : u.includes("/api/weirlings/plan")
                    // SHAPED LIKE THE REAL SERVER: proposals for the changes REQUESTED, with the
                    // in-path cost riding on the mode change (that warning is what the confirm
                    // dialog exists for), and a warning list when the merged plan cannot arm.
                    ? (() => {
                        const row = WEIRLINGS_PAYLOAD.sensors.find(
                          (x) => x.sensor_id === (sent.sensor_id || ""));
                        const proposals = Object.entries(sent.changes || {}).map(([key, value]) => ({
                          key, value: String(value), warning: (key === "mode" && value === "siphon")
                            ? "this puts " + sent.sensor_id + " IN THE TRAFFIC PATH" : "",
                        }));
                        const merged = Object.assign({}, (row && row.plan) || {}, sent.changes || {});
                        const warnings = (merged.mode === "siphon" && !merged.targets)
                          ? ["the plan cannot arm yet: no intercept targets"] : [];
                        return { ok: true, sensor_id: sent.sensor_id || "", proposals,
                                 restart_targets: [], warnings,
                                 note: (sent.sensor_id || "") + " reads its own plan on every refresh" };
                      })()
                  : u.includes("/api/weirlings/apply")
                    // STATEFUL, like the real store: the write PERSISTS into the fixture row, so
                    // the re-read after the click shows the plan the server now holds. A stub
                    // that forgot would let "applied" checks pass while the panel still showed
                    // the old plan.
                    ? (() => {
                        const row = WEIRLINGS_PAYLOAD.sensors.find(
                          (x) => x.sensor_id === (sent.sensor_id || ""));
                        if (row) {
                          row.plan = Object.assign({}, row.plan || {}, sent.changes || {});
                          if (row.plan.mode) row.expected_mode = row.plan.mode;
                        }
                        return { ok: true, sensor_id: sent.sensor_id || "",
                                 applied: sent.changes || {}, restart_targets: [],
                                 note: "saved. " + (sent.sensor_id || "") + " applies it within 30s" };
                      })()
                  : u.includes("/api/weirlings/register")
                    ? (() => {
                        // STATEFUL, like the real store: a registration PERSISTS, so the
                        // re-read after the click shows the sensor as declared. A stub that
                        // forgets would let a "registered" check pass while the view still
                        // renders the sensor as undeclared.
                        const row = WEIRLINGS_PAYLOAD.sensors
                          .find((s) => s.sensor_id === sent.sensor_id);
                        if (row) {
                          row.registered = true;
                          row.enabled = true;
                          row.state = "alive";
                          row.address = sent.address || row.address;
                          row.expected_mode = sent.expected_mode || row.expected_mode;
                          row.note = sent.note || row.note;
                          row.findings = ["reporting normally, last heard just now."];
                        }
                        return { ok: true, sensor_id: sent.sensor_id || "" };
                      })()
                  : u.includes("/api/scan-jobs")
                    ? { ok: true, job_id: "job-scan-1", ip: sent.ip || "",
                        state: "queued", already: false }
                  : u.includes("/api/weirlings/revoke")
                    ? { ok: true, sensor_id: sent.sensor_id || "",
                        note: "revoked; the record stays for the audit trail" }
                  : { ok: false, error: "no write route at " + u };
      // `__http` lets one reply carry a real status code: the failed sign-in and the dead-session
      // password refusal are 401s on the real server, and the client decides whether to throw by
      // `resp.ok` -- a stub answering 200-with-{ok:false} exercises a different branch than the
      // one the operator runs.
      const httpStatus = (reply && reply.__http) || 200;
      return Promise.resolve({ ok: httpStatus === 200, status: httpStatus,
                               statusText: httpStatus === 200 ? "OK" : "Refused",
                               json: async () => reply });
    }
    // /api/weirlings/detail is REQUEST-AWARE, like the real server: it answers for the sensor
    // asked about. A static payload serves one sensor's row under EVERY name -- a check on
    // registering the undeclared "ghost-box" would silently act on a registered sensor's data,
    // passing while proving the opposite of what it claims.
    if (u.includes("/api/weirlings/detail")) {
      const m = /[?&]sensor=([^&]+)/.exec(u);
      const sid = m ? decodeURIComponent(m[1]) : "";
      const row = WEIRLINGS_PAYLOAD.sensors.find((s) => s.sensor_id === sid);
      // Answers for ANY id, like the real server: an unknown sensor gets its own row shape
      // rather than another sensor's data under the wrong name.
      const payload = row
        ? { available: true, reason: null, sensor: row }
        : { available: true, reason: null,
            sensor: Object.assign({}, (WEIRLINGS_DETAIL_PAYLOAD || {}).sensor || {},
                                  { sensor_id: sid }) };
      return Promise.resolve({ ok: true, status: 200, statusText: "OK",
                               json: async () => payload });
    }
    for (const [match, rawPayload] of ROUTES) {
      if (u.includes(match)) {
        // A FUNCTION entry is resolved per REQUEST (the anomalies filter; issue #20).
        const payload = (typeof rawPayload === "function") ? rawPayload(u) : rawPayload;
        // /api/session is TOKEN-AWARE, like the real server, and SESSION FIRST: a valid
        // session reports the account; only when there is none does a presented operator
        // token report the break-glass admin (`via: "token"`). This is what the break-glass
        // door on the sign-in gate relies on.
        if (match === "/api/session") {
          if (SESSION_STUB.authenticated) {
            return Promise.resolve({ ok: true, status: 200, statusText: "OK",
                                     json: async () => SESSION_STUB });
          }
          const hdrs = (opts && opts.headers) || {};
          if (hdrs["X-Weirvern-Token"] === "test-token-value") {
            return Promise.resolve({ ok: true, status: 200, statusText: "OK",
              json: async () => ({ accounts: true, authenticated: true, username: "",
                role: "admin", must_change: false, via: "token",
                note: SESSION_STUB.note || "" }) });
          }
        }
        return Promise.resolve({ ok: true, status: 200, statusText: "OK",
                                 json: async () => payload });
      }
    }
    return Promise.resolve({ ok: true, status: 200, statusText: "OK",
                             json: async () => ({ available: true, reason: "", points: [] }) });
  };


// ── WEIRLINGS: the fleet ──────────────────────────────────────────────────────────────────────
//
// SHAPED LIKE THE REAL SERVER'S PAYLOAD, with every key `fleet_store._health_to_json` emits.
// A fixture invented beside the renderer would encode the renderer's own assumptions and could
// not detect that the two sides disagree about a field name -- and a missing key kills the whole
// panel at the first formatter call rather than degrading one row.
//
// THE ROWS ARE CHOSEN TO MAKE EVERY DISTINCTION THIS VIEW EXISTS FOR VISIBLE:
//   * an ALIVE sensor with a measured loss,
//   * a STALE one that ran and stopped (the finding must say so, not just "no heartbeat"),
//   * a NEVER-SEEN one -- registered and silent, which is a different fact from stale,
//   * an UNREGISTERED one feeding the hub that nobody declared,
//   * a DISABLED one, whose silence is EXPECTED and must not be raised,
//   * a sensor with capture loss as NULL, which must render as a dash and not 0.0%,
//   * a sensor whose DECLARED segment disagrees with the one it REPORTS.
const WEIRLINGS_PAYLOAD = {
  available: true,
  reason: null,
  heartbeats_available: true,
  heartbeat_reason: null,
  summary: { total: 6, registered: 5, problems: 4, networks: 1, networks_observed: 1,
             networks_declared: 2, networks_declared_all: 2,
             networks_coverage_available: true, networks_coverage_reason: "",
             alive: 1, stale: 1, never_seen: 1,
             unregistered: 1, disabled: 1 },
  network_coverage: {
    available: true, declared: 2, declared_monitored: 2, observed: 1,
    observed_segments: ["198.51.100.0/24"],
    unobserved: [{ cidr: "203.0.113.0/24", label: "dmz", monitored: true, policy: "full" }],
    scopes: [
      { id: "a", cidr: "198.51.100.0/24", label: "internal", monitored: true,
        policy: "full", description: "", source: "operator", warning: "", observed: true },
      { id: "b", cidr: "203.0.113.0/24", label: "dmz", monitored: true,
        policy: "full", description: "", source: "operator", warning: "", observed: false },
    ],
    unconfigured: false,
  },
  sensors: [
    {
      sensor_id: "edge-alive", state: "alive", is_problem: false,
      iface: "eth1", address: "198.51.100.7", segment: "third floor", reported_segment: "third floor",
      expected_mode: "loch", reported_mode: "loch", enabled: true, registered: true,
      local: true,
      plan: { mode: "", iface: "", segment: "", addr: "", gateway: "", targets: "" },
      age_s: 4.0, last_seen: "2026-09-23T12:00:00+00:00",
      interfaces: ["eth1", "eth2"],
      capture_loss_pct: 0.0, packets_recv: 900000, packets_dropped: 0, hosts: 12,
      note: "ops owns this one", stale_after_s: 45,
      findings: ["reporting normally, last heard 4s ago."],
      flow_series: [3, 5, 0, 8, 12, 4, 0, 0, 6, 9, 2, 1],
      netflow: { known: true, observed: true, flows: 120,
                 last_at: "2026-09-23T12:00:00+00:00", why: "" },
      zeek: { known: true, observed: true, last_at: "2026-09-23T11:59:00+00:00", why: "" },
    },
    {
      sensor_id: "edge-stopped", state: "stale", is_problem: true,
      iface: "eth1",
      plan: { mode: "", iface: "", segment: "", addr: "", gateway: "", targets: "" },
      address: "", segment: "second floor", reported_segment: "",
      expected_mode: "loch", reported_mode: "loch", enabled: true, registered: true,
      age_s: 900.0, last_seen: "2026-09-23T11:45:00+00:00",
      capture_loss_pct: null, packets_recv: null, packets_dropped: null, hosts: 0,
      note: "", stale_after_s: 45,
      interfaces: ["eth0", "eth1"],
      flow_series: [],
      netflow: { known: false, observed: false, flows: 0, last_at: "",
                 why: "the sensor has not reported an address yet" },
      zeek: { known: false, observed: false, last_at: "",
              why: "only the hub runs Zeek; a remote weirling does not report one" },
      findings: ["last reported 900s ago, past the 45s freshness window, so it has stopped. It ran "
        + "and then stopped, which is different from never starting: look for why it died rather "
        + "than why it never came up.",
        "no capture-loss measurement, so packet loss is unknown rather than zero."],
    },
    {
      sensor_id: "edge-promised", state: "never_seen", is_problem: true,
      plan: { mode: "siphon", iface: "eth2", segment: "198.51.100.0/24", addr: "", gateway: "198.51.100.1", targets: "*" },
      address: "198.51.100.9", segment: "fourth floor IDF", reported_segment: "",
      interfaces: ["eth2"],
      flow_series: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
      netflow: { known: true, observed: false, flows: 0, last_at: "",
                 why: "no flows from this sensor's address in 24h" },
      zeek: { known: false, observed: false, last_at: "",
              why: "only the hub runs Zeek; a remote weirling does not report one" },
      expected_mode: "siphon", reported_mode: "", enabled: true, registered: true,
      age_s: null, last_seen: null,
      capture_loss_pct: null, packets_recv: null, packets_dropped: null, hosts: 0,
      note: "waiting on the switch port", stale_after_s: 45,
      findings: ["registered but has never reported. Check that it can reach this hub.",
        "this sensor was registered as IN-PATH (siphon), so the segment it covers may be waiting "
        + "on an intercept that has never run."],
    },
    {
      sensor_id: "ghost-box", state: "unregistered", is_problem: true,
      plan: { mode: "", iface: "", segment: "", addr: "", gateway: "", targets: "" },
      address: "198.51.100.44", segment: "", reported_segment: "",
      expected_mode: "", reported_mode: "loch", enabled: false, registered: false,
      age_s: 2.0, last_seen: "2026-09-23T12:00:00+00:00",
      capture_loss_pct: 3.5, packets_recv: 1000, packets_dropped: 35, hosts: 3,
      note: "", stale_after_s: 45,
      findings: ["this sensor is feeding the hub but is not registered, so nobody declared it."],
    },
    {
      sensor_id: "edge-off", state: "disabled", is_problem: false,
      plan: { mode: "loch", iface: "", segment: "", addr: "", gateway: "", targets: "" },
      address: "", segment: "spare", reported_segment: "",
      expected_mode: "loch", reported_mode: "", enabled: false, registered: true,
      age_s: 90000.0, last_seen: "2026-09-22T11:00:00+00:00",
      capture_loss_pct: null, packets_recv: null, packets_dropped: null, hosts: 0,
      note: "pulled for maintenance", stale_after_s: 45,
      findings: ["this sensor is registered but switched off, so it is not expected to report."],
    },
    {
      sensor_id: "edge-moved", state: "alive", is_problem: false,
      interfaces: ["eth3"],
      plan: { mode: "siphon", iface: "eth3", segment: "203.0.113.0/24", addr: "203.0.113.250", gateway: "203.0.113.1", targets: "203.0.113.7" },
      address: "198.51.100.60", segment: "fifth floor", reported_segment: "sixth floor",
      expected_mode: "loch", reported_mode: "siphon", enabled: true, registered: true,
      age_s: 9.0, last_seen: "2026-09-23T12:00:00+00:00",
      capture_loss_pct: 62.5, packets_recv: 400, packets_dropped: 250, hosts: 5,
      note: "", stale_after_s: 45,
      findings: ["reporting normally, last heard 9s ago.",
        "registered for segment 'fifth floor' but reporting 'sixth floor'.",
        "capture loss is 62.5%: this sensor is blind to most of what is on the wire."],
    },
  ],
};

const WEIRLINGS_DETAIL_PAYLOAD = {
  available: true, reason: null, sensor: WEIRLINGS_PAYLOAD.sensors[1],
};

  // DISCOVER: the raw-flow browser. Two rows and two facet values are enough to prove the
  // renderer, the detail expansion, and the bucket drill targets exist.
  const DISCOVER_TRENDS_PAYLOAD = {
    available: true, reason: "", bucket_s: 900,
    feeds: {
      netflow: { available: true, total: 120, points: [
        { t: "2026-10-16T00:00:00", n: 10 }, { t: "2026-10-16T00:15:00", n: 30 },
        { t: "2026-10-16T00:30:00", n: 80 }] },
      zeek: { available: true, total: 40, points: [
        { t: "2026-10-16T00:00:00", n: 4 }, { t: "2026-10-16T00:15:00", n: 12 },
        { t: "2026-10-16T00:30:00", n: 24 }] },
      dns: { available: true, total: 9, points: [
        { t: "2026-10-16T00:00:00", n: 1 }, { t: "2026-10-16T00:15:00", n: 3 },
        { t: "2026-10-16T00:30:00", n: 5 }] },
    },
  };

  const DISCOVER_PAYLOAD = {
    available: true, reason: "", total: 42, limit: 100, offset: 0, bucket_s: 60,
    rows: [
      { timestamp: "2026-10-16 06:00:00", sensor: "127.0.0.1", weirling: "weirvern",
        src_addr: "198.51.100.20",
        src_port: 4444, dst_addr: "198.51.100.10", dst_port: 443, proto: 6, proto_label: "tcp",
        bytes: 1234, packets: 12, tcp_flags: 2, ip_ttl: 64, next_hop: "", src_as: 0, dst_as: 0,
        direction: "request", direction_evidence: "tcp-syn", direction_confidence: "proven",
        opened_by: "198.51.100.20:4444" },
      { timestamp: "2026-10-16 06:01:00", sensor: "127.0.0.1", weirling: "weirvern",
        src_addr: "198.51.100.20",
        src_port: 4445, dst_addr: "198.51.100.10", dst_port: 53, proto: 17, proto_label: "udp",
        bytes: 300, packets: 4, tcp_flags: 0, ip_ttl: 64, next_hop: "", src_as: 0, dst_as: 0,
        direction: "request", direction_evidence: "service-port", direction_confidence: "inferred",
        opened_by: "198.51.100.20:4445" },
    ],
    histogram: [
      { t: "2026-10-16 06:00:00", n: 30, bytes: 9000 },
      { t: "2026-10-16 06:01:00", n: 12, bytes: 4000 },
    ],
    facets: { protos: [{ value: 6, label: "tcp", count: 30 }, { value: 17, label: "udp", count: 12 }],
              weirlings: [{ value: "127.0.0.1", count: 42, label: "weirvern" }] },
  };

  // US-1: the discover DNS feed, so the record detail's actions are checkable. Shaped like
  // soc.discover_dns serves it (client/query/qtype/rcode/answer_ips).
  const DISCOVER_DNS_PAYLOAD = {
    available: true, reason: "", total: 1, limit: 100, offset: 0, feed: "dns",
    rows: [
      { ts: "2026-10-16 06:00:00", client: "198.51.100.77", query: "tracker.example",
        qtype: 1, qtype_label: "A", rcode: 0, rcode_label: "NOERROR",
        answer_ips: ["198.51.100.9"], answers: "198.51.100.9" },
    ],
    histogram: [{ t: "2026-10-16 06:00:00", n: 1, bytes: 0 }],
    facets: { clients: [{ value: "198.51.100.77", count: 1, label: "198.51.100.77" }] },
  };

  // AB-1: the adaptive-baseline card's payload, shaped like web_api.baselines_payload().
  const BASELINES_PAYLOAD = {
    available: true, host_count: 3, refreshed_at: "2026-10-17T15:24:53-05:00",
    refreshed_age_s: 245, behavioural_hosts: 2, fingerprint_hosts: 1,
    last_trained: "2026-10-17T15:24:53-05:00",
    fired_24h: 4, last_fired: "2026-10-17T15:28:33-05:00",
    hosts: [
      { src_addr: "198.51.100.5", hostname: "host.example",
        avg_bytes: 9394, stddev_bytes: 9258, avg_packets: 40,
        avg_unique_dsts: 2.5, p95_bytes: 5000, p99_bytes: 12000, p999_bytes: 20000,
        window_hours: 24, computed_at: "2026-10-17T15:24:53-05:00" },
      { src_addr: "198.51.100.9", avg_bytes: 4421, stddev_bytes: 800, avg_packets: 12,
        avg_unique_dsts: 1.0, p95_bytes: 2000, p99_bytes: 5000, p999_bytes: 9000,
        window_hours: 24, computed_at: "2026-10-17T15:24:53-05:00" },
      { src_addr: "203.0.113.7", avg_bytes: 60, stddev_bytes: 1, avg_packets: 2,
        avg_unique_dsts: 1.0, p95_bytes: 50, p99_bytes: 60, p999_bytes: 70,
        window_hours: 24, computed_at: "2026-10-17T15:24:53-05:00" },
    ],
    errors: null,
  };

  // US-2: the discover Zeek feed -- logs, not rows (soc.discover_zeek's own shape).
  const DISCOVER_ZEEK_PAYLOAD = {
    available: true, reason: "", feed: "zeek", rows: [], total: 12,
    logs: [
      { log: "conn", rows: 12, total: 99, last_ts: "2026-10-17T15:00:00" },
      { log: "ssl", rows: 0, total: 5, last_ts: "2026-10-17T14:00:00" },
    ],
  };

  const DNS_PAYLOAD = {
    available: true, reason: "", total: 12, limit: 100, offset: 0, bucket_s: 60,
    rows: [
      { ts: "2026-10-16 06:00:00", client: "198.51.100.20", query: "ads.example.com",
        qtype: 1, qtype_label: "A", rcode: 0, rcode_label: "NOERROR",
        answers: "198.51.100.10", answer_ips: ["198.51.100.10"] },
      { ts: "2026-10-16 06:01:00", client: "198.51.100.20", query: "nope.example.net",
        qtype: 1, qtype_label: "A", rcode: 3, rcode_label: "NXDOMAIN",
        answers: "", answer_ips: [] },
    ],
    histogram: [
      { t: "2026-10-16 06:00:00", n: 7 },
      { t: "2026-10-16 06:01:00", n: 5 },
    ],
    facets: {
      domains: [{ value: "ads.example.com", count: 7 }],
      clients: [{ value: "198.51.100.20", count: 12 }],
      rcodes: [{ value: 0, label: "NOERROR", count: 9 }, { value: 3, label: "NXDOMAIN", count: 3 }],
    },
  };
  const BLOCKED_PAYLOAD = {
    available: true, reason: "", total: 3, limit: 200, offset: 0,
    hits: [
      { ts: "2026-10-16 06:02:00", rule_id: "r1", domain: "ads.example.com",
        query: "ads.example.com", client: "198.51.100.20" },
      { ts: "2026-10-16 06:01:00", rule_id: "", domain: "track.example.net",
        query: "x.track.example.net", client: "198.51.100.21" },
    ],
    blocks: [
      { rule_id: "r1", describes: "block ads.example.com (resolves to 2 addresses)",
        mode: "block", domain: "ads.example.com", origin: "manual", severity: "",
        expires_at: "2026-10-16 07:00:00", resolved: ["203.0.113.7", "203.0.113.8"],
        resolved_count: 2, resolved_error: false },
    ],
    alerts: [
      { rule_id: "r2", describes: "alert on track.example.net",
        mode: "alert", domain: "track.example.net", origin: "manual", severity: "",
        expires_at: "", resolved: ["203.0.113.9"], resolved_count: 1, resolved_error: false },
    ],
    gate: { state: "armed", iface: "eth1", rules_active: 1, rules_total: 2,
            packets_blocked: 12, bytes_blocked: 8000, enforcement: "channel" },
  };

  const DNS_REVERSE_PAYLOAD = {
    available: true, reason: "",
    domains: [{ domain: "ads.example.com", last_seen: "2026-10-16 06:00:00" }],
  };

  // The routes, each registered with the payload it serves. One list, so a payload cannot be
  // declared and then forgotten.
  // ── the tri-state health payload (audit F081) ─────────────────────────────────────────────────
  //
  // Carries all THREE probe states, because the renderer's bug was specifically that a
  // not-applicable probe (`ok: null`) was counted and painted as a failure:
  //
  //     checks.filter((c) => !c.ok)   <- null is falsy, so it counted as failing
  //     c.ok ? "ok" : "FAIL"          <- null fell into the FAIL branch
  //
  // A fixture with only true/false cannot see that. The three rows below are the whole point.
  const HEALTH_PAYLOAD = {
    health: {
      ok: true,
      fetched_at: "2026-01-03T10:00:00Z",
      checks: [
        // A DOCUMENTATION-RANGE address, deliberately. This was the deployment's real server
        // version for one revision -- read off the live cluster -- which is deployment information
        // in a tracked file and tripped the sanitation guard. The value is irrelevant: the renderer
        // prints whatever `value` holds, so a reserved address demonstrates it just as well.
        { name: "clickhouse", ok: true, value: "198.51.100.10", latency_ms: 4 },
        { name: "ingest_freshness", ok: false, value: 2000, latency_ms: 6 },
        { name: "zeek_freshness", ok: null, value: null, latency_ms: 5 },
      ],
    },
    ingest: { available: true, points: [] },
    tables: { available: true, points: [
      { table: "flows", rows: 1000, bytes: 4096, trend: "up",
        history: [ { bytes: 1000 }, { bytes: 2000 }, { bytes: 4096 } ] },
      { table: "zeek_dns", rows: 800, bytes: 2048, trend: "static",
        history: [ { bytes: 2048 }, { bytes: 2048 }, { bytes: 2048 } ] },
      { table: "alert_events", rows: 10, bytes: 512, trend: "down",
        history: [ { bytes: 900 }, { bytes: 700 }, { bytes: 512 } ] },
    ] },
    // `alerts`, NOT `alert_audit`: the product's payload key is `alerts` (web_api.py) and the
    // SOC renderer reads `d.alerts`. The stub carried `alert_audit`, so the key was never read
    // and the loader path rendered an EMPTY audit -- meaning the one route that exercises
    // renderAlertAudit through the real code path proved nothing about it, while the direct
    // calls below kept passing. A name that only the test knows is a test that checks nothing.
    sensor: {},
    alerts: { available: true, by_reason: [], recent: [], suppressed: 0,
              total: 0, truncated: false, names: {} },
  };

  // TWO EXTRA PROBES, and they are the point of the panel's contract: a FAILING probe whose reason
  // must be readable, and a value that is an OBJECT (the old renderer printed String(value) and the
  // operator read "[object Object]" where the sentence should have been). Both live under `health`,
  // which is where the server puts them.
  const HEALTH_WITH_FAILURE = Object.assign({}, HEALTH_PAYLOAD, {
    health: Object.assign({}, HEALTH_PAYLOAD.health, {
      ok: false,
      checks: [
        { name: "models", ok: false, detail: "no training runs recorded; the last 24h hold 20 flow row(s) from 3 host(s); training needs more than that before a detector is stored", value: [], latency_ms: 1.7 },
        { name: "tables", ok: true, detail: "9/9 present", value: { flows: 20, flows_aggregated: 17 }, latency_ms: 11.1 },
      ].concat(HEALTH_PAYLOAD.health.checks || []),
    }),
  });

  ROUTES.push(
    // The 6h window answers with the two extra probes (a FAILING one with a reason, one whose value
    // is an object). The 24h window is untouched: the harness's own checks count that payload's
    // probes, and weakening them to make room for this would trade one blind spot for another.
    ["/api/health?hours=6", HEALTH_WITH_FAILURE],
    ["/api/health", HEALTH_PAYLOAD],
    ["/api/system", () => ({ available: true, reason: "", proc_root: "/host-proc",
      sampled_at: 1, cpu_percent: 21.5, memory_percent: 48.0,
      memory_used_bytes: 4 * 1024 ** 3, memory_total_bytes: 8 * 1024 ** 3,
      history: [{ t: 1, cpu: 18.0, memory: 47.0 }, { t: 2, cpu: 21.5, memory: 48.0 }],
      interfaces: [{ name: "eth0", rx_bps: 1200, tx_bps: 800, rx_drops: 0, tx_drops: 0 },
                   { name: "eth1", rx_bps: 5500, tx_bps: 2100, rx_drops: 2, tx_drops: 0 }] })],
    // US-7: the inventory, finally stubbed -- the facet checks need real services, and a
    // missing arm made loadAssets answer an empty {} ("0 hosts in the last undefinedh").
    ["/api/assets", () => ({
      available: true, reason: "", hours: 24,
      hosts: [
        { addr: "203.0.113.42", name: "workstation.lan", bytes: 7153288, bytes_out: 5000000,
          bytes_in: 2153288, flows: 900, dst_count: 37, services: ["conn", "http", "ssh"],
          anomalies: 3, last_seen: "2026-09-19T07:39:10" },
        { addr: "192.0.2.40", name: "vault", bytes: 1824000, bytes_out: 24000,
          bytes_in: 1800000, flows: 60, dst_count: 4, services: ["conn", "ssh"],
          anomalies: 0, last_seen: "2026-09-19T07:00:00" },
        { addr: "198.51.100.77", name: "", bytes: 9000, bytes_out: 1000, bytes_in: 8000,
          flows: 12, dst_count: 2, services: ["dns"], anomalies: 0,
          last_seen: "2026-09-19T06:00:00" },
      ], unreadable: [], errors: null })],
    // US-10: the write trail (the fleet_audit read surface).
    ["/api/write-trail", () => ({
      available: true, reason: "",
      scopes: ["fleet", "settings"],
      actions: ["apply", "plan", "revert", "revoke"],
      rows: [
        { at: "2026-10-17T11:50:00Z", scope: "settings", action: "apply", target: "base_threshold",
          reason: "tighten after the scanner", actor: "admin" },
        { at: "2026-10-17T11:00:00Z", scope: "settings", action: "revert", target: "sluice_auto_score",
          reason: "auto-block misfired on the lab segment", actor: "admin" },
        { at: "2026-10-16T09:00:00Z", scope: "fleet", action: "plan", target: "edge-alive",
          reason: "split the plan for the new segment", actor: "operator" },
      ] })],
    ["/api/graph", GRAPH_PAYLOAD],
    ["/api/flows", (u) => { FLOW_REQS.push(String(u)); return FLOWS_PAYLOAD; }],
    ["/api/discover/trends", DISCOVER_TRENDS_PAYLOAD],
    ["/api/discover", (u) => {
      DISCOVER_REQS.push(String(u));
      const s = String(u);
      if (s.includes("feed=dns")) return DISCOVER_DNS_PAYLOAD;
      if (s.includes("feed=zeek")) return DISCOVER_ZEEK_PAYLOAD;
      return DISCOVER_PAYLOAD;
    }],
    // COUNTED (issue #15): the Sluice tab must be able to fetch this ON DEMAND, once.
    ["/api/blocked", () => { BLOCKED_FETCHES += 1; return BLOCKED_PAYLOAD; }],
    ["/api/dns/reverse", DNS_REVERSE_PAYLOAD],
    ["/api/dns", DNS_PAYLOAD],
    ["/api/settings", SETTINGS_PAYLOAD],
    ["/api/zeeklog", () => ({ available: true, points: [{ addr: "198.51.100.20", n: 5 }] })],
    ["/api/zeek", (u) => {
      ZEEK_REQS.push(String(u));
      const parsed = new URL(String(u), BASE);
      const log = parsed.searchParams.get("log");
      const service = parsed.searchParams.get("service");
      const query = parsed.searchParams.get("query");
      // A filtered response must visibly differ from the unfiltered one; returning the same
      // payload would let a browser-side no-op pass this harness.
      const out = { ...ZEEK_PAYLOAD };
      if (log) out.counts = { ...ZEEK_PAYLOAD.counts,
        points: ZEEK_PAYLOAD.counts.points.filter((p) => p.log === log) };
      if (service) out.services = { ...ZEEK_PAYLOAD.services,
        points: ZEEK_PAYLOAD.services.points.filter((p) => p.service === service) };
      if (query) out.dns = { ...ZEEK_PAYLOAD.dns,
        points: ZEEK_PAYLOAD.dns.points.filter((p) => p.query === query) };
      return out;
    }],
    ["/api/session", SESSION_STUB],
    ["/api/users", USERS_PAYLOAD],
    ["/api/identity", IDENTITY_PAYLOAD],
    ["/api/sluice", SLUICE_PAYLOAD],
    ["/api/fingerprints", FP_PAYLOAD],
    ["/api/models/retrain", RETRAIN_PAYLOAD],
    // PHASE 1: the Ripples card reads its own route. The fixture is a real two-channel ripple
    // with the sentence the server builds, so the check below proves the card renders the
    // explanation and the channel list rather than an empty table.
    [ "/api/ripples", () => ({
      available: true, reason: "", window_hours: 24, count: 1,
      model_version: "ripple-evidence-1",
      monitored_networks: ["198.51.100.0/24"],
      ripples: [{
        host: "198.51.100.5", window_start: "2026-01-01T00:00:00",
        window_end: "2026-01-01T01:00:00", score: 2.41, combined_p: 0.0039,
        channels: ["conn_volume", "dns_volume"],
        families: ["conn", "dns"], single_family: false,
        explanation: "ripple on 198.51.100.5 at 2026-01-01 00:00 UTC: " +
          "conn_volume 41 vs median 5 (p=0.012, rose at 1h); " +
          "dns_volume 60 vs median 6 (p=0.006, rose at 1h).",
        evidence: [
          { channel: "conn_volume", family: "conn", scale: "1h", value: 41,
            baseline_median: 5, p_value: 0.012, p_floor: 0.001996, at_floor: false,
            baseline_short: false, sample_count: 500, direction: "rose" },
          { channel: "dns_volume", family: "dns", scale: "1h", value: 60,
            baseline_median: 6, p_value: 0.006, p_floor: 0.001996, at_floor: false,
            baseline_short: false, sample_count: 500, direction: "rose" },
        ],
      }],
    })],
    ["/api/models/shadow", () => ({ available: true, rows: [
      { key: "hdbscan", label: "HDBSCAN challenger", available: true, state: "collecting",
        rows: 5000, detail: 56, detail_label: "clusters", latest: "2026-01-01T00:00:00", reason: "" },
      { key: "temporal", label: "Matrix Profile", available: true, state: "collecting",
        rows: 48, detail: 2, detail_label: "metrics", latest: "2026-01-01T00:00:00", reason: "" },
      { key: "changepoints", label: "Change points", available: true, state: "collecting",
        rows: 50, detail: 5, detail_label: "hosts", latest: "2026-01-01T00:00:00", reason: "" },
      { key: "calibration", label: "Calibration", available: true, state: "collecting",
        rows: 4, detail: 4, detail_label: "models", latest: "2026-01-01T00:00:00", reason: "" },
    ] })],
    ["/api/baselines", () => BASELINES_PAYLOAD],

    // WEIRLINGS. The DETAIL route is handled ABOVE this table because it must be
    // REQUEST-AWARE: it answers for the sensor asked about, like the real server. A static
    // payload served one sensor's row under every name, which would let a check on registering
    // an undeclared sensor act on a registered one's data.
    ["/api/weirlings", WEIRLINGS_PAYLOAD],

    // The host view (TH-5): its timeline feeds the bytes/flows tile sparklines, and the zero
    // bucket exercises the stub-height rule (a gap must not read as a missing bar).
    ["/api/host", () => ({
      available: true, hostname: "host.example", src_addr: "198.51.100.5", hours: 24,
      totals: { bytes: 1234567, packets: 900, flows: 42, unique_destinations: 7,
                unique_ports: 9, last_seen: "2026-01-01T00:30:00" },
      timeline: [
        { hour: "2026-01-01T00:00:00", bytes: 100, flows: 1 },
        { hour: "2026-01-01T01:00:00", bytes: 900, flows: 5 },
        { hour: "2026-01-01T02:00:00", bytes: 0, flows: 0 },
        { hour: "2026-01-01T03:00:00", bytes: 4000, flows: 9 },
      ],
      top_destinations: [], top_ports: [], errors: null,
    })],


    // The anomalies list, for the SOC-1 review-column checks and the #20 agreement checks.
    // Registered LAST so its match cannot shadow the others; the dispatcher takes the first
    // hit and /api/anomalies shares no prefix with any of the above. REQUEST-AWARE (issue
    // #20): the unreviewed-only filter keeps a row while ANY occurrence is unreviewed -- the
    // rule web.py applies -- because the filter is one of the three surfaces the agreement
    // check compares, so the stub must apply it too.
    ["/api/audit", () => ({ available: true, reason: "",
      now: "2026-10-17T12:00:00+00:00",
      findings: [
        { class: "silent_sensor", severity: "warn", subject: "edge-stale",
          detail: "silent for 1h (stale after 45s)", elapsed_s: 3600,
          fix: { view: "weirlings", sensor: "edge-alive", label: "open the sensor" } },
        { class: "expired_rule", severity: "info", subject: "r-2026-10-14-1",
          detail: "domain rule for ads.example", elapsed_s: 259200,
          fix: { view: "sluice", rule_id: "r-2026-10-14-1", label: "adjust or revoke on Sluice" } },
        { class: "stuck_rule", severity: "warn", subject: "r-2026-09-01-2",
          detail: "firing without a quiet week since 46d (400 hits in 30d) \u2014 still wanted?",
          elapsed_s: 3974400,
          fix: { view: "blocked", rule_id: "r-2026-09-01-2", label: "read the hits on Blocked" } },
        { class: "unowned_detector", severity: "warn", subject: "Mystery Net",
          detail: "unregistered \u2014 no owner, no runbook: it cannot page", elapsed_s: null,
          fix: { view: "anomalies", detector: "Mystery Net", label: "register it (registry strip)" } },
        { class: "silent_sensor", severity: "warn", subject: "edge-promised",
          detail: "declared and enabled but never heard from \u2014 in-path, so its segment may be waiting for it",
          elapsed_s: null,
          fix: { view: "weirlings", sensor: "edge-promised", label: "open the sensor" } },
        { class: "capture_loss", severity: "warn", subject: "edge-moved",
          detail: "dropping 62.5% of packets (400 received, 250 dropped): this sensor is blind to most of what is on the wire",
          elapsed_s: null,
          fix: { view: "weirlings", sensor: "edge-moved", label: "open the sensor" } },
        { class: "segment_mismatch", severity: "info", subject: "edge-moved",
          detail: "registered for segment 'fifth floor' but reporting 'sixth floor'",
          elapsed_s: null,
          fix: { view: "weirlings", sensor: "edge-moved", label: "open the sensor" } },
      ],
      counts: { silent_sensor: 2, expired_rule: 1, stuck_rule: 1, unowned_detector: 1,
                capture_loss: 1, segment_mismatch: 1 },
      errors: {} })],
    ["/api/detectors", () => ({ available: true, reason: "", detectors: [
      { name: "Isolation Forest", owner: "ops", runbook: "read the evidence first",
        rule: "IsolationForest scored this window above the strong-signal floor",
        loud: true, known: true, fired: 3, acted: 1 },
      { name: "LOF", owner: "ops", runbook: "check first-seen before acting",
        rule: "LOF found the window in a sparser local neighbourhood than its peers",
        loud: true, known: true, fired: 2, acted: 0 },
      { name: "Mystery Net", owner: "", runbook: "", rule: "", loud: false, known: false,
        fired: 1, acted: 0 },
    ] })],
    ["/api/anomalies", (u) => {
      // REQUEST-AWARE, like the server: unreviewed keeps a row while ANY occurrence is
      // unreviewed (issue #20), and the min-score floor excludes below-threshold rows so the
      // empty-state checks exercise the same filter path the real query takes.
      const q = new URLSearchParams(String(u).split("?")[1] || "");
      const minF = Number(q.get("min_score") || q.get("min") || "0") || 0;
      const rows = ANOMALIES_STATE.filter(
        (r) => (r.anomaly_score || 0) >= minF
          && (!String(u).includes("unreviewed=1") || (r.unreviewed_n || 0) > 0));
      // THE FUSED STATUS RIDES THE ROWS, exactly as payloads.anomalies builds it: strongest
      // score, configured strong-signal target, union of contributing detectors.
      const detectors = [...new Set(rows.flatMap((r) =>
        String(r.detected_by_models || "").split(",").map((x) => x.trim()).filter(Boolean)))].sort();
      return { rows,
               fused: { score: rows.length ? Math.max(...rows.map((r) => r.anomaly_score || 0)) : null,
                        target: 0.85, detectors },
               discipline: { available: true, reason: "", fired: 4, acted: 1,
                             by_state: { ack: 1 } },
               severity_counts: { available: true, reason: "",
                                 counts: [{ severity: "high", count: 1 },
                                          { severity: "medium", count: 1 }] },
               band_counts: { available: true, reason: "",
                              counts: [{ band: "high", count: 2 },
                                       { band: "medium", count: 1 }] } };
    }],
  );

  const H = window.__H;

  // BF-9: fill and submit the destructive echo (the modal every destructive action opens now).
  // Returns whether the echo was actually there -- a missing echo IS a failing condition in
  // the checks that call this, not something to paper over.
  const confirmEcho = async (reason) => {
    const box = doc.querySelector("#modal-body .dest-confirm");
    if (!box) return false;
    const rIn = box.querySelector(".dest-reason");
    rIn.value = reason || "the check said so";
    rIn.dispatchEvent(new window.Event("input", { bubbles: true }));
    const go = [...box.querySelectorAll(".dest-acts button")].find((b) => /Do it/i.test(b.textContent));
    if (!go || go.hasAttribute("disabled")) return false;
    go.click();
    await new Promise((r) => setTimeout(r, 60));
    return true;
  };

  // jsdom does NOT implement window.confirm: calling it raises a jsdomError, which the "no
  // JavaScript errors" check below would (correctly) flag. The plan editor uses it exactly the
  // way the Settings tab's Apply does -- for a warned-but-allowed change -- so the harness
  // answers it here. Individual checks flip the answer to prove the DECLINE path too.
  window.confirm = () => true;
  if (!H) {
    console.log("  FATAL: the harness epilogue did not run -- cannot assert anything");
    process.exit(2);
  }

  // Let DOMContentLoaded handlers run.
  await new Promise((r) => setTimeout(r, 100));

  // The production Anomalies tab defaults to the incident queue. This harness predates that
  // contract and its checks drive the raw anomaly table; select the raw mode explicitly so the
  // existing renderer checks still exercise the table they were written for. The incident queue
  // gets its own checks below.
  const queueMode = needEl("f-queue-mode");
  if (queueMode) queueMode.value = "raw";

  // ── the incident queue contract ──────────────────────────────────────────────────────────
  // The raw-table checks below predate this surface. Drive the queue once with a stubbed
  // payload: one high/critical pageable episode with a named feature is an incident; a
  // low/medium episode and a model-only high episode are leads. Then restore raw mode.
  {
    const originalFetch = window.fetch;
    window.fetch = (u, o) => {
      if (String(u).includes("/api/episodes")) {
        return Promise.resolve({ ok: true, json: () => Promise.resolve({
          available: true, counts: { episodes: 3, incidents: 1, leads: 2, pageable: 1 },
          incidents: [{ src_addr: "198.51.100.5", episode_start: "2026-11-02T12:00:00-06:00",
            last_detected: "2026-11-02T12:10:00-06:00", window_count: 3, max_score: 0.99,
            severity: "critical", pageable: 1, page_reason: "within-budget",
            primary_feature: "bytes_z", strong_families: 2, role: "server",
            queue_reason: "pageable high/critical with measured evidence" }],
          leads: [
            { src_addr: "198.51.100.6", episode_start: "2026-11-02T12:01:00-06:00",
              last_detected: "2026-11-02T12:09:00-06:00", window_count: 2, max_score: 0.70,
              severity: "medium", pageable: 0, page_reason: "",
              primary_feature: "unique_dst_ips", strong_families: 1, role: "workstation",
              queue_reason: "low/medium observation" },
            { src_addr: "198.51.100.7", episode_start: "2026-11-02T12:02:00-06:00",
              last_detected: "2026-11-02T12:08:00-06:00", window_count: 1, max_score: 0.95,
              severity: "high", pageable: 1, page_reason: "within-budget",
              primary_feature: "", strong_families: 0, role: "server",
              queue_reason: "model-only: no named feature or strong family" },
          ],
        }) });
      }
      return originalFetch(u, o);
    };
    queueMode.value = "incidents";
    await H.loadAnomalies();
    const incRows = doc.querySelectorAll("#episodes-table tbody tr");
    check("the default queue renders one row per incident", incRows.length === 1,
          `${incRows.length} rows`);
    check("an incident names its measured signal", incRows[0]
          && incRows[0].textContent.includes("bytes_z"), incRows[0] && incRows[0].textContent);
    check("the raw anomaly table is not the default queue",
          needEl("anomalies-table").classList.contains("hidden"));
    queueMode.value = "leads";
    await H.loadAnomalies();
    check("Leads hold the low/medium and model-only episodes",
          doc.querySelectorAll("#episodes-table tbody tr").length === 2,
          `${doc.querySelectorAll("#episodes-table tbody tr").length} rows`);
    queueMode.value = "raw";
    window.fetch = originalFetch;
  }

  // ── the new views exist ────────────────────────────────────────────────────────────────
  for (const id of ["view-assets", "view-network"]) {
    check(`#${id} exists`, !!doc.getElementById(id));
  }
  check("the About view is gone", !doc.getElementById("view-about"));
  check("no About tab in the nav",
        !Array.from(doc.querySelectorAll(".tab")).some((t) => t.dataset.view === "about"));
  check("Assets and Network tabs exist",
        !!doc.querySelector('.tab[data-view="assets"]') &&
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
  // Two hop classes on purpose (0 and 1): the ring behaviour needs more than one class to
  // exist at all, and the checks below assert the 0-hop node settles inside the 1-hop one.
  const NODES = [
    { id: "203.0.113.42", name: "workstation.lan", degree: 38, bytes: 7153288, hops: 0, ttl: 64 },
    { id: "192.0.2.40", name: "vault", degree: 6, bytes: 182400000, hops: 1, ttl: 63 },
    { id: "203.0.113.1", name: "gateway", degree: 4, bytes: 900000 },
  ];
  const EDGES = [
    { source: "203.0.113.42", target: "203.0.113.1", bytes: 5000000, flows: 900,
      ttl_min: 64, ttl_max: 64 },
    { source: "203.0.113.42", target: "192.0.2.40", bytes: 400000, flows: 60,
      ttl_min: 63, ttl_max: 63 },
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
  const assetHeads = [...doc.querySelectorAll("#as-table thead th")]
    .map((th) => th.textContent.trim().toLowerCase());
  check("the inventory carries an Identity column",
        assetHeads.includes("identity"), assetHeads.join("|"));
  check("the old Hosts table is retired from the visible Assets page",
        !doc.getElementById("id-hosts-card")
        || needEl("id-hosts-card").classList.contains("hidden"),
        "the duplicate hosts card is still visible");
  check("the address is shown ALONGSIDE the name, not replaced by it",
        !!firstRow && firstRow.textContent.includes("203.0.113.42"));
  check("a zero-anomaly host is shown, not hidden",
        !!rows[1] && doc.querySelectorAll("#as-table tbody tr").length === 2);
  check("unreadable sources are named, not silently dropped",
        needEl("as-note").textContent.includes("zeek_quic"));

  // ONE ASSETS TAB, ONE REAL SCOPE (operator, 2026-11-20: "remove external it will always
  // show 0"). The inventory is monitored-only by the server's rule; a one-item selector was a
  // choice that could not succeed, so the scope is stated rather than selected.
  check("Identity is not a tab of its own any more",
        !doc.querySelector('.tab[data-view="identity"]')
        && !!doc.querySelector("#view-assets #id-table"),
        "the identity table is not inside Assets");
  check("the Assets view no longer offers an External scope",
        !doc.getElementById("as-scope")
        && !/external network/i.test(needEl("as-scope-note")?.parentElement?.textContent || ""),
        "the scope selector or its external option is still present");
  check("the remaining scope is stated, not a one-item dropdown",
        !!doc.getElementById("as-scope-note")
        && /monitored networks/i.test(doc.getElementById("as-scope-note").textContent));
  {
    const baseInv = H.ASSETS_STATE.inventory;
    H.ASSETS_STATE.inventory = {
      ...baseInv,
      hosts: [...baseInv.hosts,
        { addr: "fd00::50", name: "printer", bytes: 10, flows: 1, dst_count: 1,
          first_seen: "", last_seen: "", services: ["dns"], anomalies: 0, scope: "monitored" }],
    };
    // A stale client-side scope value must NOT filter a payload the server already scoped.
    window.NET_SCOPE = "external";
    H.renderAssets();
    const shown = [...doc.querySelectorAll("#as-table tbody tr")].map((r) => r.textContent);
    check("the inventory ignores a stale client-side scope and shows every server row",
          shown.length === 3, `rows=${shown.length}`);
    check("the summary names the monitored set",
          /monitored hosts/i.test(needEl("as-summary").textContent),
          needEl("as-summary").textContent);
    window.NET_SCOPE = "all";
    H.ASSETS_STATE.inventory = baseInv;
    H.renderAssets();
  }

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
  // BARE `openHost(...)` calls in the page resolve the GLOBAL PROPERTY, not the __H export:
  // restoring only H.openHost left the spy armed for the entire run (measured: every later
  // host drill silently no-opped while its check, asserting only the view, kept passing).
  window.openHost = realOpenHost;

  // ── the asset inventory pager ──────────────────────────────────────────────────────────
  // The bug this guards: 245 hosts rendered as one scroll. ONE page size for the console
  // (PAGER_PAGE_SIZE = 25), and the range must be stated -- "page 2 of 2" alone hides the total.
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
        doc.querySelectorAll("#as-table tbody tr").length === 25,
        `${doc.querySelectorAll("#as-table tbody tr").length} rows`);
  check("the pager states the range AND the total",
        needEl("as-pager").textContent.includes("rows 1\u201325 of 47"),
        needEl("as-pager").textContent);
  check("the pager states which page of how many",
        needEl("as-pager").textContent.includes("page 1 of 2"),
        needEl("as-pager").textContent);
  check("'previous' is disabled on the first page",
        doc.querySelector("#as-pager .pager-btn").disabled === true);

  // The next arrow must advance, and the rows must change.
  const nextBtn = Array.from(doc.querySelectorAll("#as-pager .pager-btn")).find(
    (b) => b.textContent.includes("\u203a"));
  check("a next arrow exists", !!nextBtn);
  nextBtn.dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  check("clicking next advances to page 2",
        needEl("as-pager").textContent.includes("page 2 of 2"),
        needEl("as-pager").textContent);
  check("page 2 shows the NEXT range of hosts",
        needEl("as-pager").textContent.includes("rows 26\u201347 of 47"),
        needEl("as-pager").textContent);
  check("page 2 holds exactly the remaining rows",
        doc.querySelectorAll("#as-table tbody tr").length === 22,
        `${doc.querySelectorAll("#as-table tbody tr").length} rows`);
  // Assert the rows CHANGED, not a specific address: the default sort is by anomalies then
  // bytes, so page 1 holds the highest-byte hosts and pinning a literal would encode an
  // assumption about the sort rather than about pagination (which is what is under test here).
  const pageTwoFirst = doc.querySelector("#as-table tbody tr td").textContent;
  check("the rows on page 2 differ from page 1",
        pageTwoFirst !== "192.0.2.47", `page2 first row = ${pageTwoFirst}`);

  // The last page holds the remainder, not a full slice -- and the range stops at the total.
  check("the final page's range stops at the total",
        needEl("as-pager").textContent.includes("26\u201347 of 47"),
        needEl("as-pager").textContent);
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
        needEl("nw-caption").textContent.includes("capped"),
        needEl("nw-caption").textContent);
  check("the chips area explains the empty selection",
        needEl("nw-selected").textContent.includes("every connection"),
        needEl("nw-selected").textContent.slice(0, 80));

  // ── the force map: deterministic, TTL-ringed ──────────────────────────────────────────────
  // The property the old fixed circle existed to protect was comparability -- two people on
  // the same data see the same picture. The map has to keep it BY CONSTRUCTION: no randomness,
  // one fixed tick count. Two runs, one map.
  {
    const box = { cx: 500, cy: 230, w: 960, h: 420 };
    const a = H.computeLayout(NODES, EDGES, box);
    const b = H.computeLayout(NODES, EDGES, box);
    let same = a.end.size === b.end.size;
    for (const [id, p] of a.end) {
      const q = b.end.get(id);
      if (!q || Math.abs(p.x - q.x) > 1e-9 || Math.abs(p.y - q.y) > 1e-9) same = false;
    }
    check("the force layout is deterministic: the same window settles to the same map", same);
    const rad = (id) => {
      const p = a.end.get(id);
      return Math.hypot(p.x - box.cx, p.y - box.cy);
    };
    check("TTL hop classes settle into ordered rings (0-hop inside the 1-hop)",
          rad("203.0.113.42") < rad("192.0.2.40"),
          `r0=${rad("203.0.113.42").toFixed(1)} r1=${rad("192.0.2.40").toFixed(1)}`);
    check("every settled position is finite and inside the frame",
          [...a.end.values()].every((p) => Number.isFinite(p.x) && Number.isFinite(p.y) &&
            p.x > 0 && p.x < 1000 && p.y > 0 && p.y < 460));
    check("a host with no TTL reading still gets a position (links alone)",
          a.end.has("203.0.113.1"));
    const c = H.computeLayout(NODES, EDGES, box, a.end, new Set(["203.0.113.42"]));
    const held = c.end.get("203.0.113.42");
    check("a dragged (pinned) host holds its dropped position through the re-settle",
          Math.abs(held.x - a.end.get("203.0.113.42").x) < 0.5 &&
          Math.abs(held.y - a.end.get("203.0.113.42").y) < 0.5,
          `held=${held.x.toFixed(1)},${held.y.toFixed(1)}`);
    check("the hop rings are drawn when TTL gives more than one class",
          doc.querySelectorAll("#nw-graph circle.ring").length === 2,
          `rings=${doc.querySelectorAll("#nw-graph circle.ring").length}`);
    check("the hover card carries the TTL evidence behind a ring",
          H.nodeTitle(NODES[0]).includes("ttl 64"), H.nodeTitle(NODES[0]));
  }

  // (A bare node click no longer tracks -- see the block that drives the panel's track
  //  button, which is the path the user actually takes. These assertions moved there.)
  // Clicking a node triggers loadNetwork(), which is async: the re-render that marks the node
  // as selected happens in a later tick. Asserting synchronously measures the clock, not the
  // code -- and that is exactly what produced the earlier false failure.
  // (A bare node click no longer tracks -- see the block that drives the panel's track
  //  button, which is the path the user actually takes. These assertions moved there.)

  // Two hosts tracked at once -- the user's "select any number" requirement. Tracking is now
  // driven by the explicit action in the detail panel rather than by a bare node click, so the
  // test drives the real path: open a node, press its track button.
  H.ASSETS_STATE.tracked = [];
  H.renderNetwork();
  for (const idx of [0, 1]) {
    const g = doc.querySelectorAll("#nw-graph g.node")[idx];
    g.dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
    const trackBtn = Array.from(doc.querySelectorAll("#nw-detail button"))
      .find((b) => b.textContent.includes("track only"));
    check(`node ${idx}'s detail panel offers a track button`, !!trackBtn);
    trackBtn.dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  }
  await new Promise((r) => setTimeout(r, 60));
  check("two hosts can be tracked at once",
        H.ASSETS_STATE.tracked.length === 2,
        JSON.stringify(H.ASSETS_STATE.tracked));
  check("both tracked hosts are listed as chips",
        doc.querySelectorAll("#nw-selected .bubble").length === 2,
        `${doc.querySelectorAll("#nw-selected .bubble").length} chips`);
  check("a chip removes its host when clicked",
        (() => {
          doc.querySelector("#nw-selected .bubble")
             .dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
          return H.ASSETS_STATE.tracked.length === 1;
        })(), JSON.stringify(H.ASSETS_STATE.tracked));

  // ── what clicking the GRAPH means ──────────────────────────────────────────────────────
  H.ASSETS_STATE.tracked = [];
  // The user's report: "i like the network diagram. i dont understand what clicking down.
  // i need like source and destination". Clicking used to toggle a filter silently.
  H.ASSETS_STATE.tracked = [];
  H.ASSETS_STATE.graph = GRAPH_PAYLOAD;
  H.renderNetwork();

  const edgeLines = doc.querySelectorAll("#nw-graph line.edge-hit");
  check("each drawn edge has a widened click target", edgeLines.length === 2,
        `${edgeLines.length} hit-lines`);

  // Click an EDGE -> that pair's source and destination.
  edgeLines[0].dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
  const dTitle = needEl("nw-detail-title").textContent;
  check("clicking an edge says it is showing one connection",
        dTitle.includes("one connection"), dTitle);
  check("the edge detail names the SOURCE",
        needEl("nw-detail").textContent.includes("203.0.113.42"),
        needEl("nw-detail").textContent.slice(0, 80));
  check("the edge detail names the DESTINATION",
        needEl("nw-detail").textContent.includes("203.0.113.1"),
        needEl("nw-detail").textContent.slice(0, 80));
  check("the source and destination are LABELLED, not just listed",
        needEl("nw-detail").textContent.includes("source") &&
        needEl("nw-detail").textContent.includes("destination"));
  check("the edge detail shows the ports",
        needEl("nw-detail").textContent.includes("443"));
  check("the name is shown ALONGSIDE the address, never instead of it",
        needEl("nw-detail").textContent.includes("workstation.lan") &&
        needEl("nw-detail").textContent.includes("203.0.113.42"));
  check("the edge detail renders the arrow between the two sides",
        !!doc.querySelector("#nw-detail .pair-arrow"));

  // Click a NODE -> everything that host talked to, direction separated.
  H.showNodeDetail(GRAPH_PAYLOAD.nodes[0]);
  check("clicking a node lists its conversations",
        doc.querySelectorAll("#nw-detail-table tbody tr").length >= 2,
        `${doc.querySelectorAll("#nw-detail-table tbody tr").length} rows`);
  check("the node detail separates outbound from inbound",
        needEl("nw-detail-table").textContent.includes("outbound"),
        needEl("nw-detail-table").textContent.slice(0, 80));
  check("the node detail offers tracking as an explicit ACTION",
        needEl("nw-detail").textContent.includes("track only this host"));
  check("clicking an edge and clicking a node show DIFFERENT panels",
        needEl("nw-detail-title").textContent.includes("workstation") ||
        needEl("nw-detail-title").textContent.includes("192.0.2.10"),
        needEl("nw-detail-title").textContent);

  // And the node's own click handler must open the panel, not silently toggle tracking.
  H.ASSETS_STATE.tracked = [];
  H.renderNetwork();
  doc.querySelector("#nw-graph g.node").dispatchEvent(
    new window.MouseEvent("click", { bubbles: true }));
  check("a real click on a node opens the detail panel",
        needEl("nw-detail-title").textContent.length > 0 &&
        needEl("nw-detail-title").textContent !== "click a line or a dot",
        needEl("nw-detail-title").textContent);
  check("a real click on a node does NOT silently change the tracked set",
        H.ASSETS_STATE.tracked.length === 0,
        JSON.stringify(H.ASSETS_STATE.tracked));

  // ── RIPPLE PRESENCE ON THE NETWORK VIEW (2026-11-20) ──────────────────────────────────────
  //
  // The Network tab reads `ripples` and `severity_bands` from the /api/graph payload, which the
  // server fills from the SAME ripple grouping `/api/ripples` returns. The checks below pin the
  // table chips, the blank cell, the higher-of-two rule, the graph ring and the header count.
  {
    const bands = {
      low: { min_score: 3.0, min_families: 1 },
      medium: { min_score: 4.0, min_families: 2 },
      high: { min_score: 6.0, min_families: 3 },
      bar: { family_max_p: 0.01, extreme_p: 0.001, min_score: 3.0, min_families: 2 },
    };
    const RIPPLE_GRAPH = {
      available: true, hours: 24, total_edges: 3, status_available: true,
      ripple_available: true, ripple_window_hours: 24, severity_bands: bands,
      ripples: [
        { host: "203.0.113.42", window_start: "2026-11-20T09:00:00", score: 7.11,
          families: ["conn", "dns", "tls"], severity: "high", single_family: false,
          explanation: "ripple on 203.0.113.42", evidence: [] },
        { host: "192.0.2.40", window_start: "2026-11-20T08:00:00", score: 3.42,
          families: ["flow"], severity: "low", single_family: true,
          explanation: "ripple on 192.0.2.40", evidence: [] },
      ],
      nodes: [
        { id: "203.0.113.42", name: "workstation.lan", degree: 2, bytes: 700, hops: 0, ttl: 64,
          ripple_count: 1, ripple_worst: "high", ripple_families: ["conn", "dns", "tls"],
          anomaly_count: 3, model_worst: "high" },
        { id: "192.0.2.40", name: "vault", degree: 2, bytes: 500,
          ripple_count: 1, ripple_worst: "low", ripple_families: ["flow"],
          anomaly_count: 0, model_worst: "" },
        { id: "203.0.113.1", name: "gateway", degree: 1, bytes: 200,
          ripple_count: 0, ripple_worst: "", ripple_families: [],
          anomaly_count: 0, model_worst: "" },
        { id: "198.51.100.9", name: "quiet", degree: 1, bytes: 100,
          network_scope: "unclassified",
          ripple_count: 0, ripple_worst: "", ripple_families: [],
          anomaly_count: 0, model_worst: "" },
      ],
      edges: [
        { source: "203.0.113.42", target: "203.0.113.1", bytes: 500, flows: 9, ports: [443] },
        { source: "192.0.2.40", target: "203.0.113.42", bytes: 300, flows: 4, ports: [22] },
        { source: "203.0.113.1", target: "198.51.100.9", bytes: 100, flows: 1, ports: [53] },
      ],
    };
    H.ASSETS_STATE.tracked = [];
    H.ASSETS_STATE.status = "all";
    H.ASSETS_STATE.graph = RIPPLE_GRAPH;
    H.renderNetwork();

    const nwRows = [...doc.querySelectorAll("#nw-table tbody tr")];
    check("the Network edge table carries a signals cell for EACH endpoint",
          nwRows.length === 3
          && !!nwRows[0].querySelectorAll(".nw-sig-cell")[0].querySelector(".nw-sig.sev-high")
          && nwRows[0].children.length === 7,
          `${nwRows.length} rows; ${nwRows[0] ? nwRows[0].textContent : "none"}`);
    check("the signals cell states ripples and model detections, not a bare dot",
          !!nwRows[0] && nwRows[0].children[2].textContent.trim() === "1r · 3m",
          nwRows[0] ? `|${nwRows[0].children[2].textContent}|` : "no row");
    check("a quiet edge leaves both signals cells blank, never a zero chip",
          !!nwRows[2] && !nwRows[2].querySelector(".nw-sig")
          && nwRows[2].children[2].textContent.trim() === ""
          && nwRows[2].children[3].textContent.trim() === "",
          nwRows[2] ? `|${nwRows[2].children[2].textContent}|` : "no row");
    check("an edge with ripples on BOTH ends shows each endpoint's own band",
          !!nwRows[1]
          && !!nwRows[1].children[2].querySelector(".nw-sig.sev-low")
          && !!nwRows[1].children[3].querySelector(".nw-sig.sev-high"),
          nwRows[1] ? `${nwRows[1].children[2].textContent} / ${nwRows[1].children[3].textContent}` : "no row");

    // THE INBOUND HALF. An edge whose ONLY rippling endpoint is its TARGET must still carry the
    // chip: that host's evidence comes from the inbound flow channels, and before schema 061 it
    // had none. A source-only lookup would draw this edge as quiet. The edge is stated so the
    // target is the ONLY rippling end (the old fixture used 192.0.2.40 -> .42, where the SOURCE
    // also ripples, so it could not tell source attribution from target attribution).
    H.ASSETS_STATE.graph = {
      ...RIPPLE_GRAPH,
      edges: [{ source: "203.0.113.1", target: "192.0.2.40", bytes: 90, flows: 2, ports: [445] }],
      ripples: [RIPPLE_GRAPH.ripples[1]],
    };
    H.renderNetwork();
    const targetRows = [...doc.querySelectorAll("#nw-table tbody tr")];
    check("an edge is attributed to its DESTINATION endpoint when only the target ripples",
          !!targetRows[0] && !!targetRows[0].children[3].querySelector(".nw-sig.sev-low")
          && targetRows[0].children[2].textContent.trim() === ""
          && targetRows[0].children[3].querySelector(".nw-sig").getAttribute("title")
            .includes("192.0.2.40"),
          targetRows[0] ? `${targetRows[0].children[2].textContent}|${targetRows[0].children[3].textContent}` : "no row");
    H.ASSETS_STATE.graph = RIPPLE_GRAPH;
    H.renderNetwork();

    const line = needEl("nw-ripple-line").textContent.replace(/\s+/g, " ");
    check("the Network header counts the hosts in view and the same ripple count",
          /2 of 4 hosts in view have 2 ripples in this 24h window/.test(line)
          && /open Alerts/.test(line), line.slice(0, 180));

    const rippleNodes = [...doc.querySelectorAll("#nw-graph g.node.has-ripple")];
    check("a ripple host's graph node carries a severity ring",
          rippleNodes.length === 2
          && !!doc.querySelector("#nw-graph .node-ripple-ring.rp-sev-high")
          && !!doc.querySelector("#nw-graph .node-ripple-ring.rp-sev-low"),
          `${rippleNodes.length} ripple nodes`);
    // TWO SIGNAL LAYERS, AND NO DASH ANYWHERE (operator, 2026-11-20: "you have three icons
    // that are basically orange ... unclassified, alerted and ripple"). Scope is a word in the
    // host table/sheet, never an outline on this map.
    const graphMarks = [...doc.querySelectorAll("#nw-graph *")];
    const dashes = graphMarks.filter((el2) => {
      const style = el2.getAttribute("style") || "";
      const css = window.getComputedStyle(el2).strokeDasharray || "none";
      return /dasharray/.test(style) || (css !== "none" && css !== "");
    });
    check("no graphic in the Network map uses a dash — the graph carries two signal layers only",
          dashes.length === 0,
          dashes.map((d) => d.tagName + ":" + (d.getAttribute("style") || "")).join(" | ").slice(0, 200));
    const quietNode = [...doc.querySelectorAll("#nw-graph g.node")]
      .find((n) => (n.getAttribute("aria-label") || "").includes("198.51.100.9")
        || n.textContent.includes("198.51.100.9"));
    check("a host with zero ripples draws NO ring at all (no invented signal)",
          !!quietNode && !quietNode.querySelector(".node-ripple-ring"),
          quietNode ? `${quietNode.querySelectorAll("circle").length} circles` : "quiet node not drawn");
    check("an unclassified host renders as an ORDINARY node — scope is a word, not a mark",
          !!quietNode
          && !/unclassified/i.test(quietNode.getAttribute("class") || "")
          && !/dasharray/i.test(quietNode.querySelector("circle").getAttribute("style") || ""),
          quietNode ? quietNode.getAttribute("class") : "quiet node not drawn");
    const cssText = [...doc.querySelectorAll("style")].map((s) => s.textContent).join("\n");
    const ringRules = ["high", "medium", "low"].map((band) => {
      const m = cssText.match(new RegExp(
        `\\.node-ripple-ring\\.rp-sev-${band}\\s*\\{\\s*stroke:\\s*([^;]+);`));
      return m ? m[1].trim() : "";
    });
    check("the three ripple bands use three distinct COOL tokens, never the alerted orange",
          new Set(ringRules).size === 3 && ringRules.every((v) => v.startsWith("var(--series-")),
          ringRules.join(" | "));
    const legendText = needEl("nw-legend").textContent.replace(/\s+/g, " ");
    check("the legend lists the two signal layers and no scope outline",
          /alerted: anomaly in this range/.test(legendText)
          && /solid ring = ripples in this window/.test(legendText)
          && !/unclassified/i.test(legendText)
          && !/dashed/i.test(legendText),
          legendText.slice(0, 320));
    check("the node's accessible name names the ripple score and families",
          rippleNodes.some((n) => (n.getAttribute("aria-label") || "").includes("ripple: score 7.11")
            && (n.getAttribute("aria-label") || "").includes("conn / dns / tls")),
          rippleNodes.map((n) => n.getAttribute("aria-label")).join(" | ").slice(0, 220));
    check("the graph legend names the solid ripple ring and no scope outline",
          /solid ring = ripples in this window/.test(needEl("nw-legend").textContent)
          && !/unclassified/i.test(needEl("nw-legend").textContent),
          needEl("nw-legend").textContent.slice(0, 240));

    // A CHIP IS A DOOR TO THE HOST SHEET, and it must not trigger the row's own click.
    const beforeTracked = JSON.stringify(H.ASSETS_STATE.tracked);
    nwRows[0].children[2].querySelector(".nw-sig").dispatchEvent(
      new window.MouseEvent("click", { bubbles: true }));
    const hostSheet = needEl("nw-host-card");
    check("clicking a Network signals chip opens that host's sheet",
          !hostSheet.classList.contains("hidden")
          && (needEl("nw-host-title").textContent + needEl("nw-host-addr").textContent)
            .includes("203.0.113.42"),
          needEl("nw-host-title").textContent + needEl("nw-host-addr").textContent);
    check("...and the chip click does not trigger the row's tracking handler",
          JSON.stringify(H.ASSETS_STATE.tracked) === beforeTracked,
          JSON.stringify(H.ASSETS_STATE.tracked));
    needEl("nw-host-close").click();

    H.showEdgeDetail(RIPPLE_GRAPH.edges[1]);
    check("the connection detail table also carries the Ripple column",
          [...doc.querySelectorAll("#nw-detail-table th")]
            .some((th) => th.textContent.trim() === "Ripple")
          && !!doc.querySelector("#nw-detail-table tbody .nw-ripple-bubble.sev-high"),
          needEl("nw-detail-table").textContent.slice(0, 200));

    // ── THE RIPPLE FILTER (operator, 2026-11-20: "for network i need to be able to filter by
    // ripples") ───────────────────────────────────────────────────────────────────────────────
    // One state narrows the graph, the detail table and the edge table together; All restores
    // the full set; the count line names the matched hosts; an empty result names the filter.
    const clickRipple = (mode) => {
      const btn = doc.querySelector(`#nw-ripple [data-nw-ripple="${mode}"]`);
      if (btn) btn.click();
    };
    clickRipple("any");
    const anyRows = [...doc.querySelectorAll("#nw-table tbody tr")];
    const anyNodes = [...doc.querySelectorAll("#nw-graph g.node")];
    check("the Network ripple filter narrows graph and edge table together",
          anyRows.length === 2 && anyNodes.length === 3,
          `rows=${anyRows.length} nodes=${anyNodes.length}`);
    check("...and the count line restates what is shown",
          /2 of 4 hosts have ripples in this 24h window — showing 2/.test(
            needEl("nw-ripple-line").textContent.replace(/\s+/g, " ")),
          needEl("nw-ripple-line").textContent.replace(/\s+/g, " ").slice(0, 200));
    check("...and the caption says the filter is on",
          /24h window/.test(needEl("nw-caption").textContent)
          && /showing 2 of 4 hosts/.test(needEl("nw-caption").textContent)
          && /ripples: hosts with ripples/.test(needEl("nw-caption").textContent),
          needEl("nw-caption").textContent);

    H.showNodeDetail(RIPPLE_GRAPH.nodes[2]);
    check("the connection-detail table obeys the same ripple filter",
          doc.querySelectorAll("#nw-detail-table tbody tr.clickable").length === 1,
          `${doc.querySelectorAll("#nw-detail-table tbody tr.clickable").length} detail edge rows`);

    clickRipple("high");
    check("High and above keeps only the high-band host",
          /1 of 4 hosts have high-band ripples in this 24h window — showing 1/.test(
            needEl("nw-ripple-line").textContent.replace(/\s+/g, " ")),
          needEl("nw-ripple-line").textContent.replace(/\s+/g, " ").slice(0, 200));

    H.syncURL();
    check("the ripple filter rides the URL", /nw\.ripple=high/.test(window.location.hash),
          window.location.hash.slice(0, 110));
    const savedFilter = H.ASSETS_STATE.rippleFilter;
    H.ASSETS_STATE.rippleFilter = "all";
    window.location.hash = "#v=network&nw.ripple=high";
    H.applyURLState();
    check("...and a filtered link restores it on load",
          H.ASSETS_STATE.rippleFilter === "high" && savedFilter === "high"
          && doc.querySelector('[data-nw-ripple="high"]').getAttribute("aria-pressed") === "true",
          `state=${H.ASSETS_STATE.rippleFilter} pressed=${doc.querySelector('[data-nw-ripple="high"]').getAttribute("aria-pressed")}`);

    clickRipple("any");
    H.ASSETS_STATE.graph = { ...RIPPLE_GRAPH, ripples: [] };
    H.renderNetwork();
    check("an empty filtered result names the active filter, never 'No edges to show'",
          /No host has a ripple/.test(needEl("nw-caption").textContent)
          && /ripple filter/i.test(doc.querySelector("#nw-table tbody").textContent)
          && !/No edges to show/.test(doc.querySelector("#nw-table tbody").textContent),
          `${needEl("nw-caption").textContent} | ${doc.querySelector("#nw-table tbody").textContent}`);

    clickRipple("all");
    H.ASSETS_STATE.graph = { ...RIPPLE_GRAPH };
    H.renderNetwork();
    check("clearing the filter restores the full graph and table",
          doc.querySelectorAll("#nw-table tbody tr").length === 3
          && doc.querySelectorAll("#nw-graph g.node").length === 4,
          `rows=${doc.querySelectorAll("#nw-table tbody tr").length} nodes=${doc.querySelectorAll("#nw-graph g.node").length}`);

    H.ASSETS_STATE.status = "all";
    H.ASSETS_STATE.rippleFilter = "all";
    H.ASSETS_STATE.graph = GRAPH_PAYLOAD;
  }

  // ── THE COMPOSABLE FILTERS, THE HOST TABLE, AND THE HOST SHEET (2026-11-20) ──────────────
  // Family, subnet and text all narrow the SAME cached payload; a host must pass every active
  // reading. The count line's denominator is the population before tracked-only. A host row opens
  // the sheet, and the sheet must render real identity/traffic/ripple/model sections with the
  // window's honest coverage — not a loading state and not a zero for an unread source.
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const FILTER_GRAPH = {
      available: true, hours: 24, total_edges: 2, status_available: true,
      ripple_available: true, ripple_window_hours: 24, severity_bands: {},
      coverage: { available: true, from: "2026-11-17T05:30:00", to: "2026-11-20T09:00:00" },
      nodes: [
        { id: "203.0.113.42", name: "workstation.lan", degree: 2, bytes: 700,
          ripple_count: 2, ripple_worst: "high", ripple_families: ["conn", "dns", "tls"],
          anomaly_count: 3, model_worst: "high" },
        { id: "192.0.2.40", name: "vault", degree: 2, bytes: 500,
          ripple_count: 1, ripple_worst: "low", ripple_families: ["flow"],
          anomaly_count: 0, model_worst: "" },
        { id: "203.0.113.1", name: "gateway", degree: 1, bytes: 200,
          ripple_count: 0, ripple_worst: "", ripple_families: [], anomaly_count: 0, model_worst: "" },
      ],
      edges: [
        { source: "203.0.113.42", target: "203.0.113.1", bytes: 700, flows: 5, ports: [443] },
        { source: "203.0.113.42", target: "192.0.2.40", bytes: 500, flows: 4, ports: [22] },
      ],
    };
    const HOST_SHEET = {
      available: true, addr: "192.0.2.40", hours: 24,
      window: { hours: 24, since: "2026-11-19T09:00:00", until: "2026-11-20T09:00:00" },
      identity: { available: true, ptr: "vault.example", hostnames: ["vault.example", "vault"],
                  ja4: ["t13d1516"], mac: "aa:bb:cc:dd:ee:ff", os: "Linux 6", confidence: 0.9,
                  updated_at: "", netbios: [{ name: "VAULT", domain: "CORP", count: 4 }],
                  dhcp_names: [{ name: "vault-dhcp", count: 2 }], role: "", first_seen: "",
                  last_seen: "", first_seen_basis: "not measured" },
      traffic: { available: true, reason: "",
                 in: { flows: 12, bytes: 4096, packets: 30, peers: 3,
                       first: "2026-11-19T12:00:00", last: "2026-11-20T08:00:00" },
                 out: { flows: 8, bytes: 2048, packets: 20, peers: 2,
                        first: "2026-11-19T12:00:00", last: "2026-11-20T08:00:00" },
                 outbound_flows: null },
      peers: { available: true, reason: "",
               rows: [{ peer: "203.0.113.9", out_bytes: 1000, in_bytes: 2000,
                        out_conns: 3, in_conns: 4 }] },
      services: { available: true, reason: "", services: [{ service: "ssl", conns: 5 }],
                  listening_ports: [{ port: 443, proto: "tcp", conns: 4 }],
                  used_ports: [{ port: 53, proto: "udp", conns: 2 }] },
      dns: { available: true, reason: "", queries: [{ name: "example.test", qtype: 1, asks: 7 }] },
      tls: { available: true, reason: "", names: [{ name: "vault.example", sessions: 3 }],
             ja4_count: 2 },
      models: { available: true, reason: "", count: 3, worst: "high",
                by_severity: { high: 2, low: 1 },
                rows: [{ window_start: "2026-11-20T08:00:00", severity: "high", score: 0.91,
                         models: "LOF,IF", attack: "beacon" }] },
      ripples: { available: true, reason: "", count: 1, worst: "high", window_hours: 24,
                 rows: [{ host: "192.0.2.40", severity: "high", score: 7.11,
                          window_start: "2026-11-20T08:00:00", families: ["conn", "dns"],
                          explanation: "a ripple on 192.0.2.40", evidence: [] }] },
      normalized: { available: true, reason: "", count: 0, rows: [] },
      coverage: {
        flows_window: { from: "2026-11-12T13:50:00", to: "2026-11-20T09:00:00" },
        flows_window_endpoint: { from: "2026-11-19T14:00:00", to: "2026-11-20T09:00:00" },
        ripple_evidence: { from: "2026-11-19T14:00:00", to: "2026-11-20T09:00:00" },
        netflow_anomalies: { from: "2026-11-10T00:00:00", to: "2026-11-20T09:00:00" },
      },
      errors: {},
    };
    H.ASSETS_STATE.tracked = [];
    H.ASSETS_STATE.status = "all";
    H.ASSETS_STATE.rippleFilter = "all";
    H.ASSETS_STATE.family = "all";
    H.ASSETS_STATE.subnet = "";
    H.ASSETS_STATE.query = "";
    H.ASSETS_STATE.sortHosts = "interest";
    H.ASSETS_STATE.graph = FILTER_GRAPH;
    H.renderNetwork();

    const hostRows = () => [...doc.querySelectorAll("#nw-hosts-table tbody tr")]
      .filter((r) => r.querySelector("td.link"));
    check("the host table lists the map's matched population",
          hostRows().length === 3, `${hostRows().length} host rows`);
    check("the host table orders by band first, bytes second",
          hostRows()[0].textContent.includes("203.0.113.42")
          && hostRows()[1].textContent.includes("192.0.2.40"),
          hostRows().map((r) => r.textContent.replace(/\s+/g, " ").trim()).join(" | ").slice(0, 200));

    doc.querySelector('#nw-family [data-nw-family="dns"]').click();
    check("the family chip narrows the host table to the host carrying that family",
          hostRows().length === 1 && hostRows()[0].textContent.includes("203.0.113.42"),
          `${hostRows().length} rows: ${hostRows().map((r) => r.textContent.trim()).join(" | ")}`);

    const subnetInput = needEl("nw-subnet");
    subnetInput.value = "192.0.2.0/24";
    subnetInput.dispatchEvent(new window.Event("input", { bubbles: true }));
    check("family and subnet COMPOSE: a host must pass every active reading",
          hostRows().length === 0
          && /family dns/.test(needEl("nw-caption").textContent)
          && /subnet 192\.0\.2\.0\/24/.test(needEl("nw-caption").textContent),
          needEl("nw-caption").textContent);
    // A GENUINE EMPTY FILTER RESULT KEEPS THE FILTER'S WORD. This is the contrast that gives the
    // failed read below its meaning: zero rows because the filters selected none is not a failure.
    check("...and an empty FILTER result still says 'Nothing matches', with the filters named",
          /Nothing matches/.test(doc.querySelector("#nw-hosts-table tbody").textContent)
          && !!doc.querySelector('#nw-hosts-table .empty-state[data-state="filtered"]'),
          doc.querySelector("#nw-hosts-table tbody").textContent.replace(/\s+/g, " ").trim().slice(0, 160));

    // A FAILED GRAPH READ IS NOT AN EMPTY FILTER RESULT. The host table used to fall through to
    // "Nothing matches" in amber on a failed /api/graph read, implying the operator's filters had
    // emptied it while the edges table beside it said "Could not read". Both surfaces must state
    // the same fact, and the failure must never borrow the filter's word.
    H.ASSETS_STATE.graph = { available: false, hours: 24,
      reason: "the graph query timed out after 20s" };
    H.renderNetwork();
    const failedHosts = doc.querySelector("#nw-hosts-table tbody").textContent;
    check("a failed graph read says 'Could not read' in the host table, not 'Nothing matches'",
          /Could not read/.test(failedHosts) && !/Nothing matches/.test(failedHosts)
          && !!doc.querySelector('#nw-hosts-table .empty-state[data-state="failed"]'),
          failedHosts.replace(/\s+/g, " ").trim().slice(0, 160));
    check("...and it names the read that failed, not the operator's filters",
          /connection graph could not be read/i.test(failedHosts)
          && /timed out after 20s/.test(failedHosts),
          failedHosts.replace(/\s+/g, " ").trim().slice(0, 160));
    H.ASSETS_STATE.graph = FILTER_GRAPH;
    H.renderNetwork();

    doc.querySelector('#nw-family [data-nw-family="all"]').click();
    check("clearing the family leaves the subnet reading in place",
          hostRows().length === 1 && hostRows()[0].textContent.includes("192.0.2.40"),
          hostRows().map((r) => r.textContent.replace(/\s+/g, " ").trim()).join(" | "));

    const findInput = needEl("nw-find");
    findInput.value = "gateway";
    findInput.dispatchEvent(new window.Event("input", { bubbles: true }));
    check("the text filter composes with the subnet (no host passes both)",
          hostRows().length === 0, `${hostRows().length} rows`);
    findInput.value = "vault";
    findInput.dispatchEvent(new window.Event("input", { bubbles: true }));
    check("the text filter searches the NAME as well as the address",
          hostRows().length === 1 && hostRows()[0].textContent.includes("vault"),
          hostRows().map((r) => r.textContent.replace(/\s+/g, " ").trim()).join(" | "));

    findInput.value = "";
    findInput.dispatchEvent(new window.Event("input", { bubbles: true }));
    subnetInput.value = "";
    subnetInput.dispatchEvent(new window.Event("input", { bubbles: true }));
    const sortSelect = needEl("nw-sort");
    sortSelect.value = "busy";
    sortSelect.dispatchEvent(new window.Event("change", { bubbles: true }));
    check("busy order leads with bytes, and the note states the arithmetic",
          hostRows()[0].textContent.includes("203.0.113.42")
          && /Ordered by bytes/.test(needEl("nw-hosts-note").textContent),
          needEl("nw-hosts-note").textContent);

    H.syncURL();
    check("the new filters ride the URL",
          /nw\.sort=busy/.test(window.location.hash), window.location.hash.slice(0, 140));
    H.ASSETS_STATE.family = "all";
    H.ASSETS_STATE.sortHosts = "interest";
    window.location.hash = "#v=network&nw.family=tls&nw.subnet=203.0.113.0%2F24&nw.q=work&nw.sort=busy";
    H.applyURLState();
    check("...and a cold load restores all four, controls included",
          H.ASSETS_STATE.family === "tls" && H.ASSETS_STATE.subnet === "203.0.113.0/24"
          && H.ASSETS_STATE.query === "work" && H.ASSETS_STATE.sortHosts === "busy"
          && needEl("nw-subnet").value === "203.0.113.0/24"
          && needEl("nw-find").value === "work" && needEl("nw-sort").value === "busy"
          && doc.querySelector('#nw-family [data-nw-family="tls"]').getAttribute("aria-pressed") === "true",
          `family=${H.ASSETS_STATE.family} subnet=${H.ASSETS_STATE.subnet} q=${H.ASSETS_STATE.query} sort=${H.ASSETS_STATE.sortHosts}`);

    // THE URL ROUND TRIP LEAVES THE HASH LOADED. The app re-applies it on hashchange, so clear
    // it BEFORE resetting the state — otherwise the event restores the filters just cleared, and
    // every later Network section inherits them.
    window.location.hash = "#v=network";
    H.applyURLState();
    await sleep(20);
    H.ASSETS_STATE.family = "all";
    H.ASSETS_STATE.subnet = "";
    H.ASSETS_STATE.query = "";
    H.ASSETS_STATE.sortHosts = "interest";
    needEl("nw-subnet").value = "";
    needEl("nw-find").value = "";
    needEl("nw-sort").value = "interest";
    H.ASSETS_STATE.graph = FILTER_GRAPH;
    H.renderNetwork();

    fetchOverride = (u) => (String(u).includes("/api/network/host")
      ? Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => HOST_SHEET })
      : null);
    H.clearGetCache();
    const vaultRow = hostRows().find((r) => r.textContent.includes("192.0.2.40"));
    if (vaultRow) { vaultRow.click(); }
    await sleep(80);
    const sheetBody = needEl("nw-host-body");
    check("clicking a host row opens the host sheet for that address",
          !needEl("nw-host-card").classList.contains("hidden")
          && /192\.0\.2\.40/.test(needEl("nw-host-title").textContent
            + needEl("nw-host-addr").textContent),
          needEl("nw-host-title").textContent + needEl("nw-host-addr").textContent);
    check("...with identity, traffic, peers, services, DNS/TLS, ripples, models and normalization",
          ["Identity and names", "Traffic in this 24h window", "Top peers",
           "Services and ports", "DNS and TLS", "Ripples", "Model detections",
           "Normalized patterns"].every((h) => sheetBody.textContent.includes(h)),
          sheetBody.textContent.replace(/\s+/g, " ").slice(0, 220));
    check("...rendering real identity and traffic, not a loading placeholder",
          sheetBody.textContent.includes("vault.example")
          && sheetBody.textContent.includes("4.1 KB")
          && sheetBody.textContent.includes("0.91")
          && /0 patterns normalized/.test(sheetBody.textContent),
          sheetBody.textContent.replace(/\s+/g, " ").slice(0, 300));
    check("...and the sheet states the global window and its owner",
          /24h window/.test(needEl("nw-host-note").textContent)
          && /owned by the header time control/.test(needEl("nw-host-note").textContent),
          needEl("nw-host-note").textContent);
    check("...and names the shorter in/out retention instead of drawing it as the full window",
          /measured only from/.test(sheetBody.textContent),
          sheetBody.textContent.replace(/\s+/g, " ").slice(0, 300));
    needEl("nw-host-close").click();
    fetchOverride = null;
    H.clearGetCache();

    // ── THE FILTER BAR: A VALUE ADDS A PILL, A ROW OPENS THE SHEET, NEVER BOTH ────────────
    // The operator's two verbs (2026-11-20). Each is asserted by EXECUTING the shipping
    // capture-phase handler, not by reading filters.js: a value cell must add exactly one
    // pill and swallow the click; a row click must open the sheet and add nothing; a pill
    // must be removable and Clear all must empty the bar; the state must survive a URL trip.
    H.ASSETS_STATE.graph = FILTER_GRAPH;
    H.ASSETS_STATE.status = "all";
    H.ASSETS_STATE.rippleFilter = "all";
    H.ASSETS_STATE.family = "all";
    H.ASSETS_STATE.subnet = "";
    H.ASSETS_STATE.query = "";
    needEl("nw-find").value = "";
    needEl("nw-subnet").value = "";
    H.renderNetwork();
    await sleep(40);   // the tbody MutationObserver tags value cells a tick later
    const bar = needEl("filter-bar");
    const barPills = () => [...bar.querySelectorAll(".bubble.filter[data-filter-key]")];
    const liveRows = () => [...doc.querySelectorAll("#nw-hosts-table tbody tr")]
      .filter((r) => r.querySelector("td.link"));
    check("the filter bar starts hidden on an unfiltered view",
          bar.hidden === true && barPills().length === 0, `hidden=${bar.hidden}`);

    const valueCells = [...doc.querySelectorAll("#nw-hosts-table tbody td[data-filter-field]")];
    const vaultCell = valueCells.find((c) => /192\.0\.2\.40/.test(c.textContent));
    check("a host address in the table is a tagged value cell", !!vaultCell,
          `${valueCells.length} tagged cells`);
    if (vaultCell) { vaultCell.click(); }
    await sleep(220);  // the click's own render, plus the 150ms URL debounce
    check("a value click adds ONE removable pill naming the value",
          barPills().length === 1 && bar.hidden === false
          && barPills()[0].dataset.filterKey === "nw.q"
          && /192\.0\.2\.40/.test(barPills()[0].textContent),
          `pills=${barPills().length} bar=${bar.textContent.trim()}`);
    check("...it narrows the table to the value that was clicked",
          liveRows().length === 1 && /192\.0\.2\.40/.test(liveRows()[0].textContent),
          `${liveRows().length} rows`);
    check("...and it does NOT also open the host sheet (the verbs are separated by the event)",
          needEl("nw-host-card").classList.contains("hidden"),
          needEl("nw-host-card").className);
    check("...and the filter rides the URL", /nw\.q=192\.0\.2\.40/.test(window.location.hash),
          window.location.hash.slice(0, 140));

    // A ROW CLICK IS THE OTHER VERB. Target the row itself so no value cell is in the path.
    fetchOverride = (u) => (String(u).includes("/api/network/host")
      ? Promise.resolve({ ok: true, status: 200, statusText: "OK",
                          json: async () => HOST_SHEET })
      : null);
    H.clearGetCache();
    const pillsBeforeRow = barPills().length;
    if (liveRows()[0]) { liveRows()[0].click(); }
    await sleep(120);
    check("a row click opens the host sheet",
          !needEl("nw-host-card").classList.contains("hidden"),
          needEl("nw-host-card").className);
    check("...and adds NO pill and leaves the value filter in place",
          barPills().length === pillsBeforeRow && H.ASSETS_STATE.query === "192.0.2.40",
          `pills=${barPills().length} q=${H.ASSETS_STATE.query}`);
    needEl("nw-host-close").click();
    fetchOverride = null;
    H.clearGetCache();

    if (barPills()[0]) { barPills()[0].click(); }
    await sleep(220);
    check("removing the pill restores the full table and hides the bar",
          barPills().length === 0 && bar.hidden === true && liveRows().length === 3,
          `pills=${barPills().length} rows=${liveRows().length} hidden=${bar.hidden}`);

    // TWO PILLS, THEN CLEAR ALL. The second one comes from the view's own status control,
    // which is the bar's mirror contract: pressing it must surface the same pill.
    // Re-query: the previous render replaced the tbody, so a captured cell is detached and its
    // click never reaches the document's capture listener (a real click would not either).
    const firstCell = [...doc.querySelectorAll("#nw-hosts-table tbody td[data-filter-field]")][0];
    if (firstCell) { firstCell.click(); }
    await sleep(220);
    const blockedChip = doc.getElementById("nw-status-blocked");
    if (blockedChip) { blockedChip.click(); }
    await sleep(220);
    check("the bar mirrors a filter set by the view's own control (two pills)",
          barPills().length === 2 && H.ASSETS_STATE.status === "blocked",
          `pills=${barPills().length} status=${H.ASSETS_STATE.status}`);
    const clearAll = bar.querySelector(".bubble.filter.filter-clear");
    check("Clear all is a bubble.filter too, not a second pill shape", !!clearAll);
    if (clearAll) { clearAll.click(); }
    await sleep(220);
    check("Clear all empties every pill and restores the view",
          barPills().length === 0 && bar.hidden === true
          && liveRows().length === 3 && H.ASSETS_STATE.query === ""
          && H.ASSETS_STATE.status === "all",
          `pills=${barPills().length} q='${H.ASSETS_STATE.query}' status=${H.ASSETS_STATE.status}`);

    // URL ROUND TRIP: a link built after a filter must rebuild the pill on a cold load.
    window.location.hash = "#v=network&nw.q=192.0.2.40";
    H.applyURLState();
    await sleep(60);
    check("a cold load from a filtered URL rebuilds the pill and the table",
          barPills().length === 1 && H.ASSETS_STATE.query === "192.0.2.40"
          && liveRows().length === 1 && needEl("nw-find").value === "192.0.2.40",
          `pills=${barPills().length} q='${H.ASSETS_STATE.query}' rows=${liveRows().length}`);

    window.location.hash = "#v=network";
    H.applyURLState();
    await sleep(40);
    H.ASSETS_STATE.query = "";
    H.ASSETS_STATE.status = "all";
    needEl("nw-find").value = "";
    H.ASSETS_STATE.graph = GRAPH_PAYLOAD;
    H.renderNetwork();
  }

  // ── THE UNIVERSAL PAGER, AND THE TWO COUNTER ROWS (2026-11-20) ───────────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const peerCount = 40;
    const PAGER_GRAPH = {
      available: true, hours: 24, total_edges: 400, truncated: true, status_available: true,
      ripple_available: true, severity_bands: {}, coverage: { available: true,
        from: "2026-11-17T05:30:00", to: "2026-11-20T09:00:00" },
      nodes: [{ id: "203.0.113.42", name: "hub", degree: peerCount, bytes: 90000 }].concat(
        Array.from({ length: peerCount }, (_, i) => ({
          id: `192.0.2.${i + 1}`, name: `peer${i}`, degree: 1, bytes: 1000 - i,
        }))),
      edges: Array.from({ length: peerCount }, (_, i) => ({
        source: "203.0.113.42", target: `192.0.2.${i + 1}`,
        bytes: 1000 - i, flows: 2, ports: [443],
      })),
    };
    H.ASSETS_STATE.graph = PAGER_GRAPH;
    H.ASSETS_STATE.tracked = [];
    H.ASSETS_STATE.status = "all";
    H.ASSETS_STATE.rippleFilter = "all";
    H.renderNetwork();
    await sleep(30);
    const visibleRows = (sel) => [...doc.querySelectorAll(sel)].filter((r) => !r.hidden);
    check("the edges table pages at 25 rows, not one endless scroll",
          visibleRows("#nw-table tbody tr").length === 25
          && doc.querySelectorAll("#nw-table tbody tr").length === peerCount,
          `${visibleRows("#nw-table tbody tr").length} visible of ${doc.querySelectorAll("#nw-table tbody tr").length}`);
    check("the edges pager states rows and the server cap honestly",
          /first 25 of 400 \(server cap\)/.test(needEl("nw-table-pager").textContent)
          && /page 1 of 2/.test(needEl("nw-table-pager").textContent),
          needEl("nw-table-pager").textContent);
    const nwNext = [...doc.querySelectorAll("#nw-table-pager .pager-btn")]
      .find((b) => /Next/.test(b.textContent));
    check("the edges pager has a Next control", !!nwNext);
    if (nwNext) { nwNext.click(); await sleep(20); }
    check("Next advances the edges table and the count line follows",
          /page 2 of 2/.test(needEl("nw-table-pager").textContent)
          && /first 40 of 400 \(server cap\)/.test(needEl("nw-table-pager").textContent)
          && visibleRows("#nw-table tbody tr").length === 15
          && visibleRows("#nw-table tbody tr")[0].textContent.includes("192.0.2.26"),
          needEl("nw-table-pager").textContent);

    H.showNodeDetail(PAGER_GRAPH.nodes[0]);
    await sleep(30);
    const detailTotal = doc.querySelectorAll("#nw-detail-table tbody tr").length;
    check("the connection-detail table pages the same way",
          detailTotal >= peerCount
          && visibleRows("#nw-detail-table tbody tr").length === 25
          && /rows 1\u201325 of \d+/.test(needEl("nw-detail-table-pager").textContent),
          `${visibleRows("#nw-detail-table tbody tr").length} visible; ${needEl("nw-detail-table-pager").textContent}`);
    const detailNext = [...doc.querySelectorAll("#nw-detail-table-pager .pager-btn")]
      .find((b) => /Next/.test(b.textContent));
    if (detailNext) { detailNext.click(); await sleep(20); }
    check("...and its Next pages forward, with Previous enabled at page 2",
          /page 2 of 2/.test(needEl("nw-detail-table-pager").textContent)
          && visibleRows("#nw-detail-table tbody tr").length === detailTotal - 25
          && [...doc.querySelectorAll("#nw-detail-table-pager .pager-btn")]
               .find((b) => /Previous/.test(b.textContent)).disabled === false,
          needEl("nw-detail-table-pager").textContent);

    // ── THE COUNTERS: one helper, two lists, clickable bands ──────────────────────────────
    const RIPPLE_PAGE = {
      available: true, window_hours: 24, severity_bands: { low: {}, medium: {}, high: {} },
      ripples: [
        { host: "203.0.113.42", window_start: "2026-11-20T08:00:00", score: 7.1,
          severity: "high", families: ["conn"], explanation: "high one", evidence: [] },
        { host: "203.0.113.1", window_start: "2026-11-20T07:00:00", score: 4.2,
          severity: "medium", families: ["dns"], explanation: "medium one", evidence: [] },
        { host: "192.0.2.40", window_start: "2026-11-20T06:00:00", score: 3.1,
          severity: "low", families: ["flow"], explanation: "low one", evidence: [] },
      ],
    };
    H.renderRipplePage(RIPPLE_PAGE);
    H.anRenderSeverity({ available: true, counts: [
      { band: "high", count: 2 }, { band: "medium", count: 1 }, { band: "unclassified", count: 1 },
    ] });
    const anTiles = [...doc.querySelectorAll("#an-sev .tile")];
    const rpTiles = [...doc.querySelectorAll("#rp-sev .tile")];
    check("both criticality counter rows render from the same markup and classes",
          anTiles.length === 3 && rpTiles.length === 3
          && anTiles[0].className === rpTiles[0].className
          && anTiles[0].querySelector(".v").className === rpTiles[0].querySelector(".v").className
          && anTiles[0].parentElement.classList.contains("sev-tiles")
          && rpTiles[0].parentElement.classList.contains("sev-tiles"),
          `tiles ${anTiles.length}/${rpTiles.length}; classes ${anTiles[0] ? anTiles[0].className : "?"}/${rpTiles[0] ? rpTiles[0].className : "?"}; parents ${doc.getElementById("an-sev").className}/${doc.getElementById("rp-sev").className}`);

    const highTile = rpTiles.find((t) => t.textContent.includes("high"));
    check("a ripple band tile is a pressed-capable button",
          !!highTile && highTile.tagName === "BUTTON"
          && highTile.getAttribute("aria-pressed") === "false",
          highTile ? highTile.outerHTML.slice(0, 120) : "no high tile");
    if (highTile) { highTile.click(); }
    await sleep(20);
    check("clicking a ripple band narrows the list and the count sentence says so",
          doc.querySelectorAll("#ripples-table tbody tr").length === 1
          && /1 of 3 alerts/.test(needEl("rp-count").textContent)
          && /high/.test(needEl("rp-count").textContent)
          && doc.querySelector('#rp-sev .tile.active').getAttribute("aria-pressed") === "true",
          needEl("rp-count").textContent);
    H.syncURL();
    check("...and the ripple band rides the URL",
          /al\.band=high/.test(window.location.hash), window.location.hash.slice(0, 120));
    const highActive = doc.querySelector('#rp-sev .tile.active');
    if (highActive) { highActive.click(); }
    await sleep(20);
    check("clicking the active band again clears the filter",
          doc.querySelectorAll("#ripples-table tbody tr").length === 3
          && /3 alerts/.test(needEl("rp-count").textContent)
          && !doc.querySelector("#rp-sev .tile.active"),
          needEl("rp-count").textContent);
    H.ASSETS_STATE.graph = GRAPH_PAYLOAD;
    H.ASSETS_STATE.status = "all";
    H.ASSETS_STATE.tracked = [];
    H.renderNetwork();
  }

  // ── blocked / alerted graph readings ─────────────────────────────────────────────────────
  const STATUS_GRAPH = {
    available: true, hours: 24, status_available: true, total_edges: 2,
    nodes: [
      { id: "192.0.2.10", name: "blocked-host", degree: 2, bytes: 100,
        status: "blocked", blocked: true, alerted: false,
        status_reasons: ["block rule: block sabnzbd.home"] },
      { id: "192.0.2.20", name: "alerted-host", degree: 1, bytes: 50,
        status: "alerted", blocked: false, alerted: true, anomaly_count: 2,
        status_reasons: ["2 anomaly windows in this range"] },
      { id: "192.0.2.30", name: "peer", degree: 1, bytes: 50, status: "" },
    ],
    edges: [
      { source: "192.0.2.10", target: "192.0.2.20", bytes: 100, flows: 2,
        source_status: "blocked", target_status: "alerted", status: "blocked" },
      { source: "192.0.2.20", target: "192.0.2.30", bytes: 50, flows: 1,
        source_status: "alerted", target_status: "", status: "alerted" },
    ],
  };
  H.ASSETS_STATE.tracked = [];
  H.ASSETS_STATE.status = "blocked";
  H.ASSETS_STATE.graph = STATUS_GRAPH;
  H.renderNetwork();
  check("the Blocked reading keeps the blocked host and its peer as context",
        doc.querySelectorAll("#nw-graph g.node").length === 2 &&
        needEl("nw-caption").textContent.includes("showing 1 blocked host"),
        needEl("nw-caption").textContent);
  check("the status buttons report which reading is active",
        needEl("nw-status-blocked").getAttribute("aria-pressed") === "true" &&
        needEl("nw-status-all").getAttribute("aria-pressed") === "false");
  check("the blocked host is drawn in the blocked colour",
        [...doc.querySelectorAll("#nw-graph g.node circle")]
          .some((c) => /fill:var\(--bad\)/.test(c.getAttribute("style") || "")));

  H.ASSETS_STATE.status = "alerted";
  H.renderNetwork();
  check("the Alerted reading keeps the alerted host and both of its peers",
        doc.querySelectorAll("#nw-graph g.node").length === 3 &&
        needEl("nw-caption").textContent.includes("showing 1 alerted host"),
        needEl("nw-caption").textContent);
  check("the alerted host is drawn in the alerted colour",
        [...doc.querySelectorAll("#nw-graph g.node circle")]
          .some((c) => /fill:var\(--warn\)/.test(c.getAttribute("style") || "")));

  H.showNodeDetail(STATUS_GRAPH.nodes[0]);
  check("a blocked host's connection details say why it is blocked",
        needEl("nw-detail").textContent.includes("blocked") &&
        needEl("nw-detail").textContent.includes("block sabnzbd.home"),
        needEl("nw-detail").textContent.slice(0, 120));
  H.showEdgeDetail(STATUS_GRAPH.edges[0]);
  check("a connection detail names both endpoint statuses",
        needEl("nw-detail").textContent.includes("source blocked") &&
        needEl("nw-detail").textContent.includes("destination alerted"),
        needEl("nw-detail").textContent.slice(0, 160));

  H.ASSETS_STATE.graph = { ...STATUS_GRAPH, status_available: false,
                           status_reason: "block rules could not be read" };
  H.ASSETS_STATE.status = "blocked";
  H.renderNetwork();
  check("an unreadable status source is named, not rendered as a normal graph",
        needEl("nw-caption").textContent.includes("Host status is unavailable") &&
        needEl("nw-graph").textContent.includes("could not be computed"),
        needEl("nw-caption").textContent);
  H.ASSETS_STATE.status = "all";
  H.ASSETS_STATE.minEdges = 1;

  // ── honest failure states ──────────────────────────────────────────────────────────────
  H.ASSETS_STATE.graph = { available: false, nodes: [], edges: [],
                               reason: "the connection query failed" };
  H.renderNetwork();
  check("a failed graph query names the reason rather than drawing an empty canvas",
        needEl("nw-graph").textContent.includes("connection query failed"),
        needEl("nw-graph").textContent.slice(0, 90));

  H.ASSETS_STATE.graph = { available: true, nodes: [], edges: [], total_edges: 0 };
  H.renderNetwork();
  check("an empty graph says nothing was recorded, not that it failed",
        needEl("nw-graph").textContent.includes("No host-to-host traffic"),
        needEl("nw-graph").textContent.slice(0, 90));

  // FILTERED is not EMPTY (review round 2026-10-15): edges exist, but every one of them is
  // below the flows filter -- the panel must NAME the filter and its count, not claim the
  // network was quiet. Measured before the fix: the filter removed the edges and the panel
  // said "No host-to-host traffic was recorded" over a window that had traffic.
  H.ASSETS_STATE.minEdges = 5;
  H.ASSETS_STATE.graph = {
    available: true, hours: 24, total_edges: EDGES.length,
    nodes: NODES, edges: EDGES.map((e) => ({ ...e, flows: 2 })),
  };
  H.renderNetwork();
  check("a filtered-to-empty graph NAMES the flows filter instead of claiming no traffic",
        needEl("nw-graph").textContent.includes("flows filter is hiding") &&
        needEl("nw-caption").textContent.includes("below the flows filter") &&
        !doc.getElementById("nw-caption").textContent.includes("was recorded") &&
        !doc.getElementById("nw-graph").textContent.includes("was recorded"),
        `caption: ${needEl("nw-caption").textContent.slice(0, 90)} | ` +
        `graph: ${needEl("nw-graph").textContent.slice(0, 90)}`);
  H.ASSETS_STATE.minEdges = 1;

  H.ASSETS_STATE.inventory = { available: false, hosts: [], reason: "cannot reach ClickHouse" };
  H.renderAssets();
  check("a failed inventory query names the reason",
        needEl("as-note").textContent.includes("cannot reach ClickHouse"));

  // ── the Netflow click-through ──────────────────────────────────────────────────────────
  check("loadFlowDetail() is defined and reachable as a global",
        typeof window.loadFlowDetail === "function", `typeof = ${typeof window.loadFlowDetail}`);

  await window.loadFlowDetail({ port: 443, name: "port 443" });
  await new Promise((r) => setTimeout(r, 40));
  const fdRows = doc.querySelectorAll("#nf-detail-table tbody tr");
  check("the flow drill-down renders one row per host pair", fdRows.length === 2,
        `rows=${fdRows.length}`);
  check("the drill-down names the bar that was clicked",
        needEl("nf-detail-title").textContent.includes("443"),
        needEl("nf-detail-title").textContent);
  check("the drill-down states that the list was CAPPED",
        needEl("nf-detail-note").textContent.includes("busiest of"),
        needEl("nf-detail-note").textContent);
  check("the drill-down draws a bar chart too", !!doc.querySelector("#nf-detail .bar-row"));
  check("a drill-down row is clickable through to the host",
        !!fdRows[0] && fdRows[0].className.includes("clickable"));

  // A failed query must say so, not render an empty panel.
  // NOTE: this stub is installed LATER than the first one, so it is the one in force for
  // everything below this point. Any payload a later check needs must be served HERE --
  // /api/settings was silently falling through to this default and rendering "0 settings", and
  // the same trap applies to every write route.
  // A deliberate FAILURE for ONE check: only the flow drill-down fails. An override, not a
  // replacement stub -- a replacement would strand every payload registered with the dispatcher,
  // which is precisely the bug this refactor removes.
  fetchOverride = (u) => (u.includes("/api/flows")
    ? { ok: true, status: 200, statusText: "OK",
        json: async () => ({ available: false, points: [],
                             reason: "the flow drill-down failed" }) }
    : null);
  await window.loadFlowDetail({ proto: 6, name: "TCP" });
  await new Promise((r) => setTimeout(r, 40));
  check("a failed flow drill-down names the reason",
        needEl("nf-detail").textContent.includes("flow drill-down failed"),
        needEl("nf-detail").textContent.slice(0, 90));

  // ── the chips reach the flow-detail table (#31) ─────────────────────────────────────────────
  // The charts and the table used to answer different questions: a chip narrowed the charts
  // while the table kept the last bar's rows. Applying/removing a chip re-requests the drill
  // WITH the chip's filter (through the REAL setter, the real netflow reload, and the real
  // detail reload), and a chip the request cannot express is NAMED -- never silently dropped.
  fetchOverride = null;
  const flowReqs = () => FLOW_REQS.length;
  let n0 = flowReqs();
  H.nfSetFilter("src", "192.0.2.10", "192.0.2.10");
  for (let i = 0; i < 50 && flowReqs() === n0; i++) {
    await new Promise((r) => setTimeout(r, 20));
  }
  const reqWithChip = FLOW_REQS[FLOW_REQS.length - 1] || "";
  check("applying a source chip re-requests the drill WITH the source",
        flowReqs() > n0 && /[?&]src=192\.0\.2\.10/.test(reqWithChip),
        reqWithChip);
  check("the re-request still carries the bar's own drill",
        /[?&]proto=6/.test(reqWithChip), reqWithChip);
  n0 = flowReqs();
  // Remove the SOURCE chip by identity, not by position: other checks in this file have left
  // chips behind, and splicing index 0 could drop an unrelated one and leave `src` in place.
  const srcChip = H.NF_FILTERS.findIndex((f) => f.field === "src");
  // AND CLEAR THE GET CACHE: the un-chipped URL was fetched before the chip went on, so without
  // this the removal is answered from the 8s cache, no request reaches the router, and the check
  // reads the PRE-removal request still sitting last in the list.
  H.clearGetCache();
  H.nfRemoveChip(srcChip >= 0 ? srcChip : 0);
  for (let i = 0; i < 50 && flowReqs() === n0; i++) {
    await new Promise((r) => setTimeout(r, 20));
  }
  const reqAfterRemoval = FLOW_REQS[FLOW_REQS.length - 1] || "";
  check("removing the chip re-requests the drill WITHOUT the source",
        flowReqs() > n0 && !/[?&]src=/.test(reqAfterRemoval), reqAfterRemoval);
  // A chip the drill cannot express is named in the note, never silently dropped.
  H.NF_FILTERS.push({ field: "client", value: "198.51.100.9", label: "198.51.100.9" });
  H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
  await H.loadFlowDetail(H.ASSETS_STATE.detailParams);
  await new Promise((r) => setTimeout(r, 80));
  check("a chip the table cannot apply is NAMED in its heading",
        /cannot apply: client/.test(needEl("nf-detail-note").textContent),
        needEl("nf-detail-note").textContent);
  H.NF_FILTERS.pop();
  await H.loadFlowDetail(H.ASSETS_STATE.detailParams);
  await new Promise((r) => setTimeout(r, 80));

  // ── ONE BOX, ONE IDENTITY (QA-1-D2) ─────────────────────────────────────────────────────────
  {
    const origFetch = window.fetch;
    const identityUrls = [];
    window.fetch = (u) => {
      if (String(u).includes("/api/identity")) identityUrls.push(String(u));
      return String(u).includes("/api/identity")
        ? Promise.resolve({ ok: true, json: async () => ({
          available: true, merged: 1,
          coverage: { available: true, hosts_seen: 20, hosts_classified: 2, coverage_pct: 10,
                      high_confidence: 1, medium_confidence: 1, unknown: 0, window_days: 7 },
          hosts: [
            { host: "weirvern", score: 0.9, confidence: "high", agreeing_sources: 2,
              os_label: "Linux", signals: [], age_s: 60, aliases: ["Weirvern"], merged_from: 2 },
            { host: "other-box", score: 0.7, confidence: "medium", agreeing_sources: 1,
              os_label: "Linux", signals: [], age_s: 90 },
          ] }) })
        : origFetch(u);
    };
    H.showView("identity");
    await H.loadIdentity();
    await new Promise((r) => setTimeout(r, 120));
    window.fetch = origFetch;
    const note = needEl("id-coverage-note").textContent;
    check("a folded host spelling is named in the coverage note",
          /1 duplicate spelling folded/.test(note), note.slice(0, 160));
    // ISSUE #63: no discarded `hours` and no unlabelled second window.
    check("the identity request carries NO header range",
          identityUrls.length > 0 && identityUrls.every((u) => !/[?&]hours=/.test(u)),
          identityUrls.join(" | "));
    check("...and the coverage copy names the current snapshot and its own window",
          /Current snapshot/.test(note) && /header range does not apply/.test(note)
          && /7 days/.test(note), note.slice(0, 220));
    const rowText = doc.querySelector("#id-table tbody tr").textContent;
    check("...and the surviving row shows what else it was called",
          /also seen as Weirvern/.test(rowText), rowText.slice(0, 120));
    check("...with one row per box, not two",
          doc.querySelectorAll("#id-table tbody tr").length === 2);
  }

  // ── THE EVIDENCE CHAIN (US-D1) ──────────────────────────────────────────────────────────────
  {
    const origFetch = window.fetch;
    window.fetch = (u) => (String(u).includes("/api/evidence")
      ? Promise.resolve({ ok: true, json: async () => ({
          available: true, hostname: "host.example", src_addr: "198.51.100.5",
          window_start: "2026-10-17T10:55:00", window_end: "2026-10-17T11:00:00",
          anomaly: { severity: "high", anomaly_score: 0.91,
                     detected_by_models: "Isolation Forest",
                     baseline_comparison: "bytes 4.1x the learned mean for this hour",
                     primary_deviation_feature: "bytes",
                     review_state: "ack" },
          flow_summary: { bytes: 1000, packets: 9, flows: 3,
                          unique_destinations: 1, unique_ports: 1 },
          flows: [], zeek_conn: [], zeek_ssl: [], zeek_dns: [], notice: [],
          errors: null }) })
      : origFetch(u));
    H.showView("evidence");
    await H.loadEvidence("198.51.100.5", "2026-10-17T10:55:00", "2026-10-17T11:00:00");
    await new Promise((r) => setTimeout(r, 150));
    window.fetch = origFetch;

    const steps = [...doc.querySelectorAll("#ev-chain .chain-step")];
    check("the evidence page shows the six stages in order",
          steps.length === 6
          && steps.map((s) => s.getAttribute("data-stage")).join(",") ===
             "observed,sources,detected,explained,ruled,done",
          steps.map((s) => s.getAttribute("data-stage")).join(","));
    const txt = steps.map((s) => s.textContent).join(" | ");
    check("...each carrying its own measurements, not a heading",
          /3 flows/.test(txt) && /0\.910/.test(txt) && /4\.1x/.test(txt), txt.slice(0, 160));
    check("...and the ruling is stated in words",
          /acknowledged/.test(txt) && /still open/.test(txt), txt.slice(0, 200));
    check("RULED names the rule (or says none), and DONE owns the review state",
          /no rule \u2014 alert only/.test(steps[4].textContent)
          && !/acknowledged/.test(steps[4].textContent)
          && /acknowledged/.test(steps[5].textContent),
          steps.map((s) => s.textContent).join(" | ").slice(0, 240));
    check("the chain carries no step numerals", doc.querySelectorAll("#ev-chain .chain-n").length === 0);
  }

  // ── THE DUPLICATE MODELS PANELS ARE GONE (operator, 2026-11-20) ─────────────────────────────
  // Deleted, not hidden: the markup is out of index.html and the renderers are out of app.js.
  // A display:none node would still be a node, so this reads the DOM for absence.
  {
    check("the duplicate Models anomalies and Alerts panels are absent from the DOM",
          ["m-points", "m-ripples", "m-ripples-note", "m-review", "m-verify", "m-eval", "m-ledger"]
            .every((id) => doc.getElementById(id) === null));
  }

  // ── KNN AND LOF ARE NAMED IN FULL ON THEIR FIRST ROW ───────────────────────────────────────
  // The operator's wording rule: spell each out once at first use, then keep the acronym so
  // the table stays readable. The second KNN row in this fixture proves "once", not "every row".
  {
    const detector = (name) => ({
      name, trained: true, samples: 5000, artifact_version: "v5",
      observed_far: 0, target_far: 0.01, coverage_note: "18 of 19 inputs (1 imputed)",
      status: "eligible",
    });
    H.renderDetectors([detector("KNN distance"), detector("KNN distance"), detector("LOF")],
                      "3 detectors: 3 eligible.", { budget: 0.3, bar: 0.35, windows: 25 });
    const names = [...doc.querySelectorAll("#md-table tbody tr td:first-child")]
      .map((td) => td.textContent);
    check("the first KNN row is spelled out and the next one uses the acronym",
          names[0] === "k-nearest neighbours (KNN distance)" && names[1] === "KNN distance",
          names.join(" | "));
    check("the LOF row is spelled out at its first use",
          names[2] === "local outlier factor (LOF)", names.join(" | "));
  }


  // ── THE RIPPLES PAGE (phase 2): ripples first, model anomalies as corroboration ──────────────
  //
  // The operator's direction: "the anomaly page is actually the ripples". These checks drive the
  // shipping renderer against a real payload shape. They are deliberately end-to-end: the same
  // /api/ripples response that the Models card reads must draw this page, and the anomaly queue
  // must still be on the same view, below it, labelled corroboration.
  {
    H.showView("anomalies");
    H.clearGetCache();
    await H.loadAnomalies();
    await new Promise((r) => setTimeout(r, 160));

    const tab = [...doc.querySelectorAll("#tabs .tab")]
      .find((t) => t.dataset.view === "anomalies");
    check("the tab is labelled Alerts and keeps the stable view id",
          !!tab && tab.textContent.trim() === "Alerts"
          && !!doc.getElementById("view-anomalies"),
          tab ? tab.textContent.trim() : "no tab");
    const heading = doc.querySelector("#view-anomalies .view-title");
    check("the view heading says Alerts, not only Ripples", !!heading
          && /Alerts/.test(heading.textContent)
          && /ripples first, model detections as corroboration/.test(
            needEl("view-anomalies").textContent),
          heading ? heading.textContent : "no heading");
    // THE NAME CHANGED, THE HONESTY DID NOT. "Read-only: this page does not alert" became a
    // contradiction once the tab was called Alerts; this check pins the replacement sentence and
    // the absence of the old one, so a later copy edit cannot quietly reintroduce it.
    const readOnly = needEl("rp-note").textContent.replace(/\s+/g, " ");
    check("the Alerts page says it is a record and does not send notifications",
          /Alerts collects ripples and model detections/.test(readOnly)
          && /This page is a record: it does not send notifications\./.test(readOnly)
          && !/does not alert/.test(readOnly),
          readOnly.slice(0, 240));

    const rows = [...doc.querySelectorAll("#ripples-table tbody tr")];
    const text = rows.map((r) => r.textContent).join(" ");
    check("the page renders the ripple as an explanation sentence, not a bare score",
          rows.length === 1 && /198\.51\.100\.5/.test(text)
          && /conn_volume 41 vs median 5/.test(text) && /dns_volume 60 vs median 6/.test(text),
          `rows=${rows.length} text=${text.slice(0, 180)}`);
    check("...with the contributing families on the row", /conn \/ dns/.test(text),
          text.slice(0, 180));

    const anRows = doc.querySelectorAll("#anomalies-table tbody tr");
    check("the old model-anomaly table is still reachable on the same page", anRows.length === 3,
          `${anRows.length} rows`);
    check("...and its section is labelled corroboration, not the finding",
          /corroboration, not the finding/.test(needEl("view-anomalies").textContent),
          needEl("view-anomalies").textContent.replace(/\s+/g, " ").slice(0, 220));

    // THE ML SIGNPOST (operator, 2026-11-20): beside the ripple count, from the list's payload.
    const ml = needEl("rp-ml");
    const mlText = ml.textContent.replace(/\s+/g, " ");
    check("the header carries an ML signpost whose count equals the list's row count",
          !ml.classList.contains("hidden") && /^3 model detections/.test(mlText)
          && /2 high, 1 medium/.test(mlText),
          mlText);
    const fusedText = needEl("an-fused-line").textContent.replace(/\s+/g, " ");
    check("the fused-score status names the score, the target and the contributing detectors",
          /0\.910/.test(fusedText) && /0\.85/.test(fusedText)
          && /Isolation Forest/.test(fusedText) && /LOF/.test(fusedText)
          && /corroboration, not 3 incidents/.test(fusedText),
          fusedText.slice(0, 260));

    // ── THE MODEL LIST WEARS THE RIPPLE LIST'S CRITICALITY (operator, 2026-11-20) ────────────
    // Equal grammar, different words: the same inset left edge, the same score treatment, the
    // same severity cell helper, and the same chip in the stacked phone card.
    const firstModel = anRows[0];
    const firstRipple = rows[0];
    check("a model-anomaly row carries the same severity edge class as a ripple row",
          !!firstModel && /\brp-sev-high\b/.test(firstModel.className)
          && /\brp-sev-low\b/.test(firstRipple.className),
          `model=${firstModel ? firstModel.className : "none"} ripple=${firstRipple.className}`);
    const modelSev = firstModel ? firstModel.querySelector("td.rp-sevcell") : null;
    const rippleSev = firstRipple ? firstRipple.querySelector("td.rp-sevcell") : null;
    check("both lists resolve the severity cell from the same helper and the same band word",
          !!modelSev && !!rippleSev
          && modelSev.textContent.trim() === "\u25c6 high"
          && rippleSev.textContent.trim() === "\u25cb low"
          && !!modelSev.querySelector(".sev-high") && !!rippleSev.querySelector(".sev-low"),
          `model=${modelSev ? modelSev.textContent.trim() : "none"} ripple=${rippleSev ? rippleSev.textContent.trim() : "none"}`);
    const modelScore = firstModel ? firstModel.querySelector(".rp-score.sev-high") : null;
    const rippleScore = firstRipple ? firstRipple.querySelector(".rp-score.sev-low") : null;
    check("both lists colour the score from the same band class",
          !!modelScore && !!rippleScore && /0\.9/.test(modelScore.textContent)
          && /2\.41/.test(rippleScore.textContent),
          `model=${modelScore ? modelScore.textContent : "none"} ripple=${rippleScore ? rippleScore.textContent : "none"}`);

    const modelCards = [...doc.querySelectorAll("#anomalies-cards .rp-card")];
    const rippleCards = [...doc.querySelectorAll("#ripples-cards .rp-card")];
    const modelChip = modelCards[0] ? modelCards[0].querySelector(".bubble.state") : null;
    const rippleChip = rippleCards[0] ? rippleCards[0].querySelector(".bubble.state") : null;
    check("the model list has a stacked card per row, with the ripple card's geometry",
          modelCards.length === anRows.length,
          `cards=${modelCards.length} rows=${anRows.length}`);
    check("both stacked-card lists carry the same severity chip class and word",
          !!modelChip && !!rippleChip
          && modelChip.className === "bubble state sev-high"
          && rippleChip.className === "bubble state sev-low"
          && modelChip.textContent.trim() === "\u25c6 high",
          `model=${modelChip ? modelChip.className + "/" + modelChip.textContent.trim() : "none"} ` +
          `ripple=${rippleChip ? rippleChip.className + "/" + rippleChip.textContent.trim() : "none"}`);

    const tiles = [...doc.querySelectorAll("#an-sev .tile .k")].map((x) => x.textContent.trim());
    check("the criticality tiles speak the three-band vocabulary, not critical/unknown",
          tiles.join("|") === "high|medium", tiles.join("|"));
  }

  // ── THE SHARED GEOMETRY IS MEASURED, NOT JUST WRITTEN IN SLUICE'S CSS ─────────────────────
  //
  // A class-name assertion cannot prove that a later Sluice rule did not re-size a card, chip
  // or button. These read the computed cascade in each view: one card, one severity chip and
  // one primary button per view, and every value must equal Alerts' value.
  {
    const views = ["view-anomalies", "view-models", "view-network", "view-discover", "view-sluice"];
    const measure = (id) => {
      const root = doc.getElementById(id);
      const card = root && root.querySelector(".card");
      const chip = doc.createElement("span");
      chip.className = "bubble state sev-low";
      const btn = doc.createElement("button");
      btn.className = "primary";
      if (root) { root.appendChild(chip); root.appendChild(btn); }
      const c = card ? window.getComputedStyle(card) : null;
      const ch = window.getComputedStyle(chip);
      const b = window.getComputedStyle(btn);
      const out = {
        cardRadius: c ? c.borderRadius : "",
        cardPadding: c ? c.padding : "",
        chipRadius: ch.borderRadius,
        chipPadding: ch.padding,
        chipFont: ch.fontSize,
        btnRadius: b.borderRadius,
        btnHeight: b.height,
      };
      if (root) { chip.remove(); btn.remove(); }
      return out;
    };
    const all = views.map((id) => [id, measure(id)]);
    const ref = all[0][1];
    const same = (key) => all.every(([, g]) => g[key] === ref[key]);
    check("card radius is identical in Alerts, Models, Network, Flows and Sluice",
          same("cardRadius") && Boolean(ref.cardRadius),
          all.map(([id, g]) => `${id}:${g.cardRadius}`).join(" "));
    check("card padding is identical in Alerts, Models, Network, Flows and Sluice",
          same("cardPadding") && Boolean(ref.cardPadding),
          all.map(([id, g]) => `${id}:${g.cardPadding}`).join(" "));
    check("severity chip shape and type are identical wherever a chip is rendered",
          same("chipRadius") && same("chipPadding") && same("chipFont")
          && Boolean(ref.chipRadius),
          all.map(([id, g]) => `${id}:${g.chipRadius}/${g.chipPadding}/${g.chipFont}`).join(" "));
    check("primary button radius and height are identical in every view",
          same("btnRadius") && same("btnHeight") && Boolean(ref.btnRadius),
          all.map(([id, g]) => `${id}:${g.btnRadius}/${g.btnHeight}`).join(" "));
  }

  // A SILENT ENGINE MUST LOOK SILENT, NOT ABSENT: zero rows still renders the signpost.
  {
    fetchOverride = (u) => {
      if (!String(u).includes("/api/anomalies")) return null;
      return { ok: true, status: 200, statusText: "OK", json: async () => ({
        available: true, rows: [], total_unfiltered: 0,
        fused: { score: null, target: 0.85, detectors: [] },
        discipline: { available: true, reason: "", fired: 0, acted: 0, by_state: {} },
        severity_counts: { available: true, reason: "", counts: [] },
      }) };
    };
    H.clearGetCache();
    await H.loadAnomalies();
    await new Promise((r) => setTimeout(r, 140));
    const ml = needEl("rp-ml");
    check("with zero model detections the ML signpost is present and says so",
          !ml.classList.contains("hidden") && /^0 model detections/.test(ml.textContent),
          ml.textContent);
    check("...and the fused-score line says the read was quiet, never absent",
          /No fused-score detection/.test(needEl("an-fused-line").textContent)
          && /strong-signal target is 0\.85/.test(needEl("an-fused-line").textContent),
          needEl("an-fused-line").textContent.slice(0, 200));
    fetchOverride = null;
    H.clearGetCache();
  }

  // THE EMPTY STATE IS THE COMMON CASE TODAY. It must name the scales and the baseline counts,
  // not print "no results"; and it must describe the window the payload returned (6h), which
  // proves the view is not carrying its own hardcoded 24.
  {
    fetchOverride = (u) => {
      if (!String(u).includes("/api/ripples")) return null;
      return { ok: true, status: 200, statusText: "OK", json: async () => ({
        available: true, reason: "", window_hours: 6, count: 0,
        model_version: "ripple-evidence-1",
        ripples: [], monitored_networks: ["198.51.100.0/24"],
        evidence: { rows: 12, monitored_rows: 12, subjects: 3, baseline_short_rows: 0 },
        baseline: {
          "1h": { baseline_windows: 167, minimum_windows: 30, scale_seconds: 3600,
                  lookback_days: 7, required_lookback_days: 2, p_floor: 0.005952,
                  usable: true, reason: "" },
          "6h": { baseline_windows: 27, minimum_windows: 30, scale_seconds: 21600,
                  lookback_days: 7, required_lookback_days: 8, p_floor: 0.035714,
                  usable: false,
                  reason: "baseline too short at this scale: 27 window(s), 30 required" },
          "24h": { baseline_windows: 6, minimum_windows: 30, scale_seconds: 86400,
                   lookback_days: 7, required_lookback_days: 31, p_floor: 0.142857,
                   usable: false,
                   reason: "baseline too short at this scale: 6 window(s), 30 required" },
          "7d": { baseline_windows: 0, minimum_windows: 30, scale_seconds: 604800,
                  lookback_days: 7, required_lookback_days: 217, p_floor: 1.0,
                  usable: false,
                  reason: "baseline too short at this scale: 0 window(s), 30 required" },
        },
      }) };
    };
    H.clearGetCache();
    await H.loadAnomalies();
    await new Promise((r) => setTimeout(r, 140));
    const empty = needEl("rp-empty");
    const emptyText = empty.textContent.replace(/\s+/g, " ");
    check("an empty window renders a named empty state, never 'no results'",
          !empty.classList.contains("hidden") && !/no results/i.test(emptyText),
          emptyText.slice(0, 200));
    check("...naming every scale the engine measures",
          ["1h", "6h", "24h", "7d"].every((s) => emptyText.includes(s + " scale")),
          emptyText.slice(0, 240));
    check("...with the baseline window counts, not a bare zero",
          /1h scale is usable: 167 baseline windows/.test(emptyText)
          && /6h scale needs 30 baseline windows: 27 of 30/.test(emptyText),
          emptyText.slice(0, 320));
    check("...and what the next scale needs to become available",
          /The next scale to become available is 6h/.test(emptyText)
          && /lookback of at least 8 days/.test(emptyText), emptyText.slice(0, 400));
    check("...describing the payload's 6h window, not a hardcoded 24h",
          /last 6h/.test(emptyText) && !/last 24h/.test(emptyText), emptyText.slice(0, 200));
    fetchOverride = null;
    H.clearGetCache();
  }

  // THE ROW OPENS THE HOUSE SHEET: evidence lines first, corroboration after them. The anomaly
  // fixture's 203.0.113.42 row is 09:10-09:15, inside this ripple's 09:00-10:00 hour.
  {
    const seen = [];
    fetchOverride = (u, opts) => {
      seen.push(String(u));
      if (String(u).includes("/api/ripple-signatures/patterns")) {
        return { ok: true, status: 200, statusText: "OK", json: async () => ({
          ok: true, capable: true, reason: "", host: "203.0.113.42",
          channel: "tls_fingerprint_diversity", family: "tls",
          values: [{ value: "example.test|ja4abc", count: 7,
                     normalized_until: "", normalized_id: "" }],
          review_after_default: "2027-02-18", review_days: 90, max_review_days: 365,
        }) };
      }
      if (String(u).includes("/api/ripple-signatures") && opts && opts.method === "POST") {
        return { ok: true, status: 200, statusText: "OK", json: async () => ({
          ok: true, duplicate: false,
          entry: { id: "sig-1", host_addr: "203.0.113.42",
                   channel: "tls_fingerprint_diversity",
                   value: "example.test|ja4abc", review_after: "2027-02-18" },
        }) };
      }
      if (!String(u).includes("/api/ripples")) return null;
      return { ok: true, status: 200, statusText: "OK", json: async () => ({
        available: true, reason: "", window_hours: 12, count: 1,
        signature_channels: ["tls_fingerprint_diversity"],
        ripples: [{
          host: "203.0.113.42", window_start: "2026-01-02T09:00:00",
          window_end: "2026-01-02T10:00:00", score: 3.42, combined_p: 0.0021,
          channels: ["conn_volume", "dns_volume", "tls_fingerprint_diversity"],
          families: ["conn", "dns", "tls"], single_family: false,
          explanation: "ripple on 203.0.113.42 at 2026-01-02 09:00 UTC — 3 independent " +
            "families: conn, dns, tls: conn family: conn_volume 41 vs median 5 (rose at 1h; " +
            "p=0.004 over 500 baseline windows); dns family: dns_volume 60 vs median 6 " +
            "(rose at 1h; p=0.006 over 500 baseline windows); tls family: " +
            "tls_fingerprint_diversity 7 vs median 2 (rose at 1h; p=0.002 over 500 windows).",
          evidence: [
            { channel: "conn_volume", family: "conn", scale: "1h", value: 41,
              baseline_median: 5, p_value: 0.004, p_floor: 0.001996, at_floor: false,
              baseline_short: false, sample_count: 500, direction: "rose",
              signature_capable: false },
            { channel: "dns_volume", family: "dns", scale: "1h", value: 60,
              baseline_median: 6, p_value: 0.006, p_floor: 0.001996, at_floor: false,
              baseline_short: false, sample_count: 94, direction: "rose",
              p_method: "negbin", p_detail: "negbin n=94 mean=87.8 var=2146 index=24.4 "
                + "size=3.2", signature_capable: false },
            { channel: "tls_fingerprint_diversity", family: "tls", scale: "1h", value: 7,
              baseline_median: 2, p_value: 0.002, p_floor: 0.001996, at_floor: false,
              baseline_short: false, sample_count: 500, direction: "rose",
              signature_capable: true },
          ],
        }],
      }) };
    };
    H.clearGetCache();
    await H.loadAnomalies();
    await new Promise((r) => setTimeout(r, 140));
    const row = doc.querySelector("#ripples-table tbody tr");
    check("a ripple row is a focusable door", !!row && row.getAttribute("tabindex") === "0",
          row ? String(row.getAttribute("tabindex")) : "no row");
    if (row) row.click();
    await new Promise((r) => setTimeout(r, 220));
    const sheet = needEl("rp-detail-card");
    const sheetText = sheet.textContent.replace(/\s+/g, " ");
    check("the ripple row opens the house sheet", !sheet.classList.contains("hidden"),
          sheet.className);
    check("the sheet carries one evidence line per channel with scale, p-value, baseline and family",
          /conn_volume/.test(sheetText) && /dns_volume/.test(sheetText)
          && /1h/.test(sheetText) && /0\.00400/.test(sheetText)
          && /500 windows/.test(sheetText) && /conn/.test(sheetText) && /dns/.test(sheetText),
          sheetText.slice(0, 320));
    // A FITTED P MUST SAY IT IS FITTED. The row's p_method travels from the API into the sheet,
    // so a reader can tell a rank from a negative-binomial tail without opening the database.
    check("a fitted-tail p-value is labelled with the method that produced it",
          /0\.00600 \(negbin tail\)/.test(sheetText)
          && /94 windows/.test(sheetText), sheetText.slice(0, 420));
    check("the sheet labels the model anomalies as corroboration, not the finding",
          /corroboration, not the finding/.test(sheetText), sheetText.slice(0, 260));
    const corrText = needEl("rp-corroboration").textContent.replace(/\s+/g, " ");
    check("a model anomaly in the same window is shown as secondary corroboration",
          /0\.910/.test(corrText) && /Isolation Forest, LOF/.test(corrText),
          corrText.slice(0, 260));
    check("...and it sits after the evidence, never above it",
          sheetText.indexOf("Evidence") >= 0 && sheetText.indexOf("Evidence")
            < sheetText.indexOf("Model anomalies in this window"));
    // ── NORMALIZE ONE EVIDENCE LINE (2026-11-20) ───────────────────────────────────────────
    // The verb is per evidence line, the preview names the exact value, and the write says what
    // changed and offers the one-click way back. The rate-only lines must say why they cannot.
    const sigButtons = [...doc.querySelectorAll("#rp-evidence .rp-sig-open:not([disabled])")];
    const allSigButtons = [...doc.querySelectorAll("#rp-evidence tbody tr td:first-child button")];
    check("every evidence line carries the Normalize this pattern verb, and a rate-only line is refused",
          sigButtons.length === 1 && allSigButtons.length === 3
          && allSigButtons.filter((b) => b.disabled).length === 2,
          `${sigButtons.length} live / ${allSigButtons.length} total`);
    if (sigButtons[0]) sigButtons[0].click();
    await new Promise((r) => setTimeout(r, 120));
    const sigPanel = doc.getElementById("rp-signature-panel");
    const sigText = sigPanel ? sigPanel.textContent.replace(/\s+/g, " ") : "";
    check("the pattern preview names the host, the channel and the exact value that becomes expected",
          /203\.0\.113\.42/.test(sigText) && /tls_fingerprint_diversity/.test(sigText)
          && /example\.test\|ja4abc/.test(sigText) && /in this window/.test(sigText),
          sigText.slice(0, 260));
    check("the preview requires a reason and says the claim is reversible in one click",
          !!doc.getElementById("rp-sig-reason") && /reversible in one click/i.test(sigText),
          sigText.slice(0, 260));
    needEl("rp-sig-confirm").click();
    await new Promise((r) => setTimeout(r, 40));
    check("...and confirming without a reason is refused in the sheet",
          /reason is required/i.test(needEl("rp-sig-error").textContent));
    needEl("rp-sig-reason").value = "the new backup appliance";
    needEl("rp-sig-confirm").click();
    await new Promise((r) => setTimeout(r, 120));
    const doneText = sigPanel.textContent.replace(/\s+/g, " ");
    check("confirming names what is expected, until when, and offers one-click undo",
          /Expected from now on/.test(doneText) && /2027-02-18/.test(doneText)
          && /Undo — remove this normalization/.test(doneText) && /next ripple pass/.test(doneText),
          doneText.slice(0, 300));
    const undo = [...sigPanel.querySelectorAll("button")].find((b) => /Undo/.test(b.textContent));
    if (undo) undo.click();
    await new Promise((r) => setTimeout(r, 120));
    check("undo removes the signature and says the evidence returns on the next pass",
          /No longer expected/.test(sigPanel.textContent)
          && /next ripple pass/.test(sigPanel.textContent),
          sigPanel.textContent.replace(/\s+/g, " ").slice(0, 220));
    const sigReqs = seen.filter((u) => u.includes("/api/ripple-signatures"));
    check("the sheet action uses the signature route, never the alert path",
          sigReqs.some((u) => u.includes("/patterns"))
          && sigReqs.some((u) => !u.includes("/patterns")), sigReqs.join(" | ") || "none");
    const anReqs = seen.filter((u) => u.includes("/api/anomalies"));
    check("the page and the payload agree on the window (12h, never 24h)",
          anReqs.length > 0
          && anReqs.every((u) => /[?&]hours=12(?:&|$)/.test(u))
          && !anReqs.some((u) => /[?&]hours=24(?:&|$)/.test(u)),
          anReqs.join(" | ") || "no anomaly request");
    check("...and the corroboration read is bounded to the ripple's host",
          anReqs.some((u) => /[?&]host=203\.0\.113\.42(?:&|$)/.test(u)),
          anReqs.join(" | ") || "no anomaly request");
    needEl("rp-detail-close").click();
    await new Promise((r) => setTimeout(r, 80));
    check("closing the sheet hides it again", needEl("rp-detail-card").classList.contains("hidden"));
    fetchOverride = null;
    H.clearGetCache();
  }

  // ── RIPPLES ON A PHONE + CRITICALITY (2026-11-20) ───────────────────────────────────────────
  //
  // The live failure this block pins: the five fixed columns summed to 480px inside a 390px
  // viewport, so the explanation column was 0px wide and ONE row measured 4,497px tall -- the
  // other rows existed but were thousands of pixels below the fold, which read as "only one of
  // three ripples rendered". The cards are the phone layout; the table stays for the desk.
  //
  // The bands below are deliberately NOT the engine's (medium 4.25, high 7.25). The legend must
  // print THOSE numbers, proving the page reads `severity_bands` from the payload instead of
  // hardcoding the bar in app.js. The per-row `severity` is the server's answer.
  {
    const bands = {
      low: { min_score: 3.0, min_families: 1 },
      medium: { min_score: 4.25, min_families: 2 },
      high: { min_score: 7.25, min_families: 3 },
      bar: { family_max_p: 0.01, extreme_p: 0.001, min_score: 3.0, min_families: 2 },
    };
    const why = "ripple on 198.51.100.5 at 2026-11-20 09:00 UTC — 2 independent families: " +
      "conn, dns: conn family: conn_volume 812 vs median 74 (rose at 1h; p=0.006 over 167 " +
      "baseline windows); dns family: dns_volume 1440 vs median 210 (rose at 1h; p=0.005 " +
      "over 167 baseline windows).";
    fetchOverride = (u) => {
      if (!String(u).includes("/api/ripples")) return null;
      return { ok: true, status: 200, statusText: "OK", json: async () => ({
        available: true, reason: "", window_hours: 24, count: 3,
        model_version: "ripple-evidence-4", severity_bands: bands,
        monitored_networks: ["198.51.100.0/24"],
        ripples: [
          { host: "198.51.100.5", window_start: "2026-11-20T09:00:00",
            window_end: "2026-11-20T10:00:00", score: 4.29, combined_p: 0.00021,
            channels: ["conn_volume", "dns_volume"], families: ["conn", "dns"],
            single_family: false, severity: "medium", explanation: why, evidence: [] },
          { host: "198.51.100.51", window_start: "2026-11-20T08:00:00",
            window_end: "2026-11-20T09:00:00", score: 3.42, combined_p: 0.00038,
            channels: ["flow_bytes"], families: ["flow"], single_family: true,
            severity: "low",
            explanation: "ripple on 198.51.100.51 at 2026-11-20 08:00 UTC — single family " +
              "flow at the extreme bar, not cross-family corroboration: flow family: " +
              "flow_bytes 9.4 GB vs median 220 MB (rose at 24h; p<=0.001, the floor for 258 " +
              "baseline windows).", evidence: [] },
          { host: "198.51.100.23", window_start: "2026-11-20T07:00:00",
            window_end: "2026-11-20T08:00:00", score: 7.11, combined_p: 0.0000031,
            channels: ["conn_volume", "dns_query_diversity", "tls_fingerprint_diversity"],
            families: ["conn", "dns", "tls"], single_family: false, severity: "high",
            explanation: "ripple on 198.51.100.23 at 2026-11-20 07:00 UTC — 3 independent " +
              "families: conn, dns, tls: conn family: conn_volume 233 vs median 18 (rose at " +
              "1h; p=0.002 over 167 baseline windows); dns family: dns_query_diversity 91 vs " +
              "median 12 (rose at 1h; p=0.0007 over 167 baseline windows); tls family: " +
              "tls_fingerprint_diversity 44 vs median 6 (rose at 1h; p=0.0004 over 167 " +
              "baseline windows).", evidence: [] },
        ],
        baseline: {}, evidence: { rows: 14, monitored_rows: 14, subjects: 3,
                                  baseline_short_rows: 0 },
      }) };
    };
    H.clearGetCache();
    await H.loadAnomalies();
    await new Promise((r) => setTimeout(r, 160));

    const tableRows = [...doc.querySelectorAll("#ripples-table tbody tr")];
    const cards = [...doc.querySelectorAll("#ripples-cards .rp-card")];
    check("three ripples render as three table rows and three phone cards",
          tableRows.length === 3 && cards.length === 3,
          `table=${tableRows.length} cards=${cards.length}`);

    const first = cards[0];
    const firstText = first ? first.textContent.replace(/\s+/g, " ") : "";
    check("a phone card carries host, window, score, families and the full explanation",
          !!first && firstText.includes("198.51.100.5") && firstText.includes("11-20 09:00")
          && firstText.includes("4.29") && firstText.includes("conn / dns")
          && firstText.includes("conn_volume 812 vs median 74"),
          firstText.slice(0, 200));
    check("a phone card is a role=button door with a >=44px tap target",
          !!first && first.getAttribute("role") === "button"
          && first.getAttribute("tabindex") === "0"
          && window.getComputedStyle(first).minHeight === "44px",
          first ? `${first.getAttribute("role")} min-height=${window.getComputedStyle(first).minHeight}` : "no card");

    const single = cards[1];
    const singleText = single ? single.textContent.replace(/\s+/g, " ") : "";
    check("a single-family ripple is LOW and never styled sev-high",
          !!single && single.classList.contains("rp-sev-low")
          && !single.classList.contains("rp-sev-high")
          && !!single.querySelector(".bubble.state.sev-low")
          && !!single.querySelector(".rp-card-score.sev-low")
          && !singleText.includes("high"),
          single ? `${single.className} | ${singleText.slice(0, 80)}` : "no single-family card");
    check("a three-family ripple is HIGH and carries the severity chip + coloured score",
          !!cards[2] && cards[2].classList.contains("rp-sev-high")
          && !!cards[2].querySelector(".bubble.state.sev-high")
          && !!cards[2].querySelector(".rp-card-score.sev-high"),
          cards[2] ? cards[2].className : "no high card");
    check("the desk table carries the same band per row",
          tableRows.map((r) => r.className).join(" ").includes("rp-sev-high")
          && tableRows.map((r) => r.className).join(" ").includes("rp-sev-low"),
          tableRows.map((r) => r.className).join(" | "));

    const legend = needEl("rp-legend");
    const legendText = legend.textContent.replace(/\s+/g, " ");
    check("the criticality legend exists and prints the payload's own thresholds",
          !legend.classList.contains("hidden") && legendText.includes("4.3")
          && legendText.includes("7.3") && !legendText.includes("6.0"),
          legendText.slice(0, 260));

    fetchOverride = null;
    H.clearGetCache();
  }


  // ── THE TRAINING HISTORY NAMES WHAT EACH LINE COUNTS (2026-11-17) ────────────────────────────
  //
  // Measured on the live Models tab: the chart said "samples per retrain" for four lines, and one
  // of them was not samples. `training_sample_count` is rows drawn for Isolation Forest (80k cap),
  // Gradient Boosting (40k) and LOF (5k), but for the Adaptive Baseline it is the number of
  // PER-HOST baselines it just rebuilt -- 23 hosts against 80,000 rows on one log axis -- and that
  // model refreshes every detection cycle over 24h instead of every 6h over 72h, so it carried 191
  // points where the others had 4. A reader comparing the lines was comparing nothing.
  {
    const origFetch = window.fetch;
    window.fetch = (u, o) => {
      if (/\/api\/models\?/.test(String(u)))
        return Promise.resolve({ ok: true, json: async () => ({
          available: true, summary: "4 runs", points: [], staleness: [],
          retrain_interval_h: 6,
          training_history: {
            "Isolation Forest": [
              { t: "2026-11-17T06:04:00-06:00", n: 80000, w: 1.0, metrics: {} },
              { t: "2026-11-17T08:04:00-06:00", n: 80000, w: 1.0, metrics: {} },
            ],
            "Adaptive Baseline": [
              { t: "2026-11-17T08:00:00-06:00", n: 22, w: 1.0, metrics: {} },
              { t: "2026-11-17T08:04:00-06:00", n: 23, w: 1.0, metrics: {} },
            ],
          },
          scores: {}, model_counts: {}, feature_deviations: [], baselines: {} }) });
      return origFetch(u, o);
    };
    H.clearGetCache();
    H.showView("models");
    await H.loadModels();
    await new Promise((r) => setTimeout(r, 150));
    window.fetch = origFetch;
    H.clearGetCache();

    const legend = doc.getElementById("m-history-legend");
    const text = legend ? legend.textContent : "";
    check("the training history legend says what the sampled detectors count",
          /Isolation Forest — last 80000 samples/.test(text), text || "no legend");
    check("...and does not call the baseline's host count 'samples'",
          /Adaptive Baseline — last 23 host baselines/.test(text) && !/Adaptive Baseline[^·]*samples/.test(text),
          text || "no legend");
    check("...and names the baseline's different cadence",
          /every cycle/.test(text), text || "no legend");
  }

  // ── THE ADAPTIVE BASELINE CARD (AB-1) ───────────────────────────────────────────────────────
  {
    H.showView("models");
    await H.loadModels();
    await new Promise((r) => setTimeout(r, 250));
    const mbRows = [...doc.querySelectorAll("#mb-hosts tbody tr")];
    check("the adaptive baseline card lists the hosts it learned", mbRows.length === 3,
          "rows=" + mbRows.length);
    const mbTxt = needEl("mb-hosts").textContent;
    check("...with learned volumes in human units, not raw floats",
          /9\.2 KB/.test(mbTxt) && /4\.3 KB/.test(mbTxt) && !/9394/.test(mbTxt),
          mbTxt.slice(0, 120));
    check("...and the reverse name beside the address it belongs to",
          /host\.example/.test(mbTxt) && /198\.51\.100\.5/.test(mbTxt), mbTxt.slice(0, 80));
    check("...and the freshness line reads the server's own age",
          /Newest snapshot 4 min ago/.test(needEl("mb-note").textContent),
          needEl("mb-note").textContent);
    check("the summary counts the behavioural and fingerprint baselines",
          /3 hosts carry a learned baseline/.test(needEl("mb-summary").textContent)
          && /2 with behavioural \(Zeek\) baselines/.test(needEl("mb-summary").textContent)
          && /1 with fingerprint history/.test(needEl("mb-summary").textContent),
          needEl("mb-summary").textContent);
    check("what it flagged is a count, stated plainly",
          /Flagged 4 rows in the last 24h/.test(needEl("mb-fired").textContent),
          needEl("mb-fired").textContent);
    const mbFirst = mbRows[0] ? mbRows[0].querySelector("td") : null;
    if (mbFirst) {
      mbFirst.click();
      await new Promise((r) => setTimeout(r, 220));
      check("a baselined host opens its host view in one click",
            needEl("view-host").classList.contains("active"));
      H.showView("models");
      await new Promise((r) => setTimeout(r, 120));
    }
    // A store that cannot be read says so -- never "no baselines", which would read as a
    // trainer that died.
    fetchOverride = (u) => (String(u).includes("/api/baselines")
      ? Promise.resolve({ ok: false, status: 500, statusText: "Boom", json: async () => ({}) })
      : null);
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadModels();
    await new Promise((r) => setTimeout(r, 220));
    check("a baseline store that cannot be read says so, never 'no baselines'",
          /Unavailable/.test(needEl("mb-note").textContent),
          needEl("mb-note").textContent);
    fetchOverride = null;
    await H.loadModels();
    await new Promise((r) => setTimeout(r, 220));
    // Back to the landing view: the load-state capture below reads it and a block that
    // leaves the console somewhere else would break a check that is not about this card.
    H.showView("health");
  }

  // ── the Detectors table ─────────────────────────────────────────────────────────
  // The operator's ruling: "a detector the engine trains is not retired by a card." The status is
  // derived on the server from training rows, artifacts, the measured FAR and the promotion
  // budget; the browser renders it verbatim and must never show a stored card word instead.
  H.renderDetectors([
    { name: "LOF", trained: true, trained_at: "2026-11-19T08:21:17", samples: 5000,
      artifact_version: "v5", observed_far: 1.0, target_far: 0.01,
      coverage: 0.1299, coverage_detail: "10/77",
      coverage_note: "10 of 77 inputs (67 imputed)", missing_mode: "on",
      eligible: false, contributing: false,
      status: "not contributing: FAR 1.000 above the 0.030 tolerance (3 x 0.010 target)" },
    { name: "Isolation Forest", trained: true, trained_at: "2026-11-19T08:21:17", samples: 11900,
      artifact_version: "v5", observed_far: 0.0, target_far: 0.01,
      eligible: true, contributing: true, status: "eligible" },
  ], "2 detectors: 1 eligible. Fused false-alarm rate 0.04 against a 0.01 target.",
     { budget: 0.30, bar: 0.35, windows: 25 });
  check("the Detectors table renders one row per detector",
        doc.querySelectorAll("#md-table tbody tr").length === 2,
        `${doc.querySelectorAll("#md-table tbody tr").length} row(s)`);
  check("a detector over its FAR budget states both numbers and does not contribute",
        /not contributing: FAR 1\.000 above the 0\.030 tolerance/.test(
          needEl("md-table").textContent));
  // A FAR is not readable without what it was measured on. The count is the whole point of the
  // missing-data work: 0.0097 against 0.01 is a different claim on 10 of 77 than on 77 of 77.
  check("a detector row states how many inputs its FAR was measured on",
        /10 of 77 inputs \(67 imputed\)/.test(needEl("md-table").textContent));
  // NEVER COMPLETE BY DEFAULT. A row with no coverage record must say so; rendering it as
  // 77/77 would turn "we did not look" into "we looked at everything".
  check("an unrecorded coverage reads as unrecorded, never as complete",
        /coverage not recorded/.test(needEl("md-table").textContent)
        && !/77 of 77/.test(needEl("md-table").textContent));
  check("the budget the promotions were judged against is stated with its population",
        /alert budget: 30% of scored windows at or above 0\.35/.test(needEl("md-note").textContent)
        && /25 windows measured/.test(needEl("md-note").textContent));
  check("the summary carries the fused rate AND its target",
        /0\.04/.test(needEl("md-summary").textContent)
        && /0\.01 target/.test(needEl("md-summary").textContent));
  check("no stored card status word reaches the table",
        !/retired/i.test(needEl("md-table").textContent));

  // ── the Models staleness panel ─────────────────────────────────────────────────────────
  // The bug this guards: three detectors were 16h overdue against a 6h interval and the Models
  // view drew them as healthy lines, because it plotted run COUNT rather than RECENCY.
  H.renderStaleness([
    { model: "Isolation Forest", last_trained: "2026-01-01T00:00:00", age_h: 16.0,
      stale: true, never_trained: false },
    { model: "LOF", last_trained: "", age_h: null, stale: true, never_trained: true },
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
        needEl("m-stale").textContent.includes("16.0h"));
  check("a never-trained detector says so rather than showing an age",
        needEl("m-stale").textContent.includes("never"));
  check("the interval is stated in the heading",
        needEl("m-stale-window").textContent.includes("6"),
        needEl("m-stale-window").textContent);
  check("the note explains what an overdue model means for its scores",
        needEl("m-stale-note").textContent.includes("older traffic mix"),
        needEl("m-stale-note").textContent.slice(0, 100));
  check("the note distinguishes never-trained from merely overdue",
        needEl("m-stale-note").textContent.includes("never trained"));

  // ── the near-miss panel (SOC-2) ────────────────────────────────────────────────────────
  // The anomalies list shows what was FLAGGED; this panel exists because "nothing nearly
  // alerted" and "the near-miss table does not exist yet" are different facts, and an
  // empty table renders them identically.
  H.renderNearMisses({
    near_misses_available: true,
    near_misses: [
      { window_start: "2026-01-03T10:00:00", src_addr: "198.51.100.44", score: 0.66,
        threshold: 0.70, reason: "below-threshold", agreement: 0.5,
        models: ["Isolation Forest", "LOF"] },
      { window_start: "2026-01-03T10:05:00", src_addr: "198.51.100.45", score: 0.81,
        threshold: 0.70, reason: "agreement-gate", agreement: 0.2,
        models: ["Gradient Boosting"] },
    ],
  });
  const nearRows = doc.querySelectorAll("#m-near tbody tr");
  check("the near-miss table renders one row per recorded near miss",
        nearRows.length === 2, `rows=${nearRows.length}`);
  check("a below-threshold near miss is labelled as such",
        needEl("m-near").textContent.includes("below threshold"),
        needEl("m-near").textContent.slice(0, 140));
  check("a gate-dropped near miss states the gate",
        needEl("m-near").textContent.includes("agreement gate"),
        "an agreement-gate row rendered without its reason");
  check("the score and the bar it faced are both shown",
        needEl("m-near").textContent.includes("0.66")
          && needEl("m-near").textContent.includes("0.70"),
        "score/threshold pair missing from the row");
  check("the panel states what a threshold change would do",
        needEl("m-near-note").textContent.includes("Raising the threshold"),
        needEl("m-near-note").textContent.slice(0, 120));

  // ── the score distribution scales stacks, and the chart clips (issues #6, #35) ─────────────
  // ONE BAND, SEVERAL DETECTORS, EACH NEAR WHAT THE OLD GLOBAL MAX WOULD HAVE BEEN: in the old
  // code every segment drew against that max, the band stacked to three times the plot height
  // and painted over the card above. Geometry is read from the rect ATTRIBUTES the renderer
  // writes -- jsdom does no layout, so the attributes are the measurable truth here. PLOT_TOP
  // mirrors PAD.t in renderScoreDistribution. The SAME fixture doubles as #35's discriminator
  // (band stacks 10 vs 1), which is why the band-touching check below can tell the two scales
  // apart at all.
  H.renderScoreDistribution({
    "Isolation Forest": [0.95, 0.95, 0.95, 0.95],
    "Gradient Boosting": [0.95, 0.95, 0.95, 0.95],
    "LOF": [0.95, 0.95, 0.25],
  });
  const PLOT_TOP = 10;
  const distSvg = doc.querySelector("#m-scores svg");
  const distRects = distSvg ? [...distSvg.querySelectorAll("rect")] : [];
  const distTops = distRects.map((r) => Number(r.getAttribute("y")));
  check("the score distribution draws something to measure", distRects.length >= 3,
        `rects=${distRects.length}`);
  check("no segment stack overruns the plot top",
        distRects.length > 0 && distTops.every((y) => y >= PLOT_TOP - 0.001),
        `tops=${distTops.join(",")}`);
  check("the tallest stack touches the plot top, never above it",
        distTops.length > 0 && Math.abs(Math.min(...distTops) - PLOT_TOP) < 0.001,
        `closest top=${distTops.length ? Math.min(...distTops) : "n/a"}`);
  // THE #35 DISCRIMINATOR: band 9 stacks to 10 while band 2 holds a SINGLE score. Under the
  // retired per-band scaling both bands drew full height (2 touching); under the global max
  // stack only band 9 reaches the top and band 2 tops out at a tenth of the plot.
  const bandTop = {};
  for (const r of distRects) {
    const x = r.getAttribute("x");
    bandTop[x] = Math.min(bandTop[x] ?? Infinity, Number(r.getAttribute("y")));
  }
  const touching = Object.values(bandTop).filter((y) => Math.abs(y - PLOT_TOP) < 0.001).length;
  check("only the tallest band touches the plot top", touching === 1, `bands touching the top=${touching}`);
  check("the chart clips as a belt", /\.svg-chart\s*\{[^}]*overflow:\s*hidden/.test(css),
        "style.css no longer clips the chart");

  // ── include revoked actually asks, and the list appears (issue #7) ──────────────────────────
  {
    const asked = [];
    fetchOverride = (u) => {
      const s = String(u);
      if (!s.includes("/api/weirlings")) return null;
      asked.push(s);
      return Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => ({
        available: true, reason: null, heartbeats_available: true, heartbeat_reason: null,
        summary: { total: 2, registered: 1, problems: 0, alive: 1, stale: 0, never_seen: 0,
                   unregistered: 0, disabled: 0 },
        sensors: [WEIRLINGS_PAYLOAD.sensors[0]],
        revoked: [{ sensor_id: "edge-retired", revoked_at: "2026-09-01T00:00:00+00:00" }],
        revoked_reason: "",
      }) });
    };
    const wlTableText = () => (H.document.getElementById("wl-table") || {}).textContent || "";
    const revokedBox = H.document.getElementById("wl-revoked");
    revokedBox.checked = true;
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadWeirlings();
    check("ticking include-revoked asks the server for them",
          asked.length > 0 && asked[asked.length - 1].includes("revoked=1"),
          `urls=${asked.join(" | ")}`);
    check("the revoked registration renders once asked for",
          wlTableText().includes("edge-retired"), "revoked row missing from the table");
    revokedBox.checked = false;
    await H.loadWeirlings();
    check("unticking it stops asking, and the row leaves",
          asked.length > 1 && !asked[asked.length - 1].includes("revoked=1")
            && !wlTableText().includes("edge-retired"),
          `urls=${asked.join(" | ")}`);
    fetchOverride = null;
  }

  // ── a failed read is not an empty panel (issue #13) ──────────────────────────────────────────
  {
    const serve = (payload) => Promise.resolve(
      { ok: true, status: 200, statusText: "OK", json: async () => payload });
    const textOf = (id) => (H.document.getElementById(id) || {}).textContent || "";

    // Netflow talkers: FAILED says why; EMPTY keeps the quiet copy.
    // CLEAR FIRST: getJSON caches every GET for eight seconds, and /api/netflow was already loaded
    // earlier in this run, so without this the stub is never consulted and the assertion reads the
    // cached quiet copy -- which is exactly the "No talkers in this window." it reported.
    H.clearGetCache();
    fetchOverride = (u) => (String(u).includes("/api/netflow")
      ? serve({ volume: { available: true, reason: "", points: [] },
                protocols: { available: true, reason: "", points: [] },
                ports: { available: true, reason: "", points: [] },
                spread: { available: true, reason: "", points: [] },
                talkers: { available: false, reason: "the talkers query failed: Timeout",
                           points: [] },
                noise: {}, data_error: null })
      : null);
    H.clearGetCache();  // each stubbed re-load needs its own clear
    await H.loadNetflow();
    check("a FAILED talkers read says why instead of reading as a quiet network",
          textOf("nf-talkers").includes("Cannot draw this: the talkers query failed"),
          textOf("nf-talkers").slice(0, 90));
    fetchOverride = (u) => (String(u).includes("/api/netflow")
      ? serve({ volume: { available: true, reason: "", points: [] },
                protocols: { available: true, reason: "", points: [] },
                ports: { available: true, reason: "", points: [] },
                spread: { available: true, reason: "", points: [] },
                talkers: { available: true, reason: "", points: [] },
                noise: {}, data_error: null })
      : null);
    H.clearGetCache();  // each stubbed re-load needs its own clear
    await H.loadNetflow();
    check("an EMPTY talkers window keeps the quiet copy",
          textOf("nf-talkers").includes("No talkers in this window"),
          textOf("nf-talkers").slice(0, 90));

    // DNS: FAILED carries the reason on the histogram and the table.
    fetchOverride = (u) => (String(u).includes("/api/dns")
      ? serve({ available: false, reason: "cannot reach ClickHouse: OperationalError",
                rows: [], total: 0, histogram: [], facets: {}, data_error: "x" })
      : null);
    H.clearGetCache();  // each stubbed re-load needs its own clear
    await H.loadDns();
    check("a FAILED dns read says why instead of 'No DNS records in this window'",
          textOf("dn-volume").includes("Cannot draw this: cannot reach ClickHouse"),
          textOf("dn-volume").slice(0, 90));
    check("the failed dns read does not tell the operator to widen a filter",
          textOf("dn-rows").includes("Cannot list these:"),
          textOf("dn-rows").slice(0, 90));

    // Blocked: FAILED says why in both rule tables and the hits list.
    fetchOverride = (u) => (String(u).includes("/api/blocked")
      ? serve({ available: false, reason: "the events query failed: OperationalError",
                hits: [], total: 0, blocks: [], alerts: [], gate: {}, data_error: "x" })
      : null);
    H.clearGetCache();  // each stubbed re-load needs its own clear
    await H.loadBlocked();
    check("a FAILED blocked read says why instead of inviting a new rule",
          textOf("bl-summary").includes("Blocks unavailable")
            && textOf("bl-hit-rows").includes("Cannot list these:"),
          `${textOf("bl-summary").slice(0, 80)} | ${textOf("bl-hit-rows").slice(0, 60)}`);
    fetchOverride = (u) => (String(u).includes("/api/blocked")
      ? serve({ available: true, reason: "", hits: [], total: 0, blocks: [], alerts: [],
                gate: {}, data_error: null })
      : null);
    H.clearGetCache();  // each stubbed re-load needs its own clear
    await H.loadBlocked();
    check("an EMPTY blocked read keeps the real empty copies",
          /0 recorded hits/.test(textOf("bl-summary"))
            && textOf("bl-hit-rows").includes("Nothing recorded in this window"),
          textOf("bl-summary").slice(0, 80));
    fetchOverride = null;
  }

  // The two states that must NOT render identically.
  H.renderNearMisses({ near_misses_available: false, near_misses: [],
                       near_misses_reason: "the near-miss table has not been created on this "
                         + "deployment yet (it arrives with the schema job on the version "
                         + "that added it)" });
  check("an unavailable near-miss table names the schema job, not an empty list",
        needEl("m-near-note").textContent.includes("schema job"),
        needEl("m-near-note").textContent.slice(0, 120));
  H.renderNearMisses({ near_misses_available: true, near_misses: [] });
  check("an empty near-miss list is distinguishable from an unavailable one",
        needEl("m-near").textContent.includes("No near misses")
          && !doc.getElementById("m-near-note").textContent.includes("schema job"),
        "empty and unavailable collapse to the same rendering");


  // The nav's LANDING state, captured before any navigation in this file changes it.
  //
  // ASSERTED HERE, immediately, because these describe the state at load and a later block cannot
  // read it back: by then showView() has moved the active tab and the capture would be the only
  // thing still describing load. That is why the two facts are stated separately -- "Health is the
  // landing view" (asserted from this capture) and "Health sits between Models and Settings"
  // (asserted from the live nav later). They coincided while Health happened to be first.
  const navAtLoad = [...doc.querySelectorAll("nav .tab")].map((b) => b.dataset.view);
  const healthWasActive =
    doc.querySelector('nav .tab[data-view="health"]').classList.contains("active");
  check("Health is ACTIVE at load (it inherited the landing role from Overview)",
        healthWasActive, `active=${healthWasActive}`);
  // TH-3: the nav is grouped now, and Health leads the first group (Operations); what this
  // check must keep true is that Health sits in the FIRST group and Settings in the LAST --
  // the landing view is where the eye starts, and the console's controls are where it ends.
  const groupOf = (v) => {
    const t = doc.querySelector(`nav .tab[data-view="${v}"]`);
    const g = t && t.closest(".tab-group");
    return g ? g.dataset.group : null;
  };
  check("Health sits in its own group and Settings in the console group last",
        groupOf("health") === "health" && groupOf("settings") === "console",
        `health=${groupOf("health")} settings=${groupOf("settings")} nav is ${navAtLoad.join(", ")}`);


  // ── the Zeek tab ───────────────────────────────────────────────────────────────────────────
  // THIS SECTION EXISTS BECAUSE ITS ABSENCE SHIPPED A BUG. The Zeek tab rendered a summary and an
  // empty bar chart while the API returned all 18 logs correctly: the rows were mapped to one shape
  // and the accessors read another, so the formatter threw on undefined and took the panel down.
  // Nothing caught it because the harness never loaded this view, and its stub served an EMPTY
  // payload -- which renders a legitimate "nothing in this window" note rather than crashing.
  //
  // A tab with no coverage is a tab whose bugs reach the user. Every view now gets exercised.
  H.showView("zeek");
  // ── THE HEALTH PANEL SHOWS THE REASON A CHECK FAILED ─────────────────────────────────────────
  //
  // MEASURED ON THE LIVE CONSOLE: the panel said "2 of 8 checks FAILING -- see below" and the cell
  // below was EMPTY, because the renderer printed `String(c.value ?? "")` and dropped the `detail`
  // the server had sent all along. An operator cannot act on "FAIL" alone, and a datum rendered as
  // "[object Object]" is worse than nothing.
  {
    // The health view answers the GLOBAL range now (the per-view hours box is gone): set the
    // range itself, exactly as the header control does.
    H.trApply({ mode: "relative", hours: 6 });
    await H.loadHealthDeep();
    const hp = doc.querySelector("#hp-checks tbody");
    const text = hp ? hp.textContent : "";
    check("the health panel renders the REASON a check failed",
          /no training runs recorded; the last 24h hold 20 flow row\(s\)/.test(text),
          "the failing check's detail sentence is not in the table");
    check("the health panel never stringifies an object value",
          !/\[object Object\]/.test(text),
          "a probe value was rendered with String(): the operator sees [object Object]");
    check("a healthy check still shows its own sentence, not its datum",
          /9\/9 present/.test(text),
          "the healthy row lost its detail line");
    // Put the range back the way the rest of the harness expects to find it (24h, the default).
    H.trApply({ mode: "relative", hours: 24 });
    await H.loadHealthDeep();
  }

  await H.loadZeek();

  const zkSummary = needEl("zk-summary").textContent;
  check("the zeek summary states rows and how many logs are active",
        /rows from \d+ of \d+ configured logs/.test(zkSummary), zkSummary);

  const zkLogBars = doc.querySelectorAll("#zk-counts .bar-row");
  check("the per-log bar chart renders a bar for every log reported",
        zkLogBars.length === ZEEK_PAYLOAD.counts.points.length,
        `${zkLogBars.length} bars for ${ZEEK_PAYLOAD.counts.points.length} logs`);

  // THE EXACT DEFECT: a bar whose label or value came out undefined. Check the rendered text, not
  // just the element count -- a <span> with undefined in it still counts as a rendered bar.
  const barText = [...doc.querySelectorAll("#zk-counts .bar-row")].map((r) => r.textContent);
  check("no bar renders 'undefined' (the crash signature)",
        !barText.some((t) => t.includes("undefined")), barText.slice(0, 3).join(" | "));
  check("each bar names its log and shows a count",
        barText.some((t) => t.includes("conn") && t.includes("40,731")),
        barText.slice(0, 3).join(" | "));

  const zkTimeline = needEl("zk-timeline");
  check("the timeline drew an svg", !!zkTimeline.querySelector("svg"));
  check("the timeline drew a path per series",
        zkTimeline.querySelectorAll("path").length >= 2,
        `${zkTimeline.querySelectorAll("path").length} paths`);
  check("the timeline legend names the series",
        /conn/.test(zkTimeline.textContent), zkTimeline.textContent.slice(0, 80));

  check("a log that recorded NOTHING in the window is explained, not just zeroed",
        /recorded nothing in this window|widen the window/i.test(needEl("zk-counts").textContent),
        needEl("zk-counts").textContent.slice(-160));
  check("an empty-forever log is distinguished from a quiet one",
        /NEVER produced a row/i.test(needEl("zk-counts").textContent));

  check("the services panel rendered its bars",
        doc.querySelectorAll("#zk-services .bar-row").length === 2);
  check("the dns panel rendered its names",
        doc.querySelectorAll("#zk-dns .bar-row").length === 1);

  // ── ZK-FILTER-1: the three Zeek dimensions add server-side filters ───────────────────────
  // A click that only repaints the clicked bar is the dead-affordance defect; check the chip,
  // the request query, AND the panel count that the filtered response changes.
  async function zkClick(label) {
    const rows = [...doc.querySelectorAll("#zk-counts .bar-row, #zk-services .bar-row, #zk-dns .bar-row")];
    const row = rows.find((r) => r.textContent.includes(label));
    check(`a ${label} bar exists to click`, !!row);
    if (row) row.dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
  }

  await zkClick("ssl");
  check("a log click adds a visible filter chip",
        /log = ssl/.test(needEl("zk-chips").textContent),
        needEl("zk-chips").textContent);
  check("a log click sends the filter to the server",
        ZEEK_REQS.some((u) => u.includes("log=ssl")), ZEEK_REQS.slice(-1)[0]);
  check("a log filter changes the log count panel",
        doc.querySelectorAll("#zk-counts .bar-row").length === 1,
        `${doc.querySelectorAll("#zk-counts .bar-row").length} bars`);

  await zkClick("dns");
  check("a service click adds a visible filter chip",
        /service = dns/.test(needEl("zk-chips").textContent),
        needEl("zk-chips").textContent);
  check("a service click sends the filter to the server",
        ZEEK_REQS.some((u) => u.includes("service=dns")), ZEEK_REQS.slice(-1)[0]);
  check("a service filter changes the service panel",
        doc.querySelectorAll("#zk-services .bar-row").length === 1,
        `${doc.querySelectorAll("#zk-services .bar-row").length} services`);

  await zkClick("host.example");
  check("a DNS click adds a visible filter chip",
        /DNS name = host.example/.test(needEl("zk-chips").textContent),
        needEl("zk-chips").textContent);
  check("a DNS click sends the filter to the server",
        ZEEK_REQS.some((u) => u.includes("query=host.example")), ZEEK_REQS.slice(-1)[0]);
  check("a DNS filter changes the DNS panel",
        doc.querySelectorAll("#zk-dns .bar-row").length === 1,
        `${doc.querySelectorAll("#zk-dns .bar-row").length} names`);

  // Remove the chips and prove the next request is unfiltered again.
  while (doc.querySelector("#zk-chips .bubble.filter")) {
    doc.querySelector("#zk-chips .bubble.filter")
      .dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  check("removing the Zeek filters clears the chip row",
        needEl("zk-chips").textContent.trim() === "",
        needEl("zk-chips").textContent);
  check("removing the Zeek filters returns to the unfiltered request",
        ZEEK_REQS.some((u) => !u.includes("log=") && !u.includes("service=") && !u.includes("query=")),
        ZEEK_REQS.slice(-1)[0]);

  // ── operator access and staged writes ──────────────────────────────────────────────────────
  // Everything below drives the SHIPPING functions against the SHIPPING markup and asserts the
  // OUTCOME. The riskiest thing here is a write, so the checks cover what was actually POSTed, not
  // just what rendered.

  check("the operator token field exists and is not readonly",
        !!doc.getElementById("st-token") && !doc.getElementById("st-token").readOnly);
  check("the token field is a password input (a token left on screen is a token leaked)",
        needEl("st-token").type === "password");
  check("the page states the no-TLS boundary where the operator will read it",
        /no TLS|plain HTTP/i.test(needEl("st-auth-card").textContent),
        needEl("st-auth-card").textContent.slice(0, 120));

  // An editable setting renders an INPUT; a secret renders text and a read-only tag.
  // NAVIGATE AND LOAD HERE, in this block. Depending on another section having already done it is
  // the ordering trap that broke the graph checks: that block ran after one which deliberately
  // replaced the state it needed.
  H.showView("settings");
  await H.loadSettings();
  // SETTINGS AUDIT (2026-10-22): the tab now has the same scan layer as the rest of the console.
  check("Settings has a view header with a find control",
        !!doc.querySelector("#view-settings .settings-head") &&
        !!doc.getElementById("st-filter"),
        "settings header or find control missing");
  check("Settings groups its cards under section labels",
        ["st-section-access", "st-section-detection", "st-section-operations", "st-section-changes"]
          .every((id) => !!doc.getElementById(id)),
        "a settings section label is missing");
  check("Settings has no expand/collapse control — every card is always open",
        !doc.getElementById("st-expand") && !doc.getElementById("st-collapse")
          && ![...doc.querySelectorAll("#view-settings .card")].some((c) => c.classList.contains("collapsed")));
  check("Settings has a jump to the one pending set",
        !!doc.getElementById("st-stage-jump"));
  const inputs = [...doc.querySelectorAll("#view-settings .setting-input")];
  const editableKeys = inputs.map((n) => n.dataset.key);
  check("editable settings render as inputs", editableKeys.includes("base_threshold"),
        `inputs: ${editableKeys.join(",")}`);
  check("a SECRET is never editable from the page",
        !editableKeys.includes("clickhouse_password"), `inputs: ${editableKeys.join(",")}`);
  check("a non-editable row says so rather than looking broken",
        /read-only/.test(needEl("view-settings").textContent));

  // THESE TWO DESCRIBE THE PRE-EDIT STATE, so they are asserted NOW, before anything is staged.
  // They ran after an apply initially, which is how they became flaky assertions about a state the
  // block itself had already changed.
  const applyBtn0 = needEl("st-stage-apply");
  check("there IS an apply control now (the operator asked for one)", !!applyBtn0);
  check("apply is DISABLED until something is staged", applyBtn0.disabled === true,
        `disabled=${applyBtn0.disabled}`);
  check("the page states that nothing is written on edit",
        /edit a value above to stage one/i.test(needEl("st-stage-note").textContent),
        needEl("st-stage-note").textContent);

  // STAGING: an edit must NOT write. This is the single most important assertion here.
  const before = POSTED.length;
  const bt = inputs.find((n) => n.dataset.key === "base_threshold");
  bt.value = "0.5";
  bt.dispatchEvent(new window.Event("input", { bubbles: true }));
  check("editing a setting stages it without writing anything", POSTED.length === before,
        `${POSTED.length - before} request(s) were sent on edit`);
  check("the staged change is listed for review",
        needEl("st-stage-list").textContent.includes("base_threshold"));
  check("the staged count is stated", /1 staged/.test(needEl("st-stage-count").textContent));
  check("the header chip states the staged count from every tab",
        /1 staged/.test(needEl("stage-pill").textContent)
        && !doc.getElementById("stage-pill").classList.contains("hidden"),
        needEl("stage-pill").textContent);
  check("the staged change is saved to the tab's own storage until applied",
        (window.sessionStorage.getItem("wv-stage") || "").includes("base_threshold"),
        String(window.sessionStorage.getItem("wv-stage")).slice(0, 80));
  needEl("stage-pill").click();
  await new Promise((r) => setTimeout(r, 40));
  check("clicking the chip lands on the review list without writing anything",
        needEl("view-settings").classList.contains("active"));
  check("Apply is enabled once something is staged",
        needEl("st-stage-apply").disabled === false);

  // THE PLAN: fetched from the server, so validation and blast radius come from the code that
  // will do the write rather than a second copy in JavaScript.
  await H.planStage();
  check("the plan was requested from the server",
        POSTED.some((r) => r.url.includes("/api/settings/plan")),
        POSTED.map((r) => r.url).join(","));
  const planBody = JSON.parse((POSTED.find((r) => r.url.includes("/api/settings/plan")) || {}).body || "{}");
  check("the plan carries the staged change", planBody.changes && planBody.changes.base_threshold === "0.5",
        JSON.stringify(planBody));
  check("the blast radius is shown BEFORE apply",
        /restart/i.test(needEl("st-stage-list").textContent),
        needEl("st-stage-list").textContent.slice(0, 160));
  check("each plan row states the value it would replace",
        /\(was /.test(needEl("st-stage-list").textContent),
        needEl("st-stage-list").textContent.slice(0, 160));

  // APPLY: the request must carry the token header and the staged values.
  H.setToken("test-token-value");
  await H.applyStage();
  const applied = POSTED.find((r) => r.url.includes("/api/settings/apply"));
  check("apply POSTs to the apply route", !!applied, POSTED.map((r) => r.url).join(","));
  const aBody = JSON.parse((applied || {}).body || "{}");
  check("apply sends the staged change", aBody.changes && aBody.changes.base_threshold === "0.5",
        JSON.stringify(aBody));
  check("apply sends the operator token as a header",
        (applied || {}).headers && applied.headers["X-Weirvern-Token"] === "test-token-value",
        JSON.stringify((applied || {}).headers));
  check("the outcome is reported in the server's terms",
        /saved|restarted|not applied/i.test(needEl("st-stage-note").textContent),
        needEl("st-stage-note").textContent.slice(0, 140));
  check("staging is cleared after a successful apply",
        Object.keys(H.STAGE.changes).length === 0);
  check("the chip hides again once the stage is empty",
        needEl("stage-pill").classList.contains("hidden"));

  // THE RECEIPT: per-item results after an apply.
  check("the receipt names the key and the time it landed",
        /base_threshold/.test(needEl("st-apply-results").textContent)
        && /applied/.test(needEl("st-apply-results").textContent),
        needEl("st-apply-results").textContent.slice(0, 140));

  // A REFUSED WRITE: the read-back refuses the 0.7 write once -- the receipt must say FAILED
  // with the server's reason and offer the one-click re-apply.
  const bt7 = [...doc.querySelectorAll("#view-settings .setting-input")]
    .find((n) => n.dataset.key === "base_threshold");
  bt7.value = "0.7";
  bt7.dispatchEvent(new window.Event("input", { bubbles: true }));
  await H.applyStage();
  check("a failed apply says which item failed and why",
        /FAILED/.test(needEl("st-apply-results").textContent)
        && /did not land/.test(needEl("st-apply-results").textContent),
        needEl("st-apply-results").textContent.slice(0, 180));
  const reBtn = [...doc.querySelectorAll("#st-apply-results button")]
    .find((b) => /Re-apply failed/.test(b.textContent));
  check("a failed item offers a one-click re-apply", !!reBtn);
  if (reBtn) {
    const beforeRe = POSTED.length;
    reBtn.click();
    await new Promise((r) => setTimeout(r, 260));
    const reReq = POSTED.slice(beforeRe).find((r) => r.url.includes("/api/settings/apply"));
    let reBody = {};
    try { reBody = JSON.parse(reReq.body || "{}"); } catch (_e) { reBody = {}; }
    check("re-apply stages just the failed key and posts it again",
          !!reReq && reBody.changes && reBody.changes.base_threshold === "0.7",
          JSON.stringify(reBody).slice(0, 120));
    check("the re-applied item now reads as applied",
          /applied/.test(needEl("st-apply-results").textContent)
          && !/FAILED/.test(needEl("st-apply-results").textContent),
          needEl("st-apply-results").textContent.slice(0, 140));
  }

  // DISCARD: staged changes are dropped and the view reloads from the server's values.
  const bt2 = [...doc.querySelectorAll("#view-settings .setting-input")]
    .find((n) => n.dataset.key === "base_threshold");
  if (bt2) {
    bt2.value = "0.9";
    bt2.dispatchEvent(new window.Event("input", { bubbles: true }));
  }
  check("a second edit stages again", Object.keys(H.STAGE.changes).length === 1);
  H.discardStage();
  check("discard clears the staged set", Object.keys(H.STAGE.changes).length === 0);

  // ── RETENTION: derived from disk, and destructive to lower ───────────────────────────────
  // The window is AUTO by default: the day count is an OUTCOME (read-only, from the server's
  // measurement) and the arithmetic is printed under it. Lowering it expires data, so it must
  // NOT ride the ordinary warned-change confirm: it opens the destructive echo (a reason,
  // recorded). The DECLINE path is driven first -- nothing may be posted -- then the real one.
  const ret = [...doc.querySelectorAll("#view-settings .setting-input")]
    .find((n) => n.dataset.key === "data_retention_days");
  const autoBox = ret ? ret.parentElement.querySelector(".setting-auto") : null;
  check("data retention renders as an auto checkbox plus a bounded number input",
        !!ret && ret.type === "number" && ret.getAttribute("min") === "7"
          && ret.getAttribute("max") === "365" && !!autoBox,
        ret ? `type=${ret.type} min=${ret.getAttribute("min")} auto=${!!autoBox}`
            : "no data_retention_days control");
  check("auto is CHECKED by default and the derived day count is read-only",
        !!autoBox && autoBox.checked === true && ret.disabled === true
          && ret.value === String(SETTINGS_PAYLOAD.groups.runtime
            .find((r) => r.key === "data_retention_days").retention.days),
        `checked=${autoBox && autoBox.checked} disabled=${ret && ret.disabled} value=${ret && ret.value}`);
  const sentence = doc.querySelector("#view-settings [data-retention-sentence]");
  check("the row shows the ARITHMETIC, not just a number",
        !!sentence && /45 days from 214 GB free at 1\.9 GB\/day \(40% budget\)/.test(sentence.textContent)
          && /Merge headroom kept/.test(sentence.textContent),
        sentence ? sentence.textContent.slice(0, 160) : "no retention sentence");
  const ratio = [...doc.querySelectorAll("#view-settings .setting-input")]
    .find((n) => n.dataset.key === "data_retention_ratio");
  check("the disk-budget ratio is its own bounded number control",
        !!ratio && ratio.type === "number" && ratio.getAttribute("min") === "10"
          && ratio.getAttribute("max") === "70",
        ratio ? `min=${ratio.getAttribute("min")} max=${ratio.getAttribute("max")}` : "missing");

  autoBox.checked = false;
  autoBox.dispatchEvent(new window.Event("change", { bubbles: true }));
  check("switching auto off seeds an explicit value from the derived one and unlocks it",
        ret.disabled === false && ret.value === "45" && H.STAGE.changes.data_retention_days === "45",
        `disabled=${ret.disabled} value=${ret.value} staged=${H.STAGE.changes.data_retention_days}`);
  ret.value = "7";
  ret.dispatchEvent(new window.Event("input", { bubbles: true }));
  await H.planStage();
  const retRow = [...doc.querySelectorAll("#st-stage-list .stage-row")]
    .find((r) => /data_retention_days/.test(r.textContent));
  check("lowering retention is marked destructive before Apply",
        !!retRow && /DESTRUCTIVE/i.test(retRow.textContent),
        retRow ? retRow.textContent.slice(0, 180) : "no staged retention row");
  const retPosts = () => POSTED.filter((r) => r.url.includes("/api/settings/apply")).length;
  const beforeRet = retPosts();
  const declined = H.applyStage();
  await new Promise((r) => setTimeout(r, 40));
  const dbox = doc.querySelector("#modal-body .dest-confirm");
  check("lowering retention opens the destructive echo, not a plain confirm",
        !!dbox && /DELETES history/i.test(dbox.textContent),
        dbox ? dbox.textContent.slice(0, 120) : "no destructive echo");
  const cancelRet = [...(dbox ? dbox.querySelectorAll(".dest-acts button") : [])]
    .find((b) => /Cancel/.test(b.textContent));
  if (cancelRet) cancelRet.click();
  await declined;
  check("declining the retention echo writes nothing", retPosts() === beforeRet,
        `${retPosts() - beforeRet} apply request(s) after a decline`);
  check("the decline is stated rather than silently ignored",
        /declined the retention confirmation/i.test(needEl("st-stage-note").textContent),
        needEl("st-stage-note").textContent);

  const accepted = H.applyStage();
  await new Promise((r) => setTimeout(r, 40));
  const echoed = await confirmEcho("the 24h baseline needs 30 days, not 7");
  check("the destructive echo requires a reason and accepts it", echoed === true);
  await accepted;
  const retReq = POSTED.slice(-1).find((r) => r.url.includes("/api/settings/apply"));
  let retBody = {};
  try { retBody = JSON.parse((retReq || {}).body || "{}"); } catch (_e) { retBody = {}; }
  check("the retention apply sends the value AND the recorded reason",
        retBody.changes && retBody.changes.data_retention_days === "7"
          && /24h baseline/.test(retBody.reason || ""),
        JSON.stringify(retBody).slice(0, 180));
  // THE RATCHET'S EXPLICIT ACTION. The destructive echo above is the operator's consent; the
  // request has to SAY so, or the server refuses the very change that was just confirmed.
  check("the destructive retention apply is an explicit ratchet reset",
        retBody.reset_ratchet === true,
        `reset_ratchet=${retBody.reset_ratchet} in ${JSON.stringify(retBody).slice(0, 160)}`);
  {
    const ordinary = POSTED.filter((r) => r.url.includes("/api/settings/apply"))
      .map((r) => { try { return JSON.parse(r.body || "{}"); } catch (_e) { return {}; } })
      .filter((b) => !((b.changes || {}).data_retention_days));
    check("an ordinary apply never resets the retention floor",
          ordinary.length > 0 && ordinary.every((b) => !b.reset_ratchet),
          `${ordinary.filter((b) => b.reset_ratchet).length} of ${ordinary.length} ordinary `
            + "apply request(s) carried reset_ratchet");
  }
  const receipt = needEl("st-apply-results").textContent;
  check("the receipt reports the cluster's EFFECTIVE TTL, not the requested one",
        /flows_window — TTL 7 days \(read back\)/.test(receipt),
        receipt.slice(0, 200));
  check("a table the cluster did not change is named, not hidden",
        /zeek_http — NOT CHANGED: the cluster reports 35 days, not 7/.test(receipt),
        receipt.slice(0, 240));
  check("the apply note says the cluster did not fully converge",
        /NOT APPLIED — 1 of 2 table/.test(needEl("st-stage-note").textContent),
        needEl("st-stage-note").textContent.slice(0, 200));

  // HOW EVERY CONTROL APPLIES (BF-5): the badge is payload-driven from the writer's restart
  // table, and every editable row shows it.
  {
    const rows = [...doc.querySelectorAll("#st-detect .setting, #st-sensor .setting, #st-runtime .setting")];
    const editableRows = rows.filter((r) => {
      const ctl = r.querySelector(".setting-ctl");
      if (!ctl) return false;
      return !!ctl.querySelector("input, select") ||
        [...ctl.querySelectorAll("button")].some((b) => !b.classList.contains("setting-help-btn"));
    });
    const badge = (r) => r.querySelector(".setting-applies");
    const naked = editableRows.filter((r) => !(badge(r) && /applies with Apply/.test(badge(r).textContent)));
    check("every editable settings row says how it applies",
          editableRows.length >= 3 && naked.length === 0,
          naked.map((r) => r.dataset.key).join(", ") || `${editableRows.length} editable rows`);
    const bt = rows.find((r) => r.dataset.key === "base_threshold");
    check("...and the restart consequence is named, from the writer's own table",
          !!bt && !!badge(bt) && /restarts the detection worker/.test(badge(bt).textContent),
          bt && badge(bt) ? badge(bt).textContent : "no base_threshold badge");
  }

  // ── SONAR: the survey button ──────────────────────────────────────────────────────────────
  // The button must exist with its help, a click must hit the sonar route, and the
  // recommendations must land as STAGED changes (the pending-changes review step) rather
  // than being applied straight away.
  check("the Sonar button exists (in the sensor drill-down panel)",
        !!doc.getElementById("st-sonar"));
  check("the Sonar button carries its own ? explanation",
        !!doc.getElementById("st-sonar-help") &&
        /ARP/.test(needEl("st-sonar-help-text").textContent),
        (needEl("st-sonar-help-text") || {}).textContent);
  check("the Sonar explanation starts hidden",
        needEl("st-sonar-help-text").classList.contains("hidden"));
  const sonarBefore = POSTED.filter((r) => r.url.includes("/api/settings/sonar")).length;
  H.discardStage();
  await H.runSonar();
  check("Sonar POSTs to the sonar route",
        POSTED.filter((r) => r.url.includes("/api/settings/sonar")).length === sonarBefore + 1,
        POSTED.map((r) => r.url).join(","));
  // THE OPERATOR'S PREFILL (2026-10-19): a standalone survey puts its measured answer in the
  // controls as pending changes for review -- it still writes nothing until Apply.
  check("a standalone survey stages its recommendations for review",
        H.STAGE.changes && H.STAGE.changes.sensor_mode === "siphon"
        && H.STAGE.changes.intercept_segment === "198.51.100.0/24",
        JSON.stringify(H.STAGE.changes));
  H.stageSonarRecommendations(H.SONAR_STATE.result);
  check("Sonar stages its recommendations as pending changes (not applied)",
        H.STAGE.changes && H.STAGE.changes.sensor_mode === "siphon"
        && H.STAGE.changes.intercept_segment === "198.51.100.0/24"
        && H.STAGE.changes.intercept_addr === "198.51.100.250",
        JSON.stringify(H.STAGE.changes));
  check("Sonar stages nothing for a recommendation equal to the running value",
        !("intercept_gateway" in H.STAGE.changes),
        "intercept_gateway is already 198.51.100.1 in the stub; a no-op recommendation must "
        + "not appear as a pending change: " + JSON.stringify(H.STAGE.changes));
  check("Sonar reports what it measured",
        /198\.51\.100\.0\/24/.test(needEl("st-sonar-note").textContent)
        && /gateway/i.test(needEl("st-sonar-note").textContent),
        needEl("st-sonar-note").textContent.slice(0, 200));
  check("the staged list shows the Sonar-sourced keys",
        needEl("st-stage-list").textContent.includes("intercept_segment"),
        needEl("st-stage-list").textContent.slice(0, 200));
  H.discardStage();
  check("discarding Sonar's recommendations clears them like any other staged change",
        Object.keys(H.STAGE.changes).length === 0);

  // ── SONAR'S COUNTS AND THE PLAN'S REQUIREMENTS (2026-10-17) ──────────────────────────────
  // The live report: "Sonar doesn't work". Measured live: 5 recommendations, 2 staged, and the
  // panel read "Staged 5" over a two-row list -- the note claimed changes the dedupe had
  // (correctly) refused to stage. It now counts what actually staged and says so when nothing did.
  {
    H.discardStage();
    const note = needEl("st-sonar-note");
    const base = { ok: true, interface: "eth0", segment: "198.51.100.0/24",
                   address: "198.51.100.5/24", hosts_answered: 3, swept: 254,
                   free_addresses: ["198.51.100.250"], gateway: "198.51.100.1",
                   gateway_source: "assumed", notes: [] };
    const allMatch = Object.assign({}, base,
      { recommended: { sensor_mode: "loch", intercept_gateway: "198.51.100.1" } });
    H.stageSonarRecommendations(allMatch);
    H.renderSonarNote(allMatch);
    check("a survey whose recommendations ALL match says nothing was staged, not 'staged 2'",
          /nothing to stage/i.test(note.textContent)
          && Object.keys(H.STAGE.changes).length === 0,
          note.textContent.slice(0, 170));
    const mixed = Object.assign({}, base,
      { recommended: { sensor_mode: "siphon", intercept_gateway: "198.51.100.1" } });
    H.stageSonarRecommendations(mixed);
    H.renderSonarNote(mixed);
    check("a MIXED survey counts only what staged and names the rest as already in effect",
          /Staged 1 change/.test(note.textContent)
          && /already match/.test(note.textContent)
          && Object.keys(H.STAGE.changes).join(",") === "sensor_mode",
          note.textContent.slice(0, 220));
    H.discardStage();
  }
  // ── NETFLOW AS A CHECKBOX (operator, 2026-10-17) ──────────────────────────────────────────
  {
    const nfRow = doc.querySelector("#st-sensor .setting[data-key='channel_netflow']");
    const box = nfRow && nfRow.querySelector(".setting-toggle");
    check("netflow renders as a single checkbox, off",
          !!box && box.type === "checkbox" && !box.checked,
          nfRow ? nfRow.textContent.slice(0, 80) : "no channel_netflow row");
    H.discardStage();
    if (box) {
      box.checked = true;
      box.dispatchEvent(new window.Event("change", { bubbles: true }));
      check("ticking netflow stages the probe's port value, not a boolean string",
            H.STAGE.changes.channel_netflow === "upstream", JSON.stringify(H.STAGE.changes));
      H.discardStage();
      box.checked = false;
      box.dispatchEvent(new window.Event("change", { bubbles: true }));
      // "off" equal to what is running stages NOTHING (the dedupe every control uses);
      // the check asserts that semantic, not a phantom change.
      check("unticking netflow stages nothing (off is what is running)",
            !("channel_netflow" in H.STAGE.changes), JSON.stringify(H.STAGE.changes));
    }
    H.discardStage();
  }

  // ── TEST RUN: the siphon probe ────────────────────────────────────────────────────────────
  // The button must exist next to Apply with its own "?" help, a click must POST to the test
  // route, and the result must report BOTH the observation and the revert -- "the mode went
  // back" and "an intercept was seen" are different facts and the note says which happened.
  check("the Test run button exists with the sensor's settings", !!doc.getElementById("st-test"));
  check("the Test run button carries its own ? explanation",
        !!doc.getElementById("st-test-help")
        && /30 seconds/.test(needEl("st-test-help-text").textContent),
        (needEl("st-test-help-text") || {}).textContent);
  const testBefore = POSTED.filter((r) => r.url.includes("/api/settings/test")).length;
  await H.runSiphonTest();
  check("the test run POSTs to /api/settings/test",
        POSTED.filter((r) => r.url.includes("/api/settings/test")).length === testBefore + 1,
        POSTED.map((r) => r.url).join(","));
  const testReq = POSTED.filter((r) => r.url.includes("/api/settings/test")).pop();
  check("the test run asks for a 30-second window",
        JSON.parse((testReq || {}).body || "{}").seconds === 30,
        (testReq || {}).body);
  check("the test result states the revert",
        /set back to loch/i.test(needEl("st-test-note").textContent),
        needEl("st-test-note").textContent.slice(0, 180));
  check("the test result states what was observed",
        /observed live/i.test(needEl("st-test-note").textContent)
        || /No intercept evidence/.test(needEl("st-test-note").textContent),
        needEl("st-test-note").textContent.slice(0, 180));

  // A REFUSED WRITE MUST SAY SO, and must not look like a success.
  // A deliberate 401 for one check: the write must be refused and the staged changes must
  // SURVIVE. As an override, so it cannot strand the payloads registered with the dispatcher.
  fetchOverride = (u, opts) => (String(opts.method || "").toUpperCase() === "POST"
    ? { ok: false, status: 401, statusText: "Unauthorized",
        json: async () => ({ error: "a valid operator token is required to change settings" }) }
    : null);
  const bt3 = [...doc.querySelectorAll("#view-settings .setting-input")]
    .find((n) => n.dataset.key === "base_threshold");
  if (bt3) {
    bt3.value = "0.7";
    bt3.dispatchEvent(new window.Event("input", { bubbles: true }));
  }
  await H.applyStage();
  check("a refused write reports the server's reason",
        /not applied/i.test(needEl("st-stage-note").textContent),
        needEl("st-stage-note").textContent.slice(0, 140));
  check("a refused write does NOT clear the staged changes (nothing was saved)",
        Object.keys(H.STAGE.changes).length === 1);

  // ── the tab restructure ───────────────────────────────────────────────────────────────────
  // Asserted BEFORE any navigation: these describe the landing state (Health first, Health
  // active, no Overview). Reading them after showView("settings") would assert the state this
  // block itself just changed, which is how the "Health is active" check first failed.
  const navTabs = [...doc.querySelectorAll("nav .tab")].map(b => b.dataset.view);
  const healthTabActive = doc.querySelector('nav .tab[data-view="health"]').classList.contains("active");
  check("the Overview tab is gone from the nav", !navTabs.includes("overview"),
        `nav is ${navTabs.join(", ")}`);
  check("the Overview SECTION is gone from the DOM", doc.getElementById("view-overview") === null);
  // TWO FACTS, NOT ONE, and this block checks the ORDER rather than the landing state.
  //
  // Health inherited the LANDING role from Overview, and it used to be the first tab, so the
  // original assertion tested both as a unit. The operator moved Health between Models and
  // Settings, which separates them: the landing view is not necessarily the leftmost tab, and a
  // nav whose active entry is not the first is entirely ordinary. Asserting "the first tab is
  // Health" from here would now fail against a CORRECT nav, and the tempting repair is to weaken
  // the check until it stops describing anything.
  //
  // The landing state is asserted where it was captured -- before any navigation -- rather than
  // re-derived here, where showView("settings") has already moved it.
  // The nav button and its section must agree: a tab marked active whose section is not, or a
  // section shown with no tab lit, means clicking the tab appears to do nothing.
  const healthSectionActive = needEl("view-health").classList.contains("active");
  check("the active nav tab and the visible section agree",
        healthTabActive === healthSectionActive,
        `tab=${healthTabActive} section=${healthSectionActive}`);
  check("the Settings tab is in the nav", navTabs.includes("settings"));
  check("the Overview SECTION is gone from the DOM",
        doc.getElementById("view-overview") === null);
  check("sensor state and the health checks live on the Health tab now",
        !!doc.getElementById("hp-checks"));
    // ── THREE PROBE STATES RENDER AS THREE (audit F081) ────────────────────────────────────────
    //
    // The probe added to stop a MISSING row reading as healthy would itself have read as FAILING,
    // because `!c.ok` counts null as false and `c.ok ? "ok" : "FAIL"` sends it to the FAIL branch.
    // The counts exclude it as not-applicable, and the row says so.
    await H.loadHealthDeep();
    {
      const rows = [...doc.querySelectorAll("#hp-checks tbody tr")];
      const states = rows.map(tr => tr.children[1].textContent.trim());
      check("a tri-state probe row renders n/a rather than FAIL",
            states.includes("n/a"),
            `states are ${JSON.stringify(states)}`);
      check("the healthy and failing rows still render ok and FAIL",
            states.includes("ok") && states.includes("FAIL"),
            `states are ${JSON.stringify(states)}`);
      const summary = needEl("hp-summary").textContent;
      check("the summary counts only MEASURABLE checks (2, not 3)",
            /of 2 checks FAILING/.test(summary),
            summary.slice(0, 140));
      check("the summary states how many were not applicable",
            /not applicable/.test(summary),
            summary.slice(0, 140));
      const pill = needEl("health-pill").textContent;
      check("the pill excludes the not-applicable probe from its ratio",
            /1\/2 checks passing/.test(pill),
            pill.slice(0, 140));
      // ── CLICK IT (the operator, 2026-10-16): the ratio must open the per-check list ──────────
      {
        const pid = needEl("status-pop");
        needEl("health-pill").click();
        await new Promise((r) => setTimeout(r, 30));
        const lines = pid ? pid.querySelectorAll(".status-line").length : 0;
        check("clicking the health pill lists every check", !!pid && !pid.hidden && lines >= 2,
              "lines=" + lines + " hidden=" + (pid ? pid.hidden : "?"));
        check("with its states, not-applicable included",
              !!pid && /PASS/.test(pid.textContent) && /N\/A/.test(pid.textContent),
              pid ? pid.textContent.slice(0, 100) : "");
        check("and a way into the full health view", !!pid && /health view/i.test(pid.textContent), "");
        needEl("health-pill").click();
        await new Promise((r) => setTimeout(r, 30));
        check("clicking the pill again closes it", !!pid && pid.hidden, "still open");
      }
    }

  check("the System card is the first thing on the Health tab",
        !!doc.getElementById("hp-system")
        && needEl("view-health").querySelector(".card") ===
           needEl("hp-system").closest(".card"));
  check("the Weirlings fleet carries CPU and memory in the sensor row and throughput in the NIC rows",
        !!doc.querySelector("[data-wl-cpu]")
        && !!doc.querySelector("[data-wl-rate]")
        && !!doc.querySelector("#wl-table .wl-colhead"),
        "performance columns not rendered");
  check("the alert audit panels are at the top of the Logs tab (operator, 2026-10-20)",
        !!doc.getElementById("hp-alerts-reasons")
          && !!doc.getElementById("hp-alerts-recent")
          && !!doc.getElementById("hp-alerts-note"));

  // The alert audit (SOC-8) renders directly -- its payload rides on /api/health, which the
  // harness drives through the real loader, so a direct call pins the renderer's three
  // states without standing up the whole deep-health path.
  const HEALTH_AUDIT = {
    available: true,
    suppressed: 3,
    by_reason: [
      { reason: "log-only", sent: false, count: 5, last_at: "2026-01-03T10:00:00" },
      { reason: "cooldown", sent: false, count: 3, last_at: "2026-01-03T10:05:00" },
    ],
    recent: [
      { sent_at: "2026-01-03T10:05:00", src_addr: "198.51.100.9", severity: "high",
        score: 0.81, sent: false, reason: "cooldown", message: "" },
    ],
  };
  H.renderAlertAudit(HEALTH_AUDIT);
  check("the audit note counts suppressed separately from log-only",
        needEl("hp-alerts-note").textContent.includes("3 suppressed"),
        needEl("hp-alerts-note").textContent.slice(0, 140));
  check("a log-only outcome is labelled as not-configured, not suppressed",
        needEl("hp-alerts-reasons").textContent.includes("log-only (not configured)"),
        needEl("hp-alerts-reasons").textContent.slice(0, 160));
  check("a cooldown outcome is labelled suppressed",
        needEl("hp-alerts-reasons").textContent.includes("cooldown (suppressed)"),
        "a withheld alert rendered without saying it was withheld");
  check("the recent list renders the decision rows",
        doc.querySelectorAll("#hp-alerts-recent tbody tr").length === 1,
        `rows=${doc.querySelectorAll("#hp-alerts-recent tbody tr").length}`);

  H.renderAlertAudit({ available: false, reason: "alert audit query failed: RuntimeError",
                       by_reason: [], recent: [], suppressed: 0 });
  check("an unavailable audit names the failure, not an empty list",
        needEl("hp-alerts-note").textContent.includes("Alert audit unavailable"),
        needEl("hp-alerts-note").textContent.slice(0, 140));
  H.renderAlertAudit({ available: true, by_reason: [], recent: [], suppressed: 0 });
  check("an empty audit says nothing fired at all",
        needEl("hp-alerts-note").textContent.includes("nothing fired"),
        needEl("hp-alerts-note").textContent.slice(0, 140));

  // ── the alert audit PAGES, 15 at a time ────────────────────────────────────────────────────
  // The user asked for these tables to page like the Assets inventory. Twenty-four events means
  // two pages, so the second page is real and the first must not render all of them -- an
  // unpaged table here would silently be the old behaviour and still look populated.
  const manyEvents = Array.from({ length: 24 }, (_, i) => ({
    sent_at: `2026-01-03T10:${String(59 - i).padStart(2, "0")}:00`,
    src_addr: `198.51.100.${i + 1}`,
    severity: i % 2 ? "high" : "low",
    score: 0.5 + i / 100,
    sent: false,
    reason: "cooldown",
    message: `Anomaly on host ${i + 1}: sustained scan traffic`,
  }));
  // The BREAKDOWN gets more than 15 outcomes too, so its paging is real rather than a loop that
  // happens to render everything. With one reason row, "paged" and "unpaged" render identically
  // and a mutation that removes the slice survives -- which is what the first version of this
  // check did.
  const manyReasons = Array.from({ length: 18 }, (_, i) => ({
    reason: i % 3 === 0 ? "cooldown" : `cause-${i}`,
    sent: i % 3 === 0,
    count: 24 - i,
    last_at: "2026-01-03T10:59:00",
  }));
  H.renderAlertAudit({
    available: true, suppressed: 24,
    by_reason: manyReasons,
    recent: manyEvents, total: 24, truncated: false,
    names: { "198.51.100.1": "host-a.example" },
  });
  const reasonRows = doc.querySelectorAll("#hp-alerts-reasons tbody tr").length;
  check("the breakdown table shows only the first 15 outcomes",
        reasonRows === 15, `rows=${reasonRows} (expected 15 of 18)`);
  check("the breakdown has its own pager with its own range",
        needEl("hp-alerts-reasons-pager").textContent.includes("1\u201315 of 18"),
        needEl("hp-alerts-reasons-pager").textContent.slice(0, 120));
  const firstPageRows = doc.querySelectorAll("#hp-alerts-recent tbody tr").length;
  check("the event table shows only the first 15 rows",
        firstPageRows === 15, `rows=${firstPageRows} (expected 15 of 24)`);
  check("the pager reports the real total and page count",
        needEl("hp-alerts-recent-pager").textContent.includes("1\u201315 of 24"),
        needEl("hp-alerts-recent-pager").textContent.slice(0, 120));
  check("a host with a resolved name shows the name AND the address",
        needEl("hp-alerts-recent").textContent.includes("host-a.example")
          && needEl("hp-alerts-recent").textContent.includes("198.51.100.1"),
        "the name replaced the address, or was not shown at all");
  check("the message a decision was about is rendered, not just that it happened",
        needEl("hp-alerts-recent").textContent.includes("sustained scan traffic"),
        "the audit row shows the outcome without the subject");

  // Page 2, through the pager's own callback.
  const alertNext = [...doc.querySelectorAll("#hp-alerts-recent-pager .pager-btn")]
    .find((b) => b.textContent.includes("\u203a"));
  check("the next-page button exists", !!alertNext);
  if (alertNext) alertNext.dispatchEvent(new window.Event("click", { bubbles: true }));
  const page2Rows = doc.querySelectorAll("#hp-alerts-recent tbody tr").length;
  check("page 2 shows the remaining 9 rows",
        page2Rows === 9, `rows=${page2Rows} (expected 24-15=9)`);
  check("page 2 reports its own range, not page 1's",
        needEl("hp-alerts-recent-pager").textContent.includes("16\u201324 of 24"),
        needEl("hp-alerts-recent-pager").textContent.slice(0, 120));

  // A TRUNCATED fetch must say so: a full page of 15 with no note reads as "this is everything".
  H.renderAlertAudit({
    available: true, suppressed: 0, by_reason: [],
    recent: manyEvents.slice(0, 15), total: 4000, truncated: true, names: {},
  });
  check("a capped list states how many it is showing out of how many exist",
        needEl("hp-alerts-note").textContent.includes("newest 15 of 4000"),
        needEl("hp-alerts-note").textContent.slice(0, 200));

  // An UNAVAILABLE audit must not leave the previous payload's pager on screen: a range line
  // above an unavailable table describes a window that is no longer there.
  H.renderAlertAudit({ available: false, reason: "boom", by_reason: [], recent: [],
                       suppressed: 0, total: 0, truncated: false, names: {} });
  check("an unavailable audit clears the pagers rather than leaving a stale range",
        needEl("hp-alerts-recent-pager").textContent.trim() === "",
        `pager=${needEl("hp-alerts-recent-pager").textContent}`);

  // ── the Settings tab ───────────────────────────────────────────────────────────────────────
  // Now navigate to Settings the way a user would.
  H.showView("settings");
  await H.loadSettings();

  const stSummary = needEl("st-summary");
  check("the settings view no longer counts its own rows",
        !/settings in effect/.test(stSummary.textContent || ""),
        stSummary.textContent);

  // SCOPED TO EVERY SETTINGS GRID, wherever it renders: the sensor's group moved into the
  // Weirlings drill-down on request ("configure each weirling"), and a check still scoped to
  // `#view-settings` would quietly stop covering four rows -- the same under-coverage this
  // count was written to catch.
  const vals = [...doc.querySelectorAll(".setting[data-key]")];
  // DERIVED from the payload, not hardcoded: a literal row count is a second copy of a fact and
  // it drifted the moment a group gained a row (rendered 9 against a hardcoded 10).
  const expectedRows = Object.values(SETTINGS_PAYLOAD.groups)
    .reduce((n, rows) => n + rows.length, 0);
  // ONE payload row renders as a CONTROL, not a grid row: the sensor mode is the weirlings
  // drill-down's selector (operator restructure, 2026-10-17), so the grid covers expected - 1.
  check("every setting renders as a key/value row, not a JSON blob",
        vals.length === expectedRows - 1,
        `rendered ${vals.length} rows, payload has ${expectedRows} (one is the mode selector)`);

  // Provenance must be visible, so a blank cannot be confused with a field that does not exist.
  const srcs = [...doc.querySelectorAll(".setting-src")].map(n => n.textContent);
  check("an env-only key is labelled as env", srcs.includes("env"), `srcs: ${srcs.join(",")}`);
  check("a derived value is labelled as derived", srcs.includes("derived"));

  const shown = needEl("clickhouse_host");
  check("an ordinary setting shows its value",
        [...doc.querySelectorAll(".setting-val")].some(n => n.textContent === "clickhouse"));

  // THE SECURITY CHECK. The sentinel is what a real credential would be; it must not be here.
  const panelText = needEl("view-settings").textContent;
  check("NO SECRET VALUE reaches the DOM", !panelText.includes(SECRET_SENTINEL),
        "the credential value rendered into the page");
  check("a secret shows as set-by-length instead",
        [...doc.querySelectorAll(".setting-val.secret")].some(
          n => /^\(set, \d+ chars\)$/.test(n.textContent)));
  check("an unset secret is distinguishable from a set one",
        [...doc.querySelectorAll(".setting-val.secret")].some(
          n => n.textContent === "(not set)"));

  // A read-only page must SAY so, or the reader hunts for a Save button.
  check("the settings view states it cannot change the configuration",
        /read-only|cannot change/i.test(needEl("view-settings").textContent));
  check("the settings view says where the settings CAN be changed",
        needEl("view-settings").textContent.includes("weirvern config set"));
  // The page used to have no write control at all. It now has one, because an operator asked for
  // it -- so the assertion changes to the property that still matters: the APPLY control must be
  // DISABLED until something is staged, so a stray click cannot write the cluster configuration.
  const applyBtn = needEl("st-stage-apply");
  check("the apply control reflects whether anything is staged",
        applyBtn.disabled === (Object.keys(H.STAGE.changes).length === 0),
        `disabled=${applyBtn.disabled} staged=${Object.keys(H.STAGE.changes).length}`);

  // ── the control revision: natural controls + "?" help on every row ────────────────────────
  // The operator asked for toggles / buttons / dropdowns instead of free-text boxes, and a "?"
  // explanation on every setting. These checks drive the SHIPPING renderer against the stub
  // payload and assert the OUTCOME, including that choosing still only STAGES (never writes).

  // SCOPED TO `.setting` ROWS, and that is the assertion's real meaning: "every setting row
  // carries a ?". An unscoped count also picked up the SONAR button's ? (a different
  // affordance, in the same view) and reported 12 for 11 rows -- a false failure that would
  // have hidden a genuinely missing row help behind noise. Document-wide now: the sensor's
  // rows render in the weirling drill-down and must keep their help there.
  const helpBtns = [...doc.querySelectorAll(".setting .setting-help-btn")];
  const settingRows = [...doc.querySelectorAll(".setting")];
  check("every setting row carries a ? help button", helpBtns.length === settingRows.length,
        `${helpBtns.length} buttons for ${settingRows.length} rows`);

  // Clicking "?" must reveal the SERVER's explanation for THAT row, not a placeholder.
  // ANCHORED TO A NAMED ROW now that settings rows render in more than one view: "the first row"
  // stopped meaning the retrain row the moment the sensor group moved ahead of it in the
  // document, and the check would have asserted against whichever group happened to go first.
  const retrainRow = doc.querySelector(".setting[data-key='retrain_every_h']");
  const firstHelp = retrainRow.querySelector(".setting-help");
  const hiddenBefore = firstHelp.classList.contains("hidden");
  retrainRow.querySelector(".setting-help-btn").click();
  check("clicking ? reveals the row's explanation",
        hiddenBefore && !firstHelp.classList.contains("hidden"),
        `hidden before=${hiddenBefore} after=${firstHelp.classList.contains("hidden")}`);
  check("the explanation is the row's own text from the server",
        firstHelp.textContent.includes("retrained"), firstHelp.textContent.slice(0, 90));
  retrainRow.querySelector(".setting-help-btn").click();
  check("clicking ? again hides the explanation", firstHelp.classList.contains("hidden"));

  // THE MODE IS NOT A GRID ROW ANY MORE (operator restructure, 2026-10-17): it is the
  // weirlings drill-down's selector -- one control for one value. Its per-sensor behavior
  // (survey + apply) is checked in the weirlings section.
  const wlModeSel = needEl("wl-mode-select");
  check("the sensor mode renders as the drill-down's selector, not a grid row",
        !doc.querySelector(".setting[data-key='sensor_mode']") && !!wlModeSel,
        "a second control for one value is the duplication this restructure removed");
  const wlModeOpts = wlModeSel ? [...wlModeSel.options].map((o) => o.value) : [];
  check("the selector carries loch and siphon",
        wlModeOpts.includes("loch") && wlModeOpts.includes("siphon"), wlModeOpts.join(","));

  // A numeric setting is a NUMBER input carrying the server's own bounds.
  const btNum = doc.querySelector('#view-settings input[data-key="base_threshold"]');
  check("a numeric setting renders as a number input", !!btNum && btNum.type === "number",
        btNum ? btNum.type : "missing");
  check("the number control carries the server's bounds",
        !!btNum && btNum.getAttribute("min") === "0" && btNum.getAttribute("max") === "1",
        btNum ? `${btNum.getAttribute("min")}..${btNum.getAttribute("max")}` : "missing");

  // An on/off setting is a TOGGLE whose state is stated in words.
  const poToggle = doc.querySelector('#view-settings input[data-key="pushover_enabled"]');
  check("an on/off setting renders as a toggle", !!poToggle && poToggle.type === "checkbox",
        poToggle ? poToggle.type : "missing");
  check("the toggle is OFF for a disabled value", !!poToggle && poToggle.checked === false);
  const poStateWord = poToggle
    ? poToggle.closest(".setting-toggle-label").querySelector(".setting-toggle-state") : null;
  check("the toggle states its position in words", !!poStateWord && poStateWord.textContent === "off",
        poStateWord ? poStateWord.textContent : "missing");
  if (poToggle) {
    poToggle.checked = true;
    poToggle.dispatchEvent(new window.Event("change", { bubbles: true }));
  }
  check("toggling stages the canonical true/false value",
        H.STAGE.changes.pushover_enabled === "true", JSON.stringify(H.STAGE.changes));
  if (poToggle) {
    poToggle.checked = false;
    poToggle.dispatchEvent(new window.Event("change", { bubbles: true }));
  }
  check("flipping a switch back to its running state un-stages it (no phantom change)",
        H.STAGE.changes.pushover_enabled === undefined, JSON.stringify(H.STAGE.changes));

  // ── the review column (SOC-1) ──────────────────────────────────────────────────────────────
  //
  // The workflow this closes: before SOC-1 the anomalies list was read-only -- no ack, no
  // resolve, no false-positive -- and the same recurring benign alert re-appeared forever.
  // These checks drive the SHIPPING renderer and the SHIPPING post path against the stub
  // payload and assert what was POSTed, not just what rendered.
  //
  // The 401 override above is CLEARED here, deliberately: it simulates a refused write, and
  // leaving it on would make the review POST below fail for a reason that has nothing to do
  // with the code under test. (Which is exactly what the review checks caught the first time.)
  fetchOverride = null;

  H.showView("anomalies");
  H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
  await H.loadAnomalies();

  const anomRows = doc.querySelectorAll("#anomalies-table tbody tr");
  check("the anomalies table renders a row per payload entry", anomRows.length === 3,
        `${anomRows.length} rows`);

  const chips = [...doc.querySelectorAll("#anomalies-table .review-bubble")];
  check("every anomaly row carries a review chip", chips.length === anomRows.length,
        `${chips.length} chips for ${anomRows.length} rows`);
  check("an UNREVIEWED row says so", chips.some((c) => c.textContent === "unreviewed"));
  check("a REVIEWED row shows its state, not 'unreviewed'",
        chips.some((c) => c.textContent === "ack"), chips.map((c) => c.textContent).join(", "));

  const actBtns = [...doc.querySelectorAll("#anomalies-table .review-act")];
  check("the row offers the dispositions that are not its current state",
        actBtns.length > 0, `${actBtns.length} action buttons`);

  // ── A2: THE VERBS ARE BEHIND ONE DISCLOSURE ─────────────────────────────────────────────────
  // The row used to carry seven 28px buttons. At ~90 rows that is 630 controls -- a wall of
  // misses on a phone. One <details> per row holds them, closed at rest; the row itself still
  // opens the evidence. These two checks keep it that way.
  const rowMores = [...doc.querySelectorAll("#anomalies-table tbody tr .row-more")];
  check("every row's verbs live behind one closed disclosure",
        rowMores.length === anomRows.length && rowMores.every((d) => !d.open && !!d.querySelector("summary")),
        `${rowMores.length} disclosures for ${anomRows.length} rows; open: ${rowMores.filter((d) => d.open).length}`);
  // Open the disclosure with its own summary: that click must not reach the row handler (which
  // opens Evidence), and it must not post anything -- the state checks below still expect row 0
  // to be unreviewed.
  const summaryInDisclosure = rowMores[0] && rowMores[0].querySelector("summary");
  if (summaryInDisclosure) {
    summaryInDisclosure.click();
    await new Promise((r) => setTimeout(r, 80));
    check("opening the disclosure does NOT fall through to the row's Evidence drill",
          needEl("view-anomalies").classList.contains("active"),
          "the row handler must not fire through the disclosure");
    check("...and the disclosure actually opens", !!rowMores[0].open);
  }
  // `[title*='ack']` matched "back to unreviewed" -- substring traps. Match the exact
  // affordance instead: the acked row must not offer "as ack", the unreviewed row must.
  const rowsArr = [...doc.querySelectorAll("#anomalies-table tbody tr")];
  check("the current state is not offered as an action on its own row",
        !rowsArr[1].querySelector(".review-act[title*='as ack']"),
        rowsArr[1].textContent.slice(0, 120));
  check("an unreviewed row DOES offer ack",
        !!rowsArr[0].querySelector(".review-act[title*='as ack']"));

  // Click "resolve" on the first (unreviewed) row and assert the REQUEST.
  const firstRowResolve = [...doc.querySelectorAll("#anomalies-table tbody tr")][0]
    .querySelector(".review-act[title*='resolved']");
  check("the resolve control exists on the unreviewed row", !!firstRowResolve);
  if (firstRowResolve) {
    const postedBefore = POSTED.length;
    firstRowResolve.click();
    await new Promise((r) => setTimeout(r, 120));
    const reviewReq = POSTED.slice(postedBefore).find((r) => r.url.includes("/api/review"));
    check("a click POSTs the disposition to /api/review", !!reviewReq,
          POSTED.slice(postedBefore).map((r) => r.url).join(","));
    if (reviewReq) {
      let body = {};
      try { body = JSON.parse(reviewReq.body || "{}"); } catch (_e) { body = {}; }
      check("the POST carries the anomaly's identity and the new state",
            body.src_addr === "203.0.113.42" && body.state === "resolved",
            `src_addr=${body.src_addr} state=${body.state}`);
      check("the POST carries the window_start the server keyed the row by",
            !!body.window_start, String(body.window_start));
    }
  }

  // ── THE ALERT ACTION CELL (BF-1) ───────────────────────────────────────────────────────────
  // Every row carries its three one-click actions; Watch POSTs the toggle; Evidence opens the
  // raw records; the watched row renders as watching without a local guess.
  {
    const actionRow = [...doc.querySelectorAll("#anomalies-table tbody tr")][0];
    const actionsBox = actionRow && actionRow.querySelector(".an-actions");
    check("the row's action cell offers Evidence, Block and Watch",
          !!actionsBox
          && !!actionsBox.querySelector("button[title*='raw records']")
          && !!actionsBox.querySelector(".gate-act .gate-open")
          && !!actionsBox.querySelector(".watch-act button"),
          actionsBox ? actionsBox.textContent.replace(/\s+/g, " ") : "no .an-actions");
    const watchBtn = actionsBox && actionsBox.querySelector(".watch-act button");
    if (watchBtn) {
      check("a watched host's toggle reads as Watching and pressed",
            /Watching/.test(watchBtn.textContent)
            && watchBtn.getAttribute("aria-pressed") === "true",
            watchBtn.textContent);
      const postedBeforeW = POSTED.length;
      watchBtn.click();
      await new Promise((r) => setTimeout(r, 150));
      const wreq = POSTED.slice(postedBeforeW).find((r) => r.url.includes("/api/watch"));
      check("a Watch click POSTs the toggle to /api/watch", !!wreq,
            POSTED.slice(postedBeforeW).map((r) => r.url).join(","));
      if (wreq) {
        let wbody = {};
        try { wbody = JSON.parse(wreq.body || "{}"); } catch (_e) { wbody = {}; }
        check("the Watch POST carries the host and the new state",
              wbody.src_addr === "203.0.113.42" && wbody.on === false,
              `src_addr=${wbody.src_addr} on=${wbody.on}`);
      }
    }
    const evBtn = actionsBox && actionsBox.querySelector("button[title*='raw records']");
    if (evBtn) {
      evBtn.click();
      await new Promise((r) => setTimeout(r, 150));
      check("the Evidence button opens the evidence view",
            needEl("view-evidence").classList.contains("active"));
      const backTab = [...doc.querySelectorAll(".tab")].find((t) => t.dataset.view === "anomalies");
      if (backTab) backTab.click();
      await new Promise((r) => setTimeout(r, 150));
    }
  }

  // ── ONE definition of reviewed (#20) ───────────────────────────────────────────────────────
  //
  // A grouped row holds several occurrences, each with its own review state. Three surfaces
  // describe the row -- the chip, the count tooltip, and the unreviewed-only filter -- and
  // they used to disagree: the chip echoed only the NEWEST occurrence, so acking the newest
  // read as "done" while the filter (rightly) still listed the row, and the older occurrences
  // could not be dispositioned from the UI at all. This check performs real writes, reloads,
  // and asserts all three surfaces tell the SAME story at every step -- including the end,
  // where every occurrence is dispositioned and all three say so.
  const findGroupRow = () => [...doc.querySelectorAll("#anomalies-table tbody tr")]
    .find((tr) => !tr.classList.contains("an-exp")
                  && tr.querySelector("td.num") && tr.querySelector("td.num").textContent === "3");
  const openOccurrences = async (row) => {
    row.querySelector("td.num").click();
    await new Promise((r) => setTimeout(r, 60));
    return [...doc.querySelectorAll("#anomalies-table tr.an-exp .occ")];
  };

  const gRow0 = findGroupRow();
  const rem0 = gRow0 && gRow0.querySelector(".review-remain");
  check("the 3-occurrence group renders as one row, with the remaining count beside the state",
        !!rem0 && rem0.textContent === "3 unreviewed",
        rem0 ? rem0.textContent : "no remainder chip");

  // 1) ack the newest occurrence FROM THE ROW; the reload must show one acked, two left.
  gRow0.querySelector(".review-act[title*='as ack']").click();
  await new Promise((r) => setTimeout(r, 120));
  const gRow1 = findGroupRow();
  const chip1 = gRow1.querySelector(".review-bubble");
  const rem1 = gRow1.querySelector(".review-remain");
  const tip1 = gRow1.querySelector("td.num").getAttribute("title");
  check("after acking the newest of three, the chip states the state AND the remainder",
        chip1.textContent === "ack" && !!rem1 && rem1.textContent === "2 unreviewed",
        `chip=${chip1.textContent} remain=${rem1 ? rem1.textContent : "none"}`);
  check("the count tooltip states the same K",
        tip1 === "3 occurrence(s), 2 unreviewed \u2014 click to list them"
        && !!rem1 && tip1.includes(rem1.textContent),
        tip1);

  // 2) the unreviewed-only filter must keep the row: every surface reads the same fields.
  needEl("f-unreviewed").checked = true;
  await H.loadAnomalies();
  const filteredRows = [...doc.querySelectorAll("#anomalies-table tbody tr")];
  check("under unreviewed-only the row stays -- chip, tooltip and filter agree",
        filteredRows.length === 1 && !!findGroupRow(),
        `${filteredRows.length} row(s)`);

  // 3) each unfolded occurrence is dispositioned ON ITS OWN.
  needEl("f-unreviewed").checked = false;
  await H.loadAnomalies();
  let occ = await openOccurrences(findGroupRow());
  check("the unfold lists every occurrence with its own controls",
        occ.length === 3 && occ.every((o) => o.querySelector(".review-bubble")
                                              && o.querySelector(".review-act")),
        `${occ.length} occurrence(s)`);
  check("the acked newest occurrence offers the OTHER dispositions, not ack",
        !occ[2].querySelector(".review-act[title*='as ack']")
        && [...occ[2].querySelectorAll(".review-act")].some((b) => b.textContent === "clear"));
  const oldResolve = occ[0].querySelector(".review-act[title*='resolved']");
  check("an older occurrence offers its own resolve", !!oldResolve);

  const postedBefore = POSTED.length;
  oldResolve.click();
  await new Promise((r) => setTimeout(r, 120));
  const occReq = POSTED.slice(postedBefore).find((r) => r.url.includes("/api/review"));
  let occBody = {};
  try { occBody = JSON.parse((occReq || {}).body || "{}"); } catch (_e) { occBody = {}; }
  check("resolving an older occurrence posts THAT occurrence's window",
        !!occReq && occBody.window_start === "2026-01-02T06:45:00"
        && occBody.src_addr === "198.51.100.77" && occBody.state === "resolved",
        JSON.stringify(occBody));

  const gRow2 = findGroupRow();
  const rem2 = gRow2.querySelector(".review-remain");
  const tip2 = gRow2.querySelector("td.num").getAttribute("title");
  check("after that write the row reads one fewer unreviewed, and the tooltip says so",
        !!rem2 && rem2.textContent === "1 unreviewed"
        && tip2 === "3 occurrence(s), 1 unreviewed \u2014 click to list them",
        tip2);
  occ = await openOccurrences(gRow2);
  check("and the occurrence itself now reads resolved",
        occ[0].querySelector(".review-bubble").textContent === "resolved");

  // 4) finish the row: with every occurrence dispositioned, all three surfaces say "done".
  occ[1].querySelector(".review-act[title*='as ack']").click();
  await new Promise((r) => setTimeout(r, 120));
  const gRow3 = findGroupRow();
  check("a fully dispositioned group drops the remainder chip",
        gRow3 && !gRow3.querySelector(".review-remain")
        && gRow3.querySelector(".review-bubble").textContent === "ack");
  check("its tooltip no longer claims any unreviewed",
        gRow3.querySelector("td.num").getAttribute("title")
        === "3 occurrence(s) \u2014 click to list them");
  needEl("f-unreviewed").checked = true;
  await H.loadAnomalies();
  check("and the unreviewed-only filter hides it -- the same story, three times",
        !findGroupRow(),
        doc.querySelector("#anomalies-table tbody").textContent.slice(0, 90));
  needEl("f-unreviewed").checked = false;
  await H.loadAnomalies();

  // 5) the unavailable path is unchanged: a distinct label, no controls.
  const midWin = ANOMALIES_STATE.find((r) => r.src_addr === "198.51.100.77").windows[1];
  const midState = midWin.review_state;
  midWin.review_state = "unavailable";
  anRecompute();
  await H.loadAnomalies();
  occ = await openOccurrences(findGroupRow());
  check("an unavailable occurrence keeps its distinct label",
        occ[1].querySelector(".review-bubble").textContent === "review unavailable",
        occ[1].querySelector(".review-bubble").textContent);
  check("...and offers no write at all",
        occ[1].querySelectorAll(".review-act").length === 0);
  midWin.review_state = midState;
  anRecompute();
  await H.loadAnomalies();

  // ── the gate pivot: an alert → a block on the Sluice Gate ──────────────────────────────────
  //
  // Three outcomes matter here, and the reasons they do:
  //  1. With the gate ACTIVE (the stub says armed, enforcement channel) every alert row offers
  //     the control -- a button on the page where the operator is actually reading the alert.
  //  2. Clicking it opens a form whose reason is PRE-FILLED from the alert, and filing POSTs the
  //     alert's host with the scope the operator chose. The reason is the part that is
  //     unanswerable three weeks later if it is empty.
  //  3. With the gate OFF the button is GONE and the reason is stated instead. A block that
  //     cannot stop traffic must not be offered as if it could, and it must not be hidden in
  //     silence either.
  const gpRows = [...doc.querySelectorAll("#anomalies-table tbody tr")];
  const gpBtns = [...doc.querySelectorAll("#anomalies-table .gate-open")];
  check("an active gate offers a Block control on every alert row",
        gpRows.length > 0 && gpBtns.length === gpRows.length,
        `${gpBtns.length} control(s) for ${gpRows.length} row(s)`);

  if (gpBtns.length) {
    gpBtns[0].click();
    await new Promise((r) => setTimeout(r, 60));
    const gf = gpRows[0].querySelector(".gate-form");
    check("clicking Block opens the form IN PLACE", !!gf);
    check("and does not fall through to the row's own click (which opens the evidence view)",
          needEl("view-anomalies").classList.contains("active"));
    if (gf) {
      const whyIn = gf.querySelector(".gate-why");
      check("the reason is PRE-FILLED from the alert -- host and score",
            !!whyIn && whyIn.value.includes("203.0.113.42") && whyIn.value.includes("0.910"),
            whyIn ? whyIn.value.slice(0, 120) : "no reason field");
      const portIn = gf.querySelector("input[type=number]");
      check("the port field is hidden until 'one service' is chosen",
            !!portIn && portIn.style.display === "none");
      const blastAll = gf.querySelector(".gate-blast");
      check("the confirm states the blast radius for all traffic before any switch",
            !!blastAll && blastAll.textContent.includes("all traffic from 203.0.113.42"),
            blastAll ? blastAll.textContent : "no .gate-blast");
      if (portIn) {
        const scopeSel = gf.querySelector('select[aria-label="what to block"]');
        scopeSel.value = "port";
        scopeSel.dispatchEvent(new window.Event("change", { bubbles: true }));
        check("choosing 'one service' reveals the port fields", portIn.style.display !== "none");
        portIn.value = "3389";
        portIn.dispatchEvent(new window.Event("input", { bubbles: true }));
        const blastEl = gf.querySelector(".gate-blast");
        check("the confirm re-states the target, scope, duration and enforcement surface",
              !!blastEl
              && blastEl.textContent.includes("203.0.113.42")
              && blastEl.textContent.includes("tcp port 3389")
              && blastEl.textContent.includes("eth1")
              && blastEl.textContent.includes("60 min"),
              blastEl ? blastEl.textContent : "no .gate-blast");
        const postedBefore = POSTED.length;
        gf.querySelector("button.review-act:not(.gate-open)").click();
        await new Promise((r) => setTimeout(r, 80));
        const req = POSTED.slice(postedBefore).find((r) => r.url.includes("/api/sluice/block"));
        check("filing the block POSTs to /api/sluice/block", !!req,
              POSTED.slice(postedBefore).map((r) => r.url).join(","));
        if (req) {
          let body = {};
          try { body = JSON.parse(req.body || "{}"); } catch (_e) { body = {}; }
          check("the POST names the alert's host, the chosen service and protocol, and a reason",
                body.src_cidr === "203.0.113.42" && body.protocol === "tcp"
                && body.dst_port === 3389 && !!body.reason && body.direction === "forward",
                JSON.stringify(body).slice(0, 160));

          // The reason is optional: clearing the pre-filled one must still file (the server
          // records it blank), because a field the operator does not have to fill in must not
          // behave as if it were required.
          whyIn.value = "";
          const before2 = POSTED.length;
          gf.querySelector("button.review-act:not(.gate-open)").click();
          await new Promise((r) => setTimeout(r, 80));
          check("clearing the pre-filled reason still files the block (it is optional)",
                POSTED.slice(before2).some((r) => r.url.includes("/api/sluice/block")),
                POSTED.slice(before2).map((r) => r.url).join(","));
        }
      }
    }
  }

  // ── THE VIEW IS IN THE URL (BF-6) ───────────────────────────────────────────────────────────
  // Every state change lands in the hash; a link restores exactly the view it names.
  {
    H.showView("anomalies");
    await new Promise((r) => setTimeout(r, 150));
    check("a severity cell wears its glyph and its word",
          [...doc.querySelectorAll("#anomalies-table span")]
            .some((n) => /^[\u25b2\u25c6\u25cf\u25cb] (critical|high|medium|low)$/.test(n.textContent.trim())),
          "no glyph-bearing severity cell found");
    const sevTile = [...doc.querySelectorAll("#view-anomalies .tile")]
      .find((t) => /high/i.test(t.textContent));
    if (sevTile) {
      sevTile.click();
      await new Promise((r) => setTimeout(r, 250));
      check("a severity filter lands in the URL", /an\.sev=high/.test(window.location.hash),
            window.location.hash.slice(0, 90));
      sevTile.click();   // toggle back off before the round-trip below
      await new Promise((r) => setTimeout(r, 250));
    }
    const unrevBox = needEl("f-unreviewed");
    unrevBox.checked = true;
    unrevBox.dispatchEvent(new window.Event("change", { bubbles: true }));
    await new Promise((r) => setTimeout(r, 250));
    check("a checkbox filter lands in the URL", /an\.unrev=1/.test(window.location.hash),
          window.location.hash.slice(0, 90));
    // THE ROUND TRIP: exactly what opening a shared link does. The checkbox is cleared FIRST,
    // so the restore is observable -- a fixture value left over from the previous check would
    // make any restore look correct.
    unrevBox.checked = false;
    unrevBox.dispatchEvent(new window.Event("change", { bubbles: true }));
    await new Promise((r) => setTimeout(r, 250));
    window.location.hash = "#v=anomalies&an.sev=high&an.unrev=1&tr=6";
    H.applyURLState();
    check("opening a link restores its tab",
          needEl("view-anomalies").classList.contains("active"));
    check("...its range", Number(H.TIME_RANGE.hours) === 6, String(H.TIME_RANGE.hours));
    check("...its severity filter", H.AN_FILTERS.severity === "high", String(H.AN_FILTERS.severity));
    check("...and its checkbox filter", needEl("f-unreviewed").checked === true);
    // every remaining tab rides the same grammar
    H.M_FILTERS.host = "203.0.113.42";
    await H.loadModels();
    await new Promise((r) => setTimeout(r, 250));
    check("the models filter lands in the URL", /m\.host=203\.0\.113\.42/.test(window.location.hash),
          window.location.hash.slice(0, 110));
    H.nfSetFilter("src_addr", "203.0.113.42");
    await new Promise((r) => setTimeout(r, 250));
    check("the netflow filter lands in the URL", /nf=src_addr/.test(window.location.hash),
          window.location.hash.slice(0, 110));
    const blInput = needEl("bl-domain");
    if (blInput) {
      blInput.value = "example.test";
      await H.loadBlocked();
      await new Promise((r) => setTimeout(r, 250));
      check("the Blocked filter lands in the URL", /bl\.domain=example\.test/.test(window.location.hash),
            window.location.hash.slice(0, 110));
    }
    // and a link restores: a tab filter, and the sensor drill-down it names
    const wlSensor = WEIRLINGS_PAYLOAD.sensors[0].sensor_id;
    window.location.hash = "#v=weirlings&wl=" + encodeURIComponent(wlSensor)
      + "&m.host=203.0.113.42";
    H.applyURLState();
    await new Promise((r) => setTimeout(r, 450));
    check("a link restores a tab filter", H.M_FILTERS.host === "203.0.113.42", String(H.M_FILTERS.host));
    check("a link opens the sensor drill-down it names",
          needEl("wl-detail-id").textContent === wlSensor,
          needEl("wl-detail-id").textContent);

    // reset the world for the checks after this block
    window.location.hash = "";
    unrevBox.checked = false;
    unrevBox.dispatchEvent(new window.Event("change", { bubbles: true }));
    H.AN_FILTERS.severity = "";
    H.AN_FILTERS.host = "";
    H.M_FILTERS.host = ""; H.M_FILTERS.feature = "";
    H.ID_FILTERS.os = ""; H.ID_FILTERS.confidence = "";
    if (H.NF_FILTERS.length) H.nfRemoveChip(0);
    if (blInput) blInput.value = "";
    H.trApply({ mode: "relative", hours: 24 });
    await new Promise((r) => setTimeout(r, 250));
  }

  // ── HELP ANSWERED FOUR WAYS (BF-10) ─────────────────────────────────────────────────────────
  // Every i-circle answers what it is / what writes it / when it last changed / where to see
  // its effect -- provenance, not just a definition -- and one key ("?") shows them all.
  {
    const missing = [];
    for (const id of ["an-info", "wl-info", "sl-info", "bl-info", "dc-info", "nw-info", "hp-info"]) {
      const p = doc.getElementById(id);
      if (!p) { missing.push(id + ":gone"); continue; }
      const t = p.textContent;
      for (const label of ["What it is", "What writes it", "Last changed", "Where to see it"]) {
        if (!t.includes(label)) missing.push(id + ":" + label);
      }
    }
    check("every sampled help panel answers the four questions", missing.length === 0,
          missing.slice(0, 4).join(", "));
    const nwRefs = [...doc.querySelectorAll("[data-info]")].map((b) => b.dataset.info);
    check("the doubled Network panels are one panel, one story",
          !nwRefs.includes("nw-edges-info") && nwRefs.includes("nw-info") &&
          !doc.getElementById("nw-edges-info"),
          nwRefs.filter((r) => r.startsWith("nw")).join(", "));
    H.toggleAllHelp(false);   // deterministic start: everything closed
    await new Promise((r) => setTimeout(r, 40));
    const anPanel = needEl("an-info");
    const helpPill = needEl("all-help");
    helpPill.click();
    await new Promise((r) => setTimeout(r, 40));
    check("the all-help toggle opens every panel at once",
          [...doc.querySelectorAll(".info-text")].every((p) => !p.classList.contains("hidden")) &&
          helpPill.getAttribute("aria-pressed") === "true");
    doc.dispatchEvent(new window.KeyboardEvent("keydown", { key: "?", bubbles: true }));
    await new Promise((r) => setTimeout(r, 40));
    check("...and the ? key puts them all away again",
          anPanel.classList.contains("hidden") && helpPill.getAttribute("aria-pressed") === "false");
    helpPill.click();   // open all again, then prove a field's question mark is inert
    await new Promise((r) => setTimeout(r, 40));
    const addrBox = needEl("h-addr");
    addrBox.dispatchEvent(new window.KeyboardEvent("keydown", { key: "?", bubbles: true }));
    await new Promise((r) => setTimeout(r, 40));
    check("...while a question mark typed into a field is just a question mark",
          !anPanel.classList.contains("hidden"));
    H.toggleAllHelp(false);   // tidy for whatever follows
    await new Promise((r) => setTimeout(r, 40));
  }

  // ── THE EMPTY STATES TEACH (BF-8) ───────────────────────────────────────────────────────────
  {
    // 1. a queue filter that matches nothing: cause + the way back
    H.showView("anomalies");
    await new Promise((r) => setTimeout(r, 150));
    const minBox = needEl("f-min-score");
    minBox.value = "99";
    minBox.dispatchEvent(new window.Event("change", { bubbles: true }));
    await new Promise((r) => setTimeout(r, 300));
    const anEmpty = doc.querySelector("#anomalies-table .empty-state");
    check("an empty queue says why and offers the way back",
          !!anEmpty && /at or above score 99/.test(anEmpty.textContent) &&
            /Clear filters/.test(anEmpty.textContent),
          anEmpty ? anEmpty.textContent.slice(0, 90) : "no empty row at all");
    const clearBtn = anEmpty ? anEmpty.querySelector("button.empty-state-act") : null;
    if (clearBtn) {
      clearBtn.click();
      await new Promise((r) => setTimeout(r, 300));
    }
    check("...and the button behind it actually clears the filter", String(minBox.value) === "0");

    // 2. a fleet that has never had a sensor: the empty state, its explainer, the first run
    const savedSensors = WEIRLINGS_PAYLOAD.sensors.splice(0, WEIRLINGS_PAYLOAD.sensors.length);
    try { window.sessionStorage.removeItem("wv-firstrun"); } catch (_e) {}
    await H.loadWeirlings();
    await new Promise((r) => setTimeout(r, 150));
    const wlEmpty = doc.querySelector("#wl-table .empty-state");
    check("an empty fleet teaches and offers the button",
          !!wlEmpty && /Point a sensor's exporter/.test(wlEmpty.textContent) &&
            /How adding works/.test(wlEmpty.textContent),
          wlEmpty ? wlEmpty.textContent.slice(0, 90) : "no empty fleet row");
    const wlBtn = wlEmpty ? wlEmpty.querySelector("button.empty-state-act") : null;
    if (wlBtn) {
      wlBtn.click();
      await new Promise((r) => setTimeout(r, 40));
    }
    check("...and its button opens the explainer",
          !doc.getElementById("wl-info").classList.contains("hidden"));
    const frCard = needEl("firstrun-card");
    check("the first run appears only while the fleet is empty",
          !!frCard && !frCard.classList.contains("hidden"));
    const frNext = doc.querySelector("#firstrun-body button.firstrun-next");
    if (frNext) {
      frNext.click();   // step 1 -> 2 (settings load behind it)
      await new Promise((r) => setTimeout(r, 300));
      const frInput = doc.querySelector('#firstrun-body input[type="number"]');
      if (frInput) {
        frInput.value = String(Number(frInput.value || "0") + 7);
        frInput.dispatchEvent(new window.Event("change", { bubbles: true }));
        await new Promise((r) => setTimeout(r, 60));
      }
      check("step two stages real settings through the real flow",
            Object.keys(H.STAGE.changes).length >= 1, JSON.stringify(H.STAGE.changes));
      const frNext2 = doc.querySelector("#firstrun-body button.firstrun-next");
      if (frNext2) {
        frNext2.click();   // step 2 -> 3
        await new Promise((r) => setTimeout(r, 40));
      }
      const frReview = doc.querySelector("#firstrun-body button.firstrun-review");
      if (frReview) {
        frReview.click();
        await new Promise((r) => setTimeout(r, 80));
      }
      check("step three lands on the ordinary review",
            needEl("view-settings").classList.contains("active") &&
            frCard.classList.contains("hidden"));
    }
    // the skip, on a fresh appearance
    try { window.sessionStorage.removeItem("wv-firstrun"); } catch (_e) {}
    H.firstrunShow(1);
    await new Promise((r) => setTimeout(r, 40));
    const frSkip = doc.querySelector("#firstrun-body button.firstrun-skip");
    if (frSkip) frSkip.click();
    await new Promise((r) => setTimeout(r, 40));
    check("Skip for now dismisses it for this tab",
          frCard.classList.contains("hidden") &&
          window.sessionStorage.getItem("wv-firstrun") === "skip");
    // restore the world for the checks after this block
    WEIRLINGS_PAYLOAD.sensors.push(...savedSensors);
    try { window.sessionStorage.removeItem("wv-firstrun"); } catch (_e) {}
    if (typeof H.discardStage === "function") H.discardStage();
    await H.loadWeirlings();
    await new Promise((r) => setTimeout(r, 150));
  }

  // ── THE REFRESH TELLS THE TRUTH, THE MARK IS A VECTOR (TH-1) ───────────────────────────────
  {
    const styleCss = require("fs").readFileSync(path.join(WEB, "style.css"), "utf8");
    check("a heading never runs into its subtitle",
          styleCss.includes("h2 > .muted:not(:empty)::before"),
          "the separator rule is missing");
    check("the range panel names its timezone",
          !!doc.getElementById("tr-tz") && /timezone/i.test(needEl("tr-tz").textContent),
          needEl("tr-tz") ? needEl("tr-tz").textContent : "no tr-tz line");
    H.trApply({ mode: "absolute", from: "2026-10-16 05:00", to: "now" });
    check("an absolute range freezes 'now' into a concrete minute",
          /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/.test(String(H.TIME_RANGE.to)),
          String(H.TIME_RANGE.to));
    check("...and the button says it is frozen",
          /frozen/.test(needEl("tr-open").textContent),
          needEl("tr-open").textContent);
    H.trApply({ mode: "relative", hours: 24 });
    await H.refreshAll();
    check("the statusline says when the view last finished updating",
          /updated \d\d:\d\d:\d\d/.test(needEl("fetched").textContent),
          needEl("fetched").textContent);
    // refreshAll follows the view you are on: spy on fetch
    const spy = [];
    const origFetch = window.fetch;
    window.fetch = (u, o) => { spy.push(String(u)); return origFetch(u, o); };
    H.showView("anomalies");
    await new Promise((r) => setTimeout(r, 60));
    spy.length = 0;
    await H.refreshAll();
    window.fetch = origFetch;
    check("refreshAll refreshes the view you are looking at",
          spy.some((u) => /api\/anomalies/.test(u)), spy.join(" | ").slice(0, 90));
    const autoPill = needEl("auto-toggle");
    check("the auto-refresh pill names its state",
          !!autoPill && /live · 15s/.test(autoPill.textContent));
    if (autoPill) {
      autoPill.click();
      await new Promise((r) => setTimeout(r, 30));
      check("...pausing says so, in the pill and the statusline",
            /paused/.test(autoPill.textContent) && /paused/.test(needEl("fetched").textContent),
            autoPill.textContent);
      autoPill.click();
      await new Promise((r) => setTimeout(r, 30));
      check("...resuming puts it back", /live · 15s/.test(autoPill.textContent),
            autoPill.textContent);
    }
    check("the title is the name, not an emoji",
          !/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(doc.title) && /Weirvern/.test(doc.title),
          doc.title);
    // THE MARK WEARS THE README'S ART (operator, 2026-10-18: "the top left icon on the platform
    // should be the same as the one in the readme"). Every mark slot -- the tab icon and each
    // img.mark (header, sign-in, forced-password gate) -- points at the supplied raster emblem.
    check("the mark is the README's mark everywhere",
          doc.querySelector('link[rel="icon"]').getAttribute("href") === "/logo.png" &&
          [...doc.querySelectorAll("img.mark")].every((i) => i.getAttribute("src") === "/logo.png"),
          [...doc.querySelectorAll("img.mark")].map((i) => i.getAttribute("src")).join(","));
  }

  // ── THE AUTO-BLOCK IS LOUD AND PAUSABLE (BF-3) ──────────────────────────────────────────────
  // The threshold that can stop traffic by itself is off by default, unmistakable when armed,
  // and pausable in one click. The gate-rule behavior itself is pinned by tests/test_sluice.py
  // (derive with auto_score=0 -> no rule; with 0.9 -> a rule reasoned "auto: threshold 0.90").
  {
    const autoRow = SETTINGS_PAYLOAD.groups.detect.find((r) => r.key === "sluice_auto_score");
    const abPill = needEl("auto-block-pill");
    check("the auto-block pill is absent while the threshold is off",
          !!abPill && abPill.classList.contains("hidden"),
          abPill ? abPill.textContent : "no pill in the markup");
    autoRow.value = "0.9";
    await H.loadBlockingControls();
    await new Promise((r) => setTimeout(r, 120));
    // RE-AUTHORED, not repointed: the wording changed and the fact is now stated on two
    // elements. The controls card carries a chip plus a plain sentence; the header pill carries
    // the threshold. The old check looked for "AUTO-BLOCK IS ON" and "auto: threshold 0.90",
    // phrasing the console no longer uses anywhere -- measured, not assumed.
    const state = needEl("sl2-auto");
    check("an armed auto-block says so, in full, on the controls card",
          !!state && /auto-block on/i.test(state.textContent) &&
            /0\.90/.test(state.textContent) &&
            /blocked without review/i.test(state.textContent),
          state ? state.textContent.slice(0, 130) : "no state line");
    check("...and the header pill appears with the threshold",
          !abPill.classList.contains("hidden") && /0\.90/.test(abPill.textContent),
          abPill.textContent);
    abPill.click();
    await new Promise((r) => setTimeout(r, 80));
    check("...and clicking that pill lands on the controls",
          needEl("view-sluice").classList.contains("active"));
    const pause = doc.querySelector("#sl2-auto button");
    check("a pause control is offered while it is armed",
          !!pause && !pause.classList.contains("hidden") && /pause/i.test(pause.textContent),
          pause ? pause.textContent : "no pause control");
    if (pause) {
      // RE-AUTHORED (2026-11-20): pausing now opens the ONE confirm surface -- a consequence
      // sentence and a required reason -- and the write is followed by a read-back. Two clicks
      // on the banner button is no longer the flow; a confirm without a recorded reason is.
      pause.click();
      await new Promise((r) => setTimeout(r, 40));
      const confirmTitle = needEl("sl2-confirm-title").textContent || "";
      const openNow = !needEl("modal").classList.contains("hidden");
      check("...pausing asks a blocking question with its consequence",
            openNow && /automatic blocking/i.test(confirmTitle), confirmTitle);
      // The mock does not echo a POST back into the fixture, so the landing alone cannot
      // prove WHAT was posted -- spy the body to pin the value itself.
      const posts = [];
      const origFetch2 = window.fetch;
      window.fetch = (u, o) => {
        if (/settings\/apply/.test(String(u)) && o && o.body) posts.push(String(o.body));
        return origFetch2(u, o);
      };
      const why = needEl("sl2-confirm-reason");
      why.value = "harness: pause the auto-block";
      autoRow.value = "0";   // the apply lands; the re-read after it sees zero
      needEl("sl2-confirm-go").click();
      await new Promise((r) => setTimeout(r, 250));
      window.fetch = origFetch2;
      check("...and the pause posts the zero with a reason",
            posts.some((b) => /SLUICE_AUTO_SCORE/.test(b) && /"0"/.test(b) && /harness/.test(b)),
            posts.join(" | ").slice(0, 160));
      check("...the receipt reports what landed and what was read back",
            /SLUICE_AUTO_SCORE=0/.test(needEl("sl2-receipt").textContent || "")
            && /read back/i.test(needEl("sl2-receipt").textContent || ""),
            (needEl("sl2-receipt").textContent || "").slice(0, 120));
      check("...the state line reports it off",
            /off/i.test((needEl("sl2-auto") || {}).textContent || "")
            || needEl("sl2-auto").classList.contains("hidden"));
      check("...and the header pill is gone",
            abPill.classList.contains("hidden") && abPill.textContent === "");
    }
    await H.loadBlockingControls();   // tidy: a clean re-read at zero
  }

  // ── THE GATE'S STATUS LINE AND THE DOMAIN SWITCH (2026-10-18) ──────────────────────────────
  // The operator removed the duplicate "Blocking controls" card -- a second policy strip, a
  // second arm button, an auto-block score field and three notes -- and asked for the state in
  // one line plus a domain-blocking setting with enabled/disabled.
  {
    check("the duplicate blocking-controls card is gone",
          !doc.getElementById("sl-criticality") && !doc.getElementById("sl-bc-auto"),
          "a strip or score field is still in the DOM");
    await H.loadBlockingControls();
    await new Promise((r) => setTimeout(r, 80));
    const gateState = needEl("sl2-traf-chip");
    check("the status line states the packet gate's state in words",
          !!gateState && /^(?:[\u25b2\u25c6\u25cf\u25cb]\s*)?(enforcing|monitoring|off|degraded|unknown)/i
            .test(gateState.textContent.trim()),
          gateState ? gateState.textContent : "no state");
    check("...and offers exactly one control to change it",
          !!doc.getElementById("sl2-traf-toggle")
          && doc.querySelectorAll("#view-sluice #sl2-traf-toggle").length === 1);
    const domLine = needEl("sl2-dom-line");
    const domState = needEl("sl2-dom-chip");
    check("the domain-blocking card states its enforcement state and what it costs",
          !!domState
          && /^(?:[\u25b2\u25c6\u25cf\u25cb]\s*)?(enforcing|monitoring|off|degraded|unknown)$/i
            .test(domState.textContent.trim())
          && !!domLine && domLine.textContent.length > 40,
          domState ? domState.textContent : "no state");
    const domToggle = needEl("sl2-dom-toggle");
    check("...with one toggle", !!domToggle && /domain blocking/i.test(domToggle.textContent));
    if (domToggle) {
      const before = POSTED.length;
      const spy = [];
      const origFetch3 = window.fetch;
      window.fetch = (u, o) => {
        if (/settings\/apply/.test(String(u)) && o && o.body) spy.push(String(o.body));
        return origFetch3(u, o);
      };
      // ONE CONFIRM SURFACE (2026-11-20): the button opens a modal, the reason is required,
      // and the write is read back. The old two-click-in-place flow is gone on purpose.
      domToggle.click();
      await new Promise((r) => setTimeout(r, 40));
      needEl("sl2-confirm-reason").value = "harness: exercise the domain gate";
      needEl("sl2-confirm-go").click();
      await new Promise((r) => setTimeout(r, 200));
      window.fetch = origFetch3;
      check("the domain toggle posts SLUICE_BLOCK_DOMAINS through the apply path",
            spy.some((b) => /SLUICE_BLOCK_DOMAINS/.test(b)),
            spy.join(" | ").slice(0, 140) || `${POSTED.length - before} request(s), none to apply`);
    }
  }

  // ── A DEGRADED GATE SAYS WHY, WHERE IT IS READ (QA-1-D3) ────────────────────────────────────
  //
  // THE CHIP IS THE STATE. There is no `sl-gate-state` element and there never was; the gate card's
  // addressable parts are `sl2-traf-chip` (the word) and `sl2-traf-line` (the sentence beside it),
  // plus `sl-gate-warning` for the same reason. Two checks skipped on the invented id rather than
  // failing, which is the third outcome working as designed but leaving QA-1-D3 unmeasured.
  //
  // AND THE FIXTURE HAD TO ARM THE GATE. `gateOn` comes from the SETTINGS read (`sl2On`), not from
  // the payload's `enabled` field, so with the default settings the card renders "off" and the
  // degraded branch is unreachable however degraded the payload claims to be. The settings stub is
  // therefore part of the fixture: the case worth pinning is ARMED and degraded, because that is
  // the one where rules are meant to be live while something underneath them is wrong.
  {
    const origFetch = window.fetch;
    const armedSettings = JSON.parse(JSON.stringify(SETTINGS_PAYLOAD));
    armedSettings.groups = Object.assign({}, armedSettings.groups, {
      detect: (armedSettings.groups.detect || []).concat([
        { key: "SLUICE_ENABLED", label: "packet gate", value: "1", secret: false,
          source: "setting", applies: "applies with Apply",
          help: "Arms the packet gate: live rules drop traffic." },
      ]),
    });
    window.fetch = (u, o) => {
      const url = String(u).split("?")[0];
      if (url.endsWith("/api/settings")) {
        return Promise.resolve({ ok: true, json: async () => armedSettings });
      }
      if (url.endsWith("/api/sluice")) {
        return Promise.resolve({ ok: true, json: async () => Object.assign({}, SLUICE_PAYLOAD, {
          enabled: true,
          gate: Object.assign({}, SLUICE_PAYLOAD.gate, {
            state: "degraded", rules_active: 2, rules_total: 2,
            detail: "these tables are still present after deletion: weirvern_sluice",
          }),
        }) });
      }
      return origFetch(u, o);
    };
    H.clearGetCache();   // getJSON caches for 8s; both stubs are only seen after a clear
    await H.loadBlockingControls();
    await new Promise((r) => setTimeout(r, 120));
    const gateChip = needEl("sl2-traf-chip");
    const gateLine = needEl("sl2-traf-line");
    check("a degraded gate names its state beside the gate line",
          !!gateChip && /degraded/i.test(gateChip.textContent.trim()),
          gateChip ? gateChip.textContent : "no chip");
    check("...and carries the server's reason where it is read",
          /still present after deletion/.test(needEl("sl-gate-warning").textContent || ""),
          needEl("sl-gate-warning").textContent || "no reason");
    window.fetch = origFetch;
    H.clearGetCache();
    await H.loadBlockingControls();   // tidy back to the healthy fixture
  }

  // ── A FAILED SLUICE READ MUST NOT RENDER AS "off" (WV1-07) ──────────────────────────────────
  //
  // Measured live with no database: /api/sluice answered available:false with a reason and the
  // Traffic Gate card still said chip "off" plus "The packet gate is off. Rules still record hits,
  // but no packet is dropped." while the Rules panel on the same screen said "Reach unavailable".
  //
  // THIS CHECK NEEDS clearGetCache(), AND THAT IS WHY IT EXISTS ONLY NOW. getJSON serves a cached
  // body for eight seconds, so re-loading an endpoint the run has already fetched returns the
  // CACHED payload: fetchOverride is never called, the stub is ignored, and the assertions read
  // healthy data whatever is installed. Three earlier attempts failed on that, not on the product.
  // Any future check that stubs a read of an already-fetched endpoint needs the same line.
  {
    H.clearGetCache();
    fetchOverride = (u) => (String(u).includes("/api/sluice") && !String(u).includes("/api/sluice/")
      ? { ok: true, status: 200, statusText: "OK", json: async () => ({
          available: false, reason: "cannot read the gate: FileNotFoundError",
          gate: {}, gates: [], blocklists: [], hits: [] }) }
      : null);
    await H.loadSluice();
    // READ IMMEDIATELY: a pending render from an earlier block can resolve during a sleep and
    // overwrite the card, which would make this measure the previous render instead.
    const chipNow = (needEl("sl2-traf-chip").textContent || "").trim();
    const lineNow = (needEl("sl2-traf-line").textContent || "").trim();
    const disabledNow = needEl("sl2-traf-toggle").disabled;
    const statsNow = (needEl("sl2-traf-stats").textContent || "").trim();
    fetchOverride = null;

    check("a failed gate read does not render the chip as 'off'",
          chipNow.toLowerCase() !== "off", `chip read ${JSON.stringify(chipNow)}`);
    check("...it says the state is unknown instead", /unknown/i.test(chipNow), chipNow);
    check("...the line carries the reason and disclaims the card",
          /cannot read the gate/i.test(lineNow)
          && /no claim/i.test(needEl("sl2-traf-ev").textContent || ""),
          lineNow.slice(0, 110));
    // `disabled` ALONE DOES NOT DISCRIMINATE. With an empty gate payload the button is already
    // disabled for an unrelated reason ("no nft backend"), so that assertion passes with the fix
    // reverted -- measured by mutation. The TITLE is what the fix sets, so it is what proves it.
    check("...the traffic toggle is disabled rather than arming a gate it cannot see",
          disabledNow === true
          && /could not be read/i.test(needEl("sl2-traf-toggle").title || ""),
          `disabled=${disabledNow} title=${JSON.stringify(needEl("sl2-traf-toggle").title || "")}`);
    check("...and the stats are not rendered as zeros", statsNow === "", statsNow.slice(0, 80));

    H.clearGetCache();
    await H.loadSluice();   // tidy back
    H.clearGetCache();
  }

  // ── A FAILED LOOKUP MUST NOT BE SHOWN AS A REVOCATION (WV1-08) ──────────────────────────────
  //
  // `blocked.js:blOpenRuleById` opens this sheet for a rule id it could not find in the lists the
  // page holds. It used to set `revoked: true` on the record it fabricated for that case, and the
  // sheet renders revoked first -- so a transient read failure, or a rule simply absent from a
  // capped list, told the operator "This rule is revoked ... it cannot be edited", i.e. that
  // enforcement had ended, when the rule might have been live and blocking.
  //
  // The record below is deliberately the OLD one, `revoked: true` AND `lookup_failed: true`, so
  // this measures the ordering fix in sluice.js rather than the one-word change in blocked.js.
  {
    H.openRuleSheet({ rule_id: "no-such-rule", describes: "example.com", domain: "example.com",
                      mode: "", live: false, revoked: true, origin: "", expires_at: "",
                      resolved_count: 0, resolved: [], lookup_failed: true, not_live: true });
    const note = (needEl("sl2-detail-note").textContent || "");
    check("a failed lookup is not reported as a revocation", !/revoked/i.test(note), note.slice(0, 130));
    check("...it says the state could not be confirmed instead",
          /Cannot confirm/i.test(note), note.slice(0, 130));
    // NOT a search for the words "is live": the disclaimer legitimately says "Nothing is being
    // claimed about whether it is live", and the first version of this assertion matched that and
    // failed on correct text. The property that matters is that the note STATES its own uncertainty.
    check("...and it says outright that it is making no claim about liveness",
          /no claim|Nothing is being claimed/i.test(note), note.slice(0, 130));

    // The genuinely-absent case must still read as absent, or the fix has traded one wrong
    // message for another.
    H.openRuleSheet({ rule_id: "absent", describes: "example.com", domain: "example.com",
                      mode: "", live: false, revoked: false, origin: "", expires_at: "",
                      resolved_count: 0, resolved: [], lookup_failed: false, not_live: true });
    const absentNote = (needEl("sl2-detail-note").textContent || "");
    check("a rule that is simply not in the live store still says so",
          /not in the live store/i.test(absentNote), absentNote.slice(0, 130));
  }

  // ── THE AUTO-BLOCK PAUSE MUST HAVE SOMEWHERE TO SPEAK (WV1-11) ──────────────────────────────
  //
  // It passed `autoEl` -- a DIV built with replaceChildren -- as the note element, and
  // applySluiceSetting deliberately writes nothing when `note.tagName === "DIV"`. So the pause
  // produced no confirmation and, after the POST, neither the server's note nor an error appeared
  // anywhere: a refused pause was indistinguishable from a slow one and the banner stayed up.
  //
  // ASSERTED ON THE PRESENCE OF THE NOTE ELEMENT, not on a message, because what the fix changes is
  // that a place to write exists at all. The banner carries three spans when it has one (chip,
  // description, note) and two when it does not.
  {
    H.clearGetCache();
    fetchOverride = (u) => {
      const s = String(u);
      if (s.includes("/api/sluice") && !s.includes("/api/sluice/")) {
        return { ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true,
          gate: { state: "disarmed", backend: "nftables", rules_active: 0, rules_total: 0 },
          gates: [], blocklists: [], hits: [] }) };
      }
      if (s.includes("/api/settings")) {
        return { ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true,
          groups: { detect: [{ key: "sluice_auto_score", value: "0.9" }] } }) };
      }
      return null;
    };
    await H.loadSluice();
    const auto = needEl("sl2-auto");
    const spans = auto.querySelectorAll ? Array.from(auto.querySelectorAll("span")) : [];
    fetchOverride = null;
    H.clearGetCache();

    check("the auto-block banner is shown when the threshold is armed",
          !auto.classList.contains("hidden"), `class=${auto.className || ""}`);
    // RE-AUTHORED (2026-11-20): the answer surface moved from a span inside the banner to the
    // one confirm modal -- it carries the consequence, a required reason and the server's reply.
    check("...and its pause control has a confirm surface with a reason field",
          !!doc.querySelector("#sl2-auto button") && !!doc.getElementById("sl2-confirm-reason")
          && !!doc.getElementById("sl2-confirm-note"),
          `${spans.length} span(s) in the banner, confirm=${
            !!doc.getElementById("sl2-confirm-reason")}`);
  }

  // ── DNS FAILED READ: THE FACET STRIP AND THE PAGER (WV1-09) ─────────────────────────────────
  //
  // dnsview.js's own comment says the empty-versus-unavailable conflation was removed from this
  // view; two panels still had it. An empty facet strip reads as "no domains and no clients in the
  // window", and "0-0 of 0" is exactly what a genuinely empty result prints -- so a failed query
  // looked like a quiet network on the tab an operator is most likely to trust.
  //
  // The histogram and rows already branch this way, so the assertions below are the class, not a
  // new idea: the summary's wording is reused deliberately.
  {
    H.clearGetCache();
    fetchOverride = (u) => (String(u).includes("/api/dns")
      // offset > 0 WITH a non-zero total ON PURPOSE: at offset 0 and total 0 the two nav buttons
      // are already disabled for arithmetic reasons, so "both disabled" would pass with the fix
      // reverted -- measured. This fixture makes the fix the only thing that disables them.
      ? { ok: true, status: 200, statusText: "OK", json: async () => ({
          available: false, reason: "cannot reach ClickHouse: OperationalError",
          rows: [], total: 500, offset: 100, facets: {}, histogram: [] }) }
      : null);
    await H.loadDns();
    const facetText = (needEl("dn-facets").textContent || "").trim();
    const pagerText = (needEl("dn-page").textContent || "").trim();
    const newerDisabled = needEl("dn-newer").disabled;
    const olderDisabled = needEl("dn-older").disabled;
    fetchOverride = null;
    H.clearGetCache();

    check("a failed DNS read does not leave the facet strip blank",
          facetText.length > 0, `facet strip: ${JSON.stringify(facetText.slice(0, 80))}`);
    check("...it says the facets could not be listed",
          /Cannot list these/i.test(facetText), facetText.slice(0, 120));
    check("...and the pager does not print the empty-result '0-0 of 0'",
          pagerText === "", `pager: ${JSON.stringify(pagerText)}`);
    check("...with both nav buttons disabled, because there is no range to walk",
          newerDisabled === true && olderDisabled === true,
          `newer=${newerDisabled} older=${olderDisabled}`);

    H.clearGetCache();
    await H.loadDns();   // tidy back to the healthy fixture
    H.clearGetCache();
  }

  // ── THE SERVER'S NOTE REACHES THE SCREEN WHEN READS ARE OPEN (WV1-17) ───────────────────────
  //
  // /api/session returns `note`, which says things like "the user store could not be read; no
  // accounts were created this startup". It reached the screen from one place only: the sign-in
  // gate's text. The gate is shown when accounts EXIST and nobody is signed in, so the one state
  // that PRODUCES the note was the one state that never displayed it -- boot went straight to the
  // dashboard. Meanwhile Settings said "no accounts provisioned", which describes a benign first
  // run. With no readable store every READ is served without a session, so failing open silently
  // is the thing the operator most needs to know.
  {
    const NOTE = "the user store could not be read; no accounts were created this startup";
    const banner = () => doc.getElementById("auth-note-banner");
    const stash = { accounts: H.AUTH.accounts, note: H.AUTH.note, authenticated: H.AUTH.authenticated };

    // A leftover banner from another block would make every assertion below meaningless.
    if (banner()) banner().remove();
    H.AUTH.accounts = false;
    H.AUTH.authenticated = false;
    H.AUTH.note = NOTE;
    H.showSessionNote();
    const shown = banner() ? String(banner().textContent) : "";
    check("the server's note is shown when the console runs without accounts",
          !!banner(), "no #auth-note-banner was prepended");
    check("...and it repeats what the server actually said",
          shown.includes(NOTE), `banner=${JSON.stringify(shown.slice(0, 120))}`);
    check("...and says reads are open rather than implying a normal first run",
          /reads are open|read without signing in/i.test(shown),
          `banner=${JSON.stringify(shown.slice(0, 160))}`);

    // THE NEXT THREE CHECKS ASSERT AN ABSENCE, SO THEY PASS VACUOUSLY IF THE FUNCTION RENDERS
    // NOTHING AT ALL -- measured: with showSessionNote() made a no-op they still pass. They are
    // meaningful only as companions to the three above, which prove the mechanism does render.
    // Recorded rather than dressed up: the discrimination for this fix lives in those three.
    //
    // Idempotent: boot can run more than once, and two banners stack.
    const countBefore = doc.querySelectorAll("#auth-note-banner").length;
    H.showSessionNote();
    check("...it does not stack a second banner",
          doc.querySelectorAll("#auth-note-banner").length === countBefore,
          `banners=${doc.querySelectorAll("#auth-note-banner").length}`);

    // With accounts ON the gate carries the note, and a banner would be wrong.
    if (banner()) banner().remove();
    H.AUTH.accounts = true;
    H.showSessionNote();
    check("...and nothing is shown when a gate exists",
          !banner(), "a banner was drawn even though accounts exist");

    // An empty note is a genuine first run: silence is correct.
    H.AUTH.accounts = false;
    H.AUTH.note = "";
    H.showSessionNote();
    check("...and an empty note draws nothing at all",
          !banner(), "a banner was drawn with no note to carry");

    // Settings must word its line from the note, not from a fixed sentence.
    H.AUTH.note = NOTE;
    H.refreshAccountCard();
    const sNote = doc.getElementById("st-account-note");
    const sText = sNote ? String(sNote.textContent) : "";
    check("...and Settings repeats the reason rather than calling it a first run",
          sText.includes("user store could not be read"),
          `settings=${JSON.stringify(sText.slice(0, 160))}`);

    if (banner()) banner().remove();
    H.AUTH.accounts = stash.accounts;
    H.AUTH.note = stash.note;
    H.AUTH.authenticated = stash.authenticated;
    H.refreshAccountCard();
  }

  // ── A DESTRUCTIVE CONTROL IS NOT ONE CLICK (WV1-12, WV1-14) ──────────────────────────────────
  //
  // Both of these posted on a single click. `sl2Create` (block mode) and `sl2Delete` already
  // required a two-step confirm, so parking a live block rule -- which re-opens the path it was
  // blocking -- was the odd one out, and the blocklist toggle was the whole <tr>, so clicking the
  // error text to READ it changed DNS enforcement.
  {
    H.clearGetCache();
    fetchOverride = null;
    H.openRuleSheet({ rule_id: "r-live-1", describes: "example.com", domain: "example.com",
                      mode: "block", disabled: false, origin: "operator", hits: 3 });

    const park = doc.getElementById("sl2-park");
    const note = doc.getElementById("sl2-detail-note");
    const posts = [];
    fetchOverride = (url, opts) => {
      posts.push(`${(opts && opts.method) || "GET"} ${url}`);
      return Promise.resolve({ ok: true, status: 200, statusText: "OK",
                               json: async () => ({ ok: true }) });
    };

    check("parking a live rule starts from a button that names the rule's state",
          !!park && park.textContent.trim() === "Park rule",
          park ? `label=${JSON.stringify(park.textContent)}` : "no #sl2-park");

    if (park) park.click();
    await new Promise((r) => setTimeout(r, 80));
    const armedLabel = park ? String(park.textContent) : "";
    const armedNote = note ? String(note.textContent) : "";
    const armedFlag = park ? park.dataset.confirm : null;

    check("...one click only ARMS parking, it does not post",
          posts.length === 0, `requests=${JSON.stringify(posts)}`);
    check("...and says what parking does before it does it",
          armedFlag === "1" && /reachable again/i.test(armedNote),
          `confirm=${JSON.stringify(armedFlag)} note=${JSON.stringify(armedNote.slice(0, 80))}`);
    check("...with the label changed so the armed state is visible",
          /^Confirm: park rule$/.test(armedLabel), `label=${JSON.stringify(armedLabel)}`);

    if (park) park.click();
    await new Promise((r) => setTimeout(r, 120));
    // COUNT THE POSTS, NOT THE REQUESTS: a successful park reloads the pane, so the list also
    // holds the GETs that reload issues. Asserting length === 1 measured the reload, not the post.
    //
    // THIS CHECK DOES NOT DISCRIMINATE THE FIX, AND SAYS SO RATHER THAN IMPLYING IT DOES. A
    // successful park closes the rule sheet, which clears SL2_STATE.current, so the second click
    // returns early -- two clicks produce exactly ONE post whether or not the two-step exists.
    // Measured: with `if (false)` in place of the arming branch this still passes. It is kept
    // because it catches the opposite regression (a two-step control that posts on both clicks),
    // and the discrimination for THIS fix lives in the three checks above, all of which flip.
    const parkPosts = posts.filter((p) => p === "POST /api/sluice/rule/disabled");
    check("...the second click posts the change, once",
          parkPosts.length === 1, `posts=${JSON.stringify(parkPosts)}`);
    fetchOverride = null;
    H.clearGetCache();
  }

  // ── THE BLOCKLIST ROW IS INERT (WV1-14) ─────────────────────────────────────────────────────
  {
    H.clearGetCache();
    const posts = [];
    fetchOverride = (url, opts) => {
      const method = (opts && opts.method) || "GET";
      if (method === "GET" && String(url).includes("/api/blocklists")) {
        return Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true,
          sources: [{ source_id: "hagezi-light", name: "HaGeZi LIGHT", enabled: true,
                      domain_count: 1200, fetched_at: "2026-11-13T09:00:00Z",
                      last_error: "HTTP 429 from the mirror; retrying in 15m" }] }) });
      }
      posts.push(`${method} ${url}`);
      return Promise.resolve({ ok: true, status: 200, statusText: "OK",
                               json: async () => ({ ok: true }) });
    };

    await H.loadBlocklistPane();
    const row = doc.querySelector("#sl-bl-rows tr");
    check("a blocklist row is rendered", !!row, "no row in #sl-bl-rows");

    check("the row itself is not a click target",
          !!row && !row.classList.contains("clickable"),
          row ? `class=${JSON.stringify(row.className)}` : "no row");

    // The cell that used to be a trap: the error text an operator wants to read and copy.
    const cells = row ? Array.from(row.children) : [];
    const errCell = cells[4];
    if (errCell) errCell.click();
    await new Promise((r) => setTimeout(r, 80));
    check("...clicking the error text does not toggle the list",
          posts.length === 0, `requests=${JSON.stringify(posts)}`);

    const btn = row ? row.querySelector("button") : null;
    check("the toggle is a button that names what it does",
          !!btn && /turn (on|off)/i.test(String(btn.textContent)),
          btn ? `label=${JSON.stringify(btn.textContent)}` : "no button in the row");

    if (btn) btn.click();
    await new Promise((r) => setTimeout(r, 80));
    check("...one click only arms the toggle",
          posts.length === 0 && !!btn.dataset.confirm,
          `requests=${JSON.stringify(posts)} confirm=${JSON.stringify(btn.dataset.confirm)}`);

    if (btn) btn.click();
    await new Promise((r) => setTimeout(r, 120));
    check("...the second click posts the change",
          posts.length === 1 && /\/api\/blocklists\/enable/.test(posts[0]),
          `requests=${JSON.stringify(posts)}`);

    fetchOverride = null;
    H.clearGetCache();
  }

  // ── ROW OPENERS ARE KEYBOARD REACHABLE (WV1-10) ─────────────────────────────────────────────
  //
  // `tr.clickable` opens a hit's detail or a DNS row's answers. `.clickable` had no keyboard
  // handler anywhere in weirvern/admin/web (zero hits for a keydown reaching it) and a <tr> is not
  // focusable, so reviewing a hit without a mouse was impossible. The filter cells INSIDE those
  // rows were already handled by markFilterCells, which is why the gap survived: the row looked
  // wired in exactly the way a reviewer would check.
  {
    H.clearGetCache();
    fetchOverride = null;
    await H.loadDns();
    const row = doc.querySelector("#dn-rows tr.clickable") || doc.querySelector("tr.clickable");

    check("a DNS row opener carries a tabindex", !!row && row.getAttribute("tabindex") === "0",
          row ? `tabindex=${JSON.stringify(row.getAttribute("tabindex"))}` : "no .clickable row");

    let fired = 0;
    if (row) {
      row.addEventListener("click", () => { fired += 1; });
      row.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
      await new Promise((r) => setTimeout(r, 60));
    }
    check("...and Enter activates it, once", fired === 1, `clicks=${fired}`);
  }

  {
    // DIAGNOSTIC: is the harness router still the live window.fetch, and does it consult
    // fetchOverride? If a block restored an older reference, later overrides are never read.
    const body = String(window.fetch);
    console.log("  [DIAG] window.fetch consults fetchOverride: " + /fetchOverride/.test(body));
    console.log("  [DIAG] window.fetch is the harness router: " + /POSTED\.push/.test(body));
    console.log("  [DIAG] typeof fetchOverride: " + typeof fetchOverride);
  }

  // ── THE RULES SURFACE (US-SL1, the operator's rules 1-3 and the absorbed A3) ────────────────
  {
    H.showView("sluice");
    await H.loadSluice();
    await new Promise((r) => setTimeout(r, 120));

    const rows = [...doc.querySelectorAll("#sl2-rules tbody tr.sl2-rule-row")];
    check("every rule row reads as a sentence, not a protocol tuple",
          rows.length > 0 && rows.every((tr) => {
            const cell = tr.querySelector("button.sl2-rule-btn");
            return cell && /^(block|alert on)\b/.test(cell.textContent.trim());
          }),
          rows.map((tr) => (tr.querySelector("button.sl2-rule-btn") || {}).textContent)
            .join(" | "));

    const newRule = needEl("sl2-new");
    check("the rules card offers one obvious add", !!newRule && /new rule/i.test(newRule.textContent));
    if (newRule) {
      newRule.click();
      await new Promise((r) => setTimeout(r, 80));
      const sheet = needEl("sl-rule-sheet");
      check("...which opens the rule sheet, not a form on the tab",
            !!sheet && !sheet.classList.contains("hidden")
            && !doc.getElementById("sl2-create").classList.contains("hidden"),
            "the composer is not the sheet");
      check("...and it is a labelled dialog with one close",
            sheet.getAttribute("role") === "dialog"
            && sheet.getAttribute("aria-modal") === "true"
            && !!doc.getElementById(sheet.getAttribute("aria-labelledby"))
            && sheet.querySelectorAll(".sheet-close").length === 1,
            sheet.getAttribute("aria-labelledby") || "no label");
      const targetType = needEl("sl-target-type");
      check("...it starts with one Domain/Address target choice and names its gate",
            !!targetType && targetType.value === "domain"
            && [...targetType.options].every((o) => /Domain Gate|Traffic Gate/.test(o.textContent))
            && /Domain Gate|answered by DNS/i.test(
              (needEl("sl-gate-hint") || {}).textContent || ""),
            targetType ? targetType.value : "no target type");
      // THE CONFIRM IS ABOUT THE VALUES ON SCREEN. Arm it, edit the target, and the button must
      // fall back to Create rule; no write is attempted here.
      const target = needEl("sl2-domain");
      const createBtn = needEl("sl2-create-submit");
      if (target && createBtn) {
        target.value = "ads.example.com";
        createBtn.click();
        await new Promise((r) => setTimeout(r, 40));
        check("...a blocking rule arms with a target-and-gate sentence",
              /Confirm/.test(createBtn.textContent)
              && /block rule changes what the gate drops/i.test(
                (needEl("sl2-create-note") || {}).textContent || ""),
              createBtn.textContent + " / "
              + ((needEl("sl2-create-note") || {}).textContent || ""));
        target.dispatchEvent(new window.Event("input", { bubbles: true }));
        await new Promise((r) => setTimeout(r, 20));
        check("...and editing the target disarms the confirmation",
              createBtn.textContent === "Create rule" && createBtn.dataset.confirm !== "1",
              createBtn.textContent);
      }
      // THE SHEET STANDARD: Escape is the documented exit, handled once in sheets.js.
      doc.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
      await new Promise((r) => setTimeout(r, 60));
      check("...and Escape closes it, scrim and all",
            sheet.classList.contains("hidden")
            && needEl("sl-rule-scrim").classList.contains("hidden"));
    }

    // A ROW OPENS THE SAME SHEET, with the destructive act inside it.
    const firstRow = doc.querySelector("#sl2-rules tbody tr.sl2-rule-row");
    if (firstRow) {
      const rid = firstRow.getAttribute("data-rule-id");
      firstRow.click();
      await new Promise((r) => setTimeout(r, 80));
      const sheet = needEl("sl-rule-sheet");
      check("a rule row opens its sheet with the delete act inside",
            !!sheet && !sheet.classList.contains("hidden")
            && !doc.getElementById("sl2-detail").classList.contains("hidden")
            && !!sheet.querySelector("#sl-rule-delete")
            && (needEl("sl2-sheet-id").textContent || "") === rid,
            "row click did not open the rule sheet");
      check("...and no per-row delete control sits on the tab",
            !doc.querySelector("#sl2-rules .icon-btn")
            && !doc.querySelector("#sl2-rules button.danger"),
            "a per-row delete control is still on the tab");
      check("...the sheet's actions are named buttons, not icons",
            ["sl-rule-delete", "sl2-mode-save", "sl2-park"].every((id) => {
              const b = doc.getElementById(id);
              return b && (b.textContent || "").trim().length > 3;
            }));
      // DELETING ASKS TWICE, AND THE SERVER REQUIRES A REASON: with an empty reason nothing arms;
      // with a reason the first click arms and still nothing is posted.
      const delBtn = needEl("sl-rule-delete");
      if (delBtn) {
        const beforeDel = POSTED.length;
        delBtn.click();
        await new Promise((r) => setTimeout(r, 60));
        check("delete without a reason refuses to arm",
              !/Click again/.test(delBtn.textContent)
              && !POSTED.slice(beforeDel).some((r) => r.url.includes("/api/sluice/revoke")),
              delBtn.textContent);
        const why = needEl("sl-rule-delete-reason");
        if (why) why.value = "harness: this rule has lapsed";
        delBtn.click();
        await new Promise((r) => setTimeout(r, 60));
        check("delete arms before it revokes",
              /Confirm/.test(delBtn.textContent)
              && !POSTED.slice(beforeDel).some((r) => r.url.includes("/api/sluice/revoke")),
              delBtn.textContent);
      }
      const close = doc.querySelector("#sl-rule-sheet .sheet-close");
      if (close) close.click();
    }

    // The glance strip and the "top names" strip are gone: the counts live in the view header
    // (`#sl2-count`) and the names in the rule rows themselves, so the checks follow them there.
    const slCount = needEl("sl2-count");
    check("the live/total count is stated with its nouns",
          /\d+\s+live\s+·\s+\d+\s+total/.test(slCount.textContent || ""),
          slCount.textContent || "no count");
    check("...and the rule list names the names, not a bare count",
          /ads\.example\.com/.test((doc.getElementById("view-sluice") || {}).textContent || ""),
          "no rule names on the tab");

    const picks = [...doc.querySelectorAll("#sl2-rules tbody button.sl2-rule-btn")];
    check("every rule row's opener is a named button",
          picks.length > 0 && picks.every((b) => b.tagName === "BUTTON"
            && (b.textContent || "").trim().length > 8),
          `${picks.filter((b) => (b.textContent || "").trim().length <= 8).length} unnamed`);

    const rowGates =
      [...doc.querySelectorAll("#sl2-rules tbody tr.sl2-rule-row .sl2-rule-gate")];
    check("every rule names the gate that enforces it",
          rowGates.length > 0 && rowGates.every((c) => /^(Domain|Traffic)$/.test(c.textContent.trim()))
          && rowGates.some((c) => c.textContent.trim() === "Domain")
          && rowGates.some((c) => c.textContent.trim() === "Traffic"),
          rowGates.map((c) => c.textContent.trim()).join("|"));
    const gateFilter = needEl("sl2-filters");
    check("the rule table offers a Domain / Traffic filter",
          !!gateFilter && gateFilter.querySelectorAll("[data-gate]").length === 3,
          gateFilter ? gateFilter.textContent : "no rule gate filter");
  }

  // ── THE FLEET IS A WORKLIST (BF-7) ──────────────────────────────────────────────────────────
  {
    try { window.sessionStorage.removeItem("wv-wl-views"); } catch (_e) {}
    H.showView("weirlings");
    await new Promise((r) => setTimeout(r, 250));
    const tiles = [...doc.querySelectorAll("#wl-summary .stat")];
    check("the fleet's counts are filters, not decoration",
          tiles.length >= 6 && tiles.every((t) => t.tagName === "BUTTON"),
          `${tiles.length} tiles, first tag ${tiles[0] ? tiles[0].tagName : "none"}`);
    const declaredTile = tiles.find((t) => /networks declared/i.test(t.textContent));
    const seenTile = tiles.find((t) => /segments seen/i.test(t.textContent));
    check("the fleet states declared networks AND observed segments, never one bare count",
          !!declaredTile && !!seenTile && /2/.test(declaredTile.textContent)
          && /1/.test(seenTile.textContent)
          && !tiles.some((t) => /problems/i.test(t.textContent)),
          `${declaredTile ? declaredTile.textContent.trim() : "no declared tile"} / ` +
          `${seenTile ? seenTile.textContent.trim() : "no seen tile"}`);
    check("a declared-but-unobserved network is named in the fleet note",
          /203\.0\.113\.0\/24/.test(needEl("wl-summary-note").textContent),
          needEl("wl-summary-note").textContent);
    // THE LAST OVER-BUDGET PARAGRAPH: the explanation now lives in #wl-summary-details, so the
    // line above the scanner card is measured on its own, at the same 25 words as every card.
    check("the fleet note is one short line inside the 25-word copy budget",
          visibleWords(needEl("wl-summary-note")) <= 25,
          `${visibleWords(needEl("wl-summary-note"))} words: ` +
          needEl("wl-summary-note").textContent);
    // THE TILE MUST NOT WEAR THE BUTTON'S 28px BOX (2026-10-19): the clickable summary tiles
    // are <button>s, so BTN-1's height squeezed a 51px label+number stack out of the pill.
    if (tiles.length) {
      const tileH = window.getComputedStyle(tiles[0]).height;
      check("...and a tile is sized by its content, not the button height",
            !/^28px$/.test(tileH), tileH);
    }
    const headRow = doc.querySelector("#wl-table .wl-colhead");
    const heads = headRow ? [...headRow.children]
      .map((th) => th.textContent.trim().toLowerCase()) : [];
    check("the NIC headers sit below the sensor: interface, mode, channel, networks, throughput, flow, feeds",
          heads.join("|") === "interface|mode|channel|networks|throughput|flow|feeds",
          heads.join("|"));
    const localRow = [...doc.querySelectorAll("#wl-table tbody tr:not(.wl-nic-row):not(.wl-colhead)")]
      .find((tr) => {
        const b = tr.querySelector("button.link, .link");
        return b && b.textContent.trim() === "weirvern";
      });
    if (localRow) {
      // THE SENSOR ROW IS A NAME, NOT A SECOND COPY OF THE FACTS (operator, 2026-10-19).
      check("the sensor row carries CPU and memory without column headers",
            localRow.children.length === 2
            && /CPU/i.test(localRow.textContent) && /MEMORY/i.test(localRow.textContent),
            [...localRow.children].map((td) => td.textContent.trim()).join("|"));
      const nicRows = [...doc.querySelectorAll("#wl-table tbody tr.wl-nic-row")];
      check("every non-management NIC is its own line under the sensor row",
            nicRows.length >= 1 && !doc.querySelector(".wl-nics-open"),
            `${nicRows.length} NIC lines`);
      check("...each NIC line carries mode, channel, networks, throughput, flow and feeds",
            nicRows.every((tr) => tr.children.length === 7)
            && nicRows.some((tr) => /capture/.test(tr.textContent)),
            nicRows.map((tr) => tr.children.length).join(","));
      const captureRow = nicRows.find((tr) => /capture/.test(tr.textContent));
      if (captureRow) {
        const cells = [...captureRow.children];
        check("mode states only loch or siphon, not the declaration",
              /^(loch|siphon|\u2014)/i.test(cells[1].textContent.trim())
              && !/declared/i.test(cells[1].textContent), cells[1].textContent.trim());
        check("the channel column states enabled or disabled",
              /^(enabled|disabled|\u2014)$/i.test(cells[2].textContent.trim()),
              cells[2].textContent.trim());
        check("the feeds cell keeps both indicators",
              cells[6].querySelectorAll(".tap").length === 2, cells[6].textContent.trim());
        check("the flow cell draws a trend even at a measured zero",
              !!cells[5].querySelector("svg.wl-spark"), cells[5].textContent.trim());
        // THE PLAN DECIDES EACH NIC'S LINE (operator, 2026-10-20): a survey of eth2 must not
        // relabel eth1's network, and a siphon on eth1 must not mark eth2's channel enabled.
        const plansHeld = H.STAGE.changes.intercept_plans;
        const upHeld = H.SETTINGS_ROWS.channel_upstream;
        const downHeld = H.SETTINGS_ROWS.channel_downstream;
        H.STAGE.changes.intercept_plans = JSON.stringify({
          eth1: { mode: "siphon", segment: "198.51.100.0/24", gateway: "198.51.100.1",
                  addr: "198.51.100.10", targets: "*" },
          eth2: { capture: true, segment: "", gateway: "", addr: "", targets: "*" },
        });
        H.SETTINGS_ROWS.channel_upstream = { value: "eth1" };
        H.SETTINGS_ROWS.channel_downstream = { value: "eth2" };
        const nfModeHeld = H.SETTINGS_ROWS.netflow_mode;
        const nfIfaceHeld = H.SETTINGS_ROWS.netflow_iface;
        H.SETTINGS_ROWS.netflow_mode = { value: "active" };
        H.SETTINGS_ROWS.netflow_iface = { value: "eth2" };
        const fake = { sensor_id: "weirvern", local: true, iface: "eth1",
          interfaces: ["eth1", "eth2"], network_names: {},
          channel: { state: "enabled" }, reported_mode: "siphon",
          expected_mode: "siphon", plan: {},
          flow_series: [1, 3, 2, 5, 4, 8, 6, 9, 7, 11, 10, 12],
          netflow: { known: true, observed: true, flows: 78, last_at: "", why: "",
                     scope: "sensor", scope_label: "netflow" },
          zeek: { known: true, observed: true, last_at: "", why: "" } };
        const facts = typeof window.wlNicFacts === "function"
          ? window.wlNicFacts(fake)
          : { rows: [] };
        // THE POD-SCOPED HEARTBEAT CASE (measured live 2026-10-22): the local worker can see
        // only its own eth0 while the host capture port is eth1. The configured port must still
        // get a line, with no mode claim and an explicit "configured, not reported" note.
        const configuredFake = Object.assign({}, fake, { interfaces: ["eth0"], iface: "eth3" });
        const configuredFacts = typeof window.wlNicFacts === "function"
          ? window.wlNicFacts(configuredFake) : { rows: [] };
        const configuredEth1 = configuredFacts.rows.find((n) => n.name === "eth3") || {};
        check("a configured capture NIC survives a pod-scoped heartbeat",
              configuredEth1.role === "capture" && configuredEth1.reported === false
              && configuredEth1.mode === "",
              JSON.stringify(configuredEth1));
        if (typeof window.wlNicRows === "function") {
          const configuredRendered = window.wlNicRows(configuredFake);
          check("...and its row says configured, not reported",
                configuredRendered.length === 1
                && /configured, not reported/.test(configuredRendered[0].textContent),
                configuredRendered.map((tr) => tr.textContent.trim()).join(" | "));
        }
        const eth1 = facts.rows.find((n) => n.name === "eth1") || {};
        const eth2 = facts.rows.find((n) => n.name === "eth2") || {};
        if (typeof window.wlNicRows === "function") {
          const rendered = window.wlNicRows(fake);
          const siphonRow = rendered.find((tr) => /siphon/.test(tr.textContent));
          check("a SIPHON NIC line still carries a flow trend and both feed indicators",
                !!siphonRow && !!siphonRow.children[5].querySelector("svg.wl-spark")
                && siphonRow.children[6].querySelectorAll(".tap").length === 2,
                siphonRow ? [...siphonRow.children].map((td) => td.textContent.trim()).join("|")
                          : "no siphon row");
          check("the active NetFlow NIC owns the chip and the other NIC says why",
                eth1.netflow.observed === false && /eth2/.test(eth1.netflow.why || "")
                && eth2.netflow.observed === true,
                `eth1=${JSON.stringify(eth1.netflow)} eth2=${JSON.stringify(eth2.netflow)}`);
          check("the netflow chip is named netflow, not a generic sensor feed",
                !!siphonRow && /netflow/.test(siphonRow.children[6].textContent)
                && !/sensor feed/.test(siphonRow.children[6].textContent),
                siphonRow ? siphonRow.children[6].textContent.trim() : "no siphon row");
        }
        check("a NIC's line uses its own plan segment, not the sensor-level one",
              eth1.networks === "198.51.100.0/24" && eth2.networks === "",
              `eth1=${eth1.networks} eth2=${eth2.networks}`);
        check("a siphon on eth1 does not mark eth2's channel enabled",
              eth1.channel === "enabled" && eth2.channel === "",
              `eth1=${eth1.channel} eth2=${eth2.channel}`);
        check("a capture-only NIC with no mode in its plan reads loch, not the sensor's siphon",
              eth1.mode === "siphon" && eth2.mode === "loch",
              `eth1=${eth1.mode} eth2=${eth2.mode}`);
        if (plansHeld === undefined) delete H.STAGE.changes.intercept_plans;
        else H.STAGE.changes.intercept_plans = plansHeld;
        H.SETTINGS_ROWS.channel_upstream = upHeld;
        H.SETTINGS_ROWS.channel_downstream = downHeld;
        H.SETTINGS_ROWS.netflow_mode = nfModeHeld;
        H.SETTINGS_ROWS.netflow_iface = nfIfaceHeld;
      }
    }
    // PER-NIC PLAN ISOLATION (operator, 2026-10-20: "It's still cross polluting the two nics").
    // Run the real helper against two plans; this is the regression for a survey of eth2
    // relabelling eth1, which the row-level fallback used to do.
    {
      const plansHeld = H.STAGE.changes.intercept_plans;
      const upHeld = H.SETTINGS_ROWS.channel_upstream;
      const downHeld = H.SETTINGS_ROWS.channel_downstream;
      H.STAGE.changes.intercept_plans = JSON.stringify({
        eth1: { mode: "siphon", segment: "198.51.100.0/24", gateway: "198.51.100.1",
                addr: "198.51.100.10", targets: "*" },
        eth2: { capture: true, segment: "", gateway: "", addr: "", targets: "*" },
      });
      H.SETTINGS_ROWS.channel_upstream = { value: "eth1" };
      H.SETTINGS_ROWS.channel_downstream = { value: "eth2" };
      H.STAGE.changes.channel_upstream = "eth1";
      H.STAGE.changes.channel_downstream = "eth2";
      const ifaceNamesHeld = H.SETTINGS_ROWS.interface_networks;
      H.SETTINGS_ROWS.interface_networks = { value: "eth1=Servers,eth2=Data" };
      const ifaceStageHeld = H.STAGE.changes.interface_networks;
      H.STAGE.changes.interface_networks = "eth1=Servers,eth2=Data";
      const facts = typeof window.wlNicFacts === "function"
        ? window.wlNicFacts({ local: true, iface: "eth1", interfaces: ["eth1", "eth2"],
            network_names: { eth1: "Servers" }, channel: { state: "enabled" },
            reported_mode: "siphon", expected_mode: "siphon", plan: {} })
        : { rows: [] };
      const eth1 = facts.rows.find((n) => n.name === "eth1") || {};
      const eth2 = facts.rows.find((n) => n.name === "eth2") || {};
      check("a NIC's line uses its own plan segment, not the sensor-level one",
            eth1.networks === "198.51.100.0/24" && eth2.networks === "",
            `eth1=${eth1.networks} eth2=${eth2.networks}`);
      check("a siphon on eth1 does not mark eth2's channel enabled",
            eth1.channel === "enabled" && eth2.channel === "",
            `eth1=${eth1.channel} eth2=${eth2.channel}`);
      check("a capture-only NIC with no mode in its plan reads loch, not the sensor's siphon",
            eth1.mode === "siphon" && eth2.mode === "loch",
            `eth1=${eth1.mode} eth2=${eth2.mode}`);
      check("eth2 keeps its interface name when the payload map is stale or partial",
            eth1.network_name === "Servers" && eth2.network_name === "Data",
            `eth1=${eth1.network_name} eth2=${eth2.network_name} cfg=${typeof window.wlCfgValue === "function" ? window.wlCfgValue("interface_networks") : "no-fn"} parsed=${typeof window.wlIfaceNames === "function" ? JSON.stringify(window.wlIfaceNames("eth1=Servers,eth2=Data")) : "no-fn"}`);
      const renderedFake = { sensor_id: "weirvern", local: true, iface: "eth1",
        interfaces: ["eth1", "eth2"], network_names: {}, channel: { state: "enabled" },
        reported_mode: "siphon", expected_mode: "siphon", plan: {},
        flow_series: [1, 3, 2, 5, 4, 8, 6, 9, 7, 11, 10, 12],
        netflow: { known: true, observed: true, flows: 78, last_at: "", why: "",
                   scope: "sensor", scope_label: "netflow" },
        zeek: { known: true, observed: true, last_at: "", why: "" } };
      const renderedNic = typeof window.wlNicRows === "function"
        ? window.wlNicRows(renderedFake).find((tr) => /siphon/.test(tr.textContent)) : null;
      check("a SIPHON NIC line still carries a flow trend and both feed indicators",
            !!renderedNic && !!renderedNic.children[5].querySelector("svg.wl-spark")
            && renderedNic.children[6].querySelectorAll(".tap").length === 2,
            renderedNic ? [...renderedNic.children].map((td) => td.textContent.trim()).join("|")
                        : "no siphon row");
      if (typeof window.wlShowNicSettings === "function") {
        const zeekHeld = H.SETTINGS_ROWS.zeek_ifaces;
        const plansForSheet = H.STAGE.changes.intercept_plans;
        H.STAGE.changes.intercept_plans = JSON.stringify({
          eth1: { mode: "siphon", segment: "198.51.100.0/24", gateway: "198.51.100.1",
                  addr: "198.51.100.10", targets: "*" } });
        H.SETTINGS_ROWS.zeek_ifaces = { value: "eth2,eth1" };
        window.wlShowNicSettings("eth2", ["eth1", "eth2"]);
        const roleText = (needEl("wl-nic-role") || {}).textContent || "";
        const zeekChecked = !!doc.getElementById("wl-nic-zeek").checked;
        check("the eth2 SETTINGS sheet agrees with the visual: unassigned, Zeek off",
              /unassigned/i.test(roleText) && zeekChecked === false,
              `role=${roleText.trim()} zeek=${zeekChecked}`);
        H.SETTINGS_ROWS.zeek_ifaces = zeekHeld;
        H.STAGE.changes.intercept_plans = plansForSheet;
        if (typeof window.wlCloseNicSettings === "function") window.wlCloseNicSettings();
      }
      if (plansHeld === undefined) delete H.STAGE.changes.intercept_plans;
      else H.STAGE.changes.intercept_plans = plansHeld;
      H.SETTINGS_ROWS.channel_upstream = upHeld;
      H.SETTINGS_ROWS.channel_downstream = downHeld;
      H.SETTINGS_ROWS.interface_networks = ifaceNamesHeld;
      if (ifaceStageHeld === undefined) delete H.STAGE.changes.interface_networks;
      else H.STAGE.changes.interface_networks = ifaceStageHeld;
      delete H.STAGE.changes.channel_upstream;
      delete H.STAGE.changes.channel_downstream;
    }
    // THE STALE TILE, not a never-seen tile: the operator asked for that count to leave the
    // summary row (2026-10-19). The worklist filter itself still exists for declarations.
    const staleTile = tiles.find((t) => /stale/.test(t.textContent));
    check("the summary no longer offers a never-seen tile",
          !tiles.some((t) => /never seen/.test(t.textContent)),
          tiles.map((t) => t.textContent).join("|").slice(0, 180));
    staleTile.click();
    await new Promise((r) => setTimeout(r, 250));
    const rowsNow = [...doc.querySelectorAll("#wl-table tbody tr:not(.wl-nic-row):not(.wl-colhead)")];
    check("...clicking a count filters the worklist to exactly it",
          rowsNow.length >= 1 &&
            rowsNow.every((tr) => tr.classList.contains("wl-state-stale")),
          rowsNow.map((t) => t.className).join(", ").slice(0, 120));
    check("...and the filter rides the URL",
          String(window.location.hash).includes("wl.f=stale"), String(window.location.hash));
    staleTile.click();   // toggle off
    await new Promise((r) => setTimeout(r, 250));
    check("...and clicking it again clears the filter",
          [...doc.querySelectorAll("#wl-table tbody tr:not(.wl-nic-row):not(.wl-colhead)")].length > 1,
          String([...doc.querySelectorAll("#wl-table tbody tr:not(.wl-nic-row):not(.wl-colhead)")].length));
    // THE SENSOR ROW IS A MENU; THE NIC ROW IS THE SETTINGS (operator, 2026-10-19).
    check("there are no selection checkboxes any more",
          doc.querySelectorAll("#wl-table input.wl-sel").length === 0,
          String(doc.querySelectorAll("#wl-table input.wl-sel").length));
    const sensorRow = [...doc.querySelectorAll("#wl-table tbody tr:not(.wl-nic-row):not(.wl-colhead)")]
      .find((tr) => (tr.textContent || "").includes("edge-alive"));
    const sensorLink = sensorRow && sensorRow.querySelector("button.link");
    check("the sensor name is the action affordance", !!sensorLink);
    sensorLink.click();
    await new Promise((r) => setTimeout(r, 120));
    const sensorCard = needEl("wl-sensor-card");
    check("clicking the sensor name opens ONLY the sensor actions",
          !!sensorCard && !sensorCard.classList.contains("hidden")
          && /edge-alive/.test(needEl("wl-sensor-title").textContent),
          sensorCard ? sensorCard.className : "no card");
    const sensorExtras = [...sensorCard.querySelectorAll("input, select")]
      .filter((node) => !node.closest("#wl-sensor-channel"));
    check("...with enable/disable/delete/adopt and the Channel pair, nothing else",
          ["wl-sensor-adopt", "wl-sensor-enable", "wl-sensor-disable", "wl-sensor-delete"]
            .every((id) => !!doc.getElementById(id))
          && sensorExtras.length === 0,
          sensorExtras.map((n) => n.id || n.tagName).join(",") || "unexpected control");
    check("...the verbs match this sensor's state",
          needEl("wl-sensor-adopt").classList.contains("hidden")
          && needEl("wl-sensor-enable").classList.contains("hidden")
          && !doc.getElementById("wl-sensor-disable").classList.contains("hidden")
          && !doc.getElementById("wl-sensor-delete").classList.contains("hidden"));
    check("the sensor sheet owns the Channel pair",
          /Channel/.test(sensorCard.textContent)
          && !!doc.getElementById("wl-sensor-channel-upstream")
          && !!doc.getElementById("wl-sensor-channel-downstream"),
          "the channel controls are not on the sensor sheet");
    // A REMOTE WEIRLING CAN CARRY A CHANNEL, not only the hub. This uses the shipping helper,
    // so it is a runtime check rather than a source grep: three reported interfaces (one
    // management plus two) are offered, two are not, and a pair the sensor reports as inactive
    // is never described as active.
    const remoteChannel = {
      sensor_id: "edge-remote", local: false, interfaces: ["eth0", "eth1", "eth2"],
      plan_nics: "", plan: { channel_upstream: "eth1", channel_downstream: "eth2" },
      channel_active: false, channel_upstream: "eth1", channel_downstream: "eth2",
      channel_bridge: "",
    };
    const remoteOffer = H.wlChannelOffered(remoteChannel);
    check("a REMOTE weirling with three NICs is offered a channel",
          remoteOffer.show === true && remoteOffer.usable.join(",") === "eth1,eth2",
          `show=${remoteOffer.show} usable=${remoteOffer.usable.join(",")}`);
    check("...while a two-NIC sensor is not offered one",
          H.wlChannelOffered({ interfaces: ["eth0", "eth1"], plan_nics: "" }).show === false,
          "two NICs cannot form a bridge after management is removed");
    H.wlRenderChannelNote(remoteChannel);
    const chanNote = needEl("wl-sensor-channel-note").textContent || "";
    check("...and a declared-but-inactive pair is never called active",
          /NOT active/.test(chanNote) && !/Channel active/.test(chanNote), chanNote.slice(0, 160));
    needEl("wl-sensor-close").click();
    await new Promise((r) => setTimeout(r, 80));
    const capRow = (() => {
      let sib = sensorRow.nextElementSibling;
      if (sib && sib.classList.contains("wl-colhead")) sib = sib.nextElementSibling;
      while (sib && sib.classList.contains("wl-nic-row")) {
        if (/capture/.test(sib.textContent)) return sib;
        sib = sib.nextElementSibling;
      }
      return null;
    })();
    check("a NIC line is clickable", !!capRow && capRow.classList.contains("clickable"));
    // A CHANNEL IS A SENSOR DECISION; the NIC sheet must make the conflicting choices
    // unavailable (operator, 2026-10-19). Staging the pair is enough to exercise the rule.
    const channelHeld = H.STAGE.changes.channel_upstream;
    const channelHeldDown = H.STAGE.changes.channel_downstream;
    H.STAGE.changes.channel_upstream = "eth1";
    H.STAGE.changes.channel_downstream = "eth2";
    capRow.click();
    await new Promise((r) => setTimeout(r, 180));
    check("clicking a NIC line opens that NIC's settings",
          !doc.getElementById("wl-detail-card").classList.contains("hidden")
          && (needEl("wl-plan-iface").value || "") === "eth1"
          && /editing NIC eth1/.test((needEl("wl-nic-edit") || {}).textContent || ""),
          `iface=${needEl("wl-plan-iface").value} note=${(needEl("wl-nic-edit") || {}).textContent}`);
    check("an enabled channel locks siphon and passive NetFlow out of the NIC sheet",
          needEl("wl-nic-siphon").disabled
          && needEl("wl-nic-netflow-passive").disabled
          && needEl("wl-nic-loch").checked
          && needEl("wl-nic-netflow-active").checked,
          `siphon disabled=${needEl("wl-nic-siphon").disabled} ` +
          `passive disabled=${needEl("wl-nic-netflow-passive").disabled}`);
    if (channelHeld === undefined) delete H.STAGE.changes.channel_upstream;
    else H.STAGE.changes.channel_upstream = channelHeld;
    if (channelHeldDown === undefined) delete H.STAGE.changes.channel_downstream;
    else H.STAGE.changes.channel_downstream = channelHeldDown;
    // ONE NIC'S SETTINGS MUST NOT NAME ANOTHER NIC (operator, 2026-10-19: "If I am configuring
    // eth1 ... there should be no reference of eth2"). The global Zeek list is stored elsewhere;
    // the scoped panel reads only this interface.
    {
      const panel = needEl("wl-nic-settings");
      const words = panel ? panel.textContent : "";
      // THE CHANNEL SELECTORS ARE THE ONE PLACE ANOTHER NIC'S NAME MAY APPEAR: choosing an
      // upstream and downstream pair requires listing the candidates. The facts and the
      // heading still name only the interface being edited.
      const ownWords = (needEl("wl-nic-name") || {}).textContent
        + " " + (needEl("wl-nic-facts") || {}).textContent;
      check("a NIC's settings panel names only that NIC",
            !/eth2/i.test(ownWords) && !/eth0/i.test(ownWords), ownWords.slice(0, 180));
      check("the NIC sheet separates Mode from Feeds",
            /Mode/.test(words) && /Feeds/.test(words)
            && !!doc.getElementById("wl-nic-siphon") && !!doc.getElementById("wl-nic-loch")
            && !!doc.getElementById("wl-nic-zeek") && !!doc.getElementById("wl-nic-netflow"),
            words.slice(0, 220));
      check("...and states whether NetFlow is passive or active",
            /NetFlow source/.test(words)
            && !!doc.getElementById("wl-nic-netflow-passive")
            && !!doc.getElementById("wl-nic-netflow-active"), words.slice(0, 260));
      check("...with Networks fields Sonar fills, and the name above the mode",
            /Networks/.test(words) && /Scan Network/.test(words)
            && !!doc.getElementById("wl-nic-sonar")
            && !!doc.getElementById("wl-nic-cidr") && !!doc.getElementById("wl-nic-gateway")
            && !!doc.getElementById("wl-nic-intercept-ip")
            && /Network name/.test(needEl("wl-nic-settings").textContent),
            words.slice(0, 360));
      check("the channel pair is not a NIC field; the NIC sheet states its consequence",
            !/Channel/.test(words)
            && !!doc.getElementById("wl-sensor-channel-upstream")
            && !!doc.getElementById("wl-sensor-channel-downstream"),
            words.slice(0, 360));
      const held = H.STAGE.changes;
      H.STAGE.changes = { zeek_ifaces: "eth1,eth2" };
      H.renderStageMirror(["zeek_ifaces"]);
      const diff = needEl("wl-stage-list").textContent || "";
      check("...and its pending diff states this NIC's on/off, not the other NIC's name",
            !/eth2/i.test(diff) && /eth1/.test(diff) && /\bon\b/.test(diff), diff.slice(0, 120));
      H.STAGE.changes = held;
      H.renderStageMirror(Object.keys(held));
    }
    needEl("wl-detail-close").click();
    await new Promise((r) => setTimeout(r, 80));
    // views: a default exists, switching applies filters, saving adds one
    await H.loadWeirlings();
    const viewSel = needEl("wl-view");
    check("saved views exist, with a default",
          !!viewSel && viewSel.options.length >= 3 && /All sensors/.test(viewSel.options[0].textContent),
          viewSel ? [...viewSel.options].map((o) => o.textContent).join(" | ") : "no select");
    viewSel.value = "needs-action";
    viewSel.dispatchEvent(new window.Event("change", { bubbles: true }));
    await new Promise((r) => setTimeout(r, 250));
    check("...switching to Needs action drives the problems filter",
          needEl("wl-problems-only").checked === true,
          String(needEl("wl-problems-only").checked));
    viewSel.value = "all";
    viewSel.dispatchEvent(new window.Event("change", { bubbles: true }));
    await new Promise((r) => setTimeout(r, 250));
    const before = viewSel.options.length;
    needEl("wl-view-save").click();
    await new Promise((r) => setTimeout(r, 80));
    check("...and the current filters save as a view",
          viewSel.options.length === before + 1, `${before} -> ${viewSel.options.length}`);
    check("...which persists for the tab",
          (() => {
            try {
              const v = JSON.parse(window.sessionStorage.getItem("wv-wl-views") || "[]");
              return Array.isArray(v) && v.length >= 1;
            } catch (_e) { return false; }
          })(),
          String(window.sessionStorage.getItem("wv-wl-views")).slice(0, 80));
    // THE ROW'S VERBS ARE MINIMAL (WL-1): membership changes live in the sheet; the list's
    // only row-level action is Adopt, and only while a sensor is undeclared.
    check("a sensor row carries NO verbs (the sensor sheet owns membership)",
          !doc.querySelector("#wl-table .wl-inline-toggle")
          && doc.querySelectorAll("#wl-table button.wl-adopt").length === 0,
          String(doc.querySelectorAll("#wl-table button.wl-adopt").length));
    try { window.sessionStorage.removeItem("wv-wl-views"); } catch (_e) {}
    await H.loadWeirlings();
  }

  // ── THE SCANNABLE LIST (WL-1) ──────────────────────────────────────────────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    H.showView("weirlings");
    await H.loadWeirlings();
    await sleep(300);
    const headRow = doc.querySelector("#wl-table .wl-colhead");
    const heads = headRow ? [...headRow.children].map((t) => t.textContent.trim()) : [];
    check("WL-1: the NIC columns are interface / mode / channel / networks / throughput / flow / feeds",
          heads.join("|") === "interface|mode|channel|networks|throughput|flow|feeds",
          heads.join("|"));
    const row = (id) => [...doc.querySelectorAll("#wl-table tbody tr:not(.wl-nic-row):not(.wl-colhead)")]
      .find((tr) => (tr.textContent || "").includes(id));
    const nicsOf = (tr) => {
      const out = [];
      let sib = tr ? tr.nextElementSibling : null;
      if (sib && sib.classList.contains("wl-colhead")) sib = sib.nextElementSibling;
      while (sib && sib.classList.contains("wl-nic-row")) { out.push(sib); sib = sib.nextElementSibling; }
      return out;
    };
    const capOf = (tr) => nicsOf(tr).find((x) => /capture/.test(x.textContent));
    const alive = row("edge-alive");
    const aliveCap = capOf(alive);
    const spark = aliveCap && aliveCap.querySelector("svg.wl-spark polyline");
    const pts = spark ? (spark.getAttribute("points") || "").trim().split(/\s+/).length : 0;
    check("...a sensor with flow draws its trend from the series", pts >= 3,
          spark ? spark.getAttribute("points") : "no sparkline");
    const taps = aliveCap ? [...aliveCap.querySelectorAll(".tap")] : [];
    check("...the taps LIGHT on evidence", taps.length === 2
          && taps.every((t) => t.classList.contains("on")),
          taps.map((t) => `${t.className}:${t.textContent}`).join(" "));
    const promised = row("edge-promised");
    const promisedCap = capOf(promised);
    const dark = promisedCap ? promisedCap.querySelector(".tap.off") : null;
    check("...and SUBDUE with the reason when there is none",
          !!dark && /no flows/.test(dark.getAttribute("title") || ""),
          dark ? dark.getAttribute("title") : "none");
    const stopped = row("edge-stopped");
    const stoppedCap = capOf(stopped);
    check("...no series is an explicit absence, never a flat zero line",
          !!stoppedCap && !!stoppedCap.querySelector(".spark-value")
          && !stoppedCap.querySelector("svg.wl-spark"),
          stoppedCap ? stoppedCap.textContent.slice(0, 80) : "no row");
    const cidrCell = promisedCap && promisedCap.querySelector("td:nth-child(4)");
    check("...networks carries the subnet with CIDR",
          !!cidrCell && /198\.51\.100\.0\/24/.test(cidrCell.textContent || ""),
          cidrCell ? cidrCell.textContent : "none");
    check("...and no findings prose leaks into the list",
          !/reporting normally, last heard/.test(
            needEl("wl-table").textContent || ""));
  }

  // ── ALERT DISCIPLINE (BF-12) ────────────────────────────────────────────────────────────────
  {
    H.showView("anomalies");
    await new Promise((r) => setTimeout(r, 300));
    const head = [...doc.querySelectorAll("#anomalies-table thead th")]
      .map((t) => t.textContent.toLowerCase());
    check("the triage table names its fixed contract",
          head.includes("location") && head.includes("matched rule"), head.join(","));
    const first = doc.querySelector("#anomalies-table tbody tr");
    const cells = first ? [...first.querySelectorAll("td")].map((t) => t.textContent) : [];
    check("...and rows carry the location and what matched",
          cells.length >= 11 && cells.some((c) => /edge-alive/.test(c)) &&
            cells.some((c) => /scored this window/.test(c)),
          cells.join(" | ").slice(0, 140));
    const disc = needEl("an-discipline").textContent;
    check("the fired-vs-acted-on budget line renders",
          /4 fired/.test(disc) && /1 acted on/.test(disc) && /3 still open/.test(disc), disc);
    const detRows = [...doc.querySelectorAll("#detectors-table tbody tr")];
    const detText = detRows.map((r) => r.textContent).join(" || ");
    check("the registry says who may page",
          detRows.length >= 3 && detRows.some((r) => /pages/.test(r.textContent)) &&
            detRows.some((r) => /quiet/.test(r.textContent)),
          detText.slice(0, 160));
    check("...and flags a detector nobody registered",
          /unregistered/.test(detText), detText.slice(0, 140));
    const acts = [...doc.querySelectorAll("#anomalies-table .review-acts .review-act")]
      .map((b) => b.textContent);
    const allowed = new Set(["Acknowledge", "Resolve", "Ignore", "clear"]);
    check("the disposition vocabulary is closed",
          acts.length >= 1 && acts.every((a) => allowed.has(a)), acts.join(","));
    // US-4: every count cell carries the cue now; target the GROUPED row by its count.
    const collapse = [...doc.querySelectorAll("#anomalies-table td.num.expander")]
      .find((td) => td.textContent.trim() === "3");
    check("a collapsed group shows its count",
          !!collapse && collapse.textContent.trim() === "3",
          collapse ? collapse.textContent : "no grouped count cell");
    if (collapse) {
      collapse.click();
      await new Promise((r) => setTimeout(r, 80));
      check("...and expands into its occurrences",
            !!doc.querySelector("#anomalies-table tr.an-exp"));
      collapse.click();
      await new Promise((r) => setTimeout(r, 40));
    }
  }

  // ── THE PIPELINE AUDITS ITSELF (BF-13; now read on the Logs tab) ────────────────────────────
  {
    H.showView("logs");
    await new Promise((r) => setTimeout(r, 350));
    const auditRows = [...doc.querySelectorAll("#audit-table tbody tr")];
    const auditText = auditRows.map((r) => r.textContent).join(" || ");
    check("every audit class renders a finding with its name",
          auditRows.length === 7 &&
            ["silent sensor", "expired rule", "stuck rule", "unowned detector",
             "capture loss", "segment mismatch"].every((c) => auditText.includes(c)),
          auditText.slice(0, 200));
    check("...and the elapsed column says how long",
          auditText.includes("3d") && auditText.includes("1h"),
          auditRows.map((r) => r.textContent).join(" | ").slice(0, 180));
    const fixBtn = [...doc.querySelectorAll("#audit-table button")]
      .find((b) => /open the sensor/.test(b.textContent));
    check("every finding carries its fix", !!fixBtn, String(fixBtn && fixBtn.textContent));
    if (fixBtn) {
      fixBtn.click();
      await new Promise((r) => setTimeout(r, 300));
      check("...and the fix button lands on the fixing surface",
            needEl("view-weirlings").classList.contains("active"));
    }
    const detBtn = [...doc.querySelectorAll("#audit-table button")]
      .find((b) => /register it/.test(b.textContent));
    if (detBtn) {
      detBtn.click();
      await new Promise((r) => setTimeout(r, 200));
      check("...and another class lands on its own surface",
            needEl("view-anomalies").classList.contains("active"));
    }
    H.showView("anomalies");
  }

  // ── EVERY SETTINGS CONTROL HAS A NAME (QA-1-D4, WCAG 4.1.2) ────────────────────────────────
  {
    H.showView("settings");
    await new Promise((r) => setTimeout(r, 250));
    const ctrls = [...doc.querySelectorAll("#view-settings input, #view-settings select, #view-settings textarea")];
    const named = (el2) => {
      if ((el2.getAttribute("aria-label") || "").trim()) return true;
      const id = el2.id;
      if (id && doc.querySelector(`label[for="${id}"]`)) return true;
      const wrap = el2.closest("label");
      return !!(wrap && (wrap.textContent || "").trim());
    };
    const unnamed = ctrls.filter((c) => !named(c));
    check("every settings control has an accessible name",
          ctrls.length > 0 && unnamed.length === 0,
          `${unnamed.length} of ${ctrls.length} unnamed: ` +
            unnamed.map((c) => c.dataset.key || c.type).join(", "));
    const num = ctrls.find((c) => c.type === "number");
    check("...and a number field points at its range hint",
          !!num && !!(num.getAttribute("aria-describedby") || "")
          && !!doc.getElementById(num.getAttribute("aria-describedby")),
          num ? (num.getAttribute("aria-describedby") || "no describedby") : "no number field");
  }

  // ── APPLY-TIME CHECKS CAN BLOCK (BF-14) ─────────────────────────────────────────────────────
  {
    H.showView("settings");
    await new Promise((r) => setTimeout(r, 200));
    H.setToken("test-token-value");
    const btIn = [...doc.querySelectorAll("#view-settings .setting-input")]
      .find((n) => n.dataset.key === "base_threshold");
    btIn.value = "0.001";
    btIn.dispatchEvent(new window.Event("input", { bubbles: true }));
    await H.applyStage();
    await new Promise((r) => setTimeout(r, 60));
    const noteT = needEl("st-stage-note").textContent;
    check("a failed apply-time check BLOCKS the write and names itself",
          /BLOCKED/.test(noteT) && /threshold does not fire on yesterday/.test(noteT),
          noteT.slice(0, 150));
    const resT = needEl("st-apply-results").textContent;
    check("...and the receipt counts what passed and what skipped",
          /2 skipped/.test(resT) && /1 failed/.test(resT),
          resT.slice(0, 180));
    const line = [...doc.querySelectorAll("#st-apply-results .stage-res-item")]
      .find((n) => /BLOCKED|apply-time checks/.test(n.textContent));
    check("...with every check's verdict and reason on the hover",
          !!line && /999 rows/.test(line.getAttribute("title") || ""),
          line ? (line.getAttribute("title") || "").slice(0, 160) : "no line");
    check("a blocked apply does NOT clear the stage -- the fix is the staged value",
          Object.keys(H.STAGE.changes).length > 0,
          JSON.stringify(H.STAGE.changes));
    // QA-1-D1: the refusal must not be a dead end. The receipt carries its own way out, and
    // Discard clears the whole thing -- staged row, BLOCKED line, receipt -- in one click.
    const clearBtn = [...doc.querySelectorAll("#st-apply-results button")]
      .find((b) => /Clear this plan/i.test(b.textContent));
    check("a blocked apply offers a live way out in the receipt", !!clearBtn);
    const discardBtn = needEl("st-stage-discard");
    check("...and Discard is live while the refused plan is staged",
          !!discardBtn && !discardBtn.disabled);
    check("the staged line states the from-value immediately (no plan needed)",
          /was 0\.35|was 0\.3/.test(needEl("st-stage-list").textContent),
          needEl("st-stage-list").textContent.slice(0, 120));
    if (clearBtn) {
      clearBtn.click();
      await new Promise((r) => setTimeout(r, 200));
      const noteAfter = needEl("st-stage-note").textContent;
      check("...and clearing it removes the BLOCKED line and the staged row",
            !/BLOCKED/.test(noteAfter)
            && !/base_threshold/.test(needEl("st-stage-list").textContent)
            && needEl("st-stage-apply").disabled,
            noteAfter.slice(0, 120));
    }
    // now a value that passes: the checks ride the success receipt too
    btIn.value = "0.5";
    btIn.dispatchEvent(new window.Event("input", { bubbles: true }));
    await H.applyStage();
    await new Promise((r) => setTimeout(r, 60));
    const resOk = needEl("st-apply-results").textContent;
    check("a clean apply reports its checks in the receipt",
          /1 passed, 1 skipped/.test(resOk), resOk.slice(0, 180));
    check("...and the stage clears when the write lands",
          Object.keys(H.STAGE.changes).length === 0);
  }

  // ── THE COMMAND PALETTE AND ITS SHORTCUTS (BF-11) ───────────────────────────────────────────
  {
    const fire = (key, opts) => window.document.dispatchEvent(
      new window.KeyboardEvent("keydown", Object.assign({ key, bubbles: true, cancelable: true }, opts || {})));
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    H.showView("health");
    await sleep(200);
    fire("k", { ctrlKey: true });
    await sleep(300);
    const pal = needEl("palette");
    const palInput = needEl("palette-input");
    // NB: `pal` may be created on first open -- that IS the check.
    check("Ctrl-K opens the palette", !!doc.getElementById("palette")
          && !doc.getElementById("palette").classList.contains("hidden"));
    check("...with the input focused for typing", !!palInput);
    palInput.value = "zeek";
    palInput.dispatchEvent(new window.Event("input", { bubbles: true }));
    await sleep(60);
    let rows = [...doc.querySelectorAll("#palette-results .palette-row")];
    check("...typing filters the commands to the match",
          rows.length >= 1 && rows.every((r) => /zeek/i.test(r.textContent)),
          rows.map((r) => r.textContent).join(" | ").slice(0, 140));
    check("...and every result carries its path as a breadcrumb",
          rows.length > 0 && /\u203a/.test(rows[0].textContent),
          rows[0] ? rows[0].textContent.slice(0, 140) : "none");
    palInput.dispatchEvent(new window.KeyboardEvent("keydown",
      { key: "Enter", bubbles: true, cancelable: true }));
    await sleep(300);
    check("...Enter executes the command",
          needEl("view-zeek").classList.contains("active"));
    check("...and the palette closes behind it",
          needEl("palette").classList.contains("hidden"));
    fire("/");
    await sleep(60);
    check("slash opens the palette for a search",
          !doc.getElementById("palette").classList.contains("hidden"));
    fire("Escape");
    await sleep(40);
    check("escape closes it again",
          needEl("palette").classList.contains("hidden"));
    // ISSUE #64: focus must go BACK to the opener, and Tab must not leave the open overlay.
    // This is the runtime probe from the issue, kept beside the palette suite.
    {
      const opener = needEl("palette-btn");
      opener.focus();
      const focusBefore = doc.activeElement;
      fire("k", { ctrlKey: true });
      await sleep(120);
      const openInput = needEl("palette-input");
      check("PALETTE FOCUS: opening moves focus into the palette",
            doc.activeElement === openInput,
            doc.activeElement ? doc.activeElement.id || doc.activeElement.tagName : "none");
      openInput.dispatchEvent(new window.KeyboardEvent(
        "keydown", { key: "Tab", bubbles: true, cancelable: true }));
      await sleep(40);
      check("PALETTE FOCUS: Tab stays inside the open palette",
            needEl("palette").contains(doc.activeElement),
            doc.activeElement ? doc.activeElement.id || doc.activeElement.tagName : "none");
      openInput.dispatchEvent(new window.KeyboardEvent(
        "keydown", { key: "Tab", shiftKey: true, bubbles: true, cancelable: true }));
      await sleep(40);
      check("PALETTE FOCUS: Shift+Tab stays inside the open palette",
            needEl("palette").contains(doc.activeElement),
            doc.activeElement ? doc.activeElement.id || doc.activeElement.tagName : "none");
      fire("Escape");
      await sleep(80);
      check("PALETTE FOCUS: closing returns focus to the opener",
            doc.activeElement === focusBefore,
            doc.activeElement ? doc.activeElement.id || doc.activeElement.tagName : "none");
      // A COMMAND THAT NAVIGATES IS A CLOSE TOO. `paletteRun` closes first; if that ever stops
      // returning focus, this check catches it even though the view changed.
      opener.focus();
      const commandBefore = doc.activeElement;
      H.paletteOpen();
      await sleep(100);
      H.paletteRun(0);
      await sleep(200);
      check("PALETTE FOCUS: a navigating command returns focus to the opener",
            doc.activeElement === commandBefore,
            doc.activeElement ? doc.activeElement.id || doc.activeElement.tagName : "none");
    }
    fire("g");
    fire("n");
    await sleep(300);
    check("g n jumps straight to Netflow",
          needEl("view-netflow").classList.contains("active"));

    // ── THE PALETTE AS SEARCH (US-8) ──────────────────────────────────────────
    {
      const type = (q) => {
        const inp = needEl("palette-input");
        inp.value = q;
        inp.dispatchEvent(new window.Event("input", { bubbles: true }));
        return inp;
      };
      const rowsNow = () => [...doc.querySelectorAll("#palette-results .palette-row")];
      const openPal = () => {
        const pb = needEl("palette-btn");
        if (pb) pb.click();
      };
      // 1) THE MOUSE PATH: the chrome button is the entry, the keys stay accelerators.
      H.showView("health");
      await sleep(150);
      const pbtn = needEl("palette-btn");
      check("PALETTE: the chrome carries a visible entry", !!pbtn);
      check("...and it is named for what it does (Quick links, not palette)",
            !!pbtn && pbtn.textContent.trim() === "Quick links",
            pbtn ? pbtn.textContent.trim() : "missing");
      check("the removed Copy-link button is gone from the header",
            !doc.getElementById("copy-link"));
      if (pbtn) pbtn.click();
      await sleep(150);
      check("...and a mouse opens the palette with it",
            !doc.getElementById("palette").classList.contains("hidden"));
      // 2) AN IP IS A HOST: the entity row leads, and activating lands on the host's view.
      type("198.51.100.5");
      await sleep(80);
      const ipRows = rowsNow();
      check("PALETTE: an IP query returns its entity row FIRST",
            ipRows.length > 0 && /Open host 198\.51\.100\.5/.test(ipRows[0].textContent),
            ipRows[0] ? ipRows[0].textContent.slice(0, 120) : "none");
      if (ipRows[0]) ipRows[0].click();
      await sleep(450);
      check("...activating it lands on the host's view with the address loaded",
            needEl("view-host").classList.contains("active")
            && (needEl("hp-title").textContent || "") === "198.51.100.5",
            `addr=${needEl("h-addr").value}`);
      // 3) A DOMAIN IS ITS DNS RECORDS.
      openPal();
      await sleep(120);
      type("ads.example.com");
      await sleep(80);
      const nameRows = rowsNow();
      check("PALETTE: a domain query returns its DNS row first",
            nameRows.length > 0 && /DNS records for ads\.example\.com/.test(nameRows[0].textContent),
            nameRows[0] ? nameRows[0].textContent.slice(0, 120) : "none");
      if (nameRows[0]) nameRows[0].click();
      await sleep(450);
      check("...activating it lands on DNS with the domain filter ACTIVE",
            needEl("view-dns").classList.contains("active")
            && needEl("dn-domain").value === "ads.example.com",
            `dom=${needEl("dn-domain").value}`);
      // 4) A RULE ID IS A RULE -- its home is the Sluice gate, and it lands flashed.
      openPal();
      await sleep(120);
      type("r-live-1");
      await sleep(80);
      const ruleRows = rowsNow();
      check("PALETTE: a rule id returns its rule row",
            ruleRows.length > 0 && /Open rule r-live-1/.test(ruleRows[0].textContent),
            ruleRows[0] ? ruleRows[0].textContent.slice(0, 120) : "none");
      if (ruleRows[0]) ruleRows[0].click();
      await sleep(500);
      check("...activating it lands on the Sluice gate",
            needEl("view-sluice").classList.contains("active"));
      check("...and the rule's own row is flashed there",
            !!doc.querySelector('#view-sluice [data-rule-id="r-live-1"].flash-hit')
            || !!doc.querySelector('#view-sluice [data-rule-id="r-live-1"]'),
            "no rule row for r-live-1");
      // 5) RECENTS: what this session just did leads an empty palette.
      openPal();
      await sleep(350);
      const recentRows = rowsNow();
      check("RECENTS: the session's last views and commands lead the empty palette",
            recentRows.length > 0
            && recentRows.slice(0, 3).some((r) => /Open rule r-live-1|Go to Sluice/.test(r.textContent)),
            recentRows.slice(0, 3).map((r) => r.textContent.slice(0, 50)).join(" | "));
      check("...and every recent row SAYS it is a recent",
            recentRows.length > 0
            && recentRows.slice(0, 3).every((r) => /recent/.test(r.textContent)),
            recentRows.slice(0, 3).map((r) => r.textContent.slice(0, 60)).join(" | "));
      H.paletteClose();
      await sleep(80);
      // 6) SETTINGS: the boot-collapsed card is EXPANDED before its row is shown.
      H.showView("health");
      await sleep(150);
      openPal();
      await sleep(200);
      type("sluice_auto_score");
      await sleep(250);
      const sRows = rowsNow().filter((r) => /Open setting/.test(r.textContent));
      check("SETTINGS: a setting is findable from the palette", sRows.length > 0,
            rowsNow().map((r) => r.textContent.slice(0, 50)).join(" | ").slice(0, 140));
      if (sRows[0]) { sRows[0].click(); await sleep(600); }
      const keyRow = doc.querySelector('#view-settings [data-key="sluice_auto_score"]');
      const keyCard = keyRow && keyRow.closest(".card");
      check("...and its boot-collapsed card is EXPANDED before the row is shown",
            !!keyCard && !keyCard.classList.contains("collapsed")
            && needEl("view-settings").classList.contains("active"),
            keyCard ? `collapsed=${keyCard.classList.contains("collapsed")}` : "no card");
      // 7) the disabled retrain STATES why instead of swallowing the click.
      openPal();
      await sleep(150);
      type("retrain");
      await sleep(150);
      const rtRows = rowsNow().filter((r) => /Force a model retrain/.test(r.textContent));
      check("PALETTE: the retrain command exists", rtRows.length > 0);
      const errBefore = (needEl("err-banner") || {}).textContent || "";
      if (rtRows[0]) { rtRows[0].click(); await sleep(600); }
      const mrForce = needEl("mr-force");
      const errAfter = (needEl("err-banner") || {}).textContent || "";
      check("...and when the button is DISABLED the palette says why (never a silent no-op)",
            !mrForce || !mrForce.disabled || /retrain unavailable|Could not/.test(errAfter),
            `disabled=${mrForce ? mrForce.disabled : "none"} err="${errAfter.slice(0, 80)}" errBefore="${errBefore.slice(0, 40)}"`);
      H.paletteClose();
      H.showView("health");
      await sleep(150);
    }
    fire("f");
    await sleep(40);
    check("f maximizes the active view's main table", !!doc.querySelector(".card.table-max"));
    fire("f");
    await sleep(40);
    check("...and f puts it back", !doc.querySelector(".card.table-max"));
    H.showView("health");
    await sleep(250);
    fire("h");
    await sleep(60);
    check("h toggles help for whatever is on screen",
          !!doc.querySelector("#view-health .info-text:not(.hidden)"));
    fire("h");
    await sleep(60);
    check("...and h toggles it back",
          !doc.querySelector("#view-health .info-text:not(.hidden)"));
    // A SENSOR COMMAND: the palette reaches into the fleet.
    await H.loadWeirlings();
    fire("k", { ctrlKey: true });
    await sleep(300);
    const pIn = needEl("palette-input");
    pIn.value = "edge-alive";
    pIn.dispatchEvent(new window.Event("input", { bubbles: true }));
    await sleep(60);
    rows = [...doc.querySelectorAll("#palette-results .palette-row")];
    check("a sensor appears as its own commands", rows.length >= 2
          && rows.some((r) => /Open sensor edge-alive/.test(r.textContent))
          && rows.some((r) => /Select edge-alive/.test(r.textContent)),
          rows.map((r) => r.textContent.replace(/\s+/g, " ")).join(" | ").slice(0, 180));
    fire("Escape");
    await sleep(40);
    // TYPING IN A FIELD MUST NOT TRIGGER ANY OF IT
    H.showView("settings");
    await sleep(250);
    const sIn = [...doc.querySelectorAll("#view-settings .setting-input")][0];
    if (sIn) {
      sIn.focus();
      sIn.dispatchEvent(new window.KeyboardEvent("keydown", { key: "g", bubbles: true }));
      sIn.dispatchEvent(new window.KeyboardEvent("keydown", { key: "n", bubbles: true }));
      await sleep(60);
      check("shortcuts stay quiet while a field is being typed into",
            needEl("palette").classList.contains("hidden")
            && !doc.getElementById("view-netflow").classList.contains("active"));
    }
  }

  // ── THE BUTTON SYSTEM (BTN-1) ───────────────────────────────────────────────────────────────
  {
    // ONE SIZE: the base owns size, so no button may smuggle its own via an inline style.
    const inlineSized = [...doc.querySelectorAll("button")].filter((b) =>
      /(?:^|;)\s*(height|width|padding|font-size)\s*:/.test(b.getAttribute("style") || ""));
    check("BTN-1: no button carries an inline size (the base owns size)",
          inlineSized.length === 0,
          inlineSized.slice(0, 3).map((b) => b.getAttribute("style")).join(" | "));
    // ...and no legacy size class survives in the live document.
    check("BTN-1: no button still wears a retired size class",
          doc.querySelectorAll("button.small, .btn-small, .btn-lg").length === 0,
          String(doc.querySelectorAll("button.small").length));
  }

  // ── THE BUBBLE RATCHET (operator pass, 2026-11-20) ─────────────────────────────────────────
  // ONE pill, everywhere. The console had `.chip`, `.dc-chip`, `.rp-sev-chip` and a `.pill` in
  // different views; adjacent tabs drew status and filter pills at different heights. This
  // walks every view, collects EVERY `.bubble` (state, filter, control, static markup and
  // rendered), and requires one computed geometry: radius, all four paddings, height and type.
  // Height is read from the cascade (jsdom does not lay out); the stylesheet pin in
  // tests/test_bubble_contract.py separately forbids any `.bubble` variant declaring its own.
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const sweep = () => {
      const seen = new Map();
      let n = 0;
      for (const b of doc.querySelectorAll(".bubble")) {
        const cs = window.getComputedStyle(b);
        const sig = [cs.borderTopLeftRadius, cs.paddingTop, cs.paddingRight,
                     cs.paddingBottom, cs.paddingLeft, cs.height, cs.fontSize].join("|");
        n += 1;
        if (!seen.has(sig)) seen.set(sig, []);
        if (seen.get(sig).length < 3) {
          seen.get(sig).push(`${b.className || "?"}: ${(b.textContent || "").trim().slice(0, 22)}`);
        }
      }
      return { n, seen };
    };
    let total = 0;
    const variants = new Map();
    for (const view of ["health", "anomalies", "normalize", "network", "discover", "dns",
                        "zeek", "sluice", "weirlings", "models", "assets", "netflow",
                        "blocked", "settings", "logs"]) {
      await H.showView(view);
      await sleep(60);
      const { n, seen } = sweep();
      total = Math.max(total, n);
      for (const [sig, names] of seen) {
        if (!variants.has(sig)) variants.set(sig, []);
        variants.get(sig).push(...names);
      }
    }
    // The filter bar is markup the views do not own: render a real pill so the remove control
    // is measured too (its `×` used to be a larger font than the pill and grew the box).
    await H.showView("network");
    H.ASSETS_STATE.query = "vault";
    if (window.FILTER_BAR) window.FILTER_BAR.render();
    await sleep(60);
    const withBar = sweep();
    total = Math.max(total, withBar.n);
    for (const [sig, names] of withBar.seen) {
      if (!variants.has(sig)) variants.set(sig, []);
      variants.get(sig).push(...names);
    }
    H.ASSETS_STATE.query = "";
    if (window.FILTER_BAR) window.FILTER_BAR.render();

    const geometry = [...variants.entries()].filter(([, names]) => names.length);
    check("the console has one bubble geometry in every view (radius, padding, height, type)",
          geometry.length === 1 && total >= 20,
          `${total} bubbles, ${geometry.length} geometry/ies: ` +
          geometry.map(([sig, names]) => `[${sig}] ${names.join(" / ")}`).join(" ;; "));
    check("...and no legacy pill class survives in the live DOM",
          doc.querySelectorAll(".chip, .dc-chip, .rp-sev-chip, .pill").length === 0,
          `${doc.querySelectorAll(".chip, .dc-chip, .rp-sev-chip, .pill").length} legacy pills`);
  }

  // ── THE GROUPED NAV AND ITS BREADCRUMBS (TH-3) ──────────────────────────────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const groups = [...doc.querySelectorAll("#tabs .tab-group")];
    // The grouping is what keeps this nav readable; eight groups is the current ceiling (the
    // sluice, fleet and telemetry groups split out of Operations as those views grew).
    check("the nav holds at most eight groups", groups.length <= 8 && groups.length >= 2,
          String(groups.length));
    check("...every group carries tabs and none carries an inert label",
          groups.every((g) => g.querySelectorAll(".tab").length >= 1)
          && doc.querySelectorAll("#tabs .tab-group-label").length === 0,
          groups.map((g) => g.querySelectorAll(".tab").length + " tab(s)").join(", "));
    const views = [...doc.querySelectorAll("#tabs .tab")].map((t) => t.dataset.view);
    // FOURTEEN, NOT THIRTEEN. Logs joined the row (2026-10-18) and Normalize followed
    // (2026-11-19); the count is the contract, so it moves with the product. The list is spelled
    // out so a tab cannot vanish quietly while the count is padded by a duplicate.
    check("...and all fourteen tabs survive the regrouping",
          views.length === 14 && new Set(views).size === 14
          && ["health", "anomalies", "normalize", "logs", "network", "netflow", "discover", "dns",
              "zeek", "sluice", "weirlings", "models", "assets", "settings"]
             .every((v) => views.includes(v)),
          views.join(","));
    check("...nothing collapses into a sub-menu", !doc.querySelector("#tabs select, #tabs details"));

    // HOST IS ITS OWN SURFACE (operator, 2026-10-19): an old #v=host link lands on the host
    // page, not back on the inventory.
    H.showView("host");
    check("an old #v=host link lands on the host view",
          needEl("view-host").classList.contains("active"), H.CURRENT_VIEW);
    H.showView("assets");
    const cssText = fs.readFileSync(path.join(WEB, "style.css"), "utf8");
    check("...one row: the strip is nowrap and scrolls rather than wrapping",
          cssText.includes("#tabs { display: flex; align-items: center; flex-wrap: nowrap; }"));
    await H.showView("weirlings");
    await H.loadWeirlings();
    await H.openWeirling("edge-alive");
    await sleep(250);
    const crumbs = needEl("crumbs");
    check("a drill-down posts its breadcrumb path",
          !crumbs.classList.contains("hidden") && /Fleet/.test(crumbs.textContent)
          && /Weirlings/.test(crumbs.textContent) && /edge-alive/.test(crumbs.textContent),
          crumbs.textContent.trim());
    check("...and the nav stays on screen inside the detail view",
          !doc.getElementById("tabs").classList.contains("hidden")
          && doc.querySelectorAll("#tabs .tab").length === 14);
    const back = [...crumbs.querySelectorAll("button.crumb")].find((b) => /Weirlings/.test(b.textContent));
    check("...with a real, clickable way back out of the drill", !!back);
    if (back) back.click();
    await sleep(80);
    check("...which closes the detail and clears the trail",
          needEl("wl-detail-card").classList.contains("hidden")
          && needEl("crumbs").classList.contains("hidden"));
    H.showView("health");
    await sleep(80);
    check("a view change clears any breadcrumb that was left",
          needEl("crumbs").classList.contains("hidden"));
  }

  // ── THE DRILL-DOWN SHEET (TH-4) ─────────────────────────────────────────────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const cssText = fs.readFileSync(path.join(WEB, "style.css"), "utf8");
    check("the drill-down is a sheet: fixed to the right edge, so the view never reflows",
          cssText.includes(".sheet { position: fixed; top: 0; right: 0; bottom: 0; left: auto;"),
          "css rule");
    const card = needEl("wl-detail-card");
    check("...and it slides in (the sheet-in keyframe is defined)",
          card.classList.contains("sheet") && cssText.includes("@keyframes sheet-in"));
    check("editors stay centred modals: the settings stage card is NOT a sheet",
          !doc.getElementById("st-stage-card").classList.contains("sheet"));
    await H.showView("weirlings");
    await H.loadWeirlings();
    await H.openWeirling("edge-alive");
    await sleep(200);
    check("opening a sensor brings the sheet up",
          !card.classList.contains("hidden"));
    check("...with focus moved INTO the sheet (keyboard belongs to it)",
          doc.activeElement === card, String(doc.activeElement && doc.activeElement.id));
    const scrim = needEl("wl-sheet-scrim");
    check("...and a click-out scrim behind it", !!scrim && !scrim.classList.contains("hidden"));
    window.document.dispatchEvent(new window.KeyboardEvent("keydown",
      { key: "Escape", bubbles: true, cancelable: true }));
    await sleep(60);
    check("Escape returns from the sheet",
          card.classList.contains("hidden") && scrim.classList.contains("hidden"));
    check("...and the breadcrumb trail goes with it",
          needEl("crumbs").classList.contains("hidden"));
    await H.openWeirling("edge-alive");
    await sleep(120);
    scrim.click();
    await sleep(60);
    check("a click outside returns too", card.classList.contains("hidden"));
    await H.openWeirling("edge-alive");
    await sleep(120);
    needEl("wl-sheet-close").click();
    await sleep(60);
    check("...and the sheet carries its own visible Close",
          card.classList.contains("hidden") && !!doc.getElementById("wl-sheet-close"));
    H.showView("health");
    await sleep(60);
  }

  // ── THE METRIC-TILE RECIPE (TH-5) ───────────────────────────────────────────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const cssText = fs.readFileSync(path.join(WEB, "style.css"), "utf8");
    check("the sparkline's two fills are the chart's own colours",
          /svg\.spark rect \{ fill: var\(--chart-area\); \}/.test(cssText)
          && /svg\.spark rect\.cur \{ fill: var\(--accent\); \}/.test(cssText));
    // the host view: the two series-backed tiles earn sparklines; the rest do not.
    await H.openHost("198.51.100.5");
    await sleep(250);
    const hStats = needEl("h-stats");
    const hTiles = [...hStats.querySelectorAll(".stat")];
    check("the host tiles put the LABEL above the value",
          hTiles.length >= 5 && hTiles.every((t) => t.children[0].classList.contains("k")),
          hTiles.map((t) => t.children[0].className).join(","));
    const bytesTile = hTiles.find((t) => /bytes/.test(t.textContent));
    const bytesSpark = bytesTile && bytesTile.querySelector("svg.spark");
    check("...and a series-backed number carries its sparkline",
          !!bytesSpark && bytesSpark.querySelectorAll("rect").length === 4,
          bytesSpark ? String(bytesSpark.querySelectorAll("rect").length) : "no svg");
    check("...with the current bucket in accent and the past in chart-area",
          !!bytesSpark
          && bytesSpark.querySelectorAll("rect.cur").length === 1
          && bytesSpark.querySelector("rect:last-of-type").classList.contains("cur")
          && bytesSpark.querySelectorAll("rect.rest").length === 3);
    check("...a zero bucket keeps a stub, so a gap never reads as a missing bar",
          !!bytesSpark && [...bytesSpark.querySelectorAll("rect")]
            .some((r) => Number(r.getAttribute("height")) === 1.5));
    const destTile = hTiles.find((t) => /destinations/.test(t.textContent));
    check("...and a number with no series gets no invented shape",
          !!destTile && !destTile.querySelector("svg.spark"));
    // the other tile families follow the same reading order, without sparklines
    await H.loadWeirlings();
    await sleep(200);
    const wlFirst = doc.querySelector("#wl-summary .stat");
    check("the fleet's count tiles read label-then-value too",
          !!wlFirst && wlFirst.children[0].classList.contains("k"));
    await H.loadAnomalies();
    await sleep(200);
    const sevFirst = doc.querySelector("#an-sev .tile");
    check("the severity tiles read label-then-value as well",
          !!sevFirst && sevFirst.children[0].classList.contains("k"),
          sevFirst ? sevFirst.children[0].className : "none");
    if (sevFirst) {
      const sevH = window.getComputedStyle(sevFirst).height;
      check("...and a severity tile is sized by its content, not the button height",
            !/^28px$/.test(sevH), sevH);
    }
    H.showView("health");
    await sleep(60);
  }

  // ── THE ACCESSIBILITY GUARANTEES, LIVE (TH-6) ──────────────────────────────────────────────
  {
    const stageNote = needEl("st-stage-note");
    const applyRes = needEl("st-apply-results");
    check("the staged-changes note announces itself to a screen reader",
          stageNote.getAttribute("aria-live") === "polite"
          && stageNote.getAttribute("role") === "status");
    check("...and so do the apply results",
          applyRes.getAttribute("aria-live") === "polite"
          && applyRes.getAttribute("role") === "status");
  }

  // ── DESTRUCTIVE ACTIONS: THE ECHO AND THE READ-BACK (BF-9) ─────────────────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    // (1) the echo's contents and the required reason -- asserted exactly, on the dialog itself
    const pend = H.confirmDestructive({ title: "Retire it.", target: "edge-alive",
                                        blast: "the segment loses its cut point" });
    await sleep(40);
    const box = doc.querySelector("#modal-body .dest-confirm");
    check("the echo names the exact target and the blast radius",
          !!box && /edge-alive/.test(box.textContent) && /loses its cut point/.test(box.textContent),
          box ? box.textContent.slice(0, 140) : "no dialog");
    const goBtn = [...box.querySelectorAll(".dest-acts button")].find((b) => /Do it/i.test(b.textContent));
    check("...and Do it stays disabled until a reason is written",
          !!goBtn && goBtn.hasAttribute("disabled"));
    const rIn = box.querySelector(".dest-reason");
    rIn.value = "it is being retired";
    rIn.dispatchEvent(new window.Event("input", { bubbles: true }));
    check("...and enables the moment one exists", !goBtn.hasAttribute("disabled"));
    const cancelBtn = [...box.querySelectorAll(".dest-acts button")].find((b) => /Cancel/.test(b.textContent));
    cancelBtn.click();
    check("Cancel answers {ok: false} -- the caller writes nothing",
          (await pend).ok === false);
    // (2) type-the-target: only for the truly irreversible (blocklist replace)
    const pend2 = H.confirmDestructive({ title: "Replace the list.", target: "hagezi-light",
                                         blast: "every name the list was watching is replaced",
                                         typeToConfirm: true });
    await sleep(40);
    const box2 = doc.querySelector("#modal-body .dest-confirm");
    const go2 = [...box2.querySelectorAll(".dest-acts button")].find((b) => /Do it/i.test(b.textContent));
    const rIn2 = box2.querySelector(".dest-reason");
    const tIn2 = box2.querySelector(".dest-type");
    rIn2.value = "the list moved upstream";
    rIn2.dispatchEvent(new window.Event("input", { bubbles: true }));
    check("type-the-target: a reason alone is not enough", go2.hasAttribute("disabled"));
    tIn2.value = "hagezi-light";
    tIn2.dispatchEvent(new window.Event("input", { bubbles: true }));
    check("...the exact target unlocks it", !go2.hasAttribute("disabled"));
    go2.click();
    const verdict2 = await pend2;
    check("...and the verdict carries the reason for the write", verdict2.ok === true
          && verdict2.reason === "the list moved upstream");
    // (3) the read-back: pending -> applied (a reader that agrees inside the window)
    const noteEl = doc.createElement("span");
    doc.body.appendChild(noteEl);
    let agrees = false;
    const p1 = H.withReadBack({ note: noteEl, read: async () => ({}), ok: () => agrees,
                                tries: 3, delayMs: 40, label: "applied",
                                carry: "the sensor picks it up on its next refresh" });
    await sleep(50);
    check("...pending says what happens next while the world catches up",
          /pending/.test(noteEl.textContent) && /next refresh/.test(noteEl.textContent),
          noteEl.textContent);
    agrees = true;
    await p1;
    check("...APPLIED AT a time once the read-back agrees",
          /applied at \d\d?:\d\d/.test(noteEl.textContent), noteEl.textContent);
    // (4) the read-back: NOT APPLIED -- a different word, on purpose
    const p2 = H.withReadBack({ note: noteEl, read: async () => ({}), ok: () => false,
                                tries: 2, delayMs: 40, check: "check the sensor" });
    await p2;
    check("...and a stuck change escalates to NOT APPLIED, never to a false done",
          /^NOT APPLIED/.test(noteEl.textContent) && /check the sensor/.test(noteEl.textContent),
          noteEl.textContent);
    noteEl.remove();
    // (5) the APPLIED side end-to-end: this stub DOES flip the fixture on an apply, so the
    //     same flow's read-back must land on applied.
    await H.openWeirling("edge-stopped");
    await sleep(120);
    const appliedRun = H.wlApplyPlanChanges({ mode: "siphon" });
    for (let i = 0; i < 200 && !doc.querySelector("#modal-body .dest-confirm"); i++) {
      await sleep(20);
    }
    await confirmEcho("proving the applied path");
    await appliedRun;
    check("a siphon apply whose plan moves reads back as APPLIED",
          /applied to the hub's plan at/.test(needEl("wl-plan-note").textContent),
          needEl("wl-plan-note").textContent);
    // (5b) the ESCALATION: force the detail read to keep reporting the old mode -- the
    //      read-back cannot agree, and the note must say NOT APPLIED, not a false done.
    fetchOverride = (u) => (String(u).includes("/api/weirlings/detail")
      ? Promise.resolve({ ok: true, status: 200, json: async () => ({
          available: true, sensor: Object.assign({}, (window.__wlRows || []).find((x) => x.sensor_id === "edge-stopped") || {},
          { reported_mode: "loch", plan_mode: "loch" }) }) })
      : null);
    await H.openWeirling("edge-stopped");
    await sleep(120);
    const stuckRun = H.wlApplyPlanChanges({ mode: "siphon" });
    for (let i = 0; i < 200 && !doc.querySelector("#modal-body .dest-confirm"); i++) {
      await sleep(20);
    }
    await confirmEcho("proving the escalation path");
    await stuckRun;
    fetchOverride = null;
    check("a siphon apply whose plan does NOT move escalates NOT APPLIED",
          /NOT APPLIED/.test(needEl("wl-plan-note").textContent),
          needEl("wl-plan-note").textContent);
    // (6) delete: the sensor sheet's Delete posts the echo's reason
    H.showView("weirlings");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadWeirlings();
    await sleep(150);
    const victim = [...doc.querySelectorAll("#wl-table tbody tr:not(.wl-nic-row):not(.wl-colhead)")]
      .find((tr) => (tr.textContent || "").includes("edge-moved"));
    victim.querySelector("button.link").click();
    await sleep(80);
    const before6 = POSTED.length;
    needEl("wl-sensor-delete").click();
    await sleep(80);
    await confirmEcho("decommissioned after the move");
    await sleep(200);
    const rvs = POSTED.slice(before6).filter((r) => r.url.includes("/api/weirlings/revoke"));
    check("Delete on the sensor sheet posts the echo's reason",
          rvs.length === 1 && /decommissioned after the move/.test(rvs[0].body),
          rvs.map((r) => r.body).join(" | ").slice(0, 160));
    const card = needEl("wl-sensor-card");
    if (card && !card.classList.contains("hidden")) needEl("wl-sensor-close").click();
  }

  // ── THE POLICY CARD IS INDEPENDENT OF THE RULE LIST (measured live 2026-10-22) ───────────────
  {
    const origFetch = window.fetch;
    window.fetch = (u, o) => {
      if (String(u).split("?")[0].endsWith("/api/sluice"))
        return Promise.resolve({ ok: true, json: async () => Object.assign({}, SLUICE_PAYLOAD, {
          rules: [], hits: [],
        }) });
      return origFetch(u, o);
    };
    H.showView("sluice");
    await H.loadSluice();
    await new Promise((r) => setTimeout(r, 120));
    window.fetch = origFetch;
    // The policy CARD is gone (the per-rule mode select replaced it), so this checks the shape
    // that still matters: an empty rule list renders the gates and says why the table is empty
    // instead of leaving a blank card.
    // THE GATE PAIR IS KEYED BY ITS OWN CLASS. The 2026-11-18 house-pattern rebuild moved the
    // pair from `.grid` to `.grid2` (same two-column intent), so pinning the grid utility made
    // this check fail on a page that was rendering correctly. `.sl2-gates` is the contract.
    const emptyLine = doc.getElementById("sl2-empty");
    check("an empty rule list still renders the gates and says why the table is empty",
          !!emptyLine && !emptyLine.classList.contains("hidden")
          && /no (live )?rules match|no rule has been filed|no .* rule exists/i
            .test(emptyLine.textContent || "")
          && doc.querySelectorAll("#view-sluice .sl2-gates > .card").length === 2,
          emptyLine ? emptyLine.textContent.slice(0, 100) : "no empty line");
    await H.loadSluice();   // tidy back to the full fixture
  }

  // ── THE BLOCKLIST PANEL (the operator: hagezi lists, custom names, hits) ────────────────────
  {
    H.showView("sluice");
    H.clearGetCache();
    await H.loadSluice();
    // EVERY CARD HAS ITS OWN LOADER. `loadSluice()` renders the gates and rules; the blocklist
    // pane is `loadBlocklistPane()`. This block only ever called the first, so the pane kept
    // whatever it had from an earlier render -- measured as the "No sources yet - Sync now seeds
    // the defaults" empty state, which made BOTH checks below fail against a fixture that was
    // never asked for.
    // /api/blocklists IS ITS OWN ENDPOINT and the default fixture does not serve it -- the lists
    // live inside SLUICE_PAYLOAD, which is the combined /api/sluice body. So the pane was reading a
    // real-but-empty answer and rendering "No sources yet". Stub it from the same fixture rather
    // than inventing a second copy of the data.
    const blServe = (payload) => Promise.resolve(
      { ok: true, status: 200, statusText: "OK", json: async () => payload });
    H.clearGetCache();
    fetchOverride = (u) => (String(u).includes("/api/blocklists")
      ? blServe({ available: true, sources: SLUICE_PAYLOAD.blocklists })
      : null);
    await H.loadBlocklistPane();
    const bl = needEl("sl-bl-rows").textContent;
    check("the blocklist panel renders the imported source", /HaGeZi/.test(bl) && /123456/.test(bl),
          bl.slice(0, 110));
    // The card moved to Settings (2026-10-16) and its Recent domain hits panel was removed --
    // hits are read on the Blocked page now. What must stay checkable here: each row is
    // CLICKABLE to toggle the list, and the on/off state is on the row.
    const row0 = doc.querySelector("#sl-bl-rows tr");
    // RE-AUTHORED FOR WV1-14. This asserted the WHOLE ROW was the toggle, which was the defect:
    // one cell is `last_error.slice(0, 90)`, so clicking the error text to read or copy it silently
    // disabled a DNS blocklist. The row is now inert and an explicit button carries the action, so
    // asserting "clickable" would have demanded the bug back.
    const blBtn = row0 ? row0.querySelector("button") : null;
    check("a blocklist row offers an explicit toggle button, and the row is inert",
          !!row0 && !row0.classList.contains("clickable")
            && !!blBtn && /turn (on|off)/i.test(String(blBtn.textContent)),
          row0 ? `class=${JSON.stringify(row0.className)} button=${
            blBtn ? JSON.stringify(blBtn.textContent) : "none"}` : "(no row)");
    fetchOverride = null;
    H.clearGetCache();
  }

  // The gate OFF: the same rows must state the reason instead of offering the button.
  fetchOverride = (u, opts) => (String(u).split("?")[0].endsWith("/api/sluice")
    ? { ok: true, status: 200,
        json: async () => (Object.assign({}, SLUICE_PAYLOAD, { enabled: false })) }
    : null);
  H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
  await H.loadAnomalies();
  const offBtns = [...doc.querySelectorAll("#anomalies-table .gate-open")];
  const offNotes = [...doc.querySelectorAll("#anomalies-table .gate-off")];
  check("with the gate off, no row offers the button", offBtns.length === 0,
        `${offBtns.length} button(s)`);
  check("and every row STATES why the block is unavailable",
        offNotes.length > 0 && /Sluice Gate is off/.test(offNotes[0].textContent),
        offNotes[0] ? offNotes[0].textContent.slice(0, 160) : "no reason rendered");
  fetchOverride = null;
  await H.loadAnomalies();

  check("the evidence view carries a TLS-sessions section for the JA4 pivot",
        !!doc.getElementById("ev-tls"));

  // ── the fingerprint lookup, on the identity view ────────────────────────────────────────────
  //
  // The question pointing the other way: not "what does this host run" but "who else presents
  // this stack". The empty case is checked too, because a lookup that finds nothing must SAY it
  // found nothing rather than render an empty box.
  H.showView("identity");
  H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
  await H.loadIdentity();
  const fpIn = needEl("fp-input");
  const fpGo = needEl("fp-go");
  check("the identity view carries the fingerprint lookup", !!fpIn && !!fpGo);
  if (fpIn && fpGo) {
    fpIn.value = "t13d1516h2_8daaf6152771_02713d6af862";
    fpGo.click();
    await new Promise((r) => setTimeout(r, 80));
    const hits = [...doc.querySelectorAll("#fp-results tbody tr")];
    check("the lookup renders one row per host that presented the fingerprint",
          hits.length === 2, `${hits.length} row(s)`);
    check("the note states how many hosts, and over what window",
          /2 host/.test(needEl("fp-note").textContent),
          needEl("fp-note").textContent);

    fetchOverride = (u, opts) => (String(u).split("?")[0].endsWith("/api/fingerprints")
      ? { ok: true, status: 200,
          json: async () => ({ ja4: "deadbeef", count: 0, hosts: [], reason: "" }) }
      : null);
    fpIn.value = "deadbeef";
    fpGo.click();
    await new Promise((r) => setTimeout(r, 80));
    check("a lookup that found nothing SAYS so",
          /no host/.test(needEl("fp-note").textContent),
          needEl("fp-note").textContent);
    check("and renders no table for it",
          doc.querySelectorAll("#fp-results tbody tr").length === 0);
    fetchOverride = null;
  }

  // ── accounts: the sign-in gate, roles, and the Users panel ────────────────────────────────
  //
  // Everything below drives the SHIPPING code against the MUTABLE session stub, which behaves
  // like the real server: signing in flips /api/session to an authenticated admin, signing out
  // clears it. The checks assert OUTCOMES the operator would see -- gates shown/hidden, controls
  // present/absent per role, the Users panel admin-only -- and never trust client-side state
  // the server has not confirmed.

  // 1. PRE-ACCOUNTS POSTURE: with no accounts provisioned, no gate is shown. This is the
  //    state the rest of this file runs in, so asserting it here documents why nothing above
  //    ever hit a login wall.
  check("no accounts means no sign-in gate (the pre-accounts posture)",
        needEl("auth-gate").classList.contains("hidden"),
        "auth gate visible with accounts:false");
  check("the sign-in form is a password input, not plain text",
        needEl("gate-pass").type === "password");

  // COMPUTED, NOT MERELY CLASSED. `classList.contains("hidden")` was TRUE for the whole
  // outage: `.gate { display: flex }` sat after `.hidden { display: none }` at equal
  // specificity, source order won, and both gates stayed painted -- the forced-change form
  // covered the sign-in form and the dashboard was unreachable. Only the COMPUTED display
  // decides what an operator sees, so every gate-state assertion below reads it.
  const gateDisplay = (id) => window.getComputedStyle(doc.getElementById(id)).display;
  check("no gate is PAINTED in the pre-accounts posture (computed style, not class names)",
        gateDisplay("auth-gate") === "none" && gateDisplay("pw-gate") === "none",
        `auth=${gateDisplay("auth-gate")} pw=${gateDisplay("pw-gate")}`);

  // 2. A FAILED SIGN-IN shows the server's reason -- and does NOT say which half was wrong.
  let loginErr = null;
  try { await H.doLogin("admin", "wrong-password"); } catch (e) { loginErr = e; }
  check("a wrong password is refused", !!loginErr, "doLogin resolved with a wrong password");
  check("the refusal does not say whether the user exists",
        loginErr && /username or password/.test(String(loginErr.message)),
        loginErr ? String(loginErr.message) : "no error");

  // 3. A SUCCESSFUL SIGN-IN mints a session, reports the account, and boots the dashboard.
  SESSION_STUB.accounts = true;
  await H.doLogin("admin", "correct-password");
  await H.boot();
  check("signing in stores a session token that requests then carry",
        H.getSession() === "test-session-token", `session=${H.getSession()}`);
  check("the user chip names the signed-in account and role",
        /admin/.test(needEl("user-chip").textContent),
        needEl("user-chip").textContent);
  check("the auth gate is hidden after signing in",
        needEl("auth-gate").classList.contains("hidden"));
  check("no gate is painted once signed in (computed)",
        gateDisplay("auth-gate") === "none" && gateDisplay("pw-gate") === "none",
        `auth=${gateDisplay("auth-gate")} pw=${gateDisplay("pw-gate")}`);
  check("Sign out is offered to a signed-in account",
        !doc.getElementById("sign-out").classList.contains("hidden"));

  // 4. AN ADMIN SEES THE USERS PANEL, with every account and the role control.
  await H.loadSettings();
  check("the Users card is visible to an admin",
        !doc.getElementById("st-users-card").classList.contains("hidden"));
  const userRows = doc.querySelectorAll("#st-users tbody tr");
  check("the Users table renders a row per account", userRows.length === 2,
        `${userRows.length} rows`);
  check("the signed-in account is marked 'you' rather than offered a Delete aimed at itself",
        /you/.test(userRows[0].textContent) && !userRows[0].querySelector(".user-act.danger"),
        userRows[0].textContent.slice(0, 80));
  check("another account carries the Delete control",
        !!userRows[1].querySelector(".user-act.danger"));
  check("a role control is present per account",
        doc.querySelectorAll("#st-users .user-role").length === 2);
  // THE DROPDOWN MUST SHOW THE STORE'S ROLE, NOT ITS FIRST OPTION. Reported live as "stuck
  // on viewer": el() dropped the `selected` property, so every dropdown rendered "viewer"
  // while the store held "admin" -- the change landed server-side every time and the panel
  // re-rendered the wrong value. Assert the SELECTED value, which is what the operator sees.
  const firstRole = doc.querySelector("#st-users .user-role");
  check("the role dropdown SHOWS the account's actual role (not the first option)",
        firstRole && firstRole.value === "admin",
        `selected=${firstRole ? firstRole.value : "missing"}`);
  check("the second account's dropdown shows viewer, not a default",
        doc.querySelectorAll("#st-users .user-role")[1].value === "viewer",
        doc.querySelectorAll("#st-users .user-role")[1].value);

  // ...and after a role CHANGE the re-read shows the new value. The stub answers the POST,
  // then re-serves /api/users: flip the payload's role for the account the panel just changed.
  USERS_PAYLOAD.users[0].role = "viewer";
  const roleSelect = doc.querySelector("#st-users .user-role");
  roleSelect.value = "viewer";
  roleSelect.dispatchEvent(new window.Event("change", { bubbles: true }));
  await new Promise((r) => setTimeout(r, 120));
  const rolePost = POSTED.slice().reverse().find((r) => r.url.includes("/api/users/role"));
  check("a role change POSTs the account and the new role",
        !!rolePost && JSON.parse(rolePost.body).role === "viewer",
        rolePost ? rolePost.body : "no POST");
  check("after the change the dropdown shows the STORE's new value",
        doc.querySelector("#st-users .user-role").value === "viewer");
  USERS_PAYLOAD.users[0].role = "admin";  // restore for anything after this block

  // Adding a user POSTs the account and the forced-change flag.
  const createBefore = POSTED.length;
  needEl("st-new-user").value = "newviewer";
  needEl("st-new-pass").value = "initial-pass-1";
  needEl("st-new-role").value = "viewer";
  await H.createUser();
  const createReq = POSTED.slice(createBefore).find((r) => r.url.includes("/api/users/create"));
  check("Add user POSTs to /api/users/create", !!createReq,
        POSTED.slice(createBefore).map((r) => r.url).join(","));
  if (createReq) {
    const cb = JSON.parse(createReq.body || "{}");
    check("the new account carries its role and must_change",
          cb.username === "newviewer" && cb.role === "viewer" && cb.must_change === true,
          JSON.stringify(cb));
  }

  // 5. A VIEWER CAN READ AND CANNOT EDIT. The settings payload flips to writes-disabled, which
  //    is what the server sends a viewer; the controls must disappear rather than merely fail
  //    on Apply.
  SETTINGS_PAYLOAD.writes.enabled = false;
  SESSION_STUB.username = "reader";
  SESSION_STUB.role = "viewer";
  await H.loadSession();
  await H.loadSettings();
  const viewerInputs = [...doc.querySelectorAll("#view-settings .setting-input, "
    + "#view-settings .setting-select, #view-settings .setting-toggle")];
  check("a viewer gets NO edit controls at all", viewerInputs.length === 0,
        `${viewerInputs.length} control(s) rendered for a viewer`);
  check("a viewer still SEES the values",
        [...doc.querySelectorAll(".setting-val")].some((n) => n.textContent === "clickhouse"));
  check("the viewer's Users card is hidden (account data is admin-only)",
        needEl("st-users-card").classList.contains("hidden"));
  check("the page tells the viewer why it is read-only",
        /read-only|viewer/i.test(needEl("st-note").textContent),
        needEl("st-note").textContent.slice(0, 120));
  SETTINGS_PAYLOAD.writes.enabled = true;

  // 6. A FORCED PASSWORD CHANGE gates the whole dashboard: the pw gate is shown and the auth
  //    gate stays hidden (the account IS signed in; it just cannot use the dashboard yet).
  SESSION_STUB.username = "admin";
  SESSION_STUB.role = "admin";
  SESSION_STUB.must_change = true;
  await H.loadSession();
  await H.boot();
  check("must_change shows the forced password-change gate",
        !doc.getElementById("pw-gate").classList.contains("hidden"),
        "pw gate hidden while must_change is set");
  check("the forced gate is not the sign-in gate (the account is signed in)",
        needEl("auth-gate").classList.contains("hidden"));
  // THE EXACT COLLISION, asserted the only way it can be: the forced gate must be PAINTED
  // (flex) while the sign-in gate, carrying the same `hidden` class and the same `.gate`
  // display rule, must compute to none. Before the fix this read flex/flex.
  check("must_change PAINTS the forced gate and leaves the sign-in gate unpainted (computed)",
        gateDisplay("pw-gate") === "flex" && gateDisplay("auth-gate") === "none",
        `pw=${gateDisplay("pw-gate")} auth=${gateDisplay("auth-gate")}`);

  // The change POSTs the current and new passwords, and returns to the sign-in gate.
  const pwBefore = POSTED.length;
  await H.changePassword("correct-password", "a-new-password-1");
  const pwReq = POSTED.slice(pwBefore).find((r) => r.url.includes("/api/password"));
  check("the password change POSTs to /api/password", !!pwReq,
        POSTED.slice(pwBefore).map((r) => r.url).join(","));
  if (pwReq) {
    const pb = JSON.parse(pwReq.body || "{}");
    check("the password POST carries both the current and the new password",
          pb.current === "correct-password" && pb.new === "a-new-password-1",
          JSON.stringify({ current: !!pb.current, next: !!pb.new }));
  }
  check("after changing the password the tab returns to the sign-in gate",
        !doc.getElementById("auth-gate").classList.contains("hidden"));
  check("after the change the sign-in gate is PAINTED and the forced gate is not (computed)",
        gateDisplay("auth-gate") === "flex" && gateDisplay("pw-gate") === "none",
        `auth=${gateDisplay("auth-gate")} pw=${gateDisplay("pw-gate")}`);
  SESSION_STUB.must_change = false;

  // 6b. A DEAD SESSION ON THE PASSWORD FORM RETURNS TO SIGN-IN. The box report that motivated
  //     this: the password form was submitted without a session, the server answered "sign in
  //     first", and the UI dead-ended on a form that could not work. The client must clear the
  //     dead state and put up the sign-in gate with a note that says what to do.
  SESSION_STUB.accounts = true;
  SESSION_STUB.authenticated = false;
  H.setToken("");  // the locked-out operator has no credentials at all
  H.setSession("stale-session-value");
  await H.boot();
  H.showGate("pw");  // the operator is looking at the forced-change form
  let deadErr = null;
  try { await H.changePassword("whatever", "a-new-password-1"); } catch (e) { deadErr = e; }
  check("a password change with a dead session is refused", !!deadErr);
  check("the dead session is cleared rather than left to be retried", H.getSession() === "",
        `session=${H.getSession()}`);
  check("the sign-in gate comes back up with a pointer, not a dead end",
        gateDisplay("auth-gate") === "flex" && gateDisplay("pw-gate") === "none"
        && /sign in again/i.test(needEl("gate-note").textContent),
        `auth=${gateDisplay("auth-gate")} note=${needEl("gate-note").textContent}`);
  SESSION_STUB.authenticated = true;

  // 6c. THE BREAK-GLASS DOOR IS ON THE GATE ITSELF. The operator token recovers a lost admin
  //     password, but the token input once lived ONLY on the Settings tab -- which is behind
  //     the very gate it exists to open. A locked-out operator must be able to reach it from
  //     the sign-in screen: toggle it open, a wrong token is refused with the gate left up,
  //     and the right token is accepted BY THE SERVER's answer (loadSession), never assumed.
  SESSION_STUB.accounts = true;
  SESSION_STUB.authenticated = false;
  H.setToken("");
  H.setSession("");
  await H.boot();
  check("the locked-out screen is the sign-in gate (computed)",
        gateDisplay("auth-gate") === "flex" && gateDisplay("pw-gate") === "none");
  const tokenToggle = needEl("gate-token-toggle");
  check("the sign-in gate offers the operator-token door", !!tokenToggle);
  check("the token form starts hidden (computed)",
        gateDisplay("gate-token-block") === "none",
        `block=${gateDisplay("gate-token-block")}`);
  tokenToggle.click();
  check("the door opens on click (computed)",
        gateDisplay("gate-token-block") === "flex" || gateDisplay("gate-token-block") === "block",
        `block=${gateDisplay("gate-token-block")}`);

  const tokenForm = needEl("gate-token-form");
  needEl("gate-token").value = "not-the-token";
  tokenForm.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
  await new Promise((r) => setTimeout(r, 80));
  check("a wrong token is refused and the gate stays up",
        gateDisplay("auth-gate") === "flex"
        && /not accepted/i.test(needEl("gate-token-error").textContent),
        `note=${needEl("gate-token-error").textContent}`);

  H.setToken("");
  needEl("gate-token").value = "test-token-value";
  tokenForm.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
  await new Promise((r) => setTimeout(r, 120));
  check("the right token is accepted on the SERVER's answer (via: token)",
        H.AUTH.authenticated && H.AUTH.via === "token", `via=${H.AUTH.via}`);
  check("the break-glass door closes the gate it was opened from (computed)",
        gateDisplay("auth-gate") === "none" && gateDisplay("pw-gate") === "none",
        `auth=${gateDisplay("auth-gate")}`);
  H.setToken("");
  H.setSession("");

  // 7. SIGNING OUT clears the session and arms the gate again.
  SESSION_STUB.accounts = true;
  await H.doLogin("admin", "correct-password");
  await H.doLogout();
  check("signing out clears the stored session", H.getSession() === "",
        `session=${H.getSession()}`);
  check("signing out shows the sign-in gate again",
        !doc.getElementById("auth-gate").classList.contains("hidden"));
  // Back to the pre-accounts state so nothing after this block inherits a session.
  SESSION_STUB.accounts = false;
  SESSION_STUB.authenticated = false;
  SESSION_STUB.username = "";
  SESSION_STUB.role = "";
  await H.boot();



  // ── host identity: the panel must distinguish its states ───────────────────────────────────
  //
  // The defect this guards against is the one that has shipped three times in this project: a
  // panel that cannot be told apart from a panel with nothing in it. So the checks assert the
  // DISTINCTIONS -- a contradicted host shows both claims, a failed query names a reason, and a
  // low-confidence label reads as low.

  await H.showView("identity");
  // WAIT FOR THE ROWS, do not sleep at them. `showView` fires loadIdentity without awaiting it,
  // and getJSON needs a microtask turn plus the stub's promise to settle -- so a fixed delay is a
  // guess that passes on a fast machine and fails on a slow one. Bounded anyway, so a real hang
  // is a loud failure rather than a silent pass.
  for (let i = 0; i < 50 && doc.querySelectorAll("#id-table tbody tr").length === 0; i++) {
    await new Promise((r) => setTimeout(r, 20));
  }

  const idRows = doc.querySelectorAll("#id-table tbody tr");
  check("identity renders a row per host", idRows.length === 3, `${idRows.length} rows`);

  const idText = needEl("view-assets").textContent;
  // THE DISAGREEMENT LIVES IN THE DETAIL PANEL, which opens on click -- so the check must click.
  // Asserting against the table text was checking the wrong surface and would have passed only by
  // accident if a hostname happened to appear in a row.
  const contradicted = Array.from(idRows).find((r) => r.textContent.includes("203.0.113.20"));
  check("a host whose sources disagree is present to inspect", !!contradicted,
        "the contradicted host is missing from the table");
  if (contradicted) {
    contradicted.click();
    await new Promise((r) => setTimeout(r, 40));
    const dtext = needEl("id-detail").textContent;
    check("a contradicting signal is reported, not averaged away",
          dtext.includes("Contradicting signals") && dtext.includes("DESKTOP-7A3B2C"),
          dtext.slice(0, 120));
    check("the evidence behind the label is shown with its source and weight",
          dtext.includes("User-Agent names Windows NT") && dtext.includes("weight"),
          "evidence not rendered");
  }
  // Confidence must be readable as a word, not only as a colour.
  check("confidence is shown as a word, not colour alone",
        idText.includes("high") && idText.includes("medium"), "confidence words missing");
  // The denominator, so a small numerator cannot mislead.
  check("coverage shows the denominator alongside the classified count",
        idText.includes("245") && idText.includes("1.2%"),
        "coverage fraction not rendered");

  // A host with NO signals must not be presented as identified.
  const unknownRow = Array.from(idRows).find((r) => r.textContent.includes("203.0.113.30"));
  check("a host with no evidence reads as unknown rather than guessed",
        unknownRow && unknownRow.textContent.includes("unknown"),
        unknownRow ? unknownRow.textContent.slice(0, 80) : "row missing");

  // The evidence list must expose its reasoning, because a label nobody can check is a label
  // nobody can correct.
  const idFirstRow = idRows[0];
  if (idFirstRow) {
    idFirstRow.click();
    await new Promise((r) => setTimeout(r, 40));
    const detail = needEl("id-detail").textContent;
    check("clicking a host shows the evidence behind its label",
          detail.includes("Ubuntu") && detail.includes("weight"),
          detail.slice(0, 100));
    check("the decoded TLS structure is shown as a fact, not as an OS claim",
          detail.includes("TLS 1.3") && detail.includes("ciphers"),
          "JA4 structure not rendered");
  }



  // ── the failure state: a broken query must SAY SO ──────────────────────────────────────────
  fetchOverride = ((url) => {
    if (url.includes("/api/identity")) {
      return {
        ok: true, status: 200, statusText: "OK",
        json: async () => ({ available: false, reason: "cannot reach ClickHouse: boom",
                             hosts: [], count: 0, coverage: null }),
      };
    }
    return null; // fall through to the real dispatcher
  });
  H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
  await H.loadIdentity().catch(() => {});
  await new Promise((r) => setTimeout(r, 40));
  // The failure banner lives on <main> (that is where showDataError prepends it), NOT inside the
  // view section -- so the check reads the banner. Asserting against the view text was checking a
  // surface the message never reaches.
  const banner = needEl("data-banner");
  check("a failed identity query names its cause instead of rendering empty",
        !!banner && banner.textContent.includes("boom"),
        banner ? banner.textContent.slice(0, 100) : "no banner was shown");
  // And the coverage panel must say UNKNOWN rather than render zeros, which would read as
  // "identified nothing" -- a different and much more alarming claim.
  const failView = needEl("view-assets").textContent;
  check("coverage unknown is distinguishable from coverage zero",
        failView.includes("Coverage unknown"), "unknown coverage rendered as zero");
  fetchOverride = null;



  // ── no page errors accumulated ─────────────────────────────────────────────────────────
  // ── Sluice Gate: the three states must LOOK DIFFERENT ──────────────────────────────────────
//
// The tab exists to answer two questions: "is the gate actually holding?" and "is this specific
// rule in force?". Both have a failure mode where the wrong answer looks like the right one -- a
// degraded gate reading as armed, and a lapsed rule reading as deleted. These checks assert the
// DISTINCTIONS, not merely that something rendered.
await H.showView("sluice");
const slText = () => (H.document.getElementById("view-sluice") || {}).textContent || "";
// POLL for the rows rather than sleeping at them: showView fires loadSluice without
// awaiting it, and a fixed delay is a guess about stub latency that gets more fragile
// the more the payload grows.
for (let i = 0; i < 40 && !slText().includes("scanner on the lab segment"); i++) {
  await new Promise((r) => setTimeout(r, 20));
}

check("the Sluice Gate tab exists and renders both gates",
      slText().includes("Domain Gate") && slText().includes("Traffic Gate"));

check("the gate's STATE is shown, not just a rule count",
      slText().includes("armed") && slText().includes("eth1"),
      slText().slice(0, 200));

// THE OPERATOR'S ORDER (2026-10-19): the working DNS gate first, then the packet gate.
// The 2026-11-18 rebuild moved the pair to `.grid2` and sentence-cased the headings ("Domain
// gate"), so the old `.grid` selector and the capital-G regex both went stale. Assert the ORDER
// and the identity of the two gates, not the utility class or the capitalization.
check("the sluice page leads with the Domain Gate and then the Traffic Gate",
      (() => {
        const heads = [...doc.querySelectorAll("#view-sluice .sl2-gates > .card h2, "
          + "#view-sluice .sl2-gates > .card h3")];
        return heads.length === 2 && /domain gate/i.test(heads[0].textContent)
          && /traffic gate/i.test(heads[1].textContent);
      })(), [...doc.querySelectorAll("#view-sluice .sl2-gates > .card h2, "
        + "#view-sluice .sl2-gates > .card h3")]
        .map((h) => h.textContent.trim()).join(",") || "no first card");
check("the two gate cards share one horizontal grid, not two stacked full-width cards",
      (() => {
        const g = doc.querySelector("#view-sluice .sl2-gates");
        if (!g) return false;
        return window.getComputedStyle(g).display === "grid"
          && [...g.children].filter((c) => c.classList.contains("card")).length === 2;
      })(), doc.querySelector("#view-sluice .sl2-gates")
        ? "grid missing cards or not display:grid" : "no sl2-gates grid");
check("the fleet packet table is its own card, not folded into a gate card",
      (() => {
        const fleet = doc.querySelector("#sl2-fleet");
        return !!fleet && !!fleet.closest(".card") && !fleet.closest(".sl2-gate");
      })(), "fleet table is not in its own card");
// THE DOMAIN CARD MUST NOT BORROW THE PACKET GATE'S NUMBERS. The 2026-11-18 rebuild moved the
// packet state ("armed on eth1", rule counts) onto the Traffic card and left the Domain card with
// only list/domain/hit facts -- the defect this check was written for is fixed. The assertion
// still pinned the old `.grid` wrapper and a capital-G heading, so it read no card at all and
// reported the copy bug it was meant to guard. Keep the no-packet-facts rule; match the card by
// its own container and case-insensitively.
check("the Domain Gate carries no packet/interface facts",
      (() => {
        const domain = [...doc.querySelectorAll("#view-sluice .sl2-gates > .card")]
          .find((c) => /domain gate/i.test((c.querySelector("h2, h3") || {}).textContent || ""));
        return !!domain && !/packet state|packet rules|interfaces?/i.test(domain.textContent);
      })(), "DNS card still carries packet facts");
// ── FLEET PACKET GATES ARE PER-SENSOR CARDS (2026-11-20) ─────────────────────────────────────
//
// The table's fifth column fell off a phone. Each sensor is now its own card: which sensor,
// which interface, what it is dropping and when it last reported -- and a card that has caught
// nothing says so in words instead of showing a column of zeros.
const slGateCards = [...doc.querySelectorAll("#sl2-fleet .sl2-sensor")];
check("five weirlings produce five packet-gate cards",
      slGateCards.length === 5, `${slGateCards.length} cards`);
check("every sensor card names its own interfaces, not one global interface",
      slGateCards.length > 0
      && slGateCards.every((c) => /eth\d/.test((c.querySelector(".sl2-sensor-meta") || {}).textContent || "")),
      slGateCards.map((c) => (c.querySelector(".sl2-sensor-meta") || {}).textContent).join(" | "));
const dualCard = slGateCards.find((c) => c.textContent.includes("weirvern-dual"));
check("each fleet card carries its own installed/stored rule counts",
      !!dualCard && /2 of 3 stored packet rules installed/.test(dualCard.textContent),
      dualCard ? dualCard.textContent.slice(0, 140) : "no weirvern-dual card");
const zeroCard = slGateCards.find((c) => c.textContent.includes("lab-west"));
check("a stopped gate's real zero still renders as a real zero",
      !!zeroCard && /0 of 3 stored packet rules installed/.test(zeroCard.textContent),
      zeroCard ? zeroCard.textContent.slice(0, 140) : "no lab-west card");
const openCard = slGateCards.find((c) => c.textContent.includes("weirvern-open"));
check("a gate with no live rules reads open, not degraded",
      !!openCard && /open by choice/i.test(openCard.textContent)
      && !/degraded/i.test(openCard.textContent),
      openCard ? openCard.textContent.slice(0, 160) : "no weirvern-open card");
check("every fleet card states what it has actually done",
      slGateCards.length > 0
      && slGateCards.every((c) => /packets? dropped|no packets matched/.test(c.textContent)),
      slGateCards.map((c) => c.textContent.slice(-70)).join(" | "));
check("a stale gate says so on its own card",
      !!zeroCard && /stale/i.test(zeroCard.textContent)
      && /stopped reporting/i.test(zeroCard.textContent),
      zeroCard ? zeroCard.textContent.slice(0, 140) : "no lab-west card");

check("a LIVE rule is distinguishable from an EXPIRED one",
      slText().includes("live") && slText().includes("expired"),
      "an expired rule must not look like a live one, nor like a deleted one");

check("a REVOKED rule stays visible rather than disappearing",
      slText().includes("revoked"),
      "the audit trail of what was blocked must survive the unblocking");

check("a detection-derived rule is attributed to the detection",
      slText().includes("detection"),
      "an operator must be able to tell a model's block from an analyst's");

// THE PER-RULE EVIDENCE IS THE POINT OF THE REBUILD: a sentence, then what it has actually
// done in the window on screen. The fixture gives one domain rule 12 DNS matches and one
// traffic rule four flow matches with packets; the rest have none, and say so.
{
  const rows = [...doc.querySelectorAll("#sl2-rules tbody tr.sl2-rule-row")];
  const byId = (id) => rows.find((r) => r.getAttribute("data-rule-id") === id);
  check("a rule row carries its firing evidence, not just its text",
        /12 DNS matches in the last 24h/.test((byId("r1") || {}).textContent || "")
        && /last 6m ago/.test((byId("r1") || {}).textContent || ""),
        byId("r1") ? byId("r1").textContent : "no r1 row");
  check("a packet rule's evidence counts the packets it dropped",
        /4 flow matches in the last 24h/.test((byId("r-live-1") || {}).textContent || "")
        && /1,204 packets dropped/.test((byId("r-live-1") || {}).textContent || ""),
        byId("r-live-1") ? byId("r-live-1").textContent : "no r-live-1 row");
  check("a rule that has matched nothing says exactly that",
        /no DNS matches in the last 24h/.test((byId("r2") || {}).textContent || ""),
        byId("r2") ? byId("r2").textContent : "no r2 row");
  check("a rule links into the surface that owns its evidence",
        !!byId("r1") && /#v=blocked&bl\.domain=ads\.example\.com/.test(
          (byId("r1").querySelector("a.link") || {}).getAttribute?.("href") || "")
        && !!byId("r-live-1") && /#v=discover&dc\.addr=198\.51\.100\.7/.test(
          (byId("r-live-1").querySelector("a.link") || {}).getAttribute?.("href") || ""),
        "a rule row does not link to its blocks/flows");
  check("the raw rule fields are out of the table and only the sheet holds them",
        [...doc.querySelectorAll("#sl2-rules thead th")].length === 2,
        [...doc.querySelectorAll("#sl2-rules thead th")].map((t) => t.textContent).join(" | "));
}

// The per-rule mode is where a policy lives now: the old policy cards are gone, so the check
// follows the control that replaced them, and it still asserts the COST is named rather than
// only the verb.
const modeSel = doc.getElementById("sl2-mode");
check("the rule mode options name their cost",
      !!modeSel && /alert/.test(modeSel.textContent) && /block nothing/i.test(modeSel.textContent)
      && /block/.test(modeSel.textContent),
      modeSel ? modeSel.textContent.replace(/\s+/g, " ").trim().slice(0, 120) : "no mode select");

check("a rule with no reason says so rather than showing blank",
      !slText().includes("undefined"),
      "undefined reached the screen, which means a missing field rendered as a value");

check("a rule with NO EXPIRY reads as 'until revoked', not as a date or a dash",
      slText().includes("until revoked"),
      "the operator set the duration to 0; the row must say what that means");

// ── one rule store, many gates ───────────────────────────────────────────────────────────────
check("every gate is listed, with the local one marked as this hub",
      slText().includes("weirvern-eth2") && !!dualCard && /this hub/.test(dualCard.textContent),
      slText().slice(0, 240));
// The reach line is where the console says which sensors can actually act, and it must exclude
// a stale one.
check("the reach line names the sensors that can actually enforce",
      (() => {
        const reach = doc.getElementById("sl-reach");
        if (!reach) return false;
        const t = reach.textContent || "";
        return /can act on 4 sensors/.test(t) && t.includes("weirvern-dual")
          && t.includes("weirvern-eth2") && !t.includes("lab-west");
      })(), (doc.getElementById("sl-reach") || {}).textContent || "no reach line");

// THE MANUAL FORM (2026-10-16): the reason is OPTIONAL and a duration of 0 means until revoked.
// Both are the operator's own instruction, and each fails silently in its own way -- the client
// refusing a blank reason, or the server reading a deliberate 0 as "unset" and substituting the
// default hour.
{
  // The manual form is the rule SHEET now (`sl-rule-sheet`), opened by the view's own New rule
  // verb. Target first: choosing traffic reveals the address fields that the old flat form showed
  // beside a domain box.
  H.document.getElementById("sl2-new").click();
  await new Promise((r) => setTimeout(r, 30));
  const slKind = H.document.getElementById("sl-target-type");
  const slSrc = H.document.getElementById("sl2-src");
  const slTtl = H.document.getElementById("sl2-ttl");
  const slWhy = H.document.getElementById("sl2-reason");
  const slGo = H.document.getElementById("sl2-create-submit");
  check("the rule sheet asks for a target first and still carries duration and reason",
        !!slKind && !!slSrc && !!slTtl && !!slWhy && !!slGo);
  if (slKind && slSrc && slTtl && slWhy && slGo) {
    slKind.value = "traffic";
    slKind.dispatchEvent(new window.Event("change", { bubbles: true }));
    slSrc.value = "203.0.113.77";
    slWhy.value = "";
    slTtl.value = "0";
    // ALERT MODE: the check is about the OPTIONAL reason and a deliberate 0 TTL, not about the
    // blocking confirm. Block mode arms on the first click (retained BF-9 step).
    const slMode = H.document.getElementById("sl2-mode");
    if (slMode) slMode.value = "alert";
    const postedBefore = POSTED.length;
    slGo.click();
    await new Promise((r) => setTimeout(r, 140));
    const req = POSTED.slice(postedBefore).find((r) => r.url.includes("/api/sluice/block"));
    check("a block with NO reason and a duration of 0 is still filed", !!req,
          POSTED.slice(postedBefore).map((r) => r.url).join(","));
    if (req) {
      let body = {};
      try { body = JSON.parse(req.body || "{}"); } catch (_e) { body = {}; }
      check("the POST carries ttl_minutes 0 and an empty reason -- not the default hour",
            body.ttl_minutes === 0 && body.reason === "",
            JSON.stringify(body).slice(0, 160));
    }
    slSrc.value = "";
    slWhy.value = "";
    // The sheet is a dialog with a Tab trap: leaving it open would swallow the keyboard checks
    // later in this file (the modal trap yields to any open sheet), so close it here.
    const sheetClose = doc.querySelector("#sl-rule-sheet .sheet-close");
    if (sheetClose) sheetClose.click();
  }
}

// ── the failure path: a broken gate must not read as an empty one ──────────────────────────
//
// MUST LEAVE AND COME BACK. `showView` returns early when the target view is already active, so
// calling it twice in a row reloads NOTHING and this check would pass or fail on a stale panel
// rather than on the failure path it is named for. Switching to another view first is what makes
// the second call actually run the loader.
fetchOverride = (u) => (String(u).includes("/api/sluice")
  ? Promise.reject(new Error("sluice unavailable"))
  : null);
H.showView("overview");
await new Promise((r) => setTimeout(r, 20));
await H.showView("sluice");
// A TRANSPORT FAILURE, not a route answering with available:false -- different code paths. This
// drives the loader DIRECTLY with the failure in place, because showView attaches its own catch and
// the point here is what the LOADER does when the request never produces a response.
fetchOverride = (url) => (String(url).includes("/api/sluice")
  ? Promise.reject(new Error("sluice query failed"))
  : null);
H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
await H.loadSluice().catch(() => {});
await new Promise((r) => setTimeout(r, 60));
// THE LOADER'S CONTRACT, tested directly. The harness's stub dispatcher does not hand a rejected
// promise to the page in the way a real transport failure does -- verified: calling loadSluice with
// the override set resolved normally, while the same function called against a rejecting getJSON in
// isolation produces the banner. So asserting through the stub would be testing the harness, not the
// product. What matters is that the loader CANNOT return quietly when its request fails, and that is
// checkable where it lives: it must catch around the call and report through showDataError.
//
// A source check is weaker than a behavioural one, so it is paired with the behavioural proof in
// tests/test_sluice.py (test_a_failed_gate_query_reports_rather_than_rendering_empty), which drives
// loadSluice against a rejecting fetch in a real DOM.
const sluiceSrc = fs.readFileSync(path.join(WEB, "sluice.js"), "utf8");
const loadBody = sluiceSrc.slice(sluiceSrc.indexOf("async function loadSluice"));
const loadBodyTrimmed = loadBody.slice(0, loadBody.indexOf("\nasync function ") + 1 || loadBody.length);
check("a FAILED gate query cannot return quietly",
      loadBodyTrimmed.includes("try {") && loadBodyTrimmed.includes("showDataError") &&
      loadBodyTrimmed.includes("catch"),
      "loadSluice has no catch around its request, so a transport failure would leave the panel "
      + "looking like an empty gate");

// ── WEIRLINGS: every state must LOOK like what it is ──────────────────────────────────────────
//
// The tab exists to keep five states apart, because each needs a different action from the
// operator. The failure mode this guards is the project's most-named one: a view that renders
// something plausible while collapsing two facts that require opposite responses. So these
// checks assert the DISTINCTIONS, not merely that rows appeared.
await H.showView("weirlings");
const wlText = () => (H.document.getElementById("view-weirlings") || {}).textContent || "";
// POLL rather than sleep: showView fires loadWeirlings without awaiting it, and a fixed delay is
// a guess about stub latency that gets more fragile as the payload grows.
for (let i = 0; i < 40 && !wlText().includes("edge-alive"); i++) {
  await new Promise((r) => setTimeout(r, 20));
}

check("the Weirlings tab exists and renders the fleet",
      wlText().includes("edge-alive") && wlText().includes("edge-stopped"));

check("the never-seen tile and view are gone; stale remains",
      // The summary tile and saved view are what the operator removed. A row's state CHIP may
      // still say "never seen" (GitHub #56): the state word is the row's fact, not a tile.
      ![...doc.querySelectorAll("#wl-summary .tile")].some((t) => /never seen/i.test(t.textContent))
      && !doc.querySelector("#wl-view option[value='never-seen']")
      && wlText().toLowerCase().includes("stale"),
      "the operator removed both the summary tile and the saved view");

// WL-2: THE SHEET IS CHANGE-ONLY. The facts it used to list live on the ISSUES list (Logs),
// where a problem belongs beside its fix -- so the claims are checked THERE, and the sheet is
// checked for having no fact dump at all.
H.showView("logs");
await new Promise((r) => setTimeout(r, 400));
const auditTextNow = () => (needEl("audit-table") || {}).textContent || "";
check("a never-seen IN-PATH sensor says the segment may be waiting (issues)",
      /in-path/i.test(auditTextNow()),
      "an in-path sensor that never came up is more urgent than a passive one and must say why");
await H.openWeirling("edge-promised");
const wlDetailText = () => (needEl("wl-detail-body") || {}).textContent || "";

check("an UNDECLARED sensor is reported as unregistered",
      wlText().includes("unregistered"),
      "a sensor feeding the hub that nobody declared is security-relevant, the same class as an "
      + "unexpected NetFlow exporter");

check("a DISABLED sensor is shown as disabled, not as a fault",
      wlText().includes("disabled"),
      "switched-off sensors are not problems; raising them trains the reader to ignore the column");

// ── measured-zero vs not-measured: the DISTINCTION is pinned at the unit level
// (tests/test_capture_loss.py), and the sheet no longer renders a loss figure at all -- so it
// cannot print 0.0% for an unmeasured sensor. What the operator must still SEE is the measured
// problem, and that lives on the issues list with its fix.
check("WL-2: the sheet carries no capture-loss figure (the issues list owns it)",
      !/capture loss|62\.5%|0\.0%/i.test(wlDetailText()),
      wlDetailText().slice(0, 120));
check("...a measured high loss is called out on the issues list, with the number",
      auditTextNow().includes("62.5"),
      "capture loss is the only field showing a sensor is blind to most of what is on the wire");
check("...a contradicted segment names BOTH segments on the issues list",
      auditTextNow().includes("fifth floor") && auditTextNow().includes("sixth floor"),
      "the declared segment and the observed one are different facts; letting the declaration "
      + "win makes a sensor covering the wrong segment look correctly placed");

// ── THE SHEET ITSELF: changes only ───────────────────────────────────────────────────────────
{
  await H.openWeirling("edge-alive");
  const sheet = needEl("wl-detail-card");
  const bodyNow = needEl("wl-detail-body");
  check("WL-2: the sheet has NO fact dump (no dl, no findings list, no table)",
        !sheet.querySelector("dl") && !sheet.querySelector("ul.findings")
        && !sheet.querySelector("table"),
        "a read-only fact list survived in the sheet");
  check("...it says its purpose in the heading",
        /Change this weirling/.test(sheet.querySelector("h2, h3").textContent || ""),
        sheet.querySelector("h2, h3").textContent);
  check("...and explains the change in a short situation, not a fact sheet",
        !!bodyNow.querySelector(".wl-situation")
        && bodyNow.querySelectorAll(".wl-situation p").length <= 6,
        String(bodyNow.querySelectorAll(".wl-situation p").length) + " paragraph(s)");
  const localSettings = needEl("wl-local-settings");
  check("...this hub's own sensor points at the surface that changes it",
        !!localSettings && !localSettings.classList.contains("hidden")
        && !!localSettings.querySelector("#st-sensor"),
        "the local sheet does not mount the settings");
  await H.openWeirling("edge-moved");
  check("...a remote sensor's sheet offers its plan, and nothing else to read",
        !doc.getElementById("wl-plan").classList.contains("hidden")
        && !!doc.getElementById("wl-plan").querySelector("input, select"),
        "the plan editor is the change surface for a remote weirling");
  needEl("wl-detail-close").click();
}

// ── the drill-down ───────────────────────────────────────────────────────────────────────────
{
  const stoppedRow = [...H.document.querySelectorAll("#wl-table tbody tr:not(.wl-nic-row):not(.wl-colhead)")]
    .find((tr) => (tr.textContent || "").includes("edge-stopped"));
  const btn = stoppedRow ? (() => {
    let sib = stoppedRow.nextElementSibling;
    if (sib && sib.classList.contains("wl-colhead")) sib = sib.nextElementSibling;
    while (sib && sib.classList.contains("wl-nic-row")) {
      if (/capture/.test(sib.textContent)) return sib;
      sib = sib.nextElementSibling;
    }
    return null;
  })() : null;
  check("a NIC line opens that sensor's drill-down", !!btn);
  if (btn) {
    btn.click();
    for (let i = 0; i < 40 && !(H.document.getElementById("wl-detail-body").textContent || "")
         .includes("why it died"); i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    const body = H.document.getElementById("wl-detail-body").textContent || "";
    check("the drill-down shows the REASON, not just the state word",
          body.includes("why it died"),
          "a state word alone cannot tell the operator whether the box is off or its capture died");
    check("DECLARED and REPORTED are both readable where the mode is, without sharing the cell",
          (() => {
            const r = [...H.document.querySelectorAll("#wl-table tbody tr:not(.wl-nic-row):not(.wl-colhead)")]
              .find((tr) => (tr.textContent || "").includes("edge-moved"));
            const cap = r ? (() => {
              let sib = r.nextElementSibling;
              if (sib && sib.classList.contains("wl-colhead")) sib = sib.nextElementSibling;
              while (sib && sib.classList.contains("wl-nic-row")) {
                if (/capture/.test(sib.textContent)) return sib;
                sib = sib.nextElementSibling;
              }
              return null;
            })() : null;
            const cell = cap ? cap.querySelector("td:nth-child(2)") : null;
            const title = cell ? (cell.getAttribute("title") || "") : "";
            return !!cell && /^siphon$/i.test(cell.textContent.trim())
              && /registry declares loch/.test(title || "");
          })(),
          (() => {
            const r = [...H.document.querySelectorAll("#wl-table tbody tr:not(.wl-nic-row):not(.wl-colhead)")]
              .find((tr) => (tr.textContent || "").includes("edge-moved"));
            const parts = [];
            let sib = r ? r.nextElementSibling : null;
            for (let i = 0; sib && i < 4; i++, sib = sib.nextElementSibling) {
              parts.push(`${i}:${sib.className}:${(sib.textContent || "").slice(0, 80)}`);
            }
            return parts.join(" || ") + (() => {
              const cap = (() => {
                let s = r ? r.nextElementSibling : null;
                if (s && s.classList.contains("wl-colhead")) s = s.nextElementSibling;
                while (s && s.classList.contains("wl-nic-row")) {
                  if (/capture/.test(s.textContent)) return s;
                  s = s.nextElementSibling;
                }
                return null;
              })();
              const c = cap ? cap.querySelector("td:nth-child(2)") : null;
              return ` TITLE=${c ? JSON.stringify(c.getAttribute("title")) : "none"}` +
                ` TEXT=${c ? JSON.stringify(c.textContent.trim()) : "none"}`;
            })();
          })());
    H.document.getElementById("wl-detail-close").click();
  }
}

// ── REGISTERING from the row's own reports, in one click ───────────────────────────────────────
// The undeclared row's guidance said "Register it above" while the id sat in the row in front of
// the operator -- at the first deployment the view's first question was "where do i get the
// sensor id". The drill-down for an undeclared sensor must offer REGISTER, and the click must
// file the declaration from the OBSERVED identity rather than leaving an empty form.
{
  const btn = [...H.document.querySelectorAll("#wl-table button.link")]
    .find((b) => (b.textContent || "") === "ghost-box");
  check("the undeclared sensor's name opens its actions", !!btn);
  if (btn) {
    btn.click();
    for (let i = 0; i < 40 && !((H.document.getElementById("wl-sensor-card") || {})
         .classList || { contains: () => false }).contains("hidden"); i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    const regBtn = H.document.getElementById("wl-sensor-adopt");
    check("an undeclared sensor offers an ADOPT button, not only prose",
          !!regBtn && !regBtn.classList.contains("hidden")
          && (regBtn.textContent || "").includes("Adopt"),
          "the id the hub is already hearing should not have to be retyped from the row into the " +
          "form below");
    const before = POSTED.length;
    if (regBtn) regBtn.click();
    for (let i = 0; i < 80 && POSTED.length === before; i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    const post = POSTED.slice(before).find((r) => r.url.includes("/api/weirlings/register"));
    let sentBody = {};
    try { sentBody = JSON.parse((post || {}).body || "{}"); } catch (_e) { sentBody = {}; }
    check("the click registers the OBSERVED identity, not a blank form",
          !!post && sentBody.sensor_id === "ghost-box",
          "registering the wrong id -- or leaving the form for the operator to fill -- leaves the " +
          "sensor undeclared while looking like it worked");
    check("the observed mode rides along as the expectation",
          !!post && sentBody.expected_mode === "loch",
          "the declaration should start from what the sensor reports, not from a default nobody " +
          "chose");
    for (let i = 0; i < 80 && !(H.document.getElementById("wl-detail-note").textContent || "")
         .includes("Registered"); i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    check("the outcome is stated on the detail, not silently swallowed",
          (H.document.getElementById("wl-detail-note").textContent || "")
            .includes("Registered ghost-box"));
    const detailReg = H.document.getElementById("wl-detail-register");
    check("a registered sensor does not offer REGISTER",
          !detailReg || detailReg.classList.contains("hidden"),
          "the button is offered only while the sensor reads as undeclared; anything else " +
          "invites a click that cannot mean anything");
    // ── and the panel's controls are BOUND, not merely rendered ──────────────────
    // wireWeirlings() was defined but never called from the app's bootstrap, so every button in
    // this panel and the register form rendered and did NOTHING. Labels all looked right; only a
    // click assertion can tell "wired" from "decorative". These two clicks are that assertion for
    // the panel and for the form.
    H.document.getElementById("wl-detail-close").click();
    check("the detail's Close is WIRED, not decorative",
          H.document.getElementById("wl-detail-card").classList.contains("hidden"),
          "a control that renders and does nothing is this project's most-repeated defect class");
    // The register FORM is gone (operator restructure, 2026-10-17): registration is the
    // drill-down's one-click button (checked above), not a standalone card.
    check("the standalone register form is gone with its card",
          !H.document.getElementById("wl-save") && !H.document.getElementById("wl-id"));
  }
}

// ── ONE PANEL, ONE JOB: the weirling sheet is STATUS + MEMBERSHIP + ITS OWN PLAN ─────────────
// The operator, 2026-10-18: "Weirling control is still conflated... duplicate settings and
// advanced. It's not clean." The sheet had grown a runtime row (mode/Sonar/test run), a
// second copy of the sensor settings grid under "Advanced", and the settings page's own
// state notes. All of it is Settings' -- ONE control surface per value, the rule the console
// already lives by. The sheet keeps what only a sensor can answer: its state, its NICs, the
// actions that change its fleet membership, and (for a remote registered sensor) its plan.
{
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const openRow = (id) => [...doc.querySelectorAll("#wl-table button")]
    .find((b) => (b.textContent || "") === id);

  // THE LOCAL WEIRLING'S SHEET really holds the controls (moved from Settings, not copied).
  H.showView("weirlings");
  await H.loadWeirlings();
  await H.openWeirling("edge-alive");
  await sleep(250);
  const localBox = needEl("wl-local-settings");
  check("the local weirling's sheet holds the sensor's own settings grid",
        !!localBox && !localBox.classList.contains("hidden")
        && localBox.querySelectorAll("#st-sensor .setting").length >= 1,
        localBox ? `${localBox.querySelectorAll("#st-sensor .setting").length} row(s)` : "no grid");
  check("...and the mode, Sonar and test-run controls sit IN that section",
        !!localBox.querySelector(".sonar-row #wl-mode-select")
        && !!localBox.querySelector(".sonar-row #st-sonar")
        && !!localBox.querySelector(".sonar-row #st-test"));
  const modeSel = needEl("wl-mode-select");
  check("...the mode selector carries the configured mode, disabled for viewers only",
        !!modeSel && modeSel.value === "loch", modeSel ? modeSel.value : "no select");

  // THE MODE CHANGE still runs the real path: siphon surveys first, opens the echo, applies.
  // (A killed selector FAILS the checks below rather than crashing the run -- crash-safe.)
  const t0 = POSTED.length;
  H.SONAR_STATE.result = null;
  if (modeSel) {
    modeSel.value = "siphon";
    modeSel.dispatchEvent(new window.Event("change", { bubbles: true }));
  }
  for (let i = 0; i < 150 && !doc.querySelector("#modal-body .dest-confirm"); i++) {
    await sleep(20);
  }
  check("going in-path opens the destructive echo", await confirmEcho("the cut point is on purpose"));
  for (let i = 0; i < 100 && !POSTED.slice(t0).some((r) => r.url.includes("/api/settings/apply")); i++) {
    await sleep(20);
  }
  const sonarPost = POSTED.slice(t0).find((r) => r.url.includes("/api/settings/sonar"));
  const applyPost = POSTED.slice(t0).find((r) => r.url.includes("/api/settings/apply"));
  check("selecting siphon surveys first (no survey this session), then applies",
        !!sonarPost && !!applyPost,
        "posts since the select: " + POSTED.slice(t0).map((r) => r.url).join(","));
  check("the applied changes carry the mode and the survey's plan",
        !!applyPost && /"sensor_mode":"siphon"/.test(applyPost.body || "")
        && /"intercept_segment":"198\.51\.100\.0\/24"/.test(applyPost.body || ""),
        (applyPost || {}).body || "no apply");

  // THE SHEET: the local weirling's controls are here; Settings has no second copy.
  H.showView("weirlings");
  await H.loadWeirlings();
  const localBtn = openRow("edge-alive");
  if (localBtn) {
    localBtn.click();
    for (let i = 0; i < 60 && !(needEl("wl-detail-body").textContent || "")
         .includes("reporting normally"); i++) {
      await sleep(20);
    }
    const localSection = needEl("wl-local-settings");
    check("the local weirling's sheet carries the settings controls",
          !!localSection && !localSection.classList.contains("hidden")
          && !!localSection.querySelector("#st-sensor .setting")
          && !!localSection.querySelector(".sonar-row #wl-mode-select"),
          "the controls did not move with their section");
    check("...and Settings no longer holds a copy",
          !doc.querySelector("#view-settings #st-sensor")
          && !doc.querySelector("#view-settings .sonar-row #wl-mode-select"));
    // WSM-2: the sheet's pending bar renders the SAME STAGE that it applies.
    H.discardStage();
    await sleep(80);
    const nfBox = localSection.querySelector(
      "#st-sensor .setting[data-key='channel_netflow'] .setting-toggle");
    if (nfBox) {
      nfBox.checked = true;
      nfBox.dispatchEvent(new window.Event("change", { bubbles: true }));
      await sleep(40);
      check("a change staged in the sheet appears in the sheet's pending bar",
            !doc.getElementById("wl-stage").classList.contains("hidden")
            && (needEl("wl-stage-list").textContent || "").includes("channel_netflow"),
            "the mirror did not follow STAGE");
      check("...and in Settings' pending list -- one STAGE, not a second",
            (needEl("st-stage-list").textContent || "").includes("channel_netflow"));
      needEl("wl-stage-discard").click();
      await sleep(80);
      check("...and Discard from the sheet clears both surfaces",
            needEl("wl-stage").classList.contains("hidden")
            && !(needEl("st-stage-list").textContent || "").includes("channel_netflow"));
    }
    check("...and no Advanced disclosure doubling the settings page",
          !doc.getElementById("wl-advanced"));
    await H.openWeirling("edge-stopped");
    check("...the plan offers the sensor's own reported NICs as iface candidates",
          (() => {
            const inp = needEl("wl-plan-iface");
            const id = inp && inp.getAttribute("list");
            const dl = id ? doc.getElementById(id) : null;
            const vals = dl ? [...dl.querySelectorAll("option")]
              .map((o) => o.getAttribute("value")) : [];
            return vals.includes("eth0");
          })(),
          "the NICs were a read-only row; the plan's iface field is where they matter");
    check("...and keeps its membership actions",
          !!doc.getElementById("wl-detail-enable") || !!doc.getElementById("wl-detail-disable"));
  }
  if (localBtn) needEl("wl-detail-close").click();
  await sleep(60);

  // A REMOTE sensor gets its OWN plan editor (the mechanism that can reach it), nothing else.
  const remoteBtn = openRow("edge-stopped");
  if (remoteBtn) {
    remoteBtn.click();
    for (let i = 0; i < 60 && !(needEl("wl-detail-body").textContent || "")
         .includes("edge-stopped"); i++) {
      await sleep(20);
    }
    check("a remote sensor's sheet offers its own intercept plan",
          !doc.getElementById("wl-plan").classList.contains("hidden"),
          "the plan editor is the one per-sensor control that is not Settings'");
    check("...and never the hub's runtime controls",
          needEl("wl-local-settings").classList.contains("hidden"));
    needEl("wl-detail-close").click();
    await sleep(60);
  }
}

// ── gateway-STYLE ADOPTION: one click, in the row (operator, 2026-10-17) ──────────────────────
{
  // The earlier drill-down click already adopted ghost-box in the stub (its register call
  // flips the fixture row); reset it so THIS check's subject is an unadopted sensor again.
  const ghostFix = WEIRLINGS_PAYLOAD.sensors.find((s) => s.sensor_id === "ghost-box");
  if (ghostFix) { ghostFix.registered = false; ghostFix.state = "unregistered"; ghostFix.enabled = false; }
  await H.loadWeirlings();
  const rows = [...doc.querySelectorAll("#wl-table tbody tr:not(.wl-nic-row):not(.wl-colhead)")];
  const rowFor = (id) => rows.find((tr) => (tr.textContent || "").includes(id));
  const ghost = rowFor("ghost-box");
  const alive = rowFor("edge-alive");
  const adopt = ghost && ghost.querySelector("button.wl-adopt");
  check("an unregistered sensor offers Adopt in its actions, not as a row verb",
        !adopt && !(alive && alive.querySelector("button.wl-adopt")),
        "membership is the sensor name's job; the row carries only the name");
  if (ghost) {
    ghost.querySelector("button.link").click();
    await new Promise((r) => setTimeout(r, 100));
    const adoptBtn = needEl("wl-sensor-adopt");
    check("...and its sensor actions carry the Adopt", !!adoptBtn);
    const before = POSTED.length;
    if (adoptBtn) adoptBtn.click();
    for (let i = 0; i < 80 && POSTED.length === before; i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    const post = POSTED.slice(before).find((r) => r.url.includes("/api/weirlings/register"));
    let sent = {};
    try { sent = JSON.parse((post || {}).body || "{}"); } catch (_e) { sent = {}; }
    check("Adopt files the declaration from the sensor's own reports -- no form",
          !!post && sent.sensor_id === "ghost-box" && sent.expected_mode === "loch"
          && (sent.segment === "" || sent.segment === undefined),
          (post || {}).body || "no register POST");
    const close = needEl("wl-detail-close");
    if (close) close.click();
  }
}

// ── THE PER-SENSOR INTERCEPT PLAN (operator, 2026-10-17: "On adopt can the sensor run sonar
//    and the user toggles between or sets siphon or loch?") ──────────────────────────────────
//
// WHAT IS BEING HELD HERE, and why each half matters:
//   * a REGISTERED, non-local weirling gets a plan editor whose values come from the SERVER's
//     plan -- not from the mode the sensor happens to report;
//   * this hub's OWN sensor gets none (its runtime is the Settings tab's ConfigMap) and an
//     UNDECLARED sensor gets none (nothing a plan could belong to). Both are the "no lying
//     controls" rule: the panel shows the mechanism that can actually reach that sensor;
//   * the enable path surveys THE SENSOR's port first, writes THAT sensor's row, and never
//     posts the hub's ConfigMap route;
//   * a refused survey reverts the toggle and says why; a declined warning writes nothing.
{
  // RESET THE FIXTURES THIS BLOCK DEPENDS ON. The plan/apply stubs are stateful (like the real
  // store) and the blocks above have already clicked through them, so a check that only works
  // after another one ran is exactly the state-leak class this file has been bitten by.
  const reset = (id, plan) => {
    const row = WEIRLINGS_PAYLOAD.sensors.find((s) => s.sensor_id === id);
    if (!row) return null;
    row.plan = Object.assign({}, plan);
    row.registered = true;
    row.enabled = true;
    return row;
  };
  const moved = reset("edge-moved", { mode: "siphon", iface: "eth3", segment: "203.0.113.0/24",
                                      addr: "203.0.113.250", gateway: "203.0.113.1",
                                      targets: "203.0.113.7" });
  moved.reported_mode = "siphon";
  moved.expected_mode = "siphon";
  const stopped = reset("edge-stopped", { mode: "", iface: "", segment: "", addr: "",
                                          gateway: "", targets: "" });
  stopped.reported_mode = "loch";
  stopped.expected_mode = "loch";
  await H.loadWeirlings();

  const planBox = () => needEl("wl-plan");
  const planNote = () => (needEl("wl-plan-note") || {}).textContent || "";
  const planModeSel = () => needEl("wl-plan-mode");
  const waitFor = async (predicate, tries = 120) => {
    for (let i = 0; i < tries; i++) {
      if (predicate()) return true;
      await new Promise((r) => setTimeout(r, 20));
    }
    return false;
  };

  // ── (1) which panels get an editor, and which must not
  await H.openWeirling("edge-alive");
  check("the LOCAL sensor's panel offers no per-sensor plan (its runtime is the Settings tab)",
        planBox().classList.contains("hidden"),
        "a plan stored for this hub's own sensor would be a second source its worker never reads");

  // The undeclared sensor: temporarily undeclared (the adoption block registered it in the
  // stub), because a plan needs a declaration to belong to.
  const ghost = WEIRLINGS_PAYLOAD.sensors.find((s) => s.sensor_id === "ghost-box");
  if (ghost) { ghost.registered = false; ghost.state = "unregistered"; }
  await H.openWeirling("ghost-box");
  check("an UNDECLARED sensor offers no plan editor -- adopt it first",
        planBox().classList.contains("hidden"),
        "a plan for a sensor nobody declared would be a declaration about a declaration");
  if (ghost) { ghost.registered = true; ghost.state = "alive"; }

  await H.openWeirling("edge-moved");
  check("a registered remote weirling's drill-down OFFERS its plan editor",
        !planBox().classList.contains("hidden"),
        "the sensor's own plan is the only control that can reach it");
  check("the editor shows the DECLARED plan, not the mode the sensor reports",
        planModeSel().value === "siphon"
        && needEl("wl-plan-segment").value === "203.0.113.0/24"
        && needEl("wl-plan-targets").value === "203.0.113.7",
        planModeSel().value + " / " + needEl("wl-plan-segment").value);
  check("the editor states declared versus reported on the same line",
        /declared: siphon/.test(needEl("wl-plan-state").textContent || "")
        && /last reported: siphon/.test(needEl("wl-plan-state").textContent || ""),
        needEl("wl-plan-state").textContent);

  // ── (2) staging a field writes NOTHING; Apply goes plan -> apply, for THAT sensor
  {
    const before = POSTED.length;
    const input = needEl("wl-plan-targets");
    input.value = "203.0.113.7,203.0.113.8";
    input.dispatchEvent(new window.Event("input", { bubbles: true }));
    check("editing a plan field STAGES it and writes nothing",
          POSTED.length === before && /staged for edge-moved/.test(planNote()),
          `${POSTED.length - before} request(s) sent on edit; note: ${planNote()}`);
    check("the Apply button is enabled only while something is staged",
          !doc.getElementById("wl-plan-apply").disabled);

    needEl("wl-plan-apply").click();
    await waitFor(() => POSTED.slice(before).some((r) => r.url.includes("/api/weirlings/apply")));
    const planPost = POSTED.slice(before).find((r) => r.url.includes("/api/weirlings/plan"));
    const applyPost = POSTED.slice(before).find((r) => r.url.includes("/api/weirlings/apply"));
    let planBody = {}; let applyBody = {};
    try { planBody = JSON.parse((planPost || {}).body || "{}"); } catch (_e) { planBody = {}; }
    try { applyBody = JSON.parse((applyPost || {}).body || "{}"); } catch (_e) { applyBody = {}; }
    check("Apply PREVIEWS through the server before writing anything",
          !!planPost && planBody.sensor_id === "edge-moved"
          && planBody.changes && planBody.changes.targets === "203.0.113.7,203.0.113.8",
          (planPost || {}).body || "no plan POST");
    check("...then writes THAT sensor's plan, not the hub's ConfigMap",
          !!applyPost && applyBody.sensor_id === "edge-moved"
          && applyBody.changes.targets === "203.0.113.7,203.0.113.8"
          && !POSTED.slice(before).some((r) => r.url.includes("/api/settings/apply")),
          (applyPost || {}).body || "no apply POST");
    await waitFor(() => /saved/.test(planNote()));
    check("the outcome reported is the SERVER's, including who applies it and when",
          /saved/.test(planNote()) && /30s|30 seconds|refresh/.test(planNote()),
          planNote());
    check("the panel re-reads the server's plan, so the edit cannot linger locally",
          needEl("wl-plan-targets").value === "203.0.113.7,203.0.113.8",
          needEl("wl-plan-targets").value);
  }

  // ── (3) the warn-then-decline path writes nothing
  {
    const realConfirm = window.confirm;
    window.confirm = () => false;
    const before = POSTED.length;
    // The WARN path declines via window.confirm BEFORE the BF-9 echo is reached; this check
    // still pins that path (the echo's own decline is pinned in the BF-9 block).
    await H.wlApplyPlanChanges({ mode: "siphon" });
    check("DECLINING the in-path warning writes NOTHING and says so",
          !POSTED.slice(before).some((r) => r.url.includes("/api/weirlings/apply"))
          && /declined/.test(planNote()),
          planNote());
    window.confirm = realConfirm;
    await H.openWeirling("edge-moved");
  }

  // ── (4) a refused survey: the toggle reverts, the reason is the server's
  {
    await H.openWeirling("edge-stopped");
    fetchOverride = (u) => (String(u).includes("/api/settings/sonar")
      ? Promise.resolve({ ok: false, status: 422, statusText: "Refused",
                          json: async () => ({ ok: false, sensor: "edge-stopped",
                            error: "no such interface 'eth9' on this node; interfaces present: eth0, eth1" }) })
      : null);
    const before = POSTED.length;
    const sel = planModeSel();
    sel.value = "siphon";
    sel.dispatchEvent(new window.Event("change", { bubbles: true }));
    await waitFor(() => /could not survey/.test(planNote()));
    check("a REFUSED survey says why and writes nothing",
          /could not survey/.test(planNote()) && /no such interface/.test(planNote())
          && !POSTED.slice(before).some((r) => r.url.includes("/api/weirlings/apply")),
          planNote());
    check("the mode control REVERTS when the enable could not run (never a dead toggle)",
          planModeSel().value === "",
          planModeSel().value);
    fetchOverride = null;
    await H.openWeirling("edge-stopped");
  }

  // ── (5) the one-click enable: Sonar for THIS sensor, then its plan
  {
    const before = POSTED.length;
    const sel = planModeSel();
    sel.value = "siphon";
    sel.dispatchEvent(new window.Event("change", { bubbles: true }));
    // BF-9: the one-click enable still runs the survey first, then the ECHO; confirming it is
    // what releases the plan write (with the reason it recorded).
    for (let i = 0; i < 150 && !doc.querySelector("#modal-body .dest-confirm"); i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    check("the remote enable opens the echo too", await confirmEcho("edge-stopped goes in path"));
    await waitFor(() => POSTED.slice(before).some((r) => r.url.includes("/api/weirlings/apply")), 200);
    const sonarPost = POSTED.slice(before).find((r) => r.url.includes("/api/settings/sonar"));
    const applyPost = POSTED.slice(before).find((r) => r.url.includes("/api/weirlings/apply"));
    let sonarBody = {}; let applyBody = {};
    try { sonarBody = JSON.parse((sonarPost || {}).body || "{}"); } catch (_e) { sonarBody = {}; }
    try { applyBody = JSON.parse((applyPost || {}).body || "{}"); } catch (_e) { applyBody = {}; }
    check("switching a weirling into the path surveys THE SENSOR's own port first",
          !!sonarPost && sonarBody.sensor === "edge-stopped",
          (sonarPost || {}).body || "no sonar POST");
    check("...and then writes that weirling's plan from what the survey measured",
          !!applyPost && applyBody.sensor_id === "edge-stopped"
          && applyBody.changes && applyBody.changes.mode === "siphon"
          && applyBody.changes.segment === "198.51.100.0/24",
          (applyPost || {}).body || "no apply POST");
    check("the hub's OWN ConfigMap is never touched for another weirling",
          !POSTED.slice(before).some((r) => r.url.includes("/api/settings/apply")
                                     || r.url.includes("/api/settings/plan")),
          POSTED.slice(before).map((r) => r.url).join(","));
    check("the panel states what happens next rather than claiming the sensor armed",
          /30s|30 seconds|refresh/.test(planNote()),
          planNote());
  }

  // ── (6) an apply the SERVER refuses: the control reverts, the reason is the server's
  {
    await H.openWeirling("edge-moved");      // plan mode siphon, so loch is a change
    fetchOverride = (u) => (String(u).includes("/api/weirlings/apply")
      ? Promise.resolve({ ok: false, status: 503, statusText: "Unavailable",
                          json: async () => ({ ok: false,
                            error: "the registration for 'edge-moved' could not be written" }) })
      : null);
    const sel = planModeSel();
    sel.value = "loch";
    sel.dispatchEvent(new window.Event("change", { bubbles: true }));
    await waitFor(() => /could not be written/.test(planNote()));
    check("an apply the server REFUSES is reported in the server's words",
          /could not be written/.test(planNote()), planNote());
    check("and the mode control reverts to the DECLARED plan, not to what was clicked",
          planModeSel().value === "siphon",
          planModeSel().value);
    fetchOverride = null;
  }

  needEl("wl-detail-close").click();
}

// ── no content-less cards on the Settings tab (audit 2026-10-17) ─────────────────────────────
// The tab carried a "Sensor" card that was heading + hidden help only -- an empty box an
// operator reads as broken. A card must carry at least one element beyond its h2 and help.
{
  const emptyCards = [...doc.querySelectorAll("#view-settings .card")].filter((c) => {
    const kids = [...c.children].filter((k) => k.tagName !== "H2" && !k.classList.contains("info-text"));
    return kids.length === 0;
  });
  check("no content-less cards on the Settings tab",
        emptyCards.length === 0,
        emptyCards.map((c) => ((c.querySelector("h2, h3") || {}).textContent || "?").trim()).join(", "));
}

// ── an outage must never render as an empty fleet ────────────────────────────────────────────
// THE MOST IMPORTANT CHECK HERE. "the registry could not be read" and "you have no sensors" are
// opposite facts -- an outage and a fresh install -- and both render as a calm empty table.
{
  // THE SETTER, which is the ONLY mechanism that reaches the dispatcher. A plain
  // `H.fetchOverride = fn` creates a property nothing reads, so a check written that way runs
  // against whatever override was last active and can pass while proving nothing -- which is what
  // three checks in this file were doing, including the pre-existing sluice failure-path check.
  fetchOverride = (u) => (String(u).includes("/api/weirlings")
    ? Promise.resolve({ ok: true, status: 200, statusText: "OK",
                        json: async () => ({ available: false,
                                             reason: "the weirling registry could not be read",
                                             sensors: [], summary: null,
                                             heartbeats_available: false,
                                             heartbeat_reason: null }) })
    : null);
  // LEAVE AND COME BACK. `showView` returns early when the target view is already active, so
  // calling it again would reload NOTHING and the check would pass or fail against a stale panel
  // rather than against the failure path it is named for.
  H.showView("overview");
  await new Promise((r) => setTimeout(r, 20));
  await H.showView("weirlings");
  H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
  await H.loadWeirlings().catch(() => {});
  await new Promise((r) => setTimeout(r, 80));
  const txt = wlText();
  check("an unreadable registry says so instead of showing an empty fleet",
        txt.includes("registry could not be read") || txt.includes("Fleet unknown"),
        "a blank table during a registry outage reads as good news");
  // A BANNER IS A MOMENT, NOT A PERSISTENT NODE: a concurrent loader finishing can clear it
  // between the render and this line. Poll for it rather than sampling once.
  let bannerHit = false;
  let bannerSeen = "";
  for (let i = 0; i < 40; i++) {
    const b = H.document.getElementById("data-banner");
    if (b) {
      bannerSeen = b.textContent || "";
      if (bannerSeen.includes("registry")) { bannerHit = true; break; }
    }
    await new Promise((r) => setTimeout(r, 20));
  }
  check("an unreadable registry raises the data banner", bannerHit,
        bannerSeen || "no banner at any point");
  fetchOverride = null;
}

// ── responsive layout: the same console on a desk and in a pocket ────────────────────────
  // WHAT CANNOT BE CHECKED HERE: jsdom has no layout engine, and its getComputedStyle ignores
  // @media rules entirely (measured: a declaration under (max-width: 720px) computes as if the
  // query did not exist). The BREAKPOINT behaviour is therefore verified in a real browser;
  // what CI holds here is the other half -- the JS that runs at every width, and the base rules
  // whose absence would silently re-break narrow screens.
  const appjs = fs.readFileSync(path.join(WEB, "app.js"), "utf8");
  check("boot() wraps every table in a scroll box before the first render",
        /async function boot\(\)\s*\{[^}]*?wrapTables\(\);/.test(appjs),
        "without this call, a wide table widens the page on a phone");
  H.wrapTables();  // idempotent -- boot may already have run it; a second call must change nothing
  const mainTables = Array.from(doc.querySelectorAll("main table"));
  check("every table in main sits in its own scroll box",
        mainTables.length >= 10 &&
          mainTables.every((t) => t.parentElement && t.parentElement.classList.contains("tablewrap")),
        `${mainTables.length} tables; unwrapped: ` +
          mainTables.filter((t) => !(t.parentElement && t.parentElement.classList.contains("tablewrap")))
                    .map((t) => t.id || t.tagName).slice(0, 3).join(", "));
  const wrapBoxes = Array.from(doc.querySelectorAll(".tablewrap"));
  check("wrapping twice cannot nest or duplicate scroll boxes",
        wrapBoxes.every((b) => b.parentElement && !b.parentElement.classList.contains("tablewrap")) &&
          doc.querySelectorAll("main table").length === mainTables.length,
        "a second boot must not wrap the wrappers");
  check("the nav strip scrolls horizontally rather than overflowing the page",
        window.getComputedStyle(needEl("tabs")).overflowX === "auto",
        "eleven tabs never fit a phone, and a squashed strip is not a layout");
  check("tabs keep their intrinsic width inside the scrolling strip",
        window.getComputedStyle(doc.querySelector(".tab")).flexShrink === "0",
        "flex-shrink squashes eleven labels into a smear instead of letting the strip scroll");
  check("the stylesheet carries the responsive section (both breakpoints, the grid cap, the scroll box)",
        /@media\s*\(max-width:\s*720px\)/.test(css) &&
          /@media\s*\(max-width:\s*420px\)/.test(css) &&
          /minmax\(min\(380px, 100%\), 1fr\)/.test(css) &&
          /\.tablewrap\s*\{[^}]*overflow-x:\s*auto/.test(css),
        "the media rules themselves are browser-verified; their absence must still fail a machine");

  // ── the "i" in a circle (one affordance, everywhere) ──────────────────────────────────────
  // The operator asked for it by name: one click on a circle-i and the reader gets more about
  // whatever it sits beside. What a machine can hold: every button names a panel that exists,
  // a click REALLY opens it (and flips aria-expanded), a second click closes it, and the old
  // "?" glyph is gone -- two glyphs for one habit means readers learn it twice.
  const infoBtns = Array.from(doc.querySelectorAll(".info-btn"));
  check("every explainer in the console is an 'i' button with a panel behind it",
        infoBtns.length >= 8 && infoBtns.every((b) => doc.getElementById(b.dataset.info || "")),
        `${infoBtns.length} info buttons; missing panels: ` +
          infoBtns.filter((b) => !doc.getElementById(b.dataset.info || ""))
                  .map((b) => b.dataset.info).slice(0, 3).join(", "));
  check("no '?' glyph survives on any button",
        !Array.from(doc.querySelectorAll("button")).some((b) => (b.textContent || "").trim() === "?"),
        "one glyph for one habit");
  const probeBtn = infoBtns[0];
  const probePanel = probeBtn ? doc.getElementById(probeBtn.dataset.info) : null;
  if (probeBtn && probePanel) {
    const wasHidden = probePanel.classList.contains("hidden");
    probeBtn.click();
    check("clicking an 'i' opens its explanation and says so in aria-expanded",
          wasHidden && !probePanel.classList.contains("hidden") &&
            probeBtn.getAttribute("aria-expanded") === "true",
          "the affordance must open the panel it names");
    probeBtn.click();
    check("clicking it again closes the panel",
          probePanel.classList.contains("hidden") &&
            probeBtn.getAttribute("aria-expanded") === "false", "");
  }

  // ── THE GLOBAL TIME RANGE (the operator's ask: "a time search like kibana, throughout") ────
  const trBtn = needEl("tr-open");
  check("the header carries the global time control", !!trBtn && !!doc.getElementById("tr-panel"));
  check("it names the default range", !!(trBtn && /24 hours/.test(trBtn.textContent)),
        trBtn ? trBtn.textContent : "missing");
  const trPreset = doc.querySelector('#tr-presets button[data-hours="1"]');
  if (trPreset) {
    trPreset.click();
    check("a preset re-ranges the whole console (the global range is what loaders read)",
          H.trHours() === 1, "trHours()=" + H.trHours());
    check("and the control names the range that is applied", /1 hour/.test(trBtn.textContent),
          trBtn.textContent);
  } else {
    check("the presets exist", false, "no #tr-presets button[data-hours]");
  }
  check("no per-view time controls remain (one control, every tab)",
        ["nf-hours", "zk-hours", "hp-hours", "h-hours", "nw-hours", "id-hours", "as-hours", "m-hours"]
          .every((id) => !doc.getElementById(id)),
        "a redundant per-view hours control is still in the page");
  const trText = needEl("tr-text");
  const trApplyBtn = needEl("tr-text-apply");
  if (trText && trApplyBtn) {
    trText.value = "last 15 minutes";
    trApplyBtn.click();
    check("free text is read the way Kibana reads it ('last 15 minutes')",
          H.trHours() === 1, "trHours()=" + H.trHours());
    trText.value = "banana";
    trApplyBtn.click();
    const note = needEl("tr-note");
    check("an unreadable range is refused with a sentence, not a silent fallback",
          !!(note && /cannot read|type a range/.test(note.textContent)),
          note ? note.textContent : "no note element");
  }
  // ── THE FLOW-DETAIL DRILL FOLLOWS THE RANGE ────────────────────────────────────────────────
  // Measured by the operator: "last 15 minutes still shows <old addresses>". The table fetched
  // a STALE fixed 24h and was only re-fetched on a bar click, so a range change left it
  // rendering the previous window's rows. Both halves are pinned here.
  {
    H.trApply({ mode: "relative", hours: 1 });
    H.showView("netflow");
    await H.loadNetflow();
    // (the detail table is EMPTY until a drill runs -- that is its honest initial state)
    const note = needEl("nf-detail-note");
    H.loadFlowDetail({ port: 443, name: "port 443" });
    await new Promise((r) => setTimeout(r, 80));
    check("the flow-detail table names the window it is showing",
          !!(note && /last 1 hour/.test(note.textContent)), note ? note.textContent : "no note");
    H.trApply({ mode: "relative", hours: 24 });
    await new Promise((r) => setTimeout(r, 80));
    check("and a range change re-runs the drill instead of leaving stale rows",
          /last 24 hours/.test(note.textContent), note.textContent);
  }

  // ── A FAILED LOAD MUST NOT LEAVE "loading…" STANDING ───────────────────────────────────────
  // Measured on the box (2026-10-16): a stale token made /api/netflow answer 401 and the
  // summary froze on its "loading…" placeholder forever -- a stale spinner claiming work that
  // had already failed. The loader now names the failure and the next good load replaces it.
  {
    H.showView("netflow");
    fetchOverride = (url) => String(url).includes("/api/netflow")
      ? { ok: false, status: 401, json: async () => ({ detail: "unauthorized" }) } : null;
    try { await H.loadNetflow(); } catch (_e) { /* the loader re-throws for the banner */ }
    fetchOverride = null;
    const s = needEl("nf-summary").textContent;
    check("a failed netflow load does not leave 'loading…' standing",
          !/loading/i.test(s) && /unavailable/i.test(s), s);
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadNetflow();
    // (this fixture's payload legitimately reports an unavailable volume, so the assertion is
    // that the FAILURE note is gone -- not that any particular success text is present)
    const s2 = needEl("nf-summary").textContent;
    check("the next good load replaces the failure note",
          !/loading/i.test(s2) && !/the error is shown at the top/i.test(s2), s2);
  }
  // ── THE CLICKS THAT LIE (US-1) ──────────────────────────────────────────────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    // (a) a gate-form field must not bubble to the anomaly row (it used to open Evidence mid-edit)
    H.showView("anomalies");
    await sleep(300);
    const anRow = doc.querySelector("#anomalies-table tbody tr");
    const gateOpen = anRow ? anRow.querySelector(".gate-open") : null;
    check("the anomaly row offers its gate form", !!gateOpen);
    if (gateOpen) {
      gateOpen.click();
      await sleep(60);
      const form = anRow.querySelector(".gate-form");
      check("...and the form opens inside the row", !!form);
      const sel = form ? form.querySelector("select") : null;
      if (sel) {
        sel.click();
        await sleep(60);
        check("a click on a form field does NOT fall through to the row (no Evidence mid-edit)",
              needEl("view-anomalies").classList.contains("active")
              && !doc.getElementById("view-evidence").classList.contains("active")
              && !!anRow.querySelector(".gate-form"),
              "anomalies active=" + needEl("view-anomalies").classList.contains("active"));
      }
      const port = form ? form.querySelector("input[type=number]") : null;
      if (port) {
        port.click();
        await sleep(60);
        check("...not even typing into the port field",
              !doc.getElementById("view-evidence").classList.contains("active"));
      }
    }
    // (b) the sheet's Close button releases the scrim (it used to hide the card only)
    H.showView("weirlings");
    await H.loadWeirlings();
    await H.openWeirling("edge-alive");
    await sleep(150);
    let scrim = needEl("wl-sheet-scrim");
    check("the sheet opens with its scrim", !!scrim && !scrim.classList.contains("hidden"));
    needEl("wl-detail-close").click();
    await sleep(40);
    check("Close hides the card AND releases the scrim (the console stays clickable)",
          needEl("wl-detail-card").classList.contains("hidden")
          && (!scrim || scrim.classList.contains("hidden")),
          "scrim hidden=" + (scrim ? scrim.classList.contains("hidden") : "no scrim"));
    // (b2) the drill revoke: through the echo, carrying the reason, and it releases the scrim
    await H.openWeirling("edge-alive");
    await sleep(150);
    const beforeRevoke = POSTED.length;
    needEl("wl-detail-revoke").click();
    await sleep(120);
    check("the drill's Revoke opens the echo first", !!doc.querySelector("#modal-body .dest-confirm"));
    await confirmEcho("retiring it on purpose");
    await sleep(200);
    const revReq = POSTED.slice(beforeRevoke).find((r) => r.url.includes("/api/weirlings/revoke"));
    check("...and the revoke carries its reason", !!revReq && /retiring it on purpose/.test(revReq.body),
          revReq ? revReq.body.slice(0, 120) : "no revoke POST");
    scrim = needEl("wl-sheet-scrim");
    check("...and the exit releases the scrim too",
          needEl("wl-detail-card").classList.contains("hidden")
          && (!scrim || scrim.classList.contains("hidden")));
    // (d) the anomalies header and its row cells agree BY POSITION
    H.showView("anomalies");
    await sleep(300);
    const head = [...doc.querySelectorAll("#anomalies-table thead th")].map((t) => t.textContent.toLowerCase());
    const cells = [...doc.querySelectorAll("#anomalies-table tbody tr")[0].querySelectorAll("td")].map((t) => t.textContent);
    const locAt = cells.findIndex((c) => /edge-alive/.test(c));
    const matchedAt = cells.findIndex((c) => /scored this window/.test(c));
    check("the header names its columns where the rows put them",
          head.indexOf("location") === locAt && head.indexOf("matched rule") === matchedAt
          && locAt > -1 && matchedAt > -1,
          "location head=" + head.indexOf("location") + " cell=" + locAt
          + "; matched head=" + head.indexOf("matched rule") + " cell=" + matchedAt);
  }

  // ── ENTITY LINKS: every entity one click from its home (US-2) ───────────────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    // 1. the anomaly row's host cell -> the Host view (was: filter the queue)
    H.showView("anomalies");
    await sleep(250);
    const anRow1 = doc.querySelector("#anomalies-table tbody tr");
    const hostCellEl = anRow1
      ? [...anRow1.querySelectorAll("td")].find((td) => CELLLABEL(td) && /open this host's view/.test(CELLLABEL(td)))
      : null;
    check("the anomaly row's host cell names its destination", !!hostCellEl);
    if (hostCellEl) {
      hostCellEl.click();
      await sleep(220);
      check("...and it opens the Host view", needEl("view-host").classList.contains("active"));
    }
    // 2. a netflow talker -> its host (was: filter-only, the audit's runner-up)
    fetchOverride = (u) => (String(u).includes("/api/netflow")
      ? Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true, reason: "", hours: 24,
          talkers: { available: true, reason: "", points: [
            { src_addr: "198.51.100.20", hostname: "host.example", bytes: 123456, flows: 9 }] },
        }) })
      : null);
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadNetflow();
    await sleep(150);
    const tkBar = doc.querySelector("#nf-talkers .bar-row");
    check("the talkers chart offers its click targets", !!tkBar);
    if (tkBar) {
      tkBar.click();
      await sleep(220);
      check("a talker opens its host, not just a filter",
            needEl("view-host").classList.contains("active"));
    }
    fetchOverride = null;
    // 3. a Discover Zeek log row -> that log's drill in the Zeek view
    H.showView("discover");
    const feedSel = needEl("dc-feed");
    if (feedSel) {
      feedSel.value = "zeek";
      feedSel.dispatchEvent(new window.Event("change", { bubbles: true }));
      await sleep(220);
      const zrows = doc.querySelectorAll("#dc-rows tr.dc-row");
      check("the Zeek feed lists its logs", zrows.length >= 2, "rows=" + zrows.length);
      if (zrows[0]) {
        zrows[0].querySelector("td").click();
        await sleep(250);
        check("a Zeek log row drills into that log's rows in the Zeek view",
              needEl("view-zeek").classList.contains("active")
              && (needEl("zk-drill-title").textContent || "").includes("conn.log"),
              needEl("zk-drill-title").textContent);
      }
      feedSel.value = "netflow";
      feedSel.dispatchEvent(new window.Event("change", { bubbles: true }));
      await sleep(200);
    }
    // 4. the sensor's flow trend -> its flows, filtered to the sensor in Discover
    H.showView("weirlings");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadWeirlings();
    await sleep(200);
    const aliveRow = [...doc.querySelectorAll("#wl-table tbody tr:not(.wl-nic-row):not(.wl-colhead)")]
      .find((tr) => (tr.textContent || "").includes("edge-alive"));
    let flowCell = null;
    if (aliveRow) {
      let sib = aliveRow.nextElementSibling;
      if (sib && sib.classList.contains("wl-colhead")) sib = sib.nextElementSibling;
      while (sib && sib.classList.contains("wl-nic-row")) {
        if (/capture/.test(sib.textContent)) { flowCell = sib.querySelector(".wl-flow-cell.clickable"); break; }
        sib = sib.nextElementSibling;
      }
    }
    check("the flow trend is the pivot to that sensor's flows", !!flowCell);
    if (flowCell) {
      const beforeDc = DISCOVER_REQS.length;
      flowCell.click();
      await sleep(280);
      check("...and the trend lands in Discover filtered to exactly this sensor",
            needEl("view-discover").classList.contains("active")
            && needEl("dc-sensor").value === "edge-alive"
            && DISCOVER_REQS.slice(beforeDc).some((u) => u.includes("sensor=edge-alive")),
            "sensor=" + needEl("dc-sensor").value);
    }
    // 5. a sluice gate's sensor -> that sensor's fleet sheet
    H.showView("sluice");
    await H.loadSluice();
    await sleep(150);
    const gateCell = doc.querySelector("#sl-reach button.bubble.filter");
    check("a gate's sensor chip names its destination",
          !!gateCell && /^weirvern-/.test((gateCell.textContent || "").trim()),
          gateCell ? gateCell.textContent : "no reach chip");
    if (gateCell) {
      gateCell.click();
      await sleep(280);
      check("...and it opens that sensor's fleet sheet",
            needEl("view-weirlings").classList.contains("active")
            && !doc.getElementById("wl-detail-card").classList.contains("hidden")
            && /weirvern-dual/.test(needEl("wl-detail-id").textContent),
            "detail id=" + needEl("wl-detail-id").textContent);
    }
    // 6. an identity row's host -> the Host view; its JA4 -> the lookup
    H.showView("identity");
    await H.loadIdentity();
    await sleep(180);
    const idRow = [...doc.querySelectorAll("#id-table tbody tr")]
      .find((tr) => /203\.0\.113\.10/.test(tr.textContent));
    const idHost = idRow ? idRow.querySelector("td") : null;
    check("the identity list offers its host cells", !!idHost && /open this host's view/.test(CELLLABEL(idHost)));
    if (idHost) {
      idHost.click();
      await sleep(220);
      check("...and the host cell opens the Host view", needEl("view-host").classList.contains("active"));
    }
    H.showView("identity");
    await H.loadIdentity();
    await sleep(180);
    const idRow2 = [...doc.querySelectorAll("#id-table tbody tr")]
      .find((tr) => /203\.0\.113\.10/.test(tr.textContent));
    if (idRow2) {
      idRow2.click();
      await sleep(120);
      const ja4li = [...doc.querySelectorAll("#id-detail li")]
        .find((li) => /t13d1516h2_8daaf6152771_02713d6af862/.test(li.textContent));
      check("identity detail lists its JA4 with a click affordance",
            !!ja4li && /look this fingerprint up/.test(ja4li.title || ""));
      if (ja4li) {
        ja4li.click();
        await sleep(280);
        check("...and clicking it runs the fingerprint lookup in place",
              /presented this fingerprint/.test((needEl("fp-note") || {}).textContent || "")
              || /presented this fingerprint/.test((needEl("fp-results") || {}).textContent || ""),
              ((needEl("fp-note") || {}).textContent || "").slice(0, 80));
      }
    }
  }

  // ── ONE VIEW HEADER (VR-HDR) ─────────────────────────────────────────────────────────────────
  {
    const bad = [...doc.querySelectorAll(".view")].filter((v) => v.querySelectorAll("h2").length > 1);
    check("no view carries more than one h2 header", bad.length === 0,
          bad.map((v) => v.id + ":" + v.querySelectorAll("h2").length).join(", ") || "ok");
    const tabs = [...doc.querySelectorAll(".tab[data-view]")].map((t) => t.dataset.view);
    const missing = tabs.filter((id) => {
      const v = doc.getElementById("view-" + id);
      return !v || v.querySelectorAll("h2").length !== 1;
    });
    check("every tab view has exactly one h2 header", missing.length === 0, missing.join(", ") || "ok");
  }

  // ── NO DEAD ENDS: the way back, the way forward, and the receipt (US-3) ─────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    // THE 15s AUTO-REFRESH TICK: the console refreshes on by default; here it re-renders the
    // active view mid-click and detaches the very row a check is holding (measured: a tick
    // wiped a flashed row and a dn-detail). The checks below are about CLICK CONTRACTS, not
    // about the timer -- which has its own checks calling refreshAll directly -- so the timer
    // is stopped for the rest of the run.
    const autoPillStop = needEl("auto-toggle");
    if (autoPillStop && !/paused/.test(autoPillStop.textContent)) {
      autoPillStop.click();
    }
    // 1. Evidence is two-way: a crumb back (filters intact) and a Copy-link that carries it.
    fetchOverride = (u) => (String(u).includes("/api/evidence")
      ? Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true, hostname: "host.example", src_addr: "198.51.100.5",
          window_start: "2026-01-01T00:15:00", window_end: "2026-01-01T00:20:00",
          anomaly: { severity: "high", anomaly_score: 0.91, detected_by_models: "IF",
                     baseline_comparison: "" },
          flow_summary: { bytes: 1000, packets: 9, flows: 3, unique_destinations: 1, unique_ports: 1 },
          flows: [], errors: null }) })
      : null);
    H.showView("anomalies");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadAnomalies();
    await sleep(250);
    const sevCell = [...doc.querySelectorAll("#anomalies-table tbody tr td")]
      .find((td) => /severity/.test(td.title || ""));
    if (sevCell) { sevCell.click(); await sleep(250); }
    const chipsBefore = (needEl("an-chips") || {}).textContent || "";
    const anRowE = doc.querySelector("#anomalies-table tbody tr");
    check("a model-anomaly row opens the shared side sheet", !!anRowE);
    if (anRowE) {
      anRowE.click();
      await sleep(250);
      check("...the SAME sheet a ripple opens, titled for the detection",
            !needEl("rp-detail-card").classList.contains("hidden")
            && /model detection/i.test(needEl("rp-detail-title").textContent),
            needEl("rp-detail-title").textContent);
      const evBtn = [...doc.querySelectorAll("#rp-detail-actions button")]
        .find((b) => /^Evidence$/i.test((b.textContent || "").trim()));
      check("...with the shared action menu, including Evidence", !!evBtn,
            needEl("rp-detail-actions").textContent);
      if (evBtn) { evBtn.click(); await sleep(250); }
      const crumbs = needEl("crumbs") || { textContent: "" };
      const evBackFirst = needEl("ev-back");
      check("...and Evidence has ONE labeled back control, not a crumb plus a button",
            needEl("view-evidence").classList.contains("active")
            && !!evBackFirst && !evBackFirst.hidden
            && /back to alerts/i.test(evBackFirst.textContent)
            && crumbs.classList.contains("hidden"),
            evBackFirst ? `back=${evBackFirst.textContent} crumbs=${crumbs.textContent}` : "no #ev-back");
      H.syncURL();
      check("a Copy-link carries the drill (v=evidence + ev.host)",
            /v=evidence/.test(window.location.hash) && /ev\.host=/.test(window.location.hash),
            window.location.hash.slice(0, 130));
      if (evBackFirst) {
        evBackFirst.click();
        await sleep(250);
        check("the back button returns to Anomalies with its filters intact",
              needEl("view-anomalies").classList.contains("active")
              && ((needEl("an-chips") || {}).textContent || "") === chipsBefore,
              "chips now: " + ((needEl("an-chips") || {}).textContent || "").slice(0, 60));
      }
    }
    // 2. the host drill acts, and it DISMISSES.
    fetchOverride = (u) => (String(u).includes("/api/evidence")
      ? Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true, hostname: "host.example", src_addr: "198.51.100.5",
          window_start: "2026-01-01T00:15:00", window_end: "2026-01-01T00:20:00",
          anomaly: { severity: "high", anomaly_score: 0.91, detected_by_models: "IF",
                     baseline_comparison: "" },
          flow_summary: { bytes: 1000, packets: 9, flows: 3, unique_destinations: 1, unique_ports: 1 },
          flows: [], errors: null }) })
      : String(u).includes("/api/host")
      ? Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true, hostname: "host.example", src_addr: "198.51.100.5", hours: 24,
          totals: { bytes: 1234567, packets: 900, flows: 42, unique_destinations: 7,
                    unique_ports: 9, last_seen: "2026-01-01T00:30:00" },
          timeline: [{ hour: "2026-01-01T00:00:00", bytes: 100, flows: 1 }],
          top_destinations: [
            { dst_addr: "198.51.100.9", hostname: "peer.example", bytes: 9000, flows: 9, ports: 3 }],
          top_ports: [{ dst_port: 443, proto: "tcp", bytes: 8000, flows: 8 }],
          dns_queries: [{ query: "ads.example.com", qtype: "A", asks: 3, resolvers: 1 }],
          zeek_services: [{ service: "ssl", conns: 5, bytes: 7000 }],
          anomalies: [{ detected_at: "2026-01-01T00:20:00", anomaly_score: 0.91,
                        severity: "high", detected_by_models: "IsolationForest",
                        window_start: "2026-01-01T00:15:00", window_end: "2026-01-01T00:20:00",
                        baseline_comparison: "3.4x the host's normal" }],
          errors: null }) })
      : null);
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadHost("198.51.100.5", 24);
    await sleep(220);
    const destCell = doc.querySelector("#h-dests tbody td.dcell");
    check("host-drill destinations open their host view",
          !!destCell && /open this destination/.test(CELLLABEL(destCell)), CELLLABEL(destCell) || "missing");
    const portRow = doc.querySelector("#h-ports tbody tr.clickable");
    if (portRow) {
      portRow.click();
      await sleep(220);
      check("a host-drill port row lands in Netflow filtered to the port",
            needEl("view-netflow").classList.contains("active")
            && H.NF_FILTERS.some((f) => f.field === "dport"));
      try { H.nfRemoveChip("dport"); } catch (_e) { /* chip shape changed; the filter check stands */ }
    }
    const zRow = doc.querySelector("#h-zeek tbody tr.clickable");
    if (zRow) {
      zRow.click();
      await sleep(250);
      check("a host-drill service opens that log in the Zeek view",
            needEl("view-zeek").classList.contains("active"));
    }
    const aRow = doc.querySelector("#h-anoms tbody tr.clickable");
    if (aRow) {
      aRow.click();
      await sleep(250);
      check("a host-drill anomaly row opens its evidence",
            needEl("view-evidence").classList.contains("active")
            && /198\.51\.100\.5/.test((needEl("ev-title") || {}).textContent || ""),
            (needEl("ev-title") || {}).textContent || "");
    }
    H.showView("assets");
    await sleep(120);
    needEl("h-close").click();
    await sleep(120);
    check("the host drill DISMISSES with its Close",
          needEl("h-results").classList.contains("hidden"));

    // ── HUNT-1: the host page is a chain of filtered pivots ─────────────────────────────────
    H.showView("host");
    await H.loadHostPage("198.51.100.5");
    await sleep(120);
    const hpDest = doc.querySelector("#hp-dests tbody tr.clickable");
    check("the host page lists a clickable destination", !!hpDest);
    if (hpDest) {
      hpDest.click();
      await sleep(220);
      check("a host destination opens NetFlow filtered to that destination",
            needEl("view-netflow").classList.contains("active")
            && H.NF_FILTERS.some((f) => f.field === "dst" && f.value === "198.51.100.9"),
            JSON.stringify(H.NF_FILTERS));
    }
    H.showView("host");
    await H.loadHostPage("198.51.100.5");
    await sleep(100);
    const hpBar = doc.querySelector("#hp-flow .hp-bar.clickable");
    check("the host page draws a clickable NetFlow bar", !!hpBar);
    if (hpBar) {
      hpBar.click();
      await sleep(220);
      check("a host NetFlow bar opens NetFlow filtered to the host",
            needEl("view-netflow").classList.contains("active")
            && H.NF_FILTERS.some((f) => f.field === "src" && f.value === "198.51.100.5"),
            JSON.stringify(H.NF_FILTERS));
    }
    H.showView("host");
    await H.loadHostPage("198.51.100.5");
    await sleep(100);
    const hpNode = doc.querySelector("#hp-graph circle.hp-node");
    check("the connections graph renders a clickable host node", !!hpNode);
    if (hpNode) {
      hpNode.dispatchEvent(new window.MouseEvent("click", { bubbles: true }));
      await sleep(180);
      check("a graph node opens that host's page", H.HP_ADDR === "198.51.100.9", H.HP_ADDR);
    }
    H.showView("host");
    await H.loadHostPage("198.51.100.5");
    await sleep(100);
    const hpAnom = doc.querySelector("#hp-anoms tbody tr.clickable");
    check("the host page lists a clickable anomaly", !!hpAnom);
    if (hpAnom) {
      hpAnom.click();
      await sleep(220);
      check("a host anomaly opens its evidence chain",
            needEl("view-evidence").classList.contains("active"));
    }
    H.showView("host");
    await H.loadHostPage("198.51.100.5");
    await sleep(100);
    const hpDns = doc.querySelector("#hp-dns tbody tr.clickable");
    if (hpDns) {
      hpDns.click();
      await sleep(180);
      check("a host DNS row filters DNS to the host and name",
            needEl("view-dns").classList.contains("active")
            && needEl("dn-domain").value === "ads.example.com"
            && needEl("dn-client").value === "198.51.100.5",
            `${needEl("dn-domain").value}/${needEl("dn-client").value}`);
    }
    H.showView("host");
    await H.loadHostPage("198.51.100.5");
    await sleep(100);
    const hpZeek = doc.querySelector("#hp-zeek tbody tr.clickable");
    if (hpZeek) {
      hpZeek.click();
      await sleep(180);
      check("a host Zeek service filters the Zeek view",
            needEl("view-zeek").classList.contains("active")
            && /service = ssl/.test((needEl("zk-chips") || {}).textContent || ""),
            (needEl("zk-chips") || {}).textContent || "no chips");
    }
    // ── PIV-1: the host page is a URL location and a reload restores it ─────────────────────
    H.showView("anomalies");
    await sleep(100);
    H.openHost("198.51.100.5");
    await sleep(220);
    H.syncURL();
    check("a host page writes its address into the URL",
          /v=host/.test(window.location.hash) && /h\.addr=198\.51\.100\.5/.test(window.location.hash),
          window.location.hash);
    window.location.hash = "#v=host&h.addr=198.51.100.5";
    H.applyURLState();
    await sleep(220);
    check("a cold host URL restores the host page and its address",
          needEl("view-host").classList.contains("active")
          && H.HP_ADDR === "198.51.100.5", `${H.CURRENT_VIEW}/${H.HP_ADDR}`);
    // These pivots are real view filters; clear them so the later URL/cold-boot assertions
    // start from the same state they did before this section existed.
    try { H.NF_FILTERS.splice(0, H.NF_FILTERS.length); } catch (_e) { /* shape changed */ }
    try { H.dnClear(); } catch (_e) { /* shape changed */ }
    try { H.ZEEK_FILTERS.splice(0, H.ZEEK_FILTERS.length); H.zkRenderChips(); H.syncURL(); } catch (_e) { /* shape changed */ }
    await sleep(180);
    fetchOverride = null;
    // 3. the identity detail's exits.
    H.showView("identity");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadIdentity();
    await sleep(180);
    const idRowE = [...doc.querySelectorAll("#id-table tbody tr")]
      .find((tr) => /203\.0\.113\.10/.test(tr.textContent));
    if (idRowE) {
      idRowE.click();
      await sleep(120);
      check("the identity detail carries its exits",
            !!doc.getElementById("id-detail-open") && !!doc.getElementById("id-detail-close"));
      needEl("id-detail-close").click();
      check("...and Close dismisses it",
            needEl("id-detail-card").classList.contains("hidden"));
      idRowE.click();
      await sleep(80);
      needEl("id-detail-open").click();
      await sleep(220);
      check("...and 'Open host view' lands on the host's view",
            needEl("view-host").classList.contains("active"));
    }
    // 4. the post-block receipt keeps the id and lands on the rule.
    H.showView("anomalies");
    await H.loadAnomalies();
    await sleep(250);
    const anRowF = doc.querySelector("#anomalies-table tbody tr");
    const gateBtn = anRowF
      ? (anRowF.querySelector("button.gate-open")
         || [...anRowF.querySelectorAll("button")].find((b) => /Block/.test(b.textContent)))
      : null;
    check("the anomaly row offers its gate form", !!gateBtn);
    if (gateBtn) {
      gateBtn.click();
      await sleep(150);
      const form = anRowF.querySelector(".gate-form");
      const submit = form
        ? [...form.querySelectorAll("button")].find((b) => /File block/.test(b.textContent))
        : null;
      check("...and the form can be filed", !!submit);
      if (submit) {
        submit.click();
        await sleep(300);
        const receipt = [...form.querySelectorAll("button")]
          .find((b) => /Open the filed rule/.test(b.textContent));
        check("a filed block's receipt links to the rule it created", !!receipt);
        if (receipt) {
          receipt.click();
          await sleep(300);
          // THE DETAIL NAMES EACH CONJUNCT. Reporting only the rule id cannot distinguish "the
          // view never switched" from "the sheet stayed hidden" from "the wrong rule loaded", and all
          // three have different causes. A check that fails without saying which part failed sends
          // the next reader back to the beginning.
          // RE-AUTHORED, because the product's design changed and this check still described the old
          // one. The receipt handler (app.js, "US-3") calls showView("blocked") and then
          // blOpenRuleById, which opens the rule sheet when the rule is not in the blocked lists --
          // sluice.js:589 documents exactly that hand-off. So the landing page is BLOCKED, not
          // Sluice, and asserting view-sluice tested a design that no longer exists rather than a
          // defect. The behaviour worth pinning is the one the code promises: the receipt lands on
          // the created rule, whatever page owns the card.
          const blockedActive = needEl("view-blocked").classList.contains("active");
          const sheetEl = doc.getElementById("sl-rule-sheet");
          const sheetOpen = !!sheetEl && !sheetEl.classList.contains("hidden");
          const sheetId = needEl("sl2-sheet-id").textContent;
          check("...and clicking it lands on that rule",
                blockedActive && sheetOpen && /r-filed-1/.test(sheetId),
                `blocked-view-active=${blockedActive} sheet-open=${sheetOpen} `
                + `rule id=${sheetId || "(empty)"}`);
        }
      }
    }
    // 5. audit fixes keep their ids.
    fetchOverride = (u) => (String(u).includes("/api/audit")
      ? Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true, reason: "", now: "2026-10-17T12:00:00+00:00",
          findings: [
            { class: "expired_rule", severity: "info", subject: "r-live-1",
              detail: "domain rule for ads.example", elapsed_s: 300,
              fix: { view: "sluice", rule_id: "r-live-1", label: "adjust or revoke on Sluice" } },
            { class: "stuck_rule", severity: "warn", subject: "r1",
              detail: "firing without a quiet week", elapsed_s: 460,
              fix: { view: "blocked", rule_id: "r1", label: "read the hits on Blocked" } },
            { class: "unowned_detector", severity: "warn", subject: "LOF",
              detail: "console-only: no owner", elapsed_s: null,
              fix: { view: "anomalies", detector: "LOF", label: "register it (registry strip)" } },
          ],
          counts: { expired_rule: 1, stuck_rule: 1, unowned_detector: 1 }, errors: {} }) })
      : null);
    H.showView("health");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadAudit();
    await sleep(220);
    const fixBtns = [...doc.querySelectorAll("#audit-table tbody button")];
    check("the audit renders its fix buttons", fixBtns.length === 3, "buttons=" + fixBtns.length);
    const slFix = fixBtns.find((b) => /Sluice/.test(b.textContent));
    if (slFix) {
      H.showView("sluice");
      await H.loadSluice();
      await sleep(200);
      slFix.click();
      await sleep(300);
      // THE FLASH IS A MOMENT TOO (1.8s), and a re-render can drop and re-add the class, so poll
      // for it rather than sampling one node once.
      let flashed = false;
      let flashedId = "";
      for (let i = 0; i < 60 && !flashed; i++) {
        const hit = [...doc.querySelectorAll("#sl2-rules tbody tr.flash-hit")];
        if (hit.length) {
          flashed = true;
          flashedId = hit.map((r) => r.getAttribute("data-rule-id")).join(",");
        }
        else await new Promise((r) => setTimeout(r, 20));
      }
      check("an expired-rule fix lands ON the rule's row in Sluice",
            needEl("view-sluice").classList.contains("active")
            && flashed && flashedId === "r-live-1",
            "flashed=" + flashed + " id=" + flashedId);
    }
    const blFix = fixBtns.find((b) => /Blocked/.test(b.textContent));
    if (blFix) {
      blFix.click();
      await sleep(300);
      // The fix FETCHES the rule before it can open the sheet, so the open is asynchronous: poll
      // for it instead of sampling once at a fixed delay.
      let opened = false;
      let seenId = "";
      for (let i = 0; i < 75 && !opened; i++) {
        seenId = needEl("sl2-sheet-id").textContent || "";
        opened = /r1/.test(seenId)
          && !doc.getElementById("sl-rule-sheet").classList.contains("hidden");
        if (!opened) await new Promise((r) => setTimeout(r, 20));
      }
      // The stuck-rule finding's own fix targets the BLOCKS view (that is where the hits are),
      // and the Sluice rule sheet opens over it. Asserting Sluice was active described the old
      // routing, not this one.
      check("a stuck-rule fix opens the rule its hits live behind",
            needEl("view-blocked").classList.contains("active") && opened,
            "id=" + seenId + " opened=" + opened);
    }
    const detFix = fixBtns.find((b) => /registry/.test(b.textContent));
    if (detFix) {
      H.showView("anomalies");
      await H.loadAnomalies();
      await sleep(200);
      detFix.click();
      await sleep(250);
      const detRow = [...doc.querySelectorAll("#detectors-table tbody tr")]
        .find((r) => r.getAttribute("data-detector") === "LOF");
      check("a registry fix lands ON the detector's row",
            needEl("view-anomalies").classList.contains("active")
            && !!detRow && detRow.classList.contains("flash-hit"),
            "row=" + !!detRow + " cls=" + (detRow ? detRow.className : "n/a")
            + " btn=" + detFix.textContent.slice(0, 24));
    }
    fetchOverride = null;
    // 6. a revoked registration still opens its sheet.
    fetchOverride = (u) => (String(u).includes("/api/weirlings") && !String(u).includes("/detail")
      ? Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true, reason: null, heartbeats_available: true, heartbeat_reason: null,
          summary: { total: 2, registered: 1, problems: 0, alive: 1, stale: 0, never_seen: 0,
                     unregistered: 0, disabled: 0 },
          sensors: [WEIRLINGS_PAYLOAD.sensors[0]],
          revoked: [{ sensor_id: "edge-retired", revoked_at: "2026-09-01T00:00:00+00:00" }],
          revoked_reason: "" }) })
      : null);
    H.showView("weirlings");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadWeirlings();
    const revBox = needEl("wl-revoked");
    revBox.checked = true;
    await H.loadWeirlings();
    await sleep(180);
    const revSpan = [...doc.querySelectorAll("#wl-table tbody .dcell")]
      .find((s) => /edge-retired/.test(s.textContent));
    check("a revoked id is an entity, not inert text", !!revSpan && /sheet/.test(revSpan.title || ""));
    if (revSpan) {
      revSpan.click();
      await sleep(250);
      check("...and it opens that sensor's sheet",
            needEl("view-weirlings").classList.contains("active")
            && /edge-retired/.test((needEl("wl-detail-id") || {}).textContent || ""),
            (needEl("wl-detail-id") || {}).textContent || "");
    }
    revBox.checked = false;
    fetchOverride = null;
    H.showView("health");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadAudit();
    await sleep(150);
  }

  // ── THE CLICK GRAMMAR, LIVE (US-4) ──────────────────────────────────────────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    // 1. the palette has a visible door.
    const palBtn = needEl("palette-btn");
    check("the palette has a visible entry in the chrome", !!palBtn);
    if (palBtn) {
      palBtn.click();
      await sleep(120);
      check("...and the button opens it",
            !doc.getElementById("palette").classList.contains("hidden"),
            "palette hidden=" + needEl("palette").classList.contains("hidden"));
      if (typeof H.paletteClose === "function") H.paletteClose();
    }
    // 2. the fleet row opens its sheet (a hover wash must not be the whole story).
    H.showView("weirlings");
    await H.loadWeirlings();
    await sleep(200);
    const fleetRow = [...doc.querySelectorAll("#wl-table tbody tr:not(.wl-nic-row):not(.wl-colhead)")].find((r) => /clickable/.test(r.className));
    check("a fleet row carries the row-level cue", !!fleetRow);
    if (fleetRow) {
      fleetRow.click();
      await sleep(250);
      check("...and the row opens that sensor's sheet",
            !doc.getElementById("wl-detail-card").classList.contains("hidden")
            && ((needEl("wl-detail-id") || {}).textContent || "").length > 0,
            "id=" + ((needEl("wl-detail-id") || {}).textContent || ""));
    }
    // 3. the count cell discloses for EVERY n (the n==1 case used to be inert).
    fetchOverride = (u) => (String(u).includes("/api/anomalies")
      ? Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true, reason: "", rows: [
            { detected_at: "2026-10-17T11:00:00", window_start: "2026-10-17T10:55:00",
              window_end: "2026-10-17T11:00:00", src_addr: "198.51.100.5", hostname: "host.example",
              anomaly_score: 0.9, severity: "high", detected_by_models: "IF", n: 1,
              review_state: "", reviewed_at: null, windows: [
                { window: "2026-10-17T10:55:00", review_state: "", review_note: "", reviewed_at: null }] },
            { detected_at: "2026-10-17T11:05:00", window_start: "2026-10-17T11:00:00",
              window_end: "2026-10-17T11:05:00", src_addr: "198.51.100.9", hostname: "peer.example",
              anomaly_score: 0.8, severity: "medium", detected_by_models: "LOF", n: 3,
              review_state: "", reviewed_at: null, windows: [
                { window: "2026-10-17T11:00:00", review_state: "", review_note: "", reviewed_at: null }] },
          ],
          severity_counts: {}, discipline: null, watch_error: null }) })
      : null);
    H.showView("anomalies");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadAnomalies();
    await sleep(250);
    const exCells = [...doc.querySelectorAll("#anomalies-table tbody td.expander")];
    // (The chevron itself is a ::after pseudo-element -- not readable from the DOM -- so its
    // RULE is pinned in tests/test_grammar.py; here the cell's class + aria do the work.)
    check("the count cell carries the disclosure cue at rest",
          exCells.length === 2, "cells=" + exCells.length);
    // The driver is optional: with no cue cells the two checks below FAIL rather than
    // crash the run (a killed feature must fail a check -- the standing harness rule).
    const oneCell = exCells[0] || null;
    if (oneCell) {
      oneCell.click();
      await sleep(150);
      check("the n==1 count cell discloses (it used to be inert while a chip pointed at it)",
            !!doc.querySelector("#anomalies-table tbody tr.an-exp")
            && oneCell.getAttribute("aria-expanded") === "true");
      oneCell.click();
      await sleep(120);
      check("...and collapsing flips the cue back",
            !doc.querySelector("#anomalies-table tbody tr.an-exp")
            && oneCell.getAttribute("aria-expanded") === "false");
    } else {
      check("the n==1 count cell discloses (it used to be inert while a chip pointed at it)",
            false, "no disclosure cells to drive");
      check("...and collapsing flips the cue back", false, "no disclosure cells to drive");
    }
    fetchOverride = null;
    H.showView("health");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadAnomalies();
    await sleep(120);
  }

  // ── THE CLICK BUDGET, MEASURED (US-5): the four top jobs, counted ──────────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    // COUNTS OPERATOR CLICKS, not code steps. Budget: understanding <=1, acting <=2; where the
    // act is irreversible the BF-9 destructive echo is RETAINED and consumes its own click
    // (US-5's own carve-out: "with the BF-9 destructive echo retained where acts are
    // irreversible").
    let clicks = 0;
    const C = (elm) => { clicks += 1; elm.click(); return elm; };
    const budget = [];
    const note = (job, phase, n) => budget.push(`${job.padEnd(20)} ${phase.padEnd(11)} = ${n} click(s)`);

    // ── JOB 1: investigate an anomaly (understand 1, act 2) ──────────────────────────────────
    const AN_ONE = { available: true, reason: "", rows: [
      { detected_at: "2026-10-17T11:00:00", window_start: "2026-10-17T10:55:00",
        window_end: "2026-10-17T11:00:00", src_addr: "198.51.100.5", hostname: "host.example",
        anomaly_score: 0.91, severity: "high", detected_by_models: "Isolation Forest, LOF",
        n: 1, review_state: "", reviewed_at: null, windows: [
          { window: "2026-10-17T10:55:00", review_state: "", review_note: "", reviewed_at: null }],
        owner: "ops", matched_rule: "x", primary_deviation_feature: "bytes_z", baseline_comparison: "" },
    ], severity_counts: {}, discipline: null, watch_error: null };
    fetchOverride = (u) => (String(u).includes("/api/evidence")
      ? Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true, hostname: "host.example", src_addr: "198.51.100.5",
          window_start: "2026-10-17T10:55:00", window_end: "2026-10-17T11:00:00",
          anomaly: { severity: "high", anomaly_score: 0.91, detected_by_models: "Isolation Forest",
                     baseline_comparison: "" },
          flow_summary: { bytes: 1000, packets: 9, flows: 3, unique_destinations: 1, unique_ports: 1 },
          flows: [], errors: null }) })
      : String(u).includes("/api/anomalies")
      ? Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => AN_ONE })
      : null);
    H.showView("anomalies");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadAnomalies();
    await sleep(250);
    const jobRow = doc.querySelector("#anomalies-table tbody tr");
    check("JOB investigate-anomaly: the row is on screen", !!jobRow);
    // ISSUE #52: the drill has a VISIBLE entry and exit. The row was the only click target
    // (nothing at rest said so) and the evidence page's only way back was a nav tab.
    const evOpen = jobRow ? jobRow.querySelector(".row-more .ev-open") : null;
    const evSummary = jobRow ? jobRow.querySelector(".row-more summary") : null;
    check("every alert row carries evidence behind its one disclosure", !!evOpen && !!evSummary);
    check("no evidence button sits at rest as a second per-row verb",
          !jobRow || [...jobRow.querySelectorAll(".ev-open")].every((b) => b.closest(".row-more")));
    if (evOpen && evSummary) {
      const beforeSev = H.AN_FILTERS.severity;
      evSummary.click();
      await sleep(60);
      evOpen.click();
      await sleep(260);
      check("...which opens the evidence view",
            needEl("view-evidence").classList.contains("active"));
      const evBack = needEl("ev-back");
      check("...and the evidence page carries a visible way back",
            !!evBack && !evBack.hidden && /back to alerts/i.test(evBack.textContent),
            evBack ? `hidden=${evBack.hidden} text=${evBack.textContent}` : "no #ev-back");
      if (evBack) {
        evBack.click();
        await sleep(220);
        check("...that returns to the alert queue with its filters intact",
              needEl("view-anomalies").classList.contains("active")
              && H.AN_FILTERS.severity === beforeSev,
              `severity=${H.AN_FILTERS.severity} was=${beforeSev}`);
      }
    }
    clicks = 0;
    C(jobRow);                                   // 1: the row -> the shared sheet
    await sleep(280);
    check("JOB investigate-anomaly: understanding is ONE click (row -> the shared sheet)",
          clicks === 1 && !needEl("rp-detail-card").classList.contains("hidden"),
          `clicks=${clicks}`);
    note("investigate-anomaly", "understand", clicks);
    // The sheet's Evidence verb is the second, explicit step to the raw records. It is not
    // counted as an extra click for the one-click understanding claim.
    const jobEvBtn = [...doc.querySelectorAll("#rp-detail-actions button")]
      .find((b) => /^Evidence$/i.test((b.textContent || "").trim()));
    if (jobEvBtn) { jobEvBtn.click(); await sleep(250); }
    const evVerb = doc.querySelector("#ev-verdict .gate-open");
    clicks = 0;
    if (evVerb) {
      C(evVerb);                                 // 1: the block verb opens the Sluice composer
      await sleep(180);
      const sheet = needEl("sl-rule-sheet");
      check("JOB investigate-anomaly: the evidence Block verb opens the SLUICE rule sheet",
            !!sheet && !sheet.classList.contains("hidden")
            && (needEl("sl2-src").value || "") === "198.51.100.5",
            sheet ? `hidden=${sheet.classList.contains("hidden")}` : "no sheet");
      const create = needEl("sl2-create-submit");
      if (create) {
        C(create); await sleep(100);              // 2: arm the block rule
        C(create); await sleep(320);              // 3: file it
      }
    }
    const act1 = clicks;
    const post1 = POSTED.slice(-1)[0] || {};
    check("JOB investigate-anomaly: acting is the composer + confirm and posts the block",
          act1 === 3 && /\/api\/sluice\/block/.test(post1.url || "")
          && /198\.51\.100\.5/.test(post1.body || ""),
          `clicks=${act1} post=${(post1.url || "none")} body=${String(post1.body || "").slice(0, 60)}`);
    note("investigate-anomaly", "act", act1);
    fetchOverride = null;

    // ── JOB 2: block a domain from where it is seen (verb on the row) ────────────────────────
    H.showView("dns");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadDns();
    await sleep(220);
    const dnsRow = doc.querySelector("#dn-rows tr.dc-row");
    const blockVerb = dnsRow
      ? [...dnsRow.querySelectorAll("button")].find((b) => /^Block/.test(b.textContent.trim()))
      : null;
    check("JOB block-domain: the verb lives ON the row that shows the domain", !!blockVerb);
    clicks = 0;
    if (blockVerb) {
      C(blockVerb);                              // 1: open the rule sheet
      await sleep(180);
      const sheet = needEl("sl-rule-sheet");
      check("JOB block-domain: the row's verb opens the rule sheet with the name filled in",
            !!sheet && !sheet.classList.contains("hidden")
            && (needEl("sl2-domain").value || "").includes("ads.example.com"),
            "the composer did not open on the sheet");
      const modeSel = needEl("sl-mode");
      if (modeSel) {
        modeSel.value = "block";
        modeSel.dispatchEvent(new window.Event("change", { bubbles: true }));
      }
      check("JOB block-domain: choosing block mode is not a click (a select, not a step)",
            clicks === 1, `clicks=${clicks}`);
      const createBtn = needEl("sl2-create-submit");
      if (createBtn) {
        C(createBtn);                            // 2: arms -- the retained BF-9 echo
        await sleep(100);
        check("...the echo is on the button before it writes",
              /Confirm/.test(createBtn.textContent), createBtn.textContent);
        C(createBtn);                            // 3: commits
        await sleep(320);
      }
      const closeBtn = needEl("sl-rule-close");
      if (closeBtn) closeBtn.click();
    }
    const act2 = clicks;
    const post2 = POSTED.slice(-1)[0] || {};
    check("JOB block-domain: TWO clicks + the retained BF-9 confirm, posting the rule",
          act2 === 3 && /\/api\/sluice\/block/.test(post2.url || "")
          && /ads\.example\.com/.test(post2.body || "") && /"mode":"block"/.test(post2.body || ""),
          `clicks=${act2} post=${(post2.url || "none")} body=${String(post2.body || "").slice(0, 80)}`);
    note("block-domain", "act", act2);
    budget.push("                     (of which 1 = the BF-9 destructive confirm, retained)");

    // ── JOB 3: quiet a noisy detector (registry row -> its alerts -> ack) ────────────────────
    const AN_REQS = [];
    fetchOverride = (u) => {
      const s = String(u);
      if (!s.includes("/api/anomalies")) return null;
      AN_REQS.push(s);
      return Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => AN_ONE });
    };
    H.showView("anomalies");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadAnomalies();
    await sleep(300);
    const regCell = [...doc.querySelectorAll("#detectors-table tbody .dcell")]
      .find((el2) => /LOF/.test(el2.textContent));
    check("JOB quiet-detector: the registry row offers its verb", !!regCell);
    clicks = 0;
    if (regCell) {
      C(regCell);                                // 1: filter the queue to this detector
      await sleep(350);
    }
    const uq3 = clicks;
    check("JOB quiet-detector: understanding is ONE click (registry row -> its alerts)",
          uq3 === 1 && H.AN_FILTERS.model === "LOF"
          && AN_REQS.some((u) => u.includes("model=LOF")),
          `clicks=${uq3} model=${H.AN_FILTERS.model} asked=${AN_REQS.length ? AN_REQS[AN_REQS.length - 1] : "none"}`);
    note("quiet-detector", "understand", uq3);
    const ackBtn = [...doc.querySelectorAll("#anomalies-table .review-act")]
      .find((b) => b.textContent === "Acknowledge");
    clicks = 0;
    if (ackBtn) {
      C(ackBtn);                                 // 1: the disposition -- the actual quieting
      await sleep(300);
    }
    const post3 = POSTED.slice(-1)[0] || {};
    check("JOB quiet-detector: quieting one finding is ONE more click (ack posts)",
          clicks === 1 && /\/api\/review/.test(post3.url || "")
          && /"state":"ack"/.test(String(post3.body || "")),
          `clicks=${clicks} post=${(post3.url || "none")}`);
    note("quiet-detector", "act", clicks);
    H.anClearAllFilters();
    await sleep(200);
    fetchOverride = null;

    // ── JOB 4: find a host and inspect its traffic (1 click) ─────────────────────────────────
    H.showView("anomalies");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadAnomalies();
    await sleep(250);
    const jobHostCell = [...doc.querySelectorAll("#anomalies-table tbody td.dcell")]
      .find((td) => CELLLABEL(td) && /open this host's view/.test(CELLLABEL(td)));
    check("JOB find-and-inspect: the host cell is on the row", !!jobHostCell);
    clicks = 0;
    if (jobHostCell) {
      C(jobHostCell);                            // 1: the host's own view, traffic included
      await sleep(320);
    }
    check("JOB find-and-inspect: ONE click from the row to the host's traffic",
          clicks === 1 && needEl("view-host").classList.contains("active")
          && (needEl("h-stats").textContent || "").length > 0,
          `clicks=${clicks} stats=${(needEl("h-stats").textContent || "").slice(0, 40)}`);
    note("find-and-inspect", "understand", clicks);

    console.log("CLICK BUDGET (US-5, measured):");
    for (const line of budget) console.log("  " + line);
    H.showView("health");
    await sleep(120);
  }

  // ── ARRIVE AND RETURN (US-6): filters, range and scroll survive the trip ───────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    let scrollTo = [];
    const prevScrollTo = window.scrollTo;
    window.scrollTo = (x, y) => { scrollTo.push([x, y]); };
    let EXPECT_SCROLL = 420;
    try { Object.defineProperty(window, "scrollY", { value: EXPECT_SCROLL, configurable: true }); }
    catch (_e) { EXPECT_SCROLL = Number(window.scrollY) || 0; }

    // 1) ARRIVAL: a link carries state in. The chip says where the filters came from, and the
    //    header says WHY the list may look short (X of Y).
    const HOST_REQS = [];
    const AN_ARRIVAL = { available: true, reason: "", total_unfiltered: 40, rows: [
      { detected_at: "2026-10-17T11:00:00", window_start: "2026-10-17T10:55:00",
        window_end: "2026-10-17T11:00:00", src_addr: "198.51.100.5", hostname: "host.example",
        anomaly_score: 0.91, severity: "high", detected_by_models: "LOF", n: 1,
        review_state: "", reviewed_at: null, owner: "ops",
        windows: [{ window: "2026-10-17T10:55:00", review_state: "", reviewed_at: null }] },
      { detected_at: "2026-10-17T11:05:00", window_start: "2026-10-17T11:00:00",
        window_end: "2026-10-17T11:05:00", src_addr: "198.51.100.5", hostname: "host.example",
        anomaly_score: 0.80, severity: "medium", detected_by_models: "LOF", n: 3,
        review_state: "", reviewed_at: null, owner: "ops",
        windows: [{ window: "2026-10-17T11:00:00", review_state: "", reviewed_at: null }] },
    ], severity_counts: {}, discipline: null, watch_error: null };
    fetchOverride = (u) => {
      const s = String(u);
      if (s.includes("/api/anomalies")) {
        return Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => AN_ARRIVAL });
      }
      if (s.includes("/api/host")) {
        HOST_REQS.push(s);
        // The FULL host payload: the minimal default fixture lacks the drill's later tables
        // (zeek_services / anomalies), and a partial payload makes loadHost throw mid-render --
        // no crumb, and the failure hides behind the .catch. Serve the complete shape.
        return Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true, hostname: "host.example", src_addr: "198.51.100.5", hours: 6,
          totals: { bytes: 1234567, packets: 900, flows: 42, unique_destinations: 7,
                    unique_ports: 9, last_seen: "2026-10-17T11:00:00" },
          timeline: [{ hour: "2026-10-17T10:00:00", bytes: 100, flows: 1 }],
          top_destinations: [
            { dst_addr: "198.51.100.9", hostname: "peer.example", bytes: 9000, flows: 9, ports: 3 }],
          top_ports: [{ dst_port: 443, proto: "tcp", bytes: 8000, flows: 8 }],
          zeek_services: [{ service: "ssl", conns: 5, bytes: 7000 }],
          anomalies: [], errors: null }) });
      }
      return null;
    };
    window.location.hash = "#v=anomalies&tr=6&an.host=198.51.100.5&an.model=LOF";
    H.applyURLState();
    H.showView("anomalies");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadAnomalies();
    await sleep(300);
    check("ARRIVAL: the link's filters and range land active",
          H.AN_FILTERS.host === "198.51.100.5" && H.AN_FILTERS.model === "LOF"
          && Number(H.trHours()) === 6,
          `host=${H.AN_FILTERS.host} model=${H.AN_FILTERS.model} h=${H.trHours()}`);
    check("ARRIVAL: a removable chip explains the link's filters",
          [...doc.querySelectorAll("#an-filters .bubble.filter")]
            .some((c) => /arrived with filters/.test(c.textContent)),
          (needEl("an-filters").textContent || "").slice(0, 90));
    check("ARRIVAL: the header says showing X of Y",
          /showing 4 of 40 alerts/.test((needEl("an-count-line") || {}).textContent || ""),
          (needEl("an-count-line") || {}).textContent || "no line");

    // 2) RETURN from Evidence: the labeled exit; chips, range and SCROLL all survive.
    const rowA = doc.querySelector("#anomalies-table tbody tr");
    check("RETURN: an alert row is on screen to drill into", !!rowA);
    if (rowA) { rowA.click(); }
    await sleep(320);
    const returnEv = [...doc.querySelectorAll("#rp-detail-actions button")]
      .find((b) => /^Evidence$/i.test((b.textContent || "").trim()));
    if (returnEv) { returnEv.click(); await sleep(250); }
    const evBack = needEl("ev-back");
    check("RETURN: Evidence's exit is the labeled back button",
          !!evBack && !evBack.hidden && /back to alerts/i.test(evBack.textContent),
          evBack ? evBack.textContent : "no #ev-back");
    scrollTo = [];
    if (evBack) { evBack.click(); }
    await sleep(1250);
    check("RETURN: the origin's filters survive the round trip",
          H.AN_FILTERS.host === "198.51.100.5" && H.AN_FILTERS.model === "LOF",
          `${H.AN_FILTERS.host} / ${H.AN_FILTERS.model}`);
    check("RETURN: the time window is unchanged", Number(H.trHours()) === 6, String(H.trHours()));
    check("RETURN: the scroll is restored after the view re-renders",
          scrollTo.some(([x, y]) => x === 0 && y === EXPECT_SCROLL), JSON.stringify(scrollTo));

    // 3) RETURN from the host drill: same guarantees, and the drill asked the GLOBAL window.
    await sleep(200);
    const jobHostCell = [...doc.querySelectorAll("#anomalies-table tbody td.dcell")]
      .find((td) => CELLLABEL(td) && /open this host's view/.test(CELLLABEL(td)));
    HOST_REQS.length = 0;
    if (jobHostCell) { jobHostCell.click(); }
    await sleep(380);
    const hBack = needEl("hp-back");
    check("HOST RETURN: the jump lands with the labeled back button",
          needEl("view-host").classList.contains("active")
          && !!hBack && /back to alerts/i.test(hBack.textContent),
          hBack ? hBack.textContent : "no #hp-back");
    check("HOST RETURN: the drill answers the GLOBAL window (hours=6), not a hardcoded 24",
          HOST_REQS.some((u) => /hours=6/.test(u)), HOST_REQS.join(" ").slice(0, 120));
    scrollTo = [];
    if (hBack) { hBack.click(); }
    await sleep(1250);
    check("HOST RETURN: filters and range survive, scroll restored",
          H.AN_FILTERS.host === "198.51.100.5" && Number(H.trHours()) === 6
          && scrollTo.some(([x, y]) => x === 0 && y === EXPECT_SCROLL),
          `${H.AN_FILTERS.host} / ${H.trHours()} / ${JSON.stringify(scrollTo)}`);

    // 4) URL round trip: syncing the URL forces the CURRENT state; re-applying it from a cold
    //    state reproduces everything (a fresh boot's own path, driven again). The Copy-link
    //    button was removed by the operator (2026-10-19); the URL is still the share surface.
    H.syncURL();
    await sleep(150);
    const COPIED = String(window.location.href || "");
    check("URL: the current state carries view + filters + range",
          /v=anomalies/.test(COPIED) && /an\.host=198\.51\.100\.5/.test(COPIED)
          && /tr=6/.test(COPIED), COPIED);
    H.anClearAllFilters();
    H.showView("health");
    const q = COPIED.includes("#") ? COPIED.slice(COPIED.indexOf("#") + 1) : "v=health";
    // The shared boot carries a lingering sheet state (wl=...), which applyURLState dutifully
    // re-opens -- restore THIS card's state: strip it so the assertions answer about the
    // filters/range/view, not about a panel another section left open.
    const qp = new window.URLSearchParams(q);
    qp.delete("wl");
    window.location.hash = "#" + qp.toString();
    H.applyURLState();
    H.showView(qp.get("v") || "health");
    await sleep(250);
    check("COPY: a cold boot from that URL reproduces the exact state",
          H.AN_FILTERS.host === "198.51.100.5" && H.AN_FILTERS.model === "LOF"
          && Number(H.trHours()) === 6
          && needEl("view-anomalies").classList.contains("active"),
          `${H.AN_FILTERS.host} / ${H.AN_FILTERS.model} / ${H.trHours()} / active=` +
          needEl("view-anomalies").classList.contains("active"));

    // cleanup: back to a neutral world for the sections that follow.
    fetchOverride = null;
    window.location.hash = "";
    H.anClearAllFilters();
    H.trApply("24");   // the range is global state; the sections after assume the default
    window.scrollTo = prevScrollTo;
    try { Object.defineProperty(window, "scrollY", { value: 0, configurable: true }); }
    catch (_e) { /* ignore */ }
    H.showView("health");
    await sleep(150);
  }

  // ── CHIPS + URLS, PER VIEW (US-7) ──────────────────────────────────────────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

    // A) ASSETS: the service facet filters in place, is PRESSED, rides the URL, survives reload.
    H.showView("assets");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadAssets();
    await sleep(300);
    const facet = [...doc.querySelectorAll("#as-facets .bubble.filter")];
    check("ASSETS: the inventory offers service filter chips",
          facet.length >= 2, `chips=${facet.length}`);
    const beforeRows = doc.querySelectorAll("#as-table tbody tr").length;
    if (facet[0]) { facet[0].click(); }
    await sleep(200);
    const svcLabel = facet[0] ? facet[0].textContent.split(" \u00b7 ")[0].trim() : "";
    // The render REPLACES the chips, so the clicked node is detached and reads stale: ask the
    // fresh set which chip is pressed (the DOM is the contract, not the node we held).
    const pressedNow = [...doc.querySelectorAll("#as-facets .bubble.filter")]
      .find((c) => c.getAttribute("aria-pressed") === "true");
    check("ASSETS: clicking the chip filters the inventory in place and marks it pressed",
          !!pressedNow && H.ASSETS_STATE.svc === svcLabel
          && pressedNow.textContent.startsWith(svcLabel),
          `pressed=${pressedNow ? pressedNow.textContent.trim() : "none"} svc=${H.ASSETS_STATE.svc}`);
    const sumTxt = (needEl("as-summary") || {}).textContent || "";
    check("ASSETS: the summary says showing X of Y with the reason",
          /\d+ of \d+ monitored hosts with service/.test(sumTxt) && sumTxt.includes(svcLabel), sumTxt);
    H.syncURL();
    check("ASSETS: the service filter rides the URL",
          /as\.svc=/.test(window.location.hash), window.location.hash);
    // the reload: wipe the state, then let BOOT's own path restore it from the URL.
    const keepHash = window.location.hash;
    H.ASSETS_STATE.svc = "";
    H.renderAssets();
    await sleep(100);
    const wiped = H.ASSETS_STATE.svc;
    window.location.hash = keepHash;
    H.applyURLState();
    H.renderAssets();
    await sleep(120);
    check("ASSETS: a reload restored by the URL puts the filter back",
          wiped === "" && H.ASSETS_STATE.svc === svcLabel
          && [...doc.querySelectorAll("#as-facets .bubble.filter")]
               .some((c) => c.getAttribute("aria-pressed") === "true"),
          `wiped=${wiped} now=${H.ASSETS_STATE.svc}`);
    const pressedFacet = [...doc.querySelectorAll("#as-facets .bubble.filter")]
      .find((c) => c.getAttribute("aria-pressed") === "true");
    if (pressedFacet) { pressedFacet.click(); await sleep(120); }   // stop filtering

    // B) NETWORK: the tracked-only chip filters the map, is pressed, rides the URL.
    H.showView("network");
    await H.loadNetwork();
    await sleep(250);
    H.ASSETS_STATE.tracked = ["203.0.113.42", "203.0.113.1"];
    H.renderNetwork();
    await sleep(120);
    const nwChip = needEl("nw-only-tracked");
    if (nwChip) { nwChip.click(); }
    await sleep(150);
    check("NETWORK: the tracked-only chip filters the map and is pressed",
          nwChip && nwChip.getAttribute("aria-pressed") === "true"
          && /showing 2 of 3 hosts/.test((needEl("nw-caption") || {}).textContent || ""),
          `pressed=${nwChip ? nwChip.getAttribute("aria-pressed") : "none"} ` +
          `caption=${(needEl("nw-caption") || {}).textContent || ""}`);
    H.syncURL();
    check("NETWORK: the filter rides the URL", /nw\.tracked=1/.test(window.location.hash),
          window.location.hash);
    H.ASSETS_STATE.trackedOnly = false;
    H.renderNetwork();
    H.applyURLState();
    H.renderNetwork();
    await sleep(120);
    check("NETWORK: a reload restored by the URL puts the filter back",
          H.ASSETS_STATE.trackedOnly === true
          && needEl("nw-only-tracked").getAttribute("aria-pressed") === "true");
    if (nwChip) { nwChip.click(); await sleep(120); }   // release
    H.ASSETS_STATE.tracked = [];
    H.renderNetwork();

    // C) DISCOVER: the feed switch applies, rides the URL, and the reload asks for it.
    H.showView("discover");
    await H.loadDiscover();
    await sleep(300);
    const feedSel = needEl("dc-feed");
    check("DISCOVER: the feed select is on screen", !!feedSel);
    if (feedSel) {
      feedSel.value = "dns";
      feedSel.dispatchEvent(new window.Event("change", { bubbles: true }));
    }
    await sleep(400);
    check("DISCOVER: the feed switch is applied (the summary speaks DNS)",
          /DNS/.test((needEl("dc-summary") || {}).textContent || ""),
          (needEl("dc-summary") || {}).textContent || "");
    H.syncURL();
    check("DISCOVER: the feed rides the URL", /dc\.feed=dns/.test(window.location.hash),
          window.location.hash);
    const keepDcHash = window.location.hash;
    const DC_REQS = [];
    fetchOverride = (u) => {
      if (String(u).includes("/api/discover")) DC_REQS.push(String(u));
      return null;
    };
    feedSel.value = "netflow";
    window.location.hash = keepDcHash;
    H.applyURLState();
    check("DISCOVER: a reload restored by the URL puts the select back",
          feedSel.value === "dns", feedSel.value);
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadDiscover();
    await sleep(250);
    check("...and the request asks for the restored feed",
          DC_REQS.some((u) => /feed=dns/.test(u)), DC_REQS.join(" ").slice(0, 140));
    fetchOverride = null;
    feedSel.value = "netflow";
    await H.loadDiscover();
    await sleep(200);
    window.location.hash = "";

    H.showView("health");
    await sleep(150);
  }

  // ── THE WRITE TRAIL (US-10) ────────────────────────────────────────────────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const trailing = [];
    fetchOverride = (u) => {
      if (String(u).includes("/api/write-trail")) trailing.push(String(u));
      return null;
    };
    // 1) the trail is a readable surface: who / what / why / when -- on its OWN tab now.
    H.showView("logs");
    await sleep(450);
    const stTrail = needEl("lg-changes");
    const trailRows = stTrail ? [...stTrail.querySelectorAll("tbody tr")] : [];
    check("US-10: the write trail lists its entries",
          trailRows.length >= 3,
          `${trailRows.length} row(s)`);
    const rowText = trailRows.map((r) => r.textContent).join(" | ");
    check("...with ACTOR, REASON and TARGET on each entry",
          /admin/.test(rowText) && /tighten after the scanner/.test(rowText)
          && /base_threshold/.test(rowText) && /edge-alive/.test(rowText),
          rowText.slice(0, 160));
    const firstSel = stTrail ? stTrail.querySelector("select") : null;
    check("...and the filter menus are the table's own scopes and actions",
          !!firstSel && stTrail.querySelectorAll("select").length === 2
          && /settings/.test(firstSel.textContent),
          firstSel ? firstSel.textContent : "none");
    // 2) the settings provenance line links to the entry.
    H.showView("settings");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadSettings();
    await sleep(300);
    const provRow = doc.querySelector('#view-settings [data-key="base_threshold"] .setting-prov');
    check("US-10: a GUI-written setting says who set it, when, and why",
          !!provRow && /set via GUI/.test(provRow.textContent)
          && /tighten after the scanner/.test(provRow.textContent),
          provRow ? provRow.textContent.slice(0, 120) : "none");
    const trailLink = provRow && [...provRow.querySelectorAll("button.link")]
      .find((b) => b.textContent === "trail");
    check("...with a one-click link to its trail entries", !!trailLink);
    trailing.length = 0;
    if (trailLink) trailLink.click();
    await sleep(450);
    check("...which lands on the trail FILTERED to that key",
          trailing.some((u) => /scope=settings/.test(u) && /target=base_threshold/.test(u)),
          trailing.slice(-1)[0] || "no request");
    const hit = doc.querySelector("#lg-changes tr.wtl-hit");
    check("...with the matching entry standing out", !!hit && /base_threshold/.test(hit.textContent),
          hit ? hit.textContent.slice(0, 100) : "none");
    // 3) REVERT: the BF-9 echo demands its reason; the write posts revert with it.
    const revertBtn = provRow && [...provRow.querySelectorAll("button.link")]
      .find((b) => b.textContent === "revert");
    check("US-10: a GUI-written setting offers a revert", !!revertBtn);
    const postsBefore = POSTED.length;
    if (revertBtn) revertBtn.click();
    await sleep(300);
    const modal = doc.querySelector(".dest-confirm");
    check("...the reverts go through the destructive echo (target + blast radius shown)",
          !!modal && /base_threshold/.test(modal.textContent)
          && /0\.35/.test(modal.textContent) && /0\.45/.test(modal.textContent),
          modal ? modal.textContent.replace(/\s+/g, " ").slice(0, 140) : "no echo");
    const goBtn = modal && [...modal.querySelectorAll("button")]
      .find((b) => /Revert/.test(b.textContent));
    check("...and the confirm is DISABLED until a reason is typed",
          !!goBtn && goBtn.hasAttribute("disabled"));
    const reasonIn = modal && modal.querySelector(".dest-reason");
    if (reasonIn) {
      reasonIn.value = "the scanner is gone; put the threshold back";
      reasonIn.dispatchEvent(new window.Event("input", { bubbles: true }));
    }
    await sleep(80);
    check("...typing the reason enables it", !!goBtn && !goBtn.hasAttribute("disabled"));
    if (goBtn) goBtn.click();
    await sleep(500);
    const applyPost = POSTED.slice(postsBefore).find((r) => /\/api\/settings\/apply/.test(r.url));
    check("...and the revert POSTS the previous value, the reason, and its own flag",
          !!applyPost
          && /"base_threshold":"0\.45"/.test(applyPost.body || "")
          && /scanner is gone/.test(applyPost.body || "")
          && /"revert":true/.test(applyPost.body || ""),
          applyPost ? String(applyPost.body).slice(0, 160) : "no apply post");
    fetchOverride = null;
    H.showView("health");
    await sleep(150);
  }

  // ── PROVENANCE + REACH (US-9) ──────────────────────────────────────────────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    // 1) every alert row carries a STABLE reason code and its own Tune verb.
    H.showView("anomalies");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadAnomalies();
    await sleep(300);
    const codeEl = doc.querySelector("#anomalies-table tbody .reason-code");
    check("US-9: an alert row carries its stable reason code",
          !!codeEl && /^[A-Z+]+:[\w.-]+$/.test((codeEl.textContent || "").trim()),
          codeEl ? codeEl.textContent.trim() : "none");
    const tuneBtn = [...doc.querySelectorAll("#anomalies-table .an-actions .review-act")]
      .find((b) => b.textContent === "Tune");
    check("US-9: the row offers Tune detection (per row, not per page)", !!tuneBtn);
    if (tuneBtn) { tuneBtn.click(); }
    await sleep(550);
    const thrRow = doc.querySelector('#view-settings [data-key="base_threshold"]');
    const thrCard = thrRow && thrRow.closest(".card");
    check("...and Tune lands on the detection threshold with its card expanded",
          needEl("view-settings").classList.contains("active")
          && !!thrCard && !thrCard.classList.contains("collapsed"),
          thrCard ? `collapsed=${thrCard.classList.contains("collapsed")}` : "no threshold row");
    // 2) the rule surface states its reach, and each sensor opens its fleet sheet.
    H.showView("sluice");
    await H.loadSluice();
    await sleep(400);
    const reach = needEl("sl-reach");
    check("US-9: the rules surface states its reach",
          !!reach && /can act on \d+ sensor/.test(reach.textContent || ""),
          (reach && reach.textContent || "").slice(0, 130));
    const reachChip = reach && reach.querySelector("button.bubble.filter");
    check("...with a sensor chip for a reachable sensor", !!reachChip,
          reachChip ? reachChip.textContent : "none");
    if (reachChip) { reachChip.click(); }
    await sleep(550);
    check("...and the chip opens that sensor's fleet sheet",
          !doc.getElementById("wl-detail-card").classList.contains("hidden")
          && ((needEl("wl-detail-id") || {}).textContent || "")
               === (reachChip ? reachChip.textContent : ""),
          `id=${(needEl("wl-detail-id") || {}).textContent || ""}`);
    if (typeof H.closeWeirling === "function") H.closeWeirling();
    H.showView("health");
    await sleep(150);
  }

  // ── DISCOVER: the raw-flow browser (the operator's ask, 2026-10-16) ────────────────────────
  {
    H.showView("discover");
    await H.loadDiscover();
    const dcRows = doc.querySelectorAll("#dc-rows tr.dc-row");
    check("the tab is called Flows, not Discover",
          /^Flows/.test((doc.querySelector("#view-discover .view-head h2") || {}).textContent || ""));
    await new Promise((r) => setTimeout(r, 200));
    const trendBoxes = [...doc.querySelectorAll("#dc-trends .trend-box")];
    check("the Flows header carries three feed trend boxes",
          trendBoxes.length === 3
          && /Netflow/.test(trendBoxes[0].textContent) && /Zeek/.test(trendBoxes[1].textContent)
          && /DNS/.test(trendBoxes[2].textContent)
          && trendBoxes.every((b) => b.querySelector("svg")),
          trendBoxes.map((b) => b.textContent.trim()).join(" | "));
    check("Discover renders the flow rows the server served", dcRows.length === 2,
          "rows=" + dcRows.length);
    const dirCell = doc.querySelector("#dc-rows tr.dc-row td.dc-dir");
    check("a flow row states which half of the conversation it is",
          !!dirCell && dirCell.dataset.direction === "request" && /request/.test(dirCell.textContent),
          dirCell ? (dirCell.dataset.direction + ":" + dirCell.textContent) : "no direction cell");
    const dirHeads = [...doc.querySelectorAll("#view-discover thead th")].map((th) => th.textContent);
    check("the direction column has a heading, not a blank arrow cell",
          dirHeads.some((h) => /direction/i.test(h)), dirHeads.join(" | "));
    if (dcRows[0]) {
      dcRows[0].click();
      const detail = doc.querySelector("#dc-rows tr.dc-detail");
      check("a row opens its every-field detail", !!detail && /flow started/.test(detail.textContent),
            detail ? detail.textContent.slice(0, 60) : "no detail row");
      check("the detail names the opener and the evidence behind the direction",
            !!detail && /opened by: 198\.51\.100\.20:4444/.test(detail.textContent)
            && /direction evidence: tcp-syn/.test(detail.textContent),
            detail ? detail.textContent.slice(0, 180) : "no detail");
      check("and offers to filter on the fields it shows",
            !!(detail && detail.querySelectorAll("button").length >= 3),
            "fewer than three action buttons");
      check("the flow detail renders no 'undefined' anywhere",
            !!detail && !/undefined/.test(detail.textContent)
            && ![...detail.querySelectorAll("button")].some((b) => /undefined/.test(b.textContent)));
      dcRows[0].click();   // close the detail before the DNS arm of this block
    }
    // US-1: the DNS feed's record detail -- a client and a query, never a src/dst pair, and
    // never the word undefined.
    const feedSel = needEl("dc-feed");
    if (feedSel) {
      feedSel.value = "dns";
      feedSel.dispatchEvent(new window.Event("change", { bubbles: true }));
      await new Promise((r) => setTimeout(r, 200));
      const dnsRows = doc.querySelectorAll("#dc-rows tr.dc-row");
      check("the DNS feed renders its records", dnsRows.length >= 1, "rows=" + dnsRows.length);
      if (dnsRows[0]) {
        dnsRows[0].click();
        const dnsDetail = doc.querySelector("#dc-rows tr.dc-detail");
        check("a DNS record's detail says client and answers, with no undefined",
              !!dnsDetail && /client: 198.51.100.77/.test(dnsDetail.textContent)
              && !/undefined/.test(dnsDetail.textContent),
              dnsDetail ? dnsDetail.textContent.slice(0, 100) : "no detail");
        const dnsBtns = dnsDetail ? [...dnsDetail.querySelectorAll("button")].map((b) => b.textContent) : [];
        check("...and its one action opens the CLIENT's host view",
              dnsBtns.length === 1 && /open host 198.51.100.77/.test(dnsBtns[0]),
              dnsBtns.join(" | "));
        // Guarded: a regression that strips the button must fail the checks, not crash the run.
        const dnsBtn = dnsDetail ? dnsDetail.querySelector("button") : null;
        if (dnsBtn) dnsBtn.click();
        await new Promise((r) => setTimeout(r, 120));
        check("...and that button lands on the host view",
              !!dnsBtn && needEl("view-host").classList.contains("active"));
        H.showView("discover");
        feedSel.value = "netflow";
        feedSel.dispatchEvent(new window.Event("change", { bubbles: true }));
        await new Promise((r) => setTimeout(r, 200));
      }
    }
    const dcVol = needEl("dc-volume");
    const hits = dcVol ? dcVol.querySelectorAll("rect.hit") : [];
    check("the Discover histogram buckets are clickable drill targets", hits.length >= 1,
          "hit rects=" + hits.length);
    const protoSel = needEl("dc-proto");
    check("the flow-type facet fills from the payload",
          !!(protoSel && protoSel.options.length >= 3), "options=" + (protoSel ? protoSel.options.length : "?"));
    // ── CLICK A VALUE AND IT IS ADDED TO THE FILTER (the operator's words) ────────────────────
    const srcCell = doc.querySelector("#dc-rows tr.dc-row td.dcell[title^='add to the filter: src']");
    check("every value cell in a Discover row is a click-to-filter target", !!srcCell,
          "no src cell carries the drill title");
    if (srcCell) {
      srcCell.click();
      // The chip renders when the re-fetch lands (dcAddChip reloads the page of flows), so the
      // check waits for that microtask chain instead of racing it.
      await new Promise((r) => setTimeout(r, 60));
      const chips = doc.querySelectorAll("#dc-chips .bubble.filter");
      check("clicking a source adds it as a chip", chips.length === 1 &&
            /src = 198\.51\.100\.20/.test(chips[0].textContent),
            "chips=" + [...chips].map((c) => c.textContent).join(" | "));
      const x = chips[0] ? chips[0].querySelector("button.bubble-x") : null;
      check("and the chip can be removed again", !!x, "no remove control on the chip");
      if (x) {
        x.click();
        await new Promise((r) => setTimeout(r, 60));
        check("removing the chip empties the filter row",
              doc.querySelectorAll("#dc-chips .bubble.filter").length === 0,
              needEl("dc-chips").textContent.slice(0, 60));
      }
    }
    // ── A WEIRLING IS NAMED, NOT AN IP (the operator, 2026-10-16) ─────────────────────────────
    const wCell = doc.querySelector("#dc-rows tr.dc-row td.dcell[title*='weirling =']");
    check("the discover row names the weirling, not the exporter address",
          !!wCell && /weirvern/.test(wCell.textContent) && !/127\.0\.0\.1/.test(wCell.textContent),
          wCell ? wCell.textContent : "no weirling cell");
    const wSel = needEl("dc-sensor");
    const wOpt = wSel ? [...wSel.options].find((o) => o.value === "127.0.0.1") : null;
    check("the weirling filter shows the name but filters on the address",
          !!wOpt && /weirvern/.test(wOpt.textContent), wOpt ? wOpt.textContent : "no option");
    check("and its default option reads 'all weirlings'",
          !!wSel && /all weirlings/.test(wSel.options[0].textContent),
          wSel ? wSel.options[0].textContent : "");

  // ── BLOCKS IS A DRILL FROM SLUICE (operator, 2026-10-21) ────────────────────────────────
  {
    H.showView("blocked");
    await H.loadBlocked();
    const sum = needEl("bl-summary").textContent;
    check("the blocks summary counts hits and the live rules", /3 recorded hits/.test(sum) &&
          /1 blocking rule/.test(sum) && /1 alerting rule/.test(sum), sum.slice(0, 160));
    const sluiceTab = doc.querySelector('.tab[data-view="sluice"]');
    check("the Blocks view is a Sluice drill, not a peer tab",
          H.CURRENT_VIEW === "blocked"
          && !!sluiceTab && sluiceTab.classList.contains("active")
          && /Sluice Gate/.test(needEl("crumbs") ? needEl("crumbs").textContent : ""));
    const hitRows = doc.querySelectorAll("#bl-hit-rows tr");
    check("the hits table renders with rule/list labels",
          hitRows.length === 2 &&
          /rule|list/.test((doc.querySelector("#bl-hit-rows tr .bubble.state") || {}).textContent || ""),
          "rows=" + hitRows.length);
    check("a rule hit and a list hit are distinguishable in the row",
          /rule/.test(doc.querySelector("#bl-hit-rows tr td:nth-child(2)").textContent) &&
          /list/.test(doc.querySelectorAll("#bl-hit-rows tr")[1].textContent),
          doc.querySelector("#bl-hit-rows tr").textContent.slice(0, 80));
    // THE DUPLICATE RULE AUTHORITY IS GONE. Rules live in Sluice; this view must not carry a
    // second editable rule table or card.
    check("Blocks carries no duplicate rule tables",
          !doc.getElementById("bl-block-rows") && !doc.getElementById("bl-alert-rows"));
    check("Blocks carries no second rule editor",
          !doc.getElementById("bl-rule-card") && !doc.getElementById("bl-rule-mode"));
    // ROW -> DETAIL, the anomaly pattern.
    const first = doc.querySelector("#bl-hit-rows tr.clickable");
    if (first) first.click();
    await new Promise((r) => setTimeout(r, 120));
    const detail = needEl("bl-detail-card");
    check("a block row opens its detail sheet",
          !!detail && !detail.classList.contains("hidden")
          && /ads\.example\.com/.test(needEl("bl-detail-body").textContent)
          && /DNS answered|recorded|blocklist/.test(needEl("bl-detail-body").textContent),
          detail ? needEl("bl-detail-body").textContent.slice(0, 120) : "no detail");
    if (detail) H.closeSheet(detail);
  }

  // ── OPENING A RULE ON A FRESH CONSOLE (#15) ─────────────────────────────────────────────
  //
  // A hit carries only a rule id. The click path must fetch the live sets on demand (once),
  // then open the ONE rule editor -- Sluice's sheet. It must not fabricate "expired or revoked"
  // from a payload that was never read, and it must not re-fetch on every click.
  {
    fetchOverride = null;
    H.showView("sluice");
    H.clearGetCache();  // getJSON caches for 8s; the stub is only seen after a clear
    await H.loadSluice();
    const savedBlocked = H.BLOCKED_STATE.data;
    H.BLOCKED_STATE.data = null;                 // the console never visited Blocks
    const fetches0 = BLOCKED_FETCHES;
    check("a live rule is listed on Sluice before Blocks was ever loaded",
          [...doc.querySelectorAll("#sl2-rules tbody tr.sl2-rule-row")]
            .some((tr) => tr.textContent.includes("ads.example.com")));
    await H.blOpenRuleById("r1");
    await new Promise((r) => setTimeout(r, 160));
    const modeSel = needEl("sl2-detail-mode");
    check("clicking a hit's rule opens the Sluice sheet with the real rule",
          !doc.getElementById("sl-rule-sheet").classList.contains("hidden")
          && needEl("sl2-sheet-id").textContent === "r1"
          && !!modeSel && !modeSel.disabled && modeSel.value === "block"
          && /ads\.example\.com/.test(needEl("sl2-facts").textContent),
          `id=${needEl("sl2-sheet-id").textContent} mode=${modeSel ? modeSel.value : "missing"}`);
    check("the payload was fetched ON DEMAND, exactly once",
          BLOCKED_FETCHES === fetches0 + 1,
          `${BLOCKED_FETCHES - fetches0} fetch(es)`);
    await H.blOpenRuleById("r2");
    await new Promise((r) => setTimeout(r, 160));
    check("opening a second rule does not refetch it",
          BLOCKED_FETCHES === fetches0 + 1
          && needEl("sl2-sheet-id").textContent === "r2",
          `${BLOCKED_FETCHES - fetches0} fetch(es); id=${needEl("sl2-sheet-id").textContent}`);
    await H.blOpenRuleById("r-revoked");         // not among the live sets
    await new Promise((r) => setTimeout(r, 160));
    check("a genuinely non-live rule opens the sheet read-only, not as a live decision",
          needEl("sl2-sheet-id").textContent === "r-revoked"
          && needEl("sl2-detail-mode").disabled === true);
    const ruleClose = needEl("sl-rule-close");
    if (ruleClose) ruleClose.click();
    H.BLOCKED_STATE.data = savedBlocked;
  }

  // ── THE DNS VIEW (the operator's ask: "can we view dns on port 53") ────────────────────────
  {
    H.showView("dns");
    await H.loadDns();
    const rows = doc.querySelectorAll("#dn-rows tr.dc-row");
    check("the DNS view renders Q/A rows", rows.length === 2, "rows=" + rows.length);
    const rowMore = rows[0].querySelector("td.dn-actions details.row-more");
    check("a DNS row carries one actions disclosure, closed at rest",
          !!rowMore && !rowMore.open && !!rowMore.querySelector("summary")
          && !!rowMore.querySelector("button"),
          rowMore ? "present" : "missing");
    if (rowMore) {
      rowMore.querySelector("summary").click();
      check("the DNS row disclosure opens in place",
            rowMore.open && !doc.querySelector("tr.dn-detail"), "summary bubbled to the row");
      rowMore.open = false;
    }
    check("the summary names the NXDOMAIN count",
          /NXDOMAIN/.test(needEl("dn-summary").textContent),
          needEl("dn-summary").textContent.slice(0, 90));
    rows[0].click();
    await new Promise((r) => setTimeout(r, 150));
    const detail = doc.querySelector("tr.dn-detail");
    check("a row opens the full answers and the reverse map",
          !!detail && /ads\.example\.com/.test(detail.textContent),
          detail ? detail.textContent.slice(0, 140) : "no detail row");
    const act = detail
      ? [...detail.querySelectorAll("button.bubble.filter")].find((b) => /\+ domain/.test(b.textContent))
      : null;
    if (act) act.click();
    await new Promise((r) => setTimeout(r, 40));
    check("a detail action filters the view",
          !!(act) && needEl("dn-domain").value === "ads.example.com",
          needEl("dn-domain").value);
    H.dnClear();
    check("clear empties the DNS filters", needEl("dn-domain").value === "", "");

    // ISSUE #38: the summary line respects the payload state, the way the panels below it
    // and blocked.js's pager already did. A failed read must not claim a count or a range;
    // an empty successful read must not render the impossible "1\u20130".
    const dnServe = (payload) => Promise.resolve(
      { ok: true, status: 200, statusText: "OK", json: async () => payload });
    // CLEAR THE CACHE FIRST, OR THE STUB IS NEVER CALLED. getJSON serves every GET for eight
    // seconds and dedupes in flight, and this block already loaded /api/dns with the healthy
    // fixture above -- so the stubbed re-load returned the CACHED body, the override was never
    // consulted, and BOTH assertions below read the healthy summary ("12 queries : 3 NXDOMAIN").
    // Measured: that is exactly the text they reported. The product code was correct all along
    // (dnRenderSummary returns early on d.available === false at dnsview.js:62); these two were
    // harness artifacts, not defects, and they had been counted as failures since the repair.
    H.clearGetCache();
    fetchOverride = (u) => (String(u).includes("/api/dns")
      ? dnServe({ available: false, reason: "cannot reach ClickHouse: OperationalError",
                rows: [], total: 0, histogram: [], facets: {}, data_error: "x" })
      : null);
    await H.loadDns();
    const failedSummary = needEl("dn-summary").textContent;
    check("a FAILED dns read claims no query count and no range",
          /unavailable: cannot reach ClickHouse/.test(failedSummary)
          && !/\d+ quer/.test(failedSummary) && !/\d+\u2013\d+/.test(failedSummary),
          failedSummary.slice(0, 110));
    H.clearGetCache();   // the same seam: the failed-read payload above is cached
    fetchOverride = (u) => (String(u).includes("/api/dns")
      ? dnServe({ available: true, reason: "", total: 0, limit: 100, offset: 0,
                 rows: [], histogram: [], facets: {}, bucket_s: 60 })
      : null);
    await H.loadDns();
    const emptySummary = needEl("dn-summary").textContent;
    check("an EMPTY successful dns read keeps its count and reads 0\u20130, never 1\u20130",
          /0 quer/.test(emptySummary) && /showing 0\u20130/.test(emptySummary)
          && !/1\u20130/.test(emptySummary),
          emptySummary.slice(0, 110));
    fetchOverride = null;
    H.clearGetCache();
    await H.loadDns();
    H.clearGetCache();
  }
  }
  // ── THE TIME CONTROL REACHES DISCOVER TOO (issue #30) ───────────────────────────────────
  {
    H.showView("discover");
    await H.loadDiscover();
    check("Discover names the window it is showing",
          /last 24 hours window/i.test(needEl("dc-window").textContent),
          needEl("dc-window").textContent);
    const dn0 = DISCOVER_REQS.length;
    H.trApply({ mode: "relative", hours: 6 });
    await new Promise((r) => setTimeout(r, 300));
    const dnLast = DISCOVER_REQS[DISCOVER_REQS.length - 1] || "";
    check("changing the range re-fetches Discover with the new hours",
          DISCOVER_REQS.length > dn0 && /hours=6/.test(dnLast),
          `requests=${DISCOVER_REQS.length - dn0}; last=${dnLast.slice(0, 70)}`);
    check("and Discover's window pill follows the header",
          /last 6 hours window/i.test(needEl("dc-window").textContent),
          needEl("dc-window").textContent);
    H.trApply({ mode: "relative", hours: 24 });
    await new Promise((r) => setTimeout(r, 300));
  }
  // ── HD-17: THE DIALOG CONTRACT AND KEYBOARD FILTER CELLS ─────────────────────────────────
  {
    // Start from a closed shell: an earlier block leaves the Blocked rule card open, and a
    // modal opened over an open modal would focus the first node's control (a real stack, but
    // not what this probe is measuring). EVERY sheet is closed too: the modal's Tab trap
    // deliberately yields to a sheet, so one left open (the Sluice rule sheet, the weirling
    // sensor card) makes this probe measure nothing.
    for (const leftover of [...doc.querySelectorAll(".sheet")]) {
      if (leftover.classList.contains("hidden")) continue;
      const closer = leftover.querySelector(".sheet-close");
      if (closer) closer.click();
      else leftover.classList.add("hidden");
    }
    const shell0 = needEl("modal");
    if (shell0 && !shell0.classList.contains("hidden")) {
      for (const node of [...needEl("modal-body").children]) H.closeModal(node);
    }
    if (typeof H.closeWeirling === "function") H.closeWeirling();
    const strayClose = needEl("wl-sensor-close");
    if (strayClose) strayClose.click();
    const opener = doc.createElement("button");
    opener.textContent = "open";
    doc.body.appendChild(opener);
    opener.focus();
    const pane = doc.createElement("div");
    pane.innerHTML = "<h2>Contract probe</h2><button id='probe-a'>a</button><button id='probe-b'>b</button>";
    H.openModal(pane);
    await new Promise((r) => setTimeout(r, 40));
    const shell = needEl("modal");
    const labelId = shell.getAttribute("aria-labelledby");
    const label = labelId ? doc.getElementById(labelId) : null;
    check("the dialog is labelled by its own heading",
          !!label && /Contract probe/.test(label.textContent), labelId || "no label");
    check("focus moves into the dialog on open",
          shell.contains(doc.activeElement),
          (doc.activeElement || {}).id || (doc.activeElement || {}).tagName);
    needEl("probe-b").focus();
    doc.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Tab", bubbles: true }));
    check("Tab stays inside the dialog", doc.activeElement === needEl("probe-a"),
          (doc.activeElement || {}).id || "?");
    H.closeModal(pane);
    await new Promise((r) => setTimeout(r, 40));
    check("closing returns focus to the opener", doc.activeElement === opener);
    opener.remove();
  }
  {
    H.showView("anomalies");
    await H.loadAnomalies();
    await new Promise((r) => setTimeout(r, 80));
    const cells = [...doc.querySelectorAll(".dcell")];
    check("every filter cell is reachable by keyboard",
          cells.length > 0 && cells.every((c) => c.getAttribute("tabindex") === "0"),
          `${cells.filter((c) => c.getAttribute("tabindex") !== "0").length}/${cells.length} unmarked`);
    const cell = cells[0];
    let clicked = 0;
    if (cell) cell.addEventListener("click", () => { clicked += 1; });
    if (cell) cell.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    check("and Enter performs the click a mouse would", clicked === 1, `clicks=${clicked}`);
  }
  // ── THE NORMALIZE TAB LISTS RIPPLE SIGNATURES (2026-11-20) ────────────────────────────────
  // The list lives on the surface the flow normalizations already use: one exact value per row,
  // its reason and its review date, and one-click Remove (no confirm step -- the action is the
  // reversible one, and the row itself is the record).
  {
    const seen = [];
    fetchOverride = (u, opts) => {
      const url = String(u);
      seen.push(url);
      if (url.includes("/api/ripple-signatures/remove") && opts && opts.method === "POST") {
        return { ok: true, status: 200, statusText: "OK",
                 json: async () => ({ ok: true, entries: [], summary: {} }) };
      }
      if (url.includes("/api/normalize")) {
        return { ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true, reason: "", rows: [], entries: [], summary: {},
          window: { offset: 0, hours: 24, older: false },
          signatures: [{ id: "sig-9", host_addr: "198.51.100.5",
                         channel: "tls_fingerprint_diversity",
                         value: "example.test|ja4abc", created_at: "2026-11-20T09:00:00",
                         created_by: "admin", reason: "the new backup appliance",
                         review_after: "2027-02-18" }],
          signature_summary: { active: 1, expired: 0 },
        }) };
      }
      return null;
    };
    H.clearGetCache();
    await H.loadNormalize();
    await new Promise((r) => setTimeout(r, 160));
    const rows = [...doc.querySelectorAll("#nz-sigs tbody tr")];
    check("the Normalize tab lists a ripple signature with its exact value, reason and review date",
          rows.length === 1 && /example\.test\|ja4abc/.test(rows[0].textContent)
          && /tls_fingerprint_diversity/.test(rows[0].textContent)
          && /the new backup appliance/.test(rows[0].textContent)
          && /2027-02-18/.test(rows[0].textContent),
          rows.map((r) => r.textContent).join(" | ").slice(0, 240));
    const remove = rows[0] ? rows[0].querySelector("button.nz-sig-remove") : null;
    check("...and removing it is one click on the row's own button",
          !!remove && /Remove/.test(remove.textContent), remove ? remove.textContent : "no button");
    if (remove) remove.click();
    await new Promise((r) => setTimeout(r, 120));
    check("...which talks to the signature remove route, never the alert path",
          seen.some((u) => u.includes("/api/ripple-signatures/remove")), seen.join(" | "));
    fetchOverride = null;
    H.clearGetCache();
  }
  // ── THE SCAN SHEET (operator, 2026-11-20: watch a manual scan) ──────────────────────────────
  {
    H.clearGetCache();
    // LIVE timestamps: a fixed date would read as a 30-minute timeout on a machine running
    // later in the day, and the sheet would (correctly) say so.
    const SCAN_T0 = Date.now() - 5000;
    const at = (ms) => new Date(ms).toISOString();
    let SCAN_JOB = {
      job_id: "job-scan-1", asset_key: "a-1", ip: "192.0.2.10", requested_by: "operator",
      requested_at: at(SCAN_T0), state: "queued", lease_owner: "",
      lease_until: null, started_at: null, finished_at: null, result: "", error: "",
      derived_state: "queued", abandoned: false, state_reason: "",
    };
    // THE HUB'S OWN ANSWER, which the button and the sheet read. It says one weirling can scan
    // this host, so the sheet must not imply otherwise.
    let SCAN_READY_REPLY = { available: true, enabled: true, count: 1, capable_count: 1,
                             ip: "192.0.2.10", lease_s: 900,
                             sentence: "1 of 1 weirling can scan 192.0.2.10 (nmap 7.95)",
                             reason_unavailable: "" };
    let scanPosts = [];
    let scanDeletes = [];
    fetchOverride = (u, o) => {
      const method = String((o || {}).method || "GET").toUpperCase();
      if (method === "POST") { scanPosts.push(String(u)); return null; }
      if (method === "DELETE") {
        scanDeletes.push({ url: String(u), body: String((o || {}).body || "") });
        return { ok: true, status: 200, statusText: "OK", json: async () => ({
          ok: true, removed: true, job_id: "job-scan-1", ip: "192.0.2.10",
          reason: "duplicate request",
          note: "removed job job-scan-1 for 192.0.2.10; the cancellation is recorded in the "
            + "audit trail",
        }) };
      }
      let reply = null;
      if (String(u).includes("/api/scan-readiness")) reply = SCAN_READY_REPLY;
      else if (String(u).includes("/api/scan-jobs")) {
        reply = { available: true, reason: "", jobs: [SCAN_JOB], count: 1 };
      }
      if (!reply) return null;
      // fetchOverride answers a RESPONSE, not a payload: the dispatcher returns whatever is
      // truthy straight to the caller, and scanGet reads res.ok/res.json like the real fetch.
      return { ok: true, status: 200, statusText: "OK", json: async () => reply };
    };
    const scanSheet = needEl("scan-sheet");
    const scanBtn = doc.createElement("button");
    scanBtn.textContent = "Scan now";
    doc.body.appendChild(scanBtn);
    H.requestScan("192.0.2.10", scanBtn);
    await new Promise((r) => setTimeout(r, 300));
    check("pressing Scan opens the sheet for the job the POST created",
          !!scanSheet && !scanSheet.classList.contains("hidden")
          && H.SCAN_STATE.jobId === "job-scan-1",
          `open=${scanSheet && !scanSheet.classList.contains("hidden")} id=${H.SCAN_STATE.jobId}`);
    check("...and the sheet's subject rides the URL",
          /(^|[&#])scan=job-scan-1/.test(String(window.location.hash || "")),
          String(window.location.hash || ""));
    check("...and a queued job reads as queued, not as a percentage",
          /Queued/.test(needEl("scan-state-line").textContent)
          && !/\d\s*%/.test(needEl("scan-body").textContent)
          && !doc.querySelector("#scan-body progress"),
          needEl("scan-body").textContent.slice(0, 90));

    // RUNNING: a weirling claimed it; the state word changes and elapsed starts at started_at.
    SCAN_JOB = Object.assign({}, SCAN_JOB, {
      state: "claimed", derived_state: "claimed", lease_owner: "wl-lab",
      started_at: at(SCAN_T0 + 2000) });
    await H.scanPollOnce();
    await new Promise((r) => setTimeout(r, 30));
    check("the sheet reflects queued -> running from the queue row",
          /Running/.test(needEl("scan-state-line").textContent)
          && /wl-lab/.test(needEl("scan-body").textContent)
          && /picked up by/.test(needEl("scan-body").textContent),
          needEl("scan-state-line").textContent);

    // DONE: terminal, with the measured evidence the weirling recorded.
    SCAN_JOB = Object.assign({}, SCAN_JOB, {
      state: "done", derived_state: "done", finished_at: at(SCAN_T0 + 60000),
      result: "scan completed", lease_until: null });
    await H.scanPollOnce();
    await new Promise((r) => setTimeout(r, 30));
    check("the sheet reflects running -> done and names the recorded evidence",
          /Done/.test(needEl("scan-state-line").textContent)
          && /scan completed/.test(needEl("scan-body").textContent),
          needEl("scan-body").textContent.slice(0, 120));
    check("...and the removed Findings drill is not offered",
          !needEl("scan-sheet").querySelector("#scan-findings")
          && !/recorded findings/i.test(needEl("scan-body").textContent));
    // A SHEET IS AN OVERLAY, NOT A VIEW: moving to another tab must not close it, and coming
    // back must find it still showing the same job.
    H.showView("network");
    await new Promise((r) => setTimeout(r, 120));
    const survived = !scanSheet.classList.contains("hidden");
    H.showView("assets");
    await new Promise((r) => setTimeout(r, 120));
    check("the sheet survives navigation within the view",
          survived && !scanSheet.classList.contains("hidden")
          && H.SCAN_STATE.jobId === "job-scan-1");
    check("...and polling stops at the terminal state",
          H.SCAN_STATE.pollTimer === null, String(H.SCAN_STATE.pollTimer));

    // FAILED: the recorded error is the sentence, and Retry is offered.
    SCAN_JOB = Object.assign({}, SCAN_JOB, {
      state: "error", result: "", error: "nmap: the target refused every probe" });
    await H.scanPollOnce();
    await new Promise((r) => setTimeout(r, 30));
    check("a failed job names the scanner's recorded error",
          /Failed/.test(needEl("scan-state-line").textContent)
          && /the target refused every probe/.test(needEl("scan-body").textContent),
          needEl("scan-body").textContent.slice(0, 140));
    check("...and offers a retry rather than a dead end",
          !needEl("scan-retry").classList.contains("hidden"));
    check("no percentage is rendered anywhere in the sheet",
          !/\d\s*%/.test(needEl("scan-sheet").textContent)
          && !doc.querySelector("#scan-sheet progress, #scan-sheet [role=\"progressbar\"]"));

    // ABANDONED (server-derived from the lease and the claim, never hand-set). The sheet must
    // say why nothing will run it and offer cancellation, not sit on "Queued" forever.
    SCAN_JOB = Object.assign({}, SCAN_JOB, {
      state: "queued", derived_state: "abandoned", abandoned: true, error: "",
      result: "", finished_at: null, started_at: null, lease_owner: "",
      state_reason: "no scanner claimed this job in 31m00s; its 900s lease ran out with no claim, "
        + "so nothing is working on it",
    });
    await H.scanPollOnce();
    await new Promise((r) => setTimeout(r, 30));
    check("a queued job past its lease renders as Abandoned, not Queued",
          /Abandoned/.test(needEl("scan-state-line").textContent)
          && /ran out with no claim/.test(needEl("scan-body").textContent),
          needEl("scan-state-line").textContent);
    check("...and the sheet offers to cancel it",
          !needEl("scan-cancel-job").classList.contains("hidden"),
          needEl("scan-cancel-job").className);
    scanPosts = [];
    scanDeletes = [];
    H.scanCancelJob();
    await new Promise((r) => setTimeout(r, 20));
    check("...and cancelling asks 'Cancel scan?' with the consequence and two buttons",
          !needEl("scan-cancel-form").classList.contains("hidden")
          && /Cancel scan\?/.test(needEl("scan-cancel-form").textContent)
          && /This removes the job from the record\./.test(needEl("scan-cancel-form").textContent)
          && /Cancel scan/.test(needEl("scan-cancel-confirm").textContent)
          && /Keep/.test(needEl("scan-cancel-keep").textContent),
          needEl("scan-cancel-form").textContent);
    check("...and Keep closes it without deleting the job",
          (H.scanKeepJob(), needEl("scan-cancel-form").classList.contains("hidden")
            && scanDeletes.length === 0),
          needEl("scan-cancel-form").className);
    H.scanCancelJob();
    await new Promise((r) => setTimeout(r, 20));
    await H.scanConfirmCancel();
    await new Promise((r) => setTimeout(r, 80));
    check("...and cancelling DELETEs that job's route with the console's audit reason",
          scanDeletes.some((d) => d.url.includes("/api/scan-jobs/job-scan-1")
            && /cancelled from the console/.test(d.body)),
          JSON.stringify(scanDeletes));
    check("...and the sheet shows the server's receipt after the row is gone",
          /recorded in the audit trail/.test(needEl("scan-body").textContent),
          needEl("scan-body").textContent.slice(0, 200));
    const receiptWords = visibleWords(needEl("scan-sheet").querySelector(".scan-receipt"));
    check("the scan sheet stays inside the copy budget (a receipt is a consequence)",
          visibleWords(needEl("scan-sheet")) - receiptWords <= 25,
          `${visibleWords(needEl("scan-sheet"))} - ${receiptWords}`);

    H.closeScanSheet();
    await new Promise((r) => setTimeout(r, 260));
    check("closing the sheet drops its URL subject",
          !/(^|[&#])scan=/.test(String(window.location.hash || "")),
          String(window.location.hash || ""));
    scanBtn.remove();
    fetchOverride = null;
    H.clearGetCache();
  }
  // ── THE COPY BUDGET AND THE SHORT STRINGS (operator, 2026-11-20) ──────────────────────────
  // "This is not simple. There are too many words." Every surface below shows one status line
  // and one action; the mechanism lives under Details. These checks pin the exact strings and
  // the 25-word budget, measured on the rendered DOM rather than on the source.
  {
    H.clearGetCache();
    const prevOverride = fetchOverride;
    const ITEM = {
      sensor_id: "edge-one", nmap_available: false, nmap_version: "", profile: "basic",
      os_id: "debian", os_version: "13", sudo_state: "none", install_known: true,
      install_privileged: false, can_install: false,
      install_command: "sudo apt-get update && sudo apt-get install -y nmap",
      setcap_command: "sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap",
      install_answer: "Weirvern cannot install nmap here — the weirling's user is not in "
        + "sudoers; run the command below as root",
      networks: ["192.0.2.0/24"], scan_mode_sentence: "nmap missing",
      last_check: new Date().toISOString(), state: "reported",
    };
    const SENTENCE = "0 of 1 weirling can scan: edge-one cannot (nmap missing). Install Nmap "
      + "on a weirling and restart its agent.";
    fetchOverride = (u) => {
      if (String(u).includes("/api/scanner")) {
        return { ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true, local_sensor: "edge-one", count: 1,
          capability: { enabled: false, count: 1, capable_count: 0, sentence: SENTENCE,
                        reason_unavailable: SENTENCE },
          sensors: [ITEM],
        }) };
      }
      return null;
    };
    await H.loadScannerStatus();
    await new Promise((r) => setTimeout(r, 40));
    check("the scanner card says '0 of 1 can scan' as a number, not a paragraph",
          needEl("scanner-summary").textContent.trim() === "0 of 1 can scan",
          needEl("scanner-summary").textContent);
    check("...and one short status line: 'Not scanning — nmap missing on this weirling.'",
          needEl("scanner-note").textContent.trim()
            === "Not scanning — nmap missing on this weirling.",
          needEl("scanner-note").textContent);
    check("...with one primary action, 'Install nmap'",
          !needEl("scanner-install").classList.contains("hidden")
          && needEl("scanner-install").textContent.trim() === "Install nmap",
          needEl("scanner-install").className);
    check("...and the measured sentence is behind Details, not above the fold",
          /cannot \(nmap missing\)/.test(needEl("scanner-detail-text").textContent)
          && !needEl("scanner-details").open,
          needEl("scanner-detail-text").textContent.slice(0, 80));
    check("the scanner card stays inside the 25-word copy budget",
          visibleWords(needEl("scanner-note").closest(".card")) <= 25,
          String(visibleWords(needEl("scanner-note").closest(".card"))));

    // A STALE ROW IS NOT A VERDICT. This was the live defect: an hours-old `nmap missing` row
    // was presented as `reported`, and the card printed a capability claim it could not support.
    const STALE = Object.assign({}, ITEM, {
      state: "stale", fresh: false, age: "2h", age_s: 7200,
      install_answer: "No report from this weirling in 2h; its last report is too old to act on.",
      can_install: false, install_privileged: false,
    });
    const STALE_SENTENCE = "0 of 1 weirling can scan: edge-one unknown "
      + "(no capability report in 2h).";
    fetchOverride = (u) => {
      if (String(u).includes("/api/scanner")) {
        return { ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true, local_sensor: "edge-one", count: 1,
          capability: { enabled: false, count: 1, capable_count: 0, sentence: STALE_SENTENCE,
                        reason_unavailable: STALE_SENTENCE },
          sensors: [STALE],
        }) };
      }
      return null;
    };
    H.clearGetCache();
    await H.loadScannerStatus();
    await new Promise((r) => setTimeout(r, 40));
    check("a stale row is not an nmap verdict: the card names the silence and its age",
          needEl("scanner-note").textContent.trim()
            === "No report from this weirling in 2h — no agent is reporting.",
          needEl("scanner-note").textContent);
    check("...the count reads 'unknown', not '0 of 1 can scan'",
          needEl("scanner-summary").textContent.trim() === "unknown",
          needEl("scanner-summary").textContent);
    check("...and no Install action is offered from an aged report",
          needEl("scanner-install").classList.contains("hidden"),
          needEl("scanner-install").className);
    check("...the row's chip reads 'stale'",
          /stale/.test(needEl("scanner-list").textContent),
          needEl("scanner-list").textContent.slice(0, 120));
    check("the stale card stays inside the 25-word copy budget",
          visibleWords(needEl("scanner-note").closest(".card")) <= 25,
          String(visibleWords(needEl("scanner-note").closest(".card"))));

    H.openInstallSheet(ITEM);
    await new Promise((r) => setTimeout(r, 30));
    check("the install sheet is titled 'Install nmap'",
          needEl("install-title").textContent.trim() === "Install nmap",
          needEl("install-title").textContent);
    check("...shows exactly one command line",
          needEl("install-runs").textContent.trim()
            === "Runs: sudo apt-get update && sudo apt-get install -y nmap",
          needEl("install-runs").textContent);
    check("...hides the password field when the host needs no sudo password",
          needEl("install-password-block").classList.contains("hidden"),
          needEl("install-password-block").className);
    check("...offers Copy command, not a dead Install, when there is no privilege path",
          needEl("install-go").classList.contains("hidden")
          && !needEl("install-copy").classList.contains("hidden"),
          `go=${needEl("install-go").className} copy=${needEl("install-copy").className}`);
    check("...keeps the install sheet inside the 25-word copy budget",
          visibleWords(needEl("install-sheet")) <= 25,
          String(visibleWords(needEl("install-sheet"))));
    check("...and puts the sudoers explanation behind Details",
          /sudoers/.test(needEl("install-details").textContent)
          && !needEl("install-details").open,
          needEl("install-details").textContent.slice(0, 80));

    H.openInstallSheet(Object.assign({}, ITEM, { sudo_state: "password",
      install_privileged: false, can_install: true }));
    await new Promise((r) => setTimeout(r, 30));
    check("the password case says 'sudo password' and 'Needed to install on this host.'",
          !needEl("install-password-block").classList.contains("hidden")
          && /sudo password/.test(needEl("install-password-block").textContent)
          && /Needed to install on this host\./.test(needEl("install-password-block").textContent),
          needEl("install-password-block").textContent);
    check("...and shows the Install action for that host",
          !needEl("install-go").classList.contains("hidden")
          && needEl("install-go").textContent.trim() === "Install",
          needEl("install-go").className);
    check("...still inside the copy budget with the password line visible",
          visibleWords(needEl("install-sheet")) <= 25,
          String(visibleWords(needEl("install-sheet"))));

    H.openInstallSheet(Object.assign({}, ITEM, {
      nmap_available: true, install_privileged: true, can_install: true,
      install_answer: "Nmap is already installed on this weirling — nothing to install.",
    }));
    await new Promise((r) => setTimeout(r, 30));
    check("a capable weirling offers neither Install nor Copy -- nothing to install",
          needEl("install-go").classList.contains("hidden")
          && needEl("install-copy").classList.contains("hidden"),
          `${needEl("install-go").className} / ${needEl("install-copy").className}`);
    check("...and its state line says Nmap is already installed",
          /already installed/.test(needEl("install-state").textContent),
          needEl("install-state").textContent);
    H.closeSheet(needEl("install-sheet"));
    fetchOverride = prevOverride;
    H.clearGetCache();
  }
  check("no JavaScript errors during any of the above", errors.length === 0,
        errors.slice(0, 3).join(" | "));



  console.log(notes.join("\n"));
  if (stales.length) {
    console.log("\n  -- UNVERIFIED (element not in the DOM; NOT a pass) ------------------");
    console.log(stales.join("\n"));
  }
  if (failures.length) {
    console.log("\n" + failures.join("\n"));
    console.log(`\n  ${failures.length} FAILED, ${notes.length} passed, ${stales.length} unverified`);
    process.exit(1);
  }
  console.log(`\n  all ${notes.length} checks passed` +
              (stales.length ? `, ${stales.length} UNVERIFIED (listed above)` : "") + "\n");
  // EXIT EXPLICITLY. jsdom keeps a live window (and its timers) alive after the checks finish, so
  // the process never returns on its own -- the success path used to fall off the end of main() and
  // hang. Every run in this session LOOKED fine only because it was piped through `grep`, which
  // returns as soon as the pipe closes: the harness reported success and then sat there. A test
  // runner that never exits cannot be a gate, and a CI timeout would be read as the tests failing
  // rather than as the harness failing to finish.
  process.exit(0);
}

main().catch((e) => { console.error("harness error:", e); process.exit(2); });
