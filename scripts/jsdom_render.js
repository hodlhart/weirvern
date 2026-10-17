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
function check(label, ok, detail) {
  if (ok) notes.push(`  PASS  ${label}`);
  else failures.push(`  FAIL  ${label}${detail ? " -- " + detail : ""}`);
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

  // Load the three scripts in the SAME ORDER index.html declares, reading them from disk so
  // this tests the shipping files rather than a copy.
  const order = [];
  doc.querySelectorAll("script[src]").forEach((s) => order.push(s.getAttribute("src")));
  check("index.html loads the scripts in the required order",
        JSON.stringify(order) === JSON.stringify(["/app.js", "/soc.js", "/assets.js", "/sluice.js",
                                                 "/weirlings.js", "/discover.js",
                                                 "/dnsview.js", "/blocked.js", "/palette.js"]),
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
                   toggleTracked, loadZeekLog, loadFlowDetail, openHost,
                     showView, loadSettings, loadHealthDeep,
                     STAGE, planStage, applyStage, discardStage, setToken, getToken, stageChange,
                     syncURL, applyURLState, AN_FILTERS, M_FILTERS, ID_FILTERS, toggleAllHelp,
                     openHelpPanel, firstrunShow, anClearAllFilters, refreshAll,
                     loadModels, loadWeirlings, loadBlocked,
                     runSonar, stageSonarRecommendations, renderSonarNote, SONAR_STATE,
                     runSiphonTest, renderTestNote,
                     loadZeek, loadNetflow, loadAnomalies, postReview, reviewCell,
                     loadHost, loadEvidence, loadAudit, loadDetectors,
                     registryHighlight, sluiceHighlightRule,
                   NF_FILTERS, nfSetFilter, nfRemoveChip,
                   trApply, trHours, TIME_RANGE,
                   loadDiscover, dcClear, discoverDrill,
                   loadDns, dnClear, dnApply, loadBlocked,
                   chartFrame, svgEl, fmtBytes, el, renderStaleness, renderPager, showEdgeDetail, showNodeDetail, renderNearMisses, renderAlertAudit, settingControl, renderScoreDistribution, ALERTS_STATE, ALERTS_PAGE_SIZE,
                   AUTH, loadSession, doLogin, doLogout, loadUsers, boot, bootAuthed, showGate,
                   wrapTables, wireInfoButtons,
                   refreshChrome, getSession, setSession, createUser, setRole, changePassword,
                   loadIdentity, showIdentityDetail,
                   loadRetrain, retrainAction,
                   loadSluice, wireSluice, renderSluicePolicies, sluiceDuration, loadBlockingControls,
                   loadWeirlings, renderWeirlings, openWeirling, wireWeirlings, wlAge,
                   paletteOpen, paletteClose, paletteRun, paletteMaxToggle, paletteGlobalKey,
                   setCrumbs, clearCrumbs, closeWeirling, sparkSvg, statCells,
                   HOST_RETURN, get CURRENT_VIEW() { return CURRENT_VIEW; },
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
                    "pushover_enabled", "sluice_auto_score"],
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
      proposals.push({ key, current: "", proposed: String(changes[key]),
                       restarts: meta.restarts, blast: meta.blast, warning: meta.warning });
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
      detected_by_models: "Isolation Forest, DBSCAN", model_agreement: 0.7,
      isolation_forest_score: 0.9, gradient_boosting_score: 0.4, dbscan_score: 0.8,
      baseline_score: 0.2, primary_deviation_feature: "unique_dst_ports",
      primary_deviation_zscore: 5.2, deviation_magnitude: 3.1,
      feature_contributions: { unique_dst_ports: { z: 5.2 }, total_bytes: { z: 1.1 } },
      owner: "ops", matched_rule: "IsolationForest scored this window above the strong-signal floor",
      baseline_comparison: "unique_dst_ports is 5.2 sigma above this host's baseline",
      review_state: "", review_note: "", reviewed_at: null, watched: true },
    { detected_at: "2026-01-02T08:00:00", window_start: "2026-01-02T07:55:00",
      window_end: "2026-01-02T08:00:00", src_addr: "192.0.2.40", hostname: "vault",
      anomaly_score: 0.72, confidence: 0.6, severity: "medium",
      detected_by_models: "Adaptive Baseline", model_agreement: 0.5,
      isolation_forest_score: 0.4, gradient_boosting_score: 0.3, dbscan_score: 0.2,
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
      detected_by_models: "Isolation Forest, Gradient Boosting, DBSCAN", model_agreement: 0.6,
      isolation_forest_score: 0.8, gradient_boosting_score: 0.6, dbscan_score: 0.7,
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
    { sensor: "lab-west", state: "degraded", iface: "eth1", rules_active: 0, rules_total: 3,
      packets_blocked: 0, bytes_blocked: 0, age_s: 5400, local: false, stale: true,
      enforcement: "", detail: "no verified path" },
  ],
  rules: [
    // THE SAME STORE FEEDS BOTH TABS (issue #15): the Blocked payload's live sets are built from
    // this same rule table (soc.py reads one store), so these two carry the ids the
    // BLOCKED_PAYLOAD lists as a block and an alert -- exactly as a live deployment does. Without
    // them the fixtures would encode the bug as normal: a live rule that can never be found.
    { rule_id: "r1", describes: "domain ads.example.com", src_cidr: "", dst_cidr: "",
      protocol: "", dst_port: 0, direction: "forward", live: true, revoked: false,
      domain: "ads.example.com", origin: "manual", severity: "", created_by: "admin",
      origin_ref: "", reason: "", expires_at: "2026-10-16T07:00:00Z", expires_in_s: 1800 },
    { rule_id: "r2", describes: "domain track.example.net (alert)", src_cidr: "", dst_cidr: "",
      protocol: "", dst_port: 0, direction: "forward", live: true, revoked: false,
      domain: "track.example.net", origin: "manual", severity: "", created_by: "admin",
      origin_ref: "", reason: "", expires_at: "", expires_in_s: null },
    { rule_id: "r-live-1", describes: "from 198.51.100.7/32", src_cidr: "198.51.100.7/32",
      dst_cidr: "", protocol: "", dst_port: 0, direction: "forward", live: true, revoked: false,
      origin: "manual", severity: "", created_by: "admin", origin_ref: "",
      reason: "scanner on the lab segment", expires_at: "", expires_in_s: 1800 },
    { rule_id: "r-live-2", describes: "from 198.51.100.9/32 tcp/22", src_cidr: "198.51.100.9/32",
      dst_cidr: "", protocol: "tcp", dst_port: 22, direction: "forward", live: true, revoked: false,
      origin: "detection", severity: "high", created_by: "detection", origin_ref: "w-123",
      reason: "detection: severity high at confidence 0.91", expires_at: "", expires_in_s: 900 },
    // UNTIL REVOKED, with no reason recorded: the two states an operator can now create on
    // purpose (duration 0, reason left blank). A stub without them cannot show that either
    // renders as something an analyst can read.
    { rule_id: "r-indef", describes: "from 203.0.113.9/32", src_cidr: "203.0.113.9/32",
      dst_cidr: "", protocol: "", dst_port: 0, direction: "forward", live: true, revoked: false,
      origin: "manual", severity: "", created_by: "admin", origin_ref: "",
      reason: "", expires_at: "", expires_in_s: null },
    { rule_id: "r-lapsed", describes: "from 203.0.113.5/32", src_cidr: "203.0.113.5/32",
      dst_cidr: "", protocol: "", dst_port: 0, direction: "forward", live: false, revoked: false,
      origin: "manual", severity: "", created_by: "admin", origin_ref: "",
      reason: "temporary block that expired", expires_at: "2026-01-01T00:00:00Z",
      expires_in_s: -3600 },
    { rule_id: "r-revoked", describes: "from 203.0.113.6/32", src_cidr: "203.0.113.6/32",
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
        { name: "DBSCAN", trained: false, sample_count: 0 },
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
                            key: k, value: String(v), ok: true, error: "" })) }
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
                    ? { ok: true, rule_id: "r-filed-1", describes: "from 198.51.100.44/32",
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
  summary: { total: 6, registered: 5, problems: 4, alive: 1, stale: 1, never_seen: 1,
             unregistered: 1, disabled: 1 },
  sensors: [
    {
      sensor_id: "edge-alive", state: "alive", is_problem: false,
      address: "198.51.100.7", segment: "third floor", reported_segment: "third floor",
      expected_mode: "loch", reported_mode: "loch", enabled: true, registered: true,
      local: true,
      plan: { mode: "", iface: "", segment: "", addr: "", gateway: "", targets: "" },
      age_s: 4.0, last_seen: "2026-09-23T12:00:00+00:00",
      interfaces: ["eth1", "eth2"],
      capture_loss_pct: 0.0, packets_recv: 900000, packets_dropped: 0, hosts: 12,
      note: "ops owns this one", stale_after_s: 45,
      findings: ["reporting normally, last heard 4s ago."],
    },
    {
      sensor_id: "edge-stopped", state: "stale", is_problem: true,
      plan: { mode: "", iface: "", segment: "", addr: "", gateway: "", targets: "" },
      address: "", segment: "second floor", reported_segment: "",
      expected_mode: "loch", reported_mode: "loch", enabled: true, registered: true,
      age_s: 900.0, last_seen: "2026-09-23T11:45:00+00:00",
      capture_loss_pct: null, packets_recv: null, packets_dropped: null, hosts: 0,
      note: "", stale_after_s: 45,
      interfaces: ["eth0"],
      findings: ["last reported 900s ago, past the 45s freshness window, so it has stopped. It ran "
        + "and then stopped, which is different from never starting: look for why it died rather "
        + "than why it never came up.",
        "no capture-loss measurement, so packet loss is unknown rather than zero."],
    },
    {
      sensor_id: "edge-promised", state: "never_seen", is_problem: true,
      plan: { mode: "siphon", iface: "eth2", segment: "198.51.100.0/24", addr: "", gateway: "198.51.100.1", targets: "*" },
      address: "198.51.100.9", segment: "fourth floor IDF", reported_segment: "",
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
  const DISCOVER_PAYLOAD = {
    available: true, reason: "", total: 42, limit: 100, offset: 0, bucket_s: 60,
    rows: [
      { timestamp: "2026-10-16 06:00:00", sensor: "127.0.0.1", weirling: "weirvern",
        src_addr: "198.51.100.20",
        src_port: 4444, dst_addr: "198.51.100.10", dst_port: 443, proto: 6, proto_label: "tcp",
        bytes: 1234, packets: 12, tcp_flags: 0, ip_ttl: 64, next_hop: "", src_as: 0, dst_as: 0 },
      { timestamp: "2026-10-16 06:01:00", sensor: "127.0.0.1", weirling: "weirvern",
        src_addr: "198.51.100.20",
        src_port: 4445, dst_addr: "198.51.100.10", dst_port: 53, proto: 17, proto_label: "udp",
        bytes: 300, packets: 4, tcp_flags: 0, ip_ttl: 64, next_hop: "", src_as: 0, dst_as: 0 },
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
      { rule_id: "r1", describes: "domain ads.example.com (2 address(es) resolved)",
        mode: "block", domain: "ads.example.com", origin: "manual", severity: "",
        expires_at: "2026-10-16 07:00:00", resolved: ["203.0.113.7", "203.0.113.8"],
        resolved_count: 2, resolved_error: false },
    ],
    alerts: [
      { rule_id: "r2", describes: "domain track.example.net (alert)",
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
    tables: { available: true, points: [] },
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
    ["/api/zeek", ZEEK_PAYLOAD],
    ["/api/session", SESSION_STUB],
    ["/api/users", USERS_PAYLOAD],
    ["/api/identity", IDENTITY_PAYLOAD],
    ["/api/sluice", SLUICE_PAYLOAD],
    ["/api/fingerprints", FP_PAYLOAD],
    ["/api/models/retrain", RETRAIN_PAYLOAD],
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
      ],
      counts: { silent_sensor: 1, expired_rule: 1, stuck_rule: 1, unowned_detector: 1 },
      errors: {} })],
    ["/api/detectors", () => ({ available: true, reason: "", detectors: [
      { name: "Isolation Forest", owner: "ops", runbook: "read the evidence first",
        rule: "IsolationForest scored this window above the strong-signal floor",
        loud: true, known: true, fired: 3, acted: 1 },
      { name: "DBSCAN", owner: "ops", runbook: "check first-seen before acting",
        rule: "DBSCAN found the window outside every dense behavioural cluster",
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
      return { rows: ANOMALIES_STATE.filter(
                 (r) => (r.anomaly_score || 0) >= minF
                        && (!String(u).includes("unreviewed=1") || (r.unreviewed_n || 0) > 0)),
               discipline: { available: true, reason: "", fired: 4, acted: 1,
                             by_state: { ack: 1 } },
               severity_counts: { available: true, reason: "",
                                 counts: [{ severity: "high", count: 1 },
                                          { severity: "medium", count: 1 }] } };
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
  // BARE `openHost(...)` calls in the page resolve the GLOBAL PROPERTY, not the __H export:
  // restoring only H.openHost left the spy armed for the entire run (measured: every later
  // host drill silently no-opped while its check, asserting only the view, kept passing).
  window.openHost = realOpenHost;

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
        doc.querySelectorAll("#nw-selected .chip").length === 2,
        `${doc.querySelectorAll("#nw-selected .chip").length} chips`);
  check("a chip removes its host when clicked",
        (() => {
          doc.querySelector("#nw-selected .chip")
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
  const dTitle = doc.getElementById("nw-detail-title").textContent;
  check("clicking an edge says it is showing one connection",
        dTitle.includes("one connection"), dTitle);
  check("the edge detail names the SOURCE",
        doc.getElementById("nw-detail").textContent.includes("203.0.113.42"),
        doc.getElementById("nw-detail").textContent.slice(0, 80));
  check("the edge detail names the DESTINATION",
        doc.getElementById("nw-detail").textContent.includes("203.0.113.1"),
        doc.getElementById("nw-detail").textContent.slice(0, 80));
  check("the source and destination are LABELLED, not just listed",
        doc.getElementById("nw-detail").textContent.includes("source") &&
        doc.getElementById("nw-detail").textContent.includes("destination"));
  check("the edge detail shows the ports",
        doc.getElementById("nw-detail").textContent.includes("443"));
  check("the name is shown ALONGSIDE the address, never instead of it",
        doc.getElementById("nw-detail").textContent.includes("workstation.lan") &&
        doc.getElementById("nw-detail").textContent.includes("203.0.113.42"));
  check("the edge detail renders the arrow between the two sides",
        !!doc.querySelector("#nw-detail .pair-arrow"));

  // Click a NODE -> everything that host talked to, direction separated.
  H.showNodeDetail(GRAPH_PAYLOAD.nodes[0]);
  check("clicking a node lists its conversations",
        doc.querySelectorAll("#nw-detail-table tbody tr").length >= 2,
        `${doc.querySelectorAll("#nw-detail-table tbody tr").length} rows`);
  check("the node detail separates outbound from inbound",
        doc.getElementById("nw-detail-table").textContent.includes("outbound"),
        doc.getElementById("nw-detail-table").textContent.slice(0, 80));
  check("the node detail offers tracking as an explicit ACTION",
        doc.getElementById("nw-detail").textContent.includes("track only this host"));
  check("clicking an edge and clicking a node show DIFFERENT panels",
        doc.getElementById("nw-detail-title").textContent.includes("workstation") ||
        doc.getElementById("nw-detail-title").textContent.includes("192.0.2.10"),
        doc.getElementById("nw-detail-title").textContent);

  // And the node's own click handler must open the panel, not silently toggle tracking.
  H.ASSETS_STATE.tracked = [];
  H.renderNetwork();
  doc.querySelector("#nw-graph g.node").dispatchEvent(
    new window.MouseEvent("click", { bubbles: true }));
  check("a real click on a node opens the detail panel",
        doc.getElementById("nw-detail-title").textContent.length > 0 &&
        doc.getElementById("nw-detail-title").textContent !== "click a line or a dot",
        doc.getElementById("nw-detail-title").textContent);
  check("a real click on a node does NOT silently change the tracked set",
        H.ASSETS_STATE.tracked.length === 0,
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
        doc.getElementById("nw-graph").textContent.includes("flows filter is hiding") &&
        doc.getElementById("nw-caption").textContent.includes("below the flows filter") &&
        !doc.getElementById("nw-caption").textContent.includes("was recorded") &&
        !doc.getElementById("nw-graph").textContent.includes("was recorded"),
        `caption: ${doc.getElementById("nw-caption").textContent.slice(0, 90)} | ` +
        `graph: ${doc.getElementById("nw-graph").textContent.slice(0, 90)}`);
  H.ASSETS_STATE.minEdges = 1;

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
        doc.getElementById("nf-detail").textContent.includes("flow drill-down failed"),
        doc.getElementById("nf-detail").textContent.slice(0, 90));

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
  H.nfRemoveChip(0);
  for (let i = 0; i < 50 && flowReqs() === n0; i++) {
    await new Promise((r) => setTimeout(r, 20));
  }
  const reqAfterRemoval = FLOW_REQS[FLOW_REQS.length - 1] || "";
  check("removing the chip re-requests the drill WITHOUT the source",
        flowReqs() > n0 && !/[?&]src=/.test(reqAfterRemoval), reqAfterRemoval);
  // A chip the drill cannot express is named in the note, never silently dropped.
  H.NF_FILTERS.push({ field: "client", value: "198.51.100.9", label: "198.51.100.9" });
  await H.loadFlowDetail(H.ASSETS_STATE.detailParams);
  await new Promise((r) => setTimeout(r, 80));
  check("a chip the table cannot apply is NAMED in its heading",
        /cannot apply: client/.test(doc.getElementById("nf-detail-note").textContent),
        doc.getElementById("nf-detail-note").textContent);
  H.NF_FILTERS.pop();
  await H.loadFlowDetail(H.ASSETS_STATE.detailParams);
  await new Promise((r) => setTimeout(r, 80));

  // ── THE ADAPTIVE BASELINE CARD (AB-1) ───────────────────────────────────────────────────────
  {
    H.showView("models");
    await H.loadModels();
    await new Promise((r) => setTimeout(r, 250));
    const mbRows = [...doc.querySelectorAll("#mb-hosts tbody tr")];
    check("the adaptive baseline card lists the hosts it learned", mbRows.length === 3,
          "rows=" + mbRows.length);
    const mbTxt = doc.getElementById("mb-hosts").textContent;
    check("...with learned volumes in human units, not raw floats",
          /9\.2 KB/.test(mbTxt) && /4\.3 KB/.test(mbTxt) && !/9394/.test(mbTxt),
          mbTxt.slice(0, 120));
    check("...and the reverse name beside the address it belongs to",
          /host\.example/.test(mbTxt) && /198\.51\.100\.5/.test(mbTxt), mbTxt.slice(0, 80));
    check("...and the freshness line reads the server's own age",
          /Newest snapshot 4 min ago/.test(doc.getElementById("mb-note").textContent),
          doc.getElementById("mb-note").textContent);
    check("the summary counts the behavioural and fingerprint baselines",
          /3 hosts carry a learned baseline/.test(doc.getElementById("mb-summary").textContent)
          && /2 with behavioural \(Zeek\) baselines/.test(doc.getElementById("mb-summary").textContent)
          && /1 with fingerprint history/.test(doc.getElementById("mb-summary").textContent),
          doc.getElementById("mb-summary").textContent);
    check("what it flagged is a count, stated plainly",
          /Flagged 4 rows in the last 24h/.test(doc.getElementById("mb-fired").textContent),
          doc.getElementById("mb-fired").textContent);
    const mbFirst = mbRows[0] ? mbRows[0].querySelector("td") : null;
    if (mbFirst) {
      mbFirst.click();
      await new Promise((r) => setTimeout(r, 220));
      check("a baselined host opens its host view in one click",
            doc.getElementById("view-host").classList.contains("active"));
      H.showView("models");
      await new Promise((r) => setTimeout(r, 120));
    }
    // A store that cannot be read says so -- never "no baselines", which would read as a
    // trainer that died.
    fetchOverride = (u) => (String(u).includes("/api/baselines")
      ? Promise.resolve({ ok: false, status: 500, statusText: "Boom", json: async () => ({}) })
      : null);
    await H.loadModels();
    await new Promise((r) => setTimeout(r, 220));
    check("a baseline store that cannot be read says so, never 'no baselines'",
          /Unavailable/.test(doc.getElementById("mb-note").textContent),
          doc.getElementById("mb-note").textContent);
    fetchOverride = null;
    await H.loadModels();
    await new Promise((r) => setTimeout(r, 220));
    // Back to the landing view: the load-state capture below reads it and a block that
    // leaves the console somewhere else would break a check that is not about this card.
    H.showView("health");
  }

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

  // ── the near-miss panel (SOC-2) ────────────────────────────────────────────────────────
  // The anomalies list shows what was FLAGGED; this panel exists because "nothing nearly
  // alerted" and "the near-miss table does not exist yet" are different facts, and an
  // empty table renders them identically.
  H.renderNearMisses({
    near_misses_available: true,
    near_misses: [
      { window_start: "2026-01-03T10:00:00", src_addr: "198.51.100.44", score: 0.66,
        threshold: 0.70, reason: "below-threshold", agreement: 0.5,
        models: ["Isolation Forest", "DBSCAN"] },
      { window_start: "2026-01-03T10:05:00", src_addr: "198.51.100.45", score: 0.81,
        threshold: 0.70, reason: "agreement-gate", agreement: 0.2,
        models: ["Gradient Boosting"] },
    ],
  });
  const nearRows = doc.querySelectorAll("#m-near tbody tr");
  check("the near-miss table renders one row per recorded near miss",
        nearRows.length === 2, `rows=${nearRows.length}`);
  check("a below-threshold near miss is labelled as such",
        doc.getElementById("m-near").textContent.includes("below threshold"),
        doc.getElementById("m-near").textContent.slice(0, 140));
  check("a gate-dropped near miss states the gate",
        doc.getElementById("m-near").textContent.includes("agreement gate"),
        "an agreement-gate row rendered without its reason");
  check("the score and the bar it faced are both shown",
        doc.getElementById("m-near").textContent.includes("0.66")
          && doc.getElementById("m-near").textContent.includes("0.70"),
        "score/threshold pair missing from the row");
  check("the panel states what a threshold change would do",
        doc.getElementById("m-near-note").textContent.includes("Raising the threshold"),
        doc.getElementById("m-near-note").textContent.slice(0, 120));

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
    "DBSCAN": [0.95, 0.95, 0.25],
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
    fetchOverride = (u) => (String(u).includes("/api/netflow")
      ? serve({ volume: { available: true, reason: "", points: [] },
                protocols: { available: true, reason: "", points: [] },
                ports: { available: true, reason: "", points: [] },
                spread: { available: true, reason: "", points: [] },
                talkers: { available: false, reason: "the talkers query failed: Timeout",
                           points: [] },
                noise: {}, data_error: null })
      : null);
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
    await H.loadNetflow();
    check("an EMPTY talkers window keeps the quiet copy",
          textOf("nf-talkers").includes("No talkers in this window"),
          textOf("nf-talkers").slice(0, 90));

    // DNS: FAILED carries the reason on the histogram and the table.
    fetchOverride = (u) => (String(u).includes("/api/dns")
      ? serve({ available: false, reason: "cannot reach ClickHouse: OperationalError",
                rows: [], total: 0, histogram: [], facets: {}, data_error: "x" })
      : null);
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
    await H.loadBlocked();
    check("a FAILED blocked read says why instead of inviting a new rule",
          textOf("bl-block-rows").includes("Cannot list these:")
            && textOf("bl-hit-rows").includes("Cannot list these:"),
          `${textOf("bl-block-rows").slice(0, 60)} | ${textOf("bl-hit-rows").slice(0, 60)}`);
    fetchOverride = (u) => (String(u).includes("/api/blocked")
      ? serve({ available: true, reason: "", hits: [], total: 0, blocks: [], alerts: [],
                gate: {}, data_error: null })
      : null);
    await H.loadBlocked();
    check("an EMPTY blocked read keeps the real empty copies",
          textOf("bl-block-rows").includes("No blocking rules")
            && textOf("bl-hit-rows").includes("Nothing recorded in this window"),
          textOf("bl-block-rows").slice(0, 60));
    fetchOverride = null;
  }

  // The two states that must NOT render identically.
  H.renderNearMisses({ near_misses_available: false, near_misses: [],
                       near_misses_reason: "the near-miss table has not been created on this "
                         + "deployment yet (it arrives with the schema job on the version "
                         + "that added it)" });
  check("an unavailable near-miss table names the schema job, not an empty list",
        doc.getElementById("m-near-note").textContent.includes("schema job"),
        doc.getElementById("m-near-note").textContent.slice(0, 120));
  H.renderNearMisses({ near_misses_available: true, near_misses: [] });
  check("an empty near-miss list is distinguishable from an unavailable one",
        doc.getElementById("m-near").textContent.includes("No near misses")
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
  check("Health leads the first group and Settings the last",
        groupOf("health") === "operations" && groupOf("settings") === "console",
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

  const zkSummary = doc.getElementById("zk-summary").textContent;
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

  const zkTimeline = doc.getElementById("zk-timeline");
  check("the timeline drew an svg", !!zkTimeline.querySelector("svg"));
  check("the timeline drew a path per series",
        zkTimeline.querySelectorAll("path").length >= 2,
        `${zkTimeline.querySelectorAll("path").length} paths`);
  check("the timeline legend names the series",
        /conn/.test(zkTimeline.textContent), zkTimeline.textContent.slice(0, 80));

  check("a log that recorded NOTHING in the window is explained, not just zeroed",
        /recorded nothing in this window|widen the window/i.test(doc.getElementById("zk-counts").textContent),
        doc.getElementById("zk-counts").textContent.slice(-160));
  check("an empty-forever log is distinguished from a quiet one",
        /NEVER produced a row/i.test(doc.getElementById("zk-counts").textContent));

  check("the services panel rendered its bars",
        doc.querySelectorAll("#zk-services .bar-row").length === 2);
  check("the dns panel rendered its names",
        doc.querySelectorAll("#zk-dns .bar-row").length === 1);

  // ── operator access and staged writes ──────────────────────────────────────────────────────
  // Everything below drives the SHIPPING functions against the SHIPPING markup and asserts the
  // OUTCOME. The riskiest thing here is a write, so the checks cover what was actually POSTed, not
  // just what rendered.

  check("the operator token field exists and is not readonly",
        !!doc.getElementById("st-token") && !doc.getElementById("st-token").readOnly);
  check("the token field is a password input (a token left on screen is a token leaked)",
        doc.getElementById("st-token").type === "password");
  check("the page states the no-TLS boundary where the operator will read it",
        /no TLS|plain HTTP/i.test(doc.getElementById("st-auth-card").textContent),
        doc.getElementById("st-auth-card").textContent.slice(0, 120));

  // An editable setting renders an INPUT; a secret renders text and a read-only tag.
  // NAVIGATE AND LOAD HERE, in this block. Depending on another section having already done it is
  // the ordering trap that broke the graph checks: that block ran after one which deliberately
  // replaced the state it needed.
  H.showView("settings");
  await H.loadSettings();
  const inputs = [...doc.querySelectorAll("#view-settings .setting-input")];
  const editableKeys = inputs.map((n) => n.dataset.key);
  check("editable settings render as inputs", editableKeys.includes("base_threshold"),
        `inputs: ${editableKeys.join(",")}`);
  check("a SECRET is never editable from the page",
        !editableKeys.includes("clickhouse_password"), `inputs: ${editableKeys.join(",")}`);
  check("a non-editable row says so rather than looking broken",
        /read-only/.test(doc.getElementById("view-settings").textContent));

  // THESE TWO DESCRIBE THE PRE-EDIT STATE, so they are asserted NOW, before anything is staged.
  // They ran after an apply initially, which is how they became flaky assertions about a state the
  // block itself had already changed.
  const applyBtn0 = doc.getElementById("st-stage-apply");
  check("there IS an apply control now (the operator asked for one)", !!applyBtn0);
  check("apply is DISABLED until something is staged", applyBtn0.disabled === true,
        `disabled=${applyBtn0.disabled}`);
  check("the page states that nothing is written on edit",
        /edit a value above to stage one/i.test(doc.getElementById("st-stage-note").textContent),
        doc.getElementById("st-stage-note").textContent);

  // STAGING: an edit must NOT write. This is the single most important assertion here.
  const before = POSTED.length;
  const bt = inputs.find((n) => n.dataset.key === "base_threshold");
  bt.value = "0.5";
  bt.dispatchEvent(new window.Event("input", { bubbles: true }));
  check("editing a setting stages it without writing anything", POSTED.length === before,
        `${POSTED.length - before} request(s) were sent on edit`);
  check("the staged change is listed for review",
        doc.getElementById("st-stage-list").textContent.includes("base_threshold"));
  check("the staged count is stated", /1 staged/.test(doc.getElementById("st-stage-count").textContent));
  check("the header chip states the staged count from every tab",
        /1 staged/.test(doc.getElementById("stage-pill").textContent)
        && !doc.getElementById("stage-pill").classList.contains("hidden"),
        doc.getElementById("stage-pill").textContent);
  check("the staged change is saved to the tab's own storage until applied",
        (window.sessionStorage.getItem("wv-stage") || "").includes("base_threshold"),
        String(window.sessionStorage.getItem("wv-stage")).slice(0, 80));
  doc.getElementById("stage-pill").click();
  await new Promise((r) => setTimeout(r, 40));
  check("clicking the chip lands on the review list without writing anything",
        doc.getElementById("view-settings").classList.contains("active"));
  check("Apply is enabled once something is staged",
        doc.getElementById("st-stage-apply").disabled === false);

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
        /restart/i.test(doc.getElementById("st-stage-list").textContent),
        doc.getElementById("st-stage-list").textContent.slice(0, 160));
  check("each plan row states the value it would replace",
        /\(was /.test(doc.getElementById("st-stage-list").textContent),
        doc.getElementById("st-stage-list").textContent.slice(0, 160));

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
        /saved|restarted|not applied/i.test(doc.getElementById("st-stage-note").textContent),
        doc.getElementById("st-stage-note").textContent.slice(0, 140));
  check("staging is cleared after a successful apply",
        Object.keys(H.STAGE.changes).length === 0);
  check("the chip hides again once the stage is empty",
        doc.getElementById("stage-pill").classList.contains("hidden"));

  // THE RECEIPT: per-item results after an apply.
  check("the receipt names the key and the time it landed",
        /base_threshold/.test(doc.getElementById("st-apply-results").textContent)
        && /applied/.test(doc.getElementById("st-apply-results").textContent),
        doc.getElementById("st-apply-results").textContent.slice(0, 140));

  // A REFUSED WRITE: the read-back refuses the 0.7 write once -- the receipt must say FAILED
  // with the server's reason and offer the one-click re-apply.
  const bt7 = [...doc.querySelectorAll("#view-settings .setting-input")]
    .find((n) => n.dataset.key === "base_threshold");
  bt7.value = "0.7";
  bt7.dispatchEvent(new window.Event("input", { bubbles: true }));
  await H.applyStage();
  check("a failed apply says which item failed and why",
        /FAILED/.test(doc.getElementById("st-apply-results").textContent)
        && /did not land/.test(doc.getElementById("st-apply-results").textContent),
        doc.getElementById("st-apply-results").textContent.slice(0, 180));
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
          /applied/.test(doc.getElementById("st-apply-results").textContent)
          && !/FAILED/.test(doc.getElementById("st-apply-results").textContent),
          doc.getElementById("st-apply-results").textContent.slice(0, 140));
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
        /ARP/.test(doc.getElementById("st-sonar-help-text").textContent),
        (doc.getElementById("st-sonar-help-text") || {}).textContent);
  check("the Sonar explanation starts hidden",
        doc.getElementById("st-sonar-help-text").classList.contains("hidden"));
  const sonarBefore = POSTED.filter((r) => r.url.includes("/api/settings/sonar")).length;
  H.discardStage();
  await H.runSonar();
  check("Sonar POSTs to the sonar route",
        POSTED.filter((r) => r.url.includes("/api/settings/sonar")).length === sonarBefore + 1,
        POSTED.map((r) => r.url).join(","));
  // A standalone survey surveys and REPORTS; it stages nothing by itself (the mode selector's
  // enable is what stages, from the same result).
  check("a standalone survey stages nothing",
        Object.keys(H.STAGE.changes).length === 0, JSON.stringify(H.STAGE.changes));
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
        /198\.51\.100\.0\/24/.test(doc.getElementById("st-sonar-note").textContent)
        && /gateway/i.test(doc.getElementById("st-sonar-note").textContent),
        doc.getElementById("st-sonar-note").textContent.slice(0, 200));
  check("the staged list shows the Sonar-sourced keys",
        doc.getElementById("st-stage-list").textContent.includes("intercept_segment"),
        doc.getElementById("st-stage-list").textContent.slice(0, 200));
  H.discardStage();
  check("discarding Sonar's recommendations clears them like any other staged change",
        Object.keys(H.STAGE.changes).length === 0);

  // ── SONAR'S COUNTS AND THE PLAN'S REQUIREMENTS (2026-10-17) ──────────────────────────────
  // The live report: "Sonar doesn't work". Measured live: 5 recommendations, 2 staged, and the
  // panel read "Staged 5" over a two-row list -- the note claimed changes the dedupe had
  // (correctly) refused to stage. It now counts what actually staged and says so when nothing did.
  {
    H.discardStage();
    const note = doc.getElementById("st-sonar-note");
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
        && /30 seconds/.test(doc.getElementById("st-test-help-text").textContent),
        (doc.getElementById("st-test-help-text") || {}).textContent);
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
        /set back to loch/i.test(doc.getElementById("st-test-note").textContent),
        doc.getElementById("st-test-note").textContent.slice(0, 180));
  check("the test result states what was observed",
        /observed live/i.test(doc.getElementById("st-test-note").textContent)
        || /No intercept evidence/.test(doc.getElementById("st-test-note").textContent),
        doc.getElementById("st-test-note").textContent.slice(0, 180));

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
        /not applied/i.test(doc.getElementById("st-stage-note").textContent),
        doc.getElementById("st-stage-note").textContent.slice(0, 140));
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
  const healthSectionActive = doc.getElementById("view-health").classList.contains("active");
  check("the active nav tab and the visible section agree",
        healthTabActive === healthSectionActive,
        `tab=${healthTabActive} section=${healthSectionActive}`);
  check("the Settings tab is in the nav", navTabs.includes("settings"));
  check("the Overview SECTION is gone from the DOM",
        doc.getElementById("view-overview") === null);
  check("sensor state and the health checks live on the Health tab now",
        !!doc.getElementById("hp-sensor") && !!doc.getElementById("hp-checks"));
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
      const summary = doc.getElementById("hp-summary").textContent;
      check("the summary counts only MEASURABLE checks (2, not 3)",
            /of 2 checks FAILING/.test(summary),
            summary.slice(0, 140));
      check("the summary states how many were not applicable",
            /not applicable/.test(summary),
            summary.slice(0, 140));
      const pill = doc.getElementById("health-pill").textContent;
      check("the pill excludes the not-applicable probe from its ratio",
            /1\/2 checks passing/.test(pill),
            pill.slice(0, 140));
      // ── CLICK IT (the operator, 2026-10-16): the ratio must open the per-check list ──────────
      {
        const pid = doc.getElementById("pill-pop");
        doc.getElementById("health-pill").click();
        await new Promise((r) => setTimeout(r, 30));
        const lines = pid ? pid.querySelectorAll(".pill-line").length : 0;
        check("clicking the health pill lists every check", !!pid && !pid.hidden && lines >= 2,
              "lines=" + lines + " hidden=" + (pid ? pid.hidden : "?"));
        check("with its states, not-applicable included",
              !!pid && /PASS/.test(pid.textContent) && /N\/A/.test(pid.textContent),
              pid ? pid.textContent.slice(0, 100) : "");
        check("and a way into the full health view", !!pid && /health view/i.test(pid.textContent), "");
        doc.getElementById("health-pill").click();
        await new Promise((r) => setTimeout(r, 30));
        check("clicking the pill again closes it", !!pid && pid.hidden, "still open");
      }
    }

  check("the alert audit panels are on the Health tab (SOC-8)",
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
        doc.getElementById("hp-alerts-note").textContent.includes("3 suppressed"),
        doc.getElementById("hp-alerts-note").textContent.slice(0, 140));
  check("a log-only outcome is labelled as not-configured, not suppressed",
        doc.getElementById("hp-alerts-reasons").textContent.includes("log-only (not configured)"),
        doc.getElementById("hp-alerts-reasons").textContent.slice(0, 160));
  check("a cooldown outcome is labelled suppressed",
        doc.getElementById("hp-alerts-reasons").textContent.includes("cooldown (suppressed)"),
        "a withheld alert rendered without saying it was withheld");
  check("the recent list renders the decision rows",
        doc.querySelectorAll("#hp-alerts-recent tbody tr").length === 1,
        `rows=${doc.querySelectorAll("#hp-alerts-recent tbody tr").length}`);

  H.renderAlertAudit({ available: false, reason: "alert audit query failed: RuntimeError",
                       by_reason: [], recent: [], suppressed: 0 });
  check("an unavailable audit names the failure, not an empty list",
        doc.getElementById("hp-alerts-note").textContent.includes("Alert audit unavailable"),
        doc.getElementById("hp-alerts-note").textContent.slice(0, 140));
  H.renderAlertAudit({ available: true, by_reason: [], recent: [], suppressed: 0 });
  check("an empty audit says nothing fired at all",
        doc.getElementById("hp-alerts-note").textContent.includes("nothing fired"),
        doc.getElementById("hp-alerts-note").textContent.slice(0, 140));

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
        doc.getElementById("hp-alerts-reasons-pager").textContent.includes("1\u201315 of 18"),
        doc.getElementById("hp-alerts-reasons-pager").textContent.slice(0, 120));
  const firstPageRows = doc.querySelectorAll("#hp-alerts-recent tbody tr").length;
  check("the event table shows only the first 15 rows",
        firstPageRows === 15, `rows=${firstPageRows} (expected 15 of 24)`);
  check("the pager reports the real total and page count",
        doc.getElementById("hp-alerts-recent-pager").textContent.includes("1\u201315 of 24"),
        doc.getElementById("hp-alerts-recent-pager").textContent.slice(0, 120));
  check("a host with a resolved name shows the name AND the address",
        doc.getElementById("hp-alerts-recent").textContent.includes("host-a.example")
          && doc.getElementById("hp-alerts-recent").textContent.includes("198.51.100.1"),
        "the name replaced the address, or was not shown at all");
  check("the message a decision was about is rendered, not just that it happened",
        doc.getElementById("hp-alerts-recent").textContent.includes("sustained scan traffic"),
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
        doc.getElementById("hp-alerts-recent-pager").textContent.includes("16\u201324 of 24"),
        doc.getElementById("hp-alerts-recent-pager").textContent.slice(0, 120));

  // A TRUNCATED fetch must say so: a full page of 15 with no note reads as "this is everything".
  H.renderAlertAudit({
    available: true, suppressed: 0, by_reason: [],
    recent: manyEvents.slice(0, 15), total: 4000, truncated: true, names: {},
  });
  check("a capped list states how many it is showing out of how many exist",
        doc.getElementById("hp-alerts-note").textContent.includes("newest 15 of 4000"),
        doc.getElementById("hp-alerts-note").textContent.slice(0, 200));

  // An UNAVAILABLE audit must not leave the previous payload's pager on screen: a range line
  // above an unavailable table describes a window that is no longer there.
  H.renderAlertAudit({ available: false, reason: "boom", by_reason: [], recent: [],
                       suppressed: 0, total: 0, truncated: false, names: {} });
  check("an unavailable audit clears the pagers rather than leaving a stale range",
        doc.getElementById("hp-alerts-recent-pager").textContent.trim() === "",
        `pager=${doc.getElementById("hp-alerts-recent-pager").textContent}`);

  // ── the Settings tab ───────────────────────────────────────────────────────────────────────
  // Now navigate to Settings the way a user would.
  H.showView("settings");
  await H.loadSettings();

  const stSummary = doc.getElementById("st-summary");
  check("the settings view states how many settings are in effect",
        /\d+ settings in effect/.test(stSummary.textContent));

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

  const shown = doc.getElementById("clickhouse_host");
  check("an ordinary setting shows its value",
        [...doc.querySelectorAll(".setting-val")].some(n => n.textContent === "clickhouse"));

  // THE SECURITY CHECK. The sentinel is what a real credential would be; it must not be here.
  const panelText = doc.getElementById("view-settings").textContent;
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
        /read-only|cannot change/i.test(doc.getElementById("view-settings").textContent));
  check("the settings view says where the settings CAN be changed",
        doc.getElementById("view-settings").textContent.includes("weirvern config set"));
  // The page used to have no write control at all. It now has one, because an operator asked for
  // it -- so the assertion changes to the property that still matters: the APPLY control must be
  // DISABLED until something is staged, so a stray click cannot write the cluster configuration.
  const applyBtn = doc.getElementById("st-stage-apply");
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
  const wlModeSel = doc.getElementById("wl-mode-select");
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
  await H.loadAnomalies();

  const anomRows = doc.querySelectorAll("#anomalies-table tbody tr");
  check("the anomalies table renders a row per payload entry", anomRows.length === 3,
        `${anomRows.length} rows`);

  const chips = [...doc.querySelectorAll("#anomalies-table .review-chip")];
  check("every anomaly row carries a review chip", chips.length === anomRows.length,
        `${chips.length} chips for ${anomRows.length} rows`);
  check("an UNREVIEWED row says so", chips.some((c) => c.textContent === "unreviewed"));
  check("a REVIEWED row shows its state, not 'unreviewed'",
        chips.some((c) => c.textContent === "ack"), chips.map((c) => c.textContent).join(", "));

  const actBtns = [...doc.querySelectorAll("#anomalies-table .review-act")];
  check("the row offers the dispositions that are not its current state",
        actBtns.length > 0, `${actBtns.length} action buttons`);
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
            doc.querySelector("#view-evidence").classList.contains("active"));
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
  const chip1 = gRow1.querySelector(".review-chip");
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
  doc.getElementById("f-unreviewed").checked = true;
  await H.loadAnomalies();
  const filteredRows = [...doc.querySelectorAll("#anomalies-table tbody tr")];
  check("under unreviewed-only the row stays -- chip, tooltip and filter agree",
        filteredRows.length === 1 && !!findGroupRow(),
        `${filteredRows.length} row(s)`);

  // 3) each unfolded occurrence is dispositioned ON ITS OWN.
  doc.getElementById("f-unreviewed").checked = false;
  await H.loadAnomalies();
  let occ = await openOccurrences(findGroupRow());
  check("the unfold lists every occurrence with its own controls",
        occ.length === 3 && occ.every((o) => o.querySelector(".review-chip")
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
        occ[0].querySelector(".review-chip").textContent === "resolved");

  // 4) finish the row: with every occurrence dispositioned, all three surfaces say "done".
  occ[1].querySelector(".review-act[title*='as ack']").click();
  await new Promise((r) => setTimeout(r, 120));
  const gRow3 = findGroupRow();
  check("a fully dispositioned group drops the remainder chip",
        gRow3 && !gRow3.querySelector(".review-remain")
        && gRow3.querySelector(".review-chip").textContent === "ack");
  check("its tooltip no longer claims any unreviewed",
        gRow3.querySelector("td.num").getAttribute("title")
        === "3 occurrence(s) \u2014 click to list them");
  doc.getElementById("f-unreviewed").checked = true;
  await H.loadAnomalies();
  check("and the unreviewed-only filter hides it -- the same story, three times",
        !findGroupRow(),
        doc.querySelector("#anomalies-table tbody").textContent.slice(0, 90));
  doc.getElementById("f-unreviewed").checked = false;
  await H.loadAnomalies();

  // 5) the unavailable path is unchanged: a distinct label, no controls.
  const midWin = ANOMALIES_STATE.find((r) => r.src_addr === "198.51.100.77").windows[1];
  const midState = midWin.review_state;
  midWin.review_state = "unavailable";
  anRecompute();
  await H.loadAnomalies();
  occ = await openOccurrences(findGroupRow());
  check("an unavailable occurrence keeps its distinct label",
        occ[1].querySelector(".review-chip").textContent === "review unavailable",
        occ[1].querySelector(".review-chip").textContent);
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
          doc.getElementById("view-anomalies").classList.contains("active"));
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
        const scopeSel = gf.querySelector("select");
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
    const unrevBox = doc.getElementById("f-unreviewed");
    unrevBox.checked = true;
    unrevBox.dispatchEvent(new window.Event("change", { bubbles: true }));
    await new Promise((r) => setTimeout(r, 250));
    check("a checkbox filter lands in the URL", /an\.unrev=1/.test(window.location.hash),
          window.location.hash.slice(0, 90));
    check("the header carries a Copy-link affordance",
          !!doc.getElementById("copy-link") && /link/i.test(doc.getElementById("copy-link").title));
    const copyBtn = doc.getElementById("copy-link");
    if (copyBtn) {
      copyBtn.click();
      await new Promise((r) => setTimeout(r, 30));
      check("clicking it gives honest feedback and never throws",
            /copied|copy failed/.test(copyBtn.textContent), copyBtn.textContent);
    }
    // THE ROUND TRIP: exactly what opening a shared link does. The checkbox is cleared FIRST,
    // so the restore is observable -- a fixture value left over from the previous check would
    // make any restore look correct.
    unrevBox.checked = false;
    unrevBox.dispatchEvent(new window.Event("change", { bubbles: true }));
    await new Promise((r) => setTimeout(r, 250));
    window.location.hash = "#v=anomalies&an.sev=high&an.unrev=1&tr=6";
    H.applyURLState();
    check("opening a link restores its tab",
          doc.getElementById("view-anomalies").classList.contains("active"));
    check("...its range", Number(H.TIME_RANGE.hours) === 6, String(H.TIME_RANGE.hours));
    check("...its severity filter", H.AN_FILTERS.severity === "high", String(H.AN_FILTERS.severity));
    check("...and its checkbox filter", doc.getElementById("f-unreviewed").checked === true);
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
    const blInput = doc.getElementById("bl-domain");
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
          doc.getElementById("wl-detail-id").textContent === wlSensor,
          doc.getElementById("wl-detail-id").textContent);

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
    const anPanel = doc.getElementById("an-info");
    const helpPill = doc.getElementById("all-help");
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
    const addrBox = doc.getElementById("h-addr");
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
    const minBox = doc.getElementById("f-min-score");
    minBox.value = "99";
    minBox.dispatchEvent(new window.Event("change", { bubbles: true }));
    await new Promise((r) => setTimeout(r, 300));
    const anEmpty = doc.querySelector("#anomalies-table .empty");
    check("an empty queue says why and offers the way back",
          !!anEmpty && /at or above score 99/.test(anEmpty.textContent) &&
            /Clear filters/.test(anEmpty.textContent),
          anEmpty ? anEmpty.textContent.slice(0, 90) : "no empty row at all");
    const clearBtn = anEmpty ? anEmpty.querySelector("button.empty-act") : null;
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
    const wlEmpty = doc.querySelector("#wl-table .empty");
    check("an empty fleet teaches and offers the button",
          !!wlEmpty && /Point a sensor's exporter/.test(wlEmpty.textContent) &&
            /How adding works/.test(wlEmpty.textContent),
          wlEmpty ? wlEmpty.textContent.slice(0, 90) : "no empty fleet row");
    const wlBtn = wlEmpty ? wlEmpty.querySelector("button.empty-act") : null;
    if (wlBtn) {
      wlBtn.click();
      await new Promise((r) => setTimeout(r, 40));
    }
    check("...and its button opens the explainer",
          !doc.getElementById("wl-info").classList.contains("hidden"));
    const frCard = doc.getElementById("firstrun-card");
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
            doc.getElementById("view-settings").classList.contains("active") &&
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
    const styleCss = require("fs").readFileSync(process.env.WEIRVERN_WEB + "/style.css", "utf8");
    check("a heading never runs into its subtitle",
          styleCss.includes("h2 > .muted:not(:empty)::before"),
          "the separator rule is missing");
    check("the range panel names its timezone",
          !!doc.getElementById("tr-tz") && /timezone/i.test(doc.getElementById("tr-tz").textContent),
          doc.getElementById("tr-tz") ? doc.getElementById("tr-tz").textContent : "no tr-tz line");
    H.trApply({ mode: "absolute", from: "2026-10-16 05:00", to: "now" });
    check("an absolute range freezes 'now' into a concrete minute",
          /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/.test(String(H.TIME_RANGE.to)),
          String(H.TIME_RANGE.to));
    check("...and the button says it is frozen",
          /frozen/.test(doc.getElementById("tr-open").textContent),
          doc.getElementById("tr-open").textContent);
    H.trApply({ mode: "relative", hours: 24 });
    await H.refreshAll();
    check("the statusline says when the view last finished updating",
          /updated \d\d:\d\d:\d\d/.test(doc.getElementById("fetched").textContent),
          doc.getElementById("fetched").textContent);
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
    const autoPill = doc.getElementById("auto-toggle");
    check("the auto-refresh pill names its state",
          !!autoPill && /auto 15s/.test(autoPill.textContent));
    if (autoPill) {
      autoPill.click();
      await new Promise((r) => setTimeout(r, 30));
      check("...pausing says so, in the pill and the statusline",
            /paused/.test(autoPill.textContent) && /paused/.test(doc.getElementById("fetched").textContent),
            autoPill.textContent);
      autoPill.click();
      await new Promise((r) => setTimeout(r, 30));
      check("...resuming puts it back", /\blive\b/.test(autoPill.textContent),
            autoPill.textContent);
    }
    check("the title is the name, not an emoji",
          !/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(doc.title) && /Weirvern/.test(doc.title),
          doc.title);
    check("the mark is a vector now",
          doc.querySelector('link[rel="icon"]').getAttribute("href") === "/favicon.svg" &&
          [...doc.querySelectorAll("img.mark")].every((i) => i.getAttribute("src") === "/logo.svg"));
  }

  // ── THE AUTO-BLOCK IS LOUD AND PAUSABLE (BF-3) ──────────────────────────────────────────────
  // The threshold that can stop traffic by itself is off by default, unmistakable when armed,
  // and pausable in one click. The gate-rule behavior itself is pinned by tests/test_sluice.py
  // (derive with auto_score=0 -> no rule; with 0.9 -> a rule reasoned "auto: threshold 0.90").
  {
    const autoRow = SETTINGS_PAYLOAD.groups.detect.find((r) => r.key === "sluice_auto_score");
    const abPill = doc.getElementById("auto-block-pill");
    check("the auto-block pill is absent while the threshold is off",
          !!abPill && abPill.classList.contains("hidden"),
          abPill ? abPill.textContent : "no pill in the markup");
    autoRow.value = "0.9";
    await H.loadBlockingControls();
    await new Promise((r) => setTimeout(r, 120));
    const state = doc.getElementById("sl-bc-auto-state");
    check("an armed auto-block says so, in full, on the controls card",
          !!state && /AUTO-BLOCK IS ON/.test(state.textContent) &&
            /0\.90/.test(state.textContent) && /auto: threshold 0\.90/.test(state.textContent),
          state ? state.textContent.slice(0, 110) : "no state line");
    check("...and the header pill appears with the threshold",
          !abPill.classList.contains("hidden") && /0\.90/.test(abPill.textContent),
          abPill.textContent);
    abPill.click();
    await new Promise((r) => setTimeout(r, 80));
    check("...and clicking that pill lands on the controls",
          doc.getElementById("view-sluice").classList.contains("active"));
    const pause = doc.getElementById("sl-bc-autopause");
    check("a pause control is offered while it is armed",
          !!pause && !pause.classList.contains("hidden"));
    if (pause) {
      pause.click();   // arm the confirm (the house two-stage pattern)
      await new Promise((r) => setTimeout(r, 30));
      const armedText = pause.textContent;
      // The mock does not echo a POST back into the fixture, so the landing alone cannot
      // prove WHAT was posted -- spy the body to pin the value itself.
      const posts = [];
      const origFetch2 = window.fetch;
      window.fetch = (u, o) => {
        if (/settings\/apply/.test(String(u)) && o && o.body) posts.push(String(o.body));
        return origFetch2(u, o);
      };
      autoRow.value = "0";   // the apply lands; the re-read after it sees zero
      pause.click();   // confirm
      await new Promise((r) => setTimeout(r, 250));
      window.fetch = origFetch2;
      // The note is a STATUS line -- the apply's own message is replaced by the re-read
      // moments later, so the pin is on the landing itself, below.
      check("...pausing asks for a confirm first", /Confirm/i.test(armedText), armedText);
      check("...and the pause posts the zero, not a guess",
            posts.some((b) => /SLUICE_AUTO_SCORE/.test(b) && /"0"/.test(b)),
            posts.join(" | ").slice(0, 120));
      check("...the state line reports it off",
            /off/i.test((doc.getElementById("sl-bc-auto-state") || {}).textContent || ""));
      check("...and the header pill is gone",
            abPill.classList.contains("hidden") && abPill.textContent === "");
    }
    await H.loadBlockingControls();   // tidy: a clean re-read at zero
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
    const nsTile = tiles.find((t) => /never seen/.test(t.textContent));
    nsTile.click();
    await new Promise((r) => setTimeout(r, 250));
    const rowsNow = [...doc.querySelectorAll("#wl-table tbody tr")];
    check("...clicking a count filters the worklist to exactly it",
          rowsNow.length >= 1 &&
            rowsNow.every((tr) => tr.classList.contains("wl-state-never_seen")),
          rowsNow.map((t) => t.className).join(", ").slice(0, 120));
    check("...and the filter rides the URL",
          String(window.location.hash).includes("wl.f=never_seen"), String(window.location.hash));
    nsTile.click();   // toggle off
    await new Promise((r) => setTimeout(r, 250));
    check("...and clicking it again clears the filter",
          [...doc.querySelectorAll("#wl-table tbody tr")].length > 1,
          String([...doc.querySelectorAll("#wl-table tbody tr")].length));
    // bulk: select two rows, disable, prove every POST
    const boxes = [...doc.querySelectorAll("#wl-table input.wl-sel")];
    check("every registered row can be selected for bulk work", boxes.length >= 2,
          String(boxes.length));
    boxes[0].click();
    boxes[1].click();
    await new Promise((r) => setTimeout(r, 60));
    const bar = doc.getElementById("wl-bulk");
    check("...selecting rows raises the bulk bar with the count",
          !bar.classList.contains("hidden") && /2/.test(doc.getElementById("wl-bulk-n").textContent),
          doc.getElementById("wl-bulk-n").textContent);
    const posts = [];
    const origFetch7 = window.fetch;
    window.fetch = (u, o) => {
      if (/weirlings\/enable/.test(String(u)) && o && o.body) posts.push(String(o.body));
      return origFetch7(u, o);
    };
    doc.getElementById("wl-bulk-disable").click();   // arms the confirm (two-stage)
    await new Promise((r) => setTimeout(r, 40));
    doc.getElementById("wl-bulk-disable").click();   // confirm
    await new Promise((r) => setTimeout(r, 350));
    window.fetch = origFetch7;
    check("...and disabling acts on EVERY selected sensor, posting the inverse",
          posts.length === 2 && posts.every((b) => /"enabled":false/.test(b)),
          posts.join(" | ").slice(0, 150));
    doc.getElementById("wl-bulk-clear").click();
    await new Promise((r) => setTimeout(r, 60));
    check("...clear drops the selection and the bar",
          doc.getElementById("wl-bulk").classList.contains("hidden"));
    // views: a default exists, switching applies filters, saving adds one
    await H.loadWeirlings();
    const viewSel = doc.getElementById("wl-view");
    check("saved views exist, with a default",
          !!viewSel && viewSel.options.length >= 3 && /All sensors/.test(viewSel.options[0].textContent),
          viewSel ? [...viewSel.options].map((o) => o.textContent).join(" | ") : "no select");
    viewSel.value = "needs-action";
    viewSel.dispatchEvent(new window.Event("change", { bubbles: true }));
    await new Promise((r) => setTimeout(r, 250));
    check("...switching to Needs action drives the problems filter",
          doc.getElementById("wl-problems-only").checked === true,
          String(doc.getElementById("wl-problems-only").checked));
    viewSel.value = "all";
    viewSel.dispatchEvent(new window.Event("change", { bubbles: true }));
    await new Promise((r) => setTimeout(r, 250));
    const before = viewSel.options.length;
    doc.getElementById("wl-view-save").click();
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
    // inline toggle: one click posts the inverse
    const posts2 = [];
    const origFetch7b = window.fetch;
    window.fetch = (u, o) => {
      if (/weirlings\/enable/.test(String(u)) && o && o.body) posts2.push(String(o.body));
      return origFetch7b(u, o);
    };
    const tog = doc.querySelector("#wl-table .wl-inline-toggle");
    if (tog) tog.click();
    await new Promise((r) => setTimeout(r, 300));
    window.fetch = origFetch7b;
    check("a row's inline toggle switches that sensor in one click",
          posts2.length === 1 && /"sensor_id"/.test(posts2[0]),
          posts2.join(" | ").slice(0, 110));
    try { window.sessionStorage.removeItem("wv-wl-views"); } catch (_e) {}
    await H.loadWeirlings();
  }

  // ── ALERT DISCIPLINE (BF-12) ────────────────────────────────────────────────────────────────
  {
    H.showView("anomalies");
    await new Promise((r) => setTimeout(r, 300));
    const head = [...doc.querySelectorAll("#anomalies-table thead th")]
      .map((t) => t.textContent.toLowerCase());
    check("the triage table names its fixed contract",
          head.includes("owner") && head.includes("matched rule"), head.join(","));
    const first = doc.querySelector("#anomalies-table tbody tr");
    const cells = first ? [...first.querySelectorAll("td")].map((t) => t.textContent) : [];
    check("...and rows carry the owner and what matched",
          cells.length >= 11 && cells.includes("ops") &&
            cells.some((c) => /scored this window/.test(c)),
          cells.join(" | ").slice(0, 140));
    const disc = doc.getElementById("an-discipline").textContent;
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
    const allowed = new Set(["ack", "resolve", "FP", "clear"]);
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

  // ── THE PIPELINE AUDITS ITSELF (BF-13) ──────────────────────────────────────────────────────
  {
    H.showView("health");
    await new Promise((r) => setTimeout(r, 350));
    const auditRows = [...doc.querySelectorAll("#audit-table tbody tr")];
    const auditText = auditRows.map((r) => r.textContent).join(" || ");
    check("every audit class renders a finding with its name",
          auditRows.length === 4 &&
            ["silent sensor", "expired rule", "stuck rule", "unowned detector"]
              .every((c) => auditText.includes(c)),
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
            doc.getElementById("view-weirlings").classList.contains("active"));
    }
    const detBtn = [...doc.querySelectorAll("#audit-table button")]
      .find((b) => /register it/.test(b.textContent));
    if (detBtn) {
      detBtn.click();
      await new Promise((r) => setTimeout(r, 200));
      check("...and another class lands on its own surface",
            doc.getElementById("view-anomalies").classList.contains("active"));
    }
    H.showView("anomalies");
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
    const noteT = doc.getElementById("st-stage-note").textContent;
    check("a failed apply-time check BLOCKS the write and names itself",
          /BLOCKED/.test(noteT) && /threshold does not fire on yesterday/.test(noteT),
          noteT.slice(0, 150));
    const resT = doc.getElementById("st-apply-results").textContent;
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
    // now a value that passes: the checks ride the success receipt too
    btIn.value = "0.5";
    btIn.dispatchEvent(new window.Event("input", { bubbles: true }));
    await H.applyStage();
    await new Promise((r) => setTimeout(r, 60));
    const resOk = doc.getElementById("st-apply-results").textContent;
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
    const pal = doc.getElementById("palette");
    const palInput = doc.getElementById("palette-input");
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
          doc.getElementById("view-zeek").classList.contains("active"));
    check("...and the palette closes behind it",
          doc.getElementById("palette").classList.contains("hidden"));
    fire("/");
    await sleep(60);
    check("slash opens the palette for a search",
          !doc.getElementById("palette").classList.contains("hidden"));
    fire("Escape");
    await sleep(40);
    check("escape closes it again",
          doc.getElementById("palette").classList.contains("hidden"));
    fire("g");
    fire("n");
    await sleep(300);
    check("g n jumps straight to Netflow",
          doc.getElementById("view-netflow").classList.contains("active"));

    // ── THE PALETTE AS SEARCH (US-8) ──────────────────────────────────────────
    {
      const type = (q) => {
        const inp = doc.getElementById("palette-input");
        inp.value = q;
        inp.dispatchEvent(new window.Event("input", { bubbles: true }));
        return inp;
      };
      const rowsNow = () => [...doc.querySelectorAll("#palette-results .palette-row")];
      const openPal = () => {
        const pb = doc.getElementById("palette-btn");
        if (pb) pb.click();
      };
      // 1) THE MOUSE PATH: the chrome button is the entry, the keys stay accelerators.
      H.showView("health");
      await sleep(150);
      const pbtn = doc.getElementById("palette-btn");
      check("PALETTE: the chrome carries a visible entry", !!pbtn);
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
            doc.getElementById("view-host").classList.contains("active")
            && doc.getElementById("h-addr").value === "198.51.100.5",
            `addr=${doc.getElementById("h-addr").value}`);
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
            doc.getElementById("view-dns").classList.contains("active")
            && doc.getElementById("dn-domain").value === "ads.example.com",
            `dom=${doc.getElementById("dn-domain").value}`);
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
            doc.getElementById("view-sluice").classList.contains("active"));
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
            && doc.getElementById("view-settings").classList.contains("active"),
            keyCard ? `collapsed=${keyCard.classList.contains("collapsed")}` : "no card");
      // 7) the disabled retrain STATES why instead of swallowing the click.
      openPal();
      await sleep(150);
      type("retrain");
      await sleep(150);
      const rtRows = rowsNow().filter((r) => /Force a model retrain/.test(r.textContent));
      check("PALETTE: the retrain command exists", rtRows.length > 0);
      const errBefore = (doc.getElementById("err-banner") || {}).textContent || "";
      if (rtRows[0]) { rtRows[0].click(); await sleep(600); }
      const mrForce = doc.getElementById("mr-force");
      const errAfter = (doc.getElementById("err-banner") || {}).textContent || "";
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
    const pIn = doc.getElementById("palette-input");
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
            doc.getElementById("palette").classList.contains("hidden")
            && !doc.getElementById("view-netflow").classList.contains("active"));
    }
  }

  // ── THE GROUPED NAV AND ITS BREADCRUMBS (TH-3) ──────────────────────────────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const groups = [...doc.querySelectorAll("#tabs .tab-group")];
    check("the nav holds at most seven groups", groups.length <= 7 && groups.length >= 2,
          String(groups.length));
    check("...every group is labelled and carries tabs",
          groups.every((g) => !!g.querySelector(".tab-group-label") && !!g.querySelector(".tab")),
          groups.map((g) => (g.querySelector(".tab-group-label") || {}).textContent).join(", "));
    const views = [...doc.querySelectorAll("#tabs .tab")].map((t) => t.dataset.view);
    check("...and all fourteen tabs survive the regrouping",
          views.length === 14 && new Set(views).size === 14
          && ["health", "anomalies", "network", "netflow", "discover", "dns", "zeek", "identity",
              "sluice", "blocked", "weirlings", "models", "host", "settings"]
             .every((v) => views.includes(v)),
          views.join(","));
    check("...nothing collapses into a sub-menu", !doc.querySelector("#tabs select, #tabs details"));
    const cssText = fs.readFileSync(path.join(WEB, "style.css"), "utf8");
    check("...one row: the strip is nowrap and scrolls rather than wrapping",
          cssText.includes("#tabs { display: flex; align-items: center; flex-wrap: nowrap; }"));
    await H.showView("weirlings");
    await H.loadWeirlings();
    await H.openWeirling("edge-alive");
    await sleep(250);
    const crumbs = doc.getElementById("crumbs");
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
          doc.getElementById("wl-detail-card").classList.contains("hidden")
          && doc.getElementById("crumbs").classList.contains("hidden"));
    H.showView("health");
    await sleep(80);
    check("a view change clears any breadcrumb that was left",
          doc.getElementById("crumbs").classList.contains("hidden"));
  }

  // ── THE DRILL-DOWN SHEET (TH-4) ─────────────────────────────────────────────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    const cssText = fs.readFileSync(path.join(WEB, "style.css"), "utf8");
    check("the drill-down is a sheet: fixed to the right edge, so the view never reflows",
          cssText.includes("#wl-detail-card.sheet { position: fixed; top: 0; right: 0; bottom: 0; left: auto;"),
          "css rule");
    const card = doc.getElementById("wl-detail-card");
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
    const scrim = doc.getElementById("wl-sheet-scrim");
    check("...and a click-out scrim behind it", !!scrim && !scrim.classList.contains("hidden"));
    window.document.dispatchEvent(new window.KeyboardEvent("keydown",
      { key: "Escape", bubbles: true, cancelable: true }));
    await sleep(60);
    check("Escape returns from the sheet",
          card.classList.contains("hidden") && scrim.classList.contains("hidden"));
    check("...and the breadcrumb trail goes with it",
          doc.getElementById("crumbs").classList.contains("hidden"));
    await H.openWeirling("edge-alive");
    await sleep(120);
    scrim.click();
    await sleep(60);
    check("a click outside returns too", card.classList.contains("hidden"));
    await H.openWeirling("edge-alive");
    await sleep(120);
    doc.getElementById("wl-sheet-close").click();
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
    const hStats = doc.getElementById("h-stats");
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
    H.showView("health");
    await sleep(60);
  }

  // ── THE ACCESSIBILITY GUARANTEES, LIVE (TH-6) ──────────────────────────────────────────────
  {
    const stageNote = doc.getElementById("st-stage-note");
    const applyRes = doc.getElementById("st-apply-results");
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
          /applied to the hub's plan at/.test(doc.getElementById("wl-plan-note").textContent),
          doc.getElementById("wl-plan-note").textContent);
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
          /NOT APPLIED/.test(doc.getElementById("wl-plan-note").textContent),
          doc.getElementById("wl-plan-note").textContent);
    // (6) bulk revoke: the echo's reason rides EVERY posted revoke
    H.showView("weirlings");
    await H.loadWeirlings();
    await sleep(150);
    const boxes = [...doc.querySelectorAll("#wl-table tbody input.wl-sel")];
    if (boxes[0]) { boxes[0].checked = true; boxes[0].dispatchEvent(new window.Event("change", { bubbles: true })); }
    await sleep(80);
    const before6 = POSTED.length;
    doc.getElementById("wl-bulk-revoke").click();   // arm
    await sleep(40);
    doc.getElementById("wl-bulk-revoke").click();   // confirm -> the echo
    await sleep(80);
    await confirmEcho("decommissioned after the move");
    await sleep(200);
    const rvs = POSTED.slice(before6).filter((r) => r.url.includes("/api/weirlings/revoke"));
    check("a bulk revoke posts the echo's reason on every id",
          rvs.length >= 1 && rvs.every((r) => /decommissioned after the move/.test(r.body)),
          rvs.map((r) => r.body).join(" | ").slice(0, 160));
  }

  // ── THE BLOCKLIST PANEL (the operator: hagezi lists, custom names, hits) ────────────────────
  {
    H.showView("sluice");
    await H.loadSluice();
    const bl = doc.getElementById("sl-bl-rows").textContent;
    check("the blocklist panel renders the imported source", /HaGeZi/.test(bl) && /123456/.test(bl),
          bl.slice(0, 110));
    // The card moved to Settings (2026-10-16) and its Recent domain hits panel was removed --
    // hits are read on the Blocked page now. What must stay checkable here: each row is
    // CLICKABLE to toggle the list, and the on/off state is on the row.
    const row0 = doc.querySelector("#sl-bl-rows tr");
    check("a blocklist row is clickable to turn the list on or off",
          row0 && row0.classList.contains("clickable") && /on|off/.test(row0.textContent),
          row0 ? row0.textContent.slice(0, 110) : "(no row)");
  }

  // The gate OFF: the same rows must state the reason instead of offering the button.
  fetchOverride = (u, opts) => (String(u).split("?")[0].endsWith("/api/sluice")
    ? { ok: true, status: 200,
        json: async () => (Object.assign({}, SLUICE_PAYLOAD, { enabled: false })) }
    : null);
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
  await H.loadIdentity();
  const fpIn = doc.getElementById("fp-input");
  const fpGo = doc.getElementById("fp-go");
  check("the identity view carries the fingerprint lookup", !!fpIn && !!fpGo);
  if (fpIn && fpGo) {
    fpIn.value = "t13d1516h2_8daaf6152771_02713d6af862";
    fpGo.click();
    await new Promise((r) => setTimeout(r, 80));
    const hits = [...doc.querySelectorAll("#fp-results tbody tr")];
    check("the lookup renders one row per host that presented the fingerprint",
          hits.length === 2, `${hits.length} row(s)`);
    check("the note states how many hosts, and over what window",
          /2 host/.test(doc.getElementById("fp-note").textContent),
          doc.getElementById("fp-note").textContent);

    fetchOverride = (u, opts) => (String(u).split("?")[0].endsWith("/api/fingerprints")
      ? { ok: true, status: 200,
          json: async () => ({ ja4: "deadbeef", count: 0, hosts: [], reason: "" }) }
      : null);
    fpIn.value = "deadbeef";
    fpGo.click();
    await new Promise((r) => setTimeout(r, 80));
    check("a lookup that found nothing SAYS so",
          /no host/.test(doc.getElementById("fp-note").textContent),
          doc.getElementById("fp-note").textContent);
    check("and renders no table for it",
          doc.querySelectorAll("#fp-results tbody tr").length === 0);
    fetchOverride = null;
  }

  // ── the forced retrain: a rehearsal, and keep-or-trash as the decision ─────────────────────
  //
  // The panel has to make three things visible BEFORE the decision: what the candidate was trained
  // on, whether the window contained detections the deployment already recorded (a retrain learns
  // those as normal), and which of Keep / Trash applies. A candidate that trained nothing must not
  // offer Keep at all.
  H.showView("overview");
  await new Promise((r) => setTimeout(r, 20));
  H.showView("models");
  await H.loadRetrain();
  const mrNote = (doc.getElementById("mr-note") || {}).textContent || "";
  check("the retrain panel says what the candidate trained, and on how much",
        /2 of 4 detector/.test(mrNote) && /host-window/.test(mrNote), mrNote.slice(0, 180));
  check("the contamination warning reaches the screen, beside the decision",
        /WARNING/.test(mrNote) && /as normal/.test(mrNote), mrNote.slice(0, 240));
  check("one row per detector, so 'trained' can be read per model",
        doc.querySelectorAll("#mr-report tbody tr").length === 4,
        `${doc.querySelectorAll("#mr-report tbody tr").length} row(s)`);
  {
    const keepBtn = doc.getElementById("mr-keep");
    check("Keep is offered for a candidate that trained something",
          !!keepBtn && !keepBtn.classList.contains("hidden"));
    if (keepBtn) {
      const postedBefore = POSTED.length;
      keepBtn.click();
      await new Promise((r) => setTimeout(r, 120));
      check("Keep opens the destructive echo first (target + a required reason)",
            !!doc.querySelector("#modal-body .dest-confirm"),
            doc.getElementById("mr-note").textContent.slice(0, 80));
      await confirmEcho("the candidate's precision held up");
      await new Promise((r) => setTimeout(r, 120));
      const req = POSTED.slice(postedBefore).find((r) => r.url.includes("/api/models/retrain"));
      check("Keep is a WRITE carrying the action, the candidate's own id and the reason",
            !!req && /keep/.test(req.body) && /r123/.test(req.body)
            && /precision held up/.test(req.body),
            req ? req.body.slice(0, 180)
                : POSTED.slice(postedBefore).map((r) => r.url).join(","));
    }
  }

  // A candidate that built NOTHING: Keep must be absent, not merely unhelpful.
  fetchOverride = (u, opts) => (String(u).split("?")[0].endsWith("/api/models/retrain")
    && String((opts || {}).method || "GET").toUpperCase() === "GET"
    ? { ok: true, status: 200, json: async () => Object.assign({}, RETRAIN_PAYLOAD, {
        state: "done", can_keep: false,
        summary: "0 of 4 detector(s) trained; on 0 host-window(s)",
        report: Object.assign({}, RETRAIN_PAYLOAD.report, { trained_any: false }) }) }
    : null);
  await H.loadRetrain();
  check("a candidate that trained NOTHING does not offer Keep",
        doc.getElementById("mr-keep").classList.contains("hidden"),
        "an empty candidate must not be installable over working models");
  fetchOverride = null;
  await H.loadRetrain();

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
        doc.getElementById("auth-gate").classList.contains("hidden"),
        "auth gate visible with accounts:false");
  check("the sign-in form is a password input, not plain text",
        doc.getElementById("gate-pass").type === "password");

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
        /admin/.test(doc.getElementById("user-chip").textContent),
        doc.getElementById("user-chip").textContent);
  check("the auth gate is hidden after signing in",
        doc.getElementById("auth-gate").classList.contains("hidden"));
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
  doc.getElementById("st-new-user").value = "newviewer";
  doc.getElementById("st-new-pass").value = "initial-pass-1";
  doc.getElementById("st-new-role").value = "viewer";
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
        doc.getElementById("st-users-card").classList.contains("hidden"));
  check("the page tells the viewer why it is read-only",
        /read-only|viewer/i.test(doc.getElementById("st-note").textContent),
        doc.getElementById("st-note").textContent.slice(0, 120));
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
        doc.getElementById("auth-gate").classList.contains("hidden"));
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
        && /sign in again/i.test(doc.getElementById("gate-note").textContent),
        `auth=${gateDisplay("auth-gate")} note=${doc.getElementById("gate-note").textContent}`);
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
  const tokenToggle = doc.getElementById("gate-token-toggle");
  check("the sign-in gate offers the operator-token door", !!tokenToggle);
  check("the token form starts hidden (computed)",
        gateDisplay("gate-token-block") === "none",
        `block=${gateDisplay("gate-token-block")}`);
  tokenToggle.click();
  check("the door opens on click (computed)",
        gateDisplay("gate-token-block") === "flex" || gateDisplay("gate-token-block") === "block",
        `block=${gateDisplay("gate-token-block")}`);

  const tokenForm = doc.getElementById("gate-token-form");
  doc.getElementById("gate-token").value = "not-the-token";
  tokenForm.dispatchEvent(new window.Event("submit", { bubbles: true, cancelable: true }));
  await new Promise((r) => setTimeout(r, 80));
  check("a wrong token is refused and the gate stays up",
        gateDisplay("auth-gate") === "flex"
        && /not accepted/i.test(doc.getElementById("gate-token-error").textContent),
        `note=${doc.getElementById("gate-token-error").textContent}`);

  H.setToken("");
  doc.getElementById("gate-token").value = "test-token-value";
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

  const idText = doc.getElementById("view-identity").textContent;
  // THE DISAGREEMENT LIVES IN THE DETAIL PANEL, which opens on click -- so the check must click.
  // Asserting against the table text was checking the wrong surface and would have passed only by
  // accident if a hostname happened to appear in a row.
  const contradicted = Array.from(idRows).find((r) => r.textContent.includes("203.0.113.20"));
  check("a host whose sources disagree is present to inspect", !!contradicted,
        "the contradicted host is missing from the table");
  if (contradicted) {
    contradicted.click();
    await new Promise((r) => setTimeout(r, 40));
    const dtext = doc.getElementById("id-detail").textContent;
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
    const detail = doc.getElementById("id-detail").textContent;
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
  await H.loadIdentity().catch(() => {});
  await new Promise((r) => setTimeout(r, 40));
  // The failure banner lives on <main> (that is where showDataError prepends it), NOT inside the
  // view section -- so the check reads the banner. Asserting against the view text was checking a
  // surface the message never reaches.
  const banner = doc.getElementById("data-banner");
  check("a failed identity query names its cause instead of rendering empty",
        !!banner && banner.textContent.includes("boom"),
        banner ? banner.textContent.slice(0, 100) : "no banner was shown");
  // And the coverage panel must say UNKNOWN rather than render zeros, which would read as
  // "identified nothing" -- a different and much more alarming claim.
  const failView = doc.getElementById("view-identity").textContent;
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

check("the Sluice Gate tab exists and renders",
      slText().includes("Sluice Gate"));

check("the gate's STATE is shown, not just a rule count",
      slText().includes("armed") && slText().includes("eth1"),
      slText().slice(0, 200));

check("the server's own state sentence reaches the screen",
      slText().includes("lapsed and are no longer enforced"),
      "gate.detail was not rendered, so the operator cannot see WHY");

// ── the blocking statistics use the console's formatters (#23) ──────────────────────────────
// Raw integers read as foreign beside every other panel: no digit grouping, no byte scale.
// The fixture's gate carries 1234 packets / 987654 bytes, so both formatters have work to do;
// the stopped gate further down (0 packets) must still render a real 0, never a blank.
const slState = doc.getElementById("sl-state") ? doc.getElementById("sl-state").textContent : "";
check("the gate tiles group packet counts and scale byte totals",
      slState.includes((1234).toLocaleString()) && !slState.includes("1234")
      && slState.includes(H.fmtBytes(987654)),
      slState.slice(0, 170));
const slGateRows = [...doc.querySelectorAll("#sl-gates tbody tr")];
const dualRow = slGateRows.find((r) => r.textContent.includes("weirvern-dual"));
check("the gates table groups its packet counts too",
      !!dualRow && [...dualRow.querySelectorAll("td")][4].textContent === (1234).toLocaleString(),
      dualRow ? [...dualRow.querySelectorAll("td")][4].textContent : "no weirvern-dual row");
const zeroRow = slGateRows.find((r) => r.textContent.includes("lab-west"));
check("a stopped gate's real zero still renders as 0",
      !!zeroRow && [...zeroRow.querySelectorAll("td")][4].textContent === "0",
      zeroRow ? [...zeroRow.querySelectorAll("td")][4].textContent : "no lab-west row");

check("a LIVE rule is distinguishable from a LAPSED one",
      slText().includes("live") && slText().includes("lapsed"),
      "a lapsed rule must not look like a live one, nor like a deleted one");

check("a REVOKED rule stays visible rather than disappearing",
      slText().includes("revoked"),
      "the audit trail of what was blocked must survive the unblocking");

check("a detection-derived rule is attributed to the detection",
      slText().includes("detection"),
      "an operator must be able to tell a model's block from an analyst's");

check("the blocking policy levels are rendered with their cost",
      slText().includes("High only") && slText().includes("30 minutes"));

check("the ACTIVE policy is marked as in use",
      slText().includes("in use"),
      "an operator scanning the policies must find the one in force");

check("a rule with no reason says so rather than showing blank",
      !slText().includes("undefined"),
      "undefined reached the screen, which means a missing field rendered as a value");

check("a rule with NO EXPIRY reads as 'until revoked', not as a date or a dash",
      slText().includes("until revoked"),
      "the operator set the duration to 0; the row must say what that means");

// ── one rule store, many gates ───────────────────────────────────────────────────────────────
//
// The fleet's gates: this hub's own, a weirling enforcing on its own segment, and one that has
// stopped. "The rule is live" and "the rule is blocking the segment that saw the traffic" are
// different statements, and only this table tells them apart.
check("every gate is listed, with the local one marked as this hub",
      slText().includes("weirvern-eth2") && slText().includes("(this hub)"),
      slText().slice(0, 240));
check("a gate that STOPPED is called out, not merely listed",
      /stopped reporting/i.test(slText()),
      "a stale gate must not read like a covered segment");
check("each gate states the path it is enforcing by",
      slText().includes("channel") && slText().includes("siphon"),
      "which of the two paths is live is the difference between armed and claimed");

// THE MANUAL FORM (2026-10-16): the reason is OPTIONAL and a duration of 0 means until revoked.
// Both are the operator's own instruction, and each fails silently in its own way -- the client
// refusing a blank reason, or the server reading a deliberate 0 as "unset" and substituting the
// default hour.
{
  const slSrc = H.document.getElementById("sl-src");
  const slTtl = H.document.getElementById("sl-ttl");
  const slWhy = H.document.getElementById("sl-reason");
  const slGo = H.document.getElementById("sl-block");
  check("the manual block form is on the page with its duration and reason fields",
        !!slSrc && !!slTtl && !!slWhy && !!slGo);
  if (slSrc && slTtl && slWhy && slGo) {
    slSrc.value = "203.0.113.77";
    slWhy.value = "";
    slTtl.value = "0";
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

check("a NEVER-SEEN sensor is distinguishable from a STALE one",
      wlText().includes("never seen") && wlText().includes("stale"),
      "both render as 'no fresh heartbeat'; collapsing them sends an operator to the logs of a "
      + "sensor that never wrote any");

// The findings moved to the drill-down with the row strip (sensor + status only): the claim
// still has to REACH the operator, so open the sensor and read it there.
await H.openWeirling("edge-promised");
const wlDetailText = () => (doc.getElementById("wl-detail-body") || {}).textContent || "";
check("a never-seen IN-PATH sensor says the segment may be waiting (drill-down)",
      wlDetailText().toLowerCase().includes("in-path"),
      "an in-path sensor that never came up is more urgent than a passive one and must say why");

check("an UNDECLARED sensor is reported as unregistered",
      wlText().includes("unregistered"),
      "a sensor feeding the hub that nobody declared is security-relevant, the same class as an "
      + "unexpected NetFlow exporter");

check("a DISABLED sensor is shown as disabled, not as a fault",
      wlText().includes("disabled"),
      "switched-off sensors are not problems; raising them trains the reader to ignore the column");

// ── measured-zero vs not-measured, IN THE DRILL-DOWN (the rows carry sensor + status now) ───
// The em dash is what an unmeasured value renders as. Asserting the DASH and not merely
// "something rendered": 0.0% for a sensor that measured nothing would read as a perfect sensor.
await H.openWeirling("edge-stopped");
check("an UNMEASURED capture loss renders as a dash, not as 0.0%",
      wlDetailText().includes("capture loss") && /\u2014|—/.test(wlDetailText()),
      "an unmeasured value rendered as 0.0% reports a sensor that has measured nothing as a "
      + "perfect one");
await H.openWeirling("edge-alive");
check("a MEASURED zero loss renders as a real figure",
      wlDetailText().includes("0.0%"),
      "0.0% is 'we looked, nothing was lost' and must stay a measurement");

await H.openWeirling("edge-moved");
check("a segment the sensor CONTRADICTS is surfaced, not silently overwritten",
      wlDetailText().includes("sixth floor"),
      "the declared segment and the observed one are different facts; letting the declaration "
      + "win makes a sensor covering the wrong segment look correctly placed");

check("high capture loss is called out in the fleet",
      wlDetailText().includes("62.5"),
      "capture loss is the only field showing a sensor is blind to most of what is on the wire");

// ── the drill-down ───────────────────────────────────────────────────────────────────────────
{
  const btn = [...H.document.querySelectorAll("#wl-table button")]
    .find((b) => (b.textContent || "") === "edge-stopped");
  check("a fleet row opens that sensor's drill-down", !!btn);
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
    check("the drill-down separates DECLARED from REPORTED",
          body.includes("declared") && body.includes("reported"),
          "one is a claim somebody made and the other is a fact the sensor produced");
    H.document.getElementById("wl-detail-close").click();
  }
}

// ── REGISTERING from the row's own reports, in one click ───────────────────────────────────────
// The undeclared row's guidance said "Register it above" while the id sat in the row in front of
// the operator -- at the first deployment the view's first question was "where do i get the
// sensor id". The drill-down for an undeclared sensor must offer REGISTER, and the click must
// file the declaration from the OBSERVED identity rather than leaving an empty form.
{
  const btn = [...H.document.querySelectorAll("#wl-table button")]
    .find((b) => (b.textContent || "") === "ghost-box");
  check("the undeclared sensor is drill-down-able, to register from", !!btn);
  if (btn) {
    btn.click();
    for (let i = 0; i < 40 && !(H.document.getElementById("wl-detail-body").textContent || "")
         .includes("undeclared"); i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    const regBtn = H.document.getElementById("wl-detail-register");
    check("an undeclared sensor offers an ADOPT button, not only prose",
          !!regBtn && !regBtn.classList.contains("hidden")
          && (regBtn.textContent || "").includes("Adopt"),
          "the id the hub is already hearing should not have to be retyped from the row into the "
          + "form below");
    const before = POSTED.length;
    if (regBtn) regBtn.click();
    for (let i = 0; i < 60 && POSTED.length === before; i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    const post = POSTED.slice(before).find((r) => r.url.includes("/api/weirlings/register"));
    let sentBody = {};
    try { sentBody = JSON.parse((post || {}).body || "{}"); } catch (_e) { sentBody = {}; }
    check("the click registers the OBSERVED identity, not a blank form",
          !!post && sentBody.sensor_id === "ghost-box",
          "registering the wrong id -- or leaving the form for the operator to fill -- leaves the "
          + "sensor undeclared while looking like it worked");
    check("the observed mode rides along as the expectation",
          !!post && sentBody.expected_mode === "loch",
          "the declaration should start from what the sensor reports, not from a default nobody "
          + "chose");
    for (let i = 0; i < 60 && !(H.document.getElementById("wl-detail-note").textContent || "")
         .includes("Registered"); i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    check("the outcome is stated on the detail, not silently swallowed",
          (H.document.getElementById("wl-detail-note").textContent || "")
            .includes("Registered ghost-box"));
    check("a registered sensor does not offer REGISTER",
          !!regBtn && regBtn.classList.contains("hidden"),
          "the button is offered only while the sensor reads as undeclared; anything else "
          + "invites a click that cannot mean anything");
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

// ── THE PER-SENSOR PANEL: status, NICs, mode, Sonar (operator restructure, 2026-10-17) ─────
// "Pull weirling settings out of settings tab... I want the weirlings tab to have each sensor
// its nics, a sonar button, and a mode selection. And status."
{
  check("the Weirling settings card is gone from the Settings tab",
        !doc.getElementById("st-wl-select") && !doc.getElementById("wl-sensor-config"),
        "the scrapped card's elements are still in the document");
  check("the standalone Register-a-weirling card is gone (the drill-down registers)",
        !doc.getElementById("wl-id") && !!doc.getElementById("wl-detail-register"),
        "the register path must stay reachable from the sensor's own panel");
  check("the drill-down's Advanced disclosure holds the sensor grid",
        !!doc.getElementById("wl-advanced")
        && !!doc.querySelector("#wl-advanced #st-sensor"));

  const openRow = (id) => [...doc.querySelectorAll("#wl-table button")]
    .find((b) => (b.textContent || "") === id);
  const localBtn = openRow("edge-alive");
  const remoteBtn = openRow("edge-stopped");
  if (localBtn) {
    localBtn.click();
    for (let i = 0; i < 60 && !(doc.getElementById("wl-detail-body").textContent || "")
         .includes("reporting normally"); i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    check("the local sensor's panel shows the runtime controls",
          !doc.getElementById("wl-runtime").classList.contains("hidden"),
          "mode + Sonar must be reachable for the sensor this hub runs");
    check("the mode selector carries the sensor's reported mode",
          doc.getElementById("wl-mode-select").value === "loch",
          doc.getElementById("wl-mode-select").value);
    check("the panel shows the sensor's NICs from its own report",
          /eth1, eth2/.test(doc.getElementById("wl-detail-body").textContent || ""),
          doc.getElementById("wl-detail-body").textContent.slice(0, 200));
    const t0 = POSTED.length;
    H.SONAR_STATE.result = null;
    const modeSel = doc.getElementById("wl-mode-select");
    modeSel.value = "siphon";
    modeSel.dispatchEvent(new window.Event("change", { bubbles: true }));
    // BF-9: going in-path opens the echo; the check confirms it (with its reason) and the
    // apply then carries that reason into the write.
    for (let i = 0; i < 150 && !doc.querySelector("#modal-body .dest-confirm"); i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    check("going in-path opens the destructive echo", await confirmEcho("the cut point is on purpose"));
    for (let i = 0; i < 100 && !POSTED.slice(t0).some((r) => r.url.includes("/api/settings/apply")); i++) {
      await new Promise((r) => setTimeout(r, 20));
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
  }
  if (remoteBtn) {
    remoteBtn.click();
    for (let i = 0; i < 60 && !(doc.getElementById("wl-detail-body").textContent || "")
         .includes("edge-stopped"); i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    check("a remote sensor's panel hides the runtime controls",
          doc.getElementById("wl-runtime").classList.contains("hidden"),
          "offering controls that cannot reach the sensor would be a lie in pixels");
  }
  doc.getElementById("wl-detail-close").click();
}

// ── gateway-STYLE ADOPTION: one click, in the row (operator, 2026-10-17) ──────────────────────
{
  // The earlier drill-down click already adopted ghost-box in the stub (its register call
  // flips the fixture row); reset it so THIS check's subject is an unadopted sensor again.
  const ghostFix = WEIRLINGS_PAYLOAD.sensors.find((s) => s.sensor_id === "ghost-box");
  if (ghostFix) { ghostFix.registered = false; ghostFix.state = "unregistered"; ghostFix.enabled = false; }
  await H.loadWeirlings();
  const rows = [...doc.querySelectorAll("#wl-table tbody tr")];
  const rowFor = (id) => rows.find((tr) => (tr.textContent || "").includes(id));
  const ghost = rowFor("ghost-box");
  const alive = rowFor("edge-alive");
  const adopt = ghost && ghost.querySelector("button.wl-adopt");
  check("an unregistered sensor offers one-click Adopt in its ROW",
        !!adopt && !(alive && alive.querySelector("button.wl-adopt")),
        "the action must be where the sensor is, and only while it is needed");
  if (adopt) {
    const before = POSTED.length;
    adopt.click();
    for (let i = 0; i < 60 && POSTED.length === before; i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    const post = POSTED.slice(before).find((r) => r.url.includes("/api/weirlings/register"));
    let sent = {};
    try { sent = JSON.parse((post || {}).body || "{}"); } catch (_e) { sent = {}; }
    check("Adopt files the declaration from the sensor's own reports -- no form, no drill-down",
          !!post && sent.sensor_id === "ghost-box" && sent.expected_mode === "loch"
          && (sent.segment === "" || sent.segment === undefined),
          (post || {}).body || "no register POST");
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

  const planBox = () => doc.getElementById("wl-plan");
  const planNote = () => (doc.getElementById("wl-plan-note") || {}).textContent || "";
  const planModeSel = () => doc.getElementById("wl-plan-mode");
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
        && doc.getElementById("wl-plan-segment").value === "203.0.113.0/24"
        && doc.getElementById("wl-plan-targets").value === "203.0.113.7",
        planModeSel().value + " / " + doc.getElementById("wl-plan-segment").value);
  check("the editor states declared versus reported on the same line",
        /declared: siphon/.test(doc.getElementById("wl-plan-state").textContent || "")
        && /last reported: siphon/.test(doc.getElementById("wl-plan-state").textContent || ""),
        doc.getElementById("wl-plan-state").textContent);

  // ── (2) staging a field writes NOTHING; Apply goes plan -> apply, for THAT sensor
  {
    const before = POSTED.length;
    const input = doc.getElementById("wl-plan-targets");
    input.value = "203.0.113.7,203.0.113.8";
    input.dispatchEvent(new window.Event("input", { bubbles: true }));
    check("editing a plan field STAGES it and writes nothing",
          POSTED.length === before && /staged for edge-moved/.test(planNote()),
          `${POSTED.length - before} request(s) sent on edit; note: ${planNote()}`);
    check("the Apply button is enabled only while something is staged",
          !doc.getElementById("wl-plan-apply").disabled);

    doc.getElementById("wl-plan-apply").click();
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
          doc.getElementById("wl-plan-targets").value === "203.0.113.7,203.0.113.8",
          doc.getElementById("wl-plan-targets").value);
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

  doc.getElementById("wl-detail-close").click();
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
        emptyCards.map((c) => ((c.querySelector("h2") || {}).textContent || "?").trim()).join(", "));
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
  await H.loadWeirlings().catch(() => {});
  await new Promise((r) => setTimeout(r, 80));
  const txt = wlText();
  check("an unreadable registry says so instead of showing an empty fleet",
        txt.includes("registry could not be read") || txt.includes("Fleet unknown"),
        "a blank table during a registry outage reads as good news");
  const banner = H.document.getElementById("data-banner");
  check("an unreadable registry raises the data banner",
        !!banner && (banner.textContent || "").includes("registry"),
        "the panel-level reason explains the blank table; the banner explains the whole view");
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
        window.getComputedStyle(doc.getElementById("tabs")).overflowX === "auto",
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
  const trBtn = doc.getElementById("tr-open");
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
  const trText = doc.getElementById("tr-text");
  const trApplyBtn = doc.getElementById("tr-text-apply");
  if (trText && trApplyBtn) {
    trText.value = "last 15 minutes";
    trApplyBtn.click();
    check("free text is read the way Kibana reads it ('last 15 minutes')",
          H.trHours() === 1, "trHours()=" + H.trHours());
    trText.value = "banana";
    trApplyBtn.click();
    const note = doc.getElementById("tr-note");
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
    const note = doc.getElementById("nf-detail-note");
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
    const s = doc.getElementById("nf-summary").textContent;
    check("a failed netflow load does not leave 'loading…' standing",
          !/loading/i.test(s) && /unavailable/i.test(s), s);
    await H.loadNetflow();
    // (this fixture's payload legitimately reports an unavailable volume, so the assertion is
    // that the FAILURE note is gone -- not that any particular success text is present)
    const s2 = doc.getElementById("nf-summary").textContent;
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
              doc.getElementById("view-anomalies").classList.contains("active")
              && !doc.getElementById("view-evidence").classList.contains("active")
              && !!anRow.querySelector(".gate-form"),
              "anomalies active=" + doc.getElementById("view-anomalies").classList.contains("active"));
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
    let scrim = doc.getElementById("wl-sheet-scrim");
    check("the sheet opens with its scrim", !!scrim && !scrim.classList.contains("hidden"));
    doc.getElementById("wl-detail-close").click();
    await sleep(40);
    check("Close hides the card AND releases the scrim (the console stays clickable)",
          doc.getElementById("wl-detail-card").classList.contains("hidden")
          && (!scrim || scrim.classList.contains("hidden")),
          "scrim hidden=" + (scrim ? scrim.classList.contains("hidden") : "no scrim"));
    // (b2) the drill revoke: through the echo, carrying the reason, and it releases the scrim
    await H.openWeirling("edge-alive");
    await sleep(150);
    const beforeRevoke = POSTED.length;
    doc.getElementById("wl-detail-revoke").click();
    await sleep(120);
    check("the drill's Revoke opens the echo first", !!doc.querySelector("#modal-body .dest-confirm"));
    await confirmEcho("retiring it on purpose");
    await sleep(200);
    const revReq = POSTED.slice(beforeRevoke).find((r) => r.url.includes("/api/weirlings/revoke"));
    check("...and the revoke carries its reason", !!revReq && /retiring it on purpose/.test(revReq.body),
          revReq ? revReq.body.slice(0, 120) : "no revoke POST");
    scrim = doc.getElementById("wl-sheet-scrim");
    check("...and the exit releases the scrim too",
          doc.getElementById("wl-detail-card").classList.contains("hidden")
          && (!scrim || scrim.classList.contains("hidden")));
    // (d) the anomalies header and its row cells agree BY POSITION
    H.showView("anomalies");
    await sleep(300);
    const head = [...doc.querySelectorAll("#anomalies-table thead th")].map((t) => t.textContent.toLowerCase());
    const cells = [...doc.querySelectorAll("#anomalies-table tbody tr")[0].querySelectorAll("td")].map((t) => t.textContent);
    const ownerAt = cells.findIndex((c) => c === "ops");
    const matchedAt = cells.findIndex((c) => /scored this window/.test(c));
    check("the header names its columns where the rows put them",
          head.indexOf("owner") === ownerAt && head.indexOf("matched rule") === matchedAt
          && ownerAt > -1 && matchedAt > -1,
          "owner head=" + head.indexOf("owner") + " cell=" + ownerAt
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
      ? [...anRow1.querySelectorAll("td")].find((td) => /open this host's view/.test(td.title || ""))
      : null;
    check("the anomaly row's host cell names its destination", !!hostCellEl);
    if (hostCellEl) {
      hostCellEl.click();
      await sleep(220);
      check("...and it opens the Host view", doc.getElementById("view-host").classList.contains("active"));
    }
    // 2. a netflow talker -> its host (was: filter-only, the audit's runner-up)
    fetchOverride = (u) => (String(u).includes("/api/netflow")
      ? Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true, reason: "", hours: 24,
          talkers: { available: true, reason: "", points: [
            { src_addr: "198.51.100.20", hostname: "host.example", bytes: 123456, flows: 9 }] },
        }) })
      : null);
    await H.loadNetflow();
    await sleep(150);
    const tkBar = doc.querySelector("#nf-talkers .bar-row");
    check("the talkers chart offers its click targets", !!tkBar);
    if (tkBar) {
      tkBar.click();
      await sleep(220);
      check("a talker opens its host, not just a filter",
            doc.getElementById("view-host").classList.contains("active"));
    }
    fetchOverride = null;
    // 3. a Discover Zeek log row -> that log's drill in the Zeek view
    H.showView("discover");
    const feedSel = doc.getElementById("dc-feed");
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
              doc.getElementById("view-zeek").classList.contains("active")
              && (doc.getElementById("zk-drill-title").textContent || "").includes("conn.log"),
              doc.getElementById("zk-drill-title").textContent);
      }
      feedSel.value = "netflow";
      feedSel.dispatchEvent(new window.Event("change", { bubbles: true }));
      await sleep(200);
    }
    // 4. the sensor sheet -> its flows, filtered to the sensor in Discover
    H.showView("weirlings");
    await H.loadWeirlings();
    await H.openWeirling("edge-alive");
    await sleep(180);
    const goBtn = [...doc.querySelectorAll("#wl-detail-card button")]
      .find((b) => /Its flows/.test(b.textContent));
    check("the sensor sheet carries its onward links", !!goBtn);
    if (goBtn) {
      const beforeDc = DISCOVER_REQS.length;
      goBtn.click();
      await sleep(280);
      check("...and 'Its flows' lands in Discover filtered to exactly this sensor",
            doc.getElementById("view-discover").classList.contains("active")
            && doc.getElementById("dc-sensor").value === "edge-alive"
            && DISCOVER_REQS.slice(beforeDc).some((u) => u.includes("sensor=edge-alive")),
            "sensor=" + doc.getElementById("dc-sensor").value);
    }
    // 5. a sluice gate's sensor -> that sensor's fleet sheet
    H.showView("sluice");
    await H.loadSluice();
    await sleep(150);
    const gateCell = doc.querySelector('#sl-gates [title^="open this sensor"]');
    check("a gate's sensor cell names its destination", !!gateCell);
    if (gateCell) {
      gateCell.click();
      await sleep(280);
      check("...and it opens that sensor's fleet sheet",
            doc.getElementById("view-weirlings").classList.contains("active")
            && !doc.getElementById("wl-detail-card").classList.contains("hidden")
            && /weirvern-dual/.test(doc.getElementById("wl-detail-id").textContent),
            "detail id=" + doc.getElementById("wl-detail-id").textContent);
    }
    // 6. an identity row's host -> the Host view; its JA4 -> the lookup
    H.showView("identity");
    await H.loadIdentity();
    await sleep(180);
    const idRow = [...doc.querySelectorAll("#id-table tbody tr")]
      .find((tr) => /203\.0\.113\.10/.test(tr.textContent));
    const idHost = idRow ? idRow.querySelector("td") : null;
    check("the identity list offers its host cells", !!idHost && /open this host's view/.test(idHost.title || ""));
    if (idHost) {
      idHost.click();
      await sleep(220);
      check("...and the host cell opens the Host view", doc.getElementById("view-host").classList.contains("active"));
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
              /presented this fingerprint/.test((doc.getElementById("fp-note") || {}).textContent || "")
              || /presented this fingerprint/.test((doc.getElementById("fp-results") || {}).textContent || ""),
              ((doc.getElementById("fp-note") || {}).textContent || "").slice(0, 80));
      }
    }
  }

  // ── NO DEAD ENDS: the way back, the way forward, and the receipt (US-3) ─────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    // THE 15s AUTO-REFRESH TICK: the console refreshes on by default; here it re-renders the
    // active view mid-click and detaches the very row a check is holding (measured: a tick
    // wiped a flashed row and a dn-detail). The checks below are about CLICK CONTRACTS, not
    // about the timer -- which has its own checks calling refreshAll directly -- so the timer
    // is stopped for the rest of the run.
    const arBox = doc.getElementById("autorefresh");
    if (arBox && arBox.checked) {
      arBox.checked = false;
      arBox.dispatchEvent(new window.Event("change", { bubbles: true }));
    }
    // 1. Evidence is two-way: a crumb back (filters intact) and a Copy-link that carries it.
    fetchOverride = (u) => (String(u).includes("/api/evidence")
      ? Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true, hostname: "host.example", src_addr: "198.51.100.5",
          window_start: "2026-01-01T00:15:00", window_end: "2026-01-01T00:20:00",
          anomaly: { severity: "high", anomaly_score: 0.91, detected_by_models: "IF",
                     baseline_comparison: "", attack_techniques: "" },
          flow_summary: { bytes: 1000, packets: 9, flows: 3, unique_destinations: 1, unique_ports: 1 },
          flows: [], errors: null }) })
      : null);
    H.showView("anomalies");
    await H.loadAnomalies();
    await sleep(250);
    const sevCell = [...doc.querySelectorAll("#anomalies-table tbody tr td")]
      .find((td) => /severity/.test(td.title || ""));
    if (sevCell) { sevCell.click(); await sleep(250); }
    const chipsBefore = (doc.getElementById("an-chips") || {}).textContent || "";
    const anRowE = doc.querySelector("#anomalies-table tbody tr");
    check("an anomaly row opens Evidence", !!anRowE);
    if (anRowE) {
      anRowE.click();
      await sleep(250);
      const crumbs = doc.getElementById("crumbs") || { textContent: "" };
      check("...and Evidence shows a labeled crumb back",
            doc.getElementById("view-evidence").classList.contains("active")
            && /Anomalies/.test(crumbs.textContent), crumbs.textContent.slice(0, 60));
      H.syncURL();
      check("a Copy-link carries the drill (v=evidence + ev.host)",
            /v=evidence/.test(window.location.hash) && /ev\.host=/.test(window.location.hash),
            window.location.hash.slice(0, 130));
      const crumbBtn = doc.querySelector("#crumbs button.crumb");
      if (crumbBtn) {
        crumbBtn.click();
        await sleep(250);
        check("the crumb returns to Anomalies with its filters intact",
              doc.getElementById("view-anomalies").classList.contains("active")
              && ((doc.getElementById("an-chips") || {}).textContent || "") === chipsBefore,
              "chips now: " + ((doc.getElementById("an-chips") || {}).textContent || "").slice(0, 60));
      }
    }
    // 2. the host drill acts, and it DISMISSES.
    fetchOverride = (u) => (String(u).includes("/api/evidence")
      ? Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true, hostname: "host.example", src_addr: "198.51.100.5",
          window_start: "2026-01-01T00:15:00", window_end: "2026-01-01T00:20:00",
          anomaly: { severity: "high", anomaly_score: 0.91, detected_by_models: "IF",
                     baseline_comparison: "", attack_techniques: "" },
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
          zeek_services: [{ service: "ssl", conns: 5, bytes: 7000 }],
          anomalies: [{ detected_at: "2026-01-01T00:20:00", anomaly_score: 0.91,
                        severity: "high", detected_by_models: "IsolationForest",
                        window_start: "2026-01-01T00:15:00", window_end: "2026-01-01T00:20:00",
                        baseline_comparison: "3.4x the host's normal" }],
          errors: null }) })
      : null);
    await H.loadHost("198.51.100.5", 24);
    await sleep(220);
    const destCell = doc.querySelector("#h-dests tbody td.dcell");
    check("host-drill destinations open their host view",
          !!destCell && /open this destination/.test(destCell.title || ""), destCell ? destCell.title : "missing");
    const portRow = doc.querySelector("#h-ports tbody tr.clickable");
    if (portRow) {
      portRow.click();
      await sleep(220);
      check("a host-drill port row lands in Netflow filtered to the port",
            doc.getElementById("view-netflow").classList.contains("active")
            && H.NF_FILTERS.some((f) => f.field === "dport"));
      try { H.nfRemoveChip("dport"); } catch (_e) { /* chip shape changed; the filter check stands */ }
    }
    const zRow = doc.querySelector("#h-zeek tbody tr.clickable");
    if (zRow) {
      zRow.click();
      await sleep(250);
      check("a host-drill service opens that log in the Zeek view",
            doc.getElementById("view-zeek").classList.contains("active"));
    }
    const aRow = doc.querySelector("#h-anoms tbody tr.clickable");
    if (aRow) {
      aRow.click();
      await sleep(250);
      check("a host-drill anomaly row opens its evidence",
            doc.getElementById("view-evidence").classList.contains("active")
            && /198\.51\.100\.5/.test((doc.getElementById("ev-title") || {}).textContent || ""),
            (doc.getElementById("ev-title") || {}).textContent || "");
    }
    H.showView("host");
    await sleep(120);
    doc.getElementById("h-close").click();
    await sleep(120);
    check("the host drill DISMISSES with its Close",
          doc.getElementById("h-results").classList.contains("hidden"));
    fetchOverride = null;
    // 3. the identity detail's exits.
    H.showView("identity");
    await H.loadIdentity();
    await sleep(180);
    const idRowE = [...doc.querySelectorAll("#id-table tbody tr")]
      .find((tr) => /203\.0\.113\.10/.test(tr.textContent));
    if (idRowE) {
      idRowE.click();
      await sleep(120);
      check("the identity detail carries its exits",
            !!doc.getElementById("id-detail-open") && !!doc.getElementById("id-detail-close"));
      doc.getElementById("id-detail-close").click();
      check("...and Close dismisses it",
            doc.getElementById("id-detail-card").classList.contains("hidden"));
      idRowE.click();
      await sleep(80);
      doc.getElementById("id-detail-open").click();
      await sleep(220);
      check("...and 'Open host view' lands on the host's view",
            doc.getElementById("view-host").classList.contains("active"));
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
          check("...and clicking it lands on that rule's card",
                doc.getElementById("view-blocked").classList.contains("active")
                && !doc.getElementById("bl-rule-card").classList.contains("hidden")
                && /r-filed-1/.test(doc.getElementById("bl-rule-id").textContent)
                && doc.getElementById("bl-rule-card").classList.contains("flash-hit"),
                "rule id=" + doc.getElementById("bl-rule-id").textContent);
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
            { class: "unowned_detector", severity: "warn", subject: "DBSCAN",
              detail: "console-only: no owner", elapsed_s: null,
              fix: { view: "anomalies", detector: "DBSCAN", label: "register it (registry strip)" } },
          ],
          counts: { expired_rule: 1, stuck_rule: 1, unowned_detector: 1 }, errors: {} }) })
      : null);
    H.showView("health");
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
      const slRow = [...doc.querySelectorAll("#sl-table tbody tr.sl-rule-row")]
        .find((r) => r.getAttribute("data-rule-id") === "r-live-1");
      check("an expired-rule fix lands ON the rule's row in Sluice",
            doc.getElementById("view-sluice").classList.contains("active")
            && !!slRow && slRow.classList.contains("flash-hit"),
            "row=" + !!slRow + " cls=" + (slRow ? slRow.className : "n/a"));
    }
    const blFix = fixBtns.find((b) => /Blocked/.test(b.textContent));
    if (blFix) {
      blFix.click();
      await sleep(300);
      check("a stuck-rule fix lands on the rule's card on Blocked",
            doc.getElementById("view-blocked").classList.contains("active")
            && /r1/.test(doc.getElementById("bl-rule-id").textContent)
            && doc.getElementById("bl-rule-card").classList.contains("flash-hit"),
            "id=" + doc.getElementById("bl-rule-id").textContent);
    }
    const detFix = fixBtns.find((b) => /registry/.test(b.textContent));
    if (detFix) {
      H.showView("anomalies");
      await H.loadAnomalies();
      await sleep(200);
      detFix.click();
      await sleep(250);
      const detRow = [...doc.querySelectorAll("#detectors-table tbody tr")]
        .find((r) => r.getAttribute("data-detector") === "DBSCAN");
      check("a registry fix lands ON the detector's row",
            doc.getElementById("view-anomalies").classList.contains("active")
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
    await H.loadWeirlings();
    const revBox = doc.getElementById("wl-revoked");
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
            doc.getElementById("view-weirlings").classList.contains("active")
            && /edge-retired/.test((doc.getElementById("wl-detail-id") || {}).textContent || ""),
            (doc.getElementById("wl-detail-id") || {}).textContent || "");
    }
    revBox.checked = false;
    fetchOverride = null;
    H.showView("health");
    await H.loadAudit();
    await sleep(150);
  }

  // ── THE CLICK GRAMMAR, LIVE (US-4) ──────────────────────────────────────────────────────────
  {
    const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
    // 1. the palette has a visible door.
    const palBtn = doc.getElementById("palette-btn");
    check("the palette has a visible entry in the chrome", !!palBtn);
    if (palBtn) {
      palBtn.click();
      await sleep(120);
      check("...and the button opens it",
            !doc.getElementById("palette").classList.contains("hidden"),
            "palette hidden=" + doc.getElementById("palette").classList.contains("hidden"));
      if (typeof H.paletteClose === "function") H.paletteClose();
    }
    // 2. the fleet row opens its sheet (a hover wash must not be the whole story).
    H.showView("weirlings");
    await H.loadWeirlings();
    await sleep(200);
    const fleetRow = [...doc.querySelectorAll("#wl-table tbody tr")].find((r) => /clickable/.test(r.className));
    check("a fleet row carries the row-level cue", !!fleetRow);
    if (fleetRow) {
      fleetRow.click();
      await sleep(250);
      check("...and the row opens that sensor's sheet",
            !doc.getElementById("wl-detail-card").classList.contains("hidden")
            && ((doc.getElementById("wl-detail-id") || {}).textContent || "").length > 0,
            "id=" + ((doc.getElementById("wl-detail-id") || {}).textContent || ""));
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
              anomaly_score: 0.8, severity: "medium", detected_by_models: "DBSCAN", n: 3,
              review_state: "", reviewed_at: null, windows: [
                { window: "2026-10-17T11:00:00", review_state: "", review_note: "", reviewed_at: null }] },
          ],
          severity_counts: {}, discipline: null, watch_error: null }) })
      : null);
    H.showView("anomalies");
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
        anomaly_score: 0.91, severity: "high", detected_by_models: "Isolation Forest, DBSCAN",
        n: 1, review_state: "", reviewed_at: null, windows: [
          { window: "2026-10-17T10:55:00", review_state: "", review_note: "", reviewed_at: null }],
        owner: "ops", matched_rule: "x", primary_deviation_feature: "bytes_z", baseline_comparison: "" },
    ], severity_counts: {}, discipline: null, watch_error: null };
    fetchOverride = (u) => (String(u).includes("/api/evidence")
      ? Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => ({
          available: true, hostname: "host.example", src_addr: "198.51.100.5",
          window_start: "2026-10-17T10:55:00", window_end: "2026-10-17T11:00:00",
          anomaly: { severity: "high", anomaly_score: 0.91, detected_by_models: "Isolation Forest",
                     baseline_comparison: "", attack_techniques: "" },
          flow_summary: { bytes: 1000, packets: 9, flows: 3, unique_destinations: 1, unique_ports: 1 },
          flows: [], errors: null }) })
      : String(u).includes("/api/anomalies")
      ? Promise.resolve({ ok: true, status: 200, statusText: "OK", json: async () => AN_ONE })
      : null);
    H.showView("anomalies");
    await H.loadAnomalies();
    await sleep(250);
    const jobRow = doc.querySelector("#anomalies-table tbody tr");
    check("JOB investigate-anomaly: the row is on screen", !!jobRow);
    clicks = 0;
    C(jobRow);                                   // 1: the row -> Evidence
    await sleep(280);
    check("JOB investigate-anomaly: understanding is ONE click (row -> Evidence)",
          clicks === 1 && doc.getElementById("view-evidence").classList.contains("active"),
          `clicks=${clicks}`);
    note("investigate-anomaly", "understand", clicks);
    const evVerb = doc.querySelector("#ev-verdict .gate-open");
    clicks = 0;
    if (evVerb) {
      C(evVerb);                                 // 1: the block verb (form = the BF-9 echo)
      await sleep(180);
      const fileBtn = [...doc.querySelectorAll("#ev-verdict .gate-form button")]
        .find((b) => /File block/.test(b.textContent));
      if (fileBtn) { C(fileBtn); await sleep(320); }   // 2: file
    }
    const act1 = clicks;
    const post1 = POSTED.slice(-1)[0] || {};
    check("JOB investigate-anomaly: acting is TWO clicks (verb + file) and posts the block",
          act1 === 2 && /\/api\/sluice\/block/.test(post1.url || "")
          && /198\.51\.100\.5/.test(post1.body || ""),
          `clicks=${act1} post=${(post1.url || "none")} body=${String(post1.body || "").slice(0, 60)}`);
    note("investigate-anomaly", "act", act1);
    fetchOverride = null;

    // ── JOB 2: block a domain from where it is seen (verb on the row) ────────────────────────
    H.showView("dns");
    await H.loadDns();
    await sleep(220);
    const dnsRow = doc.querySelector("#dn-rows tr.dc-row");
    const blockVerb = dnsRow
      ? [...dnsRow.querySelectorAll("button")].find((b) => /^Block/.test(b.textContent.trim()))
      : null;
    check("JOB block-domain: the verb lives ON the row that shows the domain", !!blockVerb);
    clicks = 0;
    if (blockVerb) {
      C(blockVerb);                              // 1: open the composer (target+blast on screen)
      await sleep(180);
      const modeSel = doc.getElementById("rc-mode");
      if (modeSel) {
        modeSel.value = "block";
        modeSel.dispatchEvent(new window.Event("change", { bubbles: true }));
      }
      check("JOB block-domain: choosing block mode is not a click (a select, not a step)",
            clicks === 1, `clicks=${clicks}`);
      const createBtn = doc.getElementById("rc-create");
      if (createBtn) {
        C(createBtn);                            // 2: arms -- the retained BF-9 echo
        await sleep(100);
        check("...the echo is on the button before it writes",
              /Confirm/.test(createBtn.textContent), createBtn.textContent);
        C(createBtn);                            // 3: commits
        await sleep(320);
      }
      const cancelBtn = doc.getElementById("rc-cancel");
      if (cancelBtn) cancelBtn.click();
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
    await H.loadAnomalies();
    await sleep(300);
    const regCell = [...doc.querySelectorAll("#detectors-table tbody .dcell")]
      .find((el2) => /DBSCAN/.test(el2.textContent));
    check("JOB quiet-detector: the registry row offers its verb", !!regCell);
    clicks = 0;
    if (regCell) {
      C(regCell);                                // 1: filter the queue to this detector
      await sleep(350);
    }
    const uq3 = clicks;
    check("JOB quiet-detector: understanding is ONE click (registry row -> its alerts)",
          uq3 === 1 && H.AN_FILTERS.model === "DBSCAN"
          && AN_REQS.some((u) => u.includes("model=DBSCAN")),
          `clicks=${uq3} model=${H.AN_FILTERS.model} asked=${AN_REQS.length ? AN_REQS[AN_REQS.length - 1] : "none"}`);
    note("quiet-detector", "understand", uq3);
    const ackBtn = [...doc.querySelectorAll("#anomalies-table .review-act")]
      .find((b) => b.textContent === "ack");
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
    await H.loadAnomalies();
    await sleep(250);
    const jobHostCell = [...doc.querySelectorAll("#anomalies-table tbody td.dcell")]
      .find((td) => /open this host's view/.test(td.title || ""));
    check("JOB find-and-inspect: the host cell is on the row", !!jobHostCell);
    clicks = 0;
    if (jobHostCell) {
      C(jobHostCell);                            // 1: the host's own view, traffic included
      await sleep(320);
    }
    check("JOB find-and-inspect: ONE click from the row to the host's traffic",
          clicks === 1 && doc.getElementById("view-host").classList.contains("active")
          && (doc.getElementById("h-stats").textContent || "").length > 0,
          `clicks=${clicks} stats=${(doc.getElementById("h-stats").textContent || "").slice(0, 40)}`);
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
        anomaly_score: 0.91, severity: "high", detected_by_models: "DBSCAN", n: 1,
        review_state: "", reviewed_at: null, owner: "ops",
        windows: [{ window: "2026-10-17T10:55:00", review_state: "", reviewed_at: null }] },
      { detected_at: "2026-10-17T11:05:00", window_start: "2026-10-17T11:00:00",
        window_end: "2026-10-17T11:05:00", src_addr: "198.51.100.5", hostname: "host.example",
        anomaly_score: 0.80, severity: "medium", detected_by_models: "DBSCAN", n: 3,
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
    window.location.hash = "#v=anomalies&tr=6&an.host=198.51.100.5&an.model=DBSCAN";
    H.applyURLState();
    H.showView("anomalies");
    await H.loadAnomalies();
    await sleep(300);
    check("ARRIVAL: the link's filters and range land active",
          H.AN_FILTERS.host === "198.51.100.5" && H.AN_FILTERS.model === "DBSCAN"
          && Number(H.trHours()) === 6,
          `host=${H.AN_FILTERS.host} model=${H.AN_FILTERS.model} h=${H.trHours()}`);
    check("ARRIVAL: a removable chip explains the link's filters",
          [...doc.querySelectorAll("#an-filters .dc-chip")]
            .some((c) => /arrived with filters/.test(c.textContent)),
          (doc.getElementById("an-filters").textContent || "").slice(0, 90));
    check("ARRIVAL: the header says showing X of Y",
          /showing 4 of 40 alerts/.test((doc.getElementById("an-count-line") || {}).textContent || ""),
          (doc.getElementById("an-count-line") || {}).textContent || "no line");

    // 2) RETURN from Evidence: the labeled exit; chips, range and SCROLL all survive.
    const rowA = doc.querySelector("#anomalies-table tbody tr");
    check("RETURN: an alert row is on screen to drill into", !!rowA);
    if (rowA) { rowA.click(); }
    await sleep(320);
    const evCrumb = [...doc.querySelectorAll("#crumbs .crumb")].slice(-1)[0];
    check("RETURN: Evidence's exit is LABELED with its destination",
          !!evCrumb && /Anomalies/.test(evCrumb.textContent),
          evCrumb ? evCrumb.textContent : "no crumb");
    scrollTo = [];
    if (evCrumb) { evCrumb.click(); }
    await sleep(1250);
    check("RETURN: the origin's filters survive the round trip",
          H.AN_FILTERS.host === "198.51.100.5" && H.AN_FILTERS.model === "DBSCAN",
          `${H.AN_FILTERS.host} / ${H.AN_FILTERS.model}`);
    check("RETURN: the time window is unchanged", Number(H.trHours()) === 6, String(H.trHours()));
    check("RETURN: the scroll is restored after the view re-renders",
          scrollTo.some(([x, y]) => x === 0 && y === EXPECT_SCROLL), JSON.stringify(scrollTo));

    // 3) RETURN from the host drill: same guarantees, and the drill asked the GLOBAL window.
    await sleep(200);
    const jobHostCell = [...doc.querySelectorAll("#anomalies-table tbody td.dcell")]
      .find((td) => /open this host's view/.test(td.title || ""));
    HOST_REQS.length = 0;
    if (jobHostCell) { jobHostCell.click(); }
    await sleep(380);
    const hCrumb = [...doc.querySelectorAll("#crumbs .crumb")].slice(-1)[0];
    check("HOST RETURN: the jump lands with the labeled way back",
          doc.getElementById("view-host").classList.contains("active")
          && !!hCrumb && /Anomalies/.test(hCrumb.textContent),
          hCrumb ? hCrumb.textContent : "no crumb");
    check("HOST RETURN: the drill answers the GLOBAL window (hours=6), not a hardcoded 24",
          HOST_REQS.some((u) => /hours=6/.test(u)), HOST_REQS.join(" ").slice(0, 120));
    scrollTo = [];
    if (hCrumb) { hCrumb.click(); }
    await sleep(1250);
    check("HOST RETURN: filters and range survive, scroll restored",
          H.AN_FILTERS.host === "198.51.100.5" && Number(H.trHours()) === 6
          && scrollTo.some(([x, y]) => x === 0 && y === EXPECT_SCROLL),
          `${H.AN_FILTERS.host} / ${H.trHours()} / ${JSON.stringify(scrollTo)}`);

    // 4) COPY LINK round trip: the URL forces the CURRENT state; re-applying it from a cold
    //    state reproduces everything (a fresh boot's own path, driven again).
    let COPIED = "";
    try {
      Object.defineProperty(window.navigator, "clipboard",
        { value: { writeText: async (t) => { COPIED = String(t); } }, configurable: true });
    } catch (_e) { /* leave it; the check below will say why */ }
    const cbtn = doc.getElementById("copy-link");
    if (cbtn) { cbtn.click(); }
    await sleep(150);
    check("COPY: the link forces the current state (view + filters + range)",
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
          H.AN_FILTERS.host === "198.51.100.5" && H.AN_FILTERS.model === "DBSCAN"
          && Number(H.trHours()) === 6
          && doc.getElementById("view-anomalies").classList.contains("active"),
          `${H.AN_FILTERS.host} / ${H.AN_FILTERS.model} / ${H.trHours()} / active=` +
          doc.getElementById("view-anomalies").classList.contains("active"));

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
    H.showView("host");
    await H.loadAssets();
    await sleep(300);
    const facet = [...doc.querySelectorAll("#as-facets .dc-chip")];
    check("ASSETS: the inventory offers service filter chips",
          facet.length >= 2, `chips=${facet.length}`);
    const beforeRows = doc.querySelectorAll("#as-table tbody tr").length;
    if (facet[0]) { facet[0].click(); }
    await sleep(200);
    const svcLabel = facet[0] ? facet[0].textContent.split(" \u00b7 ")[0].trim() : "";
    // The render REPLACES the chips, so the clicked node is detached and reads stale: ask the
    // fresh set which chip is pressed (the DOM is the contract, not the node we held).
    const pressedNow = [...doc.querySelectorAll("#as-facets .dc-chip")]
      .find((c) => c.getAttribute("aria-pressed") === "true");
    check("ASSETS: clicking the chip filters the inventory in place and marks it pressed",
          !!pressedNow && H.ASSETS_STATE.svc === svcLabel
          && pressedNow.textContent.startsWith(svcLabel),
          `pressed=${pressedNow ? pressedNow.textContent.trim() : "none"} svc=${H.ASSETS_STATE.svc}`);
    const sumTxt = (doc.getElementById("as-summary") || {}).textContent || "";
    check("ASSETS: the summary says showing X of Y with the reason",
          /\d+ of \d+ hosts with service/.test(sumTxt) && sumTxt.includes(svcLabel), sumTxt);
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
          && [...doc.querySelectorAll("#as-facets .dc-chip")]
               .some((c) => c.getAttribute("aria-pressed") === "true"),
          `wiped=${wiped} now=${H.ASSETS_STATE.svc}`);
    const pressedFacet = [...doc.querySelectorAll("#as-facets .dc-chip")]
      .find((c) => c.getAttribute("aria-pressed") === "true");
    if (pressedFacet) { pressedFacet.click(); await sleep(120); }   // stop filtering

    // B) NETWORK: the tracked-only chip filters the map, is pressed, rides the URL.
    H.showView("network");
    await H.loadNetwork();
    await sleep(250);
    H.ASSETS_STATE.tracked = ["203.0.113.42", "203.0.113.1"];
    H.renderNetwork();
    await sleep(120);
    const nwChip = doc.getElementById("nw-only-tracked");
    if (nwChip) { nwChip.click(); }
    await sleep(150);
    check("NETWORK: the tracked-only chip filters the map and is pressed",
          nwChip && nwChip.getAttribute("aria-pressed") === "true"
          && /showing 2 of 3 hosts/.test((doc.getElementById("nw-caption") || {}).textContent || ""),
          `pressed=${nwChip ? nwChip.getAttribute("aria-pressed") : "none"} ` +
          `caption=${(doc.getElementById("nw-caption") || {}).textContent || ""}`);
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
          && doc.getElementById("nw-only-tracked").getAttribute("aria-pressed") === "true");
    if (nwChip) { nwChip.click(); await sleep(120); }   // release
    H.ASSETS_STATE.tracked = [];
    H.renderNetwork();

    // C) DISCOVER: the feed switch applies, rides the URL, and the reload asks for it.
    H.showView("discover");
    await H.loadDiscover();
    await sleep(300);
    const feedSel = doc.getElementById("dc-feed");
    check("DISCOVER: the feed select is on screen", !!feedSel);
    if (feedSel) {
      feedSel.value = "dns";
      feedSel.dispatchEvent(new window.Event("change", { bubbles: true }));
    }
    await sleep(400);
    check("DISCOVER: the feed switch is applied (the summary speaks DNS)",
          /DNS/.test((doc.getElementById("dc-summary") || {}).textContent || ""),
          (doc.getElementById("dc-summary") || {}).textContent || "");
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
    // 1) the trail is a readable surface: who / what / why / when.
    H.showView("settings");
    await H.loadSettings();
    await sleep(450);
    const stTrail = doc.getElementById("st-audit");
    const trailRows = stTrail ? [...stTrail.querySelectorAll("tbody tr")] : [];
    check("US-10: the write trail lists its entries",
          trailRows.length >= 3,
          `${trailRows.length} row(s)`);
    const rowText = trailRows.map((r) => r.textContent).join(" | ");
    check("...with ACTOR, REASON and TARGET on each entry",
          /admin/.test(rowText) && /tighten after the scanner/.test(rowText)
          && /base_threshold/.test(rowText) && /edge-alive/.test(rowText),
          rowText.slice(0, 160));
    check("...and the filter menus are the table's own scopes and actions",
          stTrail && stTrail.querySelectorAll("select").length === 2
          && /settings/.test(stTrail.querySelector("select").textContent),
          stTrail ? stTrail.querySelector("select").textContent : "none");
    // 2) the settings provenance line links to the entry.
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
    const hit = doc.querySelector("#st-audit tr.wtl-hit");
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
          doc.getElementById("view-settings").classList.contains("active")
          && !!thrCard && !thrCard.classList.contains("collapsed"),
          thrCard ? `collapsed=${thrCard.classList.contains("collapsed")}` : "no threshold row");
    // 2) the rule surface states its reach, and each sensor opens its fleet sheet.
    H.showView("sluice");
    await H.loadSluice();
    await sleep(400);
    const reach = doc.getElementById("sl-reach");
    check("US-9: the rules surface states its reach",
          !!reach && /can act on \d+ sensor/.test(reach.textContent || ""),
          (reach && reach.textContent || "").slice(0, 130));
    const reachChip = reach && reach.querySelector("button.dc-chip");
    check("...with a sensor chip for a reachable sensor", !!reachChip,
          reachChip ? reachChip.textContent : "none");
    if (reachChip) { reachChip.click(); }
    await sleep(550);
    check("...and the chip opens that sensor's fleet sheet",
          !doc.getElementById("wl-detail-card").classList.contains("hidden")
          && ((doc.getElementById("wl-detail-id") || {}).textContent || "")
               === (reachChip ? reachChip.textContent : ""),
          `id=${(doc.getElementById("wl-detail-id") || {}).textContent || ""}`);
    if (typeof H.closeWeirling === "function") H.closeWeirling();
    H.showView("health");
    await sleep(150);
  }

  // ── DISCOVER: the raw-flow browser (the operator's ask, 2026-10-16) ────────────────────────
  {
    H.showView("discover");
    await H.loadDiscover();
    const dcRows = doc.querySelectorAll("#dc-rows tr.dc-row");
    check("Discover renders the flow rows the server served", dcRows.length === 2,
          "rows=" + dcRows.length);
    if (dcRows[0]) {
      dcRows[0].click();
      const detail = doc.querySelector("#dc-rows tr.dc-detail");
      check("a row opens its every-field detail", !!detail && /flow started/.test(detail.textContent),
            detail ? detail.textContent.slice(0, 60) : "no detail row");
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
    const feedSel = doc.getElementById("dc-feed");
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
              !!dnsBtn && doc.getElementById("view-host").classList.contains("active"));
        H.showView("discover");
        feedSel.value = "netflow";
        feedSel.dispatchEvent(new window.Event("change", { bubbles: true }));
        await new Promise((r) => setTimeout(r, 200));
      }
    }
    const dcVol = doc.getElementById("dc-volume");
    const hits = dcVol ? dcVol.querySelectorAll("rect.hit") : [];
    check("the Discover histogram buckets are clickable drill targets", hits.length >= 1,
          "hit rects=" + hits.length);
    const protoSel = doc.getElementById("dc-proto");
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
      const chips = doc.querySelectorAll("#dc-chips .dc-chip");
      check("clicking a source adds it as a chip", chips.length === 1 &&
            /src = 198\.51\.100\.20/.test(chips[0].textContent),
            "chips=" + [...chips].map((c) => c.textContent).join(" | "));
      const x = chips[0] ? chips[0].querySelector("button.dc-chip-x") : null;
      check("and the chip can be removed again", !!x, "no remove control on the chip");
      if (x) {
        x.click();
        await new Promise((r) => setTimeout(r, 60));
        check("removing the chip empties the filter row",
              doc.querySelectorAll("#dc-chips .dc-chip").length === 0,
              doc.getElementById("dc-chips").textContent.slice(0, 60));
      }
    }
    // ── A WEIRLING IS NAMED, NOT AN IP (the operator, 2026-10-16) ─────────────────────────────
    const wCell = doc.querySelector("#dc-rows tr.dc-row td.dcell[title*='weirling =']");
    check("the discover row names the weirling, not the exporter address",
          !!wCell && /weirvern/.test(wCell.textContent) && !/127\.0\.0\.1/.test(wCell.textContent),
          wCell ? wCell.textContent : "no weirling cell");
    const wSel = doc.getElementById("dc-sensor");
    const wOpt = wSel ? [...wSel.options].find((o) => o.value === "127.0.0.1") : null;
    check("the weirling filter shows the name but filters on the address",
          !!wOpt && /weirvern/.test(wOpt.textContent), wOpt ? wOpt.textContent : "no option");
    check("and its default option reads 'all weirlings'",
          !!wSel && /all weirlings/.test(wSel.options[0].textContent),
          wSel ? wSel.options[0].textContent : "");

  // ── THE BLOCKED TAB (the operator's ask: "We need a blocked tab too") ──────────────────────
  {
    H.showView("blocked");
    await H.loadBlocked();
    const sum = doc.getElementById("bl-summary").textContent;
    check("the blocked summary counts hits and blocking rules", /3 recorded hits/.test(sum) &&
          /1 blocking rule/.test(sum), sum.slice(0, 130));
    const hitRows = doc.querySelectorAll("#bl-hit-rows tr");
    // The old escape hatch here (`|| hitRows.length === 2`) was written against the sluice
    // hits panel, which is gone (the hits are read HERE now). The label check is the real one:
    // the first row must carry its rule/list chip.
    check("the hits table renders with rule/list labels",
          hitRows.length === 2 &&
          /rule|list/.test((doc.querySelector("#bl-hit-rows tr .chip") || {}).textContent || ""),
          "rows=" + hitRows.length);
    check("a rule hit and a list hit are distinguishable in the row",
          /rule/.test(doc.querySelector("#bl-hit-rows tr td:nth-child(2)").textContent) &&
          /list/.test(doc.querySelectorAll("#bl-hit-rows tr")[1].textContent),
          doc.querySelector("#bl-hit-rows tr").textContent.slice(0, 80));
    check("the blocking rules table names what it covers",
          /203\.0\.113\.7/.test(doc.getElementById("bl-block-rows").textContent),
          doc.getElementById("bl-block-rows").textContent.slice(0, 110));
    check("and the alerting rules are separate from the blockers",
          /ads\.example\.com/.test(doc.getElementById("bl-block-rows").textContent) &&
          !/track\.example\.net/.test(doc.getElementById("bl-block-rows").textContent) &&
          /track\.example\.net/.test(doc.getElementById("bl-alert-rows").textContent),
          "");
  }

  // ── OPENING A RULE FROM SLUICE ON A FRESH CONSOLE (#15) ─────────────────────────────────────
  //
  // The rule card is fed from BLOCKED_STATE.data, and clicking a Sluice row used to fabricate a
  // "not among the live rules / expired or revoked" placeholder whenever that payload had not
  // been fetched yet -- i.e. on every fresh console until the Blocked tab was visited, telling
  // the operator a live rule was dead. These checks drive the REAL click with the store in its
  // fresh state, assert the card opens editable with the real rule, prove the payload is
  // fetched ONCE (not once per click), and keep the genuine not-live case working.
  {
    fetchOverride = null;
    H.showView("sluice");
    await H.loadSluice();
    const savedBlocked = H.BLOCKED_STATE.data;
    H.BLOCKED_STATE.data = null;                 // the console never visited Blocked
    const fetches0 = BLOCKED_FETCHES;
    const slRow = (needle) => [...doc.querySelectorAll("#sl-table tbody tr.sl-rule-row")]
      .find((tr) => tr.textContent.includes(needle));
    const liveRow1 = slRow("ads.example.com");
    check("a live rule is listed on Sluice before Blocked was ever loaded", !!liveRow1);
    liveRow1.click();
    await new Promise((r) => setTimeout(r, 160));
    const modeSel = doc.getElementById("bl-rule-mode");
    check("clicking it opens the card EDITABLE -- not the fabricated not-live state",
          !!modeSel && !modeSel.disabled
          && doc.getElementById("bl-rule-id").textContent === "r1"
          && !/not among the live rules/.test(doc.getElementById("bl-rule-note").textContent),
          `id=${doc.getElementById("bl-rule-id").textContent} disabled=${modeSel ? modeSel.disabled : "missing"}`);
    check("the card carries the REAL rule (its mode and name, not a placeholder)",
          !!modeSel && modeSel.value === "block"
          && /ads\.example\.com/.test(doc.getElementById("bl-rule-body").textContent),
          modeSel ? `mode=${modeSel.value}` : "no mode select");
    check("the payload was fetched ON DEMAND, exactly once",
          BLOCKED_FETCHES === fetches0 + 1,
          `${BLOCKED_FETCHES - fetches0} fetch(es)`);
    slRow("track.example.net").click();
    await new Promise((r) => setTimeout(r, 160));
    check("opening a second rule does not refetch it",
          BLOCKED_FETCHES === fetches0 + 1
          && doc.getElementById("bl-rule-id").textContent === "r2",
          `${BLOCKED_FETCHES - fetches0} fetch(es); id=${doc.getElementById("bl-rule-id").textContent}`);
    slRow("203.0.113.6").click();               // r-revoked: not among the live sets
    await new Promise((r) => setTimeout(r, 160));
    check("a genuinely non-live rule still renders the not-live copy",
          /not among the live rules/.test(doc.getElementById("bl-rule-note").textContent)
          && doc.getElementById("bl-rule-mode").disabled === true);
    H.BLOCKED_STATE.data = savedBlocked;
  }

  // ── THE DNS VIEW (the operator's ask: "can we view dns on port 53") ────────────────────────
  {
    H.showView("dns");
    await H.loadDns();
    const rows = doc.querySelectorAll("#dn-rows tr.dc-row");
    check("the DNS view renders Q/A rows", rows.length === 2, "rows=" + rows.length);
    check("the summary names the NXDOMAIN count",
          /NXDOMAIN/.test(doc.getElementById("dn-summary").textContent),
          doc.getElementById("dn-summary").textContent.slice(0, 90));
    rows[0].click();
    await new Promise((r) => setTimeout(r, 150));
    const detail = doc.querySelector("tr.dn-detail");
    check("a row opens the full answers and the reverse map",
          !!detail && /ads\.example\.com/.test(detail.textContent),
          detail ? detail.textContent.slice(0, 140) : "no detail row");
    const act = detail
      ? [...detail.querySelectorAll("button.dc-chip")].find((b) => /\+ domain/.test(b.textContent))
      : null;
    if (act) act.click();
    await new Promise((r) => setTimeout(r, 40));
    check("a detail action filters the view",
          !!(act) && doc.getElementById("dn-domain").value === "ads.example.com",
          doc.getElementById("dn-domain").value);
    H.dnClear();
    check("clear empties the DNS filters", doc.getElementById("dn-domain").value === "", "");

    // ISSUE #38: the summary line respects the payload state, the way the panels below it
    // and blocked.js's pager already did. A failed read must not claim a count or a range;
    // an empty successful read must not render the impossible "1\u20130".
    const dnServe = (payload) => Promise.resolve(
      { ok: true, status: 200, statusText: "OK", json: async () => payload });
    fetchOverride = (u) => (String(u).includes("/api/dns")
      ? dnServe({ available: false, reason: "cannot reach ClickHouse: OperationalError",
                rows: [], total: 0, histogram: [], facets: {}, data_error: "x" })
      : null);
    await H.loadDns();
    const failedSummary = doc.getElementById("dn-summary").textContent;
    check("a FAILED dns read claims no query count and no range",
          /unavailable: cannot reach ClickHouse/.test(failedSummary)
          && !/\d+ quer/.test(failedSummary) && !/\d+\u2013\d+/.test(failedSummary),
          failedSummary.slice(0, 110));
    fetchOverride = (u) => (String(u).includes("/api/dns")
      ? dnServe({ available: true, reason: "", total: 0, limit: 100, offset: 0,
                 rows: [], histogram: [], facets: {}, bucket_s: 60 })
      : null);
    await H.loadDns();
    const emptySummary = doc.getElementById("dn-summary").textContent;
    check("an EMPTY successful dns read keeps its count and reads 0\u20130, never 1\u20130",
          /0 quer/.test(emptySummary) && /showing 0\u20130/.test(emptySummary)
          && !/1\u20130/.test(emptySummary),
          emptySummary.slice(0, 110));
    fetchOverride = null;
    await H.loadDns();
  }
  }
  // ── THE TIME CONTROL REACHES DISCOVER TOO (issue #30) ───────────────────────────────────
  {
    H.showView("discover");
    await H.loadDiscover();
    check("Discover names the window it is showing",
          /last 24 hours window/i.test(doc.getElementById("dc-window").textContent),
          doc.getElementById("dc-window").textContent);
    const dn0 = DISCOVER_REQS.length;
    H.trApply({ mode: "relative", hours: 6 });
    await new Promise((r) => setTimeout(r, 300));
    const dnLast = DISCOVER_REQS[DISCOVER_REQS.length - 1] || "";
    check("changing the range re-fetches Discover with the new hours",
          DISCOVER_REQS.length > dn0 && /hours=6/.test(dnLast),
          `requests=${DISCOVER_REQS.length - dn0}; last=${dnLast.slice(0, 70)}`);
    check("and Discover's window pill follows the header",
          /last 6 hours window/i.test(doc.getElementById("dc-window").textContent),
          doc.getElementById("dc-window").textContent);
    H.trApply({ mode: "relative", hours: 24 });
    await new Promise((r) => setTimeout(r, 300));
  }
  check("no JavaScript errors during any of the above", errors.length === 0,
        errors.slice(0, 3).join(" | "));



  console.log(notes.join("\n"));
  if (failures.length) {
    console.log("\n" + failures.join("\n"));
    console.log(`\n  ${failures.length} FAILED, ${notes.length} passed`);
    process.exit(1);
  }
  console.log(`\n  all ${notes.length} checks passed

`);
  // EXIT EXPLICITLY. jsdom keeps a live window (and its timers) alive after the checks finish, so
  // the process never returns on its own -- the success path used to fall off the end of main() and
  // hang. Every run in this session LOOKED fine only because it was piped through `grep`, which
  // returns as soon as the pipe closes: the harness reported success and then sat there. A test
  // runner that never exits cannot be a gate, and a CI timeout would be read as the tests failing
  // rather than as the harness failing to finish.
  process.exit(0);
}

main().catch((e) => { console.error("harness error:", e); process.exit(2); });
