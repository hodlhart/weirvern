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
  const { window } = dom;
  const doc = window.document;

  // Load the three scripts in the SAME ORDER index.html declares, reading them from disk so
  // this tests the shipping files rather than a copy.
  const order = [];
  doc.querySelectorAll("script[src]").forEach((s) => order.push(s.getAttribute("src")));
  check("index.html loads the scripts in the required order",
        JSON.stringify(order) === JSON.stringify(["/app.js", "/soc.js", "/assets.js", "/sluice.js",
                                                 "/weirlings.js"]),
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
                   loadNetwork, drawGraph, computeLayout, settleGraph, nodeTitle, edgeTitle,
                   toggleTracked, loadZeekLog, loadFlowDetail, openHost,
                     showView, loadSettings, loadHealthDeep,
                     STAGE, planStage, applyStage, discardStage, setToken, getToken, stageChange,
                     runSonar, stageSonarRecommendations, renderSonarNote,
                     runSiphonTest, renderTestNote,
                     loadZeek, loadNetflow, loadAnomalies, postReview, reviewCell,
                   chartFrame, svgEl, fmtBytes, el, renderStaleness, renderPager, showEdgeDetail, showNodeDetail, renderNearMisses, renderAlertAudit, settingControl, ALERTS_STATE, ALERTS_PAGE_SIZE,
                   AUTH, loadSession, doLogin, doLogout, loadUsers, boot, bootAuthed, showGate,
                   wrapTables, wireInfoButtons,
                   refreshChrome, getSession, setSession, createUser, setRole, changePassword,
                   loadIdentity, showIdentityDetail,
                   loadSluice, wireSluice, renderSluicePolicies, sluiceDuration,
                   loadWeirlings, renderWeirlings, openWeirling, wireWeirlings, wlAge,
                   wlStateChip, wlLoss, saveWeirling, clearWeirlingForm,
                   setWeirlingEnabled, revokeWeirling,
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
    caller: { username: "", role: "", via: "" },
    editable_keys: ["retrain_every_h", "base_threshold", "sensor_mode", "intercept_segment",
                    "pushover_enabled"],
    // The control spec rides with the payload (see cluster_config.SETTING_CONTROLS): the browser
    // renders the natural control from the SERVER's rule -- bounds and options included -- so
    // what the control permits and what the write path accepts cannot drift apart.
    controls: {
      retrain_every_h: { control: "number", min: 1, max: 720, step: 1, unit: "hours" },
      base_threshold: { control: "number", min: 0, max: 1, step: 0.01, unit: "a score fraction" },
      sensor_mode: { control: "select", options: ["loch", "siphon"] },
      intercept_segment: { control: "text" },
      pushover_enabled: { control: "toggle" },
    },
    titles: { detect: "Detection", sensor: "Sensor", runtime: "Storage and runtime" },
    groups: {
      detect: [
        { key: "retrain_every_h", label: "retrain every (h)", value: 6, secret: false,
          source: "setting", help: "How often the detectors are retrained. Default 6 hours." },
        { key: "base_threshold", label: "alert threshold", value: 0.35, secret: false,
          source: "setting",
          help: "The score a host-window must reach before it counts as an anomaly. Default 0.35." },
      ],
      sensor: [
        { key: "sensor_mode", label: "mode", value: "loch", secret: false, source: "setting",
          help: "loch watches passively; siphon puts this host in the traffic path. Default loch." },
        { key: "reverse_dns", label: "reverse DNS", value: "private", secret: false,
          source: "derived", help: "Resolves only private addresses by default." },
        { key: "intercept_segment", label: "intercept segment", value: "(not set)",
          secret: false, source: "env", help: "The segment the siphon intercept operates on." },
        // Deliberately ALREADY EQUAL to what the Sonar stub recommends: this row is how the
        // harness proves the staging dedupe (an unchanged recommendation stages nothing).
        { key: "intercept_gateway", label: "intercept gateway", value: "198.51.100.1",
          secret: false, source: "env", help: "The gateway whose identity is forged." },
      ],
      runtime: [
        { key: "clickhouse_host", label: "ClickHouse host", value: "clickhouse", secret: false,
          source: "setting", help: "Hostname of the ClickHouse service. Default clickhouse." },
        { key: "clickhouse_password", label: "ClickHouse password",
          value: `(set, ${SECRET_SENTINEL.length} chars)`, secret: true, source: "setting",
          help: "Read from the weirvern-secrets Secret at startup. Never shown in value." },
        { key: "pushover_enabled", label: "Pushover", value: "disabled", secret: false,
          source: "setting",
          help: "Whether real push notifications are sent. Off logs only." },
        { key: "pushover_api_token", label: "Pushover API token", value: "(not set)",
          secret: true, source: "setting", help: "The Pushover application token." },
        { key: "version", label: "version", value: "0.5.6", secret: false, source: "derived",
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
  // Two rows deliberately: one UNREVIEWED and one already acked with a note. A single-row stub
  // cannot catch a renderer that draws every row with the same chip, and the states are what the
  // column exists to distinguish.
  const ANOMALIES_PAYLOAD = [
    { detected_at: "2026-01-02T09:12:00", window_start: "2026-01-02T09:10:00",
      window_end: "2026-01-02T09:15:00", src_addr: "203.0.113.42", hostname: "workstation.lan",
      anomaly_score: 0.91, confidence: 0.8, severity: "high",
      detected_by_models: "Isolation Forest, DBSCAN", model_agreement: 0.7,
      isolation_forest_score: 0.9, gradient_boosting_score: 0.4, dbscan_score: 0.8,
      baseline_score: 0.2, primary_deviation_feature: "unique_dst_ports",
      primary_deviation_zscore: 5.2, deviation_magnitude: 3.1,
      feature_contributions: { unique_dst_ports: { z: 5.2 }, total_bytes: { z: 1.1 } },
      baseline_comparison: "unique_dst_ports is 5.2 sigma above this host's baseline",
      review_state: "", review_note: "", reviewed_at: null },
    { detected_at: "2026-01-02T08:00:00", window_start: "2026-01-02T07:55:00",
      window_end: "2026-01-02T08:00:00", src_addr: "192.0.2.40", hostname: "vault",
      anomaly_score: 0.72, confidence: 0.6, severity: "medium",
      detected_by_models: "Adaptive Baseline", model_agreement: 0.5,
      isolation_forest_score: 0.4, gradient_boosting_score: 0.3, dbscan_score: 0.2,
      baseline_score: 0.7, primary_deviation_feature: "total_bytes",
      primary_deviation_zscore: 3.4, deviation_magnitude: 2.0,
      feature_contributions: {}, baseline_comparison: "total_bytes is 3.4 sigma above baseline",
      review_state: "ack", review_note: "nightly backup job",
      reviewed_at: "2026-01-02T08:05:00" },
  ];

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
  enabled: true, iface: "eth1", live: 2,
  criticality: "high",
  gate: {
    available: true, state: "armed", iface: "eth1", mgmt_iface: "eth0",
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
  rules: [
    { rule_id: "r-live-1", describes: "from 198.51.100.7/32", src_cidr: "198.51.100.7/32",
      dst_cidr: "", protocol: "", dst_port: 0, direction: "forward", live: true, revoked: false,
      origin: "manual", severity: "", created_by: "admin", origin_ref: "",
      reason: "scanner on the lab segment", expires_at: "", expires_in_s: 1800 },
    { rule_id: "r-live-2", describes: "from 198.51.100.9/32 tcp/22", src_cidr: "198.51.100.9/32",
      dst_cidr: "", protocol: "tcp", dst_port: 22, direction: "forward", live: true, revoked: false,
      origin: "detection", severity: "high", created_by: "detection", origin_ref: "w-123",
      reason: "detection: severity high at confidence 0.91", expires_at: "", expires_in_s: 900 },
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

  const ROUTES = [];
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
                    ? { ok: true, applied: sent.changes || {}, restarted: ["deploy/weirvern-worker"],
                        restart_errors: [], note: "restarted deploy/weirvern-worker" }
                  : u.includes("/api/settings/sonar") ? SONAR_REPLY
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
                    ? { ok: true, state: sent.state || "", note: sent.note || "" }
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
      const payload = row ? { available: true, reason: null, sensor: row } : WEIRLINGS_DETAIL_PAYLOAD;
      return Promise.resolve({ ok: true, status: 200, statusText: "OK",
                               json: async () => payload });
    }
    for (const [match, payload] of ROUTES) {
      if (u.includes(match)) {
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
      age_s: 4.0, last_seen: "2026-09-23T12:00:00+00:00",
      capture_loss_pct: 0.0, packets_recv: 900000, packets_dropped: 0, hosts: 12,
      note: "ops owns this one", stale_after_s: 45,
      findings: ["reporting normally, last heard 4s ago."],
    },
    {
      sensor_id: "edge-stopped", state: "stale", is_problem: true,
      address: "", segment: "second floor", reported_segment: "",
      expected_mode: "loch", reported_mode: "loch", enabled: true, registered: true,
      age_s: 900.0, last_seen: "2026-09-23T11:45:00+00:00",
      capture_loss_pct: null, packets_recv: null, packets_dropped: null, hosts: 0,
      note: "", stale_after_s: 45,
      findings: ["last reported 900s ago, past the 45s freshness window, so it has stopped. It ran "
        + "and then stopped, which is different from never starting: look for why it died rather "
        + "than why it never came up.",
        "no capture-loss measurement, so packet loss is unknown rather than zero."],
    },
    {
      sensor_id: "edge-promised", state: "never_seen", is_problem: true,
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
      address: "198.51.100.44", segment: "", reported_segment: "",
      expected_mode: "", reported_mode: "loch", enabled: false, registered: false,
      age_s: 2.0, last_seen: "2026-09-23T12:00:00+00:00",
      capture_loss_pct: 3.5, packets_recv: 1000, packets_dropped: 35, hosts: 3,
      note: "", stale_after_s: 45,
      findings: ["this sensor is feeding the hub but is not registered, so nobody declared it."],
    },
    {
      sensor_id: "edge-off", state: "disabled", is_problem: false,
      address: "", segment: "spare", reported_segment: "",
      expected_mode: "loch", reported_mode: "", enabled: false, registered: true,
      age_s: 90000.0, last_seen: "2026-09-22T11:00:00+00:00",
      capture_loss_pct: null, packets_recv: null, packets_dropped: null, hosts: 0,
      note: "pulled for maintenance", stale_after_s: 45,
      findings: ["this sensor is registered but switched off, so it is not expected to report."],
    },
    {
      sensor_id: "edge-moved", state: "alive", is_problem: false,
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

  ROUTES.push(
    ["/api/health", HEALTH_PAYLOAD],
    ["/api/graph", GRAPH_PAYLOAD],
    ["/api/flows", FLOWS_PAYLOAD],
    ["/api/settings", SETTINGS_PAYLOAD],
    ["/api/zeek", ZEEK_PAYLOAD],
    ["/api/session", SESSION_STUB],
    ["/api/users", USERS_PAYLOAD],
    ["/api/identity", IDENTITY_PAYLOAD],
    ["/api/sluice", SLUICE_PAYLOAD],

    // WEIRLINGS. The DETAIL route is handled ABOVE this table because it must be
    // REQUEST-AWARE: it answers for the sensor asked about, like the real server. A static
    // payload served one sensor's row under every name, which would let a check on registering
    // an undeclared sensor act on a registered one's data.
    ["/api/weirlings", WEIRLINGS_PAYLOAD],


    // The anomalies list, for the SOC-1 review-column checks. Registered LAST so its match
    // cannot shadow the others; the dispatcher takes the first hit and /api/anomalies shares
    // no prefix with any of the above.
    ["/api/anomalies", ANOMALIES_PAYLOAD],
  );

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
  check("Health sits between Models and Settings in the nav",
        navAtLoad.indexOf("models") < navAtLoad.indexOf("health")
          && navAtLoad.indexOf("health") < navAtLoad.indexOf("settings"),
        `nav is ${navAtLoad.join(", ")}`);


  // ── the Zeek tab ───────────────────────────────────────────────────────────────────────────
  // THIS SECTION EXISTS BECAUSE ITS ABSENCE SHIPPED A BUG. The Zeek tab rendered a summary and an
  // empty bar chart while the API returned all 18 logs correctly: the rows were mapped to one shape
  // and the accessors read another, so the formatter threw on undefined and took the panel down.
  // Nothing caught it because the harness never loaded this view, and its stub served an EMPTY
  // payload -- which renders a legitimate "nothing in this window" note rather than crashing.
  //
  // A tab with no coverage is a tab whose bugs reach the user. Every view now gets exercised.
  H.showView("zeek");
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

  // ── SONAR: the survey button ──────────────────────────────────────────────────────────────
  // The button must exist with its help, a click must hit the sonar route, and the
  // recommendations must land as STAGED changes (the pending-changes review step) rather
  // than being applied straight away.
  check("the Sonar button exists with the sensor's settings",
        !!doc.getElementById("st-sonar"));
  check("the Sonar button carries its own ? explanation",
        !!doc.getElementById("st-sonar-help") &&
        /ARP/.test(doc.getElementById("st-sonar-help-text").textContent),
        (doc.getElementById("st-sonar-help-text") || {}).textContent);
  check("the Sonar explanation starts hidden",
        doc.getElementById("st-sonar-help-text").classList.contains("hidden"));
  const sonarBefore = POSTED.filter((r) => r.url.includes("/api/settings/sonar")).length;
  await H.runSonar();
  check("Sonar POSTs to the sonar route",
        POSTED.filter((r) => r.url.includes("/api/settings/sonar")).length === sonarBefore + 1,
        POSTED.map((r) => r.url).join(","));
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
  check("every setting renders as a key/value row, not a JSON blob",
        vals.length === expectedRows,
        `rendered ${vals.length} rows, payload has ${expectedRows}`);

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

  // And the MOVED row's "?" works in its new home: the sensor's own explanation is still the
  // server's text for that row, revealed by that row's button.
  const modeRow = doc.querySelector(".setting[data-key='sensor_mode']");
  modeRow.querySelector(".setting-help-btn").click();
  check("the moved sensor row's ? still explains THAT row from its new home",
        modeRow.querySelector(".setting-help").textContent.includes("loch watches"),
        modeRow.querySelector(".setting-help").textContent.slice(0, 90));
  modeRow.querySelector(".setting-help-btn").click();

  // A choice setting is a DROPDOWN carrying the server's options. sensor_mode's row now lives
  // with the sensor (the weirling drill-down), so the query is document-wide: the control must
  // be the same control wherever its row renders.
  const modeSel = doc.querySelector('select[data-key="sensor_mode"]');
  check("a choice setting renders as a dropdown", !!modeSel);
  const modeOpts = modeSel ? [...modeSel.options].map((o) => o.value) : [];
  check("the dropdown carries the server's option list",
        modeOpts.includes("loch") && modeOpts.includes("siphon"), modeOpts.join(","));
  const postsBeforeChoice = POSTED.length;
  if (modeSel) {
    modeSel.value = "siphon";
    modeSel.dispatchEvent(new window.Event("change", { bubbles: true }));
  }
  check("choosing from the dropdown stages the choice without writing",
        POSTED.length === postsBeforeChoice, `${POSTED.length - postsBeforeChoice} request(s) sent`);
  check("the staged choice is the chosen value", H.STAGE.changes.sensor_mode === "siphon",
        JSON.stringify(H.STAGE.changes));
  if (modeSel) {
    modeSel.value = "loch";   // back to the running value: un-stages it again
    modeSel.dispatchEvent(new window.Event("change", { bubbles: true }));
  }

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
  check("the anomalies table renders a row per payload entry", anomRows.length === 2,
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

check("a never-seen IN-PATH sensor says the segment may be waiting",
      wlText().includes("IN-PATH") || wlText().includes("in-path"),
      "an in-path sensor that never came up is more urgent than a passive one and must say why");

check("an UNDECLARED sensor is reported as unregistered",
      wlText().includes("unregistered"),
      "a sensor feeding the hub that nobody declared is security-relevant, the same class as an "
      + "unexpected NetFlow exporter");

check("a DISABLED sensor is shown as disabled, not as a fault",
      wlText().includes("disabled"),
      "switched-off sensors are not problems; raising them trains the reader to ignore the column");

// ── measured-zero vs not-measured, at the DOM ────────────────────────────────────────────────
// The em dash is what an unmeasured value renders as. Asserting the DASH and not merely
// "something rendered": 0.0% for a sensor that measured nothing would read as a perfect sensor.
{
  const rows = [...H.document.querySelectorAll("#wl-table tbody tr")];
  const rowFor = (id) => rows.find((tr) => (tr.textContent || "").includes(id));
  const stopped = rowFor("edge-stopped");
  const alive = rowFor("edge-alive");
  check("an UNMEASURED capture loss renders as a dash, not as 0.0%",
        stopped && /\u2014|—/.test(stopped.textContent || ""),
        "an unmeasured value rendered as 0.0% reports a sensor that has measured nothing as a "
        + "perfect one");
  check("a MEASURED zero loss renders as a real figure",
        alive && (alive.textContent || "").includes("0.0%"),
        "0.0% is 'we looked, nothing was lost' and must stay a measurement");
}

check("a segment the sensor CONTRADICTS is surfaced, not silently overwritten",
      wlText().includes("sixth floor"),
      "the declared segment and the observed one are different facts; letting the declaration "
      + "win makes a sensor covering the wrong segment look correctly placed");

check("high capture loss is called out in the fleet",
      wlText().includes("62.5"),
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
    check("an undeclared sensor offers a REGISTER button, not only prose",
          !!regBtn && !regBtn.classList.contains("hidden")
          && (regBtn.textContent || "").includes("Register"),
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
    const saveBtn = H.document.getElementById("wl-save");
    const saveNote = H.document.getElementById("wl-save-note");
    if (saveBtn) saveBtn.click();
    for (let i = 0; i < 40 && !(saveNote.textContent || "").includes("required"); i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    check("the register form's own Register button is WIRED too",
          !!saveBtn && (saveNote.textContent || "").includes("required"),
          "an empty id is refused client-side; silence here would mean the form's button is "
          + "decorative for the same reason");
  }
}

// ── the sensor's settings live WITH the sensor, not in the global Settings tab ───────────────
// Moved on request (2026-10-15): "configure each weirling" -- and the honest boundary is that a
// runtime can only be changed on the box that runs it. The server marks the LOCAL row; the
// drill-down mounts the settings there and gives every other row the sentence saying where its
// settings actually are, instead of knobs that would write to the wrong machine.
{
  const cfgHost = doc.getElementById("st-sensor");
  check("the sensor settings grid lives inside the weirling drill-down",
        !!(cfgHost && cfgHost.closest("#wl-detail-card")),
        "moving the panel without moving the element would leave loadSettings rendering into a "
        + "node no operator ever opens");
  check("the Settings tab points at the new home instead of holding the controls",
        /Weirlings/.test(doc.getElementById("view-settings").textContent)
        && !(cfgHost && cfgHost.closest("#view-settings")),
        "an operator looking in Settings must be told where the sensor settings went");
  check("Sonar and the test run moved with it",
        !!(doc.getElementById("st-sonar") || {}).closest
        && !!doc.getElementById("st-sonar").closest("#wl-detail-card")
        && !!doc.getElementById("st-test").closest("#wl-detail-card"),
        "half a sensor section in each view is the two-surfaces defect");
  const aliveRow = [...doc.querySelectorAll("#wl-table button")]
    .find((b) => (b.textContent || "") === "edge-alive");
  if (aliveRow) {
    aliveRow.click();
    for (let i = 0; i < 40 && !(doc.getElementById("wl-detail-body").textContent || "")
         .includes("reporting normally"); i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    check("a LOCAL sensor's drill-down offers its settings",
          !doc.getElementById("wl-sensor-config").classList.contains("hidden")
          && (doc.getElementById("st-sensor").textContent || "").includes("mode"),
          "the sensor on this hub is the one this hub can actually configure");
    check("and no 'settings live elsewhere' note on it",
          doc.getElementById("wl-sensor-remote").classList.contains("hidden"));
  }
  const stoppedRow = [...doc.querySelectorAll("#wl-table button")]
    .find((b) => (b.textContent || "") === "edge-stopped");
  if (stoppedRow) {
    stoppedRow.click();
    for (let i = 0; i < 40 && !(doc.getElementById("wl-detail-body").textContent || "")
         .includes("why it died"); i++) {
      await new Promise((r) => setTimeout(r, 20));
    }
    check("a sensor elsewhere does NOT get knobs that would write to the wrong machine",
          doc.getElementById("wl-sensor-config").classList.contains("hidden")
          && !doc.getElementById("wl-sensor-remote").classList.contains("hidden"),
          "the hub cannot reach a remote runtime; the panel must say where those settings live");
    doc.getElementById("wl-detail-close").click();
  }
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
