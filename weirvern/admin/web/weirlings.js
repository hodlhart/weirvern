// ── Weirlings: the fleet ─────────────────────────────────────────────────────────────────────
//
// WHAT THIS VIEW IS FOR. Every other panel in this GUI describes the sensors that ARE talking.
// This one describes the ones that are NOT, which is the question an operator actually has
// during a roll-out: "I registered a sensor on the third floor and nothing has appeared."
//
// THE ONE DISTINCTION THAT MATTERS MOST, and which every other surface collapses:
//
//     "you have no sensors"  vs  "a sensor is expected and has never reported"
//
// Both render as an empty table, and they need opposite actions -- one is a fresh install, the
// other is a broken box. The server carries that difference in the payload (`available`, and a
// per-row `state`), and this file's job is to never lose it on the way to the DOM.
//
// FOUR RULES THIS FILE FOLLOWS, each learned from this project's own failures:
//
//  1. A FAILED QUERY NEVER LOOKS LIKE AN EMPTY FLEET. `available: false` renders the reason in
//     place. A blank table during a registry outage reads as good news.
//
//  2. A STATE WORD ALONE IS NOT AN ANSWER. "stale" does not say whether the box is powered off
//     or its capture died. Every row carries the server's own sentences, phrased for the action
//     they imply, and the drill-down shows them in full.
//
//  3. "NOT MEASURED" IS NOT ZERO. Capture loss arrives as null when a sensor never measured it,
//     and renders as a dash rather than 0.0% -- which would show a sensor that measured nothing
//     as a perfect one.
//
//  4. THE PROBLEMS COME FIRST, and the row is clickable to the drill-down. A fleet view is a
//     tool, not a report.

// Seconds -> a short age phrase. Null means NEVER REPORTED, which is a different fact from "0
// seconds ago" and must not render as one.
function wlAge(seconds) {
  if (seconds === null || seconds === undefined) return "never";
  const s = Math.max(0, Math.round(seconds));
  if (s < 90) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 90) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

// The state chip. Colour carries the same information as the word, because an operator scanning
// a long table reads the colour first -- but the WORD is always present, so the meaning survives
// colourblindness and a screenshot pasted into a ticket.
function wlStateChip(state) {
  // STALE IS AMBER, NOT RED (the operator, 2026-10-16: "Fleet needs to be color coded by stale,
  // alive, unregistered etc"). A stale sensor reported and went quiet -- that deserves the eye,
  // but it is not the same fact as never-seen, which is a registration whose expectation FAILED.
  // Red is kept for exactly that, so the two do not blur into "something is wrong".
  const cls = (state === "alive") ? "ok"
    : (state === "disabled") ? "muted"
    : (state === "unregistered" || state === "stale") ? "warn"
    : "bad";
  const label = {
    alive: "alive",
    stale: "stale",
    never_seen: "never seen",
    unregistered: "unregistered",
    disabled: "disabled",
  }[state] || state || "unknown";
  return el("span", { class: `bubble state ${cls}`, text: label });
}

// Capture loss: null is NOT 0.0. A sensor that has never measured it must not read as perfect.
function wlLoss(v) {
  if (v === null || v === undefined) return "—";
  return `${Number(v).toFixed(1)}%`;
}

/** One status line, and close the Details it no longer explains. */
function wlSummaryNote(text) {
  const note = document.getElementById("wl-summary-note");
  if (note) note.textContent = text;
  const more = document.getElementById("wl-summary-details");
  if (more) { more.classList.add("hidden"); more.open = false; }
}

async function loadWeirlings() {
  if (typeof scheduleURLSync === "function") scheduleURLSync();
  // A REJECTED REQUEST MUST STILL SAY SOMETHING. `showView` fires this without awaiting it, so a
  // bare `await getJSON(...)` that rejects becomes an unhandled rejection: the panel keeps
  // whatever it had and no banner appears. Caught here and reported, NOT re-thrown -- a re-throw
  // reaches `showView`'s own `.catch(showError)`, which creates a SECOND banner, and the next
  // `clearError()` removes both.
  let d;
  try {
    // BOTH TOGGLES RIDE THE QUERY (issue #7, 2026-10-16): `revoked=1` was never sent, so ticking
    // the box refetched identical data and the revoked list could never appear, however long the
    // operator looked. Both read their live checkbox on every load -- which is also what keeps
    // them across the auto-refresh cycle, the same way `problems` always did.
    const params = [];
    if (document.getElementById("wl-problems-only").checked) params.push("problems=1");
    const revokedBox = document.getElementById("wl-revoked");
    if (revokedBox && revokedBox.checked) params.push("revoked=1");
    d = await getJSON(`/api/weirlings${params.length ? "?" + params.join("&") : ""}`);
  } catch (err) {
    showDataError(`the fleet could not be loaded: ${err && err.message ? err.message : err}`);
    return;
  }

  const summaryBox = document.getElementById("wl-summary");
  const noteBox = document.getElementById("wl-summary-note");
  const moreBox = document.getElementById("wl-summary-details");
  const moreText = document.getElementById("wl-summary-detail-text");
  summaryBox.replaceChildren();
  noteBox.textContent = "";
  if (moreText) moreText.textContent = "";
  if (moreBox) { moreBox.classList.add("hidden"); moreBox.open = false; }

  if (!d.available) {
    // THE DEFECT THIS PREVENTS: a registry outage rendering as a calm, empty, healthy fleet.
    showDataError(d.reason || "the weirling registry is unavailable");
    summaryBox.appendChild(emptyState({
      state: "failed",
      message: `Fleet unknown — ${d.reason || "the registry did not answer"}.` }));
    document.getElementById("wl-count").textContent = "";
    emptyRow(document.querySelector("#wl-table tbody"), 7,
      "The fleet cannot be shown while the registry is unreadable.", null, { state: "failed" });
    return;
  }
  showDataError(null);

  // ── the fleet's own state, first and largest
  const s = d.summary || {};
  const cov = d.network_coverage || {};
  const declaredNets = s.networks_declared;
  const observedNets = s.networks_observed ?? s.networks;
  // THE THIRD ELEMENT IS THE TILE'S MEANING, not its number: a count of zero needs no colour,
  // and a problem nobody can spot at a glance is a problem reported in sixpt grey.
  const problemsOnly = document.getElementById("wl-problems-only").checked;
  const items = [
    ["weirlings", String(s.total ?? "—"), "", ""],
    ["reporting", String(s.alive ?? "—"), (s.alive ?? 0) > 0 ? "ok" : "", "alive"],
    // BOTH NETWORK COUNTS (operator, 2026-11-20): "weirlings tab says we only have 1 network,
    // but we have 2." A single observed count sat beside a Settings page that declared two, and
    // the operator had no way to tell which number was wrong. Declared and seen are separate
    // facts; when they differ the note below names every declaration no sensor has seen.
    ["networks declared", declaredNets === null || declaredNets === undefined ? "—" : String(declaredNets),
      declaredNets > 0 ? "ok" : (cov.available ? "" : "warn"), "declared"],
    ["segments seen", String(observedNets ?? "—"),
      (observedNets ?? 0) > 0 ? "ok" : "", "observed"],
    ["stale", String(s.stale ?? "—"), (s.stale ?? 0) > 0 ? "warn" : "", "stale"],
    ["unregistered", String(s.unregistered ?? "—"), (s.unregistered ?? 0) > 0 ? "warn" : "", "unregistered"],
    ["disabled", String(s.disabled ?? "—"), (s.disabled ?? 0) > 0 ? "muted" : "", "disabled"],
  ];
  // THE COUNTS ARE FILTERS (BF-7; research: Security Onion's grid grammar). Clicking a count
  // narrows the worklist to exactly it; the active filter is visibly the active one. The two
  // network tiles are READING counts, not states: they scroll to the coverage card, where the
  // declared-but-unobserved rows live.
  for (const [k, v, cls, state] of items) {
    const countOnly = state === "declared" || state === "observed";
    const active = countOnly ? false
      : (state === "problem"
        ? problemsOnly
        : (state ? WL_FILTERS.state === state : (!WL_FILTERS.state && !problemsOnly)));
    const title = state === "declared"
      ? (cov.available === false
        ? `the declared networks could not be read: ${cov.reason || "no reason reported"}`
        : "monitored networks declared in Settings — click to see every declaration and whether a sensor has seen it")
      : (state === "observed"
        ? "distinct segments a sensor is actually collecting — click to compare with the declarations"
        : (countOnly ? "a reading, not a filter" : (state ? `show ${k} only` : "clear every filter")));
    const attrs = { type: "button", title };
    if (!countOnly) attrs["data-state"] = state;
    const tile = el("button", {
      class: (cls ? `stat clickable ${cls}` : "stat clickable") + (active ? " active" : "")
        + (countOnly ? " stat-count" : ""),
      attrs,
      on: countOnly ? { click: () => {
        const target = document.getElementById("wl-network-list");
        if (target && target.scrollIntoView) {
          try { target.scrollIntoView({ block: "center" }); } catch (_e) { /* optional */ }
        }
      } } : { click: () => wlSetState(state) },
    }, [
      // TH-5 recipe, built inline: label above value; fleet counts carry no series, so no
      // sparkline is faked onto them.
      el("div", { class: "k", text: k }),
      el("div", { class: "v", text: v }),
    ]);
    summaryBox.appendChild(tile);
  }
  wlRenderViews();
  // A reading surface like the fleet table: its failure is reported by its own note rather
  // than blanking the fleet. It is loaded here so the coverage question is answered beside
  // the sensors that collect it.
  loadNetworkCoverage(d.network_coverage || null).catch(() => {});

  // ONE SHORT LINE, THE REASONING BEHIND DETAILS. A paragraph here sat above the scanner
  // card and said the same fact three ways (30+ words); the visible part is the count and the
  // network, and the "why the two counts differ" sentence is one click down. The server's own
  // sentences are kept verbatim there -- it knows whether the heartbeat read degraded, and
  // paraphrasing would lose the reason an operator acts on.
  const bits = [];
  const detailBits = [];
  if (d.heartbeats_available === false) {
    bits.push("Heartbeat read failed: every weirling below reads NEVER SEEN.");
    detailBits.push(`Heartbeats are unavailable (${d.heartbeat_reason || "the read did not run"}). `
      + `That is a gap in this view, not evidence about the weirlings.`);
  }
  if (d.filtered) bits.push("Showing problems only.");
  if (Array.isArray(cov.unobserved) && cov.unobserved.length) {
    // A DECLARATION WITH NO SENSOR BEHIND IT IS THE GAP, and it is named rather than folded
    // into a count. The operator declared these in Settings; no weirling is collecting them.
    const named = cov.unobserved.map((u) => `${u.cidr}${u.label ? ` (${u.label})` : ""}`);
    const shown = named.slice(0, 2).join(", ")
      + (named.length > 2 ? ` +${named.length - 2} more` : "");
    bits.push(`${named.length} declared network${named.length === 1 ? "" : "s"} `
      + `${named.length === 1 ? "has" : "have"} no sensor: ${shown}.`);
    detailBits.push(`No weirling has collected ${named.join(", ")}. Declared and seen are `
      + `different facts, not a disagreement: a declaration is the operator's expectation, `
      + `while the seen count is what sensors have collected.`);
  } else if (cov.available === false) {
    bits.push("Declared-network count unavailable; the seen count is still measured.");
    detailBits.push(`The declared-network count is unavailable (${cov.reason || "the read failed"}).`);
  }
  if ((s.total ?? 0) === 0 && d.heartbeats_available !== false) {
    bits.push("No weirlings registered.");
    detailBits.push("Register one below to record the expectation, so a weirling that never "
      + "comes up is reported rather than invisible.");
  }
  noteBox.textContent = bits.join(" ");
  if (moreText) moreText.textContent = detailBits.join(" ");
  if (moreBox) {
    moreBox.classList.toggle("hidden", detailBits.length === 0);
    if (!detailBits.length) moreBox.open = false;
  }

  // ── the rows
  // The local sensor's NIC ROLES come from its capture settings, not from a guess. Loaded here,
  // once per render, so the NIC sub-table can name eth0 as management and eth1 as capture.
  if ((d.sensors || []).some((r) => r.local) && typeof loadSettings === "function"
      && !Object.keys(SETTINGS_ROWS || {}).length) {
    try { await loadSettings(); } catch (_e) { /* the rows still render without config */ }
  }
  renderWeirlings(d.sensors || [], d.revoked || [], d.revoked_reason || "");
  wlRenderBulk();
  wlLoadRowPerformance(d.sensors || []);

  // THE FIRST RUN APPEARS ONLY WHILE THE FLEET HAS NEVER HAD A LIVE SENSOR -- onboarding, not
  // decoration; the moment one reports, it is gone for good (or for this tab, if skipped).
  const everLive = ((d && d.sensors) || []).length > 0;
  if (!everLive && !firstrunDismissed()) {
    firstrunShow(1);
  } else {
    firstrunHide();
  }

  const count = document.getElementById("wl-count");
  count.textContent = `— ${(d.sensors || []).length} shown`;
  // A LINK THAT NAMED A SENSOR OPENS IT. The pending drill-down is consumed here, once the
  // fleet the link describes has actually loaded -- never on a timer racing the fetch.
  if (PENDING_WL) {
    const wanted = PENDING_WL;
    PENDING_WL = "";
    openWeirling(wanted).catch(() => {});
  }
}

/* ── THE WORKLIST'S STATE (BF-7) ────────────────────────────────────────────────────────────
 * The fleet is a triage list, not a table: counts are filters, filters ride the URL, rows are
 * selectable, and filter sets are saved views (one built-in default: All sensors). All of it
 * is tab-local state -- the same rule as the stage: nothing here is a server state. */
const WL_FILTERS = { state: "" };
const WL_SELECTED = new Set();

const WL_BUILTIN_VIEWS = [
  { id: "all", label: "All sensors", state: "", problems: false },
  { id: "needs-action", label: "Needs action", state: "", problems: true },
  { id: "stale", label: "Stale", state: "stale", problems: false },
  { id: "unregistered", label: "Unregistered", state: "unregistered", problems: false },
];

function wlCustomViews() {
  try {
    const v = JSON.parse(window.sessionStorage.getItem("wv-wl-views") || "[]");
    return Array.isArray(v) ? v : [];
  } catch (_e) { return []; }
}
function wlPersistViews(views) {
  try { window.sessionStorage.setItem("wv-wl-views", JSON.stringify(views)); }
  catch (_e) { /* private mode: views live only in this page's memory then */ }
}
function wlRenderViews() {
  const sel = document.getElementById("wl-view");
  if (!sel) return;
  const current = sel.value;
  sel.replaceChildren();
  for (const v of WL_BUILTIN_VIEWS.concat(wlCustomViews())) {
    sel.appendChild(el("option", { text: v.label, attrs: { value: v.id } }));
  }
  if ([...sel.options].some((o) => o.value === current)) sel.value = current;
}
function wlApplyView(id) {
  const v = WL_BUILTIN_VIEWS.concat(wlCustomViews()).find((x) => x.id === id);
  if (!v) return;
  WL_FILTERS.state = v.state || "";
  const box = document.getElementById("wl-problems-only");
  if (box) box.checked = Boolean(v.problems);
  if (typeof scheduleURLSync === "function") scheduleURLSync();
  loadWeirlings().then(clearError).catch(showError);
}
function wlSaveView() {
  const label = (WL_FILTERS.state ? WL_FILTERS.state.replace("_", " ") : "all sensors") +
    (document.getElementById("wl-problems-only").checked ? " · needs action" : "");
  const views = wlCustomViews();
  views.push({ id: "custom-" + Date.now(), label,
               state: WL_FILTERS.state,
               problems: document.getElementById("wl-problems-only").checked });
  wlPersistViews(views);
  wlRenderViews();
}

function wlSetState(state) {
  if (state === "problem") {
    const box = document.getElementById("wl-problems-only");
    if (box) box.checked = !box.checked;
  } else if (state) {
    WL_FILTERS.state = WL_FILTERS.state === state ? "" : state;
  } else {
    WL_FILTERS.state = "";
    const box = document.getElementById("wl-problems-only");
    if (box) box.checked = false;
  }
  if (typeof scheduleURLSync === "function") scheduleURLSync();
  loadWeirlings().then(clearError).catch(showError);
}

function wlRenderBulk() {
  const bar = document.getElementById("wl-bulk");
  const n = document.getElementById("wl-bulk-n");
  if (!bar) return;
  const count = WL_SELECTED.size;
  bar.classList.toggle("hidden", count === 0);
  if (n) n.textContent = count === 1 ? "1 selected" : `${count} selected`;
  // THE BAR ONLY OFFERS WHAT THE SELECTION CAN DO. An undeclared sensor can be ADOPTED and
  // nothing else -- enable, disable, re-apply and revoke all refuse it server-side -- while a
  // declared one cannot be adopted again. Showing both groups for every selection is how a
  // button that always fails teaches the operator to stop reading the bar.
  const selected = (window.__wlRows || []).filter((r) => WL_SELECTED.has(r.sensor_id));
  const hasDeclared = selected.some((r) => r.registered);
  const hasUndeclared = selected.some((r) => !r.registered);
  for (const id of ["wl-bulk-enable", "wl-bulk-disable", "wl-bulk-reapply", "wl-bulk-revoke"]) {
    const btn = document.getElementById(id);
    if (btn) btn.classList.toggle("hidden", !hasDeclared);
  }
  const adopt = document.getElementById("wl-bulk-adopt");
  if (adopt) adopt.classList.toggle("hidden", !hasUndeclared);
  const revoke = document.getElementById("wl-bulk-revoke");
  if (revoke && count === 0) {
    delete revoke.dataset.armed;
    revoke.textContent = "Revoke selected";
  }
}

async function wlBulk(kind, btn) {
  const ids = [...WL_SELECTED];
  if (!ids.length) return;
  // DESTRUCTIVE OR PATH-TOUCHING ACTIONS ASK TWICE -- the same contract as every other
  // apply in this console (research: Security Onion's accept/deny with confirm).
  if ((kind === "revoke" || kind === "disable") && !btn.dataset.armed) {
    btn.dataset.armed = "1";
    btn.textContent = `Confirm: ${kind} ${ids.length}`;
    return;
  }
  delete btn.dataset.armed;
  const note = document.getElementById("wl-bulk-n");
  // BF-9: the second click (the confirm step) opens the ECHO -- the exact targets, the blast
  // radius, and the reason every revoke row records.
  let bulkReason = "";
  if (kind === "revoke") {
    if (typeof confirmDestructive !== "function") return;
    const verdict = await confirmDestructive({
      title: `Revoke ${ids.length} registration${ids.length === 1 ? "" : "s"}: the hub stops `
             + "expecting them.",
      target: ids.join(", "),
      blast: "their heartbeats stop being raised as missing; the records stay readable and a "
             + "revoked sensor can be registered again later",
      reasonHint: "why these are being retired",
    });
    if (!verdict.ok) {
      if (note) note.textContent = "nothing revoked — you declined the confirmation";
      return;
    }
    bulkReason = verdict.reason;
  }
  if (note) note.textContent = `working on ${ids.length}…`;
  let ok = 0;
  const failures = [];
  let skipped = 0;
  for (const id of ids) {
    const row = (window.__wlRows || []).find((r) => r.sensor_id === id);
    try {
      if (kind === "adopt") {
        // ADOPTION IS THE ONE BULK ACTION AN UNDECLARED SENSOR HAS. The declaration is filed
        // from the sensor's OWN reports -- id, address and reported mode -- and the declared
        // segment stays empty on purpose, exactly as the single-row Adopt does: copying a
        // reported value into the declaration would manufacture a fact nobody stated.
        if (!row || row.registered) { skipped += 1; continue; }
        await postJSON("/api/weirlings/register", {
          sensor_id: row.sensor_id,
          address: row.address || "",
          segment: "",
          expected_mode: row.reported_mode || "loch",
          note: "adopted from the fleet view while it was feeding unregistered",
        });
      } else if (kind === "enable" || kind === "disable") {
        if (!row || !row.registered) { skipped += 1; continue; }
        await postJSON("/api/weirlings/enable", { sensor_id: id, enabled: kind === "enable" });
      } else if (kind === "revoke") {
        if (!row || !row.registered) { skipped += 1; continue; }
        await postJSON("/api/weirlings/revoke", { sensor_id: id, reason: bulkReason });
      } else if (kind === "reapply") {
        // RE-APPLY = RE-PUSH THE SENSOR'S STORED PLAN. The apply route refuses an empty
        // `changes` on purpose (a write path with nothing to write is a lie); the sensor's
        // own plan values are what a re-apply means, so those are what is sent.
        if (!row || !row.registered || !row.plan ||
            !Object.values(row.plan).some((v) => String(v || "").trim())) {
          skipped += 1;
          continue;
        }
        await postJSON("/api/weirlings/apply", { sensor_id: id, changes: row.plan });
      }
      ok += 1;
    } catch (err) { failures.push(id); }
  }
  if (note) {
    // A VERB PER ACTION, not a suffix: `${kind}d` produced "adoptd".
    const verb = { adopt: "adopted", reapply: "re-applied" }[kind] || `${kind}d`;
    note.textContent = `${verb}: ${ok}` +
      (skipped ? `, skipped ${skipped}` : "") +
      (failures.length ? ` — failed: ${failures.join(", ")}` : "");
  }
  WL_SELECTED.clear();
  await loadWeirlings();
  wlRenderBulk();
}

/** WL-2: ONE SENTENCE ABOUT THE CHANGE, not a fact sheet. It names the state (and the first
 *  finding, when there is one) because a control whose situation is hidden is a control you
 *  press blind; everything else moved to the row, the Logs tab and this sheet's settings. */
/** Compact age for evidence lines; an unknown age says so rather than reading as zero. */
function wlAge(seconds) {
  if (seconds == null || !isFinite(seconds)) return "an unknown time";
  const s = Math.max(0, Math.round(Number(seconds)));
  if (s < 90) return `${s}s`;
  if (s < 5400) return `${Math.round(s / 60)}m`;
  if (s < 172800) return `${Math.round(s / 3600)}h`;
  return `${Math.round(s / 86400)}d`;
}

function wlSituation(r) {
  const state = String(r.state || "unknown").replace(/_/g, " ");
  const bits = [`state: ${state}` + (r.registered ? "" : " (not adopted)")];
  if (r.reported_mode) bits.push(`reported ${r.reported_mode}`);
  const box = el("div", { class: "wl-situation" }, [
    el("p", { class: "muted", text: bits.join(" · ") + "." }),
  ]);
  // CONFIGURED IS NOT OBSERVED (operator, 2026-10-19: "it says netflow is on, but from the tab
  // its not showing as working"). The sheet used to show only the settings that SAY flow capture
  // is on; this line states what the hub has actually seen, and names the two separately.
  const cap = [];
  const mode = r.reported_mode || r.expected_mode;
  if (mode) cap.push(`mode ${mode}`);
  // The sheet's evidence line makes the same distinction: a siphon is not a channel.
  if (wlChannelEnabled(r) && r.channel && r.channel.state) cap.push(`channel ${r.channel.state}`);
  const nf = r.netflow || {};
  // OBSERVED IS NOT FRESH (operator, 2026-11-12: "look at weirling when netflow is enabled").
  // A 24-hour count keeps a dead exporter looking healthy for a whole day; the row now states
  // the last flow's age and calls a silent feed stale.
  if (nf.known) {
    if (!nf.observed) {
      cap.push("no flows in 24h");
    } else if (nf.fresh) {
      cap.push(`${Number(nf.flows || 0).toLocaleString()} flows in 24h`
        + (nf.age_s != null ? ` \u00b7 last ${wlAge(nf.age_s)} ago` : ""));
    } else {
      cap.push(`NetFlow STALE \u2014 last flow ${wlAge(nf.age_s)} ago`);
    }
  }
  const zk = r.zeek || {};
  if (zk.known) cap.push(zk.observed ? `Zeek observed${zk.last_at ? ` ${zk.last_at}` : ""}` : "Zeek not observed");
  if (cap.length) box.appendChild(el("p", { class: "muted", text: `Evidence: ${cap.join(" \u00b7 ")}.` }));
  const first = (r.findings || [])[0];
  if (first) box.appendChild(el("p", { class: "muted", text: first }));
  if (r.local) {
    if (!r.registered) {
      box.appendChild(el("p", { class: "muted",
        text: "It has not been adopted into the fleet yet; adopt it below. Its settings are "
          + "available either way." }));
    }
  } else if (!r.registered) {
    box.appendChild(el("p", { class: "muted", text: "Adopt it below, then give it a plan." }));
  }
  return box;
}

/** WL-1: a twelve-bucket flow sparkline. NO SERIES IS NOT AN IDLE LINE: no samples means
 *  "not observed" and says so; a measured idle hour is a series of real zeroes. */
function wlSparkline(r) {
  let vals = Array.isArray(r.flow_series) ? r.flow_series : [];
  const ev = r.netflow || {};
  // A MEASURED ZERO STILL HAS A SHAPE (operator, 2026-10-19: "where is the flow trend line").
  // No series + a known exporter used to render as text only, so an idle sensor had no line to
  // read at all. A flat line at zero is the honest trend; a sensor with no address still gets
  // NO line, because that is not a measurement.
  const measuredZero = !vals.length && ev.known;
  if (measuredZero) vals = Array(12).fill(0);
  if (!vals.length) {
    // A MEASURED ZERO IS NOT A DASH (operator, 2026-10-19: "flow is not showing anything
    // either"). "—" means not measured; when the exporter is known and produced nothing, the
    // cell says 0 and the title says over what window. The reason is the one the server
    // computed, so it cannot drift from the netflow chip beside it.
    const why = ev.why || (!ev.known ? "no address reported yet"
      : (ev.flows ? "no flows in the last hour" : "no flows observed in 24h"));
    return el("span", { class: "muted mono spark-value",
                        text: ev.known ? `${Number(ev.flows || 0).toLocaleString()} flows` : "—",
                        attrs: { title: why } });
  }
  const w = 88, h = 22, pad = 2;
  const max = Math.max(1, ...vals);
  const step = vals.length > 1 ? (w - pad * 2) / (vals.length - 1) : 0;
  const total = vals.reduce((a, b) => a + b, 0);
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("class", "wl-spark");
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label",
    `${total} flows from this weirling in the last hour, by five-minute bucket`);
  const poly = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
  poly.setAttribute("points",
    vals.map((v, i) => `${pad + i * step},${h - pad - (v / max) * (h - pad * 2)}`).join(" "));
  poly.setAttribute("fill", "none");
  poly.setAttribute("stroke", "currentColor");
  poly.setAttribute("stroke-width", "1.5");
  svg.appendChild(poly);
  const sparkTitle = measuredZero
    ? `0 flows in the last hour \u2014 ${ev.why || "no flows observed in 24h"}`
    : `${total} flows in the last hour`;
  const wrap = el("span", { class: "wl-spark-wrap",
    attrs: { title: sparkTitle, "aria-label": sparkTitle } });
  wrap.appendChild(svg);
  if (measuredZero) {
    wrap.appendChild(el("span", { class: "muted mono wl-spark-zero", text: "0" }));
  }
  return wrap;
}

/** WL-1: a tap indicator. LIT only on evidence; SUBDUED with its reason otherwise. The word
 *  is always present -- colour is never the only signal. */
function wlTap(kind, info) {
  const i = info || {};
  // THE FEED IS NAMED "netflow" (operator, 2026-10-23). The old chip appended a generic scope
  // word on every NIC, which made one sensor-wide feed look like a per-NIC probe. The chip now
  // says netflow; the title carries the scope, and the NIC row passes its own object (see
  // wlNicFacts), so each selected NIC can show its own active indicator. The source setting is
  // a list, so eth1 and eth2 can both be active.
  const label = kind === "netflow" ? "netflow" : "zeek";
  const scope = i.scope === "sensor"
    ? ` — ${i.scope_note || "one sensor-wide feed; not attributed to this NIC"}`
    : (i.scope === "nic" && i.scope_note ? ` — ${i.scope_note}` : "");
  if (i.observed) {
    return el("span", { class: "tap on", text: label,
      attrs: { title: `${label} observed` + (i.last_at ? ` — last at ${i.last_at}` : "") + scope } });
  }
  return el("span", { class: "tap off", text: label,
    attrs: { title: `${label} not observed — ${i.why || "no evidence"}${scope}` } });
}

/** One local capture setting, by key, from the Settings payload the app already loaded. */
function wlCfg(key) {
  const row = (typeof SETTINGS_ROWS !== "undefined") ? SETTINGS_ROWS[key] : null;
  const v = row ? (row.value != null ? row.value : row.current) : "";
  return String(v == null ? "" : v).trim();
}

/** Every NON-MANAGEMENT NIC the heartbeat reports, with only the roles this hub can justify. */
function wlNicFacts(r) {
  // THE HEARTBEAT LIST IS NOT THE CONFIGURATION. The local hub's worker runs in a pod network
  // namespace and can only see its own eth0 while the host capture port is eth1; filtering the
  // reported list alone made the whole NIC table disappear. A configured capture port is still
  // a fact the hub knows, so it gets a line -- marked "configured, not reported" and without a
  // mode claim, because the heartbeat did not prove it.
  const reportedNames = new Set(Array.isArray(r.interfaces) ? r.interfaces : []);
  const configuredName = String((r.plan && r.plan.iface) || r.iface || "").trim();
  const names = [...reportedNames];
  if (configuredName && configuredName !== "lo" && !reportedNames.has(configuredName)) {
    names.push(configuredName);
  }
  const local = !!r.local;
  const mgmt = local ? wlCfg("mgmt_iface") : "";
  const capture = (local ? wlCfg("zeek_iface") : "")
    || String(r.iface || (r.plan && r.plan.iface) || "");
  const segment = (r.plan && r.plan.segment) || (local ? wlCfgValue("intercept_segment") : "")
    || r.segment || r.reported_segment || "";
  const mode = String(r.reported_mode || r.expected_mode || "").toLowerCase();
  // MANAGEMENT IS NOT A CAPTURE NIC (operator, 2026-10-19): it is excluded from this list,
  // not hidden with a dash. Every remaining interface gets its own line in the sensor's row.
  const plans = wlPlans();
  const hasPlans = Object.keys(plans).length > 0;
  // THE LABEL CAN COME FROM EITHER SIDE. The fleet payload normally carries `network_names`,
  // but a page loaded before an INTERFACE_NETWORKS apply has the old map; the settings rows it
  // already holds are the same mapping. Without this fallback eth2 rendered its CIDR where
  // eth1 rendered "Servers", which looked like the second NIC had no name at all.
  const localNames = local ? wlIfaceNames(wlStagedValue("interface_networks")) : {};
  const rows = names.filter((name) => !(mgmt && name === mgmt)).map((name) => {
    // PER-NIC PLAN, PER-NIC LINE. `capture` used to be the only NIC the row knew about, so
    // every capture line borrowed the sensor-level channel state. That made eth2 read
    // "channel enabled" when eth1 was the siphon port. The plan's own roles decide.
    const plan = plans[name] && typeof plans[name] === "object" ? plans[name] : {};
    const planMode = String(plan.mode || "").toLowerCase();
    const siphon = planMode === "siphon" || plan.siphon === true;
    const captureRole = plan.capture === true || (!hasPlans && capture === name);
    const role = siphon ? "siphon" : (plan.sluice === true ? "sluice"
      : (captureRole ? "capture" : "unassigned"));
    const hasNicPlan = Object.prototype.hasOwnProperty.call(plans, name);
    const reported = reportedNames.has(name);
    const lineMode = !reported ? ""
      : (siphon ? "siphon"
        : (planMode || (hasNicPlan ? (captureRole ? "loch" : "")
          : (captureRole ? mode : ""))));
    // NETFLOW IS THE NIC'S OWN INDICATOR. The live hub runs NETFLOW_MODE=active with
    // NETFLOW_IFACE=eth2; copying the sensor-wide object onto eth1 as well said eth1 carried
    // the same feed. Only the active source gets the measured state; every other NIC gets an
    // explicit off with the source's name. Passive/auto remains sensor-scoped and says so in
    // the title, because there is no per-NIC probe to attribute.
    const nf = r.netflow || {};
    const nfMode = String(wlCfgValue("netflow_mode") || "auto").trim().toLowerCase();
    const nfIfaces = wlIfaceList(wlCfgValue("netflow_iface"));
    const activeOwners = nfMode === "active"
      ? (nfIfaces.length ? nfIfaces : (capture ? [capture] : [])) : [];
    const nicNetflow = (() => {
      if (!local) {
        return Object.assign({}, nf, { scope: nf.scope || "sensor", scope_label: "netflow" });
      }
      if (nfMode === "active" && activeOwners.length && !activeOwners.includes(name)) {
        return { known: true, observed: false, flows: 0, last_at: "", scope: "nic",
                 scope_label: "netflow",
                 why: `active NetFlow samples ${activeOwners.join(", ")}` };
      }
      if (nfMode === "active" && activeOwners.includes(name)) {
        return Object.assign({}, nf, { scope: "nic", scope_label: "netflow",
          scope_note: "an active NetFlow probe samples this NIC" });
      }
      return Object.assign({}, nf, { scope: nf.scope || "sensor", scope_label: "netflow" });
    })();
    return {
      name, role, mode: lineMode, reported, netflow: nicNetflow,
      network_name: (r.network_names && r.network_names[name]) || localNames[name] || "",
      networks: (role === "capture" || role === "siphon")
        ? (plan.segment || (role === "capture" ? segment : "")) : "",
      // A CHANNEL BELONGS TO THE NIC THAT CARRIES IT, AND ONLY WHEN THE BRIDGE PAIR IS SET.
      // Siphon is an in-path MODE, not a channel; saying "channel enabled" for a siphon-only
      // NIC read as if the two ports had been bridged. The mode column carries siphon.
      channel: (siphon && wlChannelEnabled(r)) ? ((r.channel && r.channel.state) || "") : "",
    };
  });
  return { rows, capture, segment };
}

/** Each non-management NIC as its own line, placed immediately under the weirling's row.
 *  What the hub does not know says so; nothing is inferred. */
function wlNicRows(r) {
  const facts = wlNicFacts(r);
  return facts.rows.map((n) => {
    const capture = n.role === "capture";
    const row = el("tr", { class: "wl-nic-row clickable" }, [
      el("td", {}, [
        el("span", { class: "mono wl-nic-name", text: n.name }),
        el("span", { class: "muted", text: (() => {
          const label = n.network_name
            || (n.networks && n.networks !== "—" && n.networks !== "(not set)" ? n.networks : "");
          const provenance = n.reported ? "" : " (configured, not reported)";
          return label ? ` ${n.role} - ${label}${provenance}` : ` ${n.role}${provenance}`;
        })() }),
      ]),
      el("td", { class: "mono" + (n.mode ? "" : " muted"), text: n.mode || "—",
                 attrs: { title: !n.reported
                   ? "configured capture; this sensor's heartbeat did not list the interface"
                   : (n.mode
                     ? (String(r.expected_mode || "").toLowerCase()
                        && String(r.expected_mode).toLowerCase() !== n.mode
                          ? `the sensor reports ${n.mode}; the registry declares ${String(r.expected_mode).toLowerCase()}`
                          : "the mode the sensor reports running")
                     : "the sensor has not reported a mode") } }),
      el("td", { class: "mono" + (n.channel ? "" : " muted"), text: n.channel || "—",
                 attrs: { title: capture && r.channel ? (r.channel.why || "") : "no channel on this NIC" } }),
      el("td", { class: "mono" + (n.networks ? "" : " muted"), text: n.networks || "—" }),
      el("td", { class: "mono muted", attrs: { "data-wl-rate": n.name }, text: "—" }),
      // FLOW AND FEEDS BELONG TO EVERY NIC LINE (operator, 2026-10-20: "the flow trend and
      // feed indicators are missing"). They were gated on `capture`, so a siphon NIC -- the
      // one actually carrying traffic in path -- showed a dash in both columns. The trend is
      // the sensor's measured series (the hub does not split it per NIC), labelled as such;
      // suppressing it on a siphon line made a working feed look absent.
      (() => {
        const flowLabel = "the sensor's measured flow trend (the hub does not split it per NIC)";
        const cell = el("td", { class: "wl-flow-cell", attrs: {
          title: flowLabel, "aria-label": flowLabel,
        } }, [wlSparkline(r)]);
        if (typeof discoverDrill === "function") {
          const drillLabel = "open this sensor's flows in Discover";
          cell.classList.add("clickable");
          cell.title = drillLabel;
          cell.setAttribute("aria-label", drillLabel);
          cell.addEventListener("click", (ev) => {
            ev.stopPropagation();
            discoverDrill({ sensor: r.sensor_id });
          });
        }
        return cell;
      })(),
      el("td", {}, [el("span", { class: "wl-feeds" },
        [wlTap("netflow", n.netflow), wlTap("zeek", r.zeek)])]),
    ]);
    row.addEventListener("click", () => openWeirling(r.sensor_id, { nic: n.name }));
    return row;
  });
}

/** The ports the sensor actually sniffs: every reported NIC except management and loopback. */
function wlSniffingInterfaces(r) {
  const reported = String((r && r.iface) || "").trim();
  const ifaces = (Array.isArray(r && r.interfaces) ? r.interfaces : [])
    .filter((name) => name && name !== "lo");
  // THE CONSOLE'S mgmt_iface IS NOT THE SENSOR'S. Filtering a remote sensor's NIC list with the
  // console's own management port picked eth0 on every remote unit whenever the console's
  // management port was eth1. Use what the sensor reports; the local setting is only a default
  // for the console's own host.
  if (reported && ifaces.includes(reported)) return [reported];
  if (r && r.local) {
    const mgmt = String(wlCfgValue("mgmt_iface") || "eth0");
    return ifaces.filter((name) => name !== mgmt);
  }
  return ifaces;
}

/** Put this sensor's own reading in its row; a remote sensor says it has not reported one. */
function wlLoadRowPerformance(rows) {
  for (const r of rows) {
    const row = [...document.querySelectorAll("[data-wl-sensor-row]")]
      .find((node) => node.dataset.wlSensorRow === r.sensor_id);
    if (!row) continue;
    if (!r.local) {
      if (typeof renderSystemMetrics === "function") {
        renderSystemMetrics({ available: false, sensor: r.sensor_id,
          reason: "host metrics not reported" }, { sensor: r.sensor_id });
      }
      continue;
    }
    if (typeof loadSystemMetrics === "function") {
      loadSystemMetrics({ sensor: r.sensor_id, interfaces: wlSniffingInterfaces(r) })
        .catch(() => {});
    }
  }
}

function renderWeirlings(rows, revoked, revokedReason) {
  window.__wlRows = rows;   // the bulk actions re-read the selected rows' own values
  // A SELECTION THAT NO LONGER EXISTS MUST NOT LINGER. A row can disappear between loads --
  // an undeclared sensor stops talking and the server stops sending it, a registration is
  // revoked -- and a count for a row the operator cannot see would make the bulk bar act on
  // something invisible. Pruned here, where the new row set first becomes known.
  const present = new Set(rows.map((r) => r.sensor_id));
  for (const id of [...WL_SELECTED]) {
    if (!present.has(id)) WL_SELECTED.delete(id);
  }
  const tbody = document.querySelector("#wl-table tbody");
  tbody.replaceChildren();

  const showRevoked = document.getElementById("wl-revoked").checked;
  const stateFilter = WL_FILTERS.state;
  const visible = rows.filter((r) => !stateFilter || r.state === stateFilter);

  if (!visible.length) {
    const problemsOnly = document.getElementById("wl-problems-only").checked;
    emptyRow(tbody, 7,
      stateFilter
        ? `No sensor is in state "${stateFilter.replace("_", " ")}" right now.`
        : problemsOnly
          ? "No weirling has a problem right now."
          : "No sensors yet. Point a sensor's exporter at this hub — it appears here to adopt.",
      stateFilter || problemsOnly
        ? { label: "Show all", fn: () => {
              WL_FILTERS.state = "";
              const box = document.getElementById("wl-problems-only");
              if (box) box.checked = false;
              if (typeof scheduleURLSync === "function") scheduleURLSync();
              loadWeirlings().then(clearError).catch(showError);
            } }
        : { label: "How adding works", fn: () => openHelpPanel("wl-info") },
      { state: stateFilter || problemsOnly ? "filtered" : "none",
        filters: [stateFilter ? `state = ${stateFilter}` : "",
                  problemsOnly ? "problems only" : ""].filter(Boolean),
        word: stateFilter || problemsOnly ? "Nothing matches" : "" });
  }

  for (const r of visible) {
    // The row's LEFT EDGE carries the state (the .wl-state-* rules); the words below carry
    // only what a reader scans for. Findings prose stays out of the list: the Logs tab owns
    // issues, and the problem dot's title carries the first sentence.
    const tr = el("tr", { class: `wl-state-${r.state || "unknown"} clickable` +
                                 (r.is_problem ? " row-problem" : "") });
    // THE SENSOR ROW IS THE SENSOR'S OWN MENU (operator, 2026-10-19): enable, disable,
    // delete, or adopt -- nothing else. Settings belong to a NIC line.
    tr.addEventListener("click", () => {
      if (typeof openSensorActions === "function") openSensorActions(r);
    });

    tr.appendChild(el("td", {}, [
      el("button", {
        class: "link",
        text: r.sensor_id,
        attrs: { title: "open this sensor's actions" },
        on: { click: (ev) => { ev.stopPropagation(); openSensorActions(r); } },
      }),
      // A WORD IN THE ROW, NOT ONLY A BORDER COLOUR (GitHub #56). "Stale", "never seen" and
      // "unregistered" are three different problems with three different fixes; the sheet had
      // the word, the fleet list did not. The chip carries it where the operator scans.
      wlStateChip(r.state),
      r.is_problem
        ? el("span", { class: "wl-problem-dot",
            attrs: { title: (r.findings || [])[0] || "needs attention",
                     "aria-label": "needs attention" } })
        : null,
    ].filter(Boolean)));

    // THE SENSOR ROW CARRIES THE NAME, NOT THE FACTS (operator, 2026-10-19: "the row with the
    // sensor name should not have filled in columns, on the nics"). Mode, channel, networks,
    // flow and feeds belong to each NIC line below; repeating them here put two versions of
    // the same fact in one row.
    // PERFORMANCE IS REAL TABLE COLUMNS (operator, 2026-10-19): CPU and memory on the sensor
    // row, throughput on each NIC row, all under their own headers rather than in a strip that
    // borrowed the mode/channel width.
    tr.setAttribute("data-wl-sensor-row", r.sensor_id);
    // Remote host counters are carried on the row as the raw JSON the agent measured. The
    // system sampler only knows the hub, so this is what lets a remote weirling show its own
    // CPU/memory instead of a dash.
    tr.setAttribute("data-wl-host", r.host_stats || "");
    // The CPU/memory reading has no column headers (operator, 2026-10-19), but keeps the
    // original value-over-label presentation in the sensor row.
    tr.appendChild(el("td", { class: "wl-sensor-rest", attrs: { colspan: "6" } }, [
      el("div", { class: "wl-perf-strip" }, [
        el("div", { class: "wl-perf-metric" }, [
          el("span", { class: "wl-perf-value", attrs: { "data-wl-cpu": r.sensor_id }, text: "—" }),
          el("span", { class: "wl-perf-label", text: "CPU" }),
        ]),
        el("div", { class: "wl-perf-metric" }, [
          el("span", { class: "wl-perf-value", attrs: { "data-wl-mem": r.sensor_id }, text: "—" }),
          el("span", { class: "wl-perf-label", text: "MEMORY" }),
        ]),
      ]),
    ]));

    tbody.appendChild(tr);
    // THE HEADERS SIT BELOW THE SENSOR NAME: the sensor's CPU/memory reading has no columns,
    // so the NIC headers follow it, directly above that sensor's interface lines.
    tbody.appendChild(el("tr", { class: "wl-colhead" }, [
      el("th", { text: "interface" }), el("th", { text: "mode" }),
      el("th", { text: "channel" }), el("th", { text: "networks" }),
      el("th", { text: "throughput" }), el("th", { text: "flow" }),
      el("th", { text: "feeds" }),
    ]));
    // EACH NON-MANAGEMENT NIC, IN PLACE (operator, 2026-10-19: "placed within the weirling
    // row"). Always visible, never behind a control: a NIC list you have to discover is the
    // same dead end the old evidence drill was.
    for (const nicRow of wlNicRows(r)) tbody.appendChild(nicRow);
  }

  // Revoked registrations are shown BESIDE the fleet, never inside it: a sensor somebody removed
  // must not read as a problem on every refresh, but "was this ever covered?" has to be
  // answerable or the cleanup erases the evidence.
  if (showRevoked) {
    if (revokedReason) {
      tbody.appendChild(el("tr", {}, [emptyStateCell(7, {
        state: "failed",
        message: `Revoked registrations could not be read: ${revokedReason}`,
      })]));
    } else if (!revoked.length) {
      tbody.appendChild(el("tr", {}, [emptyStateCell(7, {
        state: "none",
        message: "No sensor has been revoked.",
      })]));
    } else {
      for (const r of revoked) {
        const tr = el("tr", { class: "muted" });
        tr.appendChild(el("td", {}, [
          // US-3: a revoked registration is not a terminus -- the id still opens its sheet,
          // which carries the state and the actions. Inert text was the dead end.
          el("span", { class: "mono dcell",
                       attrs: { title: "open this sensor's sheet" },
                       on: { click: () => {
                         if (typeof openWeirling === "function") openWeirling(r.sensor_id).catch(() => {});
                       } } },
             [el("span", { text: r.sensor_id })]),
          el("span", { class: "muted", text: " (revoked)" }),
        ]));
        // SEVEN COLUMNS, not six: first cell plus colspan 6. The old 5 left the revoked row
        // short one column and it drifted under the wrong header.
        tr.appendChild(el("td", { attrs: { colspan: "6" } }, [
          el("span", { class: "bubble state muted", text: "revoked" }),
          el("span", { class: "muted",
                       text: r.revoked_at ? ` retired ${r.revoked_at}` : "" }),
        ]));
        tbody.appendChild(tr);
      }
    }
  }
}

// ── the drill-down ────────────────────────────────────────────────────────────────────────────

// The sensor the detail card is showing RIGHT NOW. The action buttons read the DOM at click time
// (the wiring runs once, at startup), and the register action files a declaration from the
// sensor's OWN reports -- never from anything an operator would have to retype -- so it needs the
// sensor object, not a re-parse of the rendered text. One place to set, so a click can never act
// on the PREVIOUS sensor's row.
let wlDetail = null;

/** TH-4: THE ONE WAY OUT OF THE DRILL-DOWN SHEET. Escape, a click on the scrim, the Close
 *  button, and the breadcrumb's back segment all land here. The mechanics (scrim, Escape, focus)
 *  are the sheet standard's, in sheets.js -- this function only names the exit. */
function closeWeirling() {
  const card = document.getElementById("wl-detail-card");
  if (!card || !sheetIsOpen(card)) return;
  closeSheet(card);
}

// ── the sensor's own actions ────────────────────────────────────────────────────────────────
// THE SENSOR ROW IS A MENU, NOT A SETTINGS FORM (operator, 2026-10-19): enable, disable,
// delete, or adopt. Settings live on the NIC lines. Kept as its own sheet so the two jobs
// cannot be confused by a shared close button or a stray field.
let WL_ACTION_ROW = null;
let WL_SENSOR_CARD = null;

function wlSensorCard() {
  if (WL_SENSOR_CARD && document.body.contains(WL_SENSOR_CARD)) return WL_SENSOR_CARD;
  const card = el("div", { class: "card sheet hidden",
    attrs: { id: "wl-sensor-card", role: "dialog", "aria-modal": "true",
             "aria-labelledby": "wl-sensor-title" } }, [
    el("div", { class: "sheet-head" }, [
      el("h2", { attrs: { id: "wl-sensor-title" }, text: "Sensor" }),
      el("button", { class: "quiet sheet-close", text: "Close",
        attrs: { type: "button", id: "wl-sensor-close" } }),
    ]),
    el("p", { class: "muted", attrs: { id: "wl-sensor-state" }, text: "" }),
    el("p", { class: "muted", attrs: { id: "wl-sensor-note" }, text: "" }),
    // THE CHANNEL PAIR IS A SENSOR DECISION, NOT A NIC DECISION (operator, 2026-10-19:
    // "This is configured when you select the top row with the sensor name"). It lives on the
    // sensor's own sheet; the NIC sheet only reports and enforces the consequences.
    el("div", { class: "nic-section", attrs: { id: "wl-sensor-channel" } }, [
      el("h4", { text: "Channel" }),
      el("div", { class: "controls" }, [
        el("label", { text: "upstream " }, [
          el("select", { attrs: { id: "wl-sensor-channel-upstream" },
            on: { change: () => wlSensorChannelChanged() } }),
        ]),
        el("label", { text: "downstream " }, [
          el("select", { attrs: { id: "wl-sensor-channel-downstream" },
            on: { change: () => wlSensorChannelChanged() } }),
        ]),
      ]),
      el("p", { class: "muted", text: "Join these two ports into one in-line channel. They must be " +
        "different interfaces; the worker verifies the bridge before claiming it is active." }),
      el("p", { class: "muted", text: "While a channel is active, siphon mode and passive " +
        "NetFlow are unavailable: they would fight the bridge." }),
      el("div", { class: "controls" }, [
        el("button", { attrs: { type: "button", id: "wl-sensor-channel-apply" },
          text: "Apply channel", on: { click: () => wlSensorChannelApply() } }),
      ]),
      el("p", { class: "muted", attrs: { id: "wl-sensor-channel-note", role: "status",
        "aria-live": "polite" }, text: "" }),
    ]),
    el("div", { class: "sheet-actions" }, [
      el("button", { class: "quiet", attrs: { type: "button", id: "wl-sensor-adopt" },
        text: "Adopt", on: { click: () => wlSensorAdopt() } }),
      el("button", { class: "quiet", attrs: { type: "button", id: "wl-sensor-enable" },
        text: "Enable", on: { click: () => wlSensorEnable(true) } }),
      el("button", { class: "quiet", attrs: { type: "button", id: "wl-sensor-disable" },
        text: "Disable", on: { click: () => wlSensorEnable(false) } }),
      el("button", { class: "danger", attrs: { type: "button", id: "wl-sensor-delete" },
        text: "Delete", on: { click: () => wlSensorDelete() } }),
    ]),
  ]);
  document.body.appendChild(card);
  if (typeof wireSheet === "function") wireSheet(card, { scrimId: "wl-sensor-scrim" });
  WL_SENSOR_CARD = card;
  return card;
}

function openSensorActions(r) {
  if (!r) return;
  WL_ACTION_ROW = r;
  const card = wlSensorCard();
  // THE CHANNEL PAIR BELONGS TO EVERY WEIRLING, not just the hub. A channel is a bridge on
  // the sensor's OWN NICs, and its plan row is where the pair lives (068_weirling_channel.sql);
  // gating this on `r.local` hid the only control a remote unit needed. The section is offered
  // when the sensor reports enough ports to bridge, and the selects use ITS interfaces.
  const channelBox = document.getElementById("wl-sensor-channel");
  const offered = wlChannelOffered(r);
  if (channelBox) channelBox.classList.toggle("hidden", !offered.show);
  // mgmt_iface comes from the deployment settings; the read is needed so the sheet excludes
  // the same management port the plan write validates against. It does not gate the section.
  const ready = (typeof loadSettings === "function")
    ? loadSettings().catch(() => {}) : Promise.resolve();
  // THE SHEET IS REUSED. If another sensor was opened while settings were loading, its row is
  // the truth now; this captured one must not paint stale options over it.
  ready.then(() => {
    if (WL_ACTION_ROW === r) wlPopulateSensorChannel(r);
  }).catch(() => {});
  document.getElementById("wl-sensor-title").textContent = r.sensor_id;
  document.getElementById("wl-sensor-state").textContent =
    `${r.state || "unknown"} · ${r.registered ? (r.enabled ? "enabled" : "disabled") : "not adopted"}`
    + (r.is_problem ? " · needs attention" : "");
  document.getElementById("wl-sensor-note").textContent = "";
  const show = (id, on) => {
    const b = document.getElementById(id);
    if (b) b.classList.toggle("hidden", !on);
  };
  show("wl-sensor-adopt", !r.registered);
  show("wl-sensor-enable", Boolean(r.registered && !r.enabled));
  show("wl-sensor-disable", Boolean(r.registered && r.enabled));
  show("wl-sensor-delete", Boolean(r.registered));
  openSheet(card, { scrimId: "wl-sensor-scrim", initialFocus: "wl-sensor-close" });
}

async function wlSensorEnable(enabled) {
  const r = WL_ACTION_ROW;
  if (!r) return;
  const note = document.getElementById("wl-sensor-note");
  note.textContent = enabled ? "enabling…" : "disabling…";
  try {
    const d = await postJSON("/api/weirlings/enable", { sensor_id: r.sensor_id, enabled });
    if (!d || d.ok !== true) throw new Error((d && d.error) || "the server refused");
    closeSheet(WL_SENSOR_CARD);
    await loadWeirlings();
  } catch (err) {
    note.textContent = `Could not ${enabled ? "enable" : "disable"}: ${err && err.message ? err.message : err}`;
  }
}

async function wlSensorAdopt() {
  const r = WL_ACTION_ROW;
  if (!r) return;
  // The sheet's Adopt is ONE action that lands on the existing registration path: close this
  // menu, open the sensor's sheet, and press its own Adopt. That keeps the observed-identity
  // fill and the "Registered ..." outcome in the one place that already proves them.
  closeSheet(WL_SENSOR_CARD);
  await openWeirling(r.sensor_id);
  const btn = document.getElementById("wl-detail-register");
  if (!btn) {
    document.getElementById("wl-detail-note").textContent =
      "This sensor cannot be adopted from here; open it from the fleet.";
    return;
  }
  btn.click();
}

async function wlSensorDelete() {
  const r = WL_ACTION_ROW;
  if (!r) return;
  if (typeof confirmDestructive !== "function") return;
  const verdict = await confirmDestructive({
    title: `Delete ${r.sensor_id}: the hub stops expecting it.`,
    target: r.sensor_id,
    blast: "its heartbeats stop being raised as missing; the record stays readable and it can "
           + "be registered again later",
    reasonHint: "why this sensor is being retired",
  });
  if (!verdict.ok) return;
  const note = document.getElementById("wl-sensor-note");
  note.textContent = "deleting…";
  try {
    const d = await postJSON("/api/weirlings/revoke",
                             { sensor_id: r.sensor_id, reason: verdict.reason });
    if (!d || d.ok !== true) throw new Error((d && d.error) || "the server refused");
    closeSheet(WL_SENSOR_CARD);
    await loadWeirlings();
  } catch (err) {
    note.textContent = `Could not delete: ${err && err.message ? err.message : err}`;
  }
}

async function openWeirling(sensorId, opts = {}) {
  // US-2: the sheet lives on THIS view, and callers now arrive from other views (a sluice
  // gate's sensor, the palette, an audit fix). A sheet opened onto an inactive view is an
  // invisible dead end; ensure the view first, for every caller.
  if (typeof showView === "function") showView("weirlings");
  const card = document.getElementById("wl-detail-card");
  const body = document.getElementById("wl-detail-body");
  const note = document.getElementById("wl-detail-note");
  document.getElementById("wl-detail-id").textContent = sensorId;
  wlDetail = null;
  // THE SETTINGS PANELS ARE NOT IN THIS CARD ANY MORE (the operator, 2026-10-16: "move
  // weirling setting back to the settings page... select the weirling and then set setting").
  // They live in Settings -> Weirling settings, driven by that page's selector; this card is
  // status and actions, and points there.
  body.replaceChildren(el("p", { class: "muted", text: "loading…" }));
  note.textContent = "";
  // THE SHEET STANDARD (sheets.js): scrim, focus and Escape are not this module's job.
  openSheet(card, { scrimId: "wl-sheet-scrim" });
  // THE DRILL-DOWN'S PATH BACK (TH-3): Fleet > Weirlings > <sensor>; the middle segment and
  // the sheet's own exits all route through closeWeirling so they can never disagree.
  if (typeof setCrumbs === "function") {
    setCrumbs([
      { label: "Fleet" },
      { label: "Weirlings", title: "back to the fleet list", run: () => closeWeirling() },
      { label: sensorId },
    ]);
  }

  let d;
  try {
    d = await getJSON(`/api/weirlings/detail?sensor=${encodeURIComponent(sensorId)}`);
  } catch (err) {
    body.replaceChildren(emptyState({
      state: "failed",
      message: `Could not read this sensor: ${err && err.message ? err.message : err}` }));
    return;
  }

  if (!d.available) {
    body.replaceChildren(emptyState({
      state: "failed",
      message: `Sensor unknown — ${d.reason || "the read did not run"}.` }));
    return;
  }
  if (!d.sensor) {
    body.replaceChildren(emptyState({ state: "none", message: d.note || "no such sensor" }));
    return;
  }

  // MERGE THE ENRICHED LIST ROW (WL-3). /api/weirlings/detail is the classification payload;
  // the per-sensor evidence (channel, netflow/zeek, flow series) is computed for the LIST. The
  // sheet used to render without it and read "flow capture configured on" beside no channel and
  // no observed flows -- the exact contradiction the operator reported.
  const listRow = (window.__wlRows || []).find((x) => x.sensor_id === sensorId);
  const r = listRow ? Object.assign({}, d.sensor, {
    sensor_id: listRow.sensor_id || sensorId,
    channel: listRow.channel, netflow: listRow.netflow, zeek: listRow.zeek,
    flow_series: listRow.flow_series, mappings: listRow.mappings, running: listRow.running,
  }) : d.sensor;
  r.sensor_id = r.sensor_id || sensorId;   // the detail payload must never lose its identity
  wlDetail = r;
  if (typeof scheduleURLSync === "function") scheduleURLSync();
  body.replaceChildren();

  // THIS HUB'S OWN WEIRLING OWNS ITS SETTINGS HERE (WSM-3, 2026-10-18). The controls moved out
  // of Settings; the payload that fills them is the same /api/settings. Shown for the local row
  // whether or not it has been adopted -- adoption declares it to the fleet, it does not decide
  // whether the box this console runs beside can be configured.
  const localBox = document.getElementById("wl-local-settings");
  if (localBox) {
    const showLocal = Boolean(r.local);
    // A SENSOR ROW OPENS THE FIRST USABLE NIC; a NIC row opens exactly that NIC. The old
    // whole-hub settings grid is gone, so there must always be a NIC panel here.
    let chosen = opts.nic;
    if (showLocal && !chosen) {
      const mgmt = String(wlCfgValue("mgmt_iface") || "").trim();
      const ifaces = Array.isArray(r.interfaces) ? r.interfaces : [];
      chosen = ifaces.find((n) => n && n !== mgmt && n !== "lo") || "";
    }
    localBox.classList.toggle("hidden", !showLocal);
    const localState = document.getElementById("wl-local-state");
    if (localState) localState.textContent = showLocal && !r.registered ? "not yet adopted" : "";
    if (showLocal && typeof loadSettings === "function") {
      // Load on open: never render values from a page the operator may not have visited, and
      // show a change made elsewhere the next time this sheet opens.
      try {
        await loadSettings();
        // A NIC ROW SELECTS THAT NIC FOR THE INTERCEPT (operator, 2026-10-19: "Weirling setting
        // should auto select the correct nic ... I want to enable eth2 for siphon"). The plan
        // editor below is for REMOTE sensors; this hub is configured through Settings, so the
        // click has to land in the CAPTURE_IFACE control and stage the change -- setting only the
        // value would look right until Apply and then do nothing.
        if (chosen && /^[A-Za-z0-9_.:-]+$/.test(chosen)) {
          wlShowNicSettings(chosen, r.interfaces);
        }
      } catch (err) {
        const detailNote = document.getElementById("wl-detail-note");
        if (detailNote) {
          detailNote.textContent = "Settings could not be read: "
            + (err && err.message ? err.message : err);
        }
      }
    }
  }

  // THE SENSOR'S OWN PLAN: for every REGISTERED weirling except this hub's own. An undeclared
  // sensor has nothing a plan could belong to (adopt it first), and this hub's own sensor is
  // configured in its sheet's settings section -- the two mechanisms are different on purpose,
  // and each panel shows only the one that can actually reach its sensor.
  const planBox = document.getElementById("wl-plan");
  if (planBox) {
    const showPlan = !!r.registered && !r.local;
    planBox.classList.toggle("hidden", !showPlan);
    if (showPlan) wlRenderPlan(r);
    else { WL_PLAN.sensor_id = ""; WL_PLAN.changes = {}; WL_PLAN.survey = null; }
    // A NIC ROW OPENS THE SETTINGS FOR THAT NIC (operator, 2026-10-19). The plan's interface
    // field is where a NIC becomes actionable, so focus it on the NIC the operator clicked;
    // the rest of the sheet is unchanged.
    if (opts.nic) {
      const ifaceInput = document.getElementById("wl-plan-iface");
      if (ifaceInput) {
        ifaceInput.value = opts.nic;
        ifaceInput.focus();
      }
      let nicNote = document.getElementById("wl-nic-edit");
      if (!nicNote) {
        nicNote = el("p", { class: "muted", attrs: { id: "wl-nic-edit" } });
        const body = document.getElementById("wl-detail-body");
        if (body) body.prepend(nicNote);
      }
      nicNote.textContent = `editing NIC ${opts.nic}`;
    }
  }

  // WL-2: THE SHEET IS FOR CHANGES. One situation line explains what is being changed (a
  // state word alone does not say whether "stale" means the box is off or its capture died),
  // and the facts it used to list live where they belong: the row (state, mode, networks,
  // trend, taps), the Logs tab (issues), and the Settings page (this hub's own sensor).
  body.appendChild(wlSituation(r));

  // ── the controls, only where they MEAN something.
  const registerBtn = document.getElementById("wl-detail-register");
  const enableBtn = document.getElementById("wl-detail-enable");
  const disableBtn = document.getElementById("wl-detail-disable");
  const revokeBtn = document.getElementById("wl-detail-revoke");
  const all = [registerBtn, enableBtn, disableBtn, revokeBtn];
  for (const b of all) b.classList.add("hidden");

  if (!r.registered) {
    // NO ENABLE/RETIRE CONTROLS for an undeclared sensor, with the reason stated -- but REGISTER
    // is exactly the repair this row exists for, and it must not require retyping the id the hub
    // is already hearing. Measured at the first deployment, where the first question the view
    // produced was "where do i get the sensor id". One click files the declaration from the
    // sensor's own reports; the button is offered ONLY here, while the sensor reads as undeclared.
    registerBtn.classList.remove("hidden");
    registerBtn.textContent = "Adopt this weirling";
    note.textContent = "This sensor is not registered, so there is nothing to enable or retire. "
      + "Adopt it here — one click, from its own reports — or add its address to the flow "
      + "exporter allow-list if it should be ignored.";
  } else if (!r.enabled) {
    enableBtn.classList.remove("hidden");
    enableBtn.textContent = "Enable";
    note.textContent = "Switched off: it is not expected to report, so it is not raised as a problem.";
  } else {
    disableBtn.classList.remove("hidden");
    disableBtn.textContent = "Switch off";
    revokeBtn.classList.remove("hidden");
    revokeBtn.textContent = "Revoke";
    note.textContent = "Switching off keeps the sensor in the fleet and stops raising it. Revoking "
      + "retires the registration: the row is kept for the audit trail, and its live heartbeats "
      + "would then show as unregistered.";
  }
}

// ── wiring ────────────────────────────────────────────────────────────────────────────────────

/**
 * The Settings page's Weirling selector (the operator, 2026-10-16: "Create a section where you
 * select the wierling and then set setting. The wierling tab should be status and performance
 * and registration").
 *
 * THE PANEL IDS ARE UNCHANGED (#wl-sensor-config, #st-sensor and friends): the settings
 * machinery fills them by id wherever they live, and this code only decides WHOSE panel is
 * shown -- the weirling this hub runs gets the live controls, every other selection gets the
 * sentence saying where its runtime actually lives. The choice is remembered per session.
 */

function wireWeirlings() {
  // THE SHEET STANDARD (sheets.js): .sheet-close, the scrim, Escape and focus are wired once
  // there. The breadcrumb is this sheet's extra exit and routes through closeWeirling.
  wireSheet(document.getElementById("wl-detail-card"), {
    scrimId: "wl-sheet-scrim",
    onClose: () => { if (typeof clearCrumbs === "function") clearCrumbs(); },
  });
  const viewSel = document.getElementById("wl-view");
  if (viewSel && !viewSel.dataset.wired) {
    viewSel.dataset.wired = "1";
    viewSel.addEventListener("change", () => wlApplyView(viewSel.value));
  }
  const viewSave = document.getElementById("wl-view-save");
  if (viewSave && !viewSave.dataset.wired) {
    viewSave.dataset.wired = "1";
    viewSave.addEventListener("click", () => wlSaveView());
  }
  for (const [id, kind] of [["wl-bulk-adopt", "adopt"],
                            ["wl-bulk-enable", "enable"], ["wl-bulk-disable", "disable"],
                            ["wl-bulk-reapply", "reapply"], ["wl-bulk-revoke", "revoke"]]) {
    const b = document.getElementById(id);
    if (b && !b.dataset.wired) {
      b.dataset.wired = "1";
      b.addEventListener("click", () => wlBulk(kind, b));
    }
  }
  const bulkClear = document.getElementById("wl-bulk-clear");
  if (bulkClear && !bulkClear.dataset.wired) {
    bulkClear.dataset.wired = "1";
    bulkClear.addEventListener("click", () => {
      WL_SELECTED.clear();
      for (const cb of document.querySelectorAll("#wl-table input.wl-sel")) cb.checked = false;
      wlRenderBulk();
    });
  }

  const reload = document.getElementById("wl-reload");
  if (reload) reload.addEventListener("click", () => loadWeirlings().catch(showError));

  for (const id of ["wl-problems-only", "wl-revoked"]) {
    const box = document.getElementById(id);
    if (box) box.addEventListener("change", () => loadWeirlings().catch(showError));
  }

  const save = document.getElementById("wl-save");
  if (save) save.addEventListener("click", () => saveWeirling());

  const nicStage = document.getElementById("wl-nic-stage");
  if (nicStage && !nicStage.dataset.wired) {
    nicStage.dataset.wired = "1";
    nicStage.addEventListener("click", () => wlStageNicSettings());
  }
  const nicAll = document.getElementById("wl-nic-all");
  if (nicAll && !nicAll.dataset.wired) {
    nicAll.dataset.wired = "1";
    nicAll.addEventListener("click", () => wlCloseNicSettings());
  }
  for (const [id, which] of [["wl-nic-siphon", "siphon"], ["wl-nic-loch", "loch"]]) {
    const box = document.getElementById(id);
    if (box && !box.dataset.wired) {
      box.dataset.wired = "1";
      box.addEventListener("change", () => wlNicModeClicked(which));
    }
  }
  for (const id of ["wl-nic-netflow-passive", "wl-nic-netflow-active"]) {
    const radio = document.getElementById(id);
    if (radio && !radio.dataset.wired) {
      radio.dataset.wired = "1";
      radio.addEventListener("change", () => wlNicNetflowSourceChanged());
    }
  }
  const nicSonar = document.getElementById("wl-nic-sonar");
  if (nicSonar && !nicSonar.dataset.wired) {
    nicSonar.dataset.wired = "1";
    nicSonar.addEventListener("click", () => wlScanNetwork().catch(showError));
  }
  // The channel selects live on the sensor sheet (openSensorActions), not this NIC panel;
  // their change handlers are attached when that sheet is built.
  const modeSel = document.getElementById("wl-mode-select");
  if (modeSel) modeSel.addEventListener("change", () => wlApplyMode().catch(showError));

  // ── the per-sensor intercept plan's own controls ─────────────────────────────────────────
  // Its listeners are separate from the local sensor's (`wl-mode-select` above): one value,
  // one control, and each control writes through the mechanism that can reach ITS sensor.
  const planMode = document.getElementById("wl-plan-mode");
  if (planMode) planMode.addEventListener("change", () => wlPlanModeChanged().catch(showError));
  const planSonar = document.getElementById("wl-plan-sonar");
  if (planSonar) planSonar.addEventListener("click", () => wlRunPlanSonar().catch(showError));
  const planProbe = document.getElementById("wl-plan-probe");
  if (planProbe) planProbe.addEventListener("click", () => wlRunPlanProbe().catch(showError));
  const planApply = document.getElementById("wl-plan-apply");
  if (planApply) planApply.addEventListener("click", () => {
    if (!Object.keys(WL_PLAN.changes).length) return;
    wlApplyPlanChanges({ ...WL_PLAN.changes }).catch(showError);
  });
  for (const f of WL_PLAN_FIELDS) {
    const input = wlPlanInput(f);
    if (input) input.addEventListener("input", () => wlStagePlanField(f));
  }

  const cancel = document.getElementById("wl-cancel");
  if (cancel) cancel.addEventListener("click", () => clearWeirlingForm());

  const close = document.getElementById("wl-detail-close");
  // US-1: through the ONE exit. Hiding the card alone left the scrim up -- the console was
  // unclickable until a reload (measured).
  if (close) close.addEventListener("click", () => closeWeirling());

  const enableBtn = document.getElementById("wl-detail-enable");
  if (enableBtn) enableBtn.addEventListener("click", () => setWeirlingEnabled(true));
  const disableBtn = document.getElementById("wl-detail-disable");
  if (disableBtn) disableBtn.addEventListener("click", () => setWeirlingEnabled(false));
  const revokeBtn = document.getElementById("wl-detail-revoke");
  if (revokeBtn) revokeBtn.addEventListener("click", () => revokeWeirling());
  const registerBtn = document.getElementById("wl-detail-register");
  if (registerBtn) registerBtn.addEventListener("click", () => registerWeirling());
}

function clearWeirlingForm() {
  for (const id of ["wl-id", "wl-segment", "wl-address", "wl-note"]) {
    const f = document.getElementById(id);
    if (f) f.value = "";
  }
  const mode = document.getElementById("wl-mode");
  if (mode) mode.value = "loch";
  const idField = document.getElementById("wl-id");
  if (idField) idField.disabled = false;
  document.getElementById("wl-form-mode").textContent = "";
  document.getElementById("wl-cancel").classList.add("hidden");
  document.getElementById("wl-save").textContent = "Register";
  document.getElementById("wl-save-note").textContent = "";
}

/** THE VALUE A SETTINGS ROW REPORTS, cleaned of the payload's display placeholder. */
function wlCfgValue(key) {
  const row = (typeof SETTINGS_ROWS !== "undefined" && SETTINGS_ROWS)
    ? (SETTINGS_ROWS[key] || SETTINGS_ROWS[String(key).toLowerCase()]) : null;
  const raw = String((row && row.value) || "").trim();
  return (/^(\(not set\)|—)$/i.test(raw) ? "" : raw);
}

/** A setting's value as the operator would see it if they applied the pending set. */
function wlStagedValue(key) {
  if (typeof STAGE !== "undefined" && STAGE && STAGE.changes
      && Object.prototype.hasOwnProperty.call(STAGE.changes, key)) {
    const v = STAGE.changes[key];
    return String(v == null ? "" : v).trim();
  }
  return wlCfgValue(key);
}

/** The channel pair stored in a sensor's PLAN -- the only per-weirling channel store. */
function wlChannelPlanPair(r) {
  const plan = (r && r.plan) || {};
  return {
    up: String(plan.channel_upstream || "").trim(),
    down: String(plan.channel_downstream || "").trim(),
  };
}

/** The pair the SENSOR reports using, and whether it measured the bridge as active.
 *  `active === null` means the sensor did not report a channel at all; that is NOT "off". */
function wlChannelReported(r) {
  const raw = r ? r.channel_active : null;
  return {
    up: String((r && r.channel_upstream) || "").trim(),
    down: String((r && r.channel_downstream) || "").trim(),
    bridge: String((r && r.channel_bridge) || "").trim(),
    error: String((r && r.channel_error) || "").trim(),
    active: raw === true ? true : (raw === false ? false : null),
  };
}

/** The NIC names a sensor can bridge: its own report first, its declared plan_nics second. */
function wlChannelNicNames(r) {
  const reported = (Array.isArray(r && r.interfaces) ? r.interfaces : [])
    .filter((name) => name && name !== "lo");
  if (reported.length) return reported;
  try {
    const parsed = JSON.parse(String((r && r.plan_nics) || "") || "{}");
    return (parsed && typeof parsed === "object" && !Array.isArray(parsed))
      ? Object.keys(parsed).filter((name) => name && name !== "lo") : [];
  } catch (_e) {
    return [];
  }
}

/** Whether this sensor can be offered a channel, and which ports to offer.
 *  THREE interfaces is the floor: one management port plus the two a bridge needs. A sensor
 *  that has not reported any falls back to the NICs its plan declares. */
function wlChannelOffered(r) {
  const all = wlChannelNicNames(r);
  const mgmt = String(wlCfgValue("mgmt_iface") || "eth0").trim() || "eth0";
  const usable = all.filter((name) => name !== mgmt);
  return { show: all.length >= 3 && usable.length >= 2, all, usable, mgmt };
}

/** The upstream port in use: the plan's, falling back to the local staged settings pair. */
function wlChannelSide(r) {
  const pair = wlChannelPlanPair(r);
  return pair.up || String(wlStagedValue("channel_upstream") || "").trim();
}

/** THE CHANNEL PAIR IS ACTIVE ONLY WHEN BOTH SIDES ARE NAMED AND DIFFERENT.
 *  A row's own plan wins; the staged settings pair is the local NIC sheet's fallback, where
 *  an edit is staged before it is applied. */
function wlChannelEnabled(r) {
  let up = "";
  let down = "";
  if (r) {
    const pair = wlChannelPlanPair(r);
    up = pair.up;
    down = pair.down;
  }
  if (!up && !down && (!r || r.local)) {
    up = wlStagedValue("channel_upstream");
    down = wlStagedValue("channel_downstream");
  }
  return Boolean(up && down && up !== down);
}

/** What the sheet says about the pair: active / declared-not-active / staged, never a guess. */
function wlRenderChannelNote(r) {
  const note = document.getElementById("wl-sensor-channel-note");
  if (!note) return;
  const pair = wlChannelPlanPair(r);
  const reported = wlChannelReported(r);
  if (!pair.up || !pair.down) {
    note.textContent = reported.error || (reported.active
      ? `The sensor reports an active channel ${reported.up} <-> ${reported.down}` +
        `${reported.bridge ? ` on ${reported.bridge}` : ""}, but no pair is stored in its plan.`
      : "");
    return;
  }
  const same = reported.up === pair.up && reported.down === pair.down;
  if (!same || reported.active === null) {
    note.textContent = `Channel ${pair.up} <-> ${pair.down} is staged, sensor has not applied ` +
      `it yet` + (reported.up || reported.down
        ? `; it reports ${reported.up || "—"} <-> ${reported.down || "—"}.`
        : "; it has not reported a channel.")
      + (reported.error ? ` ${reported.error}` : "");
    return;
  }
  if (reported.active === true) {
    note.textContent = `Channel active: ${pair.up} <-> ${pair.down}` +
      `${reported.bridge ? ` bridged on ${reported.bridge}` : ""}. Siphon and passive NetFlow ` +
      `are locked out while a channel is active.`;
    return;
  }
  note.textContent = `Channel ${pair.up} <-> ${pair.down} is declared, but the sensor reports ` +
    `it is NOT active (bridge, carrier or forwarding check). Siphon and passive NetFlow are ` +
    `locked out while a channel is active.` + (reported.error ? ` ${reported.error}` : "");
}

function wlPopulateSensorChannel(r) {
  const box = document.getElementById("wl-sensor-channel");
  if (!box) return;
  const offered = wlChannelOffered(r);
  box.classList.toggle("hidden", !offered.show);
  if (!offered.show) return;
  const pair = wlChannelPlanPair(r);
  for (const [id, value] of [["wl-sensor-channel-upstream", pair.up],
                             ["wl-sensor-channel-downstream", pair.down]]) {
    const sel = document.getElementById(id);
    if (!sel) continue;
    const options = offered.usable.slice();
    if (value && !options.includes(value)) options.push(value);
    sel.replaceChildren();
    sel.appendChild(el("option", { attrs: { value: "" }, text: "— none —" }));
    for (const name of options) {
      sel.appendChild(el("option", { attrs: { value: name }, text: name }));
    }
    sel.value = value;
  }
  wlRenderChannelNote(r);
}

function wlSensorChannelChanged() {
  const up = document.getElementById("wl-sensor-channel-upstream");
  const down = document.getElementById("wl-sensor-channel-downstream");
  const note = document.getElementById("wl-sensor-channel-note");
  const r = WL_ACTION_ROW;
  if (!up || !down || !note || !r) return;
  if (up.value && down.value && up.value === down.value) {
    note.textContent = "Upstream and downstream must be different interfaces.";
    return;
  }
  if (Boolean(up.value) !== Boolean(down.value)) {
    note.textContent = "A channel needs BOTH ports: pick an upstream and a downstream, or " +
      "clear both to remove it.";
    return;
  }
  const pair = wlChannelPlanPair(r);
  if (up.value === pair.up && down.value === pair.down) {
    wlRenderChannelNote(r);
    return;
  }
  note.textContent = up.value && down.value
    ? `Channel ${up.value} <-> ${down.value} is staged, not saved. Apply channel writes it to ` +
      `this weirling's plan.`
    : "Channel staged for removal. Apply channel clears both ports from this weirling's plan.";
}

async function wlSensorChannelApply() {
  const r = WL_ACTION_ROW;
  const up = document.getElementById("wl-sensor-channel-upstream");
  const down = document.getElementById("wl-sensor-channel-downstream");
  const note = document.getElementById("wl-sensor-channel-note");
  if (!r || !up || !down || !note) return;
  if (Boolean(up.value) !== Boolean(down.value)) {
    note.textContent = "A channel needs BOTH ports: pick an upstream and a downstream, or " +
      "clear both to remove it.";
    return;
  }
  if (up.value && up.value === down.value) {
    note.textContent = "Upstream and downstream must be different interfaces.";
    return;
  }
  const changes = { channel_upstream: up.value, channel_downstream: down.value };
  const btn = document.getElementById("wl-sensor-channel-apply");
  note.textContent = "saving the channel to this weirling's plan…";
  if (btn) btn.disabled = true;
  try {
    // THE PLAN IS THE PER-SENSOR STORE, not the hub's ConfigMap. Preview first (the same
    // validation the write uses), then apply -- both against THIS sensor's row.
    const preview = await postJSON("/api/weirlings/plan",
      { sensor_id: r.sensor_id, changes });
    if (!preview || preview.ok !== true) {
      throw new Error((preview && preview.error) || "the server refused the plan");
    }
    const res = await postJSON("/api/weirlings/apply",
      { sensor_id: r.sensor_id, changes, reason: "" });
    if (!res || res.ok !== true) {
      throw new Error((res && res.error) || "the server refused the write");
    }
    note.textContent = up.value
      ? "Saved to this weirling's plan. It reads the plan on its next refresh; until its own " +
        "report agrees, the sheet calls the channel staged."
      : "Channel cleared from this weirling's plan.";
    if (typeof loadWeirlings === "function") await loadWeirlings();
    closeSheet(WL_SENSOR_CARD);
  } catch (err) {
    note.textContent = "Could not save the channel: "
      + (err && err.message ? err.message : err);
  } finally {
    if (btn) btn.disabled = false;
  }
}

function wlIfaceList(value) {
  return String(value || "").split(",").map((s) => s.trim()).filter(Boolean);
}

/** `eth1=Servers,eth2=DMZ` -> {eth1: "Servers", eth2: "DMZ"}. */
function wlIfaceNames(value) {
  const out = {};
  for (const token of String(value || "").split(",")) {
    const at = token.indexOf("=");
    if (at <= 0) continue;
    const iface = token.slice(0, at).trim();
    const name = token.slice(at + 1).trim();
    if (iface && name) out[iface] = name;
  }
  return out;
}

/** The per-interface plans, from the staged value when one exists. */
function wlPlans() {
  const raw = wlStagedValue("intercept_plans") || wlCfgValue("intercept_plans") || "";
  try {
    const parsed = JSON.parse(String(raw || "{}"));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch (_e) {
    return {};
  }
}

function wlPlanFor(nic) {
  const plan = wlPlans()[nic];
  return plan && typeof plan === "object" ? plan : {};
}

/** Scope the local settings to ONE NIC. The panel edits that port's two capture choices and
 *  nothing else; all other settings remain behind the explicit "All hub settings" link. */
function wlShowNicSettings(nic, interfaces) {
  const box = document.getElementById("wl-nic-settings");
  const local = document.getElementById("wl-local-settings");
  if (!box || !local) return;
  const base = wlStagedValue("zeek_iface");
  const listed = wlIfaceList(wlStagedValue("zeek_ifaces"));
  const cap = wlStagedValue("capture_iface");
  const mode = String(wlStagedValue("sensor_mode") || "loch").trim().toLowerCase();
  const plan = wlPlanFor(nic);
  const siphonOn = String(plan.mode || "").toLowerCase() === "siphon"
    || plan.siphon === true;
  // THE PLAN IS THE AUTHORITY WHEN A PER-NIC PLAN EXISTS (operator, 2026-10-20: "settings
  // don't match the visual"). The sheet used to read only the legacy ZEEK_IFACES list, so
  // opening eth2 after eth1's siphon plan showed "capture - Zeek on" while the fleet row
  // (which reads the plan) said unassigned. Same rule as wlNicFacts: capture+siphon roles
  // come from the plan; the global list is the fallback only when there is no plan at all.
  const hasPlans = Object.keys(wlPlans()).length > 0;
  const planCapture = plan.capture === true;
  const zeekOn = siphonOn || (hasPlans ? planCapture
    : (listed.length ? listed.includes(nic) : base === nic));
  const flowRaw = String(wlStagedValue("netflow_mode") || "auto").trim().toLowerCase();
  const flowActive = flowRaw === "active" || (flowRaw === "auto" && mode === "siphon");
  const flowIfaces = wlIfaceList(wlStagedValue("netflow_iface"));
  const netflowOn = !flowActive || (flowIfaces.length ? flowIfaces.includes(nic) : siphonOn);
  // A CHANNEL IS ONE INLINE PAIR. Both ports see every frame, so only the upstream side may
  // carry Zeek/NetFlow while the pair is configured; the other NIC's feed controls are disabled.
  const channelOn = wlChannelEnabled(wlDetail);
  const channelSide = wlChannelSide(wlDetail);
  const zeekFeed = channelOn ? nic === channelSide : zeekOn;
  const netflowFeed = channelOn ? nic === channelSide : netflowOn;
  const feedHere = !channelOn || nic === channelSide;
  const name = document.getElementById("wl-nic-name");
  const role = document.getElementById("wl-nic-role");
  const facts = document.getElementById("wl-nic-facts");
  const names = wlIfaceNames(wlCfgValue("interface_networks"));
  const netInput = document.getElementById("wl-nic-network");
  if (netInput) netInput.value = names[nic] || "";
  // EACH NIC OWNS ITS OWN PLAN (operator, 2026-10-20). The old sheet copied the single
  // sensor-level INTERCEPT_* plan into every NIC, so eth2 showed eth1's values and applying
  // one overwrote the other. Plans now live in INTERCEPT_PLANS keyed by interface; the
  // supervisor starts one intercept per entry with its own policy table.
  const cidrInput = document.getElementById("wl-nic-cidr");
  if (cidrInput) {
    cidrInput.value = plan.segment || "";
    cidrInput.disabled = false;
    cidrInput.title = `the segment ${nic} intercepts`;
  }
  const gatewayInput = document.getElementById("wl-nic-gateway");
  if (gatewayInput) {
    gatewayInput.value = plan.gateway || "";
    gatewayInput.disabled = false;
    gatewayInput.title = `the gateway ${nic} relays through`;
  }
  const interceptInput = document.getElementById("wl-nic-intercept-ip");
  if (interceptInput) {
    interceptInput.value = plan.addr || "";
    interceptInput.disabled = false;
    interceptInput.title = `the address ${nic} claims while intercepting`;
  }
  if (name) name.textContent = nic;
  if (role) role.textContent = siphonOn ? "siphon capture" : (zeekFeed ? "capture" : "unassigned");
  if (facts) {
    const flowWhere = flowActive ? (flowIfaces.length ? `active · ${flowIfaces.join(", ")}` : "active") : "passive";
    facts.textContent = `Mode: ${siphonOn ? "siphon" : "loch"} · `
      + `Feeds: Zeek ${zeekFeed ? "on" : "off"}, NetFlow ${flowWhere}.`;
  }
  // THE CHANNEL PAIR IS NOT A NIC FIELD (operator, 2026-10-19). It is configured on the
  // sensor's own sheet; this panel only carries its consequences.
  const z = document.getElementById("wl-nic-zeek");
  const sip = document.getElementById("wl-nic-siphon");
  const loch = document.getElementById("wl-nic-loch");
  const net = document.getElementById("wl-nic-netflow");
  const sluice = document.getElementById("wl-nic-sluice");
  if (z) { z.checked = zeekFeed; z.disabled = !feedHere; }
  if (sip) { sip.checked = siphonOn && !channelOn; sip.disabled = channelOn; }
  // SONAR IS AN IN-PATH SURVEY (operator, 2026-10-19): it is only meaningful while siphon is
  // selected. In loch mode there is no ARP/spoof plan to stage, so the button is disabled
  // rather than offering a scan whose result the operator cannot use.
  const sonarBtn = document.getElementById("wl-nic-sonar");
  if (sonarBtn) {
    sonarBtn.disabled = channelOn || !siphonOn;
    sonarBtn.title = sonarBtn.disabled
      ? "Sonar is available when siphon is selected" : "survey this segment";
  }
  if (loch) loch.checked = channelOn || !siphonOn;
  if (sluice) sluice.checked = !!plan.sluice;
  if (net) { net.checked = netflowFeed; net.disabled = channelOn ? !feedHere : (!flowActive && !channelOn); }
  const passive = document.getElementById("wl-nic-netflow-passive");
  const active = document.getElementById("wl-nic-netflow-active");
  if (passive) { passive.checked = channelOn ? false : !flowActive; passive.disabled = channelOn; }
  if (active) { active.checked = channelOn ? true : flowActive; active.disabled = false; }
  const channelNote = document.getElementById("wl-nic-channel-note");
  if (channelNote) {
    channelNote.textContent = channelOn
      ? "A channel is enabled on this sensor — siphon and passive NetFlow are locked out."
      : "";
  }
  box.dataset.nic = nic;
  const note = document.getElementById("wl-nic-note");
  if (note) note.textContent = "";
  box.classList.remove("hidden");
  local.classList.add("wl-scoped");
}

/** One mode at a time: checking either clears the other, and one always stays checked. */
function wlNicModeClicked(which) {
  const sip = document.getElementById("wl-nic-siphon");
  const loch = document.getElementById("wl-nic-loch");
  if (!sip || !loch || sip.disabled) return;
  if (which === "siphon" && sip.checked) loch.checked = false;
  if (which === "loch" && loch.checked) sip.checked = false;
  if (!sip.checked && !loch.checked) {
    if (which === "siphon") loch.checked = true; else sip.checked = true;
  }
  const sonarBtn = document.getElementById("wl-nic-sonar");
  if (sonarBtn) {
    sonarBtn.disabled = sip.disabled || !sip.checked;
    sonarBtn.title = sonarBtn.disabled
      ? "Sonar is available when siphon is selected" : "survey this segment";
  }
}

/**
 * PASSIVE MEANS THE ROUTER FEED, ACTIVE MEANS THIS SENSOR MEASURES (operator, 2026-10-19).
 * Passive disables the per-port NetFlow choice because the feed does not belong to a NIC;
 * active makes this NIC selectable as the probe source.
 */
/** Stage the channel pair through the same plan as every other setting. */
function wlNicChannelChanged() {
  const up = document.getElementById("wl-nic-upstream");
  const down = document.getElementById("wl-nic-downstream");
  if (!up || !down) return;
  stageChange("channel_upstream", up.value, wlCfgValue("channel_upstream"));
  stageChange("channel_downstream", down.value, wlCfgValue("channel_downstream"));
  const note = document.getElementById("wl-nic-note");
  if (note) note.textContent = "channel pair staged — review the pending changes, then Apply.";
}

function wlNicNetflowSourceChanged() {
  const active = document.getElementById("wl-nic-netflow-active");
  const net = document.getElementById("wl-nic-netflow");
  const sluice = document.getElementById("wl-nic-sluice");
  if (!active || !net || active.disabled) return;
  if (active.checked) {
    net.disabled = false;
    net.checked = true;
  } else {
    net.disabled = true;
    net.checked = true;   // the router feed exists regardless of which NIC is selected
  }
}

/** Back to the whole hub's settings. Nothing staged is discarded. */
function wlCloseNicSettings() {
  const box = document.getElementById("wl-nic-settings");
  const local = document.getElementById("wl-local-settings");
  if (box) { box.classList.add("hidden"); box.dataset.nic = ""; }
  if (local) local.classList.remove("wl-scoped");
}

/** Stage THIS NIC's capture choices through the ordinary settings plan. */
function wlStageNicSettings() {
  const box = document.getElementById("wl-nic-settings");
  const nic = box ? box.dataset.nic : "";
  if (!nic) return;
  const zeekBox = document.getElementById("wl-nic-zeek");
  const siphonBox = document.getElementById("wl-nic-siphon");
  const lochBox = document.getElementById("wl-nic-loch");
  const netBox = document.getElementById("wl-nic-netflow");
  const activeSource = document.getElementById("wl-nic-netflow-active");
  const note = document.getElementById("wl-nic-note");
  const channelOn = wlChannelEnabled(wlDetail);
  let zeekOn = !!(zeekBox && zeekBox.checked);
  let siphonOn = !!(siphonBox && siphonBox.checked) && !channelOn;
  let lochOn = !!(lochBox && lochBox.checked) || channelOn;
  if (channelOn) {
    // THE CHANNEL WINS OVER A STALE NIC CHECKBOX. The controls are disabled while the bridge
    // is active, so a hidden checked siphon box must not stage an in-path mode anyway.
    if (siphonBox) siphonBox.checked = false;
    if (lochBox) lochBox.checked = true;
    if (activeSource) activeSource.checked = true;
  }
  if (siphonOn) zeekOn = true;   // siphon needs a port Zeek can see
  if (siphonOn && !zeekOn) {
    zeekOn = true;
    if (zeekBox) zeekBox.checked = true;
  }

  // FEEDS: Zeek is the interface list; NetFlow is the source statement below. Use the STAGED
  // value, not the stored one: opening eth2 after staging eth1 must ADD to the pending list,
  // not replace it with whatever the cluster last applied.
  const base = wlStagedValue("zeek_iface");
  const list = wlIfaceList(wlStagedValue("zeek_ifaces"));
  if (!list.length && base) list.push(base);
  const channelSide = String(wlStagedValue("channel_upstream") || "").trim();
  let next = list.filter((n) => n !== nic);
  if (channelOn) {
    // One inline side only; the other port is disabled in the sheet and must not creep back
    // into ZEEK_IFACES through a stale list.
    next = zeekOn && nic === channelSide ? [nic] : [];
  } else if (zeekOn) {
    next.push(nic);
  }
  stageChange("zeek_ifaces", next.join(","), wlCfgValue("zeek_ifaces"));

  // THE HUMAN NAME IS PART OF THIS INTERFACE'S SETTINGS (operator, 2026-10-19). It is staged with
  // the same plan as the capture choices; anomaly locations read it after Apply.
  const netInput = document.getElementById("wl-nic-network");
  if (netInput) {
    const names = wlIfaceNames(wlCfgValue("interface_networks"));
    const wanted = String(netInput.value || "").trim();
    if (wanted) names[nic] = wanted; else delete names[nic];
    const nextNames = Object.entries(names).map(([k, v]) => `${k}=${v}`).join(",");
    stageChange("interface_networks", nextNames, wlCfgValue("interface_networks"));
  }

  // THIS NIC'S PLAN ONLY. A blank field clears only this interface's plan; it cannot
  // erase another port's segment, gateway or intercept address.
  const plans = wlPlans();
  const existing = plans[nic] && typeof plans[nic] === "object" ? plans[nic] : {};
  const cidrField = document.getElementById("wl-nic-cidr");
  const gatewayField = document.getElementById("wl-nic-gateway");
  const interceptField = document.getElementById("wl-nic-intercept-ip");
  const sluiceBox = document.getElementById("wl-nic-sluice");
  plans[nic] = {
    mode: siphonOn ? "siphon" : "loch",
    sluice: !!(sluiceBox && sluiceBox.checked),
    segment: String((cidrField && cidrField.value) || "").trim(),
    addr: String((interceptField && interceptField.value) || "").trim(),
    gateway: String((gatewayField && gatewayField.value) || "").trim(),
    targets: String(existing.targets || "*"),
  };
  stageChange("intercept_plans", JSON.stringify(plans), wlCfgValue("intercept_plans"));

  const anySiphon = Object.values(plans).some(
    (p) => p && String(p.mode || "").toLowerCase() === "siphon");
  const currentMode = String(wlCfgValue("sensor_mode") || "loch").toLowerCase();
  const wantedMode = anySiphon ? "siphon" : "loch";
  if (wantedMode !== currentMode) stageChange("sensor_mode", wantedMode, currentMode);

  // A CHECKED SLUICE ROLE IS THE ENABLE. Without this the operator applied a plan that said
  // sluice:true and still had to visit the Sluice tab and flip SLUICE_ENABLED separately.
  const anySluice = Object.values(plans).some((p) => p && p.sluice === true);
  const gateOn = /^(1|true|on|yes)$/i.test(String(wlCfgValue("sluice_enabled") || ""));
  if (anySluice && !gateOn) {
    stageChange("sluice_enabled", "1", wlCfgValue("sluice_enabled"));
  }
  const cap = wlCfgValue("capture_iface");
  if (!cap) stageChange("capture_iface", nic, cap);

  // NETFLOW SOURCE: passive leaves the router's export alone; active makes this NIC one of the
  // probe sources. The setting is a comma-separated list so eth1 and eth2 can both meter.
  const currentSource = String(wlStagedValue("netflow_mode") || "auto").toLowerCase();
  const storedSource = String(wlCfgValue("netflow_mode") || "auto").toLowerCase();
  const wantedSource = activeSource && activeSource.checked ? "active" : "passive";
  if (wantedSource !== currentSource) stageChange("netflow_mode", wantedSource, storedSource);
  const currentFlowIfaces = wlIfaceList(wlStagedValue("netflow_iface"));
  let nextFlowIfaces = currentFlowIfaces.filter((name) => name !== nic);
  if (channelOn) {
    // The inline pair is sampled once. The non-upstream port cannot add a second probe.
    nextFlowIfaces = (wantedSource === "active" && netBox && netBox.checked
                      && nic === channelSide) ? [nic] : [];
  } else if (wantedSource === "active" && netBox && netBox.checked) {
    nextFlowIfaces.push(nic);
  }
  const nextFlowValue = nextFlowIfaces.join(",");
  const currentFlowValue = currentFlowIfaces.join(",");
  if (nextFlowValue !== currentFlowValue) {
    stageChange("netflow_iface", nextFlowValue, wlCfgValue("netflow_iface"));
  }

  if (note) {
    note.textContent = `staged for ${nic} — review the pending changes below, then Apply.`;
  }
  if (typeof setStageNote === "function") {
    setStageNote(`staged capture choices for ${nic}; nothing is written until Apply.`);
  }
}

/** SCAN NETWORK: the Sonar survey, from the NIC that is open. It stages its findings through
 *  the ordinary apply plan; nothing about the segment is written by the scan itself. */
async function wlScanNetwork() {
  const btn = document.getElementById("wl-nic-sonar");
  if (btn && btn.disabled) return;
  const note = document.getElementById("wl-nic-scan-note");
  if (typeof runSonar !== "function") {
    if (note) note.textContent = "Sonar is unavailable in this build.";
    return;
  }
  if (note) note.textContent = "Scanning: DHCP, passive capture, then ARP probe — nothing is written.";
  const box = document.getElementById("wl-nic-settings");
  const nic = box ? box.dataset.nic : "";
  const res = await runSonar(nic ? {
    interface: nic,
    // THIS NIC'S PLAN, NOT THE LEGACY GLOBAL INTERCEPT_* KEYS. runSonar used to stage
    // intercept_segment/gateway/addr globally, so surveying eth2 changed what eth1 showed
    // and what the next apply wrote. The fields below are staged by wlStageNicSettings.
    stage: false,
    onProgress: (p) => { if (note && p && p.text) note.textContent = p.text; },
  } : {});
  if (!note) return;
  if (!res || res.ok !== true) {
    note.textContent = "Scan failed — " + ((res && res.error) || SONAR_STATE.error || "no result");
    return;
  }
  const where = [res.interface && `interface ${res.interface}`, res.segment]
    .filter(Boolean).join(" on ");
  // FILL THE NETWORKS SECTION WITH WHAT THE SURVEY MEASURED (operator, 2026-10-19). The
  // values are already staged by runSonar's ordinary recommendation path; this only makes the
  // measured answer visible in the fields the operator is about to review.
  const cidr = document.getElementById("wl-nic-cidr");
  if (cidr && res.segment) cidr.value = res.segment;
  const gateway = document.getElementById("wl-nic-gateway");
  if (gateway && res.gateway) gateway.value = res.gateway;
  const intercept = document.getElementById("wl-nic-intercept-ip");
  const free = (res.recommended && res.recommended.intercept_addr)
    || (Array.isArray(res.free_addresses) ? res.free_addresses[0] : "");
  if (intercept && free) intercept.value = free;
  const sourceText = String(res.intercept_addr_source || "");
  const candidate = /candidate/i.test(sourceText);
  const arpProbed = /ARP probe/i.test(sourceText);
  note.textContent = `Scan complete${where ? ` (${where})` : ""}. ` +
    (candidate
      ? `Network and gateway are filled below; the intercept IP ${free || "value"} is a candidate ${arpProbed ? "(ARP probe found no owner)" : "(not probed)"}, so confirm it is free before enabling siphon. `
      : "Network, gateway and intercept IP are filled below; ") +
    "The values are staged in this NIC's own plan. Review them, then Apply.";
  // Write the measured values into THIS NIC's plan, never the global intercept_* keys.
  if (typeof wlStageNicSettings === "function") wlStageNicSettings();
}

/** APPLY A MODE CHANGE FROM THE DRILL-DOWN (operator, 2026-10-17: "a mode selection...
 * and a sonar button" per sensor, "as easy as clicking sonar and enabling it"). Selecting
 * siphon runs Sonar first when this session has not surveyed yet, stages what it found plus
 * the mode, and applies through the ordinary plan-and-apply path (the server's gates
 * included). Selecting loch applies the mode alone. The select reverts if refused. */
async function wlApplyMode() {
  const sel = document.getElementById("wl-mode-select");
  if (!sel || sel.disabled) return;
  const want = sel.value === "siphon" ? "siphon" : "loch";
  // The select lives on the Settings page now; the current value is the settings row's.
  const prevRow = SETTINGS_ROWS["sensor_mode"];
  const prev = String(prevRow ? prevRow.value : "").toLowerCase() === "siphon"
    ? "siphon" : "loch";
  sel.disabled = true;
  try {
    if (want === "siphon") {
      if (!SONAR_STATE.result || SONAR_STATE.result.ok !== true) {
        const res = await runSonar();
        if (!res || res.ok !== true) { sel.value = prev; return; }
      }
      stageSonarRecommendations(SONAR_STATE.result);
    }
    const row = SETTINGS_ROWS["sensor_mode"];
    if (String(row ? row.value : "").toLowerCase() !== want) {
      stageChange("sensor_mode", want, row ? String(row.value) : "");
    }
    if (!Object.keys(STAGE.changes).length) {
      const n = document.getElementById("st-sonar-note");
      if (n) n.textContent = "Nothing to change — already " + want + ".";
      return;
    }
    await applyStage(true);
    const msg = LAST_APPLY.text || "applied.";
    // The settings page shows the result where the control lives; the rows re-read after
    // Apply, so the select's value follows the server rather than the click.
    await loadSettings().catch(() => {});
    const note2 = document.getElementById("st-sonar-note");
    if (note2) note2.textContent = msg;
  } finally {
    sel.disabled = false;
  }
}

// ── the sensor's own intercept plan ──────────────────────────────────────────────────────────
//
// WHY THIS IS NOT THE SETTINGS GRID (the operator's ask, 2026-10-17: "On adopt can the sensor
// run sonar and the user toggles between or sets siphon or loch?"). The Settings tab writes ONE
// deployment's ConfigMap -- this hub's sensor. Every OTHER weirling needs its own plan, and the
// only channel the hub and a remote sensor share is the sensor's registry row: the operator
// writes the plan here, the sensor's own agent reads it and arms itself, and the sensor reports
// the mode it ended up in. Two facts this panel must never blur:
//
//   * THE SENSOR OWNS WHEN IT APPLIES. The reply says "about 30 seconds", because that is the
//     sensor's own refresh; claiming "armed" here would be a claim only the sensor can make,
//     and its heartbeat is where that claim lives (declared vs reported, on the row).
//   * A CONTROL THAT CANNOT MEAN ANYTHING IS NOT RENDERED. No plan editor for an unregistered
//     sensor (nothing a plan could belong to) and none for this hub's own (its runtime is the
//     ConfigMap, edited on the Settings tab) -- in both cases the panel says where the control
//     does live rather than offering a toggle that writes into a drawer.
//
// THE STAGED-THEN-APPLIED SHAPE IS THE SETTINGS ONE, reused: `plan` validates server-side and
// returns per-key warnings (the in-path cost rides on the mode change), and only then does
// `apply` write. The browser never decides what is legal.

// The sensor whose plan is loaded in the panel, what has been edited, and the survey this
// session ran for it. One object, so a click can never act on the PREVIOUS sensor's row.
const WL_PLAN = { sensor_id: "", changes: {}, survey: null };

const WL_PLAN_FIELDS = ["iface", "segment", "addr", "gateway", "targets"];

function wlPlanInput(field) {
  return document.getElementById(`wl-plan-${field}`);
}

/** Populate the editor from a detail row. Called on every open, so it always shows the SERVER. */
function wlRenderPlan(r) {
  const box = document.getElementById("wl-plan");
  if (!box) return;
  // WL-2: the NICs left the sheet's fact list; here is where they become ACTIONABLE -- the
  // capture interface field offers the sensor's own reported interfaces as candidates.
  const ifaceInput = document.getElementById("wl-plan-iface");
  if (ifaceInput) {
    const nics = (r.interfaces || []).filter(Boolean);
    if (nics.length) {
      const listId = "wl-plan-iface-list";
      let dl = document.getElementById(listId);
      if (!dl) {
        dl = el("datalist", { attrs: { id: listId } });
        box.appendChild(dl);
      }
      dl.replaceChildren();
      for (const nic of nics) dl.appendChild(el("option", { attrs: { value: nic } }));
      ifaceInput.setAttribute("list", listId);
      ifaceInput.title = "candidates from this sensor's own report: " + nics.join(", ");
    } else {
      ifaceInput.removeAttribute("list");
    }
  }
  const plan = r.plan || {};
  WL_PLAN.sensor_id = r.sensor_id;
  WL_PLAN.changes = {};
  WL_PLAN.survey = null;

  // The mode control: the DECLARED mode, and an explicit "not set" when there is none --
  // rendering an undeclared plan as "loch" would invent a declaration nobody made.
  const sel = document.getElementById("wl-plan-mode");
  sel.replaceChildren();
  const opts = [["", "— not set —"], ["loch", "loch — passive"], ["siphon", "siphon — in traffic path"]];
  for (const [value, label] of opts) {
    const o = el("option", { value, text: label });
    if (String(plan.mode || "") === value) o.selected = true;
    sel.appendChild(o);
  }
  for (const f of WL_PLAN_FIELDS) {
    const input = wlPlanInput(f);
    if (input) input.value = String(plan[f] || "");
  }
  const state = document.getElementById("wl-plan-state");
  if (state) {
    const declared = plan.mode || "(no mode declared)";
    const reported = r.reported_mode || "(not reported)";
    state.textContent = `topology: ${r.topology || "capture"} · declared: ${declared} · last reported: ${reported}`;
  }
  const note = document.getElementById("wl-plan-note");
  if (note) {
    note.textContent = plan.mode === "" || plan.mode === undefined
      ? "No plan is declared for this weirling, so it runs as a passive capture. Sonar will "
        + "survey its capture port, or set the fields below and apply."
      : "";
  }
  wlRenderPlanProbeNote("");
  wlRenderPlanStage();
}

/** One input edit: staged against the SERVER's value, so reverting un-stages it. */
function wlStagePlanField(field) {
  const input = wlPlanInput(field);
  if (!input) return;
  const original = String((wlDetail && wlDetail.plan && wlDetail.plan[field]) || "");
  const value = (input.value || "").trim();
  if (value === original) delete WL_PLAN.changes[field];
  else WL_PLAN.changes[field] = value;
  wlRenderPlanStage();
}

function wlRenderPlanStage(message) {
  const apply = document.getElementById("wl-plan-apply");
  const note = document.getElementById("wl-plan-note");
  const keys = Object.keys(WL_PLAN.changes);
  if (apply) apply.disabled = keys.length === 0;
  if (!note) return;
  if (message) { note.textContent = message; return; }
  if (!keys.length) return;
  note.textContent = "staged for " + WL_PLAN.sensor_id + ": "
    + keys.map((k) => `${k}=${WL_PLAN.changes[k] || "(empty)"}`).join(", ")
    + " — not applied.";
}

/** The survey's recommendations, as PLAN changes. The row keys the survey speaks
 * (intercept_segment, sensor_mode...) are the SETTINGS' vocabulary; the plan's fields are its
 * own, and translating at this boundary is what keeps the two from drifting. */
function wlPlanChangesFromSurvey(res) {
  const rec = res.recommended || {};
  const changes = {};
  if (res.interface) changes.iface = String(res.interface);
  const segment = rec.intercept_segment || res.segment || "";
  if (segment) changes.segment = String(segment);
  if (rec.intercept_addr) changes.addr = String(rec.intercept_addr);
  const gateway = rec.intercept_gateway || res.gateway || "";
  if (gateway) changes.gateway = String(gateway);
  if (rec.intercept_targets) changes.targets = String(rec.intercept_targets);
  return changes;
}

/** The capture probe's own note, cleared when the sheet opens on a different sensor. */
function wlRenderPlanProbeNote(text, isError = false) {
  const note = document.getElementById("wl-plan-probe-note");
  if (!note) return;
  note.textContent = text || "";
  note.classList.toggle("sonar-err", Boolean(isError));
}

/** A READ-ONLY capture-liveness test for THIS sensor. No mode, plan or sysctl is written. */
async function wlRunPlanProbe() {
  const sid = WL_PLAN.sensor_id;
  if (!sid) return null;
  const ifaceInput = document.getElementById("wl-plan-iface");
  const iface = (ifaceInput && ifaceInput.value || "").trim();
  const btn = document.getElementById("wl-plan-probe");
  if (!iface) {
    wlRenderPlanProbeNote("Set the capture iface first — the probe measures a named NIC.", true);
    return null;
  }
  if (btn) { btn.disabled = true; btn.textContent = "Testing capture…"; }
  wlRenderPlanProbeNote("Measuring the capture port for 30 seconds. Nothing is changed; this "
    + "only reads the NIC counters and Zeek's conn log.");
  try {
    const created = await postJSON("/api/weirlings/probe",
      { sensor_id: sid, iface, seconds: 30 });
    if (!created || !created.ok) throw new Error((created && created.error) || "the probe was refused");
    let row = created;
    const deadline = Date.now() + 90000;
    while (row && (row.status === "pending" || row.status === "running")) {
      if (Date.now() > deadline) {
        wlRenderPlanProbeNote("The probe was queued but no result arrived within 90s. The sensor "
          + "may be offline or between plan polls; refresh to see whether it completed.", true);
        return null;
      }
      await new Promise((resolve) => setTimeout(resolve, 1000));
      row = await getJSON("/api/weirlings/probe?request=" + encodeURIComponent(created.request_id));
    }
    if (!row || !row.ok) throw new Error((row && row.error) || "the probe result could not be read");
    if (row.status === "failed" || row.error) {
      wlRenderPlanProbeNote("The probe could not run: " + (row.error || "the sensor refused it"), true);
      return row;
    }
    const r = row.result || {};
    if (r.observed) {
      wlRenderPlanProbeNote(
        `Capture is live: ${r.packets_recv || 0} packet(s) and ${r.conn_bytes || 0} byte(s) of `
        + `Zeek conn log growth on ${r.iface || iface} over ${r.elapsed_s || r.seconds || 30}s.`);
    } else {
      wlRenderPlanProbeNote(
        `No traffic observed on ${r.iface || iface} during the ${r.seconds || 30}s window. `
        + "The port exists, but the mirror/segment was silent or Zeek is not attached to this NIC. "
        + "This is a valid measurement, not a failed request.", false);
    }
    return row;
  } catch (err) {
    wlRenderPlanProbeNote("The probe failed: "
      + ((err && err.payload && err.payload.error) || (err && err.message) || String(err)), true);
    return null;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Test capture (30s)"; }
  }
}

/** Sonar, FOR THIS SENSOR: the survey runs against its capture port, not the hub's. */
async function wlRunPlanSonar() {
  const sid = WL_PLAN.sensor_id;
  const btn = document.getElementById("wl-plan-sonar");
  if (!sid) return null;
  if (btn) { btn.disabled = true; btn.textContent = "Surveying…"; }
  wlRenderPlanStage(`surveying ${sid}'s capture port — this sends ARP requests on its segment…`);
  try {
    const res = await postJSON("/api/settings/sonar", { sensor: sid });
    // A refusal INSIDE the job (it ran and said no) is passed through with the server's own
    // reason, verbatim: those sentences name the fix.
    if (!res || res.ok !== true) {
      wlRenderPlanStage(`Sonar could not survey ${sid}: ${(res && res.error) || "no result"}`);
      return null;
    }
    WL_PLAN.survey = res;
    const staged = wlPlanChangesFromSurvey(res);
    for (const [k, v] of Object.entries(staged)) WL_PLAN.changes[k] = v;
    for (const f of WL_PLAN_FIELDS) {
      const input = wlPlanInput(f);
      if (input && staged[f] !== undefined) input.value = staged[f];
    }
    const parts = [`Sonar surveyed ${res.interface || "the capture port"}`];
    if (res.segment) parts.push(`${res.segment} (${res.segment_derivation || "measured"})`);
    if (res.gateway) parts.push(`gateway ${res.gateway}`);
    if (res.notes && res.notes.length) parts.push(res.notes.join(" "));
    parts.push(Object.keys(staged).length
      ? "staged from the survey — press Apply to send it to this weirling."
      : "nothing new to stage from this survey.");
    wlRenderPlanStage(parts.join(" · "));
    return res;
  } catch (err) {
    wlRenderPlanStage(`Sonar could not survey ${sid}: ${(err && err.message) || err}`);
    return null;
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Sonar for this weirling"; }
  }
}

/** Plan, then apply -- against THIS sensor's row. Returns whether it landed. */
async function wlApplyPlanChanges(changes, { confirmed = false } = {}) {
  const sid = WL_PLAN.sensor_id;
  if (!sid || !Object.keys(changes).length) return false;
  let plan;
  try {
    plan = await postJSON("/api/weirlings/plan", { sensor_id: sid, changes });
  } catch (err) {
    wlRenderPlanStage(`not applied — ${(err && err.message) || err}`);
    return false;
  }
  if (!plan || plan.ok !== true) {
    wlRenderPlanStage(`refused: ${(plan && plan.error) || "the server did not accept this plan"}`);
    return false;
  }
  const warns = (plan.proposals || []).filter((p) => p.warning && p.key in changes);
  if (warns.length && !confirmed) {
    const ok = window.confirm(
      "This change is allowed but costly:\n\n"
      + warns.map((p) => `${p.key}: ${p.warning}`).join("\n\n")
      + "\n\nApply anyway?");
    if (!ok) { wlRenderPlanStage("not applied — you declined the warning"); return false; }
  }
  // BF-9: a plan that lands IN PATH gets the echo; the reason rides the write and the trail.
  let planReason = "";
  if (String(changes.mode || "").toLowerCase() === "siphon") {
    if (typeof confirmDestructive !== "function") return false;
    const verdict = await confirmDestructive({
      title: "Putting this weirling IN PATH makes it a cut point.",
      target: `${sid} — mode = siphon`,
      blast: "its segment's traffic moves through the sensor (mappings=2); while enabled, an "
             + "outage or a bad rule takes that traffic down with it",
      reasonHint: "why this sensor is going in-path",
    });
    if (!verdict.ok) {
      wlRenderPlanStage("not applied — you declined the siphon confirmation");
      return false;
    }
    planReason = verdict.reason;
  }
  let res;
  try {
    res = await postJSON("/api/weirlings/apply", { sensor_id: sid, changes, reason: planReason });
  } catch (err) {
    wlRenderPlanStage(`not applied — ${(err && err.message) || err}`);
    return false;
  }
  if (!res || res.ok !== true) {
    wlRenderPlanStage(`refused: ${(res && res.error) || "the server did not accept the plan"}`);
    return false;
  }
  const said = [res.note || "saved."].concat(plan.warnings || []).join(" ");
  WL_PLAN.changes = {};
  // RE-READ: the panel must show the SERVER's plan, never the browser's memory of the edit.
  await openWeirling(sid);
  await loadWeirlings();
  const note = document.getElementById("wl-plan-note");
  if (note) note.textContent = said;
  // THE READ-BACK (BF-9): "saved" is the SERVER's word for the write; the plan is not applied
  // until the sensor's own plan READS BACK as the new mode. Until then: pending. If the window
  // passes without the read agreeing: NOT APPLIED — a different, actionable word.
  if (String(changes.mode || "").toLowerCase() === "siphon" && note) {
    await withReadBack({
      note,
      label: "applied to the hub's plan",
      carry: "the sensor picks it up on its next refresh (≤30s)",
      check: "check the sensor",
      tries: 3,
      delayMs: 500,
      read: () => getJSON(`/api/weirlings/detail?sensor=${encodeURIComponent(sid)}`),
      ok: (d) => {
        const s = d && d.sensor;
        const mode = String((s && (s.plan_mode || (s.plan && s.plan.mode) || s.reported_mode)) || "").toLowerCase();
        return mode === "siphon";
      },
    });
  }
  return true;
}

/** THE MODE TOGGLE: one action, Sonar first when switching a sensor INTO the path. */
async function wlPlanModeChanged() {
  const sel = document.getElementById("wl-plan-mode");
  if (!sel || !WL_PLAN.sensor_id) return;
  const want = sel.value;
  const prev = String((wlDetail && wlDetail.plan && wlDetail.plan.mode) || "");
  if (want === prev) return;
  const changes = {};
  if (want) changes.mode = want;
  if (want === "siphon") {
    // SONAR FIRST, because a plan with no segment/address cannot arm: the survey is what
    // turns "make it in-path" into a plan the sensor can actually run.
    if (!WL_PLAN.survey) {
      const res = await wlRunPlanSonar();
      if (!res) { sel.value = prev; return; }
    }
    Object.assign(changes, wlPlanChangesFromSurvey(WL_PLAN.survey));
    delete changes.mode;                       // re-added below, after the survey's fields
    changes.mode = "siphon";
  }
  const landed = await wlApplyPlanChanges(changes, { confirmed: want === "siphon" });
  if (!landed) sel.value = prev;
}

async function saveWeirling() {
  const note = document.getElementById("wl-save-note");
  const body = {
    sensor_id: (document.getElementById("wl-id").value || "").trim(),
    segment: (document.getElementById("wl-segment").value || "").trim(),
    address: (document.getElementById("wl-address").value || "").trim(),
    expected_mode: document.getElementById("wl-mode").value,
    note: (document.getElementById("wl-note").value || "").trim(),
  };
  if (!body.sensor_id) {
    // Refused HERE rather than by the server, so the operator is not told their six other fields
    // were fine and only the first one was missing.
    note.textContent = "A sensor id is required — it is the name this sensor is known by.";
    return;
  }
  note.textContent = "saving…";
  let d;
  try {
    d = await postJSON("/api/weirlings/register", body);
  } catch (err) {
    note.textContent = `Could not register: ${err && err.message ? err.message : err}`;
    return;
  }
  if (!d || d.ok !== true) {
    // The server's own refusal, verbatim: it names the fix, and paraphrasing would lose it.
    note.textContent = `Refused: ${(d && d.error) || "the server did not accept this registration"}`;
    return;
  }
  note.textContent = `Registered ${body.sensor_id}.`;
  clearWeirlingForm();
  await loadWeirlings();
}

/** ONE-CLICK ADOPTION, the network-appliance pattern. The row already hears the sensor; this files the
 * declaration from the sensor's own reports -- the same register call the drill-down makes,
 * minus the drill-down. Progress shows in the button itself; the row re-reads after, so the
 * state change is visible immediately. A refusal goes to the summary line verbatim. */
async function adoptWeirling(row, btn) {
  const label = btn ? btn.textContent : "";
  if (btn) { btn.disabled = true; btn.textContent = "Adopting…"; }
  const body = {
    sensor_id: row.sensor_id,
    address: row.address || "",
    // The DECLARED segment stays empty ON PURPOSE, exactly as in registerWeirling: the
    // declaration is the operator's word, and copying the reported one would manufacture a
    // declaration nobody made.
    segment: "",
    expected_mode: row.reported_mode || "loch",
    note: "adopted from the fleet view while it was feeding unregistered",
  };
  try {
    const d = await postJSON("/api/weirlings/register", body);
    if (!d || d.ok !== true) {
      throw new Error((d && d.error) || "the server did not accept this registration");
    }
  } catch (err) {
    if (btn) { btn.disabled = false; btn.textContent = label; }
    const note = document.getElementById("wl-summary-note");
    if (note) wlSummaryNote(`Could not adopt ${row.sensor_id}: ${(err && err.message) || err}`);
    return;
  }
  await loadWeirlings();
}

async function registerWeirling() {
  // One click, from the sensor's OWN reports: the id is what the hub is already hearing (that is
  // why the row exists at all), the mode is what the sensor says it is running, and the address --
  // when the heartbeat carried one -- is where it is reporting from. The DECLARED segment stays
  // empty ON PURPOSE: that field is the operator's word, and copying the reported one into it
  // would manufacture a declaration nobody made. This view exists to keep those two apart.
  const note = document.getElementById("wl-detail-note");
  const sensor = wlDetail;
  if (!sensor) return;
  const body = {
    sensor_id: sensor.sensor_id,
    address: sensor.address || "",
    segment: "",
    expected_mode: sensor.reported_mode || "loch",
    note: "registered from the fleet view while it was feeding unregistered",
  };
  note.textContent = "registering…";
  let d;
  try {
    d = await postJSON("/api/weirlings/register", body);
  } catch (err) {
    note.textContent = `Could not register: ${err && err.message ? err.message : err}`;
    return;
  }
  if (!d || d.ok !== true) {
    // The server's own refusal, verbatim, for the same reason as the form's: it names the fix.
    note.textContent = `Refused: ${(d && d.error) || "the server did not accept this registration"}`;
    return;
  }
  await openWeirling(sensor.sensor_id);
  note.textContent = `Registered ${sensor.sensor_id}.`;
  await loadWeirlings();
}

async function wlToggle(r, btn) {
  btn.disabled = true;
  try {
    const d = await postJSON("/api/weirlings/enable",
                             { sensor_id: r.sensor_id, enabled: !r.enabled });
    if (!d || d.ok !== true) {
      const note = document.getElementById("wl-summary-note");
      if (note) wlSummaryNote(
        `Refused: ${(d && d.error) || "the server did not accept the change"}`);
      return;
    }
  } catch (err) {
    const note = document.getElementById("wl-summary-note");
    if (note) wlSummaryNote(`Could not change it: ${(err && err.message) || err}`);
  } finally {
    btn.disabled = false;
  }
  await loadWeirlings();
}

async function setWeirlingEnabled(enabled) {
  const id = document.getElementById("wl-detail-id").textContent;
  const note = document.getElementById("wl-detail-note");
  note.textContent = enabled ? "enabling…" : "switching off…";
  let d;
  try {
    d = await postJSON("/api/weirlings/enable", { sensor_id: id, enabled: enabled });
  } catch (err) {
    note.textContent = `Could not change it: ${err && err.message ? err.message : err}`;
    return;
  }
  if (!d || d.ok !== true) {
    note.textContent = `Refused: ${(d && d.error) || "the server did not accept the change"}`;
    return;
  }
  note.textContent = enabled ? "Enabled." : "Switched off.";
  await openWeirling(id);
  await loadWeirlings();
}

async function revokeWeirling() {
  const id = document.getElementById("wl-detail-id").textContent;
  const note = document.getElementById("wl-detail-note");
  // CONFIRMED through the ONE echo -- closed here as a BF-9 gap: this path kept a bare
  // window.confirm, sent no reason (which the server refuses), and hid the card without
  // releasing the scrim.
  if (typeof confirmDestructive !== "function") return;
  const verdict = await confirmDestructive({
    title: `Revoke ${id}: the hub stops expecting it.`,
    target: id,
    blast: "its heartbeats stop being raised as missing; the record stays readable and it can "
           + "be registered again later",
    reasonHint: "why this sensor is being retired",
  });
  if (!verdict.ok) return;
  note.textContent = "revoking…";
  let d;
  try {
    d = await postJSON("/api/weirlings/revoke", { sensor_id: id, reason: verdict.reason });
  } catch (err) {
    note.textContent = `Could not revoke: ${err && err.message ? err.message : err}`;
    return;
  }
  if (!d || d.ok !== true) {
    note.textContent = `Refused: ${(d && d.error) || "the server did not accept the revocation"}`;
    return;
  }
  closeWeirling();
  await loadWeirlings();
}

/* ── NETWORK COVERAGE ─────────────────────────────────────────────────────────────────────
 * A scope card is the fleet's answer to "which networks are actually monitored?" It reads
 * the same declarations as Settings; it never derives a scope from an address. An unclassified
 * card is deliberate: traffic outside every declared network is a configuration gap, not a
 * background fact that should be hidden. */
function wlRenderExternalExposure(ext) {
  const box = document.getElementById("wl-external");
  if (!box) return;
  box.replaceChildren();
  if (!ext || !ext.available) {
    box.classList.add("hidden");
    return;
  }
  box.classList.remove("hidden");
  const n = (v) => (v === null || v === undefined ? "\u2014" : Number(v).toLocaleString());
  const pct = (v) => (v === null || v === undefined ? "\u2014" : `${Math.round(Number(v) * 100)}%`);
  const bytes = (v) => (v === null || v === undefined ? "\u2014"
    : (typeof fmtBytes === "function" ? fmtBytes(Number(v) || 0) : `${Number(v) || 0} B`));
  const direction = (label, d) => {
    const data = d || {};
    const prefixes = Array.isArray(data.top_prefixes) ? data.top_prefixes.slice(0, 3) : [];
    const prefixList = el("div", { class: "ext-prefix-list" },
      prefixes.map((p) => el("div", { class: "ext-prefix-row" }, [
        el("span", { class: "mono", text: p.prefix || "\u2014" }),
        el("span", { class: "muted", text: `${n(p.peers)} peer(s) · ${bytes(p.bytes)}` }),
      ])));
    return el("div", { class: "ext-card" }, [
      el("div", { class: "ext-k", text: label }),
      el("div", { class: "ext-v", text: `${n(data.peers)} peer address${data.peers === 1 ? "" : "es"}` }),
      el("div", { class: "ext-m muted",
        text: `${bytes(data.bytes)} · ${n(data.flows)} flow(s) · top peer ${pct(data.top_peer_share)}` }),
      prefixes.length ? el("div", { class: "ext-prefix-head muted", text: "top prefixes" }) : null,
      prefixes.length ? prefixList : null,
    ].filter(Boolean));
  };
  box.appendChild(el("div", { class: "ext-head" }, [
    el("div", { class: "ext-title", text: "External exposure" }),
    el("div", { class: "muted", text: `observed · last ${ext.hours || 24}h · not alert entities` }),
  ]));
  const grid = el("div", { class: "ext-grid" });
  grid.appendChild(direction("Inbound to monitored", ext.inbound));
  grid.appendChild(direction("Outbound from monitored", ext.outbound));
  box.appendChild(grid);
  if (ext.errors && ext.errors.length) {
    box.appendChild(el("div", { class: "ext-error muted",
      text: `Some readings are unavailable: ${ext.errors.join("; ")}` }));
  }
}

async function loadNetworkCoverage(coverage) {
  const note = document.getElementById("wl-network-note");
  const list = document.getElementById("wl-network-list");
  const state = document.getElementById("wl-network-state");
  if (!note || !list) return;
  // `full` is the storage/API value, but it reads as a generic intensifier on the console.
  // Say what it actually buys the operator: per-host baselines and alerts.
  const policyLabel = (policy) => policy === "full" ? "per-host" : (policy || "");
  const covAvailable = Boolean(coverage && coverage.available);
  const covBy = new Map(((coverage && coverage.scopes) || []).map((s) => [s.cidr, s]));
  let d;
  try {
    d = await getJSON("/api/networks");
  } catch (err) {
    if (!covAvailable) {
      note.textContent = "Network coverage could not be read: " + (err && err.message ? err.message : err);
      return;
    }
    d = null;
  }
  if (!d || !d.available) {
    if (covAvailable) {
      // THE DECLARATIONS STILL RENDER WHEN THE COUNTS ROUTE FAILS. The scope list is the part
      // that answers "what did I declare, and did a sensor see it"; host/alert counts are the
      // optional half and say "—" rather than a false zero.
      d = { available: true, scopes: coverage.scopes, counts_available: false, hours: 24,
            summary: { total: coverage.declared, monitored: coverage.declared_monitored,
                       observed: Math.max(0, (coverage.declared || 0) - (coverage.declared_monitored || 0)),
                       unclassified_hosts: null, unclassified_alerts: null },
            unconfigured: Boolean(coverage.unconfigured), external: null, external_peers: [] };
    } else {
      note.textContent = "Network coverage unavailable: " + ((d && d.reason) || "the read did not run");
      list.replaceChildren();
      return;
    }
  }
  const s = d.summary || {};
  if (state) {
    const seen = covAvailable ? ` · ${coverage.observed} seen` : "";
    state.textContent = d.unconfigured ? "not configured" :
      `${s.monitored || 0} monitored · ${s.observed || 0} observed${seen}`;
  }
  list.replaceChildren();
  const peerBox = document.getElementById("wl-peer-list");
  if (peerBox) peerBox.replaceChildren();
  if (d.unconfigured) {
    note.textContent = "No networks are declared, so detection is running unscoped: every " +
      "source address is a host. Declare internal, VPN and DMZ ranges in Settings → " +
      "Monitored networks; external traffic stays observed unless you deliberately mark it.";
    const card = el("button", { class: "net-card clickable unclassified", type: "button" }, [
      el("div", { class: "net-k", text: "unclassified" }),
      el("div", { class: "net-v", text: "all traffic" }),
      el("div", { class: "net-m", text: "configure networks to scope detection" }),
    ]);
    card.addEventListener("click", () => { if (typeof showView === "function") showView("settings"); });
    list.appendChild(card);
    return;
  }
  const bits = [];
  if (s.unclassified_hosts !== null && s.unclassified_hosts !== undefined) {
    bits.push(`${s.unclassified_hosts} host(s) and ${s.unclassified_alerts || 0} alert(s) in the ` +
      "last 24h fall outside every declared network.");
  }
  if (!d.counts_available) bits.push("Some counts could not be read; — means unknown, not zero.");
  if (covAvailable && coverage.unobserved && coverage.unobserved.length) {
    bits.push(`Declared but no sensor has seen: ` +
      coverage.unobserved.map((u) => u.cidr).join(", ") + ".");
  }
  note.textContent = bits.join(" ") || "Counts cover the last 24 hours.";
  for (const scope of d.scopes || []) {
    const monitored = Boolean(scope.monitored) && ["full", "aggregate"].includes(scope.policy);
    const seen = covBy.has(scope.cidr) ? Boolean(covBy.get(scope.cidr).observed)
      : (scope.observed === undefined ? null : Boolean(scope.observed));
    const card = el("button", {
      class: "net-card clickable" + (monitored ? "monitored" : "observed")
        + (seen === false ? " not-seen" : ""),
      type: "button",
      title: `${scope.cidr} · ${scope.label} · ${policyLabel(scope.policy)}` +
        (seen === null ? "" : (seen ? " · seen by a sensor" : " · no sensor sees this network")),
    }, [
      el("div", { class: "net-k", text: scope.label }),
      el("div", { class: "net-v mono", text: scope.cidr }),
      el("div", { class: "net-m", text: (monitored ? "monitored" : "observed") + " · " +
        policyLabel(scope.policy) }),
      el("div", { class: "net-m", text: `hosts ${scope.hosts === null || scope.hosts === undefined ? "—" : scope.hosts} · alerts ${scope.alerts === null || scope.alerts === undefined ? "—" : scope.alerts}` }),
      seen === null ? null : el("div", {
        class: "net-m" + (seen ? "net-seen" : "net-not-seen"),
        text: seen ? "seen by a sensor" : "not seen by any sensor",
      }),
    ].filter(Boolean));
    card.addEventListener("click", () => {
      if (typeof AN_FILTERS !== "undefined") { AN_FILTERS.host = ""; }
      if (typeof showView === "function") showView("settings");
    });
    list.appendChild(card);
  }
  if (s.unclassified_hosts) {
    const card = el("button", { class: "net-card clickable unclassified", type: "button" }, [
      el("div", { class: "net-k", text: "unclassified" }),
      el("div", { class: "net-v", text: `${s.unclassified_hosts} host(s)` }),
      el("div", { class: "net-m", text: `${s.unclassified_alerts || 0} alert(s) · configure a scope` }),
    ]);
    card.addEventListener("click", () => { if (typeof showView === "function") showView("settings"); });
    list.appendChild(card);
  }
  // EXTERNAL EXPOSURE IS A PEER DIMENSION. It is a reading, not a scope and not an alert
  // entity: inbound peers are external sources hitting monitored destinations; outbound peers
  // are external destinations reached by monitored sources. The list below keeps the individual
  // addresses for evidence and click-through; this panel shows the population shape.
  wlRenderExternalExposure(d.external);
  // EXTERNAL PEERS ARE AN AGGREGATE, NOT A PER-ADDRESS ALERT SOURCE. The plan says external
  // traffic should remain visible against its volume and last-seen time without becoming
  // thousands of monitored hosts; this is that reading.
  const peers = document.getElementById("wl-peer-list");
  if (peers) {
    peers.replaceChildren();
    const rows = d.external_peers || [];
    if (rows.length) {
      const maxBytes = Math.max(...rows.map((p) => Number(p.bytes) || 0), 1);
      peers.appendChild(el("div", { class: "net-peers-head" }, [
        el("div", { class: "net-peers-title", text: "External peers" }),
        el("div", { class: "muted", text: `Top ${rows.length} by bytes · last ${d.hours || 24}h · outside every declared scope` }),
      ]));
      const list = el("div", { class: "net-peer-list", attrs: { role: "list" } });
      rows.slice(0, 8).forEach((p, i) => {
        const bytes = Number(p.bytes) || 0;
        const share = Math.max(2, Math.round((bytes / maxBytes) * 100));
        const when = String(p.last_seen || "").replace("T", " ").slice(5, 16);
        const windows = Number(p.windows) || 0;
        // THE PEER IS AN ADDRESS, SO IT OPENS THE SAME HOST PAGE AS ANY OTHER ADDRESS.
        // A row that looks interactive but does nothing is worse than a plain reading; this is
        // a real keyboard-operable control, but a panel-shaped one (the button base is 28px).
        const row = el("div", {
          class: "net-peer-row clickable",
          attrs: { role: "button", tabindex: "0",
                   "aria-label": `Open host details for ${p.src_addr}` },
        }, [
          el("span", { class: "net-peer-rank", text: String(i + 1) }),
          el("span", { class: "net-peer-addr mono", text: p.src_addr }),
          el("span", { class: "net-peer-volume" }, [
            el("span", { class: "net-peer-track" }, [
              el("span", { class: "net-peer-bar", attrs: { style: `width:${share}%` } }),
            ]),
            el("span", { class: "net-peer-bytes", text: typeof fmtBytes === "function" ? fmtBytes(bytes) : `${bytes} B` }),
          ]),
          el("span", { class: "net-peer-meta muted", text: `${windows} window${windows === 1 ? "" : "s"}${when ? ` · ${when}` : ""}` }),
        ]);
        const openPeer = () => {
          if (typeof openHost === "function") openHost(p.src_addr);
        };
        row.addEventListener("click", openPeer);
        row.addEventListener("keydown", (e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            openPeer();
          }
        });
        list.appendChild(row);
      });
      peers.appendChild(list);
    } else {
      peers.appendChild(emptyState({
        state: "none", message: "No external peers in this window." }));
    }
  }
}


// ── Scanner readiness ────────────────────────────────────────────────────────────────────────
// NMAP IS OPTIONAL AND WEIRVERN NEVER INSTALLS IT. This card is a read surface plus a guided
// command. The scanner writes `scanner_status` on every pass; a node with no row is
// "not reported", which is not the same fact as "basic". After the operator installs Nmap
// from their own package manager, the next scanner pass flips the profile automatically.
function scannerChip(item) {
  if (item.state === "not_reported") return el("span", { class: "bubble state muted", text: "not reported" });
  // A STALE ROW IS NOT A PROFILE. "Basic" reads as a measured verdict about what this weirling
  // can do now; the row only says what it said before it went silent.
  if (item.state === "stale") return el("span", { class: "bubble state muted", text: "stale" });
  if (item.profile === "nmap") return el("span", { class: "bubble state ok", text: "Nmap" });
  return el("span", { class: "bubble state warn", text: "Basic" });
}

function scannerAge(value) {
  if (!value) return "never";
  const then = new Date(value).getTime();
  if (!Number.isFinite(then)) return "—";
  const s = Math.max(0, Math.round((Date.now() - then) / 1000));
  if (s < 90) return `${s}s ago`;
  const m = Math.round(s / 60);
  if (m < 90) return `${m}m ago`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h}h ago`;
  return `${Math.round(h / 24)}d ago`;
}

// ── the install sheet ───────────────────────────────────────────────────────────────────────
// ONE ACTION, ONE COMMAND, EVERYTHING ELSE BEHIND DETAILS (operator, 2026-11-20). The old
// inline "setup" expansion explained the mechanism above the fold; this surface says what will
// run, asks only for the password that host actually needs, and keeps the rest one click away.
const INSTALL = { item: null, requestId: "", timer: null };

function installEls() {
  return {
    sheet: document.getElementById("install-sheet"),
    title: document.getElementById("install-title"),
    runs: document.getElementById("install-runs"),
    details: document.getElementById("install-details"),
    subject: document.getElementById("install-subject"),
    command: document.getElementById("install-command"),
    passwordBlock: document.getElementById("install-password-block"),
    password: document.getElementById("install-password"),
    state: document.getElementById("install-state"),
    go: document.getElementById("install-go"),
    copy: document.getElementById("install-copy"),
    answer: document.getElementById("install-answer"),
    os: document.getElementById("install-os"),
    why: document.getElementById("install-why"),
    setcap: document.getElementById("install-setcap"),
    setcapCopy: document.getElementById("install-setcap-copy"),
  };
}

function installSay(text) {
  const els = installEls();
  if (els.state) els.state.textContent = String(text || "");
}

function installStop() {
  if (INSTALL.timer) { clearTimeout(INSTALL.timer); INSTALL.timer = null; }
}

/** Open the sheet for one weirling. The command line is the only fact above the fold. */
function openInstallSheet(item) {
  const els = installEls();
  if (!els.sheet || !item) return;
  installStop();
  INSTALL.item = item;
  INSTALL.requestId = "";
  const command = String(item.install_command || "");
  const needsPassword = item.sudo_state === "password";
  // AN AGED ROW CANNOT AUTHORIZE AN INSTALL. The sheet may still be opened from the table's
  // Details, so it says the report is old rather than pretending the host is known-incapable.
  const stale = item.state === "stale";
  const canInstall = Boolean(item.install_known && item.sudo_state && item.sudo_state !== "none")
    && !stale && !item.nmap_available;
  if (els.subject) els.subject.textContent = item.sensor_id || "";
  if (els.title) els.title.textContent = "Install nmap";
  if (els.runs) els.runs.setAttribute("data-sensor", item.sensor_id || "");
  if (els.details) els.details.open = false;
  if (els.command) els.command.textContent = command || "—";
  if (els.passwordBlock) els.passwordBlock.classList.toggle("hidden", !needsPassword);
  if (els.password) els.password.value = "";
  if (els.go) {
    els.go.classList.toggle("hidden", !canInstall);
    els.go.disabled = false;
    els.go.textContent = "Install";
  }
  if (els.copy) els.copy.classList.toggle("hidden", canInstall || item.nmap_available || !command);
  if (els.answer) els.answer.textContent = item.install_answer || "";
  if (els.os) els.os.textContent = item.os_label || "";
  if (els.why) els.why.textContent = item.nmap_available
    ? "Nmap is already present; there is nothing to install."
    : (item.install_privileged
      ? "This weirling can run the install itself."
      : "No privilege path on this host: copy the command and run it as root.");
  if (els.setcap) els.setcap.textContent = item.setcap_command || "";
  installSay(stale ? `No report in ${item.age || "over 15m"}.`
    : (item.nmap_available ? "Nmap is already installed." : ""));
  openSheet(els.sheet, { initialFocus: "install-close" });
}

async function installPoll(attempt) {
  const els = installEls();
  if (!INSTALL.requestId) return;
  let data;
  try {
    data = await getJSON(`/api/weirlings/install/${encodeURIComponent(INSTALL.requestId)}`);
  } catch (err) {
    installSay("Could not read the install.");
    return;
  }
  if (data && data.output && els.why) els.why.textContent = String(data.output);
  if (data && data.state === "done") {
    const where = (INSTALL.item && (INSTALL.item.networks || []).join(", ")) || "its networks";
    installSay(`Installed. This weirling can scan ${where}.`);
    if (els.go) { els.go.textContent = "Installed"; els.go.disabled = true; }
    if (els.password) els.password.value = "";
    loadScannerStatus().catch(() => {});
    return;
  }
  if (data && (data.state === "failed" || data.state === "expired")) {
    installSay(data.state === "expired" ? "Request expired." : "Install failed.");
    if (els.go) { els.go.disabled = false; els.go.textContent = "Retry"; }
    return;
  }
  if (attempt > 150) {
    installSay("Still waiting for this weirling.");
    if (els.go) els.go.disabled = false;
    return;
  }
  installSay("Installing…");
  INSTALL.timer = setTimeout(() => { installPoll(attempt + 1).catch(() => {}); }, 1200);
}

async function installGo() {
  const els = installEls();
  const item = INSTALL.item;
  if (!item) return;
  const needsPassword = item.sudo_state === "password";
  const password = String((els.password && els.password.value) || "");
  if (needsPassword && !password) { installSay("Enter the sudo password."); return; }
  const body = { reason: "install nmap from the console" };
  if (needsPassword) body.sudo_password = password;
  if (els.go) { els.go.disabled = true; els.go.textContent = "Installing…"; }
  try {
    const created = await postJSON(
      `/api/weirlings/${encodeURIComponent(item.sensor_id)}/install`, body);
    if (!created || !created.request_id) throw new Error("no request id");
    INSTALL.requestId = String(created.request_id);
    installSay("Waiting for this weirling.");
    installPoll(0).catch(() => {});
  } catch (err) {
    if (els.go) { els.go.disabled = false; els.go.textContent = "Install"; }
    installSay("Install refused.");
  } finally {
    delete body.sudo_password;
    if (els.password) els.password.value = "";
  }
}

function installCopy() {
  const command = String((INSTALL.item && INSTALL.item.install_command) || "");
  if (!command) return;
  navigator.clipboard.writeText(command)
    .then(() => installSay("Copied. Run it on the host."))
    .catch(() => installSay("Select the command."));
}

(function wireInstall() {
  const els = installEls();
  if (els.sheet) wireSheet(els.sheet, { onClose: () => installStop() });
  if (els.go) els.go.addEventListener("click", () => { installGo().catch(() => {}); });
  if (els.copy) els.copy.addEventListener("click", () => installCopy());
  if (els.setcapCopy) els.setcapCopy.addEventListener("click", () => {
    const cmd = String((INSTALL.item && INSTALL.item.setcap_command) || "");
    if (cmd && navigator.clipboard) navigator.clipboard.writeText(cmd).catch(() => {});
  });
})();

// ── scanner readiness: a number, a status line, and one action ───────────────────────────────
async function loadScannerStatus() {
  const list = document.getElementById("scanner-list");
  const summary = document.getElementById("scanner-summary");
  const note = document.getElementById("scanner-note");
  const installBtn = document.getElementById("scanner-install");
  const details = document.getElementById("scanner-details");
  const detailText = document.getElementById("scanner-detail-text");
  if (!list || !summary || !note) return;
  let d;
  try {
    d = await getJSON("/api/scanner");
  } catch (err) {
    summary.textContent = "unknown";
    note.textContent = "Scan state unavailable.";
    list.replaceChildren();
    return;
  }
  if (!d.available) {
    summary.textContent = "unknown";
    note.textContent = "Scan state unavailable.";
    list.replaceChildren();
    return;
  }
  const sensors = d.sensors || [];
  const cap = d.capability || {};
  const total = cap.count === undefined ? sensors.length : cap.count;
  const capable = cap.capable_count || 0;
  // A STALE ROW IS NOT A CAPABILITY COUNT. If no registered weirling has a fresh report, the
  // count "0 of 1 can scan" is a verdict the hub cannot support -- say unknown instead.
  const stale = sensors.filter((s) => s.state === "stale");
  const fresh = sensors.filter((s) => s.state !== "stale" && s.state !== "not_reported");
  const missing = fresh.filter((s) => !s.nmap_available);
  summary.textContent = sensors.length && fresh.length === 0
    ? "unknown"
    : `${capable} of ${total} can scan`;
  if (cap.enabled) {
    note.textContent = "Scanning is available.";
    if (installBtn) installBtn.classList.add("hidden");
  } else {
    const one = total === 1 ? sensors[0] : null;
    if (one && one.state === "stale") {
      // THE FACT THE OLD CARD HID: no report. "Nmap missing" was the last thing this silent
      // weirling said, and the console presented it as today's measurement.
      note.textContent = `No report from this weirling in ${one.age || "over 15m"} — no agent is reporting.`;
    } else if (one && one.state === "not_reported") {
      note.textContent = "Not scanning — this weirling has not reported.";
    } else if (sensors.length && stale.length === sensors.length) {
      note.textContent = `No report from any weirling in ${stale[0].age || "over 15m"}.`;
    } else if (stale.length) {
      note.textContent = `No report from ${stale.length} of ${total} weirlings.`;
    } else if (one && !one.nmap_available) {
      note.textContent = "Not scanning — nmap missing on this weirling.";
    } else if (missing.length) {
      note.textContent = `Not scanning — nmap missing on ${missing.length} of ${total}.`;
    } else {
      note.textContent = "Not scanning.";
    }
    // ONE PRIMARY ACTION -- AND NEVER FROM AN AGED ROW. An install offered from a stale report
    // would be a guess about what that host runs today.
    if (installBtn) {
      const target = missing.find((s) => s.install_command) || missing[0] || null;
      installBtn.classList.toggle("hidden", !target);
      installBtn.onclick = target ? () => openInstallSheet(target) : null;
    }
  }
  // The server's measured sentence and the explanation stay available, one click away.
  if (detailText) detailText.textContent = String(cap.sentence || "");
  if (details) details.classList.toggle("hidden", !cap.enabled && !cap.sentence);

  list.replaceChildren();
  loadScanQueue().catch(() => {});
  if (!sensors.length) {
    list.appendChild(el("p", { class: "muted", text: "No weirling is registered yet." }));
    return;
  }
  const table = el("table", { class: "scanner-table" });
  table.appendChild(el("thead", {}, [el("tr", {}, [
    el("th", { text: "Scanner" }), el("th", { text: "Profile" }),
    el("th", { class: "scanner-nmap", text: "Nmap" }),
    el("th", { text: "Last check" }), el("th", { text: "" }),
  ])]));
  const body = el("tbody");
  for (const item of sensors) {
    const toggle = el("button", { class: "quiet", attrs: { type: "button" }, text: "Details" });
    toggle.addEventListener("click", () => openInstallSheet(item));
    const row = el("tr", {}, [
      el("td", {}, [el("span", { class: "mono", text: item.sensor_id }),
        item.sensor_id === d.local_sensor ? el("span", { class: "muted", text: " · hub" }) : null].filter(Boolean)),
      el("td", {}, [scannerChip(item)]),
      el("td", { class: "scanner-nmap" }, [el("span", { class: "mono", text: item.nmap_version || "—" })]),
      el("td", { class: "muted", text: scannerAge(item.last_check) }),
      el("td", {}, [toggle]),
    ]);
    body.appendChild(row);
  }
  table.appendChild(body);
  // THE TABLE SCROLLS INSIDE THE CARD, NOT THROUGH IT. At 390px four columns plus the action
  // overflow the card and clip the Details button; the wrapper keeps the overflow contained
  // (and .scanner-nmap is dropped at phone width, see style.css).
  const wrap = el("div", { class: "tablewrap" });
  wrap.appendChild(table);
  list.appendChild(wrap);
}

const scannerCheck = document.getElementById("scanner-check");
if (scannerCheck) scannerCheck.addEventListener("click", () => loadScannerStatus().catch(showError));
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => loadScannerStatus().catch(() => {}));
} else {
  loadScannerStatus().catch(() => {});
}
