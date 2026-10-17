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
  return el("span", { class: `chip ${cls}`, text: label });
}

// Capture loss: null is NOT 0.0. A sensor that has never measured it must not read as perfect.
function wlLoss(v) {
  if (v === null || v === undefined) return "—";
  return `${Number(v).toFixed(1)}%`;
}

async function loadWeirlings() {
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
  summaryBox.replaceChildren();
  noteBox.textContent = "";

  if (!d.available) {
    // THE DEFECT THIS PREVENTS: a registry outage rendering as a calm, empty, healthy fleet.
    showDataError(d.reason || "the weirling registry is unavailable");
    summaryBox.appendChild(el("p", { class: "empty",
      text: `Fleet unknown — ${d.reason || "the registry did not answer"}.` }));
    document.getElementById("wl-count").textContent = "";
    emptyRow(document.querySelector("#wl-table tbody"), 2,
      "The fleet cannot be shown while the registry is unreadable.");
    return;
  }
  showDataError(null);

  // ── the fleet's own state, first and largest
  const s = d.summary || {};
  // THE THIRD ELEMENT IS THE TILE'S MEANING, not its number: a count of zero needs no colour,
  // and a problem nobody can spot at a glance is a problem reported in sixpt grey.
  const items = [
    ["weirlings", String(s.total ?? "—"), ""],
    ["reporting", String(s.alive ?? "—"), (s.alive ?? 0) > 0 ? "ok" : ""],
    ["problems", String(s.problems ?? "—"), (s.problems ?? 0) > 0 ? "bad" : ""],
    ["never seen", String(s.never_seen ?? "—"), (s.never_seen ?? 0) > 0 ? "warn" : ""],
    ["unregistered", String(s.unregistered ?? "—"), (s.unregistered ?? 0) > 0 ? "warn" : ""],
    ["disabled", String(s.disabled ?? "—"), (s.disabled ?? 0) > 0 ? "muted" : ""],
  ];
  for (const [k, v, cls] of items) {
    summaryBox.appendChild(el("div", { class: cls ? `stat ${cls}` : "stat" }, [
      el("div", { class: "v", text: v }),
      el("div", { class: "k", text: k }),
    ]));
  }

  // The server's own sentences, verbatim: it knows whether the heartbeat read degraded, and
  // paraphrasing would lose the reason an operator acts on.
  const bits = [];
  if (d.heartbeats_available === false) {
    bits.push(`Heartbeats are unavailable (${d.heartbeat_reason || "the read did not run"}), so every `
      + `registered weirling below reads as NEVER SEEN. That is a gap in this view, not evidence about `
      + `the weirlings.`);
  }
  if (d.filtered) bits.push("Showing problems only.");
  if ((s.total ?? 0) === 0 && d.heartbeats_available !== false) {
    bits.push("No weirlings are registered and none are reporting. Register one below to record the "
      + "expectation, so a weirling that never comes up is reported rather than invisible.");
  }
  noteBox.textContent = bits.join(" ");

  // ── the rows
  renderWeirlings(d.sensors || [], d.revoked || [], d.revoked_reason || "");

  const count = document.getElementById("wl-count");
  count.textContent = `— ${(d.sensors || []).length} shown`;
}

function renderWeirlings(rows, revoked, revokedReason) {
  const tbody = document.querySelector("#wl-table tbody");
  const empty = document.getElementById("wl-empty");
  tbody.replaceChildren();
  empty.textContent = "";

  const showRevoked = document.getElementById("wl-revoked").checked;

  if (!rows.length) {
    emptyRow(tbody, 2, (document.getElementById("wl-problems-only").checked
      ? "No weirling has a problem."
      : "No sensors yet. Register one above, or point a sensor's exporter at this hub."));
  }

  for (const r of rows) {
    // The state on the ROW, not only in the chip: a scanning eye reads the row's edge before it
    // reads any word (see the .wl-state-* rules in style.css).
    const tr = el("tr", { class: `wl-state-${r.state || "unknown"}` +
                                 (r.is_problem ? " row-problem" : "") });

    // The sensor id is the drill-down affordance AND stays a plain text label -- a button inside
    // a table cell is the accessible form of "the row is clickable".
    tr.appendChild(el("td", {}, [
      el("button", {
        class: "link",
        text: r.sensor_id,
        attrs: { title: "open this sensor" },
        on: { click: () => openWeirling(r.sensor_id) },
      }),
      r.note ? el("div", { class: "muted", text: r.note }) : null,
    ].filter(Boolean)));

    // EACH SENSOR AND ITS STATUS -- the operator, 2026-10-17 ("I don't need all the extra
    // info... just each sensor and their status"). The chip carries the state and its colour;
    // the age rides beside it because "stale" without "for how long" is half the fact.
    // Everything else -- address, segments, modes, loss, findings -- is one click away in the
    // drill-down, which was always where the full story lived.
    tr.appendChild(el("td", {}, [
      wlStateChip(r.state),
      el("span", { class: "muted", text: " " + wlAge(r.age_s) }),
    ]));

    tbody.appendChild(tr);
  }

  // Revoked registrations are shown BESIDE the fleet, never inside it: a sensor somebody removed
  // must not read as a problem on every refresh, but "was this ever covered?" has to be
  // answerable or the cleanup erases the evidence.
  if (showRevoked) {
    if (revokedReason) {
      empty.textContent = `Revoked registrations could not be read: ${revokedReason}`;
    } else if (!revoked.length) {
      empty.textContent = "No sensor has been revoked.";
    } else {
      for (const r of revoked) {
        const tr = el("tr", { class: "muted" });
        tr.appendChild(el("td", {}, [
          el("span", { class: "mono", text: r.sensor_id }),
          el("span", { class: "muted", text: " (revoked)" }),
        ]));
        tr.appendChild(el("td", {}, [
          el("span", { class: "chip muted", text: "revoked" }),
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

async function openWeirling(sensorId) {
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
  card.classList.remove("hidden");

  let d;
  try {
    d = await getJSON(`/api/weirlings/detail?sensor=${encodeURIComponent(sensorId)}`);
  } catch (err) {
    body.replaceChildren(el("p", { class: "empty",
      text: `Could not read this sensor: ${err && err.message ? err.message : err}` }));
    return;
  }

  if (!d.available) {
    body.replaceChildren(el("p", { class: "empty",
      text: `Sensor unknown — ${d.reason || "the read did not run"}.` }));
    return;
  }
  if (!d.sensor) {
    body.replaceChildren(el("p", { class: "empty", text: d.note || "no such sensor" }));
    return;
  }

  const r = d.sensor;
  wlDetail = r;
  body.replaceChildren();

  // THE RUNTIME CONTROLS: only where they mean something (a runtime can only be changed on
  // the box that runs the sensor); hidden -- never lying -- for every other selection.
  const runtime = document.getElementById("wl-runtime");
  if (runtime) runtime.classList.toggle("hidden", !r.local);
  const wlSel = document.getElementById("wl-mode-select");
  if (wlSel) {
    wlSel.value = (String(r.reported_mode || "").toLowerCase() === "siphon")
      ? "siphon" : "loch";
  }
  const wlSonarNote = document.getElementById("st-sonar-note");
  if (wlSonarNote) wlSonarNote.textContent = "";
  const wlTestNote = document.getElementById("st-test-note");
  if (wlTestNote) wlTestNote.textContent = "";
  const wlAdv = document.getElementById("wl-advanced");
  if (wlAdv) wlAdv.open = false;   // each sensor's panel starts collapsed
  if (r.local && !document.querySelector("#st-sensor .setting")) {
    // The Advanced grid is filled by the settings machinery; open it on demand.
    try { await loadSettings(); } catch (_e) { /* the grid simply stays empty */ }
  }

  // The findings FIRST, because they are the reason the operator opened this. A state word alone
  // does not say whether "stale" means the box is off or its capture died.
  const findings = r.findings || [];
  if (findings.length) {
    const ul = el("ul", { class: "findings" });
    for (const f of findings) ul.appendChild(el("li", { text: f }));
    body.appendChild(ul);
  }

  const facts = [
    ["state", wlStateChip(r.state)],
    ["NICs", el("span", { class: "mono",
      text: (r.interfaces || []).join(", ") || "— (not reported)" })],
    ["address", el("span", { class: "mono", text: r.address || "— (not known yet)" })],
    ["declared segment", el("span", { text: r.segment || "— (not declared)" })],
    ["reported segment", el("span", { text: r.reported_segment || "— (not reported)" })],
    ["declared mode", el("span", { class: "mono", text: r.expected_mode || "—" })],
    ["reported mode", el("span", { class: "mono", text: r.reported_mode || "—" })],
    ["registered", el("span", { text: r.registered ? "yes" : "NO — this sensor is undeclared" })],
    ["enabled", el("span", { text: r.enabled ? "yes" : "no" })],
    ["last heard", el("span", { class: "mono", text: wlAge(r.age_s) })],
    ["capture loss", el("span", { class: "mono", text: wlLoss(r.capture_loss_pct) })],
    ["packets received", el("span", { class: "mono",
      text: r.packets_recv === null || r.packets_recv === undefined ? "— (not measured)"
        : String(r.packets_recv) })],
    ["packets dropped", el("span", { class: "mono",
      text: r.packets_dropped === null || r.packets_dropped === undefined ? "— (not measured)"
        : String(r.packets_dropped) })],
    ["hosts seen", el("span", { class: "mono", text: String(r.hosts ?? 0) })],
    ["note", el("span", { text: r.note || "—" })],
  ];
  const dl = el("dl", { class: "kv" });
  for (const [k, v] of facts) {
    dl.appendChild(el("dt", { text: k }));
    dl.appendChild(el("dd", {}, [v]));
  }
  body.appendChild(dl);

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
    registerBtn.textContent = "Register this sensor";
    note.textContent = "This sensor is not registered, so there is nothing to enable or retire. "
      + "Register it here — one click, from its own reports — or add its address to the flow "
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
  const reload = document.getElementById("wl-reload");
  if (reload) reload.addEventListener("click", () => loadWeirlings().catch(showError));

  for (const id of ["wl-problems-only", "wl-revoked"]) {
    const box = document.getElementById(id);
    if (box) box.addEventListener("change", () => loadWeirlings().catch(showError));
  }

  const save = document.getElementById("wl-save");
  if (save) save.addEventListener("click", () => saveWeirling());

  const modeSel = document.getElementById("wl-mode-select");
  if (modeSel) modeSel.addEventListener("change", () => wlApplyMode().catch(showError));

  const cancel = document.getElementById("wl-cancel");
  if (cancel) cancel.addEventListener("click", () => clearWeirlingForm());

  const close = document.getElementById("wl-detail-close");
  if (close) close.addEventListener("click", () => {
    document.getElementById("wl-detail-card").classList.add("hidden");
  });

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

/** APPLY A MODE CHANGE FROM THE DRILL-DOWN (operator, 2026-10-17: "a mode selection...
 * and a sonar button" per sensor, "as easy as clicking sonar and enabling it"). Selecting
 * siphon runs Sonar first when this session has not surveyed yet, stages what it found plus
 * the mode, and applies through the ordinary plan-and-apply path (the server's gates
 * included). Selecting loch applies the mode alone. The select reverts if refused. */
async function wlApplyMode() {
  const sel = document.getElementById("wl-mode-select");
  if (!sel || sel.disabled) return;
  const want = sel.value === "siphon" ? "siphon" : "loch";
  const prev = (wlDetail && String(wlDetail.reported_mode || "").toLowerCase() === "siphon")
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
      const n = document.getElementById("wl-detail-note");
      if (n) n.textContent = "Nothing to change — already " + want + ".";
      return;
    }
    await applyStage(true);
    const msg = LAST_APPLY.text || "applied.";
    if (wlDetail && wlDetail.sensor_id) {
      await openWeirling(wlDetail.sensor_id).catch(() => {});
    }
    // AFTER the re-open: it clears the note while rebuilding the panel.
    const note2 = document.getElementById("wl-detail-note");
    if (note2) note2.textContent = msg;
  } finally {
    sel.disabled = false;
  }
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
  // CONFIRMED, because it is not reversible from this page: re-registering is how a sensor comes
  // back, and an operator should not learn that by clicking.
  if (!window.confirm(`Revoke ${id}?\n\nThe registration is retired but kept for the audit trail. `
    + `Re-register it to bring it back.`)) return;
  note.textContent = "revoking…";
  let d;
  try {
    d = await postJSON("/api/weirlings/revoke", { sensor_id: id });
  } catch (err) {
    note.textContent = `Could not revoke: ${err && err.message ? err.message : err}`;
    return;
  }
  if (!d || d.ok !== true) {
    note.textContent = `Refused: ${(d && d.error) || "the server did not accept the revocation"}`;
    return;
  }
  document.getElementById("wl-detail-card").classList.add("hidden");
  await loadWeirlings();
}
