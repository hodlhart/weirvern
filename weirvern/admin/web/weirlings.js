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
  const cls = (state === "alive") ? "ok"
    : (state === "disabled") ? "muted"
    : (state === "unregistered") ? "warn"
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
    const problems = document.getElementById("wl-problems-only").checked ? "?problems=1" : "";
    d = await getJSON(`/api/weirlings${problems}`);
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
    emptyRow(document.querySelector("#wl-table tbody"), 7,
      "The fleet cannot be shown while the registry is unreadable.");
    return;
  }
  showDataError(null);

  // ── the fleet's own state, first and largest
  const s = d.summary || {};
  const items = [
    ["weirlings", String(s.total ?? "—")],
    ["reporting", String(s.alive ?? "—")],
    ["problems", String(s.problems ?? "—")],
    ["never seen", String(s.never_seen ?? "—")],
    ["unregistered", String(s.unregistered ?? "—")],
    ["disabled", String(s.disabled ?? "—")],
  ];
  for (const [k, v] of items) {
    summaryBox.appendChild(el("div", { class: "stat" }, [
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
    emptyRow(tbody, 7, (document.getElementById("wl-problems-only").checked
      ? "No weirling has a problem."
      : "No sensors yet. Register one above, or point a sensor's exporter at this hub."));
  }

  for (const r of rows) {
    const tr = el("tr", { class: r.is_problem ? "row-problem" : "" });

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

    tr.appendChild(el("td", {}, [wlStateChip(r.state)]));

    // The address, plus what the sensor REPORTED for its segment when the two disagree -- the
    // declaration and the observation are different facts.
    tr.appendChild(el("td", {}, [
      el("span", { class: "mono", text: r.address || "—" }),
    ]));

    tr.appendChild(el("td", {}, [
      el("span", { text: r.segment || (r.reported_segment || "—") }),
      (r.segment && r.reported_segment
        && r.segment.toLowerCase() !== r.reported_segment.toLowerCase())
        ? el("div", { class: "muted", text: `reports: ${r.reported_segment}` }) : null,
    ].filter(Boolean)));

    tr.appendChild(el("td", { class: "mono", text: wlAge(r.age_s) }));
    tr.appendChild(el("td", { class: "mono", text: wlLoss(r.capture_loss_pct) }));

    // THE ROW SHOWS THE MOST IMPORTANT FINDING, NOT THE FIRST ONE -- and the difference is a real
    // defect this harness caught. The server appends findings in classification order, so for a
    // never-seen in-path sensor the first is the generic "registered but has never reported",
    // while the URGENT one ("this segment may be waiting on an intercept that has never run")
    // is second. Showing only the first meant the most consequential sentence in the fleet never
    // reached the screen until the operator happened to click, which inverts the point of the
    // view: the row is what tells them whether to click at all.
    //
    // So the row prefers an IN-PATH finding when there is one, falling back to the first. The
    // remaining findings are counted, not hidden: "and 2 more" is what sends someone to the
    // drill-down rather than leaving them to assume the row said everything.
    const findings = r.findings || [];
    const urgent = findings.find((f) => /in-path|IN-PATH/.test(f)) || findings[0] || "";
    const shown = urgent.length > 90 ? urgent.slice(0, 88) + "…" : urgent;
    const rest = findings.length - (urgent ? 1 : 0);
    tr.appendChild(el("td", { class: "muted" }, [
      el("span", { text: shown }),
      rest > 0 ? el("div", { class: "muted", text: `and ${rest} more — open the sensor` }) : null,
    ].filter(Boolean)));

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
        tr.appendChild(el("td", {}, [el("span", { class: "chip muted", text: "revoked" })]));
        tr.appendChild(el("td", { class: "mono", text: r.address || "—" }));
        tr.appendChild(el("td", { text: r.segment || "—" }));
        tr.appendChild(el("td", { class: "mono", text: "—" }));
        tr.appendChild(el("td", { class: "mono", text: "—" }));
        tr.appendChild(el("td", { class: "muted", text: r.revoked_at ? `retired ${r.revoked_at}` : "" }));
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

  body.appendChild(el("p", { class: "muted",
    text: "Runtime settings for this weirling live in Settings \u2192 Weirling settings, " +
          "where you pick the weirling first \u2014 only the one this hub runs can be " +
          "changed here." }));

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
async function wlPopulateSelector() {
  const sel = document.getElementById("st-wl-select");
  if (!sel || sel.dataset.filled) return;
  let rows = [];
  try {
    const d = await getJSON("/api/weirlings");
    rows = d.sensors || [];
  } catch (err) {
    const note = document.getElementById("st-wl-note");
    if (note) note.textContent = `could not read the fleet: ${(err && err.message) || err}`;
    return;
  }
  sel.replaceChildren(el("option", { value: "",
    text: rows.length ? "pick a weirling" : "none registered" }));
  let localId = "";
  for (const r of rows) {
    sel.appendChild(el("option", { value: r.sensor_id,
      text: r.sensor_id + (r.local ? " (this hub)" : "") }));
    if (r.local) localId = r.sensor_id;
  }
  const keep = sessionStorage.getItem("weirvern-wl-settings") || localId
    || (rows[0] || {}).sensor_id || "";
  if (keep) sel.value = keep;
  sel.dataset.filled = "1";
  await wlSettingsFor(sel.value);
}

async function wlSettingsFor(sensorId) {
  const cfg = document.getElementById("wl-sensor-config");
  const remote = document.getElementById("wl-sensor-remote");
  const head = document.getElementById("st-wl-head");
  const note = document.getElementById("st-wl-note");
  if (!cfg || !remote) return;
  if (!sensorId) {
    cfg.classList.add("hidden");
    remote.classList.add("hidden");
    return;
  }
  sessionStorage.setItem("weirvern-wl-settings", sensorId);
  try {
    const d = await getJSON(`/api/weirlings/detail?sensor=${encodeURIComponent(sensorId)}`);
    const r = (d && d.sensor) || {};
    if (head) head.textContent = `\u2014 ${sensorId}${r.local ? " (runs on this hub)" : ""}`;
    if (r.local) {
      cfg.classList.remove("hidden");
      remote.classList.add("hidden");
      if (note) note.textContent = "Changes stage and apply like every settings edit.";
    } else {
      cfg.classList.add("hidden");
      remote.classList.remove("hidden");
      if (note) note.textContent = "Not the weirling this hub runs: its runtime can only be changed on its own box.";
    }
  } catch (err) {
    cfg.classList.add("hidden");
    remote.classList.add("hidden");
    if (note) note.textContent = `could not read ${sensorId}: ${(err && err.message) || err}`;
  }
}

function wireWeirlings() {
  const reload = document.getElementById("wl-reload");
  if (reload) reload.addEventListener("click", () => loadWeirlings().catch(showError));

  const pick = document.getElementById("st-wl-select");
  if (pick) pick.addEventListener("change", () => wlSettingsFor(pick.value));

  for (const id of ["wl-problems-only", "wl-revoked"]) {
    const box = document.getElementById(id);
    if (box) box.addEventListener("change", () => loadWeirlings().catch(showError));
  }

  const save = document.getElementById("wl-save");
  if (save) save.addEventListener("click", () => saveWeirling());

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
