// ── Sluice Gate ───────────────────────────────────────────────────────────────────────────────
//
// WHAT PASSES, AND WHAT DOES NOT. Weirvern already sees everything; this is the part that can stop
// it.
//
// THREE RULES THIS FILE FOLLOWS, all of them learned from this project's own failures:
//
//  1. THE GATE'S STATE IS NOT THE RULE COUNT. An operator's first question is "is this actually
//     blocking anything", and a list of rules answers a different question. So the state panel is
//     rendered first and separately, and a DEGRADED gate says so in the server's own words rather
//     than being inferred from an empty number.
//
//  2. A FAILED QUERY NEVER LOOKS LIKE AN EMPTY RESULT. Every panel distinguishes "the server could
//     not answer" from "the answer is none" -- the same rule the rest of this GUI follows, and the
//     reason the project treats "a green reading over work that did not happen" as its worst bug
//     class.
//
//  3. A LIVE RULE AND A LAPSED ONE LOOK DIFFERENT. "This rule exists but is not enforced" is a
//     different statement from "this rule does not exist", and it is exactly what an operator asks
//     after a block stops working.

// Seconds -> a phrase. A NEGATIVE value means it lapsed N seconds ago, which is a real answer
// rather than an error: the server sends seconds so the client never does clock arithmetic against
// a box that may not share its timezone.
function sluiceDuration(seconds) {
  // NULL IS NOT MISSING: it is a rule with NO EXPIRY, which the store records on purpose when the
  // operator sets a duration of 0 (until revoked). "never" would read as "never enforced", so the
  // row says what the operator actually chose.
  if (seconds === null || seconds === undefined) return "until revoked";
  const past = seconds < 0;
  const s = Math.abs(seconds);
  let text;
  if (s < 60) text = `${s}s`;
  else if (s < 3600) text = `${Math.round(s / 60)}m`;
  else if (s < 86400) text = `${(s / 3600).toFixed(1)}h`;
  else text = `${(s / 86400).toFixed(1)}d`;
  return past ? `${text} ago` : `in ${text}`;
}

function sluiceStateChip(state) {
  const cls = state === "armed" ? "ok" : (state === "degraded" ? "bad" : "muted");
  return el("span", { class: `chip ${cls}`, text: state || "unknown" });
}

async function loadSluice() {
  if (typeof scheduleURLSync === "function") scheduleURLSync();
  // A REJECTED REQUEST MUST STILL SAY SOMETHING. `showView` fires this without awaiting it, so a
  // bare `await getJSON(...)` that rejects becomes an unhandled rejection: the panel keeps whatever
  // it had, no banner appears, and the operator sees a stale or empty gate. That is this project's
  // worst failure class -- a failed query reading as an empty result -- and the route's own
  // `available: false` cannot cover it, because the request never produced a response to read.
  //
  // So the failure is caught HERE and rendered through the same banner the rest of the GUI uses.
  let d;
  try {
    d = await getJSON("/api/sluice");
  } catch (err) {
    showDataError(`the gate query failed: ${(err && err.message) || err}`);
    const box = document.getElementById("sl-state");
    if (box) {
      box.replaceChildren();
      box.appendChild(el("p", { class: "empty",
        text: "Gate state unknown — the query did not complete. Nothing here says the gate is " +
              "open or shut; it says the answer could not be read." }));
    }
    const note = document.getElementById("sl-state-note");
    if (note) note.textContent = "Rules and policy are not shown for the same reason.";
    // NOT RE-THROWN. `showView` attaches `.catch(showError)` to this call, and re-throwing would
    // report ONE failure as TWO banners with different ids -- "Data unavailable" from here and
    // "Could not load data" from there -- which a later successful load then clears together. The
    // operator would see the error flash and vanish. A loader that has already told the reader what
    // happened should not hand the failure on for a second telling.
    return;
  }

  // What has been imported and what it caught: same payload, same load, one place to read.
  renderBlocklists(d);
  loadBlockingControls().catch(showError);

  // ── the gate's own state ────────────────────────────────────────────────────────────────────
  const stateBox = document.getElementById("sl-state");
  const noteBox = document.getElementById("sl-state-note");
  stateBox.replaceChildren();
  noteBox.textContent = "";

  const gate = d.gate || {};
  if (!d.available) {
    // A FAILED QUERY IS NOT "THE GATE IS OFF". Saying so would tell an operator nothing is being
    // blocked when the truth is that nobody knows.
    showDataError(d.reason || "the gate state is unavailable");
  } else {
    showDataError(null);
  }

  if (gate.available === false) {
    stateBox.appendChild(el("p", { class: "empty",
      text: `Gate state unknown — ${gate.reason || "the state query did not run"}.` }));
  } else {
    const items = [
      ["state", gate.state || (d.enabled ? "not yet run" : "disabled")],
      ["interface", gate.iface || d.iface || "—"],
      ["rules enforced", String(gate.rules_active ?? "—")],
      ["rules total", String(gate.rules_total ?? "—")],
      // THE CONSOLE'S OWN FORMATTERS (issue #23): raw integers read as foreign next to every
      // other panel -- no digit grouping, and a byte total with no scale. Missing still renders
      // the placeholder and a real zero still renders 0, never hidden.
      ["packets blocked",
       gate.packets_blocked == null ? "—" : Number(gate.packets_blocked).toLocaleString()],
      ["bytes blocked",
       gate.bytes_blocked == null ? "—" : fmtBytes(gate.bytes_blocked)],
    ];
    for (const [k, v] of items) {
      stateBox.appendChild(el("div", { class: "stat" }, [
        el("div", { class: "v", text: v }),
        el("div", { class: "k", text: k }),
      ]));
    }
  }

  // The server's own sentence, verbatim. It knows WHY (no interface, missing nft, a ruleset that
  // did not install) and paraphrasing it here would lose the reason an operator acts on.
  const bits = [];
  if (gate.detail) bits.push(gate.detail);
  if (gate.warning) bits.push(gate.warning);
  if (!d.enabled) {
    bits.push("Blocking is DISABLED (SLUICE_ENABLED=0), so no rule is enforced however many exist.");
  }
  noteBox.textContent = bits.join(" ");

  // ── where the rules are enforced ─────────────────────────────────────────────────────────────
  //
  // ONE RULE STORE, MANY GATES. In a distributed deployment the hub is not the only place traffic
  // can be stopped: every weirling that sits in the path installs the same rules on its own
  // segment. "The rule is live" and "the rule is blocking the segment that saw it" are different
  // statements, and only this list tells them apart -- a gate that stopped reporting is a segment
  // where the operator THINKS traffic is filtered and it is not.
  const gateBody = document.querySelector("#sl-gates tbody");
  const gateNote = document.getElementById("sl-gates-note");
  if (gateBody && gateNote) {
    gateBody.replaceChildren();
    const gates = d.gates || [];
    if (!d.gates_available) {
      gateNote.textContent = `The fleet's gates could not be read — ${
        d.gates_reason || "the query failed"}. This says nothing about whether any of them is armed.`;
    } else if (!gates.length) {
      gateNote.textContent = "No gate has reported. Enforcement happens where a gate runs — "
        + "see the deployment notes for putting one on a sensor that sits in the path.";
    } else {
      gateNote.textContent = gates.some((g) => g.stale)
        ? "A gate marked stale has stopped reporting: its segment is NOT being filtered, "
          + "whatever the rule list says."
        : "Every gate listed reported within its own interval.";
      for (const g of gates) {
        gateBody.appendChild(el("tr", {}, [
          el("td", {}, [
            g.sensor
              // US-2: a gate's sensor is an ENTITY -- one click to its fleet sheet.
              ? el("span", { class: "mono dcell",
                             attrs: { title: "open this sensor's fleet sheet" },
                             on: { click: () => {
                               if (typeof openWeirling === "function") {
                                 openWeirling(g.sensor).catch(showError);
                               }
                             } } },
                  [el("span", { text: g.sensor })])
              : el("span", { class: "mono", text: "—" }),
            g.local ? el("span", { class: "muted", text: "  (this hub)" }) : null,
          ]),
          el("td", {}, [sluiceStateChip(g.state)]),
          el("td", { class: "mono", text: g.iface || "—" }),
          el("td", { class: "mono", text: `${g.rules_active ?? 0} / ${g.rules_total ?? 0}` }),
          el("td", { class: "mono",
                     text: Number(g.packets_blocked ?? 0).toLocaleString() }),
          el("td", { class: "muted", text: g.age_s == null ? "—" : fmtAge(g.age_s) }),
          el("td", { class: "muted", text: g.enforcement || "none" }),
        ]));
      }
    }
  }

  // ── the rules ───────────────────────────────────────────────────────────────────────────────
  const liveOnly = document.getElementById("sl-live-only").checked;
  let rules = d.rules || [];
  if (liveOnly) rules = rules.filter((r) => r.live);
  document.getElementById("sl-count").textContent = rules.length ? `(${rules.length})` : "";

  // US-9: THE REACH. A rule only bites where a sensor has a verified in-path channel (the same
  // test the gate form uses before it offers Block). Say the number beside the rules, and make
  // each sensor a door into its fleet sheet.
  const reachBox = document.getElementById("sl-reach");
  if (reachBox) {
    reachBox.replaceChildren();
    if (!d.gates_available) {
      reachBox.appendChild(el("span", { class: "muted",
        text: "Reach unavailable \u2014 the fleet's gate state could not be read." }));
    } else {
      const reach = (d.gates || [])
        .filter((g) => g.enforcement && !g.stale).map((g) => g.sensor);
      if (reach.length) {
        reachBox.appendChild(el("span", { class: "muted",
          text: `can act on ${reach.length} sensor${reach.length === 1 ? "" : "s"}: ` }));
        for (const sen of reach) {
          const chip = el("button", { class: "dc-chip", text: sen,
                                      attrs: { type: "button", title: `open ${sen}'s sheet` } });
          chip.addEventListener("click", () => {
            if (typeof openWeirling === "function") openWeirling(sen);
          });
          reachBox.appendChild(chip);
        }
      } else {
        reachBox.appendChild(el("span", { class: "muted",
          text: "can act on 0 sensors \u2014 no sensor has a verified in-path channel; "
              + "a rule filed now compiles and counts, but bites nothing." }));
      }
    }
  }

  // ── AT A GLANCE (US-SL1, the operator's rule 2: "tabs should provide at-a-glance information
  // or visualizations"). Every number comes from the payload loaded above -- nothing invented,
  // and a failed read leaves the strip empty rather than showing a confident zero.
  {
    const box = document.getElementById("sl-glance");
    const names = document.getElementById("sl-top-names");
    const note = document.getElementById("sl-glance-note");
    if (box) {
      box.replaceChildren();
      if (!d.available) {
        if (note) note.textContent = "\u2014 unavailable, the gate query failed";
      } else {
        if (note) note.textContent = "";
        const all = d.rules || [];
        const live = all.filter((r) => r.live).length;
        const lapsed = all.filter((r) => !r.live && !r.revoked && !r.disabled).length;
        const parked = all.filter((r) => r.disabled).length;
        const revoked = all.filter((r) => r.revoked).length;
        const alertMode = all.filter((r) => r.mode === "alert").length;
        const dropMode = all.length - alertMode;
        const hits = d.hits || [];
        const chips = [
          [`${all.length}`, all.length === 1 ? "rule" : "rules"],
          [`${live}`, "live"],
          [`${dropMode}`, "drop"],
          [`${alertMode}`, "alert-only"],
        ];
        if (lapsed) chips.push([`${lapsed}`, "lapsed"]);
        if (parked) chips.push([`${parked}`, "disabled"]);
        if (revoked) chips.push([`${revoked}`, "revoked"]);
        if (hits.length) chips.push([`${hits.length}`, "recent hits"]);
        for (const [v, k] of chips) {
          box.appendChild(el("span", { class: "stat-chip" }, [
            el("strong", { text: v }), el("span", { class: "muted", text: " " + k }),
          ]));
        }
      }
    }
    if (names) {
      names.replaceChildren();
      const hits = d.hits || [];
      if (hits.length) {
        const counts = new Map();
        for (const h of hits) {
          const n = h.domain || h.query || "(unnamed)";
          counts.set(n, (counts.get(n) || 0) + 1);
        }
        const top = [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
        names.appendChild(el("span", { class: "muted", text: "recent names: " }));
        for (const [n, c] of top) {
          names.appendChild(el("span", { class: "stat-chip" }, [
            el("span", { class: "mono", text: n }),
            el("span", { class: "muted", text: ` \u00d7${c}` }),
          ]));
        }
      }
    }
  }

  const tbody = document.querySelector("#sl-table tbody");
  tbody.replaceChildren();
  const empty = document.getElementById("sl-empty");

  if (!rules.length) {
    // The distinction the whole project cares about: an empty list from a WORKING server is a
    // legitimate answer; an empty list from a FAILED one is not.
    empty.textContent = d.available
      ? (liveOnly
          ? "No rule is currently enforced. Untick 'live rules only' to see rules that exist but have lapsed."
          : "No blocking rules exist. Traffic is being watched, not stopped.")
      : "";
    // Leave the table hidden rather than showing an empty grid with headers.
    return;
  }
  empty.textContent = "";

  for (const r of rules) {
    const stateCell = r.revoked
      ? el("span", { class: "chip muted", text: "revoked" })
      : (r.live
          ? el("span", { class: "chip ok", text: "live" })
          // A LAPSED RULE IS ITS OWN STATE, not a missing one: the operator needs to see that it
          // existed and stopped, because that is the difference between "the block worked and
          // expired" and "the block never applied".
          : el("span", { class: "chip muted", text: "lapsed" }));

    const pick = el("input", { attrs: { type: "checkbox" }, class: "sl-pick" });
    pick.value = r.rule_id;
    pick.title = "select for a bulk action";
    pick.setAttribute("aria-label", `select rule ${r.describes || r.rule_id}`);
    pick.addEventListener("click", (e) => e.stopPropagation());
    pick.addEventListener("change", slBulkRefresh);

    const tr = el("tr", { class: "sl-rule-row",
                          attrs: { title: "click to open and edit this rule",
                                   "data-rule-id": r.rule_id } }, [
      el("td", { class: "pick" }, [pick]),
      el("td", { class: "mono", text: r.describes || r.src_cidr || "—" }),
      el("td", {}, [stateCell]),
      // Origin matters for trust: a rule an analyst wrote and one a model derived are different
      // evidence, and the operator should be able to tell them apart at a glance.
      el("td", { text: r.origin === "detection" ? `detection (${r.severity || "?"})` : (r.origin || "manual") }),
      el("td", { class: "muted", text: r.live ? sluiceDuration(r.expires_in_s) : (r.expires_at || "—") }),
      el("td", { text: r.severity || "—" }),
      el("td", { class: "muted", text: r.reason || "(no reason recorded)" }),
    ]);

    if (!r.revoked) {
      // NO PER-ROW ACTION CELL (SL-1). A row opens its sheet; enable/disable and delete live
      // there, so a stray click cannot delete a rule from the list.
    } else {
      tr.appendChild(el("td", { class: "muted", text: "" }));
    }
    tr.addEventListener("click", () => {
      openRuleSheet(r);
    });
    tbody.appendChild(tr);
  }
  slBulkWire();
  slBulkRefresh();
  // US-3: a receipt/audit that named a rule fires its flash on THIS fresh render.
  sluiceApplyFlash();

  renderSluicePolicies(d);
}

// ── RULE MANAGEMENT (the operator, 2026-10-16): a trashcan and a disable icon next to each
// rule, each behind a confirm; a checkbox column with bulk delete/disable; rows clickable to
// edit (they open the SAME rule card the Blocked page uses -- one card, one code path).
function slIcon(kind) {
  const glyphs = {
    trash: '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M6 2h4l.6 1.2H14v2H2V3.2h3.4L6 2zm-3 5h10l-.8 8.1a1 1 0 0 1-1 .9H4.8a1 1 0 0 1-1-.9L3 7zm3 1.6v6h1v-6H6zm3 0v6h1v-6H9z"/></svg>',
    ban: '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M8 1.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13zm0 1.6a4.9 4.9 0 0 1 2.9.95l-6.45 6.45A4.9 4.9 0 0 1 8 3.1zm0 9.8a4.9 4.9 0 0 1-2.9-.95l6.45-6.45A4.9 4.9 0 0 1 8 12.9z"/></svg>',
    play: '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M4.5 2.2 13.5 8l-9 5.8z"/></svg>',
  };
  const span = el("span", { class: "icon" });
  span.innerHTML = glyphs[kind] || glyphs.ban;
  return span;
}

// The confirm: first click arms the button (it says so and outlines), a second click within
// five seconds runs it. No dialog -- this console does its confirming in place, where the
// operator can still see what they are confirming.
function slConfirm(btn, run) {
  if (btn.dataset.armed === "1") {
    delete btn.dataset.armed;
    btn.classList.remove("armed");
    run().catch(showError);
    return;
  }
  btn.dataset.armed = "1";
  btn.classList.add("armed");
  btn.title = "click again to confirm";
  setTimeout(() => {
    if (btn.isConnected) { delete btn.dataset.armed; btn.classList.remove("armed"); }
  }, 5000);
}

async function slRuleRevoke(r) {
  const out = await postJSON("/api/sluice/revoke", { rule_id: r.rule_id });
  if (out && out.ok) {
    slRuleNote(out.note || "revoked");
    await loadSluice();
  } else {
    showError(new Error((out && out.error) || "the rule could not be revoked"));
  }
}

async function slRuleSetDisabled(r, want) {
  const out = await postJSON("/api/sluice/rule/disabled", { rule_id: r.rule_id, disabled: want });
  if (out && out.ok) {
    const refused = (out.refused || [])[0];
    slRuleNote(refused ? refused.error : (out.note || (want ? "disabled" : "re-enabled")));
    await loadSluice();
  } else {
    showError(new Error((out && out.error) || "the rule could not be changed"));
  }
}

function slSelected() {
  return [...document.querySelectorAll("#sl-table .sl-pick:checked")].map((c) => c.value);
}

/** US-3: scroll to a rule's row and say "you are here" once (fix receipts + audit landings).
 *  TOP-LEVEL on purpose: auditGo in app.js calls it across files, and a nested copy is
 *  invisible to every caller outside its enclosure. */
let SL_FLASH_PENDING = "";
let SL_FLASH_TIMER = null;
function sluiceHighlightRule(ruleId) {
  SL_FLASH_PENDING = String(ruleId);
  // Immediate attempt (the receipt case: the row is already on screen, no render coming).
  sluiceFlashRow(SL_FLASH_PENDING);
  // The audit-fix case: showView() fires a re-render within the fetch round trip that REPLACES
  // the row just flashed. The pending id survives it and fires again on the fresh render (see
  // sluiceApplyFlash at the end of the table build). The timer bounds the wait so a pending
  // flash can never resurface on some later, unrelated render.
  if (SL_FLASH_TIMER) clearTimeout(SL_FLASH_TIMER);
  SL_FLASH_TIMER = setTimeout(() => { SL_FLASH_PENDING = ""; }, 2500);
}

/** Flash one row if it is present. Returns whether it landed. Never throws. */
function sluiceFlashRow(ruleId) {
  const tr = [...document.querySelectorAll("#sl-table tbody tr.sl-rule-row")]
    .find((r) => r.getAttribute("data-rule-id") === String(ruleId));
  if (!tr) return false;
  if (typeof tr.scrollIntoView === "function") {
    try { tr.scrollIntoView({ block: "center" }); } catch (_e) { /* fine without it */ }
  }
  tr.classList.remove("flash-hit");
  void tr.offsetWidth;
  tr.classList.add("flash-hit");
  return true;
}

/** Called at the close of every rules-table build: a pending receipt lands on the FRESH rows. */
function sluiceApplyFlash() {
  if (!SL_FLASH_PENDING) return;
  if (sluiceFlashRow(SL_FLASH_PENDING)) {
    SL_FLASH_PENDING = "";
    if (SL_FLASH_TIMER) { clearTimeout(SL_FLASH_TIMER); SL_FLASH_TIMER = null; }
  }
}

function slBulkRefresh() {
  const bar = document.getElementById("sl-bulk");
  const n = document.getElementById("sl-bulk-n");
  const count = slSelected().length;
  if (bar) bar.classList.toggle("hidden", count === 0);
  if (n) n.textContent = count ? count + " selected" : "";
}

async function slBulkAct(kind) {
  const ids = slSelected();
  if (!ids.length) return;
  // DELETING IS NOT A BULK ACTION (SL-1): a rule is deleted in its own sheet, behind a second
  // click. The bulk bar only parks or restores rules, which is reversible.
  const out = await postJSON("/api/sluice/rule/disabled",
    { rule_ids: ids, disabled: kind === "disable" });
  if (out && out.ok) {
    const n = document.getElementById("sl-block-note");
    const done = (out.changed || []).length;
    const bad = (out.refused || []).length + (out.missing || []).length;
    if (n) {
      n.textContent = `${done} rule(s) ` + (kind === "disable" ? "disabled" : "re-enabled")
        + (bad ? `; ${bad} refused` : "");
    }
    await loadSluice();
  } else {
    showError(new Error((out && out.error) || "the selection could not be changed"));
  }
}

function slBulkWire() {
  const bar = document.getElementById("sl-bulk");
  if (!bar || bar.dataset.wired === "1") return;
  bar.dataset.wired = "1";
  const all = document.getElementById("sl-pick-all");
  if (all) {
    all.addEventListener("change", () => {
      document.querySelectorAll("#sl-table .sl-pick").forEach((c) => { c.checked = all.checked; });
      slBulkRefresh();
    });
  }
  const wire = (id, kind) => {
    const b = document.getElementById(id);
    if (b) b.addEventListener("click", () => slConfirm(b, () => slBulkAct(kind)));
  };
  wire("sl-bulk-disable", "disable");
  wire("sl-bulk-enable", "enable");
  const clear = document.getElementById("sl-bulk-clear");
  if (clear) {
    clear.addEventListener("click", () => {
      document.querySelectorAll("#sl-table .sl-pick:checked").forEach((c) => { c.checked = false; });
      const a2 = document.getElementById("sl-pick-all");
      if (a2) a2.checked = false;
      slBulkRefresh();
    });
  }
}

// The policy levels, with their descriptions. Rendered from the server's own text so the GUI cannot
// drift from what the policy actually does -- a hand-written blurb here would eventually describe a
// different threshold than the code enforces.
function renderSluicePolicies(d) {
  const box = document.getElementById("sl-policies");
  box.replaceChildren();
  const policies = d.policies || {};
  if (!Object.keys(policies).length) {
    box.appendChild(el("p", { class: "empty", text: "Policy details are unavailable." }));
    return;
  }
  const current = d.criticality || "off";
  for (const [key, p] of Object.entries(policies)) {
    const active = key === current;
    const row = el("div", { class: `policy-row${active ? " active" : ""}` }, [
      el("div", { class: "policy-head" }, [
        el("strong", { text: p.label || key }),
        el("span", { class: "chip muted", text: key }),
        active ? el("span", { class: "chip ok", text: "in use" }) : el("span", {}, []),
      ]),
      el("div", { class: "muted", text: p.description || "" }),
    ]);
    if (key !== "off") {
      row.appendChild(el("div", { class: "muted", text:
        `blocks at ${p.min_severity || "—"} severity and above, ` +
        `confidence ${p.min_confidence}, for ${p.ttl_minutes} minutes` }));
    }
    box.appendChild(row);
  }
  document.getElementById("sl-criticality-note").textContent =
    `Current policy: ${current}. Change it in Settings, or set SLUICE_CRITICALITY in the cluster ` +
    `ConfigMap. A derived block is always capped by SLUICE_MAX_BLOCK_S.`;
}

function wireSluice() {
  const reload = document.getElementById("sl-reload");
  if (reload) reload.addEventListener("click", () => loadSluice().then(clearError).catch(showError));
  const liveOnly = document.getElementById("sl-live-only");
  if (liveOnly) liveOnly.addEventListener("change", () => loadSluice().then(clearError).catch(showError));

  // The operator's rule 3: one obvious "add" on the rules surface. The composer is the same one
  // the Blocked page opens -- one form, one code path -- and it is entered by a click, never
  // sitting open (rule 2).
  const newRule = document.getElementById("sl-new-rule");
  if (newRule) newRule.addEventListener("click", () => {
    if (typeof openRuleComposer === "function") openRuleComposer("");
  });
}

/* ── Blocklists: what has been imported, and what it has caught ──────────────────────────────── */
function renderBlocklists(d) {
  const body = document.getElementById("sl-bl-rows");
  if (!body) return;
  body.replaceChildren();
  const sources = d.blocklists || [];
  if (!sources.length) {
    const tr = el("tr", {});
    tr.appendChild(el("td", { class: "muted", attrs: { colspan: "5" },
      text: "No sources yet — Sync now seeds the defaults (HaGeZi LIGHT on, PRO listed and off)." }));
    body.appendChild(tr);
  }
  for (const s of sources) {
    const state = s.last_error
      ? el("span", { class: "chip bad", text: "last sync failed" })
      : (s.fetched_at ? el("span", { class: "chip ok", text: "ok" })
                      : el("span", { class: "chip muted", text: "never fetched" }));
    // CLICK A ROW TO TURN THE LIST ON OR OFF (the operator, 2026-10-16: "allow me to click them
    // to enable or disable them"). The on/off chip is separate from the sync-state chip: what
    // the list IS and how its last fetch went are different facts.
    const tr = el("tr", { class: "clickable", attrs: { title: s.enabled
      ? "click to turn this list off \u2014 its names leave the watch set"
      : "click to turn this list on \u2014 its names join the watch set" } }, [
      el("td", {}, [
        el("span", { class: "chip " + (s.enabled ? "ok" : "muted"),
                     text: s.enabled ? "on" : "off" }),
        el("span", { text: " " + s.name }),
      ]),
      el("td", {}, [state]),
      el("td", { class: "mono", text: String(s.domain_count || 0) }),
      el("td", { class: "muted", text: s.fetched_at ? fmtTime(new Date(s.fetched_at)) : "—" }),
      el("td", { class: "muted", text: s.last_error ? s.last_error.slice(0, 90) : "—" }),
    ]);
    tr.addEventListener("click", () => slToggleSource(s));
    body.appendChild(tr);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  const sync = document.getElementById("sl-bl-sync");
  if (sync) sync.addEventListener("click", async () => {
    const note = document.getElementById("sl-bl-note");
    if (note) note.textContent = "syncing… (fetches the lists; a few seconds)";
    try {
      const r = await postJSON("/api/blocklists/sync", {});
      const ok = (r.results || []).filter((x) => x.ok).length;
      if (note) note.textContent = `synced ${ok} source(s)`;
    } catch (err) {
      if (note) note.textContent = `sync failed: ${(err && err.message) || err}`;
    }
    loadSluice().then(clearError).catch(showError);
  });
  const add = document.getElementById("sl-bl-add");
  if (add) add.addEventListener("click", async () => {
    const note = document.getElementById("sl-bl-note");
    const field = document.getElementById("sl-bl-custom");
    const domain = field ? field.value.trim() : "";
    if (!domain) { if (note) note.textContent = "give a domain first"; return; }
    try {
      await postJSON("/api/blocklists/custom", { action: "add", domain });
      if (field) field.value = "";
      if (note) note.textContent = `added ${domain}`;
    } catch (err) {
      if (note) note.textContent = (err && err.message) || String(err);
    }
    loadSluice().then(clearError).catch(showError);
  });
});


/**
 * THE BLOCKLIST PANE + THE DOMAIN-BLOCKING SWITCH + THE RULE COMPOSER (the operator,
 * 2026-10-16). The pane moved to Settings; this loader is called from BOTH views' loaders, and
 * is a no-op where the ids are absent -- the card exists in exactly one place at a time.
 */
async function loadBlocklistPane() {
  if (!document.getElementById("sl-bl-rows")) return;
  let d;
  try {
    d = await getJSON("/api/blocklists");
  } catch (err) {
    const note = document.getElementById("sl-bl-note");
    if (note) note.textContent = "the blocklist read failed: " + ((err && err.message) || err);
    return;
  }
  const note = document.getElementById("sl-bl-note");
  if (d && d.available === false) {
    if (note) note.textContent = "the blocklists could not be read: " + (d.reason || "no reason given");
    return;
  }
  if (note && !note.textContent) note.textContent = "";
  renderBlocklists({ blocklists: (d && d.sources) || [] });
}

async function slToggleSource(s) {
  const note = document.getElementById("sl-bl-note");
  const want = !s.enabled;
  if (note) note.textContent = `${want ? "enabling" : "disabling"} ${s.name}\u2026`;
  try {
    const out = await postJSON("/api/blocklists/enable",
                               { source_id: s.source_id, enabled: want });
    if (note) note.textContent = (out && (out.note || out.error)) || "done";
  } catch (err) {
    if (note) note.textContent = String((err && err.message) || err);
  }
  loadBlocklistPane().catch(showError);
}

/**
 * ALL THE BLOCKING CONTROLS (the operator, 2026-10-16: "All blocking controls should live in
 * sluice gate. example i should be able to click high in High only to swap to it"). One reader
 * for /api/settings + /api/sluice: the policy tiles come from the gate's OWN policy registry
 * (labels and descriptions the enforcement path uses), the switches and the auto-block score
 * from the settings rows. Every change applies through the same plan/apply path as Settings --
 * with the confirm click, because applying restarts the worker, and the note SAYS so.
 */
async function slApplyChange(key, value, btn, note) {
  if (!btn.dataset.armed) {
    btn.dataset.armed = "1";
    const prev = btn.textContent;
    btn.textContent = "Confirm: apply";
    note.textContent = `Applying ${key} = ${value} restarts the worker so it takes effect. `
      + "Click again to confirm.";
    setTimeout(() => {
      if (document.body.contains(btn) && btn.textContent === "Confirm: apply") {
        delete btn.dataset.armed;
        btn.textContent = prev;
      }
    }, 6000);
    return;
  }
  delete btn.dataset.armed;
  btn.disabled = true;
  try {
    const out = await postJSON("/api/settings/apply",
      { changes: { [key]: String(value) }, confirmed: true });
    note.textContent = (out && (out.ok === false ? out.error
      : (out.note || `applied ${key} = ${value}; the worker restarts and the gate recompiles`)))
      || "applied.";
    loadBlockingControls().catch(() => {});
  } catch (err) {
    note.textContent = String((err && err.message) || err);
  } finally {
    btn.disabled = false;
  }
}

async function loadBlockingControls() {
  // THE GATE'S STATUS, ONE LINE (2026-10-18). The duplicate "Blocking controls" card is gone:
  // this reads the same settings and paints the state, the one master control, the domain
  // switch's state (its toggle lives in the domain card), and the auto-block line + pause,
  // which stay because an armed threshold must be visible and stoppable from here.
  const gateState = document.getElementById("sl-gate-state");
  const domState = document.getElementById("sl-dom-state");
  const gateBtn = document.getElementById("sl-bc-gate");
  const note = document.getElementById("sl-bc-note");
  if (!gateState || !gateBtn) return;
  let settings;
  let gate;
  try {
    settings = await getJSON("/api/settings");
  } catch (err) {
    note.textContent = "the gate state could not be read: " + ((err && err.message) || err);
    return;
  }
  try {
    gate = await getJSON("/api/sluice");
  } catch (err) {
    gate = null;
  }
  const rows = {};
  for (const rs of Object.values((settings && settings.groups) || {})) {
    for (const r of rs || []) if (r && r.key) rows[String(r.key).toLowerCase()] = r;
  }
  const val = (k) => {
    const r = rows[String(k).toLowerCase()];
    const v = r ? String(r.value != null ? r.value : (r.current != null ? r.current : "")) : "";
    return v;
  };
  const onVals = /^(1|true|on|yes|enabled|armed)$/i;
  const gateOn = onVals.test(val("SLUICE_ENABLED"));
  const domOn = onVals.test(val("SLUICE_BLOCK_DOMAINS"));
  const gateLive = gate && gate.gate ? gate.gate : null;
  const live = Number(gateLive && gateLive.rules_active) || 0;

  const gstate = String((gateLive && gateLive.state) || "");
  const gdetail = String((gateLive && gateLive.detail) || "");
  const healthy = !gstate || ["ok", "armed", "disabled", "running"].includes(gstate.toLowerCase());
  gateState.textContent = (gateOn
    ? (live > 0 ? `armed \u00b7 ${live} rule${live === 1 ? "" : "s"} enforced` : "armed \u00b7 nothing enforced")
    : "off") + (healthy ? "" : ` \u00b7 ${gstate}`);
  gateState.className = gateOn ? "sl-on" : "sl-off";

  // THE REASON, NOT JUST THE WORD (QA-1-D3). The gate reported "degraded" beside zero enforced
  // rules and nothing said why; the server had the sentence all along. A state without its cause
  // is a status the operator cannot act on.
  const detailBox = document.getElementById("sl-gate-detail");
  if (detailBox) {
    if (healthy) {
      detailBox.classList.add("hidden");
      detailBox.textContent = "";
    } else {
      detailBox.classList.remove("hidden");
      detailBox.textContent = gdetail || `${gstate} \u2014 the gate gave no reason`;
      detailBox.className = "sl-gate-detail";
    }
  }
  gateBtn.textContent = gateOn ? "Disarm the gate" : "Arm the gate";
  gateBtn.onclick = () => slApplyChange("SLUICE_ENABLED", gateOn ? "0" : "1", gateBtn, note);

  if (domState) {
    domState.textContent = domOn ? "on" : "off";
    domState.className = domOn ? "sl-on" : "sl-off";
  }
  const domLine = document.getElementById("sl-dom-line");
  const domToggle = document.getElementById("sl-dom-toggle");
  const domNote = document.getElementById("sl-dom-note");
  if (domLine) {
    domLine.textContent = domOn
      ? "On: a rule whose match is a name may drop traffic, and every drop is recorded with the name that matched."
      : "Off: domain rules still record and alert, but nothing is dropped for them; address rules are unaffected.";
  }
  if (domToggle) {
    domToggle.textContent = domOn ? "Disable domain blocking" : "Enable domain blocking";
    domToggle.onclick = () => slApplyChange("SLUICE_BLOCK_DOMAINS", domOn ? "0" : "1", domToggle,
      domNote || note);
  }
  if (domNote) {
    domNote.textContent = domOn ? "enabled \u2014 domain rules may drop" : "disabled \u2014 domain rules only record";
  }

  // THE ARMED STATE IS LOUD, HERE AND IN THE HEADER (BF-3). This is the one threshold that
  // blocks without anyone looking at the detection first, so while it is on, the line says so
  // in the alarm colour, the pause is offered in one click, and the header carries a pill.
  const autoVal = Number(val("SLUICE_AUTO_SCORE") || "0") || 0;
  const autoState = document.getElementById("sl-bc-auto-state");
  if (autoState) {
    autoState.textContent = autoVal > 0
      ? `AUTO-BLOCK IS ON: any detection at or above score ${autoVal.toFixed(2)} is blocked ` +
        `automatically, and every action is audited with the reason "auto: threshold ` +
        `${autoVal.toFixed(2)}".`
      : "Auto-block is off: detections are recorded and alerted, never blocked, until you set a score.";
    autoState.classList.toggle("auto-on", autoVal > 0);
  }
  const autoPause = document.getElementById("sl-bc-autopause");
  if (autoPause) {
    autoPause.classList.toggle("hidden", !(autoVal > 0));
    autoPause.onclick = () => slApplyChange("SLUICE_AUTO_SCORE", "0", autoPause, note);
  }
  if (typeof refreshAutoBlockPill === "function") refreshAutoBlockPill(autoVal);
  note.textContent = "";
}


/* ── THE RULE SHEET (SL-1, 2026-10-18) ────────────────────────────────────────────────────────
 *
 * One sheet for creating a rule, reading one, parking or restoring it, and deleting it. The tab's
 * table is a list; the acts live here, the way a weirling's settings live in its drill-down. The
 * DNS and Blocked pages enter the same composer -- a domain rule is a rule, not a second form.
 */
let SL_RULE = null;

function slRuleSheetOpen() {
  const card = document.getElementById("sl-rule-sheet");
  return Boolean(card && !card.classList.contains("hidden"));
}

/** The sheet's own line, mirrored into the create section's note so a create receipt survives
 *  the switch back to the form. */
function slRuleNote(text) {
  for (const id of ["sl-rule-note", "sl-block-note"]) {
    const n = document.getElementById(id);
    if (n) n.textContent = text;
  }
}

function closeRuleSheet() {
  const card = document.getElementById("sl-rule-sheet");
  if (!card || card.classList.contains("hidden")) return;
  card.classList.add("hidden");
  const scrim = document.getElementById("sl-rule-scrim");
  if (scrim) scrim.classList.add("hidden");
  SL_RULE = null;
}

function slRuleFacts(r) {
  const facts = document.getElementById("sl-rule-facts");
  if (!facts) return;
  facts.replaceChildren();
  const rows = [
    ["rule", r.describes || r.src_cidr || r.rule_id],
    ["state", r.revoked ? "revoked" : (r.disabled ? "disabled" : (r.live ? "live" : "lapsed"))],
    ["origin", r.origin === "detection"
      ? `detection (${r.severity || "?"})` : (r.origin || "manual")],
    ["expires", r.live ? sluiceDuration(r.expires_in_s) : (r.expires_at || "—")],
    ["reason", r.reason || "(no reason recorded)"],
    ["rule id", r.rule_id],
  ];
  for (const [k, v] of rows) {
    facts.appendChild(el("div", { class: "setting" }, [
      el("span", { class: "setting-key", text: k }),
      el("span", { class: "setting-val", text: String(v) }),
    ]));
  }
}

function openRuleSheet(rule, domain) {
  if (typeof showView === "function") showView("sluice");
  const card = document.getElementById("sl-rule-sheet");
  if (!card) return;
  SL_RULE = rule || null;
  const creating = !rule;
  const title = document.getElementById("sl-rule-title");
  const id = document.getElementById("sl-rule-id");
  const create = document.getElementById("sl-rule-create");
  const detail = document.getElementById("sl-rule-detail");
  if (title) title.textContent = creating ? "New rule" : "Rule";
  if (id) id.textContent = creating ? "" : (rule.rule_id || "");
  if (create) create.classList.toggle("hidden", !creating);
  if (detail) detail.classList.toggle("hidden", creating);
  slRuleNote("");
  if (creating) {
    const dom = document.getElementById("sl-domain");
    if (dom) dom.value = String(domain || "");
    const btn = document.getElementById("sl-block");
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Create rule";
      delete btn.dataset.armed;
    }
  } else {
    slRuleFacts(rule);
    const toggle = document.getElementById("sl-rule-toggle");
    if (toggle) {
      toggle.textContent = rule.disabled ? "Enable this rule" : "Disable this rule";
      toggle.disabled = Boolean(rule.revoked);
    }
    const del = document.getElementById("sl-rule-delete");
    if (del) {
      del.disabled = Boolean(rule.revoked);
      delete del.dataset.armed;
      del.classList.remove("armed");
      del.textContent = "Delete this rule";
    }
  }
  card.classList.remove("hidden");
  let scrim = document.getElementById("sl-rule-scrim");
  if (!scrim) {
    scrim = document.createElement("div");
    scrim.id = "sl-rule-scrim";
    scrim.className = "sheet-scrim hidden";
    scrim.addEventListener("click", closeRuleSheet);
    document.body.appendChild(scrim);
  }
  scrim.classList.remove("hidden");
  if (typeof card.focus === "function") card.focus();
  if (creating) {
    const dom = document.getElementById("sl-domain");
    if (dom) dom.focus();
  }
}

/** The DNS/Blocked entry point: same sheet, prefilled with the name. */
function openRuleComposer(domain) {
  openRuleSheet(null, domain);
}

function wireRuleSheet() {
  const card = document.getElementById("sl-rule-sheet");
  if (!card || card.dataset.wired === "1") return;
  card.dataset.wired = "1";

  const close = document.getElementById("sl-rule-close");
  if (close) close.addEventListener("click", closeRuleSheet);

  const create = document.getElementById("sl-block");
  if (create) create.addEventListener("click", async () => {
    const note = document.getElementById("sl-block-note");
    const value = (id) => {
      const node = document.getElementById(id);
      return node ? String(node.value || "").trim() : "";
    };
    const body = {
      src_cidr: value("sl-src"),
      dst_cidr: value("sl-dst"),
      domain: value("sl-domain"),
      mode: value("sl-mode") || "alert",
      protocol: value("sl-proto"),
      dst_port: Number(value("sl-port") || 0),
      direction: value("sl-direction") || "forward",
      ttl_minutes: Number(value("sl-ttl") || 60),
      reason: value("sl-reason"),
    };
    // A BLOCKING RULE STILL ASKS TWICE (retained from the old composer): mode=block makes the
    // kernel drop what this matches, so the first click arms and names the consequence, the
    // second commits. Alert rules write on one click; they enforce nothing.
    if (body.mode === "block" && create.dataset.armed !== "1") {
      create.dataset.armed = "1";
      create.textContent = "Confirm: create a blocking rule";
      if (note) {
        note.textContent = "Block mode makes the kernel drop what this rule matches. "
          + "Click again to confirm.";
      }
      return;
    }
    delete create.dataset.armed;
    create.textContent = "Create rule";
    // NO REASON CHECK (2026-10-16): the reason is optional and blank stays blank.
    create.disabled = true;
    if (note) note.textContent = "recording…";
    try {
      const out = await postJSON("/api/sluice/block", body);
      if (out && out.ok) {
        if (note) note.textContent = out.note || "rule created";
        await loadSluice();
        if (out.rule_id && note) {
          note.appendChild(document.createTextNode(" "));
          note.appendChild(el("button", {
            class: "quiet", text: "Show the filed rule \u2192", attrs: { type: "button" },
            on: { click: () => { closeRuleSheet(); sluiceHighlightRule(out.rule_id); } },
          }));
        }
      } else if (note) {
        note.textContent = (out && out.error) || "the rule was refused";
      }
    } catch (err) {
      if (note) note.textContent = String((err && err.message) || err);
    } finally {
      create.disabled = false;
    }
  });

  const del = document.getElementById("sl-rule-delete");
  if (del) del.addEventListener("click", () => {
    if (!SL_RULE) return;
    const rule = SL_RULE;
    if (del.dataset.armed === "1") {
      delete del.dataset.armed;
      del.classList.remove("armed");
      del.textContent = "Delete this rule";
      del.disabled = true;
      slRuleRevoke(rule)
        .then(() => closeRuleSheet())
        .catch(showError)
        .finally(() => { del.disabled = false; });
      return;
    }
    del.dataset.armed = "1";
    del.classList.add("armed");
    del.textContent = "Click again to delete";
    slRuleNote("Deleting keeps the record and the audit trail; the rule cannot come back.");
    setTimeout(() => {
      if (del.isConnected && del.dataset.armed === "1") {
        delete del.dataset.armed;
        del.classList.remove("armed");
        del.textContent = "Delete this rule";
      }
    }, 5000);
  });

  const toggle = document.getElementById("sl-rule-toggle");
  if (toggle) toggle.addEventListener("click", () => {
    if (!SL_RULE) return;
    toggle.disabled = true;
    slRuleSetDisabled(SL_RULE, !SL_RULE.disabled)
      .then(() => closeRuleSheet())
      .catch(showError)
      .finally(() => { toggle.disabled = false; });
  });

  const blocked = document.getElementById("sl-rule-blocked");
  if (blocked) blocked.addEventListener("click", () => {
    if (!SL_RULE) return;
    const rid = SL_RULE.rule_id;
    closeRuleSheet();
    if (typeof showView === "function") showView("blocked");
    if (typeof blOpenRuleById === "function") blOpenRuleById(rid).catch(() => {});
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && slRuleSheetOpen()) closeRuleSheet();
  });
}

document.addEventListener("DOMContentLoaded", () => {
  const blk = document.getElementById("dn-block");
  if (blk) blk.addEventListener("click", () => {
    const field = document.getElementById("dn-domain");
    openRuleComposer(String((field && field.value) || "").trim());
  });
  wireRuleSheet();
});
