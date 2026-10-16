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
            el("span", { class: "mono", text: g.sensor || "—" }),
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
    pick.addEventListener("click", (e) => e.stopPropagation());
    pick.addEventListener("change", slBulkRefresh);

    const tr = el("tr", { class: "sl-rule-row",
                          attrs: { title: "click to open and edit this rule" } }, [
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
      const actions = el("td", { class: "sl-actions" });
      if (r.live || r.disabled) {
        // A parked rule can be put back; a revoked one cannot -- and that two-way switch is
        // exactly what separates the disable icon from the trashcan beside it.
        const dis = el("button", { class: "icon-btn",
          attrs: { title: r.disabled ? "enable this rule again"
                                     : "disable this rule (keeps it, stops it)" } }, [slIcon(r.disabled ? "play" : "ban")]);
        dis.addEventListener("click", (e) => { e.stopPropagation(); slConfirm(dis, () => slRuleSetDisabled(r, !r.disabled)); });
        actions.appendChild(dis);
      }
      const del = el("button", { class: "icon-btn danger",
        attrs: { title: "delete this rule (the record stays; the rule cannot come back)" } }, [slIcon("trash")]);
      del.addEventListener("click", (e) => { e.stopPropagation(); slConfirm(del, () => slRuleRevoke(r)); });
      actions.appendChild(del);
      tr.appendChild(actions);
    } else {
      tr.appendChild(el("td", { class: "muted", text: "" }));
    }
    tr.addEventListener("click", () => {
      if (typeof blOpenRuleById === "function") blOpenRuleById(r.rule_id);
    });
    tbody.appendChild(tr);
  }
  slBulkWire();
  slBulkRefresh();

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
    const n = document.getElementById("sl-block-note");
    if (n) n.textContent = out.note || "revoked";
    await loadSluice();
  } else {
    showError(new Error((out && out.error) || "the rule could not be revoked"));
  }
}

async function slRuleSetDisabled(r, want) {
  const out = await postJSON("/api/sluice/rule/disabled", { rule_id: r.rule_id, disabled: want });
  if (out && out.ok) {
    const n = document.getElementById("sl-block-note");
    const refused = (out.refused || [])[0];
    if (n) n.textContent = refused ? refused.error : (out.note || (want ? "disabled" : "re-enabled"));
    await loadSluice();
  } else {
    showError(new Error((out && out.error) || "the rule could not be changed"));
  }
}

function slSelected() {
  return [...document.querySelectorAll("#sl-table .sl-pick:checked")].map((c) => c.value);
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
  const out = await postJSON(kind === "delete" ? "/api/sluice/revoke" : "/api/sluice/rule/disabled",
    kind === "delete" ? { rule_ids: ids } : { rule_ids: ids, disabled: kind === "disable" });
  if (out && out.ok) {
    const n = document.getElementById("sl-block-note");
    const done = (out.changed || out.revoked || []).length;
    const bad = (out.refused || []).length + (out.missing || []).length;
    if (n) {
      n.textContent = `${done} rule(s) ` + (kind === "delete" ? "deleted"
        : (kind === "disable" ? "disabled" : "re-enabled")) + (bad ? `; ${bad} refused` : "");
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
  wire("sl-bulk-delete", "delete");
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

  const block = document.getElementById("sl-block");
  if (!block) return;
  block.addEventListener("click", async () => {
    const note = document.getElementById("sl-block-note");
    const body = {
      src_cidr: document.getElementById("sl-src").value.trim(),
      dst_cidr: document.getElementById("sl-dst").value.trim(),
      domain: (document.getElementById("sl-domain") || {}).value ? document.getElementById("sl-domain").value.trim() : "",
      mode: document.getElementById("sl-mode") ? document.getElementById("sl-mode").value : "block",
      protocol: document.getElementById("sl-proto").value,
      dst_port: Number(document.getElementById("sl-port").value || 0),
      direction: document.getElementById("sl-direction").value,
      ttl_minutes: Number(document.getElementById("sl-ttl").value || 60),
      reason: document.getElementById("sl-reason").value.trim(),
    };
    // NO REASON CHECK HERE ANY MORE (2026-10-16): the reason is optional. A derived block always
    // carries one and the form pre-fills the field, but a manual block may be left blank, and the
    // store records it blank rather than inventing a placeholder that would read like a fact.
    block.disabled = true;
    note.textContent = "recording…";
    try {
      const out = await postJSON("/api/sluice/block", body);
      if (out && out.ok) {
        note.textContent = out.note || "recorded";
        document.getElementById("sl-reason").value = "";
        await loadSluice();
      } else {
        // The server's refusal text is the deliverable: it names the fix.
        note.textContent = (out && out.error) || "the rule was refused";
      }
    } catch (err) {
      note.textContent = String(err.message || err);
    } finally {
      block.disabled = false;
    }
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
  const note = document.getElementById("sl-bc-note");
  const strip = document.getElementById("sl-criticality");
  const gateBtn = document.getElementById("sl-bc-gate");
  const domBtn = document.getElementById("sl-bc-dom");
  const autoInput = document.getElementById("sl-bc-auto");
  const autoSave = document.getElementById("sl-bc-autosave");
  const help = document.getElementById("sl-bc-help");
  if (!note || !strip || !gateBtn || !domBtn) return;
  let settings;
  let gate;
  try {
    settings = await getJSON("/api/settings");
  } catch (err) {
    note.textContent = "the controls could not be read: " + ((err && err.message) || err);
    return;
  }
  try {
    gate = await getJSON("/api/sluice");
  } catch (err) {
    gate = null;   // the policy strip still renders from the settings row's options below
  }
  const rows = {};
  for (const rs of Object.values((settings && settings.groups) || {})) {
    // Row keys arrive in ROW vocabulary (lowercase: sluice_block_domains), while the apply
    // path speaks ConfigMap keys (uppercase). Normalize on the way in; the apply path keeps
    // the upper-case key because that is what the settings writer expects.
    for (const r of rs || []) if (r && r.key) rows[String(r.key).toLowerCase()] = r;
  }
  const val = (k) => {
    const r = rows[String(k).toLowerCase()];
    const v = r ? String(r.value != null ? r.value : (r.current != null ? r.current : "")) : "";
    return v;
  };
  const policies = (gate && gate.policies) || null;
  const current = val("SLUICE_CRITICALITY") || (gate && gate.criticality) || "";
  strip.replaceChildren();
  if (policies) {
    for (const [key, p] of Object.entries(policies)) {
      const active = key === current;
      const tile = el("button", { class: "tile" + (active ? " active" : ""),
        attrs: { title: (p.description || "") + (active ? " (current)" : " — click to switch") } }, [
        el("div", { class: "v", text: p.label || key }),
        el("div", { class: "k", text: p.ttl_minutes ? `${Math.round(p.ttl_minutes / 60)}h blocks`
                                                     : "no auto-blocks" }),
      ]);
      if (!active) {
        tile.addEventListener("click", () => slApplyChange("SLUICE_CRITICALITY", key, tile, note));
      }
      strip.appendChild(tile);
    }
  } else {
    strip.appendChild(el("span", { class: "muted",
      text: "The policy list could not be read; set it on the Settings tab instead." }));
  }
  // The payload RENDERS booleans as enabled/disabled while the reader stores 1/true/on/yes --
  // read both vocabularies, write the storage one (below).
  const onVals = /^(1|true|on|yes|enabled|armed)$/i;
  const gateOn = onVals.test(val("SLUICE_ENABLED"));
  gateBtn.textContent = gateOn ? "Take the gate off (disarm)" : "Turn the gate on (arm)";
  gateBtn.onclick = () => slApplyChange("SLUICE_ENABLED", gateOn ? "0" : "1", gateBtn, note);
  const domOn = onVals.test(val("SLUICE_BLOCK_DOMAINS"));
  domBtn.textContent = domOn ? "Domain blocking: on — turn off" : "Domain blocking: off — turn on";
  domBtn.onclick = () => slApplyChange("SLUICE_BLOCK_DOMAINS", domOn ? "0" : "1", domBtn, note);
  if (autoInput) autoInput.value = val("SLUICE_AUTO_SCORE") || "0";
  if (autoSave) autoSave.onclick = () => {
    const v = String((autoInput && autoInput.value) || "0").trim();
    slApplyChange("SLUICE_AUTO_SCORE", v, autoSave, note);
  };
  if (help) {
    help.textContent = current
      ? `Policy ${current}: ${(policies && policies[current] && policies[current].description) || ""}`
      : "";
  }
  note.textContent = gateOn
    ? "The gate is armed; block-mode rules and the policy above decide what drops."
    : "The gate is off; every rule records and alerts but nothing drops until it is armed.";
}

function openRuleComposer(domain) {
  const card = document.getElementById("rule-composer");
  if (!card) return;
  const dom = document.getElementById("rc-domain");
  const note = document.getElementById("rc-note");
  const create = document.getElementById("rc-create");
  if (dom) dom.value = String(domain || "");
  if (note) note.textContent = "";
  if (create) { create.textContent = "Create"; delete create.dataset.armed; }
  openModal(card);
  if (dom) dom.focus();
}

document.addEventListener("DOMContentLoaded", () => {
  const create = document.getElementById("rc-create");
  const cancel = document.getElementById("rc-cancel");
  if (cancel) cancel.addEventListener("click", () =>
    closeModal(document.getElementById("rule-composer")));
  if (create) create.addEventListener("click", async () => {
    const dom = document.getElementById("rc-domain");
    const wild = document.getElementById("rc-wild");
    const mode = document.getElementById("rc-mode");
    const reason = document.getElementById("rc-reason");
    const note = document.getElementById("rc-note");
    let name = String((dom && dom.value) || "").trim().toLowerCase().replace(/\.$/, "");
    if (!name) { note.textContent = "a name is required."; return; }
    if (wild && wild.checked && !name.startsWith("*.")) name = "*." + name;
    const wantMode = (mode && mode.value) || "alert";
    if (wantMode === "block" && !create.dataset.armed) {
      create.dataset.armed = "1";
      create.textContent = "Confirm: enforce in kernel";
      note.textContent = "Block mode makes the kernel drop what this name resolves to. "
        + "Click again to confirm.";
      return;
    }
    delete create.dataset.armed;
    create.disabled = true;
    try {
      const out = await postJSON("/api/sluice/block", {
        domain: name, mode: wantMode, reason: String((reason && reason.value) || "").trim(),
        origin: "dns", ttl_minutes: 0,
      });
      if (out && out.ok) {
        note.textContent = `created ${name} (${wantMode}); it appears under Rules and on the `
          + "Blocked page. A rule with no expiry lasts until revoked.";
        if (typeof loadSluice === "function") loadSluice().catch(() => {});
        if (typeof loadBlocked === "function") loadBlocked().catch(() => {});
      } else {
        note.textContent = (out && out.error) || "the rule was refused.";
      }
    } catch (err) {
      note.textContent = String((err && err.message) || err);
    } finally {
      create.disabled = false;
      create.textContent = "Create";
    }
  });
  const blk = document.getElementById("dn-block");
  if (blk) blk.addEventListener("click", () => {
    const field = document.getElementById("dn-domain");
    openRuleComposer(String((field && field.value) || "").trim());
  });
});
