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

function sluiceStateLabel(state) {
  // THE PACKET GATE, NOT THE WHOLE SLUICE GATE. A gate with no live packet rules is open by
  // choice; DNS blocking is a separate enforcement path and may still be blocking names. Calling
  // this simply "open" made a working Domain Gate look like it had been switched off.
  return state === "disarmed" ? "open \u00b7 no packet rules" : (state || "unknown");
}

function sluiceStateChip(state, stale) {
  const label = sluiceStateLabel(state);
  const cls = state === "armed" ? "ok" : (state === "degraded" ? "bad" : "muted");
  const text = stale ? `${label} \u00b7 stale` : label;
  return el("span", { class: `chip ${cls}`, text });
}

/* ONE RULE STORE, TWO ENFORCEMENT GATES. The rule table used to mix a domain rule answered in
 * DNS with an address rule dropped by nft without saying which gate would act. The filter is a
 * reading aid, not a second store: every rule still lives in the same table, opens the same sheet
 * and is counted by the same store. */
let SL_RULE_GATE = "all";

function slRuleGateMatches(rule, gate) {
  if (gate === "domain") return Boolean(rule && rule.domain);
  if (gate === "traffic") return Boolean(rule && !rule.domain);
  return true;
}

function slRuleGateLabel(rule) {
  return rule && rule.domain ? "Domain" : "Traffic";
}

function slSetRuleGate(gate) {
  SL_RULE_GATE = ["domain", "traffic"].includes(gate) ? gate : "all";
  for (const button of document.querySelectorAll("#sl-rule-gates [data-rule-gate]")) {
    const active = button.getAttribute("data-rule-gate") === SL_RULE_GATE;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", active ? "true" : "false");
  }
  loadSluice().catch(showError);
}

document.addEventListener("DOMContentLoaded", () => {
  for (const button of document.querySelectorAll("#sl-rule-gates [data-rule-gate]")) {
    button.addEventListener("click", () => slSetRuleGate(button.getAttribute("data-rule-gate")));
  }
});

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
    const slHours = typeof trHours === "function" ? trHours() : 24;
    d = await getJSON(`/api/sluice?hours=${slHours}`);
  } catch (err) {
    showDataError(`the gate query failed: ${(err && err.message) || err}`);
    // NOT RE-THROWN. `showView` attaches `.catch(showError)` to this call, and re-throwing would
    // report ONE failure as TWO banners with different ids -- "Data unavailable" from here and
    // "Could not load data" from there -- which a later successful load then clears together. The
    // operator would see the error flash and vanish. A loader that has already told the reader what
    // happened should not hand the failure on for a second telling.
    return;
  }

  // What has been imported and what it caught: same payload, same load, one place to read.
  renderBlocklists(d);
  renderGateSplit(d);
  loadBlockingControls().catch(showError);

  // THE STATE TILES ARE GONE (operator, 2026-10-19: "we dont need this"). They restated the
  // mode/interface/counts above a list that already carries them, and the cleanup sentence
  // ("these tables are still present after deletion") was housekeeping the operator cannot act
  // on. What remains: the one-line gate status below (with its arm/disarm control) and the
  // Enforcing gates table, which is now the first thing on the page.
  if (!d.available) {
    showDataError(d.reason || "the gate state is unavailable");
  } else {
    showDataError(null);
  }

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
          + "whatever the rule list says. This table reports packet enforcement only; DNS "
          + "blocking is enforced separately by the Domain Gate."
        : "Every gate listed reported within its own interval. This table reports packet "
          + "enforcement only; DNS blocking is enforced separately by the Domain Gate.";
      for (const g of gates) {
        const ifaces = String(g.iface || "").split(/[,\s]+/).filter(Boolean);
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
          el("td", {}, [sluiceStateChip(g.state, g.stale)]),
          // INTERFACES ARE A LIST, NOT A SINGLE GLOBAL PORT. One weirling can carry several
          // capture ports, and a fleet can carry several weirlings; the old single `iface` tile
          // made the second sensor disappear. The rule and packet totals beside this cell are
          // the SENSOR's totals, not per-interface measurements -- the title says so.
          el("td", {}, ifaces.length
            ? ifaces.map((iface) => el("span", { class: "mono gate-iface", text: iface }))
            : [el("span", { class: "muted", text: "—" })]),
          el("td", { class: "mono",
                     text: `${g.rules_active ?? 0} / ${g.rules_total ?? 0}` }),
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
  const showRevoked = Boolean((document.getElementById("sl-show-revoked") || {}).checked);
  const allRules = d.rules || [];
  let rules = allRules.filter((r) => slRuleGateMatches(r, SL_RULE_GATE));
  if (liveOnly) rules = rules.filter((r) => r.live);
  // DELETED MEANS GONE FROM THE LIST (operator, 2026-10-19: "deleting rules doesn't work").
  // Revoked rules were kept in the table with a disabled Delete button, so a successful delete
  // looked like nothing happened. They stay in the record and behind "show revoked".
  if (!showRevoked) rules = rules.filter((r) => !r.revoked);
  const gateHidden = allRules.filter((r) => !slRuleGateMatches(r, SL_RULE_GATE)).length;
  document.getElementById("sl-count").textContent = rules.length
    ? `(${rules.length}${rules.length !== allRules.length ? ` of ${allRules.length}` : ""})`
    : "";

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

  // ── AT A GLANCE (US-SL1). TWO READINGS, NOT ONE MIXED STRIP.
  //
  // The old strip counted every rule, every live rule and the DNS hits in one row, so a domain
  // rule answered in DNS sat beside a packet rule enforced by nft with no way to tell which gate
  // owned which number. These groups are separate on purpose; each one names its own facts.
  {
    const box = document.getElementById("sl-glance");
    const domainBox = document.getElementById("sl-glance-domain");
    const trafficBox = document.getElementById("sl-glance-traffic");
    const names = document.getElementById("sl-top-names");
    const note = document.getElementById("sl-glance-note");
    if (box) {
      const chipsFor = (rules, extra) => {
        const live = rules.filter((r) => r.live).length;
        const alertMode = rules.filter((r) => r.mode === "alert").length;
        const dropMode = rules.length - alertMode;
        const chips = [
          [`${rules.length}`, rules.length === 1 ? "rule" : "rules"],
          [`${live}`, "live"],
          [`${dropMode}`, "drop"],
          [`${alertMode}`, "alert-only"],
        ];
        return chips.concat(extra || []).map(([v, k]) =>
          el("span", { class: "stat-chip" }, [
            el("strong", { text: String(v) }), el("span", { class: "muted", text: " " + k }),
          ]));
      };
      if (!d.available) {
        if (note) note.textContent = "\u2014 unavailable, the gate query failed";
        if (domainBox) domainBox.replaceChildren();
        if (trafficBox) trafficBox.replaceChildren();
      } else {
        if (note) note.textContent = "";
        const all = d.rules || [];
        const domainRules = all.filter((r) => Boolean(r.domain));
        const trafficRules = all.filter((r) => !r.domain);
        const hits = d.hits || [];
        const hitHours = Number(d.hits_hours || 24);
        if (domainBox) {
          domainBox.replaceChildren(...chipsFor(domainRules,
            hits.length ? [[hits.length, `DNS hits in ${hitHours}h`]] : []));
        }
        if (trafficBox) {
          const gates = Array.isArray(d.gates) ? d.gates : [];
          const stale = gates.filter((g) => g.stale).length;
          trafficBox.replaceChildren(...chipsFor(trafficRules, [
            [gates.length, gates.length === 1 ? "weirling" : "weirlings"],
            ...(stale ? [[stale, "stale"]] : []),
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
        const hitHours = Number(d.hits_hours || 24);
        names.appendChild(el("span", { class: "muted", text: `names in ${hitHours}h: ` }));
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

  // THE POLICY CARD IS INDEPENDENT OF THE RULE LIST (issue measured live 2026-10-22). This call
  // used to sit after the rules loop, so the `!rules.length` early return left "Blocking on
  // detections" completely empty -- exactly on a fresh or fully revoked store. The policy is a
  // trust setting, not a property of the current rows; render it before either branch.
  renderSluicePolicies(d);

  if (!rules.length) {
    // The distinction the whole project cares about: an empty list from a WORKING server is a
    // legitimate answer; an empty list from a FAILED one is not. The sentence must not deny a
    // rule that the glance strip above is counting: an all-revoked store is not "no rules",
    // and Domain Gate is a separate enforcement path that may still be on.
    const hiddenRevoked = allRules.filter((r) => r.revoked && !showRevoked).length;
    const hiddenByLive = liveOnly ? allRules.filter((r) => !r.live).length : 0;
    if (d.available) {
      const gateName = SL_RULE_GATE === "domain" ? "Domain Gate"
        : (SL_RULE_GATE === "traffic" ? "Traffic Gate" : "");
      const parts = [liveOnly
        ? "No live traffic-gate rules match."
        : "No traffic-gate rules match the current filters."];
      if (gateHidden) {
        parts.push(`${gateHidden} rule${gateHidden === 1 ? "" : "s"} hidden by the ${gateName} filter.`);
      }
      if (hiddenByLive) {
        parts.push(`${hiddenByLive} non-live rule${hiddenByLive === 1 ? "" : "s"} `
          + "are hidden by 'live rules only'.");
      }
      if (hiddenRevoked) {
        parts.push(`${hiddenRevoked} revoked rule${hiddenRevoked === 1 ? "" : "s"} `
          + "are hidden; tick 'show revoked' to see them.");
      }
      parts.push("Domain blocking is a separate gate; read its state above.");
      empty.textContent = parts.join(" ");
    } else {
      empty.textContent = "";
    }
    // Leave the table hidden rather than showing an empty grid with headers.
    return;
  }
  empty.textContent = "";

  for (const r of rules) {
    const gateLabel = slRuleGateLabel(r);
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

    const tr = el("tr", { class: `sl-rule-row gate-${gateLabel.toLowerCase()}`,
                          attrs: { title: "click to open and edit this rule",
                                   "data-rule-id": r.rule_id, tabindex: "0",
                                   role: "button",
                                   "aria-label": `open rule ${r.describes || r.rule_id}` } }, [
      el("td", { class: "pick" }, [pick]),
      el("td", { class: "mono", text: r.describes || r.src_cidr || "—" }),
      el("td", {}, [el("span", { class: `chip rule-gate gate-${gateLabel.toLowerCase()}`,
                                  text: gateLabel })]),
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
    // A row that can be clicked must be reachable and operable from the keyboard. The guard
    // keeps Enter/Space inside the row's own checkbox from opening the editor mid-selection.
    tr.addEventListener("keydown", (e) => {
      if (e.target !== tr) return;
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openRuleSheet(r);
      }
    });
    tbody.appendChild(tr);
  }
  slBulkWire();
  slBulkRefresh();
  // US-3: a receipt/audit that named a rule fires its flash on THIS fresh render.
  sluiceApplyFlash();
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

async function slRuleRevoke(r, reason) {
  // THE SERVER REQUIRES A REASON (BF-9): it is recorded with the actor and the time. The old
  // sheet posted only the id and every delete came back 400; found by the live create/delete
  // check, not by the harness.
  const out = await postJSON("/api/sluice/revoke", { rule_id: r.rule_id, reason: reason || "" });
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

function slSetSelecting(on) {
  const table = document.getElementById("sl-table");
  const button = document.getElementById("sl-select");
  if (!table) return;
  table.classList.toggle("selecting", Boolean(on));
  if (!on) {
    document.querySelectorAll("#sl-table .sl-pick:checked").forEach((c) => { c.checked = false; });
    const all = document.getElementById("sl-pick-all");
    if (all) all.checked = false;
  }
  if (button) button.textContent = on ? "Done" : "Select";
  slBulkRefresh();
}

function slBulkRefresh() {
  const bar = document.getElementById("sl-bulk");
  const n = document.getElementById("sl-bulk-n");
  const table = document.getElementById("sl-table");
  const selecting = Boolean(table && table.classList.contains("selecting"));
  const count = slSelected().length;
  if (bar) bar.classList.toggle("hidden", count === 0 || !selecting);
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

async function slBulkDelete() {
  const ids = slSelected();
  if (!ids.length) return;
  const reasonEl = document.getElementById("sl-bulk-reason");
  const reason = reasonEl ? String(reasonEl.value || "").trim() : "";
  if (!reason) {
    const n = document.getElementById("sl-bulk-note");
    if (n) n.textContent = "A reason is required to delete rules; it is recorded with your name.";
    if (reasonEl) reasonEl.focus();
    return;
  }
  const out = await postJSON("/api/sluice/revoke", { rule_ids: ids, reason });
  const n = document.getElementById("sl-bulk-note");
  if (out && out.ok) {
    const done = (out.revoked || []).length || (out.changed || []).length || ids.length;
    const bad = (out.refused || []).length + (out.missing || []).length;
    if (n) n.textContent = `${done} rule(s) deleted` + (bad ? `; ${bad} refused` : "");
    await loadSluice();
  } else {
    showError(new Error((out && out.error) || "the selection could not be deleted"));
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
  const del = document.getElementById("sl-bulk-delete");
  if (del) del.addEventListener("click", () => slConfirm(del, slBulkDelete));
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
    const detail = key === "off"
      ? "no automatic blocks"
      : `${p.min_severity || "—"}+ · confidence ${p.min_confidence} · ${p.ttl_minutes} minutes`;
    box.appendChild(el("div", { class: `policy-row${active ? " active" : ""}` }, [
      el("div", { class: "policy-head" }, [
        el("strong", { text: p.label || key }),
        el("span", { class: "chip muted", text: key }),
        active ? el("span", { class: "chip ok", text: "in use" }) : null,
      ]),
      el("div", { class: "muted", text: detail }),
    ]));
  }
  document.getElementById("sl-criticality-note").textContent =
    `Current policy: ${current} · change in Settings.`;
}

function wireSluice() {
  const reload = document.getElementById("sl-reload");
  if (reload) reload.addEventListener("click", () => loadSluice().then(clearError).catch(showError));
  const liveOnly = document.getElementById("sl-live-only");
  if (liveOnly) liveOnly.addEventListener("change", () => loadSluice().then(clearError).catch(showError));
  const showRevoked = document.getElementById("sl-show-revoked");
  if (showRevoked) showRevoked.addEventListener("change", () => loadSluice().then(clearError).catch(showError));

  // The operator's rule 3: one obvious "add" on the rules surface. The composer is the same one
  // the Blocked page opens -- one form, one code path -- and it is entered by a click, never
  // sitting open (rule 2).
  const newRule = document.getElementById("sl-new-rule");
  if (newRule) newRule.addEventListener("click", () => {
    if (typeof openRuleComposer === "function") openRuleComposer("");
  });
  const select = document.getElementById("sl-select");
  if (select) select.addEventListener("click", () => {
    const table = document.getElementById("sl-table");
    slSetSelecting(!(table && table.classList.contains("selecting")));
  });
}

/* ── Blocklists: what has been imported, and what it has caught ──────────────────────────────── */
/** DOMAIN GATE and TRAFFIC GATE are separate enforcement paths (operator, 2026-10-19).
 *
 *  Domain blocking is answered by DNS and keeps working with no nft rules; the packet gate can be
 *  disarmed while names are still blocked. One shared "gate" state made the working half look
 *  broken, so each card carries its own measured facts. Every value is read from this payload --
 *  no inference from a setting when a measurement exists.
 */
function renderGateSplit(d) {
  const tile = (k, v, title) => el("div", { class: "stat", attrs: title ? { title } : {} }, [
    el("div", { class: "k", text: k }), el("div", { class: "v", text: String(v) }),
  ]);

  const dg = document.getElementById("dg-stats");
  if (dg) {
    const lists = d.blocklists || [];
    const on = lists.filter((s) => s.enabled);
    const domains = on.reduce((n, s) => n + (Number(s.domain_count) || 0), 0);
    const stamps = on.map((s) => s.fetched_at).filter(Boolean).sort();
    // A TILE VALUE IS ONE LINE. fmtTime prints seconds; at four tiles across a half-width
    // card that wrapped "last sync" onto a second line and broke the row's rhythm. This
    // keeps the date and minute -- the precision a sync timestamp is read at.
    const shortStamp = (value) => {
      const d = new Date(value);
      if (isNaN(d.getTime())) return String(value);
      const day = d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
      const time = d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
      return `${day} ${time}`;
    };
    const last = stamps.length ? shortStamp(stamps[stamps.length - 1]) : "never";
    dg.replaceChildren(
      tile("lists enabled", `${on.length} / ${lists.length}`),
      tile("domains", domains.toLocaleString()),
      tile("hits recorded", Array.isArray(d.hits) ? d.hits.length : (Number(d.hits) || 0)),
      tile("last sync", last),
    );
  }

  const tg = document.getElementById("tg-stats");
  if (tg) {
    const gates = Array.isArray(d.gates) ? d.gates : [];
    const available = d.gates_available !== false;
    const interfaces = new Set();
    for (const gate of gates) {
      for (const iface of String(gate.iface || "").split(/[,\s]+/).filter(Boolean)) {
        interfaces.add(`${gate.sensor || ""}|${iface}`);
      }
    }
    const stale = gates.filter((gate) => gate.stale).length;
    const trafficRules = (d.rules || []).filter((rule) => !rule.domain);
    const liveTraffic = trafficRules.filter((rule) => rule.live).length;
    const packets = gates.reduce((total, gate) => total + (Number(gate.packets_blocked) || 0), 0);
    // THE FLEET, NOT ONE INTERFACE. A single `interface` tile made a five-weirling deployment
    // look like one capture port. These tiles answer the scale question; the per-weirling table
    // below carries the interfaces and each sensor's own packet state.
    tg.replaceChildren(
      tile("weirlings reporting",
        available ? `${gates.length}${stale ? ` \u00b7 ${stale} stale` : ""}` : "\u2014"),
      tile("capture interfaces", available ? String(interfaces.size) : "\u2014"),
      tile("traffic rules", `${liveTraffic} / ${trafficRules.length}`),
      tile("packets blocked", available ? packets.toLocaleString() : "\u2014"),
    );
  }

  const manage = document.getElementById("dg-manage");
  if (manage && !manage.dataset.wired) {
    manage.dataset.wired = "1";
    manage.addEventListener("click", () => {
      showView("settings");
      const rows = document.getElementById("sl-bl-rows");
      const card = rows && rows.closest(".card");
      if (card && card.scrollIntoView) card.scrollIntoView({ block: "start" });
    });
  }
}

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
  const addSource = document.getElementById("sl-bl-source-add");
  if (addSource) addSource.addEventListener("click", async () => {
    const note = document.getElementById("sl-bl-note");
    const url = (document.getElementById("sl-bl-url") || {}).value || "";
    const name = (document.getElementById("sl-bl-name") || {}).value || "";
    const format = (document.getElementById("sl-bl-format") || {}).value || "domains";
    if (!url.trim()) { if (note) note.textContent = "give the list URL first"; return; }
    try {
      const out = await postJSON("/api/blocklists/source",
                                 { url: url.trim(), name: name.trim(), format });
      if (note) note.textContent = (out && out.note) || "added";
      const field = document.getElementById("sl-bl-url"); if (field) field.value = "";
      const nfield = document.getElementById("sl-bl-name"); if (nfield) nfield.value = "";
    } catch (err) {
      if (note) note.textContent = String((err && err.message) || err);
    }
    loadBlocklistPane().catch(showError);
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
  const stale = Boolean(gateLive && gateLive.stale);
  // OPEN BY CHOICE IS NOT DEGRADED. The aggregate state is `disarmed` when the gate has no live
  // rules; that says nothing about the sensor's health. Only a real enforcement failure keeps the
  // `degraded` label and its warning.
  const openByChoice = gstate.toLowerCase() === "disarmed";
  const healthy = !gstate || ["ok", "armed", "disabled", "running", "disarmed"]
    .includes(gstate.toLowerCase());
  const warningText = stale
    ? String((gateLive && (gateLive.warning || gdetail)) || "")
    : (openByChoice ? gdetail : (!healthy ? String((gateLive && (gateLive.warning || gdetail)) || "") : ""));
  // THE TRAFFIC GATE IS NOT THE WHOLE GATE. DNS blocking is a separate enforcement path and may
  // still be blocking 221,972 domains while the packet gate has no live rules. The line names
  // both facts; "open" alone made a working Domain Gate look off.
  const packetState = gateOn
    ? (live > 0 ? `armed \u00b7 ${live} rule${live === 1 ? "" : "s"} enforced`
                : "open \u00b7 no packet rules")
    : "off";
  const onLists = ((gate && gate.blocklists) || []).filter((s) => s.enabled);
  const dnsDomains = onLists.reduce((n, s) => n + (Number(s.domain_count) || 0), 0);
  const dnsState = domOn
    ? (dnsDomains ? `DNS gate on \u00b7 ${dnsDomains.toLocaleString()} domains` : "DNS gate on")
    : "DNS gate off";
  const stateBits = [packetState, dnsState];
  if (!healthy && !openByChoice) stateBits.push(gstate);
  if (stale) stateBits.push("stale");
  gateState.textContent = stateBits.join(" \u00b7 ");
  gateState.className = (gateOn && live > 0) || domOn ? "sl-on" : "sl-off";

  // THE REASON MUST BE VISIBLE, NOT A HOVER FACT (SL1). A stale gate is not a live-but-imperfect
  // one: the server says its state is HISTORICAL, and the operator needs that sentence on the
  // surface before deciding to trust or repair it. The title stays as a secondary copy.
  const gateWarning = document.getElementById("sl-gate-warning");
  if (gateWarning) {
    gateWarning.textContent = warningText;
    gateWarning.classList.toggle("hidden", !warningText);
  }
  if (gateState) gateState.title = warningText || (healthy ? "" : `${gstate} \u2014 the gate gave no reason`);

  // ARM IS NOT A DECORATION. The server's own state says which backend is running and how many
  // rules exist; offering "Arm the gate" over `none`/zero rules is a no-op that looks like a
  // repair. Name the precondition and disable the action; a stale state alone is not a reason
  // to forbid a real repair when rules and backend exist.
  const backend = String((gateLive && gateLive.backend) || "").toLowerCase();
  const backendMissing = !backend || backend === "none";
  const rulesTotal = Number((gateLive && gateLive.rules_total) || 0);
  let armBlocked = "";
  if (!gateOn) {
    if (backendMissing) {
      armBlocked = "Arm unavailable: no nft backend is running; the gate would report degraded.";
    } else if (live === 0 && rulesTotal === 0) {
      armBlocked = "Arm unavailable: file a rule first; there is nothing to enforce.";
    }
  }
  gateBtn.textContent = gateOn ? "Disarm the gate" : "Arm the gate";
  gateBtn.disabled = Boolean(armBlocked);
  gateBtn.onclick = () => slApplyChange("SLUICE_ENABLED", gateOn ? "0" : "1", gateBtn, note);
  if (armBlocked && note) note.textContent = armBlocked;

  if (domState) {
    domState.textContent = domOn ? "on" : "off";
    domState.className = domOn ? "sl-on" : "sl-off";
  }
  const domLine = document.getElementById("sl-dom-line");
  const domToggle = document.getElementById("sl-dom-toggle");
  const domNote = document.getElementById("sl-dom-note");
  if (domLine) {
    domLine.textContent = domOn
      ? "On: names on an enabled blocklist and block-mode domain rules are answered with a block answer. This happens in DNS, not in the packet gate."
      : "Off: domain rules still record and alert, but DNS answers are not blocked; the traffic gate is separate.";
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
  if (!armBlocked) note.textContent = "";
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
  if (!card || !sheetIsOpen(card)) return;
  closeSheet(card);            // the sheet standard hides the card and its scrim
  slCreateDisarm(true);
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

function slRuleTargetType() {
  const s = document.getElementById("sl-target-type");
  return s && s.value === "address" ? "address" : "domain";
}

/** The target is the rule's unit (vision §12.4): Domain first, Address only when chosen.
 *  Hiding a field is not enough if its value can still ride the POST; wireRuleSheet clears the
 *  other side of the pair so a hidden stale value can never become the target. */
function slSyncRuleTargetType() {
  const address = slRuleTargetType() === "address";
  const show = (id, visible) => {
    const field = document.getElementById(id);
    const label = field && field.closest("label");
    if (label) label.classList.toggle("hidden", !visible);
  };
  show("sl-domain", !address);
  show("sl-src", address);
  show("sl-dst", address);
  const hint = document.getElementById("sl-gate-hint");
  if (hint) {
    hint.textContent = address
      ? "Address rules are dropped by the Traffic Gate on the capture interface."
      : "Domain rules are answered in DNS by the Domain Gate; no packet rule is written.";
  }
}

function slRuleTargetType() {
  const s = document.getElementById("sl-target-type");
  return s && s.value === "address" ? "address" : "domain";
}

/** The target is the rule's unit (vision §12.4): Domain first, Address only when chosen.
 *  Hiding a field is not enough if its value can still ride the POST; wireRuleSheet clears the
 *  other side of the pair so a hidden stale value can never become the target. */
function slSyncRuleTargetType() {
  const address = slRuleTargetType() === "address";
  const show = (id, visible) => {
    const field = document.getElementById(id);
    const label = field && field.closest("label");
    if (label) label.classList.toggle("hidden", !visible);
  };
  show("sl-domain", !address);
  show("sl-src", address);
  show("sl-dst", address);
  const hint = document.getElementById("sl-gate-hint");
  if (hint) {
    hint.textContent = address
      ? "Address rules are dropped by the Traffic Gate on the capture interface."
      : "Domain rules are answered in DNS by the Domain Gate; no packet rule is written.";
  }
}

let SL_CREATE_ARM_TIMER = null;

function slCreateDisarm(clearNote = true) {
  const btn = document.getElementById("sl-block");
  if (SL_CREATE_ARM_TIMER) {
    clearTimeout(SL_CREATE_ARM_TIMER);
    SL_CREATE_ARM_TIMER = null;
  }
  if (!btn) return;
  delete btn.dataset.armed;
  btn.textContent = "Create rule";
  const note = document.getElementById("sl-block-note");
  if (clearNote && note) note.textContent = "";
}

/** Name the target and the enforcing gate in the confirm: "block" is not one consequence.
 *  Domain blocking is a DNS answer; address blocking is a kernel drop. */
function slCreateSummary(body) {
  const target = body.domain
    ? `domain ${body.domain}`
    : `${body.src_cidr || "any source"} to ${body.dst_cidr || "any destination"}`;
  const gate = body.domain ? "Domain Gate (DNS answer)" : "Traffic Gate (packet drop)";
  const duration = Number(body.ttl_minutes) === 0 ? "until revoked" : `${body.ttl_minutes} minutes`;
  return `Create a ${body.mode === "alert" ? "alert-only" : "blocking"} rule for ${target} `
    + `at the ${gate}, for ${duration}?`;
}

function openRuleSheet(rule, domain, prefill) {
  if (typeof showView === "function") showView("sluice");
  const card = document.getElementById("sl-rule-sheet");
  if (!card) return;
  SL_RULE = rule || null;
  const pre = prefill && typeof prefill === "object" ? prefill : {};
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
    // THE SAME COMPOSER THE SLUICE GATE USES (operator, 2026-10-20). An alert's Block action
    // opens this sheet with its source and reason prefilled instead of growing a second,
    // weaker inline form. Every field the rule model owns is here, so the quick path and the
    // full path cannot drift.
    const set = (id, value) => {
      const node = document.getElementById(id);
      if (node && value !== undefined && value !== null) node.value = String(value);
    };
    set("sl-domain", domain || pre.domain || "");
    set("sl-src", pre.src_cidr || "");
    set("sl-dst", pre.dst_cidr || "");
    set("sl-mode", pre.mode || "block");
    set("sl-proto", pre.protocol || "");
    set("sl-port", pre.dst_port || "");
    set("sl-direction", pre.direction || "forward");
    set("sl-ttl", pre.ttl_minutes === undefined ? 60 : pre.ttl_minutes);
    set("sl-reason", pre.reason || "");
    // A prefilled source is an address rule; a prefilled domain is a domain rule. The empty
    // composer starts on Domain because that is the Sluice Gate's unit (vision §12.4).
    set("sl-target-type", (domain || pre.domain) ? "domain"
      : ((pre.src_cidr || pre.dst_cidr) ? "address" : "domain"));
    slSyncRuleTargetType();
    const btn = document.getElementById("sl-block");
    if (btn) {
      btn.disabled = false;
      slCreateDisarm(false);
    }
  } else {
    slRuleFacts(rule);
    const toggle = document.getElementById("sl-rule-toggle");
    if (toggle) {
      toggle.textContent = rule.disabled ? "Enable this rule" : "Disable this rule";
      toggle.disabled = Boolean(rule.revoked);
    }
    const mode = document.getElementById("sl-rule-mode");
    if (mode) {
      mode.value = String(rule.mode || "block").toLowerCase() === "alert" ? "alert" : "block";
      mode.disabled = Boolean(rule.revoked);
    }
    const dom = document.getElementById("sl-rule-domain");
    if (dom) {
      dom.value = String(rule.domain || "");
      dom.disabled = Boolean(rule.revoked) || !rule.domain;
      dom.placeholder = rule.domain ? "ads.example.com or *.example.com"
        : "address rules have no domain";
    }
    const save = document.getElementById("sl-rule-save");
    if (save) {
      save.disabled = Boolean(rule.revoked);
      save.textContent = "Save changes";
      delete save.dataset.armed;
    }
    const del = document.getElementById("sl-rule-delete");
    if (del) {
      del.disabled = Boolean(rule.revoked);
      delete del.dataset.armed;
      del.classList.remove("armed");
      del.textContent = "Delete this rule";
    }
    const reasonEl = document.getElementById("sl-rule-delete-reason");
    if (reasonEl) reasonEl.value = "";
  }
  openSheet(card, {
    scrimId: "sl-rule-scrim",
    initialFocus: creating ? (pre.focus || (domain ? "sl-domain" : "sl-src")) : null,
  });
}

/** The DNS/Blocked entry point: same sheet, prefilled with the name. */
function openRuleComposer(domain, prefill) {
  openRuleSheet(null, domain, prefill);
}

function wireRuleSheet() {
  const card = document.getElementById("sl-rule-sheet");
  if (!card) return;
  // THE SHEET STANDARD (sheets.js): one close control, one scrim, one Escape for every sheet.
  wireSheet(card, { scrimId: "sl-rule-scrim" });
  // An armed block confirmation is about the values on screen at that moment. Any edit, including
  // changing the target type, disarms it; the timer in the click handler bounds the arm too.
  for (const field of card.querySelectorAll("#sl-rule-create input, #sl-rule-create select")) {
    field.addEventListener("input", () => slCreateDisarm(true));
    field.addEventListener("change", () => {
      if (field.id === "sl-target-type") slSyncRuleTargetType();
      slCreateDisarm(true);
    });
  }
  slSyncRuleTargetType();

  const create = document.getElementById("sl-block");
  if (create) create.addEventListener("click", async () => {
    const note = document.getElementById("sl-block-note");
    const value = (id) => {
      const node = document.getElementById(id);
      return node ? String(node.value || "").trim() : "";
    };
    // THE TARGET IS ONE CHOICE, NOT THREE COMPETING FIELDS. A hidden field must never ride the
    // POST: the server writes what it is given, so selecting Domain after typing a CIDR (or the
    // reverse) would otherwise file the hidden value. The fallback also keeps pre-W3 links and
    // the alert prefill honest when only one side is populated.
    let targetType = value("sl-target-type") === "address" ? "address" : "domain";
    const domain = value("sl-domain");
    const src = value("sl-src");
    const dst = value("sl-dst");
    if (targetType === "domain" && !domain && (src || dst)) targetType = "address";
    if (targetType === "address" && !src && !dst && domain) targetType = "domain";
    const target = targetType === "domain" ? domain : (src || dst);
    if (!target) {
      slCreateDisarm(true);
      if (note) note.textContent = "Choose a domain or an address first.";
      return;
    }
    const body = {
      src_cidr: targetType === "address" ? src : "",
      dst_cidr: targetType === "address" ? dst : "",
      domain: targetType === "domain" ? domain : "",
      mode: value("sl-mode") || "alert",
      protocol: value("sl-proto"),
      dst_port: Number(value("sl-port") || 0),
      direction: value("sl-direction") || "forward",
      ttl_minutes: Number(value("sl-ttl") || 60),
      reason: value("sl-reason"),
    };
    // A BLOCKING RULE STILL ASKS TWICE (retained from the old composer): the first click arms
    // and names the consequence and the target; the second commits. A field edit disarms, and
    // the arm expires, so "I changed the rule after confirming" cannot create something the
    // operator did not see.
    if (body.mode === "block" && create.dataset.armed !== "1") {
      create.dataset.armed = "1";
      create.textContent = "Confirm: create a blocking rule";
      if (note) note.textContent = `${slCreateSummary(body)} Click again to confirm.`;
      if (SL_CREATE_ARM_TIMER) clearTimeout(SL_CREATE_ARM_TIMER);
      SL_CREATE_ARM_TIMER = setTimeout(() => {
        if (create.dataset.armed === "1") slCreateDisarm(true);
      }, 5000);
      return;
    }
    slCreateDisarm(true);
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
    const reasonEl = document.getElementById("sl-rule-delete-reason");
    const reason = reasonEl ? String(reasonEl.value || "").trim() : "";
    if (!reason) {
      // NO REASON, NO ARM: the server refuses the write and records the reason with the actor.
      slRuleNote("A reason is required to delete a rule; it is recorded with your name and the time.");
      if (reasonEl) reasonEl.focus();
      return;
    }
    if (del.dataset.armed === "1") {
      delete del.dataset.armed;
      del.classList.remove("armed");
      del.textContent = "Delete this rule";
      del.disabled = true;
      slRuleRevoke(rule, reason)
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

  const save = document.getElementById("sl-rule-save");
  if (save) save.addEventListener("click", async () => {
    if (!SL_RULE) return;
    const note = document.getElementById("sl-rule-note");
    const wantMode = String((document.getElementById("sl-rule-mode") || {}).value || "");
    const wantDom = String((document.getElementById("sl-rule-domain") || {}).value || "").trim();
    const curMode = String(SL_RULE.mode || "block").toLowerCase();
    const curDom = String(SL_RULE.domain || "");
    save.disabled = true;
    try {
      if (wantMode && wantMode !== curMode) {
        const body = { rule_id: SL_RULE.rule_id, mode: wantMode };
        if (wantMode === "block") body.confirmed = true;
        const out = await postJSON("/api/sluice/rule/mode", body);
        if (!out || !out.ok) throw new Error((out && out.error) || "the mode was refused");
      }
      if (wantDom && wantDom !== curDom) {
        const out = await postJSON("/api/sluice/rule/domain",
                                   { rule_id: SL_RULE.rule_id, domain: wantDom });
        if (!out || !out.ok) throw new Error((out && out.error) || "the domain was refused");
      }
      if (note) note.textContent = "Saved. Enforcement follows within a few seconds.";
      await loadSluice();
    } catch (err) {
      if (note) note.textContent = String((err && err.message) || err);
    } finally {
      save.disabled = false;
    }
  });

  const blocked = document.getElementById("sl-rule-blocked");
  if (blocked) blocked.addEventListener("click", () => {
    if (!SL_RULE) return;
    const rid = SL_RULE.rule_id;
    closeRuleSheet();
    if (typeof showView === "function") showView("blocked");
    if (typeof blOpenRuleById === "function") blOpenRuleById(rid).catch(() => {});
  });
}

document.addEventListener("DOMContentLoaded", () => {
  // SLUICE IS THE PARENT OF THE BLOCK LEDGER. Blocks is a drill view, not a peer tab
  // (operator, 2026-10-21); the one entry point lives on Gate overview.
  const viewBlocks = document.getElementById("sl-view-blocks");
  if (viewBlocks) viewBlocks.addEventListener("click", () => {
    if (typeof showView === "function") showView("blocked");
  });
  const blk = document.getElementById("dn-block");
  if (blk) blk.addEventListener("click", () => {
    const field = document.getElementById("dn-domain");
    openRuleComposer(String((field && field.value) || "").trim());
  });
  wireRuleSheet();
});
