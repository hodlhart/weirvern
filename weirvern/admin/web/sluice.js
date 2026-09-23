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
  if (seconds === null || seconds === undefined) return "never";
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
      ["packets blocked", String(gate.packets_blocked ?? "—")],
      ["bytes blocked", String(gate.bytes_blocked ?? "—")],
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

    const tr = el("tr", {}, [
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
      const btn = el("button", { class: "small", text: "Revoke" });
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        btn.textContent = "…";
        try {
          const out = await postJSON("/api/sluice/revoke", { rule_id: r.rule_id });
          if (out && out.ok) {
            document.getElementById("sl-block-note").textContent = out.note || "revoked";
            await loadSluice();
          } else {
            showError(new Error((out && out.error) || "the rule could not be revoked"));
            btn.disabled = false;
            btn.textContent = "Revoke";
          }
        } catch (err) {
          showError(err);
          btn.disabled = false;
          btn.textContent = "Revoke";
        }
      });
      tr.appendChild(el("td", {}, [btn]));
    } else {
      tr.appendChild(el("td", { class: "muted", text: "" }));
    }
    tbody.appendChild(tr);
  }

  renderSluicePolicies(d);
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
      protocol: document.getElementById("sl-proto").value,
      dst_port: Number(document.getElementById("sl-port").value || 0),
      direction: document.getElementById("sl-direction").value,
      ttl_minutes: Number(document.getElementById("sl-ttl").value || 60),
      reason: document.getElementById("sl-reason").value.trim(),
    };
    // CHECK THE ONE THING THE SERVER WILL REFUSE, HERE, so the operator is not told after filling
    // in six fields. The server still enforces it -- this is convenience, not the guard.
    if (!body.reason) {
      note.textContent = "a reason is required";
      return;
    }
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
