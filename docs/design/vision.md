# The weirvern design vision

**Status:** living document · **Started:** 2026-10-18 · **Owner:** operator (Samuel) · **Steward:** the agent
**Read with:** `docs/design/canon.md` (the rules), `docs/design/ledger.json` (who owns what),
`docs/design/vision.md` (this file — the why).

This file stores the whole design idea so it can be refined rather than remembered. Every clause
here is either a **decision** (locked until the operator changes it) or an **open question** (do
not treat as settled). Change the document, not the memory.

---

## 1. The ambition

**Be more useful and more visually coherent than the reference console, and visibly more
truthful than every console in this space.**

Not "look like the reference console". It owns one thing completely — a single visual language applied without
exception — and is weak at exactly the thing weirvern is for: evidence, provenance and recovery.
The target is therefore stated in axes, not adjectives:

| axis | the peer that owns it | the bar we must clear |
|---|---|---|
| visual coherence | the reference console | one primitive, one spacing scale, one accent, every view |
| fleet legibility | Tailscale admin | one row answers what · mode · network · is it flowing |
| alert → decision → action | Security Onion | fewer clicks, measured, than the peer path |
| depth without a query bar | Elastic Security | forensic depth with no KQL on screen |
| rule clarity | OPNsense / pfSense | rules read as sentences, not field tables |
| chart honesty | Grafana | a sparkline answers a question or it is absent |
| policy as intent | Cloudflare Zero Trust | policy stated as intent, not as a form |
| state truth + recovery | *nobody* | absence ≠ zero, unknown stated, degraded explains itself, every write has actor + reason + a way back |

**What we will not try to win:** device iconography, illustration, onboarding theatre, a native
app. Those are a design team and a year; chasing them produces a worse console.

**The one-line promise:** *every decision in this product has a receipt.*

---

## 2. The signature: the evidence chain

The visible idea that no peer can copy, because no peer keeps the chain.

```
observed → detected → explained → ruled → done
```

- **observed** — flow / Zeek / DNS evidence, the count and the window.
- **detected** — which model, what score, against which baseline.
- **explained** — the reason code, in words and as its code.
- **ruled** — the policy or rule that applied, or "no rule — alert only".
- **done** — the action, the actor, the timestamp — or "nothing yet".

Three rules keep it a signature instead of wallpaper:

1. **Only where a decision is being made** — a fleet row, an alert, a blocked view, a write trail.
   Not on every card.
2. **Unknown is drawn as unknown.** A stage without evidence is a dashed mark with a reason, never
   an empty green dot. A view that cannot draw the chain is hiding something.
3. **It is a record, not a wizard.** Read-only, no arrows implying "next step", no progress
   semantics. The moment it looks like a stepper it is lying about being a process.

Sizes: the full five-stage record (detail views); two marks — *what happened*, *why* — on rows,
expanding to the record; the same two on mobile, tap to expand. One component, three sizes.

**Why this and not a neutral console:** a neutral console competes on the peers' terms and can
only be as good in the same way. The chain is the differentiator, the teaching device (the product
explains its own logic by being used) and the de-duplication engine (one component replaces the
scattered model-score / reason-code / rule-id mini-facts).

**Decision (2026-10-18, operator):** commit to the chain as the visible signature.

---

## 3. What "visually stunning" means, testably

Three tests, in priority order when they conflict:

1. **The 3am test** — a half-awake operator finds the problem and acts. Outranks everything.
2. **The blind swap** — our screenshot beside a peer's for the same job ("the fleet", "an alert",
   "a change"); a stranger should answer *what is happening* faster from ours. Not "which is
   prettier".
3. **The deck test** — any single view could sit in a vendor deck without embarrassment:
   alignment, one accent, no ragged edges, no orphan labels, no card-in-card.

Plus one question only we can answer: **"can you tell me why this happened?"** — answerable from a
screenshot of ours, not from a peer's.

---

## 4. Who is in the chair

Two seats, scored separately, because they disagree:

- **The novice seat** judges entry, flow and vocabulary: can someone cold answer "what is
  happening" and "what do I do next" without a manual?
- **The operator seat** (Samuel) judges density, speed and recovery: at 3am, with 600 rows, does
  it still work?

A verdict names its seat. A finding that only one seat can see is still a finding.

---

## 5. Mobile is a different job set, not a smaller screen

A phone console is for four jobs: **see what is happening · read one alert · act on it · check one
sensor's flow.** Configuration does not have to be pleasant on a phone; it must be honest about
where it lives.

**Decision:** a surface may say *"open this on desktop"* for bulk configuration. It may not hide a
primary action behind that sentence.

**Decision:** touch targets **44px for primary controls, 36px floor for secondary**, enforced by
the responsive audit. Density loses to the thumb.

**Decision:** "mobile support" means both viewports are reviewed for every card, and a
mobile-only severity-1 blocks a release.

---

## 6. De-duplication is a ledger, not an opinion

Two surfaces may show the same fact — Settings controls, the sheet changes, Logs records. What
must be unique is the **job**. The ledger (`docs/design/ledger.json`) records, per concept: the
canonical id, the visible label, the one surface that owns the job, the one renderer that draws
it, and the known duplicates.

Three enforcements:

- **Vocabulary pin** — every tab id and label matches the ledger exactly; an unledgered id fails.
- **One-implementation pin** — a concept has one renderer; a second is a test failure, not a
  review argument.
- **Duplicate detector** — the label set, route table and component names are compared for
  near-duplicates (case, plural, synonym) for a human decision.

Known debt at the start (from the QA-1 walk, 2026-10-18): `weirvern` vs `Weirvern` (two identities,
one box, one offering Adopt); `Assets` labelled `host` internally; the Weirlings problem dot's
first finding reachable only by hover.

---

## 7. Efficiency has budgets

Measured per view, per viewport, in the browser — not judged:

- DOM elements, API calls on load, time to interactive;
- **steps-to-answer** for the ten operator questions (triage an anomaly, find a host, prove a
  block, change a setting, explain a detection …);
- the dense views are over any sane budget today (605 buttons on Anomalies, 120 on DNS).
- **measured baseline, 2026-10-18** (`audits/2026-10-18-responsive.md`): every view overflows by
  257px at 820px; Anomalies carries 632 controls under 44px; Models holds 8,650 DOM elements;
  API calls on load are 4–9 everywhere (inside budget); the phone layout does not scroll sideways.

A budget breach is a card. "Feels slow" is not a finding.

---

## 8. How the work is governed

One board, `weirvern-usability`, four card families:

- **`UXR-`** review cards — a view or a flow. Verdict + scorecard + evidence bundle.
- **`UXF-`** findings — reproduction, screenshot, fix-shaped ACCEPT. QA-1's D1–D4 are the template.
- **`DSG-`** design/enhancement — cites a canon clause and a peer target, carries before/after in
  **both** viewports.
- **`DUP-`** de-duplication — cites a ledger row.

The gate has teeth: **no open severity-1; canon lint green against the ratchet; responsive audit
green at 390 and 820; no dimension may silently drop against the last committed scorecard**
(`docs/design/scorecards/`, one file per date — see its README).

**The judge does not fix.** Review and critique run as read-only subagents; the verdict comes back
to the parent, which files cards. A reviewer that fixes grades its own work.

**It judges the live box, not the harness.** jsdom proves wiring; only the browser proves the
product.

---

## 9. Scoring

Nine dimensions — entry, vocabulary, flow, state honesty, density & hierarchy, visual system,
accessibility, recovery, time-to-answer — each **0–3** with anchored descriptions (see
`references/rubric.md` in the `weirvern-usability` skill).

Three **hard blockers**, regardless of score: a dead end the reader cannot leave, a statement that
is untrue (zero drawn for unknown, green over degraded), an unlabelled destructive action.

Every finding carries **Claim → Observed → Measured**: the screenshot, the DOM/API fact, the
consequence in clicks or seconds. "Feels cluttered" is rejected by the skill itself.

---

## 10. Locked decisions (2026-10-18)

- Signature: **the evidence chain** (this document, §2).
- Standard: **match the reference console on coherence, beat it on truth and speed**, don't chase
  icon craft.
- Seats: **novice** for entry/flow/vocabulary, **operator** for density/recovery.
- Verdict: **numeric scorecard with hard blockers**, baseline committed per release.
- Mobile: **four jobs**, "open on desktop" allowed for bulk config, **44/36px** targets.
- Identity: **tighten the current one first**; no new visual identity until the pilot scorecard
  shows where it hurts.
- Canon: **enforced as a ratchet** — today's debt is recorded in `canon_baseline.json`; new debt
  fails the gate; paying debt down shrinks the baseline.

## 11. Open questions (refine here, not in chat)

- The evidence chain's five stages need a final naming pass (verbs vs nouns; "ruled" may read as
  judgement rather than policy).
- Should the chain appear on the Blocked view for every hit, or only on the block's detail?
- Does the operator seat want a compact density mode (32px rows) alongside the default?
- Which peer supplies the table grammar reference — Grafana's tables or Elastic's data grid?
- Do we keep the fifteen-tab rail at 820px, or collapse to a two-level nav there?

## Changelog

- **2026-10-18** — created from the operator's design conversation. Locked: signature, standard,
  seats, scoring shape, mobile rules, ratchet. Open: the five questions above.
