# The peer corpus

What eight consoles do better than us, what they do worse, and what we deliberately will not
copy. This is the reference the `weirvern-usability` skill judges against; it is not a wish list.
Every entry ends in a decision, because "inspired by" is not a specification.

Method: read the products' own documentation and walkthroughs (the 2026-10-17 research pass:
five studies, kept in the agent workspace), then test each pattern against the vision's two
questions — *does it shorten time-to-answer*, and *does it tell the truth when it does not know*.
A pattern that cannot answer both is not adopted, however pleasant it looks.

## 1. Elastic Security — alert details

**Steal.** The alert detail as a *page*, not a modal: rule name, the events that matched, the
timeline of the alert, and every field one click from the raw document. The reader never loses
the list behind them.

**Do not copy.** The field tree. Three hundred expandable fields is a debugging tool for the rule
author, not an answer for the operator. Elastic's own best pages bury the verdict under it.

**Our decision.** The Evidence page is the analogue and now carries the chain (observed →
detected → explained → ruled → done) above the raw records. Fields stay in the tables; we do not
build a tree.

## 2. Security Onion — Hunt and PCAP pivots

**Steal.** *Time is a first-class control.* Every view states its window and every pivot keeps it.
A pivot that silently changes the window is the most common way an investigation lies.

**Do not copy.** The grid of independent panes. Six panes each with their own state means the
operator cannot say what the screen is currently answering.

**Our decision.** One window, stated in the header of each view, carried through drills. No
multi-pane workspace.

## 3. OPNsense / pfSense — firewall rules

**Steal.** The **apply model**: a staged change list, a visible count of what is pending, and one
Apply that reports per-item results. Nothing takes effect because a field blurred.

**Do not copy.** Twelve tabs of settings where the difference between *saved* and *applied* is a
banner the operator learns to ignore.

**Our decision.** We already plan-and-apply with per-key results; the Sluice surface now states
its gate and domain state in one line. Staging stays, but only for configuration, never for a
single toggle.

## 4. Grafana — tables and time range

**Steal.** Column controls that are discoverable without a manual (sort, hide, resize), and a
time picker that is always visible and always says what it means.

**Do not copy.** Dashboards as the primary object. A dashboard answers a question its author had;
an operator arrives with a different one.

**Our decision.** Tables keep a fixed, meaningful column set per view. No user-authored
dashboards; the answer surfaces are designed, not assembled.

## 5. Cloudflare Zero Trust — gateway policies

**Steal.** A policy is a **sentence with an effect**: *block*, *allow*, *isolate*, applied to a
selector, with the precedence visible. The list reads as intent, not as rows of matchers.

**Do not copy.** Policy precedence as an ordered list the operator must reason about. Order-based
semantics are a support-ticket factory.

**Our decision.** Sluice rules read as `block <name> …` and the sentence is the API's own
`describes()`. Precedence is not exposed; rules are independent and the list is not ordered by
priority.

## 6. Tailscale admin — devices and ACLs

**Steal.** A device row that says what it *is* (name, owner, last seen, key expiry) and one
obvious verb. The ACL editor's plain-language preview of what a rule would allow.

**Do not copy.** A JSON editor as the only path to a real change.

**Our decision.** Weirlings rows already carry name, mode, networks and a trend. The Sluice
composer is a form, never a document editor.

## 7. Arkime / Zeek — sessions and PCAP

**Steal.** Every session row is a door: one click to the raw record. And the honest empty state —
"no sessions in this window" is different from "the query failed", and they say which.

**Do not copy.** PCAP download as the default answer. It is the last resort, not the first.

**Our decision.** Raw flows and Zeek tables are per-record and scroll inside their card. We do
not ship PCAP download; the record is the evidence.

## 8. Wazuh — agents and compliance

**Steal.** Per-agent status that distinguishes *never connected*, *disconnected*, and *stale* —
three different truths that most consoles collapse into "offline".

**Do not copy.** Compliance dashboards scored out of 100. A single number hides which control
failed, which is the only actionable part.

**Our decision.** Health and Weirlings distinguish unknown from failing (the tri-state probe rows
exist for exactly this). No composite scores anywhere in the UI.

## What we will not do, in one list

- No user-authored dashboards; no widget grids.
- No field trees; no JSON editors as the only path.
- No composite health scores.
- No ordered precedence the operator must reason about.
- No hover-only facts, and no ellipsis without a visible way to the whole value.
- No claim of zero when the read failed — "unknown" is a state we render.

## How this is used

The `weirvern-usability` skill scores each view 0–3 on nine dimensions against these patterns,
with hard blockers (dead end, truth lie, unlabelled destructive action). R1 exists so that a
score can cite *which* peer sets the bar; a score with no peer and no measurement is an opinion.
