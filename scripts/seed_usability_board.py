#!/usr/bin/env python3
"""Create the weirvern-usability board and its cards (one-shot, idempotent-ish by title)."""
from __future__ import annotations

import subprocess
from pathlib import Path

BODIES = Path("/tmp/usability_bodies")
BODIES.mkdir(parents=True, exist_ok=True)

CARDS: list[dict] = [
    {
        "key": "US-B1", "priority": 1, "status": "blocked",
        "title": "The canon exists as law, with a ratchet that can go red",
        "goal": "Write the design canon as machine-readable law plus a human explanation, and make it "
                "enforceable without lying about today's state.",
        "whence": "The operator's design conversation (2026-10-18): 'locked in, optimized, visually "
                  "stunning' needs numbers, not adjectives. The console already has tokens "
                  "(--fs-*, --s*, --r-*) and already violates them.",
        "accept": "* docs/design/canon.json is the machine law: type ramp, space ladder, radii, colour "
                  "roles, frame, component cap, motion, responsive numbers, touch, budgets.\n"
                  "* docs/design/canon.md explains why each number exists, numbered C-1..C-11 so cards cite them.\n"
                  "* scripts/canon_lint.py compares the live sheet to the canon and to a committed baseline:\n"
                  "  new debt -> exit 1; unchanged debt -> exit 0 with a report; debt paid down -> reported.\n"
                  "* tests/test_design_system.py proves the ratchet can go red "
                  "(a better baseline yields a NEW violation).\n"
                  "* The gate runs it green today: 10 hex, 41 raw font sizes, 16 radii, 136 hover-only attributes.",
    },
    {
        "key": "US-B2", "priority": 1, "status": "blocked",
        "title": "The ledger names one owner per job, and the vocabulary is pinned",
        "goal": "Record who owns what, and pin tab ids and labels to it so a surface cannot be renamed "
                "or duplicated silently.",
        "whence": "QA-1 found 'weirvern' vs 'Weirvern' and 'Assets' vs host. Similarity is not duplication; "
                  "two surfaces may show a fact, only one may own the job.",
        "accept": "* docs/design/ledger.json lists every view (15 tabs + the drill-only Evidence "
                  "section) with its job.\n"
                  "* Every concept names one owning surface and one renderer; a second canonical id fails.\n"
                  "* canon_lint.py fails on an unledgered tab or section, on a label that drifts from the ledger,\n"
                  "  and on a ledgered tab the markup does not have — strictly, no baseline tolerance.\n"
                  "* docs/design/ledger.md states the rule, the three enforcements, and the current debt table.",
    },
    {
        "key": "US-B3", "priority": 1, "status": "blocked",
        "title": "A responsive audit that measures both viewports and writes the evidence",
        "goal": "Measure the console at desktop, tablet, phone and the 320 stress width, and keep the "
                "screenshots as evidence.",
        "whence": "The operator: 'It must test mobile and desktop.' jsdom cannot measure layout; the "
                  "harness proves wiring, only a browser proves the product.",
        "accept": "* scripts/responsive_audit.py drives headless Chrome over CDP with touch emulation at <=720px,\n"
                  "  reports page overflow, clipped text, touch targets (<44/<36), meaning-only titles, unnamed\n"
                  "  controls, DOM size, API calls on load; writes one screenshot per view/viewport.\n"
                  "* It refuses to run without a token file and never prints the token; a hash-only navigation bug\n"
                  "  is guarded: the audit verifies the active tab is the one it asked for.\n"
                  "* A committed baseline record (docs/design/audits/2026-10-18-responsive.md) carries the numbers\n"
                  "  for 15 views x 4 widths, including the systemic 257px tablet overflow and 632 sub-44px controls.\n"
                  "* tests pin the script's syntax and that it holds no credential literal.",
    },
    {
        "key": "US-A1", "priority": 2, "status": "blocked",
        "title": "The tablet width has no plan: every view overflows by 257px at 820",
        "goal": "Make 720-1100 a designed width, not a gap between two layouts.",
        "whence": "Responsive audit 2026-10-18: all fifteen views overflow by exactly 257px at 820x1180 — "
                  "the same number everywhere means one root cause. 820 is the common tablet and a "
                  "half-snapped laptop window; today it is the only width broken everywhere.",
        "accept": "* No view scrolls sideways at 820x1180 (audit overflow 0 for all fifteen).\n"
                  "* The nav rail and the content column share one min-width rule; no view keeps a desktop minimum\n"
                  "  above the 720 breakpoint.\n"
                  "* 820 and 320 join the audit's default review set and the numbers are recorded in a new audit doc.\n"
                  "* Screenshots of at least Health, Weirlings, Anomalies and Settings at 820 before/after.",
    },
    {
        "key": "US-A2", "priority": 2, "status": "blocked",
        "title": "Anomalies carries 632 controls under 44px — the per-row verbs must go",
        "goal": "Apply canon C-10 to the densest view: zero per-row verbs; the weight moves to filters and "
                "one row affordance.",
        "whence": "Responsive audit 2026-10-18: 632 controls under 44px on Anomalies (605 of them row verbs); "
                  "canon C-10 allows zero per-row verbs and canon C-9 wants 44px on touch.",
        "accept": "* The Anomalies table renders no per-row buttons; a row opens its detail (row affordance) and the\n"
                  "  verbs live in the detail surface.\n"
                  "* The audit's controls-under-44 count on Anomalies falls below 60 at 390px.\n"
                  "* Every former row verb remains reachable in at most the same number of steps (measure it).\n"
                  "* Harness pins: a fixture row carries no <button>; the row is the open affordance.",
    },
    {
        "key": "US-A3", "priority": 2, "status": "blocked",
        "title": "Sluice Gate: five unnamed controls and five hover-only facts",
        "goal": "Make the enforcement surface describable by a screen reader and readable on touch.",
        "whence": "Responsive audit 2026-10-18: Sluice is the only view with controls that have no accessible "
                  "name at all (5) plus 5 title-only facts — on the surface where a mistake is most costly.",
        "accept": "* Every control on Sluice has an accessible name (aria-label or visible text); "
                  "zero unnamed in the audit.\n"
                  "* Zero meaning-only title attributes; the fact moves to visible text or a tap affordance.\n"
                  "* A test walks the view's controls and fails on one with no name.",
    },
    {
        "key": "US-A4", "priority": 3, "status": "blocked",
        "title": "Models is over the DOM budget (8,650 elements)",
        "goal": "Bring Models inside canon C-10's 6,000-element budget without hiding information.",
        "whence": "Responsive audit 2026-10-18: Models renders 8,650 elements — 44% over budget, and the "
                  "heaviest view by a wide margin.",
        "accept": "* Models renders under 6,000 elements at 1440 with no information removed (the audit reports it).\n"
                  "* If the weight is a matrix, it renders progressively (visible slice + expand).\n"
                  "* The audit number is recorded before/after in the card's evidence.",
    },
    {
        "key": "US-A5", "priority": 3, "status": "blocked",
        "title": "Truncated text: Network and Zeek clip at every width",
        "goal": "Make truncation a decision (ellipsis with the full value reachable), not an accident.",
        "whence": "Responsive audit 2026-10-18: Network and Zeek clip >=8 text elements at 1440, 820, 390 and "
                  "320; Models and Netflow clip at phone widths; Blocked, Identity and Sluice at 390.",
        "accept": "* No text element clips its content without an ellipsis and a way to read the full value.\n"
                  "* The audit's clipped list is empty on Network and Zeek at all four widths, or every remaining\n"
                  "  clip is an intentional ellipsis with a title-equivalent tap affordance.\n"
                  "* Before/after screenshots for the affected views.",
    },
    {
        "key": "US-D1", "priority": 2, "status": "blocked",
        "title": "The evidence chain: observed -> detected -> explained -> ruled -> done",
        "goal": "Build the product's visible signature: one component that draws the record behind any "
                "decision, at three sizes, with unknown drawn as unknown.",
        "whence": "vision.md §2 (operator approved the signature, 2026-10-18). The chain is the one idea "
                  "a peer cannot copy: no peer keeps the record.",
        "accept": "* One component renders the five stages in a fixed order and fixed meaning, "
                  "read-only (never a stepper).\n"
                  "* A stage without evidence is dashed with a reason, never an empty success mark.\n"
                  "* It appears where a decision is made only: fleet row (2 marks), alert detail, "
                  "blocked view, write trail.\n"
                  "* The chain's facts come from real data (model score, reason code, rule id, "
                  "action + actor + time);\n"
                  "  a stage that cannot be sourced says so.\n"
                  "* Harness pins: five stages, fixed order, unknown is dashed, no arrow/progress semantics.",
    },
    {
        "key": "US-D2", "priority": 2, "status": "blocked",
        "title": "The mobile job set: see, read one alert, act, check one flow",
        "goal": "Make the four phone jobs work end to end, and let configuration say 'open this on desktop'.",
        "whence": "vision.md §5: a phone console is a different job set. The audit shows the phone layout "
                  "does not overflow, but the controls are 24-632 per view under 44px and the row verbs are unusable.",
        "accept": "* On a 390px viewport: state, one alert, act on it, and one sensor's flow each complete in the\n"
                  "  steps-to-answer budget (3/2/3/2), measured by hand and recorded.\n"
                  "* Touch targets: 44px primary, >=36px secondary (audit), on those four paths.\n"
                  "* The Settings surface states 'open this on desktop' where bulk configuration lives — never for a\n"
                  "  primary action.\n"
                  "* Screenshots of the four paths at 390, before/after.",
    },
    {
        "key": "US-R1", "priority": 2, "status": "blocked",
        "title": "The peer corpus: eight consoles, what to steal, what not to copy",
        "goal": "Give the critic reference images and written bars per peer, so a score cites a source.",
        "whence": "vision.md §3: the blind-swap test needs the peer's screenshot for the same job. We have "
                  "notes, not pictures.",
        "accept": "* references/peers/<peer>.md for Elastic Security, Security Onion, Wazuh, OPNsense/pfSense,\n"
                  "  the reference console, Grafana, Cloudflare Zero Trust, Tailscale admin.\n"
                  "* Each: the three jobs (fleet, alert, change) with what they do, what to steal, what NOT to copy,\n"
                  "  and a screenshot or a precise description where a screenshot is not permissible.\n"
                  "* Every rubric dimension cites at least one peer lesson.",
    },
    {
        "key": "US-R2", "priority": 2, "status": "blocked",
        "title": "The pilot scorecard: all fifteen tabs, two seats, both viewports",
        "goal": "Produce the first honest baseline verdict so design work sequences by axis, not by screen.",
        "whence": "vision.md §9. Nothing in the plan can be called 'better than the reference console' "
                  "until the baseline says where we are.",
        "accept": "* A scorecard in docs/design/scorecards/ (one file per date; the README states the shape):\n"
                  "  nine dimensions x fifteen views,\n"
                  "  scored 0-3 with the novice seat for entry/flow/vocabulary and the operator seat "
                  "for density/recovery.\n"
                  "* Every score carries evidence (screenshot + measured fact); no score without evidence.\n"
                  "* Hard blockers listed separately; the top five DSG/DUP cards are proposed from the gaps.\n"
                  "* The blind-swap test run on the three jobs, recorded.",
    },
]


def run(cmd: list[str]) -> str:
    out = subprocess.run(cmd, capture_output=True, text=True)
    if out.returncode != 0:
        raise SystemExit(f"FAILED {cmd}: {out.stdout}{out.stderr}")
    return out.stdout.strip()


def main() -> int:
    boards = run(["hermes", "kanban", "boards", "list"])
    if "weirvern-usability" not in boards:
        print(run(["hermes", "kanban", "boards", "create", "weirvern-usability"]))
    existing = run(["hermes", "kanban", "--board", "weirvern-usability", "list"])
    made = []
    for card in CARDS:
        if card["key"] in existing:
            print(f"skip {card['key']} (exists)")
            continue
        body = (f"GOAL: {card['goal']}\n\nWHENCE: {card['whence']}\n\nACCEPT:\n{card['accept']}\n")
        path = BODIES / f"{card['key'].lower()}.txt"
        path.write_text(body, encoding="utf-8")
        out = run(["hermes", "kanban", "--board", "weirvern-usability", "create",
                   f"{card['key']}  {card['title']}", "--body-file", str(path),
                   "--priority", str(card["priority"]), "--initial-status", card["status"]])
        print(out)
        made.append(card["key"])
    print("created:", ", ".join(made) if made else "none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
