# The ledger — who owns what

`docs/design/ledger.json` is the machine-readable version; this page explains how to use it.

## The rule

**Two surfaces may show a fact. Only one may own the job.**

Settings declares a segment; the fleet row reports it. Logs records a change; Settings stages it;
the sheet changes one weirling. Those are three jobs and one fact — not duplicates. A duplicate is
**the same job done twice**, or **one concept with two names**, or **one name with two meanings**.

## The three enforcements

1. **Vocabulary pin** (`scripts/canon_lint.py`) — every tab's `data-view` and its visible label must
   match a ledger view exactly. An unledgered id fails the gate; a label drift fails the gate.
2. **One-implementation pin** — each concept names one renderer. A second renderer for the same
   concept is a test failure, not a review argument.
3. **Duplicate detector** — the lint compares ids, labels and concept names for near-duplicates
   (case, plural, synonym) and prints them for a human decision: *own it, rename it, or merge it*.

## Adding a view or a concept

1. Add the entry to `ledger.json` with the job in one sentence, starting with a verb.
2. If the job is already owned, you are not adding a surface — you are adding a view of someone
   else's job. Say so in `duplicates`.
3. If a card creates a new primitive (canon C-6), the ledger gains a concept and the canon gains a
   justification. Both in the same commit.

## Current debt (2026-10-18)

| what | where | card |
|---|---|---|
| `weirvern` and `Weirvern` are two identities for one box; the fossil offers Adopt | Weirlings | QA-1-D2 |
| the Assets tab's id is `host` | index.html, URL `#v=host` | QA-1-D4 |
| the Weirlings problem dot's first finding lives only in `title` | weirlings.js | QA-1-D4 |
| the Evidence view exists but has no tab and no nav affordance | index.html | — (candidate home for the chain) |
| `netflow` is a row indicator, a tab and a filter word | weirlings.js, soc.js | — (jobs differ; keep, but say so) |

Paying one of these down means editing this table **and** the JSON **and** the baseline, in the same
commit — otherwise the ledger becomes a second source of truth, which is the exact disease it is
meant to cure.
