# Scorecards

The committed verdicts live here, one file per review date: `YYYY-MM-DD.md`.

A scorecard is the record of a review card's outcome — nine dimensions scored 0–3 per view, each
with its evidence, the hard blockers found, and the comparison against the previous scorecard. The
rule that gives the file its meaning: **no dimension may drop silently.** If a score falls, the
same commit names the card that caused it or files the regression.

Shape:

```
# Scorecard — YYYY-MM-DD
Build: <commit sha> · Seats: novice (entry, vocabulary, flow) · operator (density, recovery)
| view | entry | vocab | flow | honesty | density | visual | a11y | recovery | tta |
| ...
Hard blockers: ...
Changes since the last scorecard: ...
```

The raw evidence bundle (screenshots, `audit.json`, control inventories) stays in the agent
workspace; a scorecard cites its paths rather than carrying the files.
