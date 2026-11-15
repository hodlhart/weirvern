"""Tests for the single folded-window definition every reader splices in.

The predicate helper exists because of a defect that stopped detection on the live box: a nested
string literal inside an f-string expression is NOT substituted by the enclosing f-string, so
``folded("window_start BETWEEN '{s}' AND '{e}'")`` handed ClickHouse the literal text ``{s}``. Every
detector's training query broke, and because ``Adaptive Baseline.train`` runs BEFORE the sweep in
the worker loop, the exception took the whole loop down on each cycle.
"""

from __future__ import annotations

import pathlib
import re

from weirvern import flow_windows

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODELS = ROOT / "weirvern" / "models"


def test_between_substitutes_the_times_and_leaves_no_braces():
    """The whole point: a caller gets SQL it can interpolate, not a template."""
    pred = flow_windows.between("2026-11-12 10:00:00", "2026-11-12 11:00:00")

    assert pred == "window_start BETWEEN '2026-11-12 10:00:00' AND '2026-11-12 11:00:00'"
    assert "{" not in pred and "}" not in pred, (
        "a predicate still carrying braces means the caller will hand ClickHouse a template"
    )


def test_folded_accepts_the_helper_and_emits_a_merge_not_a_plain_select():
    """The fragment must use the -Merge combinators, or reading an AggregatingMergeTree returns
    partial states rather than totals."""
    sql = flow_windows.folded(flow_windows.between("2026-11-12 10:00:00", "2026-11-12 11:00:00"))

    assert "{" not in sql, "the folded fragment still contains an unsubstituted placeholder"
    for combinator in ("countMerge(", "sumMerge(", "uniqMerge("):
        assert combinator in sql, f"{combinator} is missing, so partial states would be read raw"
    assert "2026-11-12 10:00:00" in sql, "the time predicate did not reach the fragment"
    # The predicate must sit BESIDE the merge so part pruning applies. Through a view the outer
    # WHERE cannot be pushed down and a five-minute sweep scans the whole retained history.
    assert "WHERE window_start BETWEEN" in sql, (
        "the predicate is not inside the merged select, so pruning cannot apply"
    )


def test_no_detector_passes_a_BRACE_TEMPLATE_into_the_fold():
    """The exact regression, guarded at the source.

    This is a source test on purpose. The defect produced valid Python and a valid f-string; the
    only way to see it was a string containing `{s}` reaching ClickHouse at runtime, which took a
    live crash and a stack trace to find. A grep is cheap and catches it at review time.

    Scoped to `weirvern/models/` because the helper's own docstring shows the broken form as its
    counter-example.
    """
    offenders: list[str] = []
    for path in sorted(MODELS.rglob("*.py")):
        text = path.read_text()
        for match in re.finditer(r"flow_windows\.folded\((.*?)\)\}", text, flags=re.S):
            arg = match.group(1)
            if "{s}" in arg or "{e}" in arg:
                offenders.append(f"{path.relative_to(ROOT)}: {arg.strip()[:80]}")
        # Also catch the plain-literal form, which is how it was written.
        if re.search(r"folded\(\s*[\"'][^\"']*\{[se]\}[^\"']*[\"']", text):
            offenders.append(f"{path.relative_to(ROOT)}: a literal predicate carrying a brace")

    assert not offenders, (
        "a folded() call site passes an unsubstituted time template; ClickHouse will fail with "
        "'Cannot read DateTime' and the training path will take the worker loop down.\n  "
        + "\n  ".join(offenders)
    )


def test_no_NEW_detector_goes_back_to_the_fragmenting_table():
    """A ratchet, not a clean bill of health.

    `flows_aggregated` is a plain MergeTree behind a materialized view, and a ClickHouse MView
    fires ONCE PER INSERTED BLOCK, so its `GROUP BY window_start, src_addr` groups within a block
    rather than across the window. Reading it directly therefore sees one host-window N times.

    Four readers still do. Each is listed with its verdict, so this test fails on a FIFTH rather
    than pretending the existing four are fine. Fixing the two real ones is deliberately deferred:
    both live in the specialist layer whose future is undecided, and folding code that may be
    deleted is wasted work.
    """
    known = {
        # DISTINCT src_addr only: fragmentation produces duplicate rows, which DISTINCT removes.
        "roles.py": "benign: SELECT DISTINCT",
        # The gate reads uniqExact(window_start) and uniqExact(src_addr), both of which are correct
        # under fragmentation. `count()` is the only inflated column and it is informational.
        "readiness.py": "benign for the gate; count() is inflated but unused for the decision",
        # REAL: reads one column per window as a time series, so a host-window with N blocks
        # appears N times with partial values.
        "changepoints.py": "REAL: per-window column read; specialist layer, fate undecided",
        "temporal.py": "REAL: per-window column read; specialist layer, fate undecided",
    }

    found = set()
    for path in sorted(MODELS.rglob("*.py")):
        if re.search(r"FROM\s+weirvern\.flows_aggregated\b", path.read_text()):
            found.add(path.name)

    new = found - set(known)
    assert not new, (
        "these newly read `flows_aggregated`, which holds one row per INSERT BLOCK, so a "
        "host-window with three blocks is seen three times: " + ", ".join(sorted(new))
    )
    # If a known one is fixed, the entry must be removed so the ratchet tightens.
    fixed = set(known) - found
    assert not fixed, (
        "these no longer read `flows_aggregated`; delete them from the `known` list so the ratchet "
        "does not keep permitting a defect that is gone: " + ", ".join(sorted(fixed))
    )
