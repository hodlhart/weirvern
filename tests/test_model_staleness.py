"""The Models view must be able to show that a detector is OVERDUE.

WHY THIS FILE EXISTS. Isolation Forest, Gradient Boosting and DBSCAN went 16 hours without a
retrain against a 6-hour interval, and the Models view rendered that as three tidy lines with
plenty of points. It plotted run COUNT, not RECENCY, and a model last retrained 16 hours ago is
indistinguishable on such a chart from one retrained a minute ago.

The fix has two halves and both need pinning:

  * `status._staleness` computes, per detector, when it last trained, how long ago that was, and
    whether that exceeds the interval -- server-side, so the TUI and the GUI cannot disagree;
  * the view prints it and states the REMEDY, not only the verdict.

The subtle cases are the ones that made the original bug invisible, so they are the ones tested
hardest: a detector that has NEVER trained must read as stale (a missing measurement must not
look like a healthy one), and the interval must come from settings rather than a hardcoded 6.
"""

from __future__ import annotations

import inspect
from datetime import datetime, timedelta

import pytest

from weirvern.admin import status


def _stamps(**ages_hours: float) -> dict[str, str]:
    """A `newest` mapping of model -> ISO timestamp, from ages in hours."""
    return {
        name: (datetime.now() - timedelta(hours=h)).isoformat()
        for name, h in ages_hours.items()
    }


# ── the computation ────────────────────────────────────────────────────────────────────────


def test_a_recently_retrained_detector_is_current():
    rows = status._staleness(_stamps(**{"Isolation Forest": 0.5}), interval_h=6)
    row = next(r for r in rows if r["model"] == "Isolation Forest")
    assert row["stale"] is False
    assert row["age_h"] == pytest.approx(0.5, abs=0.05)


def test_an_overdue_detector_is_marked_stale():
    """This is the state that was invisible for 16 hours."""
    rows = status._staleness(_stamps(**{"Isolation Forest": 16}), interval_h=6)
    row = next(r for r in rows if r["model"] == "Isolation Forest")
    assert row["stale"] is True, (
        "a detector retrained 16 hours ago against a 6h interval must be flagged; on the old "
        "view it looked identical to a fresh one because only run counts were drawn"
    )
    assert row["age_h"] == pytest.approx(16, abs=0.05)


def test_a_detector_that_never_trained_reads_as_stale_not_fresh():
    """A missing timestamp must not read as a healthy one.

    The same failure this codebase fixed in `worker._oldest_trained_at`, where a never-trained
    detector's construction-time metadata would have suppressed the retrain.
    """
    rows = status._staleness({}, interval_h=6)
    assert rows, "every known detector should be listed even with no data"
    for row in rows:
        assert row["stale"] is True, f"{row['model']} with no timestamp reported as current"
        assert row["never_trained"] is True
        assert row["age_h"] is None, "no timestamp must report no age, not an age of zero"


def test_every_known_detector_appears_even_with_no_data():
    """A missing detector must not silently vanish from the table."""
    rows = status._staleness(_stamps(**{"DBSCAN": 1}), interval_h=6)
    names = {r["model"] for r in rows}
    assert {"Isolation Forest", "Gradient Boosting", "DBSCAN", "Adaptive Baseline"} <= names, (
        f"the table omits detectors that have not reported data: {names}. Absence must be "
        f"visible, not implicit."
    )


def test_the_stalest_detector_sorts_first():
    """The thing needing attention belongs at the top of a list that gets skimmed."""
    # All four given a timestamp, so this tests ORDER BY AGE rather than the never-trained case
    # (which has its own test below and sorts ahead of everything).
    rows = status._staleness(
        _stamps(**{
            "Isolation Forest": 1, "Gradient Boosting": 30, "DBSCAN": 10,
            "Adaptive Baseline": 0.1,
        }),
        interval_h=6,
    )
    assert rows[0]["model"] == "Gradient Boosting", (
        f"order is {[r['model'] for r in rows]}; the stalest must come first"
    )
    assert [r["model"] for r in rows] == [
        "Gradient Boosting", "DBSCAN", "Isolation Forest", "Adaptive Baseline"
    ], f"not sorted by age descending: {[r['model'] for r in rows]}"


def test_a_never_trained_detector_sorts_ahead_of_a_merely_overdue_one():
    """Never-trained is the more urgent state: there is no model at all, not an old one."""
    rows = status._staleness(
        _stamps(**{"Isolation Forest": 30, "Gradient Boosting": 2}),
        interval_h=6,
    )
    ahead = [r["model"] for r in rows][:2]
    assert "DBSCAN" in ahead and "Adaptive Baseline" in ahead, (
        f"never-trained detectors did not sort ahead of the 30h-overdue one: "
        f"{[r['model'] for r in rows]}"
    )
    assert rows[0]["never_trained"] is True


def test_the_interval_comes_from_settings_not_a_hardcoded_default():
    """A hardcoded 6 would report the wrong verdict on a deployment configured otherwise."""
    src = inspect.getsource(status.model_overview)
    assert "retrain_every_h" in src, (
        "model_overview does not read the configured retrain interval, so the panel would "
        "compare against a number the worker is not using"
    )
    assert "settings" in inspect.signature(status.model_overview).parameters, (
        "model_overview must accept settings so the caller can supply the real interval"
    )


def test_the_web_route_passes_its_settings_through():
    """The route must supply the interval it actually runs with."""
    from pathlib import Path

    web = (Path(__file__).resolve().parent.parent / "weirvern" / "admin" / "web.py").read_text()
    assert "model_overview(client, hours=hours, settings=ctx.settings)" in web, (
        "the /api/models route does not pass settings, so the panel falls back to the default "
        "interval and can disagree with the worker"
    )


# ── the payload and the view ───────────────────────────────────────────────────────────────


def test_the_payload_carries_staleness_and_the_interval():
    from weirvern.admin import web_api

    out = web_api.models_payload({
        "available": True, "hours": 72, "run_count": 1,
        "training_history": {}, "scores": {}, "model_counts": {},
        "feature_deviations": [], "points": [],
        "staleness": [{"model": "DBSCAN", "age_h": 16.0, "stale": True}],
        "retrain_interval_h": 6.0,
    })
    assert out["staleness"], "models_payload drops the staleness rows"
    assert out["retrain_interval_h"] == 6.0, "models_payload drops the interval"

    # And a failure must still short-circuit rather than inventing empty staleness.
    fail = web_api.models_payload({"available": False, "reason": "nope"})
    assert fail["available"] is False and "staleness" not in fail


def test_the_view_renders_staleness_and_states_the_remedy():
    """The verdict without a remedy is a number an operator cannot act on."""
    from pathlib import Path

    web = Path(__file__).resolve().parent.parent / "weirvern" / "admin" / "web"
    app_js = (web / "app.js").read_text()
    index = (web / "index.html").read_text()

    assert "function renderStaleness" in app_js, "there is no renderer for the staleness rows"
    assert "renderStaleness(data.staleness" in app_js, (
        "loadModels does not call the renderer, so the panel would never fill"
    )
    assert 'id="m-stale"' in index, "the staleness table is missing from the Models view"
    assert "m-stale" in app_js, "the renderer targets an element the markup does not define"

    # The words must say what is wrong and what it means, not just show a colour.
    assert "last retrained more than" in app_js, (
        "the note does not explain an overdue detector in words"
    )
    assert "never trained" in app_js, (
        "the view does not distinguish 'never trained' from 'overdue'"
    )
    assert "older traffic mix" in app_js, (
        "the note states the symptom without saying what it means for the scores"
    )
