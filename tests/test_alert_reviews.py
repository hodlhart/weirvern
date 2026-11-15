"""SOC-1: alert review state -- the analyst's disposition of an anomaly.

THE GAP THIS CLOSES. The GUI could show an anomaly and explain it, and then the
workflow ended: no acknowledge, no resolve, no false-positive, no note. The same
recurring benign alert (a nightly backup, a scanner you own) re-appeared forever
with no way to clear it, and there was no record of what had been reviewed.

Phase 1 (this file) is the state machine and its persistence:
  * one disposition per (window_start, src_addr) -- the anomaly's own key, so no id
    is minted, passed around, and eventually mis-typed;
  * three real states plus a REAL "cleared" (empty string), which is the honest
    representation of undo;
  * and a distinct "unavailable" wire value: when the reviews table cannot be read
    (schema job not re-run yet), the UI must not render every row as confidently
    unreviewed -- that is the confident-empty failure this codebase treats as a bug
    class, not a cosmetic choice.

WHY THE WRITE GOES THROUGH THE OPERATOR TOKEN. The reviews are written from the
same unauthenticated LAN port as the rest of the GUI. Reads staying open is a
deliberate design choice; WRITES are not, so the review route reuses the settings
write gate. An alert marked "false positive" by whoever can reach the port would
be worse than no review state at all.
"""
from __future__ import annotations

import datetime
import re
from pathlib import Path

import pytest

from weirvern.admin import status

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


# ── the schema ──────────────────────────────────────────────────────────────────


def test_the_schema_defines_alert_reviews():
    sql = (ROOT / "weirvern" / "schema" / "008_alert_reviews.sql").read_text()
    assert "CREATE TABLE IF NOT EXISTS weirvern.alert_reviews" in sql
    for col in ("window_start", "src_addr", "state", "note", "reviewed_at", "reviewed_by"):
        assert col in sql, f"alert_reviews is missing {col}"
    assert "ReplacingMergeTree" in sql, (
        "a review is the CURRENT disposition; a plain MergeTree would accumulate "
        "contradictory rows and FINAL would not resolve them"
    )
    # Keyed like the anomaly it reviews, so the join is (window_start, src_addr) with no id.
    assert "ORDER BY (window_start, src_addr)" in sql


def test_the_schema_documents_the_states_the_code_writes():
    """One vocabulary: the comments, the code tuple, and the route's validation."""
    sql = (ROOT / "weirvern" / "schema" / "008_alert_reviews.sql").read_text()
    assert "ack" in sql and "resolved" in sql and "false_positive" in sql
    # And the code's own list agrees with the docstring's claim about 'cleared'.
    assert "" in status.VALID_REVIEW_STATES, (
        "the empty string must be a valid state -- it is how a review is cleared, "
        "and without it there is no undo"
    )
    assert set(s for s in status.VALID_REVIEW_STATES if s) == {
        "ack", "resolved", "false_positive"}


# ── the write path ──────────────────────────────────────────────────────────────


class _Ins:
    def __init__(self):
        self.calls: list[tuple] = []

    def insert(self, table, data, column_names=None):
        self.calls.append((table, data, column_names))
        return len(data)


def test_write_review_inserts_one_row_keyed_like_the_anomaly():
    c = _Ins()
    ok = status.write_review(c, window_start="2026-09-20 10:05:00",
                             src_addr="198.51.100.9", state="ack", note="watching")
    assert ok
    table, data, cols = c.calls[0]
    assert table == "weirvern.alert_reviews"
    assert cols == ["window_start", "src_addr", "state", "note", "reviewed_at"]
    assert data[0][1] == "198.51.100.9" and data[0][2] == "ack" and data[0][3] == "watching"
    assert isinstance(data[0][0], datetime.datetime), "window_start must be a real stamp"


def test_write_review_refuses_an_unknown_state():
    """Both layers refuse: the route gives a 400; this guard means code that skips
    the route still cannot write a state the UI cannot render."""
    c = _Ins()
    with pytest.raises(ValueError):
        status.write_review(c, window_start="2026-09-20 10:05:00",
                            src_addr="198.51.100.9", state="handled-ish")
    assert not c.calls, "an invalid state reached the database"


def test_clearing_a_review_is_a_write_not_a_delete():
    """Empty state = back to unreviewed. It must write the empty state rather than
    fail -- that is the undo."""
    c = _Ins()
    assert status.write_review(c, window_start="2026-09-20 10:05:00",
                               src_addr="198.51.100.9", state="")
    assert c.calls[0][1][0][2] == ""


def test_write_review_refuses_an_unparseable_window():
    c = _Ins()
    with pytest.raises(ValueError):
        status.write_review(c, window_start="not-a-time", src_addr="198.51.100.9", state="ack")


def test_parse_stamp_takes_both_forms_the_server_sends():
    """The browser round-trips the server's own value, so both ISO strings and real
    datetimes must parse -- and the key must not SHIFT between the two."""
    naive = datetime.datetime(2026, 9, 20, 10, 5, 0)
    for value in ("2026-09-20 10:05:00", "2026-09-20T10:05:00",
                  "2026-09-20T10:05:00Z", "2026-09-20T10:05:00+00:00", naive):
        parsed = status._parse_stamp(value)
        assert parsed is not None, f"{value!r} did not parse"
        assert parsed.replace(microsecond=0) == naive, (
            f"{value!r} parsed to {parsed}, shifting the key and orphaning the review"
        )


def test_parse_stamp_rejects_garbage():
    for value in ("", "   ", None, "yesterday", 12345):
        assert status._parse_stamp(value) is None


# ── the read path ───────────────────────────────────────────────────────────────


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Reader:
    def __init__(self, rows=None, fail=False):
        self.rows = rows or []
        self.fail = fail
        self.query_text = ""

    def query(self, sql, parameters=None):
        self.query_text = sql
        if self.fail:
            raise RuntimeError("simulated clickhouse failure")
        return _Result(self.rows)


def test_review_index_reads_final_and_keys_by_the_anomaly_pair():
    stamp = datetime.datetime(2026, 9, 20, 10, 5, 0)
    c = _Reader([[stamp, "198.51.100.9", "false_positive", "it is our scanner", stamp]])
    idx, err, _since = status.review_index(c)
    assert err is None
    assert idx[(stamp, "198.51.100.9")]["state"] == "false_positive"
    assert "FINAL" in c.query_text.upper(), (
        "without FINAL a ReplacingMergeTree can return superseded dispositions"
    )


def test_a_TIMEZONE_AWARE_stamp_merges_with_its_naive_twin():
    """THE LIVE-BOX BUG, as a regression test.

    ClickHouse returns window_start TZ-AWARE (the server's zone); the write path and the
    lookup both work in naive wall-clock. Building the index with the raw aware value
    while looking up with a naive one made KEY EQUALITY FAIL for every row: the review was
    stored and read back correctly, and then silently not merged -- a false-positive
    marking looked like it never saved. Caught only on the deployed box; the unit fakes
    had used naive datetimes on both sides, which is why every test was green.

    Both sides must normalise through _parse_stamp, so this pins the INDEX side and
    attach_reviews pins the lookup side.
    """
    aware = datetime.datetime(2026, 9, 20, 10, 5, 0,
                              tzinfo=datetime.timezone(datetime.timedelta(hours=-5)))
    naive = datetime.datetime(2026, 9, 20, 10, 5, 0)

    # The index, built from what ClickHouse actually returned (aware)...
    idx, err, _since = status.review_index(_Reader([[aware, "198.51.100.9", "ack", "", aware]]))
    assert err is None
    # ...must merge onto a row whose value round-tripped as naive (what the API sends
    # the browser, and what the browser sends back).
    rows = [{"window_start": naive, "src_addr": "198.51.100.9"}]
    status.attach_reviews(rows, idx, None)
    assert rows[0]["review_state"] == "ack", (
        "an aware index key did not match its naive twin -- the review is stored, read "
        "back, and then silently dropped at merge time"
    )


def test_a_missing_table_is_unavailable_not_empty():
    """THE THREE-VALUED RULE. 'Cannot read the reviews' must not collapse into
    'nothing has been reviewed' -- the analyst would stop looking for their own
    earlier decisions."""
    idx, err, _since = status.review_index(_Reader(fail=True))
    assert idx == {}
    assert err and "unavailable" in err


def test_attach_reviews_marks_every_row_unavailable_when_the_read_failed():
    rows = [{"window_start": datetime.datetime(2026, 9, 20, 10, 5), "src_addr": "198.51.100.9"}]
    status.attach_reviews(rows, {}, "review state is unavailable")
    assert rows[0]["review_state"] == status.REVIEW_UNAVAILABLE
    assert rows[0]["review_state"] != "", (
        "a failed read rendered as 'unreviewed' -- the confident-empty failure"
    )


def test_attach_reviews_merges_a_known_review():
    stamp = datetime.datetime(2026, 9, 20, 10, 5)
    rows = [{"window_start": stamp, "src_addr": "198.51.100.9"}]
    idx = {(stamp, "198.51.100.9"): {"state": "ack", "note": "seen",
                                     "reviewed_at": stamp}}
    status.attach_reviews(rows, idx, None)
    assert rows[0]["review_state"] == "ack"
    assert rows[0]["review_note"] == "seen"
    assert rows[0]["reviewed_at"], "the review time must survive serialisation"


def test_attach_reviews_leaves_unmatched_rows_empty_when_read_succeeded():
    rows = [{"window_start": datetime.datetime(2026, 9, 20, 10, 5), "src_addr": "198.51.100.9"}]
    status.attach_reviews(rows, {}, None)
    assert rows[0]["review_state"] == ""
    assert rows[0]["review_note"] == ""
    assert rows[0]["reviewed_at"] is None


# ── the route ───────────────────────────────────────────────────────────────────


def test_the_review_route_exists_and_goes_through_the_operator_gate():
    src = (ROOT / "weirvern" / "admin" / "web.py").read_text()
    assert '"/api/review"' in src, "the review POST route is gone"
    # The gate must be consulted inside _review -- the check every write route owes.
    body = src[src.index("def _review(self)"):]
    body = body[:body.index("\n        def _settings_plan")]
    assert "self._authorize()" in body, (
        "the review route does not consult the operator token, so anyone on the LAN "
        "could mark alerts as handled"
    )
    assert "review_state_refusal(" in body, (
        "the route does not ask the shared state validator, so the two surfaces can disagree "
        "about which states exist"
    )

    # THE VOCABULARY CHECK MOVED into payloads.review_state_refusal with the port; it must still
    # be the ONE tuple the UI and the database share.
    payloads = (ROOT / "weirvern" / "admin" / "payloads.py").read_text()
    guard = payloads[payloads.index("def review_state_refusal("):]
    guard = guard[:guard.index("\ndef ")]
    assert "VALID_REVIEW_STATES" in guard, (
        "the route no longer validates the state against the one tuple, so the UI and "
        "the database can disagree about the vocabulary"
    )


def test_the_anomalies_route_merges_reviews_and_filters_only_when_readable():
    """The merge moved into payloads.anomalies when the route crossed to Flask; the intent is
    unchanged, and it is asserted where the merge now lives."""
    src = (ROOT / "weirvern" / "admin" / "payloads.py").read_text()
    body = src[src.index("def anomalies("):]
    body = body[:body.index("\ndef ")]
    # The merge is the GROUPED one since 2026-10-16 (the count column); the intent is unchanged.
    assert "review_index" in body and "attach_group_reviews" in body
    # THE SUBTLE ONE: the unreviewed filter must not run on a FAILED read.
    assert "rev_err is None" in body or "rev_err is not None" in body, (
        "the filter no longer guards on the review read; filtering a failed read "
        "answers 'nothing is unreviewed' from a query that returned nothing"
    )


# ── the frontend ────────────────────────────────────────────────────────────────


def test_the_gui_has_the_review_column_and_controls():
    html = (WEB / "index.html").read_text()
    assert "<th>Actions</th>" in html, (
        "the Actions column header is gone (the Review chip shares this column now)"
    )
    assert 'id="f-unreviewed"' in html, "the unreviewed-only filter is gone"
    app = (WEB / "app.js").read_text()
    assert "reviewCell" in app and "postReview" in app
    assert 'review: "/api/review"' in app, "the API map lost the review route"


def test_every_review_state_the_server_validates_has_a_ui_label():
    """A state the server accepts but the UI cannot name would render its raw wire
    value -- or worse, 'undefined'. The mappings must cover the server's list."""
    app = (WEB / "app.js").read_text()
    for state in ("ack", "resolved", "false_positive", status.REVIEW_UNAVAILABLE):
        assert f'"{state}"' in app, f"the GUI has no label mapping for {state!r}"
    # And 'cleared' renders as the unreviewed chip, not as a blank.
    assert '"": "unreviewed"' in app


def test_the_review_chip_renders_server_state_never_local_guesses():
    """After a click the list reloads and the chip shows the server's answer. An
    optimistic local update would display a decision that a failed write never
    recorded -- the one thing a triage tool must not do."""
    app = (WEB / "app.js").read_text()
    body = app[app.index("async function postReview"):]
    body = body[:body.index("async function loadAnomalies")]
    assert "loadAnomalies()" in body, (
        "postReview no longer reloads from the server after a write; the chip would "
        "reflect the click rather than the stored disposition"
    )
    # And a failed write must surface, not be swallowed.
    assert "showError" in body


def test_the_harness_covers_the_review_flow():
    js = (ROOT / "scripts" / "jsdom_render.js").read_text()
    assert "ANOMALIES_PAYLOAD" in js and "review_state" in js, (
        "the DOM harness has no review-state payload, so the column's rendering is "
        "not exercised by the only test that runs the real DOM"
    )
    assert '"/api/review"' in js, "the harness cannot exercise the review POST"
    assert re.search(r"POSTs the disposition to /api/review", js), (
        "the harness no longer asserts the review request, only the render"
    )


# ── a row older than the review window is NOT "unreviewed" ─────────────────────────────────────
#
# MEASURED DEFECT (triaged from an independent finding, 2026-09-23). `review_index` reads a BOUNDED
# window (72h) while `anomalies_detailed` has NO time bound -- it returns the newest N rows whatever
# their age. So an anomaly older than the window found no match in the index and was labelled
# review_state="", which the UI renders as "nobody has looked at this".
#
# That label is a claim about the OPERATOR'S WORK and it can be false: the review may exist and
# simply fall outside the window. The consequence is an analyst re-triaging an alert that was
# already dispositioned, and losing trust in the queue when they later find the notes elsewhere.
#
# The bound comes from review_index itself rather than being recomputed by the caller, because two
# places computing "the window" is how they drift apart.
def test_a_row_older_than_the_index_is_marked_unknowable_not_unreviewed():
    import datetime as _dt

    from weirvern.admin import status

    covered_since = _dt.datetime.now(_dt.UTC) - _dt.timedelta(hours=72)
    old_row = {"window_start": (covered_since - _dt.timedelta(hours=1)).isoformat(),
               "src_addr": "198.51.100.9"}
    status.attach_reviews([old_row], {}, None, covered_since)
    assert old_row["review_state"] == status.REVIEW_UNAVAILABLE, (
        f"an out-of-window row read as {old_row['review_state']!r}; an empty state means "
        "'nobody has reviewed this', which may be false"
    )
    assert "older than the review history" in old_row["review_note"]


def test_a_row_inside_the_window_with_no_review_is_still_plainly_unreviewed():
    """The converse: the fix must not turn every unreviewed alert into an unknowable one.

    Without this, over-correcting would make the queue useless -- an analyst could never tell which
    alerts genuinely need attention.
    """
    import datetime as _dt

    from weirvern.admin import status

    covered_since = _dt.datetime.now(_dt.UTC) - _dt.timedelta(hours=72)
    fresh = {"window_start": (covered_since + _dt.timedelta(hours=1)).isoformat(),
             "src_addr": "198.51.100.9"}
    status.attach_reviews([fresh], {}, None, covered_since)
    assert fresh["review_state"] == "", (
        f"a fresh unreviewed row read as {fresh['review_state']!r}; it should be plainly empty"
    )


def test_a_review_inside_the_window_is_still_merged():
    """Guards the merge path against the new early-continue."""
    import datetime as _dt

    from weirvern.admin import status

    covered_since = _dt.datetime.now(_dt.UTC) - _dt.timedelta(hours=72)
    stamp = covered_since + _dt.timedelta(hours=2)
    row = {"window_start": stamp.isoformat(), "src_addr": "198.51.100.9"}
    # Build the key the same way the index does.
    from weirvern.admin.status import _parse_stamp

    merged = {(_parse_stamp(stamp.isoformat()), "198.51.100.9"):
              {"state": "ack", "note": "known scanner", "reviewed_at": stamp}}
    status.attach_reviews([row], merged, None, covered_since)
    assert row["review_state"] == "ack", f"a matching review was not merged: {row}"


def test_the_index_reports_its_own_lower_bound():
    """The bound must come from the function that applies the WHERE clause.

    A caller that recomputes the window is a second copy of the same fact, and the defect above is
    exactly what happens when the two disagree.
    """
    import datetime as _dt

    from weirvern.admin import status

    class Reader:
        def query(self, *a, **k):  # noqa: ANN002, ANN003
            class R:
                result_rows: list = []
            return R()

    idx, err, covered_since = status.review_index(Reader(), hours=24)
    assert err is None
    assert covered_since is not None, "review_index returned no bound for its own window"
    age_h = (_dt.datetime.now(_dt.UTC) - covered_since).total_seconds() / 3600
    assert 23 < age_h < 25, f"the reported bound is {age_h:.1f}h old, expected ~24h"


def test_anomalies_filters_bind_server_side():
    """The dashboard-wide filter on the triage queue: a clicked host or severity must be answered
    BY THE QUERY. Filtering in the browser after a LIMIT would quietly drop matches that were
    never fetched."""
    from weirvern.admin import status

    seen = {}

    class _C:
        def query(self, sql, parameters=None, **_kw):
            seen["sql"], seen["params"] = sql, dict(parameters or {})
            class R:
                result_rows = []
                column_names = []  # the builder zips rows against these; empty rows, empty zip
            return R()

    status.anomalies_detailed(_C(), limit=50, min_score=0.2, host="198.51.100.20",
                              severity="high")
    assert "AND src_addr = %(host)s" in seen["sql"]
    assert "AND severity = %(sev)s" in seen["sql"]
    assert seen["params"]["host"] == "198.51.100.20" and seen["params"]["sev"] == "high"
    assert seen["params"]["s"] == 0.2 and seen["params"]["n"] == 50
    status.anomalies_detailed(_C(), limit=50, min_score=0.0)
    assert "src_addr = %(host)s" not in seen["sql"], "no filter, no clause"
    assert "severity" not in seen["sql"].split("WHERE")[1].split("ORDER")[0]


def test_severity_counts_bind_and_do_not_swallow_their_own_output():
    """The tiles' counts: min-score and host apply, the SEVERITY filter itself must NOT -- a
    counts query that consumed its own output would collapse to one tile the moment a filter is
    on, and switching severity would hide the answer."""
    from weirvern.admin import status as st

    seen = {}

    class _C:
        def query(self, sql, parameters=None, **_kw):
            seen["sql"], seen["params"] = sql, dict(parameters or {})
            class R:
                result_rows = [("high", 7), ("medium", 2)]
            return R()

    out = st.anomaly_severity_counts(_C(), min_score=0.3, host="198.51.100.9")
    assert "GROUP BY severity" in seen["sql"]
    assert "severity = " not in seen["sql"].split("GROUP")[0], "no self-filter"
    assert seen["params"]["host"] == "198.51.100.9" and seen["params"]["s"] == 0.3
    assert out["available"] is True
    assert out["counts"][0] == {"severity": "high", "count": 7}


def test_anomalies_payload_is_an_object_carrying_rows_and_tiles():
    from weirvern.admin import web_api

    p = web_api.anomalies_payload([], severity_counts={"available": True, "reason": "",
                                                       "counts": [{"severity": "low", "count": 3}]})
    assert isinstance(p, dict) and p["rows"] == []
    assert p["severity_counts"]["counts"][0]["count"] == 3
    p2 = web_api.anomalies_payload([])
    assert p2["severity_counts"]["available"] is False, (
        "an unread counts query is a state, never zeros that read as a calm page")



# ── issue #20: one definition of reviewed, and per-occurrence actions ─────────────────────────
#
# The chip, the count tooltip and the unreviewed-only filter described "reviewed" differently:
# the chip echoed the NEWEST occurrence while `unreviewed_n` counted every one, so acking the
# newest of a group read as done while the filter still (correctly) listed the row; and the
# unfolded occurrence list carried no actions, so older occurrences could not be dispositioned
# from the UI at all. The chip now carries the remainder from the SAME helper the tooltip reads,
# and each unfolded occurrence posts its own window through the same review path.


def test_group_windows_carry_the_reviewed_at_the_per_occurrence_chip_shows():
    """The unfold's chip states WHEN an occurrence was reviewed; without reviewed_at on the
    window entry every restored occurrence would read "not reviewed yet" -- an occurrence
    that was plainly dispositioned presenting as untouched."""
    old = datetime.datetime(2026, 1, 2, 6, 45)
    rows = [{"windows": ["2026-01-02T06:45:00", "2026-01-02T07:25:00"],
             "src_addr": "198.51.100.9"}]
    idx = {(old, "198.51.100.9"): {"state": "resolved", "note": "", "reviewed_at": old}}
    status.attach_group_reviews(rows, idx, None, None)
    assert rows[0]["windows"][0]["reviewed_at"] == old
    assert rows[0]["windows"][1]["reviewed_at"] is None
    assert rows[0]["unreviewed_n"] == 1, (
        "the newest window is unreviewed, so the row must say one is left"
    )


def test_the_row_chip_the_tooltip_and_the_filter_read_one_definition():
    """The chip's remainder and the count tooltip must come from ONE helper -- two formulas
    for the same number is how the three surfaces drifted apart in the first place."""
    app = (WEB / "app.js").read_text()
    assert "function anReviewSummary" in app
    chip = app[app.index("function reviewCell"):app.index("async function postReview")]
    assert "anReviewSummary(a)" in chip and "review-remain" in chip, (
        "the chip no longer states how many occurrences are still unreviewed"
    )
    table = app[app.index("async function loadAnomalies"):]
    table = table[:table.index("/* ── host drill-down")]
    assert "anReviewSummary(a).title" in table, (
        "the count tooltip no longer reads the same summary the chip does"
    )


def test_each_occurrence_in_the_unfold_carries_its_own_review_actions():
    app = (WEB / "app.js").read_text()
    body = app[app.index("function anToggleOccurrences"):]
    body = body[:body.index("THE DASHBOARD-WIDE FILTER")]
    assert "window_start: w.window" in body and "reviewActs(" in body, (
        "an older occurrence cannot be dispositioned: the unfold no longer posts ITS window "
        "through the shared review path"
    )
    # And the unreadable-store rule survives the refactor, in the shared builder.
    assert 'if (state === "unavailable") return null;' in app, (
        "the unavailable path lost its no-controls rule"
    )


def test_the_feature_filter_is_bound_in_the_queue_and_its_counts():
    """A model feature bar must reach the queue as a server-side filter, not a client hide."""
    class _C:
        def __init__(self):
            self.seen = []

        def query(self, sql, parameters=None):
            self.seen.append((sql, dict(parameters or {})))
            return type("R", (), {"result_rows": [], "column_names": []})()

    c = _C()
    from weirvern.admin import status as st
    st.anomalies_grouped(c, hours=24, feature="total_packets")
    assert "primary_deviation_feature = %(feature)s" in c.seen[-1][0]
    assert c.seen[-1][1]["feature"] == "total_packets"
    st.anomaly_severity_counts(c, hours=24, feature="total_packets")
    assert "primary_deviation_feature = %(feature)s" in c.seen[-1][0]
    assert c.seen[-1][1]["feature"] == "total_packets"
