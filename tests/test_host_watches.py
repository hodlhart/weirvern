"""The alert action cell's Watch: a persistent, per-host tracking list (BF-1).

THE GAP THIS CLOSES. An anomaly row could say "this host is behaving oddly" and offer a
disposition, and then the host vanished back into the queue. "Keep an eye on this machine"
had no place to live, so it lived in the operator's memory -- the morning check was
re-finding the same hosts by hand. Watch gives that intent a server-side home: one flag per
host, a marker on its rows, and a watched-only filter on the queue.

WHY A HOST, NOT AN ANOMALY. Disposition (alert_reviews) is about one anomaly; a watch is
about the machine, across windows and across detectors, and it outlives every one of them.
Two states, two tables, no confusion about which question a row answers.

WHY THE READ IS FAIL-SOFT, LIKE THE REVIEWS. A deployment whose schema job has not re-run
has no host_watches table. That must render as "Watch unavailable" -- a visible cannot-tell --
never as an off state that claims nothing is watched, and never as a filter that answers
"nothing is watched" from a failed query. Same failure class the review code names and
avoids; this file holds the watch code to it.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.support_routes import routed
from weirvern.admin import status

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


# ── the schema ──────────────────────────────────────────────────────────────────────────────


def test_the_schema_defines_host_watches():
    sql = (ROOT / "weirvern" / "schema" / "021_host_watches.sql").read_text()
    assert "CREATE TABLE IF NOT EXISTS weirvern.host_watches" in sql
    assert "ReplacingMergeTree(watched_at)" in sql, (
        "the watch table must replace on the toggle, so FINAL reads one answer per host"
    )
    assert "ORDER BY src_addr" in sql, (
        "one row per host: keying by anything else would make 'what am I watching' " "a question about history"
    )


# ── the store functions ─────────────────────────────────────────────────────────────────────


class _Ins:
    def __init__(self):
        self.calls = []

    def insert(self, table, data, column_names=None):
        self.calls.append((table, data, column_names))

    def query(self, sql, parameters=None):
        return _Result([])


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Reader:
    def __init__(self, rows=None, fail=False):
        self.rows = rows or []
        self.fail = fail

    def query(self, sql, parameters=None):
        if self.fail:
            raise RuntimeError("Table weirvern.host_watches does not exist")
        assert "FINAL" in sql and "watching = 1" in sql, (
            "the watch read must take the replaced state (FINAL) and only the on rows"
        )
        return _Result(self.rows)


def test_write_watch_inserts_the_toggle():
    c = _Ins()
    status.write_watch(c, src_addr="203.0.113.42", watching=True)
    status.write_watch(c, src_addr="203.0.113.42", watching=False)
    assert c.calls[0][0] == "weirvern.host_watches"
    assert c.calls[0][2] == ["src_addr", "watching", "watched_at"]
    assert c.calls[0][1][0][1] == 1, "on must be stored as 1"
    assert c.calls[1][1][0][1] == 0, "off is a write of 0, not a delete -- the replace needs it"


@pytest.mark.parametrize("bad", ["", "   ", "not-an-ip", "12345", "x" * 65])
def test_write_watch_refuses_garbage(bad):
    with pytest.raises(ValueError):
        status.write_watch(_Ins(), src_addr=bad, watching=True)


def test_watch_index_reads_final_and_returns_a_set():
    idx, err = status.watch_index(_Reader([("192.0.2.40",), ("198.51.100.77",)]))
    assert err is None
    assert idx == {"192.0.2.40", "198.51.100.77"}


def test_a_missing_table_is_unavailable_not_empty():
    idx, err = status.watch_index(_Reader(fail=True))
    assert idx == set()
    assert err, "a failed read must carry an error, or the UI claims nothing is watched"


# ── the route + the merge (source contracts, like the review tests) ─────────────────────────


def test_the_watch_route_exists_and_goes_through_the_operator_gate():
    src = (ROOT / "weirvern" / "admin" / "web.py").read_text()
    assert routed("/api/watch"), "the watch POST route is gone"
    body = src[src.index("def _watch(self)"):]
    body = body[:body.index("\n        def ", 10)]
    assert "self._authorize()" in body, (
        "the watch route does not consult the operator token, so anyone on the LAN "
        "could rewrite the tracking list"
    )
    assert "payloads.watch(" in body, "the route does not use the shared fetcher"

    # THE MUTATION MOVED into payloads.watch with the port; it must still WRITE and READ BACK.
    payloads = (ROOT / "weirvern" / "admin" / "payloads.py").read_text()
    fetcher = payloads[payloads.index("def watch("):]
    fetcher = fetcher[:fetcher.index("\ndef ")]
    assert "write_watch" in fetcher and "watch_index" in fetcher, (
        "the route must WRITE and READ BACK -- render what landed, not what was asked"
    )


def test_the_anomalies_route_merges_watches_and_filters_only_when_readable():
    """The watch merge moved into payloads.anomalies with the port; the guard moved with it."""
    src = (ROOT / "weirvern" / "admin" / "payloads.py").read_text()
    body = src[src.index("def anomalies("):]
    body = body[:body.index("\ndef ")]
    assert "watch_index" in body and 'r["watched"]' in body
    assert "watch_err is None" in body, (
        "the watched filter no longer guards on the read; filtering a failed read "
        "answers 'nothing is watched' from a query that returned nothing"
    )


def test_the_gui_has_the_action_cell_and_watch_controls():
    html = (WEB / "index.html").read_text()
    assert "<th>Actions</th>" in html, "the actions column header is gone"
    assert 'id="f-watched"' in html, "the watched-only filter is gone"
    app = (WEB / "app.js").read_text()
    assert "anActions" in app and "watchAction" in app
    assert 'watch: "/api/watch"' in app, "the API map lost the watch route"
    assert '"&watched=1"' in app, "the queue no longer carries the watched filter"


def test_the_harness_covers_the_watch_flow():
    js = (ROOT / "scripts" / "jsdom_render.js").read_text()
    assert "watched: true" in js, (
        "the DOM harness has no watched row, so the action cell's rendering is not "
        "exercised by the only test that runs the real DOM"
    )
    assert '"/api/watch"' in js, "the harness cannot exercise the watch POST"
    assert re.search(r"Watch click POSTs the toggle to /api/watch", js), (
        "the harness no longer asserts the watch request, only the render"
    )
