"""The sensor panel must not change answers between two reads of the same data.

THE BUG THIS FILE EXISTS FOR, reported from the running GUI: "when i refresh the gui i am watching
it switch between loch and siphon".

The cause was not the data. `sensor_status` is keyed `(sensor_id, mode)`, so a sensor that is
INTERCEPTING has two live rows at once:

    siphon    published by the running intercept process -- segment, host count, watchdog counters
    loch    published by the worker -- the configured capture mode, which does not stop existing

Both write on the same interval. The reader did `ORDER BY ts DESC LIMIT 1`, so it returned
whichever row happened to write most recently, and a refresh landing half a beat either side of
the two writes showed a different mode. Two correct rows and a reader that picked by wall-clock.

The fix ranks rows by MEANING first -- an intercepting row describes the same sensor in a strictly
more informative state -- and only then by freshness, computing staleness per row so a stale row
can never beat a live one. The other row is reported under `others` rather than discarded, because
a sensor doing both things is real and hiding half of it is its own kind of wrong panel.
"""

from __future__ import annotations

import datetime
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from weirvern.admin import status as status_mod  # noqa: E402

NOW = datetime.datetime(2026, 9, 18, 21, 0, 50, tzinfo=datetime.UTC)


def _row(mode: str, seconds_ago: float, **overrides) -> dict:
    """One heartbeat row. Defaults mirror the columns the reader actually selects."""
    row = {
        "sensor_id": "sensor",
        "mode": mode,
        "iface": "eth1",
        "segment": "",
        "hosts": 0,
        "mappings": 0,
        "running": 1,
        "uptime_s": 100.0,
        "restores": 0,
        "refreshes": 0,
        "failures": [],
        "ts": NOW - datetime.timedelta(seconds=seconds_ago),
    }
    row.update(overrides)
    return row


class _Client:
    """Returns whatever rows it was given, and records the query for assertions."""

    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows
        self.query_text = ""

    def query(self, sql: str):
        self.query_text = sql
        outer = self

        class _Result:
            def named_results(self):
                return list(outer._rows)

        return _Result()


# ── The reported symptom ──────────────────────────────────────────────────────────────────────

def test_the_mode_does_not_change_between_two_reads_of_the_same_data():
    """THE REGRESSION. Same rows, two calls, one answer.

    The two rows are ordered differently between the calls below, which is exactly the race that
    produced the flicker: whichever the database returned first was used.
    """
    siphon = _row("siphon", 4, segment="198.51.100.0/24", hosts=1, restores=2, refreshes=144)
    loch = _row("loch", 1)  # written MORE RECENTLY -- which is what made it win before

    first = status_mod.sensor_status(_Client([siphon, loch]), now=NOW)
    second = status_mod.sensor_status(_Client([loch, siphon]), now=NOW)

    assert first["mode"] == second["mode"], (
        "the mode changed between two reads of identical data, so the panel flickers"
    )
    assert first["mode"] == "siphon", (
        "an intercepting row must win over a passive one: it describes the same sensor in a "
        "strictly more informative state"
    )
    # And the intercept's real numbers are what the operator sees, not the worker's zeros.
    assert first["hosts"] == 1
    assert first["refreshes"] == 144


def test_a_passive_only_sensor_still_reports_loch():
    """The fix must not make everything 'siphon'. With one row, that row is the answer."""
    out = status_mod.sensor_status(_Client([_row("loch", 3)]), now=NOW)
    assert out["mode"] == "loch"
    assert out["running"] is True


def test_a_stale_intercept_row_does_not_beat_a_live_passive_one():
    """Ranking by mode must not resurrect a dead intercept.

    A `siphon` row that stopped beating is a process that is gone. Preferring it because of its mode
    would report an intercept that is not running -- the configured-vs-actual error this whole
    panel exists to avoid, reintroduced through the back door.
    """
    dead_siphon = _row("siphon", status_mod.HEARTBEAT_STALE_S + 60, hosts=1)
    live_loch = _row("loch", 2)
    out = status_mod.sensor_status(_Client([dead_siphon, live_loch]), now=NOW)
    assert out["mode"] == "loch", "a stale intercept row was preferred over a live passive one"
    assert out["running"] is True


def test_both_rows_fresh_reports_the_other_one_rather_than_hiding_it():
    """A sensor doing both things is real; the panel must say so, not show half of it."""
    out = status_mod.sensor_status(_Client([_row("siphon", 4, hosts=1), _row("loch", 1)]), now=NOW)
    assert out["mode"] == "siphon"
    others = out["others"]
    assert len(others) == 1, f"the passive row was dropped from the report: {out}"
    assert others[0]["mode"] == "loch"
    assert others[0]["age_s"] >= 0


def test_a_stale_other_row_is_not_reported():
    """`others` is a statement about what IS running now, so a dead row is not listed."""
    out = status_mod.sensor_status(
        _Client([_row("siphon", 4, hosts=1), _row("loch", status_mod.HEARTBEAT_STALE_S + 30)]),
        now=NOW,
    )
    assert out["mode"] == "siphon"
    assert out["others"] == [], "a stale row was listed as also-running"


def test_other_sensors_rows_are_not_attributed_to_this_one():
    """Several workers report under their own pod names. Their rows are not this sensor's modes.

    This is why the reader selects `sensor_id` at all: without it, a different replica's heartbeat
    would appear as a second mode of this sensor.
    """
    rows = [
        _row("siphon", 4, hosts=1),
        _row("loch", 2, sensor_id="other-pod"),
    ]
    out = status_mod.sensor_status(_Client(rows), now=NOW)
    assert out["mode"] == "siphon"
    assert out["others"] == [], "another sensor's row was attributed to this one"


# ── The query itself ──────────────────────────────────────────────────────────────────────────

def test_the_reader_does_not_use_limit_one():
    """The shape of the bug, asserted directly on the SQL.

    `LIMIT 1` over a table keyed by (sensor_id, mode) cannot be correct when a sensor legitimately
    has more than one row. It is the kind of thing a later 'optimisation' would reintroduce.
    """
    client = _Client([_row("siphon", 1)])
    status_mod.sensor_status(client, now=NOW)
    sql = " ".join(client.query_text.split())
    assert "LIMIT 1" not in sql.upper(), (
        "the reader went back to taking one arbitrary row; with two live modes this flickers"
    )
    assert "FINAL" in sql.upper(), (
        "without FINAL, ReplacingMergeTree can return superseded versions of a row"
    )


def test_the_empty_shape_includes_every_key():
    """A consumer must never distinguish 'key missing' from 'empty value'."""
    out = status_mod.sensor_status(_Client([]), now=NOW)
    for key in ("reported", "running", "stale", "age_s", "mode", "others", "failures", "error"):
        assert key in out, f"the empty report omits {key!r}"
    assert out["running"] is False
    assert out["others"] == []


def test_a_stopped_intercept_is_reported_even_though_the_passive_row_wins():
    """The reader must not let a live `loch` row imply the node is untouched.

    MEASURED ON THE LIVE BOX. An intercept publishes `siphon` under one sensor_id while the worker
    publishes the configured `loch` under the SAME sensor_id. Rows observed:

        Weirvern                      loch  hosts=0   ts 00:00:15
        Weirvern                      siphon  hosts=10  ts 23:59:55

    Once the intercept ends, its row goes stale and ranking correctly demotes it -- a stale row must
    never beat a live one. But the panel then says "Weirvern observes only and cannot affect traffic"
    about a node where an intercept ran. If the process was killed before its watchdog could restore
    (`kill -9` is uncatchable), the forged ARP mappings are STILL in the neighbours' caches: the box
    is in the path and the panel says it is not.

    So the reader reports `intercept_stopped`, and the GUI shows it as uncertainty.
    """
    import datetime

    from weirvern.admin import status as status_mod

    now = datetime.datetime(2026, 9, 19, 0, 0, 30)

    class _FakeQuery:
        def __init__(self, rows):
            self._rows = rows

        def named_results(self):
            return iter(self._rows)

    class _FakeClient:
        def __init__(self, rows):
            self._rows = rows

        def query(self, _sql):
            return _FakeQuery(self._rows)

    def row(mode, hosts, age_s):
        return {
            "sensor_id": "Weirvern", "mode": mode, "iface": "eth1", "segment": "198.51.100.0/24",
            "hosts": hosts, "mappings": 10 if mode == "siphon" else 0,
            "running": 1, "uptime_s": 300.0, "restores": 20, "refreshes": 1200,
            "failures": [], "ts": now - datetime.timedelta(seconds=age_s),
        }

    # The measured case: live loch, stale siphon.
    live_loch = row("loch", 0, 2)
    stale_siphon = row("siphon", 10, 600)
    got = status_mod.sensor_status(_FakeClient([live_loch, stale_siphon]), now=now)

    assert got["mode"] == "loch", "the live row must win over the stale one"
    assert got["intercept_stopped"] is True, (
        "a stale `siphon` row means an intercept ran and stopped; the reader must say so rather than "
        "presenting the passive row as if nothing had happened"
    )

    # And the converse: with NO siphon row ever seen, there is nothing to warn about. A banner that
    # fires on a sensor that has never intercepted is a banner that gets ignored.
    got_clean = status_mod.sensor_status(_FakeClient([live_loch]), now=now)
    assert got_clean["intercept_stopped"] is False

    # A LIVE intercept is not a stopped one -- the field must not fire while it is running.
    fresh_siphon = row("siphon", 10, 3)
    got_live = status_mod.sensor_status(_FakeClient([live_loch, fresh_siphon]), now=now)
    assert got_live["mode"] == "siphon"
    assert got_live["intercept_stopped"] is False

    # The key is ALWAYS present, so a consumer never distinguishes a missing key from a false value.
    empty = status_mod.sensor_status(_FakeClient([]), now=now)
    assert "intercept_stopped" in empty
