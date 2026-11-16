"""The demo seed must exercise the real mappers, end at now, and refuse a live install.

These tests exist because the seeder has three failure modes that all look like success:

AN EMPTY TABLE THAT NOBODY NOTICES. A seed that writes nothing for `zeek_ssl` renders exactly like a
working seed until someone opens the TLS view, so the row count per table is asserted rather than the
exit code.

TIMESTAMPS THAT MISS THE WINDOW. Every query in the console is `now() - INTERVAL`, so data ending
yesterday fills the tables and shows nothing. The newest row is checked against now.

BYPASSING THE MAPPER. Hand-building rows would make the test pass and leave the layer that actually
breaks untested, so one test replaces a mapper with a sentinel and fails if it is not called.
"""

from __future__ import annotations

import pytest

from weirvern import demo_seed, ingester
from weirvern.clock import utcnow


@pytest.fixture(scope="module")
def data():
    return demo_seed.build(hours=2, hosts=6, seed=7)


def test_every_table_gets_rows(data):
    for table in demo_seed.COLUMNS:
        assert data[table], f"{table} came out empty, and its view would render blank"
    assert len(data["zeek_conn"]) > 100


def test_every_row_matches_its_table_width(data):
    """An arity mismatch is an insert error at demo time, which is the worst moment to find it."""
    for table, rows in data.items():
        width = len(demo_seed.COLUMNS[table])
        for row in rows:
            assert len(row) == width, f"{table}: got {len(row)} values for {width} columns"


def test_the_newest_row_lands_inside_the_console_window(data):
    """Data ending yesterday is the defect this tool exists to prevent."""
    newest = max(row[0] for row in data["flows"])
    age = (utcnow() - newest).total_seconds()
    assert -60 <= age <= 900, f"newest flow is {age:.0f}s from now; a 6h window may not see it"


def test_the_oldest_row_is_about_the_requested_span_back(data):
    oldest = min(row[0] for row in data["flows"])
    span_h = (utcnow() - oldest).total_seconds() / 3600
    assert 1.5 <= span_h <= 2.1, f"asked for 2 hours, oldest row is {span_h:.1f}h back"


def test_the_records_go_through_the_REAL_mappers(monkeypatch):
    """The point of the tool. If it stops calling the mapper, it is a row dumper and this fails."""
    calls = {"n": 0}
    real = ingester.map_zeek_conn

    def counting(rec):
        calls["n"] += 1
        return real(rec)

    monkeypatch.setattr(ingester, "map_zeek_conn", counting)
    demo_seed.build(hours=1, hosts=3, seed=3)
    assert calls["n"] > 10, f"map_zeek_conn was called {calls['n']} times: rows are being hand-built"


def test_the_beacon_is_present_in_every_window(data):
    """A steady small beacon is the anomaly a volume baseline will NOT catch, so the demo needs it."""
    beacon_rows = [row for row in data["zeek_conn"] if demo_seed.BEACON_TARGET in str(row)]
    windows = {str(row[0])[:16] for row in beacon_rows}
    assert len(beacon_rows) >= 20, f"only {len(beacon_rows)} beacon connections"
    assert len(windows) >= 20, "the beacon does not span the windows"


def test_the_scan_is_high_port_count_and_low_volume(data):
    """The scan must be low bytes per flow, or it is just a busy host."""
    # zeek_conn order: ts, uid, src_addr, src_port, dst_addr, dst_port, proto, service, duration,
    # orig_bytes, ... -- so dst_port is index 5 and orig_bytes is 9. Reading index 4 as the port is
    # how this test first failed, comparing an address with an integer.
    tiny = [row for row in data["zeek_conn"] if int(row[9]) <= 40 and int(row[5]) >= 20]
    assert tiny, "no scan-shaped rows: high destination port with almost no bytes"


def test_the_flow_view_and_the_zeek_view_agree_on_volume(data):
    """A demo where the two channels contradict each other reads as a product defect, not a seed."""
    zeek = sum(int(row[9]) + int(row[10]) for row in data["zeek_conn"][:200])
    flows = sum(int(row[10]) for row in data["flows"][:200])
    assert abs(zeek - flows) <= max(zeek, flows) * 0.25, (
        f"the two channels disagree about volume: zeek {zeek}, flows {flows}"
    )


def test_the_seed_is_reproducible():
    a = demo_seed.build(hours=1, hosts=4, seed=99)
    b = demo_seed.build(hours=1, hosts=4, seed=99)
    assert a["zeek_conn"][:50] == b["zeek_conn"][:50], "the same seed produced different data"


# ── inserting, and refusing to seed a live install ──────────────────────────────────────────

class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    def __init__(self, live_rows=0):
        self.live_rows = live_rows
        self.inserts = []

    def query(self, sql, parameters=None):
        return _Result([(self.live_rows,)])

    def insert(self, table, rows, column_names=None):
        self.inserts.append((table, len(rows), list(column_names or [])))
        return len(rows)


def test_insert_all_names_the_columns_and_reports_real_counts(data):
    client = _Client()
    written = demo_seed.insert_all(client, data)

    assert written["zeek_conn"] == len(data["zeek_conn"])
    for qualified, count, columns in client.inserts:
        bare = qualified.split(".", 1)[-1]
        assert count > 0
        assert columns == demo_seed.COLUMNS[bare], f"{bare} inserted with the wrong column order"


def test_an_empty_table_is_reported_rather_than_skipped_silently():
    client = _Client()
    written = demo_seed.insert_all(client, {"zeek_conn": [], "zeek_dns": [[1] * 12]})
    assert written["zeek_conn"] == 0
    assert not any(t == "weirvern.zeek_conn" for t, _n, _c in client.inserts)


def test_a_live_install_is_refused_without_force(monkeypatch):
    client = _Client(live_rows=5_000)

    class _CM:
        def __enter__(self):
            return client

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("weirvern.db.connect", lambda settings, **k: _CM())
    monkeypatch.setattr("weirvern.config.get_settings", lambda: object())

    code = demo_seed.main(["--hours", "1", "--hosts", "3"])
    assert code == 2, "a seed ran against an install with recent flow data"
    assert not client.inserts, "it refused in words but wrote anyway"


def test_force_overrides_the_refusal(monkeypatch):
    client = _Client(live_rows=5_000)

    class _CM:
        def __enter__(self):
            return client

        def __exit__(self, *a):
            return False

    monkeypatch.setattr("weirvern.db.connect", lambda settings, **k: _CM())
    monkeypatch.setattr("weirvern.config.get_settings", lambda: object())

    code = demo_seed.main(["--hours", "1", "--hosts", "3", "--force"])
    assert code == 0
    assert len(client.inserts) == len(demo_seed.COLUMNS)


def test_dry_run_writes_nothing(monkeypatch):
    def explode(*a, **k):
        raise AssertionError("dry run connected to the database")

    monkeypatch.setattr("weirvern.db.connect", explode)
    assert demo_seed.main(["--hours", "1", "--hosts", "2", "--dry-run"]) == 0


def test_the_flow_row_names_every_column_the_schema_needs():
    """A column with no value must FAIL, not quietly insert zero.

    The seeder assembles flow rows by key, so this is what stops a future schema addition from
    producing a silent 0 in a column nobody meant to leave at zero.
    """
    from datetime import datetime

    row = demo_seed._flows_row(0.0, "192.0.2.10", "198.51.100.10", 443, 100, 200)
    row["timestamp"] = row["time_flow_start"] = row["time_flow_end"] = datetime.now()
    missing = [c for c in demo_seed.COLUMNS["flows"] if c not in row]
    assert not missing, f"_flows_row leaves these columns to a default: {missing}"
    # and the assembled rows carry real values for all of them
    data = demo_seed.build(hours=1, hosts=2, seed=5)
    width = len(demo_seed.COLUMNS["flows"])
    assert all(len(r) == width for r in data["flows"])
    assert all(v is not None for r in data["flows"] for v in r), "a flow value came out None"

