"""Demo mode is a fact about the data, and the fleet and inventory are part of the demo.

WHAT THESE PIN. A seed that writes traffic and nothing else leaves the Weirlings and Assets tabs
empty, and a demo marker that cannot be read back leaves the banner and the health checks guessing.
Both are asserted here against a duck-typed client, the same shape the user store's tests use.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from weirvern import demo_extras, demo_state


class _Client:
    def __init__(self, identity_rows=()):
        self.identity_rows = list(identity_rows)
        self.inserts: list[tuple[str, list[list], list[str]]] = []

    def query(self, _sql, parameters=None):  # noqa: ARG002
        return SimpleNamespace(result_rows=self.identity_rows)

    def insert(self, table, rows, column_names=None):
        self.inserts.append((table, rows, list(column_names or [])))


def _identity_rows(n: int = 4):
    rows = []
    for i in range(n):
        rows.append((f"192.0.2.{10 + i}", f"3c:52:82:00:00:{i:02x}", "linux",
                     json.dumps([f"demo-{i}"])))
    return rows


def test_demo_state_round_trip():
    client = _Client()
    demo_state.enable(client, seed=7, hosts=4, note="test")
    table, rows, columns = client.inserts[-1]
    assert table == "weirvern.demo_state"
    assert columns == ["id", "enabled", "seeded_at", "seed", "hosts", "note"]
    assert rows[0][1] == 1 and rows[0][3] == 7 and rows[0][4] == 4

    demo_state.disable(client)
    table, rows, _ = client.inserts[-1]
    assert table == "weirvern.demo_state"
    assert rows[0][1] == 0


def test_demo_state_read_tolerates_an_older_schema():
    class _NoTable:
        def query(self, *_a, **_k):
            raise RuntimeError("no such table")

    assert demo_state.read(_NoTable()) is None
    assert demo_state.is_enabled(_NoTable()) is False


def test_fleet_seeds_both_sensors_and_their_evidence():
    client = _Client()
    written = demo_extras.seed_fleet(client, hosts=4)
    assert written["weirlings"] == 3
    assert written["sensor_status"] == 2, "the siphon has no heartbeat: it is not intercepting"
    for table, rows, columns in client.inserts:
        for row in rows:
            assert len(row) == len(columns), f"{table}: {len(row)} values for {len(columns)} columns"
    names = {table for table, _r, _c in client.inserts}
    assert {"weirvern.weirlings", "weirvern.sensor_status", "weirvern.fleet_audit",
            "weirvern.weirling_enrollments", "weirvern.weirling_probe_requests"} <= names


def test_assets_seed_one_record_per_identity():
    client = _Client(_identity_rows(4))
    written = demo_extras.seed_assets(client, hosts=4)
    assert written["asset_registry"] == 4
    assert written["asset_scans"] == 4
    assert written["scan_jobs"] == 4
    for table, rows, columns in client.inserts:
        for row in rows:
            assert len(row) == len(columns), f"{table}: {len(row)} values for {len(columns)} columns"
    registry = next(rows for table, rows, _c in client.inserts
                    if table == "weirvern.asset_registry")
    keys = [row[0] for row in registry]
    assert len(keys) == len(set(keys)), "one registry record per asset, not one per duplicate host"


def test_assets_survive_an_empty_inventory():
    """A demo with no identity pass is still a valid (empty) inventory, not a crash."""
    assert demo_extras.seed_assets(_Client(), hosts=4) == {"assets": 0}
