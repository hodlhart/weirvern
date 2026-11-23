"""A channel belongs to EVERY weirling, not just the hub.

WHY THIS FILE EXISTS. A channel is an inline bridge between two NICs (`admin/channel.py`), not a
sensor mode. Until this feature the pair lived only in the deployment ConfigMap, which describes
exactly one sensor -- the one whose worker reads it -- and the Weirlings sheet hid the control for
every other sensor. The properties pinned here are the ones that would silently regress:

  * the pair is stored in the weirling's PLAN and comes back on the same read the sheet uses;
  * a partial pair, the management port, an unknown NIC and two identical ports are all REFUSED
    with a reason an operator can act on;
  * empty strings CLEAR the pair (a channel is two ports or none);
  * the sheet offers the section to a remote (non-local) sensor, and Apply writes the plan, not
    the console's local settings.

The write tests drive the real Flask routes against a duck-typed ClickHouse client, the same shape
tests/test_weirlings_plan_api.py uses, so the shipping route, body parser, validation and store
are all exercised rather than a paraphrase of them.
"""
from __future__ import annotations

import contextlib
import datetime
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"
NOW = datetime.datetime(2026, 10, 17, 12, 0, 0, tzinfo=datetime.UTC)
OPERATOR_TOKEN = "deploy-token"

# The exact columns `status._sensor_rows` selects, so the stub's named results agree with the
# real reader rather than with a convenient shorter list.
HEARTBEAT_COLUMNS = [
    "sensor_id", "mode", "iface", "segment", "hosts", "mappings", "running", "uptime_s",
    "restores", "refreshes", "failures", "ts", "capture_loss_pct", "packets_recv",
    "packets_dropped", "host_stats", "interfaces",
    "channel_active", "channel_upstream", "channel_downstream", "channel_bridge",
]


class _StubResult:
    def __init__(self, rows, cols):
        self.result_rows = rows
        self._cols = cols

    def named_results(self):
        for row in self.result_rows:
            yield dict(zip(self._cols, row, strict=False))


class _StubCh:
    """Registry rows in `fleet_store.COLUMNS` order, plus one optional heartbeat."""

    def __init__(self, rows=None, heartbeats=None):
        self.rows = list(rows or [])
        self.heartbeats = list(heartbeats or [])
        self.inserted = []

    def query(self, sql, **_kw):
        from weirvern import fleet_store as store

        if "FROM weirvern.weirlings" in sql:
            rows = list(self.rows)
            if "revoked_at IS NULL" in sql:
                idx = store.COLUMNS.index("revoked_at")
                rows = [r for r in rows if r[idx] is None]
            return _StubResult(rows, store.COLUMNS)
        if "FROM weirvern.sensor_status" in sql:
            return _StubResult(self.heartbeats, HEARTBEAT_COLUMNS)
        return _StubResult([], [])

    def insert(self, table, rows, column_names=None):  # noqa: ANN001
        from weirvern import fleet_store as store

        cols = column_names or store.COLUMNS
        for row in rows:
            self.inserted.append({"table": table, **dict(zip(cols, row, strict=False))})
            if table == "weirvern.weirlings":
                self.rows = [x for x in self.rows if x[0] != row[0]]
                self.rows.append(list(row))


def _row(sensor_id="unit-a", *, mode="loch", plan=None, nics=None, revoked_at=None):
    """One registry row in `fleet_store.COLUMNS` order."""
    from weirvern import fleet as fleet_mod

    plan = plan or {}
    nics = {"eth1": {}, "eth2": {}, "eth3": {}} if nics is None else nics
    nics_json = json.dumps(nics, sort_keys=True) if nics else ""
    return [sensor_id, "", "third floor", mode, 1, "", NOW, NOW, revoked_at,
            *[plan.get(f, "") for f in fleet_mod.PLAN_FIELDS],
            nics_json, "capture"]


def _heartbeat(sensor_id="unit-a", *, active=False, up="eth1", down="eth2", bridge=""):
    return [sensor_id, "loch", "eth1", "third floor", 4, 0, 1, 900.0, 0, 0, [], NOW,
            None, None, None, "{}", ["eth0", "eth1", "eth2"],
            1 if active else 0, up, down, bridge]


class _Settings:
    sensor_name = "hub-sensor"
    clickhouse_password = "x"
    heartbeat_interval_s = 15
    mgmt_iface = "eth0"


def _ctx(ch):
    _settings = _Settings()

    class _Auth:
        enabled = True
        reason = ""

        def check(self, presented, client=""):  # noqa: ANN001
            return presented == OPERATOR_TOKEN

    class _Ctx:
        settings = _settings
        backend = None
        capabilities = None
        config_client = None
        user_store = None
        sessions = None
        throttle = None
        accounts_note = ""
        auth = _Auth()
        connect_factory = staticmethod(lambda s: contextlib.nullcontext(ch))

    return _Ctx()


def _post(ctx, route, body: dict):
    from weirvern.admin import flask_app

    client = flask_app.create_app(ctx).test_client()
    resp = client.post(route, data=json.dumps(body), content_type="application/json",
                       headers={"X-Weirvern-Token": OPERATOR_TOKEN})
    return resp.get_json()


def _hub_named(monkeypatch):
    from weirvern.admin import web as web_mod

    monkeypatch.setattr(web_mod, "_gate_sensor_name", lambda: "hub-sensor")


# ── (a) the pair round-trips through the production write and read paths ─────────────────────

def test_the_channel_pair_is_stored_in_the_plan_and_returned_on_the_fleet_read():
    from weirvern import fleet_store

    ch = _StubCh([_row("unit-a")], [_heartbeat("unit-a")])
    out = _post(_ctx(ch), "/api/weirlings/apply", {
        "sensor_id": "unit-a",
        "changes": {"channel_upstream": "eth1", "channel_downstream": "eth2"},
    })
    assert out["ok"] is True, out
    assert out["applied"]["channel_upstream"] == "eth1"
    assert out["applied"]["channel_downstream"] == "eth2"

    stored = fleet_store.read_registrations(ch)
    assert stored[0].plan.channel_upstream == "eth1"
    assert stored[0].plan.channel_downstream == "eth2"
    assert stored[0].plan.nics, "the write cleared plan_nics, which the pair was validated against"

    # THE READ THE SHEET USES, not a direct column read: the pair must ride the plan object.
    payload = fleet_store.build_fleet(ch)
    assert payload["available"] is True
    row = payload["sensors"][0]
    assert row["plan"]["channel_upstream"] == "eth1"
    assert row["plan"]["channel_downstream"] == "eth2"
    assert row["plan_nics"]
    assert row["channel_active"] is False, "the seeded heartbeat measured no live bridge"


# ── (b) every invalid pair is refused, naming the reason ─────────────────────────────────────

@pytest.mark.parametrize("changes, needle", [
    ({"channel_upstream": "eth1", "channel_downstream": "eth1"},
     "different interfaces"),
    ({"channel_upstream": "eth1"}, "needs BOTH ports"),
    ({"channel_upstream": "eth1", "channel_downstream": "eth9"},
     "not one of this sensor's declared NICs"),
    ({"channel_upstream": "eth0", "channel_downstream": "eth2"},
     "management interface"),
])
def test_an_invalid_channel_pair_is_refused_and_nothing_is_written(changes, needle):
    ch = _StubCh([_row("unit-a")], [_heartbeat("unit-a")])
    out = _post(_ctx(ch), "/api/weirlings/apply", {"sensor_id": "unit-a", "changes": changes})
    assert out["ok"] is False, out
    assert needle in out["error"], out["error"]
    assert ch.inserted == [], "a refused channel reached the store"


def test_the_preview_refuses_the_same_pairs_as_the_write():
    ch = _StubCh([_row("unit-a")])
    out = _post(_ctx(ch), "/api/weirlings/plan", {
        "sensor_id": "unit-a",
        "changes": {"channel_upstream": "eth1", "channel_downstream": "eth1"},
    })
    assert out["ok"] is False and "different interfaces" in out["error"], out
    assert ch.inserted == []


def test_a_sensor_with_no_plan_nics_can_name_ports_from_its_own_report():
    """Every weirling must be able to use a channel. A remote unit with no per-NIC plan yet
    reports its interfaces on its heartbeat; refusing every pair until someone hand-writes
    `plan_nics` would make the feature true only for seeded rows.
    """
    from weirvern import fleet_store

    ch = _StubCh([_row("unit-a", nics={})], [_heartbeat("unit-a")])
    out = _post(_ctx(ch), "/api/weirlings/apply", {
        "sensor_id": "unit-a",
        "changes": {"channel_upstream": "eth1", "channel_downstream": "eth2"},
    })
    assert out["ok"] is True, out
    stored = fleet_store.read_registrations(ch)[0]
    assert (stored.plan.channel_upstream, stored.plan.channel_downstream) == ("eth1", "eth2")


# ── (c) clearing is two empty strings, and it preserves the NIC declaration ──────────────────

def test_clearing_both_sides_removes_the_pair_and_keeps_plan_nics():
    from weirvern import fleet_store

    ch = _StubCh([_row("unit-a", plan={"channel_upstream": "eth1",
                                       "channel_downstream": "eth2"})],
                 [_heartbeat("unit-a")])
    before_nics = json.loads(fleet_store.read_registrations(ch)[0].plan.nics)
    out = _post(_ctx(ch), "/api/weirlings/apply", {
        "sensor_id": "unit-a",
        "changes": {"channel_upstream": "", "channel_downstream": ""},
    })
    assert out["ok"] is True, out
    stored = fleet_store.read_registrations(ch)[0]
    assert stored.plan.channel_upstream == ""
    assert stored.plan.channel_downstream == ""
    assert json.loads(stored.plan.nics) == before_nics, (
        "clearing a channel must not erase the sensor's declared NICs")


# ── the hub's own sensor: channel yes, mode still no ─────────────────────────────────────────

def test_the_local_sensor_may_take_a_channel_but_not_a_mode(monkeypatch):
    _hub_named(monkeypatch)
    ch = _StubCh([_row("hub-sensor")], [_heartbeat("hub-sensor")])
    ok = _post(_ctx(ch), "/api/weirlings/plan", {
        "sensor_id": "hub-sensor",
        "changes": {"channel_upstream": "eth1", "channel_downstream": "eth2"},
    })
    assert ok["ok"] is True, ok
    refused = _post(_ctx(ch), "/api/weirlings/plan", {
        "sensor_id": "hub-sensor", "changes": {"mode": "siphon"},
    })
    assert refused["ok"] is False and "OWN sensor" in refused["error"], refused
    assert ch.inserted == [], "a preview wrote a row"


# ── (d) the sheet offers the section to a REMOTE sensor and writes the plan ─────────────────

def test_a_remote_weirling_is_offered_the_channel_section():
    js = (WEB / "weirlings.js").read_text(encoding="utf-8")
    open_block = js[js.index("function openSensorActions(r)"):]
    open_block = open_block[:open_block.index("\nasync function ", 10)]
    assert "!r.local" not in open_block, (
        "openSensorActions still hides the channel section for a remote sensor")
    assert "wlChannelOffered(r)" in open_block
    assert "wlPopulateSensorChannel(r)" in open_block

    assert "all.length >= 3" in js, "the three-interface floor vanished"
    assert "plan.channel_upstream" in js and "plan.channel_downstream" in js
    assert "plan_nics" in js, "the sheet cannot fall back to the declared NICs"
    assert "staged, sensor has not applied" in js, (
        "the sheet no longer states that a differing pair is staged")

    apply_block = js[js.index("async function wlSensorChannelApply"):]
    apply_block = apply_block[:apply_block.index("\nfunction ", 10)]
    assert '"/api/weirlings/plan"' in apply_block, (
        "the channel apply does not go through the per-weirling plan API")
    assert "/api/settings/plan" not in apply_block
    assert "stageChange(" not in apply_block, (
        "the channel apply still stages console-local settings")


# ── (e) the demo fleet seeds site B with three NICs and its pair ─────────────────────────────

def test_site_b_seeds_three_nics_and_the_channel_pair_through_the_real_read_path():
    from weirvern import demo_extras, fleet_store

    class _ReadableClient(_StubCh):
        def __init__(self):
            super().__init__()
            self.tables = {}

        def insert(self, table, rows, column_names=None):  # noqa: ANN001
            self.inserts = getattr(self, "inserts", [])
            self.inserts.append((table, rows, list(column_names or [])))
            self.tables[table] = (list(rows), list(column_names or []))

        def query(self, sql, **_kw):
            from weirvern import fleet_store as store

            if "FROM weirvern.weirlings" in sql:
                rows, cols = self.tables.get("weirvern.weirlings", ([], []))
                projected = [[row[cols.index(c)] if c in cols else None
                              for c in store.COLUMNS] for row in rows]
                return _StubResult(projected, store.COLUMNS)
            if "FROM weirvern.sensor_status" in sql:
                rows, cols = self.tables.get("weirvern.sensor_status", ([], []))
                projected = [[row[cols.index(c)] if c in cols else None
                              for c in HEARTBEAT_COLUMNS] for row in rows]
                return _StubResult(projected, HEARTBEAT_COLUMNS)
            return _StubResult([], [])

    client = _ReadableClient()
    written = demo_extras.seed_fleet(client, hosts=4)
    assert written["weirlings"] == 3

    payload = fleet_store.build_fleet(client)
    assert payload["available"] is True, payload
    rows = {row["sensor_id"]: row for row in payload["sensors"]}
    site_b = rows["weir-site-b"]
    assert set(json.loads(site_b["plan_nics"])) == {"eth0", "eth1", "eth2"}
    assert site_b["interfaces"] == ["eth0", "eth1", "eth2"]
    assert site_b["plan"]["channel_upstream"] == "eth1"
    assert site_b["plan"]["channel_downstream"] == "eth2"
    # HONESTY: the demo has no kernel bridge, so the seeded sensor reports 0, not 1.
    assert site_b["channel_active"] is False
    assert site_b["channel_upstream"] == "eth1"
    assert site_b["channel_downstream"] == "eth2"
    assert site_b["channel_bridge"] == ""
