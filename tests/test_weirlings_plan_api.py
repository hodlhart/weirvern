"""The per-sensor plan API: what a weirling's plan may be, and who may write one.

WHY THIS FILE EXISTS. `/api/weirlings/plan` and `/api/weirlings/apply` are the ONLY write path
that can put a remote sensor into the traffic path, and they are reached from a browser. Three
properties have to hold, and each is a defect if it breaks:

  * THE WRITE IS NO LOOSER THAN THE PREVIEW. Both steps validate through the same
    `fleet.plan_from_changes`, so a value the plan step refuses can never reach the store -- a
    preview that admits more than the write is theatre, and one that admits less trains the
    operator to ignore it;
  * THE LOCAL SENSOR IS REFUSED, WITH THE REASON. This hub's own sensor is configured through
    the Settings tab's ConfigMap; a registry plan for it would be a second source nothing reads
    (the silent-no-op family). The refusal names where the real control is;
  * AN UNDECLARED SENSOR HAS NOTHING A PLAN COULD BELONG TO. Registration is the declaration;
    a plan without one is a statement about a sensor nobody declared.

And the survey route's `sensor` form: it must survey the WEIRLING's port, resolve that port from
the sensor's own report rather than the hub's ConfigMap, and refuse -- naming the candidates --
when the answer is ambiguous. A confident survey of the wrong port is worse than no survey.

The routes are driven through the REAL handler (the recipe `tests/test_gui_users.py` uses),
against a duck-typed context and a stub ClickHouse client, so what is exercised is the shipping
route code, not a paraphrase of it.
"""
from __future__ import annotations

import contextlib
import datetime
import importlib
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime.datetime(2026, 10, 17, 12, 0, 0, tzinfo=datetime.UTC)

OPERATOR_TOKEN = "deploy-token"


# ── the stub ClickHouse client (registry rows in COLUMNS order, like the real store) ──────────

class _StubResult:
    def __init__(self, rows, cols):
        self.result_rows = rows
        self._cols = cols

    def named_results(self):
        for r in self.result_rows:
            yield dict(zip(self._cols, r, strict=False))


class _StubCh:
    def __init__(self, rows=None):
        self.rows = list(rows or [])
        self.inserted = []

    def query(self, sql, **_kw):
        from weirvern import fleet_store as store

        if "FROM weirvern.weirlings" in sql:
            rows = list(self.rows)
            # THE FILTER IS HONOURED, not ignored (the lesson test_fleet.py's stub records): a
            # stub that returns revoked rows for a `WHERE revoked_at IS NULL` query makes the
            # store look like it ignores its own filter, and the test then measures the stub.
            if "revoked_at IS NULL" in sql:
                rows = [r for r in rows if r[store.COLUMNS.index("revoked_at")] is None]
            return _StubResult(rows, store.COLUMNS)
        return _StubResult([], [])

    def insert(self, table, rows, column_names=None):  # noqa: ANN001
        from weirvern import fleet_store as store

        cols = column_names or store.COLUMNS
        for r in rows:
            self.inserted.append(dict(zip(cols, r, strict=False)))
            self.rows = [x for x in self.rows if x[0] != r[0]]
            self.rows.append(list(r))


def _row(sensor_id="unit-a", *, mode="loch", plan=None, address="", segment="", note="",
         revoked_at=None):
    from weirvern import fleet as fleet_mod

    plan = plan or {}
    return [sensor_id, address, segment, mode, 1, note, NOW, NOW, revoked_at,
            *[plan.get(f, "") for f in fleet_mod.PLAN_FIELDS]]


class _Handler:
    """Drives one route method of the real handler class with a faked transport."""

    def __init__(self, ctx, headers=None, body=None):
        web_mod = importlib.import_module("weirvern.admin.web")
        cls = web_mod._build_handler(ctx)  # noqa: SLF001 -- the shipping handler
        self.inst = cls.__new__(cls)
        self.inst.headers = dict(headers or {})
        if body is not None:
            self.inst.headers["Content-Length"] = str(len(body))
        self.inst.client_address = ("198.51.100.5", 1234)
        self.inst.rfile = _Body(body)
        self.emitted: dict = {}
        self.status: int | None = None
        self.inst._json = self._capture  # noqa: SLF001

    def _capture(self, payload, code=200):
        self.emitted = payload
        self.status = code

    def call(self, name, query=None):
        import inspect as _inspect

        fn = getattr(self.inst, name)
        params = [p for p in _inspect.signature(fn).parameters.values() if p.name != "self"]
        if params:
            fn(query or {})
        else:
            fn()
        return self.emitted


class _Body:
    def __init__(self, body):
        self._raw = (body or b"").encode() if isinstance(body, str) else (body or b"")

    def read(self, n=-1):  # noqa: ANN001
        return self._raw


class _Settings:
    sensor_name = "hub-sensor"
    clickhouse_password = "x"
    heartbeat_interval_s = 15


def _ctx(ch, settings=None):
    # Bound OUTSIDE the class body: a class body cannot see the enclosing function's scope, so
    # `settings = settings or ...` inside `_Ctx` would raise NameError on the right-hand side.
    _settings = settings or _Settings()

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
    return _Handler(ctx, headers={"X-Weirvern-Token": OPERATOR_TOKEN},
                    body=json.dumps(body)).call(route)


@pytest.fixture()
def unit_ch():
    """A registered unit with an empty plan, and a heartbeat-carrying report."""
    ch = _StubCh([_row("unit-a", mode="loch", segment="third floor")])
    return ch


# ── the plan step ────────────────────────────────────────────────────────────────────────────

def _hub_named(monkeypatch):
    """Pin THIS hub's sensor name the way the route resolves it (`_gate_sensor_name`, which
    reads the deployment's own identity, not the request)."""
    web_mod = importlib.import_module("weirvern.admin.web")
    monkeypatch.setattr(web_mod, "_gate_sensor_name", lambda: "hub-sensor")


def test_the_plan_step_REFUSES_the_hubs_own_sensor_and_says_where_its_control_is(monkeypatch,
                                                                                  unit_ch):
    """This hub's sensor is configured through the ConfigMap its worker reads; a registry plan
    for it would be a second source of truth that nothing reads."""
    _hub_named(monkeypatch)
    out = _post(_ctx(unit_ch), "_weirlings_plan", {"sensor_id": "hub-sensor",
                                                   "changes": {"mode": "siphon"}})
    assert out["ok"] is False
    assert "OWN sensor" in out["error"] and "Settings tab" in out["error"], out["error"]
    assert unit_ch.inserted == [], "a plan was written for this hub's own sensor"


def test_the_plan_step_REFUSES_an_undeclared_sensor(unit_ch):
    out = _post(_ctx(unit_ch), "_weirlings_plan", {"sensor_id": "unit-a",
                                                   "changes": {"mode": "siphon"}})
    # The fixture row IS registered, so this checks the other direction: an unknown id.
    out2 = _post(_ctx(unit_ch), "_weirlings_plan", {"sensor_id": "ghost",
                                                    "changes": {"mode": "siphon"}})
    assert out2["ok"] is False
    assert "no sensor named" in out2["error"] and "Adopt" in out2["error"], out2["error"]
    assert out["ok"] is True, "a registered sensor must be plannable"


def test_the_plan_step_REFUSES_a_sensor_with_no_LIVE_registration(unit_ch):
    """A plan needs a declaration to sit on. `plan_subject` is the seam: it reads the REGISTRY
    (typed), so a heartbeat with no registration row -- a sensor feeding the hub that nobody
    declared -- has nothing to target, and a REVOKED registration is the same case."""
    from weirvern import fleet_store

    empty = _StubCh()          # no registry rows at all
    out = _post(_ctx(empty), "_weirlings_plan", {"sensor_id": "unit-a",
                                                 "changes": {"mode": "siphon"}})
    assert out["ok"] is False and "Adopt it" in out["error"], out
    assert empty.inserted == []

    revoked = _StubCh([_row("unit-a", revoked_at=NOW)])
    out2 = _post(_ctx(revoked), "_weirlings_plan", {"sensor_id": "unit-a",
                                                    "changes": {"mode": "siphon"}})
    assert out2["ok"] is False and "Adopt it" in out2["error"], out2
    assert revoked.inserted == []
    assert fleet_store.plan_subject(empty, "unit-a")[1] != ""


def test_the_plan_step_validates_with_the_WRITE_paths_own_parser(unit_ch):
    """A preview that admits a value the write refuses is theatre; both go through
    `fleet.plan_from_changes`, so this refusal is the one the apply step would give."""
    out = _post(_ctx(unit_ch), "_weirlings_plan", {"sensor_id": "unit-a",
                                                   "changes": {"segment": "banana"}})
    assert out["ok"] is False and out["error"].startswith("segment"), out["error"]
    assert unit_ch.inserted == []


def test_the_plan_step_carries_the_IN_PATH_cost_on_the_mode_change(unit_ch):
    """The warning is what the browser's confirmation dialog exists for; a plan step that
    omitted it would let a one-click enable run with no blast-radius statement at all."""
    out = _post(_ctx(unit_ch), "_weirlings_plan", {
        "sensor_id": "unit-a",
        "changes": {"mode": "siphon", "segment": "198.51.100.0/24", "addr": "198.51.100.250",
                    "gateway": "198.51.100.1", "targets": "*"}})
    assert out["ok"] is True
    by_key = {p["key"]: p for p in out["proposals"]}
    assert "IN THE TRAFFIC PATH" in by_key["mode"]["warning"], by_key["mode"]
    joined = " ".join(out["warnings"])
    assert "IN-PATH" in joined, out["warnings"]
    assert "cannot arm yet" not in joined, (
        "a complete plan must not be reported as unable to arm")
    assert out["restart_targets"] == [], (
        "nothing on this hub restarts for another sensor's plan")
    assert "30 seconds" in out["note"]


def test_the_plan_step_says_what_is_still_MISSING_rather_than_refusing(unit_ch):
    """A half-filled plan is a legitimate state (stage the segment now, the address tomorrow):
    the sensor refuses to arm and its heartbeat says why, so the preview says it up front."""
    out = _post(_ctx(unit_ch), "_weirlings_plan", {
        "sensor_id": "unit-a", "changes": {"mode": "siphon", "segment": "198.51.100.0/24"}})
    assert out["ok"] is True
    joined = " ".join(out["warnings"])
    assert "cannot arm yet" in joined and "INTERCEPT_ADDR" in joined, out["warnings"]


def test_the_plan_step_REFUSES_an_unknown_field(unit_ch):
    out = _post(_ctx(unit_ch), "_weirlings_plan", {
        "sensor_id": "unit-a", "changes": {"intercept_segment": "198.51.100.0/24"}})
    assert out["ok"] is False and "unknown plan field" in out["error"], out


# ── the apply step ───────────────────────────────────────────────────────────────────────────

def test_the_apply_step_writes_the_plan_and_keeps_the_declaration_in_step(unit_ch):
    out = _post(_ctx(unit_ch), "_weirlings_apply", {
        "sensor_id": "unit-a",
        "changes": {"mode": "siphon", "iface": "eth2", "segment": "198.51.100.0/24",
                    "addr": "198.51.100.250", "gateway": "198.51.100.1", "targets": "*"}})
    assert out["ok"] is True and out["applied"]["mode"] == "siphon", out
    written = unit_ch.inserted[-1]
    assert written["plan_mode"] == "siphon" and written["plan_targets"] == "*"
    assert written["expected_mode"] == "siphon", (
        "the declaration the fleet view compares against must not disagree with the plan")
    assert written["segment"] == "third floor", (
        "a plan write must not blank what the operator declared about the sensor")


def test_the_apply_step_is_EXACTLY_as_strict_as_the_plan_step(unit_ch):
    out = _post(_ctx(unit_ch), "_weirlings_apply", {"sensor_id": "unit-a",
                                                    "changes": {"targets": "banana"}})
    assert out["ok"] is False and "neither an address" in out["error"], out
    assert unit_ch.inserted == [], "an invalid target list reached the store"


def test_the_apply_step_refuses_the_hubs_own_sensor_too(monkeypatch, unit_ch):
    _hub_named(monkeypatch)
    out = _post(_ctx(unit_ch), "_weirlings_apply", {"sensor_id": "hub-sensor",
                                                    "changes": {"mode": "siphon"}})
    assert out["ok"] is False and "OWN sensor" in out["error"]
    assert unit_ch.inserted == []


def test_both_write_routes_are_ADMIN_gated():
    """Read from the source the way `test_every_write_route_consults_A_GATE` reads it: the
    dispatch table must route to handlers that call `_authorize` before anything else."""
    src = (ROOT / "weirvern" / "admin" / "web.py").read_text()
    for route in ("_weirlings_plan", "_weirlings_apply"):
        body = src[src.index(f"        def {route}(self"):]
        body = body[:body.index("\n        def ", 10)]
        assert "self._authorize()" in body, f"{route} is not admin-gated"


# ── the survey's `sensor` form ───────────────────────────────────────────────────────────────

def test_a_survey_for_a_weirling_resolves_the_SENSORS_own_port(monkeypatch, unit_ch):
    """The plan's declared iface wins; the hub's ConfigMap is never consulted for it."""
    from weirvern.admin import sonar as sonar_mod

    unit_ch.rows = [_row("unit-a", plan={"iface": "eth2"})]
    seen = {}

    def fake_job(client, iface, mgmt_iface="", **kw):
        seen.update({"iface": iface, "mgmt": mgmt_iface})
        return {"ok": True, "interface": iface, "segment": "198.51.100.0/24",
                "recommended": {"intercept_segment": "198.51.100.0/24"}, "notes": []}

    monkeypatch.setattr(sonar_mod, "run_survey_job", fake_job)
    out = _post(_ctx(unit_ch), "_settings_sonar", {"sensor": "unit-a"})
    assert seen["iface"] == "eth2", seen
    assert out["sensor"] == "unit-a", (
        "the reply must say which sensor it surveyed, so it cannot be staged against another")


def test_a_survey_falls_back_to_the_sensors_single_reported_nic(monkeypatch, unit_ch):
    from weirvern import fleet_store
    from weirvern.admin import sonar as sonar_mod

    unit_ch.rows = [_row("unit-a")]
    original_hb = fleet_store.read_heartbeats
    try:
        monkeypatch.setattr(fleet_store, "read_heartbeats",
                            lambda client: ([{"sensor_id": "unit-a", "interfaces": ["eth3"]}], None))
        monkeypatch.setattr(sonar_mod, "run_survey_job",
                            lambda client, iface, mgmt_iface="", **kw: {"ok": True, "interface": iface})
        out = _post(_ctx(unit_ch), "_settings_sonar", {"sensor": "unit-a"})
    finally:
        fleet_store.read_heartbeats = original_hb
    assert out["interface"] == "eth3", out


def test_a_survey_REFUSES_to_guess_when_the_sensor_reports_several_nics(monkeypatch, unit_ch):
    """Surveying the wrong port produces a confident plan for a segment the sensor is not on."""
    from weirvern import fleet_store
    from weirvern.admin import sonar as sonar_mod

    called = []
    original_hb = fleet_store.read_heartbeats
    try:
        monkeypatch.setattr(fleet_store, "read_heartbeats",
                            lambda client: ([{"sensor_id": "unit-a",
                                              "interfaces": ["eth1", "eth2"]}], None))
        monkeypatch.setattr(sonar_mod, "run_survey_job",
                            lambda *a, **kw: called.append(a) or {"ok": True})
        out = _post(_ctx(unit_ch), "_settings_sonar", {"sensor": "unit-a"})
    finally:
        fleet_store.read_heartbeats = original_hb
    assert out["ok"] is False
    assert "eth1, eth2" in out["error"] and "name the capture interface" in out["error"], out
    assert called == [], "a job ran against a port nobody chose"


def test_a_survey_for_an_unknown_sensor_is_refused(unit_ch):
    out = _post(_ctx(unit_ch), "_settings_sonar", {"sensor": "ghost"})
    assert out["ok"] is False and "Adopt it" in out["error"], out
