"""Weirlings: the fleet registry and health classification.

WHAT THESE TESTS ARE FOR. The value of a fleet view is entirely in the distinctions it keeps
apart, because every state it can show needs a DIFFERENT action from the operator:

    alive        nothing to do
    stale        it ran and stopped -- look for why it died
    never_seen   it never came up -- look at the install, not the logs
    unregistered something is feeding this hub that nobody declared
    disabled     not reporting is EXPECTED, so raise nothing

Collapsing any pair produces a view that reads as good news while being wrong, which is this
project's most-named failure mode. So the tests below are mostly about the SEAMS: the pairs a
reasonable implementation would merge, and the specific wrong answer that merging produces.

`stale` vs `never_seen` is the pair most at risk. Both render as "no fresh heartbeat", and an
operator sent to a never-seen sensor's LOGS will find no logs, because it never wrote one.
"""

from __future__ import annotations

import datetime
from dataclasses import replace

import pytest

from weirvern import fleet
from weirvern.fleet import (
    HEARTBEAT_STALE_S,
    STATE_ALIVE,
    STATE_DISABLED,
    STATE_NEVER_SEEN,
    STATE_STALE,
    STATE_UNKNOWN,
    STATE_UNREGISTERED,
    FleetError,
    Registration,
    classify,
    make_registration,
    revoke,
    summarise,
    validate_address,
    validate_mode,
    validate_sensor_id,
)
from weirvern.fleet import (
    fleet as build_fleet,
)

NOW = datetime.datetime(2026, 9, 23, 12, 0, 0, tzinfo=datetime.UTC)


def hb(sensor_id: str, *, age_s: float = 0.0, mode: str = "loch", **kw) -> dict:
    """A heartbeat row as `sensor_status` returns it, aged by `age_s` seconds."""
    row = {
        "sensor_id": sensor_id,
        "mode": mode,
        "ts": NOW - datetime.timedelta(seconds=age_s),
        "iface": "ens19",
        "segment": "",
        "hosts": 0,
        "capture_loss_pct": None,
        "packets_recv": None,
        "packets_dropped": None,
    }
    row.update(kw)
    return row


def reg(sensor_id: str, **kw) -> Registration:
    return make_registration(sensor_id, now=NOW, **kw)


# ── the five states, one test each, so a merge of any pair is caught ─────────────────────────

def test_alive():
    h = classify(reg("edge-1"), [hb("edge-1", age_s=5)], now=NOW)
    assert h.state == STATE_ALIVE
    assert not h.is_problem


def test_stale_is_it_ran_and_stopped():
    """The sensor REPORTED and has aged out. Distinct from never_seen, and the finding has to
    say which, because the two send an operator to different places."""
    h = classify(reg("edge-1"), [hb("edge-1", age_s=HEARTBEAT_STALE_S + 60)], now=NOW)
    assert h.state == STATE_STALE
    assert h.is_problem
    text = " ".join(h.findings)
    assert "stopped" in text and "never" in text, (
        "the finding must distinguish 'ran and stopped' from 'never started', or the operator "
        "hunts for logs that do not exist"
    )


def test_never_seen_is_not_the_same_as_stale():
    """NO heartbeat at all. The pair most likely to be collapsed, and a merge here is the
    difference between checking an install and checking a log."""
    h = classify(reg("edge-1"), [], now=NOW)
    assert h.state == STATE_NEVER_SEEN
    assert h.is_problem
    assert h.last_seen is None
    assert h.age_s is None
    assert "never reported" in " ".join(h.findings)


def test_never_seen_in_path_says_the_segment_may_be_waiting():
    """An in-path sensor that never came up is more urgent than a passive one, and the view has
    to say WHY rather than showing them as the same state."""
    h = classify(reg("edge-1", expected_mode="siphon"), [], now=NOW)
    assert h.state == STATE_NEVER_SEEN
    joined = " ".join(h.findings).lower()
    assert "in-path" in joined or "in path" in joined


def test_a_STALE_unregistered_row_is_not_a_problem():
    """MEASURED on the live cluster: the fleet filled with `unregistered` rows that were STALE
    GHOSTS -- heartbeat rows written under a sensor identity that no longer exists (before the
    sensor-name fix that identity was the POD NAME, so every rollout left one behind). Counting
    those as problems is indistinguishable from a sensor feeding the hub RIGHT NOW that nobody
    declared, and the real one is the security-relevant case. The stale row stays VISIBLE; it
    just does not raise."""
    h = classify(None, [hb("old-pod-name", age_s=HEARTBEAT_STALE_S * 100)], now=NOW)
    assert h.state == STATE_UNREGISTERED, "the row must still be visible"
    assert h.is_problem is False, "a ghost is not actionable and must not raise"
    said = " ".join(h.findings).lower()
    # BOTH PHRASES, because "historical" alone is also carried by the later explanation clause, so
    # asserting only that word did not notice when the identifying sentence was replaced by a bare
    # "stopped" -- mutation testing caught that the assertion did not bite. This pins the sentence
    # that actually says WHAT happened (reported once, under a name, and stopped).
    assert "reported once under this name" in said, (
        "the finding must say the row is a single historical report, not imply an active sensor"
    )
    assert "nobody ever declared it" in said


def test_a_FRESH_unregistered_row_IS_a_problem():
    """The other half: something feeding the hub right now that nobody declared. This is the
    security-relevant case and it must raise."""
    h = classify(None, [hb("mystery-box", age_s=1)], now=NOW)
    assert h.state == STATE_UNREGISTERED
    assert h.is_problem is True
    assert "right now" in " ".join(h.findings).lower()


def test_unregistered_is_flagged_and_is_a_problem():
    """Something feeds this hub that nobody declared. Security-relevant: same class as an
    unexpected NetFlow exporter, and it must not render as a normal fleet row."""
    h = classify(None, [hb("mystery-box", age_s=1)], now=NOW)
    assert h.state == STATE_UNREGISTERED
    assert h.is_problem
    assert h.registered is False
    # The wording now distinguishes FRESH from stale, so it says "not registered" either way and
    # adds that it is feeding the hub right now. The FRESH/STALE split is pinned by the two tests
    # above; this one keeps the original claim (it raises, and it is not silent).
    assert "not registered" in " ".join(h.findings)


def test_disabled_is_not_a_problem():
    """A deliberately off sensor not reporting is the INTENDED outcome. Flagging it trains the
    reader to ignore the whole column, which is the one thing an alarm may never do."""
    h = classify(reg("edge-1", ), [hb("edge-1", age_s=HEARTBEAT_STALE_S + 999)], now=NOW)
    assert h.state == STATE_STALE
    r = Registration(**{**reg("edge-1").__dict__, "enabled": False})
    h2 = classify(r, [hb("edge-1", age_s=HEARTBEAT_STALE_S + 999)], now=NOW)
    assert h2.state == STATE_DISABLED
    assert not h2.is_problem


# ── the union: neither source alone can answer "what is my fleet doing" ──────────────────────

def test_fleet_includes_unregistered_sensors():
    """Iterating only registrations hides an undeclared sensor."""
    rows = build_fleet([reg("declared")], [hb("declared", age_s=1), hb("undeclared", age_s=1)],
                       now=NOW)
    ids = {h.sensor_id for h in rows}
    assert ids == {"declared", "undeclared"}
    states = {h.sensor_id: h.state for h in rows}
    assert states["declared"] == STATE_ALIVE
    assert states["undeclared"] == STATE_UNREGISTERED


def test_fleet_includes_never_seen_registrations():
    """Iterating only heartbeats hides a sensor that never came up -- the case a roll-out needs."""
    rows = build_fleet([reg("promised")], [], now=NOW)
    assert [h.sensor_id for h in rows] == ["promised"]
    assert rows[0].state == STATE_NEVER_SEEN


def test_problems_sort_first():
    """The view exists to surface trouble. On a fleet big enough to need one, the healthy
    majority would otherwise push the one broken sensor below the fold on every load.

    THE PROBLEM SENSOR IS NAMED `zz-broken` DELIBERATELY. The first version of this test named it
    `broken`, which sorts before `ok-0` anyway -- so it passed with the problem-first sort REMOVED
    and pinned nothing. Mutation testing caught it. A test whose expected order coincides with the
    default order cannot detect that the ordering is gone, so the name has to sort LAST for the
    assertion to mean anything.
    """
    regs = [reg(f"ok-{i}") for i in range(5)] + [reg("zz-broken")]
    heartbeats = [hb(f"ok-{i}", age_s=1) for i in range(5)]  # zz-broken never reports
    rows = build_fleet(regs, heartbeats, now=NOW)
    assert rows[0].sensor_id == "zz-broken", (
        "a problem must not sort below a healthy majority -- and this name sorts last by default, "
        "so passing here can only mean the problem-first rule is working"
    )
    assert rows[0].is_problem
    assert not any(h.is_problem for h in rows[1:])


def test_revoked_is_absent_from_the_fleet():
    """A sensor somebody removed must not reappear as a stale row on every refresh."""
    r = revoke(reg("retired"), now=NOW)
    rows = build_fleet([r], [hb("retired", age_s=HEARTBEAT_STALE_S * 10)], now=NOW)
    assert [h.sensor_id for h in rows] == ["retired"]
    # Its heartbeat remains, and nobody has declared it -- the truthful reading.
    assert rows[0].state == STATE_UNREGISTERED


# ── measured-zero vs not-measured ────────────────────────────────────────────────────────────

def test_capture_loss_none_is_not_zero():
    """NULL means NOT MEASURED. Coercing it to 0.0 reports a sensor that measured nothing as a
    perfect one, which no other field would reveal."""
    h = classify(reg("edge-1"), [hb("edge-1", age_s=1, capture_loss_pct=None)], now=NOW)
    assert h.capture_loss_pct is None
    assert "unknown rather than zero" in " ".join(h.findings).lower()


def test_an_unmeasured_capture_loss_never_becomes_zero_in_the_payload():
    """The FIELD assertion above is not enough: a renderer or a store could coerce on the way out
    while the dataclass stays honest. The mutation `capture_loss_pct or 0.0` is exactly that bug,
    and it survived the first version of these tests."""
    from weirvern import fleet_store
    h = classify(reg("edge-1"), [hb("edge-1", age_s=1, capture_loss_pct=None)], now=NOW)
    row = fleet_store._health_to_json(h)
    assert row["capture_loss_pct"] is None, (
        "an unmeasured capture loss must reach the payload as null, never as 0.0, which would "
        "report a sensor that has measured nothing as a perfect one"
    )


def test_capture_loss_zero_is_a_real_measurement_and_says_nothing():
    """0.0 is "measured, nothing lost" -- a good result, and NOT the same as unmeasured."""
    h = classify(reg("edge-1"), [hb("edge-1", age_s=1, capture_loss_pct=0.0)], now=NOW)
    assert h.capture_loss_pct == 0.0
    assert not any("unknown" in f for f in h.findings)


def test_high_capture_loss_is_called_out():
    h = classify(reg("edge-1"), [hb("edge-1", age_s=1, capture_loss_pct=62.5)], now=NOW)
    assert any("capture loss" in f.lower() for f in h.findings)
    assert any("62.5" in f for f in h.findings)


# ── one reading of one dataset: the shared ranking rule ──────────────────────────────────────

def test_siphon_row_wins_over_a_fresher_loch_row():
    """A sensor intercepting has TWO live rows. The intercepting one describes the same sensor
    in a strictly more informative state, so it must win even when it is older -- otherwise the
    view alternates between them on every refresh, which is a bug this project already fixed in
    `sensor_status`. Using the shared rule is what keeps the two readers agreeing."""
    rows = [hb("edge-1", age_s=0, mode="loch"), hb("edge-1", age_s=30, mode="siphon",
                                                   segment="third-floor", hosts=7)]
    h = classify(reg("edge-1", expected_mode="siphon"), rows, now=NOW)
    assert h.reported_mode == "siphon"
    # The OBSERVED segment, kept apart from the declared one: a sensor covering the wrong
    # segment must not look correctly placed just because someone declared it correctly.
    assert h.reported_segment == "third-floor"


def test_a_stale_row_never_beats_a_fresh_one():
    rows = [hb("edge-1", age_s=HEARTBEAT_STALE_S * 5, mode="siphon"),
            hb("edge-1", age_s=1, mode="loch")]
    h = classify(reg("edge-1"), rows, now=NOW)
    assert h.reported_mode == "loch"
    assert h.state == STATE_ALIVE


def test_reported_mode_disagreeing_with_registration_is_surfaced():
    h = classify(reg("edge-1", expected_mode="loch"),
                 [hb("edge-1", age_s=1, mode="siphon")], now=NOW)
    joined = " ".join(h.findings)
    assert "declared" in joined.lower() and "observed" in joined.lower()


# ── validation: refuse, never sanitise ───────────────────────────────────────────────────────

@pytest.mark.parametrize("bad", ["", "   ", "-leading", "has space", "slash/name", "a" * 64,
                                 "semi;colon", "quote'name"])
def test_bad_sensor_ids_are_refused(bad):
    """Refused rather than rewritten: quietly sanitising means the sensor registers under a name
    the operator did not choose, and their lookup for what they typed finds nothing -- which
    reads as 'it never checked in'."""
    with pytest.raises(FleetError):
        validate_sensor_id(bad)


@pytest.mark.parametrize("good", ["edge-1", "sensor_2", "a", "floor3.idf-b", "A1"])
def test_good_sensor_ids_pass(good):
    assert validate_sensor_id(good) == good


def test_empty_address_is_allowed_and_means_unknown():
    """An operator usually does not know the address at registration time. "" must stay distinct
    from a real address, because the unregistered check compares addresses."""
    assert validate_address("") == ""
    assert validate_address("   ") == ""


def test_a_cidr_is_refused_rather_than_narrowed():
    """Guessing (taking the network address, dropping the prefix) would register a sensor at an
    address it does not have."""
    with pytest.raises(FleetError) as e:
        validate_address("192.0.2.0/24")
    assert "not a network" in str(e.value)


def test_a_bad_address_is_refused():
    with pytest.raises(FleetError):
        validate_address("not-an-ip")


def test_unknown_mode_is_refused():
    """An unknown mode would silently downgrade an in-path sensor to the harmless case, so a
    never-seen in-path sensor would stop being reported as urgent."""
    with pytest.raises(FleetError):
        validate_mode("auto")
    assert validate_mode("SIPHON") == "siphon"


def test_ipv6_address_is_accepted_and_normalised():
    assert validate_address("2001:db8::1") == "2001:db8::1"


# ── timestamps: unreadable is not fresh ──────────────────────────────────────────────────────

def test_unreadable_timestamp_is_not_alive():
    """A heartbeat whose timestamp cannot be read must not be reported as fresh. It is also not
    provably stale -- the honest state is 'not fresh', with the real reason stated."""
    h = classify(reg("edge-1"), [{"sensor_id": "edge-1", "mode": "loch", "ts": None}], now=NOW)
    assert h.state == STATE_STALE
    assert "could not be read" in " ".join(h.findings)


def test_naive_timestamp_does_not_raise():
    """ClickHouse returns aware datetimes but a fixture or a hand-written row may not be. This
    is the naive/aware defect this project hit once already, so it is pinned here too."""
    naive = (NOW - datetime.timedelta(seconds=2)).replace(tzinfo=None)
    h = classify(reg("edge-1"), [{"sensor_id": "edge-1", "mode": "loch", "ts": naive}], now=NOW)
    assert h.state == STATE_ALIVE
    assert h.age_s is not None and 1.0 <= h.age_s <= 3.0


def test_a_future_timestamp_does_not_produce_negative_age():
    """Clock skew is real. A negative age would render as a sensor that reported before it was
    asked, and sorted as the freshest thing in the fleet."""
    future = NOW + datetime.timedelta(seconds=300)
    h = classify(reg("edge-1"), [{"sensor_id": "edge-1", "mode": "loch", "ts": future}], now=NOW)
    assert h.age_s == 0.0


# ── the summary distinguishes an empty fleet from an unmeasured one ───────────────────────────

def test_summary_counts_are_zero_for_an_empty_fleet():
    s = summarise([])
    assert s["total"] == 0 and s["problems"] == 0
    assert all(s[k] == 0 for k in (STATE_ALIVE, STATE_STALE, STATE_NEVER_SEEN,
                                   STATE_UNREGISTERED, STATE_DISABLED))


def test_summary_counts_each_state():
    rows = build_fleet(
        [reg("a"), reg("b"), reg("c", expected_mode="siphon")],
        [hb("a", age_s=1), hb("b", age_s=HEARTBEAT_STALE_S * 4), hb("ghost", age_s=1)],
        now=NOW)
    s = summarise(rows)
    assert s["total"] == 4
    assert s[STATE_ALIVE] == 1
    assert s[STATE_STALE] == 1
    assert s[STATE_NEVER_SEEN] == 1   # 'c' never reported
    assert s[STATE_UNREGISTERED] == 1  # 'ghost'
    assert s["problems"] == 3
    assert s["registered"] == 3


# ── the modules must not drift apart on the one number they share ────────────────────────────

def test_the_staleness_threshold_is_imported_not_redeclared():
    """A second threshold would let the fleet view call a sensor dead while the sensor panel
    called it alive, with no way for an operator to tell which is lying."""
    from weirvern.admin import status as status_mod
    assert fleet.HEARTBEAT_STALE_S is status_mod.HEARTBEAT_STALE_S


def test_the_ranking_rule_is_shared_with_status():
    """Same defect class: two readers of one table answering differently."""
    from weirvern.admin import status as status_mod
    assert fleet.best_sensor_row is status_mod.best_sensor_row


# ── the store's envelope: an outage must never render as an empty fleet ───────────────────────
#
# THE DEFECT CLASS THESE PIN. A fleet view is a comparison against a declared expectation, so
# "I cannot read the registry" and "you have no sensors" are OPPOSITE facts needing opposite
# actions: one is an outage, the other is a fresh install. Both render as a calm empty table. The
# envelope is what carries the difference to the DOM, and mutation testing showed the first
# version of these tests did not notice when the envelope was wrong.

class _StubResult:
    def __init__(self, rows):
        self._rows = rows

    def named_results(self):
        return iter(self._rows)


class _StubClient:
    """A ClickHouse client that answers queries from a dict and HONOURS the WHERE clause.

    THE FIRST VERSION OF THIS STUB IGNORED ITS OWN QUERY and returned every row for a table
    whatever the SQL asked for. That made `read_registrations` appear to return a revoked
    registration when its `WHERE revoked_at IS NULL` filter was working perfectly -- a test
    failing for a reason that had nothing to do with the code under test, which is the same
    defect as a stub that answers with data the caller never sent. The filter is implemented
    here so the test measures the store rather than the stub.

    `fail_on` raises only for queries mentioning a given table, because "the heartbeat read
    failed while the registry read worked" is a specific state the fleet view must handle, and
    a client that fails every query cannot express it.
    """

    def __init__(self, rows_by_table=None, fail=False, fail_on=()):
        self.rows_by_table = rows_by_table or {}
        self.fail = fail
        self.fail_on = tuple(fail_on)

    def query(self, sql, *a, **kw):
        if self.fail or any(t in sql for t in self.fail_on):
            raise RuntimeError("ClickHouse is unreachable")
        for table, rows in self.rows_by_table.items():
            if table not in sql:
                continue
            out = list(rows)
            # The one filter these tests exercise. Applied rather than ignored, so the assertion
            # below is about the store's SQL and not about this helper being permissive.
            if "revoked_at IS NULL" in sql:
                out = [r for r in out if r.get("revoked_at") is None]
            return _StubResult(out)
        return _StubResult([])

    def insert(self, *a, **kw):
        return None


def test_a_registry_read_failure_is_reported_as_unavailable_not_empty():
    """THE MOST IMPORTANT ENVELOPE CASE. If a broken registry reads as an empty fleet, the view
    shows a calm, healthy, empty table during an outage -- and the operator concludes they have
    no sensors rather than that they cannot see them."""
    from weirvern import fleet_store
    payload = fleet_store.build_fleet(_StubClient(fail=True))
    assert payload["available"] is False
    assert payload["reason"], "an unavailable fleet must carry a reason, or the blank renders as calm"
    assert payload["sensors"] == []


def test_a_heartbeat_read_failure_degrades_but_still_shows_the_fleet():
    """The registry is what the view is built on, so the tab degrades rather than erroring and says
    so, or a healthy-looking panel would be mistaken for a complete one.

    ── BUT THE ROWS MUST NOT CLAIM A STATE THE HEARTBEAT CANNOT SUPPORT (glm-5.3 review) ─────────

    This test used to assert `state == never_seen`, which pinned the defect: with the registry
    readable and the heartbeat read FAILED, every registered sensor was classified `never_seen` with
    the finding "Check that it can reach this hub and that its flow exporter points at the hub's
    collector" -- a PROBLEM state, counted in the summary. So a hub-side fault was reported as a
    problem with every remote sensor's INSTALL, and the operator's next action is to go and check
    sensors that are working fine.

    The distinction is now carried instead of discarded: the state is `unknown`, and `unknown` is
    deliberately NOT a problem state, because the fix is on the hub rather than on the sensor.
    """
    from weirvern import fleet_store
    rows = [{"sensor_id": "edge-1", "address": "", "segment": "", "expected_mode": "loch",
             "enabled": 1, "note": "", "added_at": NOW, "updated_at": NOW, "revoked_at": None}]
    client = _StubClient({"weirlings": rows}, fail_on=("sensor_status",))
    payload = fleet_store.build_fleet(client)
    assert payload["available"] is True
    assert payload["heartbeats_available"] is False
    assert payload["heartbeat_reason"], "the degraded state must be stated, not implied"
    assert [s["sensor_id"] for s in payload["sensors"]] == ["edge-1"]

    s = payload["sensors"][0]
    assert s["state"] == STATE_UNKNOWN, (
        f"a failed heartbeat read classified this sensor as {s['state']!r}. Every state except "
        f"`unknown` is a CLAIM, and the hub has no evidence for one -- so it must not send the "
        f"operator to check a sensor's install over a hub-side read failure"
    )
    assert s["is_problem"] is False, (
        "an unreadable heartbeat was counted as a problem with the sensor. `is_problem` means 'a "
        "human should look at this', and the action it implies (check the sensor's install) is the "
        "wrong action for a hub fault"
    )
    joined = " ".join(s["findings"])
    assert "cannot be read" in joined, (
        f"the row must say what is unknown and why. findings: {s['findings']}"
    )
    assert payload["heartbeat_reason"] in joined, (
        f"the reason must reach the row, not only the envelope. findings: {s['findings']}"
    )


def test_an_unmeasured_count_never_reaches_the_payload_as_zero():
    """Same rule as capture loss, applied to the packet counters: NULL must survive to the JSON
    as null, because 0 packets from a sensor receiving millions reads as a broken sensor."""
    from weirvern import fleet_store
    h = classify(reg("edge-1"), [hb("edge-1", age_s=1)], now=NOW)
    row = fleet_store._health_to_json(h)
    assert row["packets_recv"] is None
    assert row["packets_dropped"] is None
    assert row["capture_loss_pct"] is None


def test_a_measured_zero_count_does_reach_the_payload_as_zero():
    """The other half: 0 IS a measurement when the sensor actually reported it, and collapsing
    that into null would hide a real reading."""
    from weirvern import fleet_store
    h = classify(reg("edge-1"), [hb("edge-1", age_s=1, packets_recv=0, packets_dropped=0,
                                    capture_loss_pct=0.0)], now=NOW)
    row = fleet_store._health_to_json(h)
    assert row["packets_recv"] == 0
    assert row["capture_loss_pct"] == 0.0


def test_the_payload_carries_every_key_the_renderer_reads():
    """A renderer reads its rows by FIELD NAME, and a missing key kills the whole panel at the
    first formatter call rather than degrading one row. Pinned against the real payload, not a
    fixture invented beside the renderer."""
    from weirvern import fleet_store
    h = classify(reg("edge-1"), [hb("edge-1", age_s=1)], now=NOW)
    row = fleet_store._health_to_json(h)
    for key in ("sensor_id", "state", "is_problem", "address", "segment", "reported_segment",
                "expected_mode", "reported_mode", "enabled", "registered", "age_s", "last_seen",
                "capture_loss_pct", "packets_recv", "packets_dropped", "hosts", "note",
                "findings", "stale_after_s"):
        assert key in row, f"the payload is missing {key!r}, which the renderer reads"


def test_revoked_registrations_are_hidden_but_still_readable_for_audit():
    """"Was this ever covered?" must survive the cleanup, so a revoked registration is excluded
    from the fleet view but still readable."""
    from weirvern import fleet_store
    rows = [{"sensor_id": "retired", "address": "", "segment": "", "expected_mode": "loch",
             "enabled": 0, "note": "", "added_at": NOW, "updated_at": NOW,
             "revoked_at": NOW}]
    client = _StubClient({"weirlings": rows})
    assert fleet_store.read_registrations(client) == []
    kept = fleet_store.read_registrations(client, include_revoked=True)
    assert [r.sensor_id for r in kept] == ["retired"]
    assert kept[0].revoked_at is not None


def test_the_summary_PUBLISHES_the_unknown_count_even_when_it_is_zero():
    """A count that is invisible in the header is how "we could not read this" would silently look
    like "nothing to report".

    `counts[h.state] = counts.get(h.state, 0) + 1` CREATES the key the moment a sensor has that
    state, so a nonzero tallies correctly whether or not the state is named in the initialiser --
    which is why my first version of this test passed with the named entry deleted. The named entry's
    real and only job is publishing the key when NOTHING has that state, which is what lets a reader
    tell "no sensor is in this state" from "this build does not have this state at all".
    """
    from weirvern.fleet import STATE_UNKNOWN as U

    healthy = classify(reg("edge-1"), [hb("edge-1", age_s=1)], now=NOW)
    assert healthy.state != U
    s = summarise([healthy])
    assert U in s, (
        f"the summary does not publish {U!r} when no sensor is in that state, so a dashboard cannot "
        f"distinguish 'nothing could not be read' from 'this build has no such state'. keys: "
        f"{sorted(s)}"
    )
    assert s[U] == 0, s

    # And it still tallies when one IS in that state.
    broken = classify(reg("edge-2"), [hb("edge-2", age_s=1)], now=NOW)
    broken.state = U
    s2 = summarise([healthy, broken])
    assert s2[U] == 1, s2


# ── THE TAB SHOWS AN UNADOPTED WEIRLING ONLY WHILE IT IS TALKING ───────────────────────────────
#
# `sensor_status` keeps seven days of heartbeats, so a sensor identity that stopped -- a pod name
# from an earlier rollout, a decommissioned unit -- keeps producing `unregistered` rows long after
# anything is on the wire. They cannot be adopted (the sensor that wrote them is gone) and they
# bury the one undeclared row that IS feeding the hub. The operator's rule (2026-10-18): an
# unadopted weirling appears in the tab only while it is online and still talking.
#
# The filter lives in `build_fleet` (the VIEW payload), not in `fleet()` (the semantics), so the
# classification tests above keep pinning what an unregistered row MEANS while this pins what the
# tab SHOWS. The distinction matters: `fleet()` still returns the ghost with its state, which is
# what makes the rule testable in one place and honest in the other.


def test_the_fleet_payload_HIDES_an_undeclared_sensor_that_stopped_talking():
    """The live defect: a stale `Weirvern` identity (78,403s old) sat in the list beside the two
    sensors that were actually feeding the hub, and there was nothing an operator could do with it.
    """
    from weirvern import fleet_store

    client = _StubClient({"sensor_status": [hb("gone-box", age_s=HEARTBEAT_STALE_S * 20)]})
    payload = fleet_store.build_fleet(client, now=NOW)

    assert payload["available"] is True
    assert payload["sensors"] == [], (
        f"a stale undeclared sensor is still in the tab: "
        f"{[s['sensor_id'] for s in payload['sensors']]}"
    )
    assert payload["summary"]["total"] == 0, payload["summary"]
    assert payload["summary"]["unregistered"] == 0, (
        f"the header still counts the hidden ghost, so the count and the rows disagree: "
        f"{payload['summary']}"
    )


def test_the_fleet_payload_KEEPS_an_undeclared_sensor_that_is_still_talking():
    """The row the tab exists for: something is feeding the hub and nobody declared it."""
    from weirvern import fleet_store

    client = _StubClient({"sensor_status": [hb("live-undeclared", age_s=1)]})
    payload = fleet_store.build_fleet(client, now=NOW)

    ids = [s["sensor_id"] for s in payload["sensors"]]
    assert ids == ["live-undeclared"], ids
    row = payload["sensors"][0]
    assert row["state"] == STATE_UNREGISTERED, row["state"]
    assert row["is_problem"] is True, "a fresh undeclared sensor must still ask for a decision"
    assert payload["summary"]["unregistered"] == 1, payload["summary"]


def test_the_hide_rule_does_not_touch_a_REGISTERED_sensor_that_went_quiet():
    """Only UNADOPTED rows are filtered. A declared sensor going quiet is the `stale` state, whose
    whole job is to tell the operator it ran and stopped -- hiding it would delete that answer.
    """
    from weirvern import fleet_store

    client = _StubClient({
        "weirlings": [{"sensor_id": "edge-quiet", "address": "", "segment": "",
                       "expected_mode": "loch", "enabled": 1, "note": "",
                       "added_at": NOW, "updated_at": NOW, "revoked_at": None}],
        "sensor_status": [hb("edge-quiet", age_s=HEARTBEAT_STALE_S * 20)],
    })
    payload = fleet_store.build_fleet(client, now=NOW)

    ids = [s["sensor_id"] for s in payload["sensors"]]
    assert ids == ["edge-quiet"], f"a registered stale sensor was hidden: {ids}"
    assert payload["sensors"][0]["state"] == STATE_STALE, payload["sensors"][0]["state"]


def test_revoking_clears_the_plan_so_a_readded_sensor_starts_clean():
    """The row survives; the settings do not.

    A revoked registration kept its per-NIC plan, so removing a sensor and adopting it again
    brought back the exact plan the operator was trying to clear. Revocation is the boundary:
    history stays, configuration goes.
    """
    from weirvern.fleet import SensorPlan

    signed = make_registration("edge-clean", segment="198.51.100.0/24",
                               expected_mode="siphon", now=NOW)
    signed = replace(signed, plan=SensorPlan(
        mode="siphon", iface="eth1", segment="198.51.100.0/24",
        addr="198.51.100.10", gateway="198.51.100.1", targets="*",
        nics='{"eth1":{"siphon":true,"segment":"198.51.100.0/24",'
             '"addr":"198.51.100.10","gateway":"198.51.100.1"}}'))
    out = revoke(signed, now=NOW)
    assert out.revoked_at == NOW and out.enabled is False
    assert not out.plan.configured
    assert out.plan.nics == ""
    assert out.plan.as_dict() == {f: "" for f in ("mode", "iface", "segment", "addr",
                                                  "gateway", "targets")}


def test_the_summary_counts_each_collected_network_once_not_each_nic():
    """Networks is a coverage count, not a NIC count.

    Two sensors whose NICs sit on the same subnet are collecting one network; two NICs on
    different subnets are two. Blank segments are not a network, and a malformed per-NIC plan
    must not make the whole summary unavailable.
    """
    from weirvern.fleet import SensorHealth, SensorPlan, summarise

    a = SensorHealth(sensor_id="a", state=STATE_ALIVE, segment="198.51.100.0/24",
                     plan=SensorPlan(nics='{"eth1": {"segment": "198.51.100.0/24"},'
                                           '"eth2": {"segment": "192.0.2.0/24"}}'))
    b = SensorHealth(sensor_id="b", state=STATE_ALIVE,
                     reported_segment="198.51.100.0/24")
    c = SensorHealth(sensor_id="c", state=STATE_ALIVE,
                     plan=SensorPlan(nics="not json"))
    out = summarise([a, b, c])
    assert out["networks"] == 2, out
    assert out["total"] == 3 and out["problems"] == 0
