"""Ripple signature normalization: one exact value, one host, one channel, until a review date.

WHY THIS FILE EXISTS. A signature is the narrowest claim in the product, and the safety of the
feature is entirely in what it REFUSES: it must be impossible to normalize a family, a channel
across hosts, a host across channels, or a host forever. Every refusal below is behavioural --
it drives the storage API or the HTTP route -- because a docstring saying "one value only" is not
a property.

The measurement tests use a fake that executes the SQL shape the module actually builds and
applies the exclusion only when the generated query carries the predicate. They assert what the
operator can see: the normalized value stops producing evidence for THAT host, the same value on
another host still ripples, a different value on the same channel still ripples, removal and
expiry bring the evidence back, and the raw event population is untouched.
"""
from __future__ import annotations

import ipaddress
import pathlib
import re
from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace

import pytest

from tests.support_routes import _Ctx
from weirvern import ripple_signatures
from weirvern.admin import flask_app
from weirvern.admin import users as users_mod
from weirvern.models import ripple_evidence

NOW = datetime(2026, 11, 20, 14, 0, tzinfo=UTC)
HOST = "198.51.100.10"
OTHER = "198.51.100.11"
EXTERNAL = "203.0.113.9"
NET = "198.51.100.0/24"
TODAY = NOW.date()

_ANCHOR = re.compile(r"intDiv\((\d+) - toUnixTimestamp")
_BUCKET = re.compile(r", (\d+)\) AS k")
_SINCE = re.compile(r">= '([^']+)'")
_UNTIL = re.compile(r"< '([^']+)'")


def _parse(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)


def _sig(*, host: str = HOST, channel: str = "http_ua_novelty", value: str,
         review_after: date | str = date(2027, 2, 18), removed_at=None, sid: str = "s1",
         reason: str = "the new appliance", created_by: str = "sam") -> dict:
    return {"id": sid, "host_addr": host, "channel": channel, "family": "http",
            "value": value, "created_at": datetime(2026, 11, 20, 9, 0, tzinfo=UTC),
            "created_by": created_by, "reason": reason, "review_after": review_after,
            "removed_at": removed_at, "removed_by": "sam" if removed_at else "",
            "removed_reason": "", "updated_at": datetime(2026, 11, 20, 9, 0, tzinfo=UTC)}


class FakeClient:
    """A tiny event store that executes the module's SQL shape, not a fixed row list.

    The signature predicate is honoured only when the generated SQL actually carries it (the
    host and value literals), so a bug that forgets to pass the filter to a channel cannot be
    masked by the fixture: the query would simply return the unfiltered population.
    """

    def __init__(self, events: dict[str, list[tuple]] | None = None,
                 *, signatures: list[dict] | None = None,
                 scopes: tuple[str, ...] = (NET,)):
        self.events = events or {}
        self.signatures = signatures or []
        self.scopes = list(scopes)
        self.queries: list[str] = []
        self.inserts: list[tuple[str, list[dict]]] = []

    # ── the signature store ──────────────────────────────────────────────────────────────────
    def _signature_rows(self, sql: str) -> list[dict]:
        rows = list(self.signatures)
        # ReplacingMergeTree(updated_at) ORDER BY (host_addr, channel, id): newest write wins.
        latest: dict[str, dict] = {}
        for row in rows:
            held = latest.get(row["id"])
            if held is None or row["updated_at"] >= held["updated_at"]:
                latest[row["id"]] = row
        live = list(latest.values())
        if "removed_at IS NULL" in sql:
            live = [row for row in live if not row.get("removed_at")]
        match = re.search(r"review_after >= toDate\('([^']+)'\)", sql)
        if match:
            day = date.fromisoformat(match.group(1))
            live = [row for row in live if _as_date(row["review_after"]) >= day]
        return live

    @staticmethod
    def _columns(sql: str) -> list[str]:
        body = sql.split("SELECT ", 1)[1].split(" FROM ", 1)[0]
        return [part.strip() for part in body.split(",")]

    # ── the query surface ────────────────────────────────────────────────────────────────────
    def query(self, sql: str, parameters=None):
        self.queries.append(sql)
        if "weirvern.normal_ripple_signatures" in sql:
            rows = self._signature_rows(sql)
            cols = self._columns(sql)
            return SimpleNamespace(column_names=cols,
                                   result_rows=[[row.get(col) for col in cols] for row in rows])
        if "weirvern.network_scopes" in sql:
            return SimpleNamespace(result_rows=[(cidr,) for cidr in self.scopes])
        if "system.columns" in sql:
            return SimpleNamespace(result_rows=[])
        if "system.tables" in sql:
            return SimpleNamespace(result_rows=[])
        table = next((name for name in self.events if name in sql), None)
        if table is None:
            return SimpleNamespace(result_rows=[])
        return SimpleNamespace(result_rows=self._execute(table, sql))

    def insert(self, table, rows, column_names=None):
        self.inserts.append((table, [dict(zip(column_names or [], row, strict=False))
                                     for row in rows]))

    # ── the event arithmetic ─────────────────────────────────────────────────────────────────
    def _execute(self, table: str, sql: str) -> list[tuple]:
        anchor_match = _ANCHOR.search(sql)
        bucket_match = _BUCKET.search(sql)
        since_match = _SINCE.search(sql)
        until_match = _UNTIL.search(sql)
        if not (anchor_match and bucket_match and since_match and until_match):
            return []
        anchor = int(anchor_match.group(1))
        bucket_s = int(bucket_match.group(1))
        since, until = _parse(since_match.group(1)), _parse(until_match.group(1))
        scopes = [ipaddress.ip_network(cidr) for cidr in dict.fromkeys(
            re.findall(r"isIPAddressInRange\([^,]+,\s*'([^']+)'\)", sql))]
        has_peer = "isIPAddressInRange(dst_addr" in sql
        distinct = "uniqExact" in sql or "uniqMerge" in sql
        values_mode = " AS v " in sql
        exclusion = self._active_exclusions(sql)

        buckets: dict[tuple[str, int], tuple[int, set[str], float]] = {}
        value_buckets: dict[tuple[str, int], set[str]] = {}
        for src, dst, when, value, nbytes in self.events[table]:
            if not (since <= when < until):
                continue
            subject = (src if _in_scope(src, scopes) else
                       dst if has_peer and _in_scope(dst, scopes) else "")
            if not subject:
                continue
            if (subject, value) in exclusion:
                continue
            index = (anchor - int(when.timestamp())) // bucket_s
            if index < 0:
                continue
            if values_mode:
                value_buckets.setdefault((subject, index), set()).add(value)
                continue
            n, seen, total = buckets.get((subject, index), (0, set(), 0.0))
            if distinct:
                seen = seen | {value}
            buckets[(subject, index)] = (n + 1, seen, total + float(nbytes))
        if values_mode:
            return [(host, index, value) for (host, index), values
                    in sorted(value_buckets.items()) for value in sorted(values)]
        return [(host, index, n, len(seen) if distinct else 0, total)
                for (host, index), (n, seen, total) in sorted(buckets.items())]

    def _active_exclusions(self, sql: str) -> set[tuple[str, str]]:
        """The signatures the SQL itself excludes. No predicate in the SQL => no exclusion."""
        out: set[tuple[str, str]] = set()
        for row in self.signatures:
            if row.get("removed_at"):
                continue
            if f"= '{row['host_addr']}'" in sql and f"'{row['value']}'" in sql:
                out.add((row["host_addr"], row["value"]))
        return out


def _in_scope(addr: str, scopes: list) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in scopes if net.version == ip.version)


def _as_date(value) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    return date.fromisoformat(str(value)[:10])


def _http_series(*, hosts: tuple[str, ...] = (HOST,), extra: dict[str, list[str]] | None = None,
                 hours: int = 168, base: int = 6) -> list[tuple]:
    """One week of hourly UA sets per host; the current bucket may add values."""
    extra = extra or {}
    events: list[tuple] = []
    for host in hosts:
        for index in range(hours):
            when = NOW - timedelta(hours=index, minutes=30)
            for slot in range(base):
                events.append((host, EXTERNAL, when + timedelta(seconds=slot),
                               f"ua-{slot}", 100.0))
            for slot, value in enumerate(extra.get(host, []) if index == 0 else []):
                events.append((host, EXTERNAL, when + timedelta(seconds=30 + slot), value, 100.0))
    return events


def _tls_series(*, host: str = HOST, new_pair: str = "new.example|ja4new",
                hours: int = 168, base: int = 6) -> list[tuple]:
    events: list[tuple] = []
    for index in range(hours):
        when = NOW - timedelta(hours=index, minutes=30)
        for slot in range(base):
            events.append((host, EXTERNAL, when + timedelta(seconds=slot),
                           f"pair-{slot}", 100.0))
        if index == 0:
            events.append((host, EXTERNAL, when + timedelta(seconds=45), new_pair, 100.0))
    return events


def _channel(items: list, channel: str, host: str = HOST, scale: str = "1h"):
    return [item for item in items
            if item.channel == channel and item.host == host and item.scale == scale]


def _significant(items: list) -> list:
    """The rows that could contribute to a ripple. A normalized value leaves a QUIET row, not
    an absent one: the layer's contract is that "measured and quiet" (p=1) is different from
    "not measured" (no row), and a signature must not turn the former into the latter."""
    return [item for item in items if item.pvalue <= ripple_evidence.DEFAULT_FAMILY_MAX_P]


# ── the claim is exactly one host, one channel, one value ────────────────────────────────────

def test_a_signature_is_one_host_one_channel_one_exact_value():
    channels = {spec.channel: spec.family for spec in ripple_evidence.SPECS}
    row = ripple_signatures.new_signature(
        host=HOST, channel="tls_fingerprint_diversity", value="appliance.example|ja4abc",
        reason="the new backup appliance", channels=channels, actor="sam", today=TODAY)
    assert row["host_addr"] == HOST
    assert row["channel"] == "tls_fingerprint_diversity"
    assert row["family"] == "tls"          # derived from the spec, never supplied by the caller
    assert row["value"] == "appliance.example|ja4abc"
    assert row["created_by"] == "sam"
    assert row["reason"] == "the new backup appliance"
    assert row["review_after"] == TODAY + timedelta(days=90)
    assert row["removed_at"] is None


def test_a_network_a_family_or_an_empty_value_is_not_a_signature():
    channels = {spec.channel: spec.family for spec in ripple_evidence.SPECS}
    with pytest.raises(ValueError, match="one host address"):
        ripple_signatures.new_signature(host="198.51.100.0/24", channel="tls_fingerprint_diversity",
                                        value="x", reason="r", channels=channels)
    with pytest.raises(ValueError, match="one host address"):
        ripple_signatures.new_signature(host="appliance.example", channel="tls_fingerprint_diversity",
                                        value="x", reason="r", channels=channels)
    # A FAMILY IS NOT A CHANNEL. `tls` names three channels; accepting it would be a family-wide
    # claim the store has no column to express.
    with pytest.raises(ValueError, match="not a channel"):
        ripple_signatures.new_signature(host=HOST, channel="tls", value="x", reason="r",
                                        channels=channels)
    with pytest.raises(ValueError, match="one exact value"):
        ripple_signatures.new_signature(host=HOST, channel="http_ua_novelty", value="  ",
                                        reason="r", channels=channels)
    with pytest.raises(ValueError, match="reason"):
        ripple_signatures.new_signature(host=HOST, channel="http_ua_novelty", value="ua-x",
                                        reason="", channels=channels)


def test_a_signature_can_never_be_granted_forever():
    channels = {spec.channel: spec.family for spec in ripple_evidence.SPECS}
    with pytest.raises(ValueError, match="in the future"):
        ripple_signatures.new_signature(host=HOST, channel="http_ua_novelty", value="ua-x",
                                        reason="r", channels=channels, today=TODAY,
                                        review_after=TODAY - timedelta(days=1))
    # `today=TODAY` PINS THE WALL CLOCK. The fixed NOW above is the test's frame; letting
    # new_signature read date.today() made this assertion expire the day after NOW, which is a
    # property of the calendar rather than of the bound under test (measured 2026-11-21).
    with pytest.raises(ValueError, match="at most"):
        ripple_signatures.new_signature(host=HOST, channel="http_ua_novelty", value="ua-x",
                                        reason="r", channels=channels, today=TODAY,
                                        review_after=TODAY + timedelta(days=366))
    row = ripple_signatures.new_signature(host=HOST, channel="http_ua_novelty", value="ua-x",
                                          reason="r", channels=channels, today=TODAY,
                                          review_after=TODAY + timedelta(days=365))
    assert (row["review_after"] - TODAY).days == 365


def test_only_channels_that_name_a_value_can_carry_a_signature():
    by_name = {spec.channel: spec for spec in ripple_evidence.SPECS}
    # A raw-value diversity/novelty/change channel is offered...
    assert ripple_signatures.supports(by_name["tls_fingerprint_diversity"])
    assert ripple_signatures.supports(by_name["http_ua_novelty"])
    assert ripple_signatures.supports(by_name["ssh_version_change"])
    # ...a pre-aggregated state channel is not (the values no longer exist to exclude)...
    assert not ripple_signatures.supports(by_name["flow_dst_diversity"])
    # ...and a numeric channel has no named value at all.
    assert not ripple_signatures.supports(by_name["dns_volume"])
    assert not ripple_signatures.supports(by_name["conn_reset_ratio"])
    assert "flow_dst_diversity" not in ripple_evidence.SIGNATURE_CHANNELS
    assert "dns_volume" not in ripple_evidence.SIGNATURE_CHANNELS


def test_the_scope_survives_a_removal_as_history():
    channels = {spec.channel: spec.family for spec in ripple_evidence.SPECS}
    row = ripple_signatures.new_signature(host=HOST, channel="http_ua_novelty", value="ua-x",
                                          reason="new appliance", channels=channels, actor="sam",
                                          today=TODAY)
    gone = ripple_signatures.removal(row, actor="ops", reason="replaced")
    assert gone["id"] == row["id"]
    assert gone["created_at"] == row["created_at"] and gone["created_by"] == "sam"
    assert gone["removed_by"] == "ops" and gone["removed_reason"] == "replaced"
    assert gone["removed_at"] is not None
    assert gone["reason"] == "new appliance"


# ── the measurement consults it ──────────────────────────────────────────────────────────────

def test_a_normalized_value_stops_producing_evidence_for_that_host():
    events = {"weirvern.zeek_http": _http_series(extra={HOST: ["ua-new-a"]})}
    before = _channel(ripple_evidence.compute(FakeClient(events), now=NOW), "http_ua_novelty")
    assert len(before) == 1 and before[0].value == 1.0 and before[0].pvalue <= 0.01 and before[0].at_floor()

    live = [_sig(channel="http_ua_novelty", value="ua-new-a")]
    after = _channel(ripple_evidence.compute(
        FakeClient(events, signatures=live), now=NOW), "http_ua_novelty")
    assert _significant(after) == [], [(item.value, item.pvalue) for item in after]
    assert after and after[0].value == 0.0 and after[0].pvalue > 0.5


def test_the_same_value_on_another_host_still_ripples():
    events = {"weirvern.zeek_http": _http_series(hosts=(HOST, OTHER),
                                                 extra={HOST: ["ua-new-a"], OTHER: ["ua-new-b"]})}
    live = [_sig(channel="http_ua_novelty", value="ua-new-a")]
    items = ripple_evidence.compute(FakeClient(events, signatures=live), now=NOW)
    assert _significant(_channel(items, "http_ua_novelty", HOST)) == []
    other = _channel(items, "http_ua_novelty", OTHER)
    assert len(other) == 1 and other[0].value == 1.0
    assert other[0].pvalue <= 0.01 and other[0].at_floor()


def test_a_different_value_on_the_same_channel_and_host_still_ripples():
    events = {"weirvern.zeek_http": _http_series(extra={HOST: ["ua-new-a", "ua-new-b"]})}
    live = [_sig(channel="http_ua_novelty", value="ua-new-a")]
    items = _significant(_channel(
        ripple_evidence.compute(FakeClient(events, signatures=live), now=NOW),
        "http_ua_novelty"))
    assert len(items) == 1, [(item.value, item.pvalue) for item in items]
    assert items[0].value == 1.0          # one new value remains, not zero
    assert items[0].pvalue <= 0.01 and items[0].at_floor()


def test_a_signature_on_one_channel_does_not_touch_another():
    events = {"weirvern.zeek_http": _http_series(extra={HOST: ["ua-new-a"]})}
    live = [_sig(channel="http_host_diversity", value="ua-new-a")]
    items = _significant(_channel(
        ripple_evidence.compute(FakeClient(events, signatures=live), now=NOW),
        "http_ua_novelty"))
    assert len(items) == 1 and items[0].value == 1.0


def test_a_tls_pair_signature_stops_counting_toward_tls_diversity():
    events = {"weirvern.zeek_ssl": _tls_series(new_pair="new.example|ja4new")}
    before = _channel(ripple_evidence.compute(FakeClient(events), now=NOW),
                      "tls_fingerprint_diversity")
    assert len(before) == 1 and before[0].value == 7.0

    live = [_sig(channel="tls_fingerprint_diversity", value="new.example|ja4new")]
    after = _channel(ripple_evidence.compute(FakeClient(events, signatures=live), now=NOW),
                     "tls_fingerprint_diversity")
    assert _significant(after) == [], [(item.value, item.baseline_median) for item in after]
    assert after and after[0].value == 6.0 and after[0].baseline_median == 6.0


def test_removing_the_signature_brings_the_evidence_back():
    events = {"weirvern.zeek_http": _http_series(extra={HOST: ["ua-new-a"]})}
    row = _sig(channel="http_ua_novelty", value="ua-new-a")
    gone = ripple_signatures.removal(row, actor="sam")
    items = ripple_evidence.compute(FakeClient(events, signatures=[gone]), now=NOW)
    assert len(_significant(_channel(items, "http_ua_novelty"))) == 1


def test_an_expired_review_after_stops_applying_without_anyone_acting():
    events = {"weirvern.zeek_http": _http_series(extra={HOST: ["ua-new-a"]})}
    row = _sig(channel="http_ua_novelty", value="ua-new-a",
               review_after=TODAY - timedelta(days=1))
    # The row is still in the store, still unremoved: the horizon alone retires it.
    items = ripple_evidence.compute(FakeClient(events, signatures=[row]), now=NOW)
    assert len(_significant(_channel(items, "http_ua_novelty"))) == 1
    assert ripple_signatures.as_filter([row], today=TODAY) == ripple_signatures.EMPTY


def test_a_live_signature_is_read_from_the_store_by_the_pass_itself():
    """No explicit filter: `compute()` must read the live rows, or the feature is not wired."""
    events = {"weirvern.zeek_http": _http_series(extra={HOST: ["ua-new-a"]})}
    client = FakeClient(events, signatures=[_sig(channel="http_ua_novelty", value="ua-new-a")])
    assert _significant(_channel(ripple_evidence.compute(client, now=NOW),
                                 "http_ua_novelty")) == []
    assert any("normal_ripple_signatures" in sql for sql in client.queries)


def test_the_raw_traffic_is_unchanged():
    """The filter changes the QUESTION, never the rows: same population, no writes."""
    events = {"weirvern.zeek_http": _http_series(extra={HOST: ["ua-new-a"]})}
    population = list(events["weirvern.zeek_http"])
    client = FakeClient(events, signatures=[_sig(channel="http_ua_novelty", value="ua-new-a")])
    ripple_evidence.compute(client, now=NOW)
    assert events["weirvern.zeek_http"] == population
    assert len(events["weirvern.zeek_http"]) == len(population)
    assert client.inserts == []
    forbidden = ("INSERT", "DELETE", "ALTER", "TRUNCATE", "DROP")
    writes = [sql for sql in client.queries if any(word in sql.upper() for word in forbidden)]
    assert writes == [], writes[:2]


def test_every_signable_channel_receives_the_filter_from_the_same_mechanism():
    """Not a special case per channel: the spec composes the predicate into its own query."""
    live = {spec.channel: {HOST: frozenset({"value-x"})} for spec in ripple_evidence.SPECS
            if ripple_signatures.supports(spec)}
    for spec in ripple_evidence.SPECS:
        if not ripple_signatures.supports(spec):
            continue
        filt = ripple_signatures.SignatureFilter(
            {(HOST, spec.channel): frozenset({"value-x"})})
        if spec.kind in ripple_evidence.SET_KINDS:
            sql = spec.sql_values(bucket_s=3600, anchor=NOW,
                                  since=NOW - timedelta(days=7), until=NOW,
                                  scope_cidrs=(NET,), signatures=filt)
            assert "NOT (" in sql and "= '198.51.100.10'" in sql, (spec.channel, sql)
        else:
            sql = spec.sql_anchored(bucket_s=3600, anchor=NOW,
                                    since=NOW - timedelta(days=7), until=NOW,
                                    scope_cidrs=(NET,), signatures=filt)
            assert "uniqExactIf" in sql and "NOT (" in sql, (spec.channel, sql)
    assert set(live) == set(ripple_evidence.SIGNATURE_CHANNELS)


# ── the write is attributable, and a viewer cannot write ─────────────────────────────────────

class _CM:
    def __init__(self, client):
        self.client = client

    def __enter__(self):
        return self.client

    def __exit__(self, *_a):
        return False


class _Auth:
    enabled = False
    reason = ""

    def check(self, presented, client=""):
        return False


def _app(client: FakeClient, *, role: str = users_mod.ROLE_ADMIN):
    store = users_mod.UserStore(_FakeK8s())
    store.load()
    sessions = users_mod.SessionRegistry()
    token = sessions.create(users_mod.Identity(username="sam", role=role))
    # BOUND OUTSIDE THE CLASS BODY: a class body cannot see the enclosing function's locals, so
    # `sessions = sessions` inside `_AppCtx` raises NameError on the right-hand side.
    _sessions = sessions
    _store = store

    class _AppCtx(_Ctx):
        settings = None
        backend = None
        config_client = None
        accounts_note = ""
        capabilities = None
        user_store = _store
        sessions = _sessions
        throttle = users_mod.LoginThrottle()
        auth = _Auth()
        connect_factory = staticmethod(lambda settings: _CM(client))

    app = flask_app.create_app(_AppCtx(), secret_key="signature-tests")
    app.config.update(TESTING=True)
    return app, token


class _FakeK8s:
    def __init__(self):
        self.data: dict = {}
        self.exists = False

    def read(self):
        if not self.exists:
            from weirvern.admin.cluster_config import NotFoundError

            raise NotFoundError("weirvern-users does not exist")
        return dict(self.data)

    def create(self, data):
        self.data, self.exists = dict(data), True

    def patch_data(self, data):
        self.data, self.exists = dict(data), True


def _post(app, token, path, body):
    with app.test_client() as client:
        return client.post(path, json=body,
                           headers={"X-Weirvern-Session": token})


def test_the_sheet_action_records_actor_and_reason():
    client = FakeClient()
    app, token = _app(client)
    got = _post(app, token, "/api/ripple-signatures", {
        "host": HOST, "channel": "tls_fingerprint_diversity",
        "value": "appliance.example|ja4abc", "reason": "the new backup appliance",
        "review_after": "2027-02-18",
    })
    assert got.status_code == 200, got.data
    payload = got.get_json()
    assert payload["ok"] is True
    table, rows = client.inserts[0]
    assert table == "weirvern.normal_ripple_signatures"
    assert len(rows) == 1
    assert rows[0]["created_by"] == "sam"
    assert rows[0]["reason"] == "the new backup appliance"
    assert rows[0]["host_addr"] == HOST
    assert rows[0]["channel"] == "tls_fingerprint_diversity"
    assert rows[0]["family"] == "tls"
    assert str(rows[0]["review_after"]) == "2027-02-18"


def test_a_viewer_cannot_write():
    client = FakeClient()
    app, token = _app(client, role=users_mod.ROLE_VIEWER)
    got = _post(app, token, "/api/ripple-signatures", {
        "host": HOST, "channel": "http_ua_novelty", "value": "ua-x", "reason": "because",
    })
    assert got.status_code == 403, got.data
    assert client.inserts == [], "a viewer's refused write still reached the store"


def test_a_family_is_not_expressible_through_the_api():
    client = FakeClient()
    app, token = _app(client)
    # `family` is not a field of the claim, and `tls` is not a channel.
    got = _post(app, token, "/api/ripple-signatures", {
        "host": HOST, "family": "tls", "value": "x", "reason": "r",
    })
    assert got.status_code == 400
    got = _post(app, token, "/api/ripple-signatures", {
        "host": HOST, "channel": "tls", "value": "x", "reason": "r",
    })
    assert got.status_code == 400
    assert client.inserts == []


def test_a_cidr_or_a_missing_reason_is_refused_through_the_api():
    client = FakeClient()
    app, token = _app(client)
    for body in (
        {"host": NET, "channel": "http_ua_novelty", "value": "ua-x", "reason": "r"},
        {"host": HOST, "channel": "http_ua_novelty", "value": "", "reason": "r"},
        {"host": HOST, "channel": "http_ua_novelty", "value": "ua-x", "reason": ""},
        {"host": HOST, "channel": "http_ua_novelty", "value": "ua-x", "reason": "r",
         "review_after": "2099-01-01"},
    ):
        got = _post(app, token, "/api/ripple-signatures", body)
        assert got.status_code == 400, (body, got.data)
    assert client.inserts == []


def test_remove_supersedes_and_the_actor_is_recorded():
    row = _sig(channel="http_ua_novelty", value="ua-new-a")
    client = FakeClient(signatures=[row])
    app, token = _app(client)
    got = _post(app, token, "/api/ripple-signatures/remove", {"id": row["id"]})
    assert got.status_code == 200, got.data
    table, rows = client.inserts[0]
    assert table == "weirvern.normal_ripple_signatures"
    assert rows[0]["id"] == row["id"]
    assert rows[0]["removed_by"] == "sam"
    assert rows[0]["removed_at"] is not None
    # The creation provenance survives the removal: the record is the audit.
    assert rows[0]["created_by"] == "sam"
    assert rows[0]["created_at"] == row["created_at"]


# ── the console surfaces ─────────────────────────────────────────────────────────────────────

ROOT_WEB = pathlib.Path(__file__).resolve().parents[1] / "weirvern/admin/web"


def test_each_evidence_line_carries_the_normalize_verb_and_a_reversible_preview():
    app_js = (ROOT_WEB / "app.js").read_text()
    assert '"Normalize this pattern"' in app_js
    assert "signature_capable" in app_js
    assert "/api/ripple-signatures/patterns" in app_js
    assert "Undo — remove this normalization" in app_js
    assert "reversible in one click" in app_js.lower() or "Reversible in one click" in app_js
    assert "next ripple pass" in app_js
    # The preview is built from the route's values, never from the numeric statistic.
    assert "renderSignatureValues" in app_js and "normalized_until" in app_js


def test_the_normalize_tab_lists_signatures_and_removes_in_one_click():
    html = (ROOT_WEB / "index.html").read_text()
    js = (ROOT_WEB / "normalize.js").read_text()
    assert 'id="nz-sigs"' in html
    for column in ("Host", "Channel", "Value", "Reason", "Review after"):
        assert f"<th>{column}</th>" in html, column
    assert "renderSignatures" in js and "/api/ripple-signatures/remove" in js
    # No confirm step on the reversible action; the row carries the record.
    assert "window.confirm" not in js.split("async function removeSignature")[1].split("}")[0]


def test_the_payload_marks_which_evidence_lines_can_be_normalized():
    client = FakeClient(
        events={"weirvern.zeek_ssl": _tls_series(new_pair="new.example|ja4new")},
        signatures=[])
    payload = ripple_evidence.overview(client, now=NOW)
    channels = payload.get("signature_channels") or []
    assert "tls_fingerprint_diversity" in channels
    assert "dns_volume" not in channels
    # The overview grouped no ripple in this fixture (one family, one scale), but the capability
    # contract is still carried on the payload the page reads.
    assert payload["available"] is True
