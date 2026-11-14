"""Block proposals: an agent may ask, only a person may apply.

THE PROPERTY WORTH TESTING IS THE SPLIT. Every test here is really asking one of two questions:
does proposing stay inert, and does applying go through the same validation any other rule gets?
A proposal path that could quietly enforce, or an apply path that bypassed a refusal, would both
look fine in a demo and be the worst defect in the product.
"""

from __future__ import annotations

import re

import pytest

from weirvern import proposals, sluice_store
from weirvern.admin import users as users_mod

flask = pytest.importorskip("flask")

from weirvern.admin import flask_app  # noqa: E402

# ── a ClickHouse stand-in that remembers inserts and serves them back ────────────────────────

class _QueryResult:
    def __init__(self, rows):
        self.result_rows = rows


class _FakeCH:
    """insert() appends, query() returns what is stored, newest first.

    Deliberately dumb: it does not interpret SQL. That means these tests assert on what the code
    WRITES and on what it does with a read, not on database behaviour, which is ClickHouse's job.
    """

    COLUMNS = ["proposal_id", "proposed_by", "host", "reason", "evidence", "ttl_minutes", "status",
               "proposed_at", "decided_at", "decided_by", "rule_id"]

    def __init__(self):
        self.rows: dict[str, list] = {}
        self.inserts: list[tuple] = []

    def insert(self, table, data, column_names=None):
        if table != "weirvern.block_proposals":
            # The auth audit writes to another table through the same factory. It is not what these
            # tests are about, and asserting on it here would make every login look like a defect.
            return len(data)
        self.inserts.append((table, data, column_names))
        for row in data:
            record = dict(zip(column_names, row, strict=False))
            # ReplacingMergeTree semantics: later version wins for the same key.
            self.rows[record["proposal_id"]] = record
        return len(data)

    def query(self, sql, parameters=None):
        rows = sorted(self.rows.values(), key=lambda r: r.get("proposed_at") or 0, reverse=True)
        if parameters and parameters.get("status"):
            rows = [r for r in rows if r["status"] == parameters["status"]]
        out = []
        for r in rows:
            out.append(tuple(r.get(c) for c in self.COLUMNS))
        return _QueryResult(out)


def _proposal(**over):
    base = {"host": "192.0.2.10", "reason": "beaconing to a known command host",
            "evidence": "anomaly 2026-11-13 18:05", "ttl_minutes": 60,
            "proposed_by": "agent:fathom"}
    base.update(over)
    return base


# ── proposing is INERT ──────────────────────────────────────────────────────────────────────

def test_a_proposal_is_stored_and_blocks_NOTHING(monkeypatch):
    """The whole reason the MCP server may propose: a row in this table changes no enforcement."""
    created: list = []
    monkeypatch.setattr(sluice_store, "create_rule", lambda *a, **k: created.append(k), raising=True)
    ch = _FakeCH()

    out = proposals.create_proposal(ch, _proposal())

    assert out["status"] == proposals.STATUS_PROPOSED
    assert not created, f"proposing created a rule: {created}"
    assert ch.inserts, "nothing was stored"
    _, data, cols = ch.inserts[0]
    assert "proposed_by" in cols and "host" in cols


def test_a_reason_is_required_because_an_unexplained_block_cannot_be_reviewed():
    ch = _FakeCH()

    with pytest.raises(proposals.ProposalError) as exc:
        proposals.create_proposal(ch, _proposal(reason="no"))

    assert "reason" in str(exc.value).lower()
    assert not ch.inserts, "an unreviewable proposal was stored"


def test_a_target_that_could_never_become_a_rule_is_refused_at_the_DOOR():
    """A proposal that looks actionable but cannot be applied is worse than none: a person clicks it
    and the failure appears later, somewhere that cannot explain itself."""
    ch = _FakeCH()

    with pytest.raises(proposals.ProposalError):
        proposals.create_proposal(ch, _proposal(host="not a domain!!"))

    assert not ch.inserts


def test_a_negative_duration_is_refused():
    with pytest.raises(proposals.ProposalError):
        proposals.create_proposal(_FakeCH(), _proposal(ttl_minutes=-5))


def test_the_actor_is_recorded_because_who_asked_is_part_of_the_record():
    ch = _FakeCH()
    proposals.create_proposal(ch, _proposal(proposed_by="account:sam"))
    stored = next(iter(ch.rows.values()))
    assert stored["proposed_by"] == "account:sam"


# ── applying goes through the SAME rule path ────────────────────────────────────────────────

class _Rule:
    rule_id = "slr_abc123"


def test_applying_CREATES_A_RULE_through_the_normal_path(monkeypatch):
    calls: list = []

    def fake_create_rule(client, **kw):
        calls.append(kw)
        return _Rule()

    monkeypatch.setattr(sluice_store, "create_rule", fake_create_rule, raising=True)
    ch = _FakeCH()
    prop = proposals.create_proposal(ch, _proposal())

    out = proposals.apply_proposal(ch, prop["proposal_id"], by="sam")

    assert calls, "applying did not create a rule"
    assert calls[0]["mode"] == "block"
    assert calls[0]["dst_cidr"] == "192.0.2.10"
    assert calls[0]["ttl_minutes"] == 60
    assert calls[0]["created_by"] == "sam"
    assert calls[0]["origin"] == "proposal", "the rule does not record where it came from"
    assert calls[0]["origin_ref"] == prop["proposal_id"]
    assert out["status"] == proposals.STATUS_APPLIED
    assert out["rule_id"] == "slr_abc123"


def test_a_DOMAIN_proposal_becomes_a_domain_rule(monkeypatch):
    calls: list = []
    monkeypatch.setattr(sluice_store, "create_rule",
                        lambda c, **kw: (calls.append(kw), _Rule())[1], raising=True)
    ch = _FakeCH()
    prop = proposals.create_proposal(ch, _proposal(host="ads.example.com"))

    proposals.apply_proposal(ch, prop["proposal_id"], by="sam")

    assert calls[0]["domain"] == "ads.example.com"
    assert calls[0]["dst_cidr"] == ""


def test_a_FAILED_rule_write_does_NOT_mark_the_proposal_applied(monkeypatch):
    """A proposal saying "applied" with no rule behind it is a false record of enforcement, which is
    the one thing this table must never contain."""
    def boom(client, **kw):
        raise RuntimeError("the gate refused the rule")

    monkeypatch.setattr(sluice_store, "create_rule", boom, raising=True)
    ch = _FakeCH()
    prop = proposals.create_proposal(ch, _proposal())

    with pytest.raises(RuntimeError):
        proposals.apply_proposal(ch, prop["proposal_id"], by="sam")

    assert ch.rows[prop["proposal_id"]]["status"] == proposals.STATUS_PROPOSED, (
        "a failed apply still marked the proposal applied"
    )


def test_a_proposal_can_only_be_applied_once(monkeypatch):
    monkeypatch.setattr(sluice_store, "create_rule", lambda c, **kw: _Rule(), raising=True)
    ch = _FakeCH()
    prop = proposals.create_proposal(ch, _proposal())
    proposals.apply_proposal(ch, prop["proposal_id"], by="sam")

    with pytest.raises(proposals.ProposalError) as exc:
        proposals.apply_proposal(ch, prop["proposal_id"], by="sam")

    assert "already applied" in str(exc.value)


def test_dismissing_keeps_the_row_because_we_saw_it_and_said_no():
    ch = _FakeCH()
    prop = proposals.create_proposal(ch, _proposal())

    out = proposals.dismiss_proposal(ch, prop["proposal_id"], by="sam")

    assert out["status"] == proposals.STATUS_DISMISSED
    assert ch.rows[prop["proposal_id"]]["decided_by"] == "sam"
    assert ch.rows[prop["proposal_id"]]["rule_id"] == ""


def test_an_unknown_status_filter_is_refused_rather_than_ignored():
    with pytest.raises(proposals.ProposalError):
        proposals.load_proposals(_FakeCH(), status="handled-ish")


# ── the form ───────────────────────────────────────────────────────────────────────────────

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
        self.data = dict(data)
        self.exists = True

    def patch_data(self, data):
        self.data = dict(data)
        self.exists = True


def _ctx():
    class _Auth:
        enabled = False

        def check(self, presented, client=""):
            return False

    class _Ctx:
        settings = None
        backend = None
        config_client = None
        throttle = users_mod.LoginThrottle()
        sessions = users_mod.SessionRegistry()
        auth = _Auth()
        accounts_note = ""
        user_store = None

    ctx = _Ctx()
    store = users_mod.UserStore(_FakeK8s())
    store.load()
    store.create_user("sam", users_mod.ROLE_ADMIN, "a long enough password")
    ctx.user_store = store
    return ctx


class _CM:
    def __init__(self, client):
        self.client = client

    def __enter__(self):
        return self.client

    def __exit__(self, *a):
        return False


def _signed_in_client(ctx, ch):
    """An app whose ClickHouse factory returns the fake, with a real signed-in cookie."""
    ctx.connect_factory = lambda settings: _CM(ch)
    app = flask_app.create_app(ctx, secret_key="test-key")
    app.config.update(TESTING=True)
    client = app.test_client()

    body = client.get("/login").data.decode()
    nonce = re.search(r'name="csrf" value="([^"]+)"', body).group(1)
    resp = client.post("/login", data={"username": "sam", "password": "a long enough password",
                                       "csrf": nonce})
    assert resp.status_code == 302, resp.data[:300]
    return client


def test_the_form_requires_a_session():
    ctx = _ctx()
    ctx.connect_factory = lambda settings: _CM(_FakeCH())
    app = flask_app.create_app(ctx, secret_key="test-key")
    app.config.update(TESTING=True)

    got = app.test_client().get("/block")

    assert got.status_code == 302
    assert "/login" in got.headers["Location"]


def test_submitting_the_form_stores_a_proposal_and_blocks_nothing(monkeypatch):
    created: list = []
    monkeypatch.setattr(sluice_store, "create_rule", lambda *a, **k: created.append(k), raising=True)
    ch = _FakeCH()
    client = _signed_in_client(_ctx(), ch)

    body = client.get("/block").data.decode()
    nonce = re.search(r'name="csrf" value="([^"]+)"', body).group(1)
    got = client.post("/block", data={"host": "ads.example.com", "reason": "known ad host",
                                      "evidence": "manual", "ttl_minutes": "30", "csrf": nonce})

    assert got.status_code == 302, got.data[:300]
    assert not created, "the form applied the block instead of proposing it"
    stored = next(iter(ch.rows.values()))
    assert stored["host"] == "ads.example.com"
    assert stored["proposed_by"] == "account:sam", (
        "a proposal from the form must record which account made it"
    )


def test_a_refusal_comes_back_to_the_form_with_the_typed_words_kept():
    ch = _FakeCH()
    client = _signed_in_client(_ctx(), ch)

    body = client.get("/block").data.decode()
    nonce = re.search(r'name="csrf" value="([^"]+)"', body).group(1)
    got = client.post("/block", data={"host": "192.0.2.10", "reason": "no",
                                      "evidence": "", "ttl_minutes": "0", "csrf": nonce})

    assert got.status_code == 400
    page = got.data.decode()
    assert "reason" in page.lower()
    assert "192.0.2.10" in page, "the host was cleared, so the operator must retype it"
    assert not ch.inserts


def test_the_form_post_needs_the_csrf_nonce():
    ch = _FakeCH()
    client = _signed_in_client(_ctx(), ch)

    got = client.post("/block", data={"host": "192.0.2.10", "reason": "known ad host"})

    assert got.status_code == 400
    assert not ch.inserts


def test_applying_from_the_form_uses_the_SIGNED_IN_username(monkeypatch):
    recorded: list = []
    monkeypatch.setattr(sluice_store, "create_rule", lambda c, **kw: _Rule(), raising=True)
    monkeypatch.setattr(proposals, "apply_proposal",
                        lambda c, pid, *, by, **kw: (recorded.append((pid, by)),
                                                     {"status": "applied"})[1],
                        raising=True)
    ch = _FakeCH()
    client = _signed_in_client(_ctx(), ch)

    body = client.get("/block").data.decode()
    nonce = re.search(r'name="csrf" value="([^"]+)"', body).group(1)
    client.post("/block/pp_test/apply", data={"csrf": nonce})

    assert recorded == [("pp_test", "sam")], (
        "the apply route must attribute the decision to the account that made it"
    )


# ── the API, so a remote agent can ask ──────────────────────────────────────────────────────

def test_the_proposals_API_requires_a_credential_to_write():
    """A proposal is a record change, so it takes the write gate. An open POST would let anything on
    the network fill the queue with blocking requests."""
    ch = _FakeCH()
    ctx = _ctx()                       # accounts exist, no session, no token configured
    ctx.connect_factory = lambda settings: _CM(ch)
    app = flask_app.create_app(ctx, secret_key="test-key")
    app.config.update(TESTING=True)

    got = app.test_client().post("/api/proposals", json={"host": "192.0.2.10",
                                                         "reason": "a good enough reason"})

    assert got.status_code in (401, 403), got.data[:200]
    assert not ch.inserts, "an unauthenticated caller stored a proposal"


def test_the_proposals_API_accepts_a_signed_in_admin_and_records_the_account():
    ch = _FakeCH()
    client = _signed_in_client(_ctx(), ch)

    got = client.post("/api/proposals", json={"host": "ads.example.com",
                                              "reason": "known ad host",
                                              "proposed_by": "agent:something-else"})

    assert got.status_code == 201, got.data[:300]
    stored = next(iter(ch.rows.values()))
    assert stored["proposed_by"] == "account:sam", (
        "the body claimed a different proposer and it was believed; an account cannot be "
        "impersonated by a request field"
    )


def test_the_proposals_API_refuses_an_unusable_target_with_a_reason():
    ch = _FakeCH()
    client = _signed_in_client(_ctx(), ch)

    got = client.post("/api/proposals", json={"host": "not a host!!", "reason": "because"})

    assert got.status_code == 400
    assert "error" in got.get_json()
    assert not ch.inserts


def test_the_proposals_API_lists_what_is_pending(monkeypatch):
    ch = _FakeCH()
    client = _signed_in_client(_ctx(), ch)
    client.post("/api/proposals", json={"host": "192.0.2.10", "reason": "a good enough reason"})

    got = client.get("/api/proposals?status=proposed")

    assert got.status_code == 200
    body = got.get_json()
    assert body["available"] is True
    assert body["total"] == 1
    assert body["proposals"][0]["host"] == "192.0.2.10"
