"""The detection -> alert path: one verdict in, one operator notification out.

── WHY THIS FILE EXISTS (audit F037: "the detection -> alert path has no test at all") ──────────

Measured before writing this: `push_alert` was referenced by exactly ONE test, and that test calls
`format_message` to pin a crash that had already happened in production. Nothing exercised
`push_alert` itself, the suppression rules that decide whether an operator is told at all, the
audit row every decision is supposed to leave behind, or the failure paths.

That is the highest-consequence untested path in the product, and the reason is structural rather
than careless: detection is the part with models and scores and something to assert on, while
alerting is the part that either fires or does not. A defect here does not produce a wrong number
anyone would notice -- it produces a SILENCE, and silence looks exactly like a quiet network.

WHAT THIS PINS, in the order a verdict travels:
  1. a delivered alert, and that the operator's payload carries the reason it fired
  2. log-only mode (no Pushover token) must not be indistinguishable from a send
  3. the two suppression rules, and that a suppressed alert still leaves an audit row
  4. a Pushover error must not be recorded as a send
  5. the audit row must never be able to break alerting

The whole path is exercised through the real `push_alert`; only the HTTP call and the ClickHouse
client are replaced, because those are the two things a unit test cannot provide.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

import pytest

from weirvern import alerts

# ── fixtures ─────────────────────────────────────────────────────────────────────────────────

@dataclass
class _Settings:
    """The subset of `Settings` the alert path reads, with production-shaped defaults."""

    pushover_enabled: bool = True
    pushover_api_token: str = "tok"
    pushover_user_key: str = "usr"
    pushover_cooldown_s: int = 300
    pushover_max_per_hour: int = 30
    alert_min_severity: str = "low"
    alert_min_score: float = 0.0
    extra: dict = field(default_factory=dict)

    def __getattr__(self, name: str) -> Any:  # any setting this path does not read
        try:
            return self.extra[name]
        except KeyError:  # pragma: no cover - only on a genuinely new setting
            raise AttributeError(name) from None


def _verdict(**kw) -> dict:
    """A verdict shaped like `detection_sweep` produces, since the alert path consumes that dict."""
    v = {
        "src_addr": "198.51.100.7",
        "window_start": "2026-09-23 07:00:00",
        "severity": "high",
        "anomaly_score": 0.91,
        "model_agreement": 0.75,
        "isolation_forest_score": 0.92,
        "gradient_boosting_score": 0.88,
        "dbscan_score": 0.71,
        "baseline_score": 1.4,
        "detected_by_models": "Isolation Forest, Gradient Boosting",
        "duration_minutes": 5,
        "baseline_comparison": "bytes 12.4x the 72h average",
    }
    v.update(kw)
    return v


class _Resp:
    def __init__(self, status_code=200, text=""):
        self.status_code = status_code
        self.text = text


class _Client:
    """Captures audit inserts. The alert path only inserts, and must never read."""

    def __init__(self):
        self.rows: list[tuple[str, list, list | None]] = []

    def insert(self, table, rows, column_names=None):
        self.rows.append((table, rows, column_names))

    def query(self, *a, **kw):  # pragma: no cover - asserting this is never called
        raise AssertionError("the alert path must not query")


@pytest.fixture(autouse=True)
def _no_real_http(monkeypatch):
    """REFUSE THE NETWORK IN EVERY TEST IN THIS FILE, whether or not it asks for a stub.

    MEASURED, and it is the reason this fixture is autouse: one of these tests was written without
    requesting the `sent` stub, so `push_alert` called the REAL Pushover API. The captured log
    contains Pushover's own reply --

        Pushover error 400: {"token":"invalid","errors":["application token is invalid"]}

    -- which means a unit test sent live HTTP traffic to a third party. Nothing was harmed (the
    tokens are fake and the calls were rejected), but a test suite that reaches the internet is
    slow, flaky, and can leak data; on a machine with real credentials it would have SENT ALERTS.
    Defaulting to a stub removes the possibility: a test must opt IN to the network, never out.
    """
    def _post(url, data=None, timeout=None):
        raise AssertionError(
            "this test reached the real network. Request the `sent`, `failing` or `raising` "
            "fixture to stub the Pushover call deliberately"
        )

    monkeypatch.setattr(alerts.requests, "post", _post)


@pytest.fixture
def sent(monkeypatch):
    """Replace the HTTP call and record what would have gone to Pushover."""
    calls: list[dict] = []

    def _post(url, data=None, timeout=None):
        calls.append({"url": url, "data": data, "timeout": timeout})
        return _Resp(200)

    monkeypatch.setattr(alerts.requests, "post", _post)
    return calls


@pytest.fixture
def failing(monkeypatch):
    """A Pushover that answers with an error status."""
    def _post(url, data=None, timeout=None):
        return _Resp(429, "rate limited")

    monkeypatch.setattr(alerts.requests, "post", _post)


@pytest.fixture
def raising(monkeypatch):
    """A Pushover that cannot be reached at all."""
    def _post(url, data=None, timeout=None):
        raise alerts.requests.RequestException("connection refused")

    monkeypatch.setattr(alerts.requests, "post", _post)


# ── 1. a delivered alert ─────────────────────────────────────────────────────────────────────

def test_a_verdict_produces_a_delivered_alert(sent):
    """THE BASIC CONTRACT, which had no test: a verdict in, an operator notification out."""
    delivered, reason = alerts.push_alert(_verdict(), _Settings(), alerts.AlertState())

    assert delivered is True, f"an alert was not delivered: reason={reason!r}"
    assert reason == "sent"
    assert len(sent) == 1, f"expected one HTTP call, saw {len(sent)}"
    assert sent[0]["url"] == alerts.PUSHOVER_ENDPOINT


def test_the_payload_carries_the_REASON_not_just_a_score(sent):
    """`format_message` documents this: a score alone tells an operator something is wrong but not
    what, 'which is the difference between an alert they can act on and one they learn to ignore'.
    Asserted on the SENT payload, since that is what the operator actually receives."""
    alerts.push_alert(_verdict(), _Settings(), alerts.AlertState())
    body = sent[0]["data"]["message"]
    assert "198.51.100.7" in body, f"the alert does not name the host: {body!r}"
    assert "bytes 12.4x the 72h average" in body, f"the alert does not say WHY: {body!r}"
    assert "0.91" in body, f"the alert does not carry the score: {body!r}"
    # Pushover truncates at 1024; a silently clipped message loses the explanation.
    assert len(body) <= 1024, f"the message exceeds Pushover's limit: {len(body)} chars"


def test_the_verdict_fields_are_read_not_guessed(sent):
    """A field renamed in the detector must fail here rather than shipping a blank alert."""
    v = _verdict(src_addr="203.0.113.9", severity="critical")
    alerts.push_alert(v, _Settings(), alerts.AlertState())
    body = sent[0]["data"]["message"]
    assert "203.0.113.9" in body and "CRITICAL" in body, body


# ── 2. log-only mode must be distinguishable from a send ─────────────────────────────────────

def test_LOG_ONLY_mode_does_not_claim_a_send(monkeypatch):
    """Pushover is unconfigured in the shipped deployment and the token is EMPTY (the user: 'there
    has never been a live pushover token'). Log-only is the normal state there, and it must not be
    recorded as a delivery -- an audit trail that says 'sent' for alerts nobody received is worse
    than no trail."""
    def _must_not_call(*a, **kw):  # pragma: no cover
        raise AssertionError("Pushover was called while disabled")

    monkeypatch.setattr(alerts.requests, "post", _must_not_call)
    delivered, reason = alerts.push_alert(_verdict(), _Settings(pushover_enabled=False),
                                          alerts.AlertState())

    assert delivered is False
    assert reason == "log-only", f"expected the log-only reason, got {reason!r}"


def test_log_only_still_leaves_an_audit_row():
    """So an operator can tell 'detection did not fire' from 'detection fired and we could not
    tell anyone'. Those need different fixes and look identical without the row."""
    c = _Client()
    alerts.push_alert(_verdict(), _Settings(pushover_enabled=False), alerts.AlertState(), c)
    assert c.rows, "log-only mode left no audit row"
    table, rows, cols = c.rows[0]
    assert table == "weirvern.alert_events"
    assert cols is not None and "sent" in cols and "reason" in cols, cols
    row = dict(zip(cols, rows[0], strict=False))
    assert row["sent"] == 0, "a log-only alert was recorded as sent"
    assert row["reason"] == "log-only"


# ── 3. suppression ───────────────────────────────────────────────────────────────────────────

def test_a_repeat_from_the_same_host_is_SUPPRESSED_within_the_cooldown(sent):
    """The rule that keeps one noisy host from burying the operator. It had no test, so a broken
    cooldown would have silently either flooded or gagged alerting."""
    st = alerts.AlertState()
    first, _ = alerts.push_alert(_verdict(), _Settings(), st)
    second, reason = alerts.push_alert(_verdict(), _Settings(), st)

    assert first is True
    assert second is False, "the second alert in the cooldown was delivered"
    assert reason == "cooldown", f"expected the cooldown reason, got {reason!r}"
    assert len(sent) == 1, f"a suppressed alert still called Pushover: {len(sent)} calls"


def test_the_cooldown_is_PER_HOST_not_global(sent):
    """A global cooldown would let one noisy host gag every other host's alerts, which is the
    failure that makes an operator distrust the whole system."""
    st = alerts.AlertState()
    a, _ = alerts.push_alert(_verdict(src_addr="198.51.100.7"), _Settings(), st)
    b, reason = alerts.push_alert(_verdict(src_addr="203.0.113.9"), _Settings(), st)

    assert a is True and b is True, (
        f"a second, different host was suppressed by the first host's cooldown: {reason!r}"
    )


def test_the_hourly_CAP_suppresses_and_says_so(sent):
    """The cap is the backstop for a storm. When it trips, the reason must be `cap` and not
    `cooldown`: they mean different things to whoever is reading the audit trail."""
    st = alerts.AlertState()
    st.hourly_events.extend([time.time()] * 30)
    delivered, reason = alerts.push_alert(_verdict(), _Settings(pushover_max_per_hour=30), st)

    assert delivered is False
    assert reason == "cap", f"expected the cap reason, got {reason!r}"
    assert not sent, "the cap was reached but Pushover was called anyway"


def test_a_SUPPRESSED_alert_still_leaves_an_audit_row(sent):
    """A suppression that leaves no trace is indistinguishable from detection not firing -- and
    the difference matters, because one is a tuning problem and the other is a detection problem.

    `sent` is requested so the first alert (which IS delivered, and legitimately so) goes to a stub
    rather than to the real Pushover API. The autouse guard caught this test reaching the network
    when the fixture was missing, which is exactly what that guard is for.
    """
    c = _Client()
    st = alerts.AlertState()
    alerts.push_alert(_verdict(), _Settings(), st, c)
    alerts.push_alert(_verdict(), _Settings(), st, c)

    assert len(c.rows) == 2, f"expected an audit row per decision, saw {len(c.rows)}"
    _, rows, cols = c.rows[1]
    row = dict(zip(cols, rows[0], strict=False))
    assert row["sent"] == 0 and row["reason"] == "cooldown", row


# ── 4. failures must not be recorded as successes ────────────────────────────────────────────

def test_a_pushover_ERROR_is_not_recorded_as_a_send(failing):
    """The reason string is the whole point: `pushover-error` sends an operator to their token,
    while `sent` sends them looking for a detection that did fire."""
    c = _Client()
    delivered, reason = alerts.push_alert(_verdict(), _Settings(), alerts.AlertState(), c)

    assert delivered is False, "a 429 was reported as delivered"
    assert reason == "pushover-error", f"expected pushover-error, got {reason!r}"
    _, rows, cols = c.rows[0]
    row = dict(zip(cols, rows[0], strict=False))
    assert row["sent"] == 0, "a failed send left an audit row claiming success"


def test_an_unreachable_pushover_does_not_raise_or_claim_success(raising):
    """`push_alert` is called from the worker loop. An exception escaping here would be caught by
    the loop's handler and take out the rest of the cycle -- including detection.

    AND IT MUST NOT START THE COOLDOWN EITHER, which is a SEPARATE code path from the HTTP-error
    case above: a 4xx takes the `else` branch on the status code, while an unreachable host raises
    from `requests.post`. MUTATION TESTING FOUND THIS GAP -- adding `state.last_sent[src] = now` to
    the `except` branch passed every test, because the cooldown assertion only exercised the status
    -code path. A transport failure is the more likely of the two in practice (a firewall, a DNS
    blip, an outage), so it is the one that most needs the guard.
    """
    st = alerts.AlertState()
    c = _Client()
    delivered, reason = alerts.push_alert(_verdict(), _Settings(), st, c)

    assert delivered is False
    assert reason == "pushover-error", f"expected pushover-error, got {reason!r}"
    assert not st.last_sent, (
        "a transport failure recorded a send time, so the cooldown would suppress the next real "
        "alert from this host -- a Pushover outage would then silence detection"
    )
    assert not st.hourly_events, (
        "a transport failure consumed the hourly alert budget"
    )
    # And the audit row must still say the truth about what happened.
    _, rows, cols = c.rows[0]
    row = dict(zip(cols, rows[0], strict=False))
    assert row["sent"] == 0 and row["reason"] == "pushover-error", row


def test_a_FAILED_delivery_does_NOT_start_the_cooldown(failing):
    """A failed delivery must not be treated as a delivery. If it were, a Pushover outage would
    suppress the next genuine alert from that host for a full cooldown -- losing a real incident
    because of a transport failure.

    THIS TEST CANNOT USE THE `sent` STUB AND THE `failing` STUB AT ONCE: both patch the same
    function, and the one applied last wins, so the first version of this test had its "successful"
    send actually fail and asserted against the wrong state. Each case gets its own fixture now.
    """
    st = alerts.AlertState()
    delivered, reason = alerts.push_alert(_verdict(), _Settings(), st)
    assert delivered is False and reason == "pushover-error"

    assert not st.last_sent, (
        "a FAILED delivery recorded a send time, so the cooldown would now suppress the next real "
        "alert from this host"
    )
    assert not st.hourly_events, (
        "a FAILED delivery counted toward the hourly cap, so an outage would consume the budget for "
        "alerts that might have got through"
    )


def test_a_DELIVERED_alert_DOES_start_the_cooldown(sent):
    """The paired case, so the test above cannot pass by the cooldown simply never starting."""
    st = alerts.AlertState()
    delivered, _ = alerts.push_alert(_verdict(), _Settings(), st)

    assert delivered is True
    assert st.last_sent, "a delivered alert did not record its time, so the cooldown never started"
    assert st.hourly_events, "a delivered alert did not count toward the hourly cap"


# ── 5. the audit insert must never break alerting ────────────────────────────────────────────

def test_a_failing_audit_insert_does_not_lose_the_alert(sent):
    """`_audit` documents 'Never raises (alerting must not crash the loop)'. Losing the trail is
    recoverable; losing the alert is not, and an insert failure is a database problem rather than
    a reason to stop telling anyone about an incident."""
    class _Broken:
        def insert(self, *a, **kw):
            raise RuntimeError("clickhouse is unreachable")

    delivered, reason = alerts.push_alert(_verdict(), _Settings(), alerts.AlertState(), _Broken())
    assert delivered is True, (
        f"a failing audit insert took the alert with it: delivered={delivered} reason={reason!r}"
    )


def test_no_client_at_all_is_fine(sent):
    """A `None` client is the documented 'no audit trail' mode, and must not raise."""
    delivered, _ = alerts.push_alert(_verdict(), _Settings(), alerts.AlertState(), None)
    assert delivered is True
