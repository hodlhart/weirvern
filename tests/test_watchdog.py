"""THE DEAD-MAN WATCHDOG: each state transition, and the delivery that must not lie.

WHY THIS FILE EXISTS. The outage this watchdog was built for (2026-11-21) was not a crash. Both
flow sinks stopped, every component stayed Ready, and `PUSHOVER_ENABLED=0` with empty keys meant
all 32,897 `alert_events` rows were `log-only`. Nothing in the deployment was in a state a
restart would have fixed; the missing thing was a process that asks "is the data still
advancing, and can I tell anyone?".

So these tests drive the TRANSITIONS, not just the happy path:

  * fresh -> stalled            (the stall is detected, with the age and the limit)
  * stalled -> recovered        (one recovery notice, not silence and not a repeat page)
  * unreadable != no_data       (a failed query must never be reported as zero/quiet)
  * unconfigured delivery       (only when pushover was asked for: exit 3, loud, no POST)
  * record-only delivery        (this version's policy: exit 0, stated, still records faults)
  * cooldown                    (a still-firing check does not page every five minutes)
"""
from __future__ import annotations

import importlib.util
import json
import logging
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("watchdog_under_test", ROOT / "scripts" / "watchdog.py")
assert SPEC and SPEC.loader
watchdog = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = watchdog
SPEC.loader.exec_module(watchdog)

GIB = 1024 ** 3
NOW = datetime(2026, 11, 21, 20, 0, 0, tzinfo=UTC)


# ── fixtures that answer like the real sources ──────────────────────────────────────────────────

class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class FakeCH:
    """ClickHouse-shaped stub: two sinks, disk space, and the health ledger.

    HONOURS THE QUERY, like the fixtures in test_health_probes: a broken sink raises only for its
    own statement, so `unreadable` cannot leak into the other sink's verdict.
    """

    def __init__(self, *, flow_age=60.0, zeek_age=60.0, flows_rows=100, zeek_rows=100,
                 free=20 * GIB, total=100 * GIB, largest=145_000_000,
                 broken=(), previous_rows=None):
        self.flow_age = flow_age
        self.zeek_age = zeek_age
        self.flows_rows = flows_rows
        self.zeek_rows = zeek_rows
        self.free = free
        self.total = total
        self.largest = largest
        self.broken = set(broken)
        self.previous_rows = previous_rows or []
        self.inserted: list[tuple] = []

    def query(self, sql, *a, **kw):
        if "FROM system.disks" in sql:
            if "clickhouse_space" in self.broken:
                raise RuntimeError("system.disks unavailable")
            return _Result([(self.free, self.total)])
        if "FROM system.parts" in sql:
            return _Result([(self.largest,)])
        if "FROM weirvern.flows" in sql:
            if "flows" in self.broken:
                raise RuntimeError("weirvern.flows unavailable")
            return _Result([(self.flows_rows, "2026-11-21 19:00:00", self.flow_age)])
        if "FROM weirvern.zeek_conn" in sql:
            if "zeek_conn" in self.broken:
                raise RuntimeError("weirvern.zeek_conn unavailable")
            return _Result([(self.zeek_rows, "2026-11-21 19:00:00", self.zeek_age)])
        if "FROM weirvern.health" in sql:
            return _Result(self.previous_rows)
        raise AssertionError(f"unexpected query: {sql}")

    def insert(self, table, rows, column_names=None):
        self.inserted.append((table, rows, column_names))


class FakeKube:
    def __init__(self, *, pods=(), jobs=(), error: str = ""):
        self._pods = list(pods)
        self._jobs = list(jobs)
        self.error = error

    def pods(self):
        if self.error:
            raise RuntimeError(self.error)
        return {"items": self._pods}

    def jobs(self):
        if self.error:
            raise RuntimeError(self.error)
        return {"items": self._jobs}


def env(**overrides):
    base = {"PUSHOVER_ENABLED": "1", "PUSHOVER_USER_KEY": "user-key",
            "PUSHOVER_API_TOKEN": "api-token"}
    base.update(overrides)
    return base


def usage(pct: float):
    total = 100 * GIB
    used = int(total * pct / 100.0)
    return SimpleNamespace(total=total, used=used, free=total - used)


def cert_file(tmp_path: Path, days: float) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "weirvern-test")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOW - timedelta(days=1))
        .not_valid_after(NOW + timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "tls.crt"
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return str(path)


def pod(name: str, *, restarts: int = 0, last_reason: str = "", finished_ago_s: float | None = None,
        waiting: str = "", container: str = "worker", oom_now: bool = False) -> dict:
    container_status = {
        "name": container,
        "restartCount": restarts,
        "lastState": {},
        "state": {},
    }
    if finished_ago_s is not None:
        container_status["lastState"] = {"terminated": {
            "reason": last_reason or "Completed",
            "finishedAt": (NOW - timedelta(seconds=finished_ago_s)).isoformat().replace("+00:00", "Z"),
        }}
    if waiting:
        container_status["state"] = {"waiting": {"reason": waiting}}
    if oom_now:
        container_status["state"] = {"terminated": {"reason": "OOMKilled"}}
    return {
        "metadata": {"name": name, "uid": f"uid-{name}",
                     "labels": {"app.kubernetes.io/name": name}},
        "status": {"containerStatuses": [container_status]},
    }


def failed_job(name: str, *, minutes_ago: float, kind: str = "Failed",
               labels: dict | None = None) -> dict:
    stamp = (NOW - timedelta(minutes=minutes_ago)).isoformat().replace("+00:00", "Z")
    return {
        "metadata": {"name": name, "labels": labels or {}},
        "status": {"conditions": [{"type": kind, "status": "True",
                                   "lastTransitionTime": stamp,
                                   "reason": "BackoffLimitExceeded"}]},
    }


def _checks(**kw):
    """The two sink checks with every other source quiet, for the transition tests."""
    client = kw.pop("client", FakeCH())
    return watchdog.check_sinks(client, limit_s=watchdog.STALE_AFTER_S)


# ── fresh -> stalled ──────────────────────────────────────────────────────────────────────────

def test_fresh_then_stalled_is_a_detected_transition_not_a_number():
    fresh = _checks(client=FakeCH(flow_age=60.0, zeek_age=60.0))
    assert [c.status for c in fresh if c.name == "flows"] == ["ok"]

    stalled = _checks(client=FakeCH(flow_age=3600.0, zeek_age=60.0))
    flows = next(c for c in stalled if c.name == "flows")
    assert flows.status == "stalled" and flows.firing
    assert "STALLED" in flows.detail
    assert "1.0h" in flows.detail or "60.0m" in flows.detail  # the age is named, not a bare 0
    assert "10.0m" in flows.detail         # and so is the limit
    assert flows.value["age_s"] == 3600.0

    actions = watchdog.plan_actions(
        stalled, {"flows": {"status": "ok"}},
        watchdog.Delivery(True, "ok"), env(), now=NOW,
    )
    alarms = [a for a in actions if a.check.name == "flows"]
    assert len(alarms) == 1 and alarms[0].kind == "alarm" and not alarms[0].suppressed
    assert alarms[0].payload["priority"] == 1
    assert "flows STALLED" in alarms[0].payload["title"]
    assert "weirvern.flows IS STALLED" in alarms[0].payload["message"]


# ── stalled -> recovered ─────────────────────────────────────────────────────────────────────

def test_stalled_then_recovered_sends_one_recovery_and_no_alarm():
    recovered = _checks(client=FakeCH(flow_age=30.0))
    previous = {"flows": {"status": "stalled",
                          "last_notified_at": (NOW - timedelta(minutes=20)).isoformat()}}
    actions = watchdog.plan_actions(
        recovered, previous, watchdog.Delivery(True, "ok"), env(), now=NOW,
    )
    flows = [a for a in actions if a.check.name == "flows"]
    assert len(flows) == 1
    assert flows[0].kind == "recovery"
    assert flows[0].payload["priority"] == 0
    assert "RECOVERED" in flows[0].payload["message"]
    assert "was stalled" in flows[0].payload["message"]

    # The next healthy run has no edge left to announce.
    actions_again = watchdog.plan_actions(
        recovered, {"flows": {"status": "ok"}},
        watchdog.Delivery(True, "ok"), env(), now=NOW,
    )
    assert [a for a in actions_again if a.check.name == "flows"] == []


# ── unreadable != no_data ────────────────────────────────────────────────────────────────────

def test_unreadable_is_not_no_data_and_neither_is_a_bare_zero():
    unreadable = watchdog.check_sinks(FakeCH(broken={"flows"}), limit_s=600)
    no_data = watchdog.check_sinks(FakeCH(flows_rows=0, flow_age=None), limit_s=600)

    broken = next(c for c in unreadable if c.name == "flows")
    empty = next(c for c in no_data if c.name == "flows")

    assert broken.status == "unreadable"
    assert empty.status == "no_data"
    assert broken.status != empty.status
    assert "UNKNOWN" in broken.detail and "unavailable" in broken.detail
    assert "NO ROWS" in empty.detail and "never" in empty.detail
    assert broken.value["age_s"] is None and empty.value["age_s"] is None
    # Both are faults, so both page; the message is what tells the operator which fault it is.
    assert broken.firing and empty.firing


def test_a_recovery_is_not_posted_when_the_pager_is_unconfigured():
    recovered = _checks(client=FakeCH(flow_age=30.0))
    previous = {"flows": {"status": "stalled",
                          "last_notified_at": (NOW - timedelta(minutes=20)).isoformat()}}
    actions = watchdog.plan_actions(
        recovered, previous,
        watchdog.Delivery(False, "unconfigured", "PUSHOVER_ENABLED is '0'"),
        env(PUSHOVER_ENABLED="0", PUSHOVER_USER_KEY="", PUSHOVER_API_TOKEN=""),
        now=NOW,
    )
    flows = next(a for a in actions if a.check.name == "flows")
    assert flows.kind == "recovery" and flows.suppressed
    assert "delivery-unconfigured" in flows.reason


# ── unconfigured delivery ────────────────────────────────────────────────────────────────────

def test_unconfigured_delivery_is_loud_never_posts_and_exits_three(tmp_path, caplog):
    client = FakeCH(flow_age=3600.0)  # there IS something to page about
    posted: list = []

    with caplog.at_level(logging.ERROR, logger="weirvern.watchdog"):
        code, report = watchdog.run(
            env=env(ALERT_DELIVERY="pushover", PUSHOVER_ENABLED="0",
                    PUSHOVER_USER_KEY="", PUSHOVER_API_TOKEN=""),
            now=NOW, client=client, kube=FakeKube(), previous={},
            post=lambda *a, **k: posted.append(a) or SimpleNamespace(status_code=200),
            host_root=str(tmp_path), cert_path=cert_file(tmp_path, 60),
            disk_usage=lambda _p: usage(50),
        )

    assert code == 3, "an opted-in pager that cannot send must not report success"
    assert posted == [], "nothing may be POSTed when the keys are empty"
    assert report["delivery"]["status"] == "unconfigured"
    delivery_row = next(c for c in report["checks"] if c["check"] == "watchdog_delivery")
    assert delivery_row["status"] == "unconfigured"
    assert "PUSHOVER_ENABLED" in delivery_row["detail"]
    # The alarm was OWED: the report says it was suppressed by configuration, not by health.
    flows = next(a for a in report["alarms"] if a["check"] == "flows")
    assert flows["suppressed"] is True and "delivery-unconfigured" in flows["reason"]

    # The durable row exists, and it is `unconfigured` -- this is the Health panel's signal.
    table, rows, columns = client.inserted[0]
    assert table == "weirvern.health"
    assert "check_name" in columns
    by_name = {row[0]: row for row in rows}
    assert by_name["watchdog_delivery"][1] == "unconfigured"
    assert by_name["flows"][1] == "stalled"

    # And it is loud in the log: one structured JSON error, not a warning nobody greps for.
    structured = [json.loads(r.getMessage()) for r in caplog.records
                  if r.getMessage().startswith('{"')]
    assert any(event["event"] == "watchdog_delivery_unconfigured"
               and "flows" in event["alarms_that_could_not_be_sent"] for event in structured)


def test_record_delivery_is_a_policy_and_does_not_fail_the_cronjob(tmp_path, caplog):
    """This version sends nothing. That choice must not leave a red CronJob behind.

    Measured 2026-11-21: three consecutive watchdog Jobs sat in `Error` because delivery was
    never configured -- a documented product decision reported as a fault. A permanent red for a
    policy trains an operator to ignore the colour that must mean "capture is down".
    """
    client = FakeCH(flow_age=3600.0)  # a real fault is present and still recorded
    posted: list = []

    with caplog.at_level(logging.INFO, logger="weirvern.watchdog"):
        code, report = watchdog.run(
            env=env(ALERT_DELIVERY="record", PUSHOVER_ENABLED="0",
                    PUSHOVER_USER_KEY="", PUSHOVER_API_TOKEN=""),
            now=NOW, client=client, kube=FakeKube(), previous={},
            post=lambda *a, **k: posted.append(a) or SimpleNamespace(status_code=200),
            host_root=str(tmp_path), cert_path=cert_file(tmp_path, 60),
            disk_usage=lambda _p: usage(50),
        )

    assert code == 0, "record-only delivery is a policy, not a failure"
    assert posted == [], "record mode must never POST"
    assert report["delivery"]["status"] == "disabled"
    row = next(c for c in report["checks"] if c["check"] == "watchdog_delivery")
    assert row["status"] == "disabled" and row["firing"] is False
    assert row["severity"] == "info"
    assert "recorded in the console" in row["detail"]

    # The fault is still recorded, and the reason says it was policy that kept it local.
    flows = next(a for a in report["alarms"] if a["check"] == "flows")
    assert flows["suppressed"] is True
    assert "delivery-disabled-by-policy" in flows["reason"]

    table, rows, _columns = client.inserted[0]
    by_name = {r[0]: r for r in rows}
    assert by_name["watchdog_delivery"][1] == "disabled"
    events = [json.loads(r.getMessage()) for r in caplog.records
              if r.getMessage().startswith('{"')]
    assert any(e["event"] == "watchdog_delivery_disabled" for e in events)
    assert not any(e["event"] == "watchdog_delivery_unconfigured" for e in events)


def test_an_enabled_but_empty_key_is_unconfigured_only_when_delivery_was_asked_for():
    asked = {"ALERT_DELIVERY": "pushover"}
    assert not watchdog.delivery_config(env(**asked, PUSHOVER_USER_KEY="")).configured
    assert not watchdog.delivery_config(env(**asked, PUSHOVER_API_TOKEN="  ")).configured
    delivery = watchdog.delivery_config(env(**asked, PUSHOVER_ENABLED="0"))
    assert delivery.status == "unconfigured" and "PUSHOVER_ENABLED" in delivery.reason
    # With no policy set, an unconfigured pager is the shipped record-only mode.
    default = watchdog.delivery_config(env(PUSHOVER_ENABLED="0", PUSHOVER_USER_KEY="",
                                           PUSHOVER_API_TOKEN=""))
    assert default.status == "disabled" and default.mode == "record"


# ── dry-run ─────────────────────────────────────────────────────────────────────────────────

def test_dry_run_prints_the_verdict_and_payload_without_sending_or_writing(tmp_path):
    client = FakeCH(flow_age=3600.0)
    posted: list = []

    code, report = watchdog.run(
        dry_run=True, env=env(), now=NOW, client=client, kube=FakeKube(), previous={},
        post=lambda *a, **k: posted.append(a) or SimpleNamespace(status_code=200),
        host_root=str(tmp_path), cert_path=cert_file(tmp_path, 60),
        disk_usage=lambda _p: usage(50),
    )

    assert code == 0, "--dry-run must be safe to run by hand"
    assert posted == [] and client.inserted == []
    assert report["dry_run"] is True
    assert report["would_exit"] == 1
    flows = next(a for a in report["alarms"] if a["check"] == "flows")
    assert flows["pushover"]["token"] == "<redacted>"
    assert flows["pushover"]["user"] == "<redacted>"
    assert set(flows["pushover"]) == {"token", "user", "message", "title", "priority", "sound"}
    assert flows["pushover"]["priority"] == 1
    assert "weirvern.flows IS STALLED" in flows["pushover"]["message"]
    assert report["checks"][0]["check"] == "flows"


# ── rate limiting and the delivered path ────────────────────────────────────────────────────

def test_a_still_firing_check_is_suppressed_inside_the_cooldown():
    checks = _checks(client=FakeCH(flow_age=3600.0))
    previous = {"flows": {"status": "stalled",
                          "last_notified_at": NOW - timedelta(minutes=5)}}
    actions = watchdog.plan_actions(
        checks, previous, watchdog.Delivery(True, "ok"), env(), now=NOW,
    )
    flows = next(a for a in actions if a.check.name == "flows")
    assert flows.suppressed and "cooldown" in flows.reason


def test_a_changed_firing_state_is_sent_immediately():
    checks = _checks(client=FakeCH(flow_age=3600.0))
    previous = {"flows": {"status": "no_data",
                          "last_notified_at": NOW - timedelta(minutes=5)}}
    actions = watchdog.plan_actions(
        checks, previous, watchdog.Delivery(True, "ok"), env(), now=NOW,
    )
    flows = next(a for a in actions if a.check.name == "flows")
    assert not flows.suppressed and flows.kind == "alarm"


def test_a_configured_delivery_posts_the_payload_and_records_it(tmp_path):
    client = FakeCH(flow_age=3600.0)
    calls: list[dict] = []

    def post(url, data=None, timeout=None):
        calls.append({"url": url, "data": data, "timeout": timeout})
        return SimpleNamespace(status_code=200, text="ok")

    code, report = watchdog.run(
        env=env(), now=NOW, client=client, kube=FakeKube(), previous={},
        post=post, host_root=str(tmp_path), cert_path=cert_file(tmp_path, 60),
        disk_usage=lambda _p: usage(50),
    )

    assert code == 1 and len(calls) == 1
    sent = calls[0]["data"]
    assert calls[0]["url"] == "https://api.pushover.net/1/messages.json"
    assert sent["token"] == "api-token" and sent["user"] == "user-key"
    assert sent["priority"] == 1
    table, rows, _columns = client.inserted[0]
    by_name = {row[0]: row for row in rows}
    assert by_name["flows"][1] == "stalled"
    assert by_name["flows"][5] is not None  # last_notified_at was stamped
    assert report["alarms"][0]["sent"] is True


# ── pods, jobs, disk, cert ──────────────────────────────────────────────────────────────────

def test_oomkilled_is_its_own_state_and_outranks_a_plain_restart():
    kube = FakeKube(pods=[pod("weirvern-worker", restarts=2, last_reason="OOMKilled",
                              finished_ago_s=120)])
    check = watchdog.check_pod_restarts(kube, {}, NOW)
    assert check.status == "oomkilled" and "OOMKilled" in check.detail
    assert check.value["counts"] == {"uid-weirvern-worker/worker": 2}


def test_a_restart_count_increase_since_the_last_row_is_detected():
    kube = FakeKube(pods=[pod("weirvern-worker", restarts=3)])
    previous = {"value": json.dumps({"counts": {"uid-weirvern-worker/worker": 2}})}
    check = watchdog.check_pod_restarts(kube, previous, NOW)
    assert check.status == "restart"
    assert "2 -> 3" in check.detail


def test_failed_jobs_ignores_old_failures_and_the_watchdogs_own_jobs():
    kube = FakeKube(jobs=[
        failed_job("weirvern-prune-1", minutes_ago=10),
        failed_job("weirvern-schema-1", minutes_ago=20, kind="FailureTarget"),
        failed_job("weirvern-prune-old", minutes_ago=120),
        failed_job("weirvern-watchdog-abc", minutes_ago=1),
    ])
    check = watchdog.check_failed_jobs(kube, NOW)
    assert check.status == "failed"
    assert "weirvern-prune-1" in check.detail and "weirvern-schema-1" in check.detail
    assert "weirvern-prune-old" not in check.detail
    assert "weirvern-watchdog-abc" not in check.detail


def test_node_disk_and_clickhouse_space_report_pressure_with_numbers(tmp_path):
    assert watchdog.check_node_disk(str(tmp_path), usage=lambda _p: usage(86)).status == "pressure"
    assert watchdog.check_node_disk(str(tmp_path), usage=lambda _p: usage(40)).status == "ok"

    tight = watchdog.check_clickhouse_space(
        FakeCH(free=5 * GIB, total=100 * GIB, largest=1))
    assert tight.status == "pressure" and "merge headroom" in tight.detail
    roomy = watchdog.check_clickhouse_space(
        FakeCH(free=20 * GIB, total=100 * GIB, largest=1))
    assert roomy.status == "ok"


def test_certificate_expiry_has_a_distinct_expiring_state(tmp_path):
    soon = watchdog.check_tls_cert(cert_file(tmp_path, 10), NOW)
    assert soon.status == "expiring" and soon.value["days_left"] < 30
    later = watchdog.check_tls_cert(cert_file(tmp_path, 90), NOW)
    assert later.status == "ok"
    missing = watchdog.check_tls_cert(str(tmp_path / "absent.crt"), NOW)
    assert missing.status == "unreadable"


def test_the_health_probe_turns_unconfigured_delivery_red():
    """The row is not just written; the Health panel reads it and reports the fault."""
    from weirvern.admin import status as status_mod

    class _HealthStub:
        def query(self, sql, *a, **kw):
            assert "weirvern.health" in sql
            return SimpleNamespace(result_rows=[
                ("flows", "ok", "", NOW),
                ("watchdog_delivery", "unconfigured", "PUSHOVER_ENABLED is '0'", NOW),
            ])

    probe = status_mod._watchdog_probe(_HealthStub())
    assert probe.ok is False
    assert "watchdog_delivery=unconfigured" in probe.detail


def test_the_health_probe_states_record_policy_without_going_red():
    """Record-only delivery is policy: said plainly, not painted as a fault."""
    from weirvern.admin import status as status_mod

    class _HealthStub:
        def query(self, sql, *a, **kw):
            assert "weirvern.health" in sql
            return SimpleNamespace(result_rows=[
                ("flows", "ok", "", NOW),
                ("watchdog_delivery", "disabled",
                 "external delivery is off for this version; alerts are recorded", NOW),
            ])

    probe = status_mod._watchdog_probe(_HealthStub())
    assert probe.ok is True
    assert "external delivery off by policy" in probe.detail
    assert "watchdog_delivery=disabled" not in probe.detail


@pytest.mark.parametrize("status_value", ["ok", "stalled", "no_data", "unreadable"])
def test_health_rows_survive_a_reload_with_their_notification_state(status_value):
    row = ["flows", status_value, "detail", "", 3, NOW, NOW]
    previous = watchdog.load_previous(FakeCH(previous_rows=[row]))
    assert previous["flows"]["status"] == status_value
    assert previous["flows"]["consecutive"] == 3
    assert watchdog._as_aware(previous["flows"]["last_notified_at"]) == NOW
