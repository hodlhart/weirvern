"""Sensor heartbeat and staleness tests.

THE RULE THIS PINS: a stale heartbeat must be reported as NOT RUNNING, never as the last
known state.

That is the same failure class this project has already hit three times -- an always-empty
Top Talkers panel, an always-empty Zeek Services panel, and a `ja3` column that could never
populate. Each looked healthy while being wrong. For the sensor panel the stakes are higher
than a blank panel: showing "intercepting 2 hosts" for a sensor that died is a claim that
network traffic is being monitored when it is not.

WHY THE CONFIGURED MODE IS NOT AN ACCEPTABLE ANSWER: the GUI runs in its own pod and has no
access to the sensor's filesystem, so `SENSOR_MODE` in the ConfigMap was all it had. But a
ConfigMap outlives the process reading it -- a siphon sensor that was killed still has
`SENSOR_MODE=siphon` set. A heartbeat is observed; the config is only intended.
"""
from __future__ import annotations

import datetime
import re
from pathlib import Path

import pytest

from weirvern.admin import heartbeat as hb
from weirvern.admin import status

ROOT = Path(__file__).resolve().parents[1]


# ── fakes ───────────────────────────────────────────────────────────────────────


class FakeResult:
    def __init__(self, rows: list[dict]) -> None:
        self._rows = rows

    def named_results(self):
        return iter(self._rows)


class FakeClient:
    def __init__(self, rows: list[dict] | None = None, fail: bool = False,
                 insert_ok: bool = True) -> None:
        self.rows = rows or []
        self.fail = fail
        self.insert_ok = insert_ok
        self.inserts: list[tuple] = []

    def query(self, _sql: str):
        if self.fail:
            raise RuntimeError("simulated query failure")
        return FakeResult(self.rows)

    def insert(self, table: str, data: list, column_names=None):
        if not self.insert_ok:
            raise RuntimeError("simulated insert failure")
        self.inserts.append((table, data, column_names))
        return len(data)


NOW = datetime.datetime(2026, 9, 18, 12, 0, 0)


def _row(**over) -> dict:
    row = {
        "mode": "siphon", "iface": "eth1", "segment": "198.51.100.0/24",
        "hosts": 11, "mappings": 22, "running": 1, "uptime_s": 120.0,
        "restores": 0, "refreshes": 24, "failures": [],
        "ts": NOW - datetime.timedelta(seconds=5),
    }
    row.update(over)
    return row


# ── the staleness rule ──────────────────────────────────────────────────────────


def test_a_fresh_heartbeat_reports_running():
    s = status.sensor_status(FakeClient([_row()]), now=NOW)
    assert s["reported"] is True
    assert s["running"] is True
    assert s["stale"] is False
    assert s["hosts"] == 11
    assert s["mappings"] == 22


def test_a_stale_heartbeat_reports_NOT_running():
    """The property that matters.

    The row still claims running=1 -- that is what it said before it died. Nothing has
    written since, so the claim is worthless and must not be repeated as current.
    """
    old = NOW - datetime.timedelta(seconds=status.HEARTBEAT_STALE_S + 30)
    s = status.sensor_status(FakeClient([_row(ts=old, running=1)]), now=NOW)
    assert s["reported"] is True
    assert s["stale"] is True
    assert s["running"] is False, (
        "a stale heartbeat reported running=1 and was taken at its word; a dead sensor "
        "must never be displayed as intercepting"
    )
    assert s["error"], "a stale sensor must say so, not just show a blank field"
    assert "siphon" in s["error"], "the message should still say which mode it stopped in"


def test_a_heartbeat_just_inside_the_window_is_trusted():
    """No flapping on a single missed write."""
    recent = NOW - datetime.timedelta(seconds=status.HEARTBEAT_STALE_S - 1)
    s = status.sensor_status(FakeClient([_row(ts=recent)]), now=NOW)
    assert s["running"] is True
    assert s["stale"] is False


def test_an_age_is_reported_so_the_operator_can_judge():
    s = status.sensor_status(FakeClient([_row()]), now=NOW)
    assert s["age_s"] == pytest.approx(5.0, abs=0.5)


# ── honest "unknown" states ─────────────────────────────────────────────────────


def test_no_rows_at_all_is_reported_as_never_reported():
    s = status.sensor_status(FakeClient([]), now=NOW)
    assert s["reported"] is False
    assert s["running"] is False
    assert s["error"], "an empty table needs an explanation, not silence"
    assert "not started" in s["error"] or "has not" in s["error"]


def test_a_missing_table_is_not_reported_as_a_dead_sensor():
    """Different facts require different operator actions.

    Before the schema Job runs, the table does not exist. Reporting that as "not running"
    would send an operator hunting for a dead sensor that was never started.
    """
    s = status.sensor_status(FakeClient(fail=True), now=NOW)
    assert s["reported"] is False
    assert s["running"] is False
    assert "unavailable" in (s["error"] or ""), (
        "a query failure must be distinguished from an absent heartbeat"
    )


def test_every_field_is_present_even_when_nothing_reported():
    """So the frontend never has to tell 'key missing' from 'null value'."""
    for client in (FakeClient([]), FakeClient(fail=True)):
        s = status.sensor_status(client, now=NOW)
        for key in ("reported", "running", "stale", "age_s", "mode", "iface",
                    "segment", "hosts", "mappings", "uptime_s", "restores",
                    "refreshes", "failures"):
            assert key in s, f"{key} missing from the sensor payload"


def test_an_unreadable_timestamp_is_not_treated_as_running():
    s = status.sensor_status(FakeClient([_row(ts="not a datetime")]), now=NOW)
    assert s["running"] is False
    assert "unreadable" in (s["error"] or "")


# ── the heartbeat writer ────────────────────────────────────────────────────────


def test_heartbeat_writes_a_row_with_every_field():
    c = FakeClient()
    ok = status.heartbeat(c, sensor_id="sensor-1", mode="siphon", iface="eth1",
                          segment="198.51.100.0/24", hosts=11, mappings=22, running=True,
                          uptime_s=5.0, restores=1, refreshes=3, failures=["stalled"])
    assert ok is True
    table, data, cols = c.inserts[0]
    assert table.endswith("sensor_status")
    values = dict(zip(cols, data[0], strict=True))
    assert values["mode"] == "siphon"
    assert values["hosts"] == 11
    assert values["running"] == 1
    assert values["failures"] == ["stalled"]
    assert values["restores"] == 1


def test_heartbeat_failure_is_reported_not_raised():
    """A sensor that cannot report its status must still capture traffic.

    The cost of a missing heartbeat is a dashboard reading "unknown", which is
    recoverable. The cost of an exception here is a dead sensor.
    """
    ok = status.heartbeat(FakeClient(insert_ok=False), sensor_id="s", mode="loch")
    assert ok is False


class FakeState:
    """A state callable that can fail, to prove the loop survives it."""

    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    def __call__(self) -> dict:
        if self.fail:
            raise RuntimeError("state unavailable")
        return {"mode": "siphon", "running": True, "hosts": 3}


def test_the_loop_records_a_failed_beat_without_dying():
    c = FakeClient()
    loop = hb.HeartbeatLoop(c, state=FakeState(fail=True), name="s1")
    assert loop.beat() is False
    assert loop.failures == 1
    # And it still works when the state recovers.
    loop.state = FakeState(fail=False)
    assert loop.beat() is True
    assert loop.writes == 1


def test_starting_the_loop_beats_immediately_not_after_one_interval():
    """A short-lived run must appear at least once.

    Otherwise a test intercept that lasts 10 seconds never reports, and looks exactly like
    one that never started.
    """
    c = FakeClient()
    loop = hb.HeartbeatLoop(c, state=FakeState(), interval_s=60, name="s2")
    loop.start()
    try:
        for _ in range(50):
            if c.inserts:
                break
            import time
            time.sleep(0.02)
        assert c.inserts, "the first beat waited for a full interval"
    finally:
        loop.stop()


def test_stopping_writes_a_final_not_running_beat():
    """Lets the dashboard say "stopped a minute ago" immediately, rather than after the
    staleness window expires."""
    c = FakeClient()
    loop = hb.HeartbeatLoop(c, state=FakeState(), name="s3")
    loop.beat()
    before = len(c.inserts)
    loop.stop(final=True)
    assert len(c.inserts) == before + 1
    _table, data, cols = c.inserts[-1]
    assert dict(zip(cols, data[0], strict=True))["running"] == 0


# ── the schema ──────────────────────────────────────────────────────────────────


def test_the_schema_defines_sensor_status():
    sql = (ROOT / "weirvern" / "schema" / "003_sensor_status.sql").read_text()
    assert "weirvern.sensor_status" in sql
    for col in ("mode", "running", "ts", "hosts", "mappings", "failures", "restores"):
        assert re.search(rf"^\s+{col}\s", sql, re.M), f"sensor_status.{col} is missing"


def test_the_schema_is_a_heartbeat_not_an_append_log():
    """One row per sensor: heartbeats update, so the table cannot grow without bound."""
    sql = (ROOT / "weirvern" / "schema" / "003_sensor_status.sql").read_text()
    assert "ReplacingMergeTree" in sql, (
        "without a replacing engine every 15s heartbeat appends a row, so a sensor running "
        "a month writes ~170k rows about its own liveness"
    )
    assert re.search(r"ORDER BY\s*\(sensor_id", sql), (
        "the replacing key must be keyed on the sensor, or two sensors would collide"
    )


def test_schema_migration_files_are_ordered():
    """apply_schema globs *.sql sorted, so numbering is what sequences them."""
    names = sorted(p.name for p in (ROOT / "weirvern" / "schema").glob("*.sql"))
    assert names[:3] == ["001_weirvern.sql", "002_zeek_tier1.sql",
                         "003_sensor_status.sql"], names


# ── the GUI must actually render it ─────────────────────────────────────────────


def test_the_gui_has_a_sensor_panel_element():
    """The sensor panel lives on the HEALTH tab.

    It moved there when the Overview tab was removed (the sensor and health panels were merged
    into Health rather than deleted). The assertion follows the panel: a merged panel that no
    test looks for is a panel that can quietly disappear in the next restructure.
    """
    html = (ROOT / "weirvern" / "admin" / "web" / "index.html").read_text()
    assert 'id="hp-sensor"' in html, (
        "the sensor panel container is missing from the Health tab, so the sensor has nowhere "
        "to render"
    )


def test_the_gui_renders_the_sensor_payload():
    """The Health view must render the sensor from the payload it already fetched."""
    js = (ROOT / "weirvern" / "admin" / "web" / "soc.js").read_text()
    assert "sensorLine" in js, "the GUI never renders the sensor payload"
    # It must read the sensor from the /api/health payload rather than a second request, or the
    # sensor's story and the health checks' story can disagree about the same moment.
    assert "d.sensor" in js, "loadHealthDeep does not pass the sensor payload to the renderer"
    assert 'id="hp-sensor"' in (ROOT / "weirvern" / "admin" / "web" / "index.html").read_text()


def test_the_renderer_distinguishes_not_running_from_running():
    """The frontend must not treat a dead sensor as merely stale-looking."""
    js = (ROOT / "weirvern" / "admin" / "web" / "soc.js").read_text()
    body = js[js.index("function sensorLine"):]
    body = body[:body.index("\n}") + 3]
    assert "s.running" in body, (
        "the renderer ignores the running flag; a dead sensor would read as live"
    )
    assert "NOT running" in body or "not running" in body.lower(), (
        "the renderer has no wording for a stopped sensor; the panel would show the mode "
        "with no indication it is dead"
    )
    # "never reported" and "reported but dead" are different facts, and collapsing them would
    # hide a sensor that died from a sensor that was never installed.
    assert "never reported" in body, (
        "the renderer does not distinguish a sensor that never reported from one that stopped"
    )
    assert "intercept_stopped" in body, (
        "the renderer drops the flag warning that an intercept ran and did not restore the node"
    )


def test_the_gui_uses_only_classes_that_exist_in_the_stylesheet():
    """An unknown class renders with NO styling -- so a watchdog failure would look like
    ordinary body text, which is the wrong emphasis for the most important line."""
    js = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()
    css = (ROOT / "weirvern" / "admin" / "web" / "style.css").read_text()
    # Anchor the CSS match to a selector boundary, not just a leading dot: a bare
    # `\.([a-z][a-z0-9-]+)` matches the "k" inside "sev-k..." and the "v" inside
    # ".stat .v", reporting phantom classes. Require the character after the name to end
    # the selector, so only whole class names are collected.
    #
    # Whole names only, and a class built by CONCATENATION cannot be checked this way:
    # `class: "sev-" + s` is a prefix, not a class, and `sev-` alone correctly does not
    # exist in the stylesheet. Such a prefix is verified against the stylesheet's own
    # family instead -- every `sev-*` selector the CSS defines -- because the failure worth
    # catching is a renamed prefix, not the presence of a template.
    known = set(re.findall(r"\.([a-z][a-z0-9-]*)(?![a-z0-9-])", css))
    used = set(re.findall(r'class:\s*"([a-z][a-z0-9- ]*)"', js))
    # A value that is immediately concatenated is a prefix, not a literal class name, so
    # it must not be judged as one. Collect those first and remove them.
    concat_prefixes = set(re.findall(r'class:\s*"([a-z][a-z0-9-]*)"\s*\+', js))
    literal = {c for group in used for c in group.split()
               if c not in known and c not in concat_prefixes}

    # Dynamic prefixes: `"prefix-" + x`. Checked for family existence, not as a class.
    prefixes = set(re.findall(r'class:\s*"([a-z][a-z0-9-]*-)"\s*\+', js))
    known_families = {m.group(1) for m in
                      re.finditer(r"\.([a-z][a-z0-9-]*-)[a-z0-9-]+\s*\{", css)}
    missing = literal | {p for p in prefixes if p not in known_families}
    assert not missing, f"app.js uses CSS classes that do not exist: {sorted(missing)}"


def test_no_orphan_placeholder_elements_remain():
    """An element with an id that nothing populates renders as blank forever.

    `id="about-mode"` was exactly that: declared in the HTML, never written to, and with no
    backend field behind it. That is the silent-empty pattern this project has had to fix
    three times, so it is checked rather than left to review.

    EVERY SCRIPT IS SCANNED, not just app.js. When soc.js was added, its panels were reported
    as orphans because only app.js was read -- the elements WERE populated, just from the
    other file. Widening the scan to the whole web directory is the fix; adding the ids to
    the exemption list would have been the opposite, turning a real check off to accommodate
    the new code.
    """
    web = ROOT / "weirvern" / "admin" / "web"
    html = (web / "index.html").read_text()
    css = (web / "style.css").read_text()
    scripts = "\n".join(p.read_text() for p in sorted(web.glob("*.js")))
    ids = set(re.findall(r'id="([a-z][a-z0-9-]*)"', html))
    referenced = set(re.findall(r'getElementById\("([a-z][a-z0-9-]*)"\)', scripts))
    referenced |= set(re.findall(r'for="([a-z][a-z0-9-]*)"', html))

    # Elements that are deliberately not written by JS, each for a reason. Without this
    # list the check is noise and gets ignored, which is how a real orphan survives.
    #   views/tabs/statusline: toggled by CSS class, not filled with data
    #   h-hint: hint text set once in the markup
    #   ev-notice-card: shown/hidden, not populated
    structural = {"view-anomalies", "view-evidence", "view-host",
                  "view-network", "view-models", "view-netflow", "view-zeek", "view-health",
                  #   view-settings: a static skeleton -- loadSettings creates every row
                  #     into the st-* hosts, so the section itself is never written to
                  "view-settings",
                  "tabs", "statusline", "h-hint",
                  # Deliberately structural, each for a stated reason:
                  #   ev-notice-card: shown/hidden, never filled with data
                  #   zk-drill-card: the Zeek drill-down wrapper, likewise shown/hidden
                  #   nw-detail-card: the graph's click-result wrapper; its CONTENTS
                  #     (#nw-detail, #nw-detail-table) are what get populated
                  "ev-notice-card", "zk-drill-card", "nw-detail-card",
                  #   st-auth-card / st-stage-card: wrappers whose CONTENTS are populated
                  #     (#st-auth-note, #st-stage-list/#st-stage-note); the cards themselves
                  #     are only shown or hidden
                  "st-auth-card", "st-stage-card",
                  #   st-account-card / st-users-card / st-user-add: wrappers the account
                  #     code shows or hides, and whose contents (#st-account-note, the users
                  #     table's tbody, #st-user-result) carry the data
                  "st-account-card", "st-users-card", "st-user-add",
                  #   gate-submit / pw-submit / gate-token-submit: form submit buttons,
                  #     handled by their forms' submit events rather than by a getElementById
                  #     binding
                  #   view-identity: a view SECTION, whose contents (#id-coverage, #id-table's
                  #     tbody, #id-count, #id-empty, #id-detail) carry the data. It is
                  #     referenced by showView's class toggle rather than by getElementById.
                  "view-identity",
                  #   view-sluice: the same shape -- a view SECTION toggled by class, whose
                  #     contents carry the data (#sl-state, #sl-state-note, #sl-count, the rules
                  #     table's tbody, #sl-empty, #sl-policies, #sl-criticality-note). Listed
                  #     explicitly rather than implied by the pattern, so a future section that
                  #     really is an orphan cannot hide behind its neighbours.
                  "view-sluice",
                  "gate-submit", "pw-submit", "gate-token-submit"}

    orphans = {i for i in ids
               if i not in referenced and i not in scripts and i not in structural}
    assert not orphans, (
        f"HTML elements nothing populates: {sorted(orphans)}. An element that is declared, "
        f"never written to, and has no backend field renders as blank forever -- the "
        f"silent-empty pattern. Either populate it or remove it; if it is deliberately "
        f"structural, add it to the exemption list with a reason."
    )
    # And the exemption list must not itself go stale.
    for name in structural:
        assert name in ids or name in css, f"{name} is exempted but no longer exists"


def test_naive_and_aware_timestamps_are_comparable():
    """Mixing them must not raise, in either direction.

    ClickHouse returns AWARE datetimes; `datetime.now()` is NAIVE. Subtracting them raises
    `TypeError: can't subtract offset-naive and offset-aware datetimes` -- which is how
    this first presented, against a real ClickHouse, after the unit tests passed with naive
    fixtures on both sides.

    The values here are chosen so the LOCAL offset cancels out, because the point of this
    test is comparability. The DIRECTION of the labelling is pinned separately in
    test_a_naive_now_is_treated_as_LOCAL_not_UTC, which is where the dangerous bug was.
    """
    local = datetime.datetime.now().astimezone().tzinfo
    assert local is not None
    base = datetime.datetime(2026, 9, 18, 12, 0, 0)

    # Naive `now` against an aware row.
    aware_row = base.replace(tzinfo=local) - datetime.timedelta(seconds=5)
    s = status.sensor_status(FakeClient([_row(ts=aware_row)]),
                             now=base - datetime.timedelta(seconds=0))
    assert s["age_s"] is not None, "comparable datetimes must produce an age"

    # Aware `now` against a naive row.
    s2 = status.sensor_status(FakeClient([_row(ts=base)]), now=base.replace(tzinfo=local))
    assert s2["age_s"] is not None


def test_the_age_is_not_shifted_by_a_timezone_offset():
    """Normalising must not silently move the age by the host's UTC offset.

    Assuming naive-local instead of naive-UTC would make a 5s-old heartbeat read as hours
    stale -- or negative -- depending on where the reader runs, and would also flip
    `running` to false.
    """
    aware_now = datetime.datetime(2026, 9, 18, 12, 0, 0, tzinfo=datetime.UTC)
    fresh = datetime.datetime(2026, 9, 18, 11, 59, 58, tzinfo=datetime.UTC)
    s = status.sensor_status(FakeClient([_row(ts=fresh)]), now=aware_now)
    assert s["age_s"] == pytest.approx(2.0, abs=1.0)
    assert s["stale"] is False


def test_a_naive_now_is_treated_as_LOCAL_not_UTC():
    """The bug that made a dead sensor report running.

    ClickHouse returns tz-aware timestamps in the SERVER's timezone. `datetime.now()` is
    naive and means LOCAL time. Labelling that naive value as UTC shifts every age by the
    container's offset -- this deployment runs TZ=America/Chicago, so a 29-second-old
    heartbeat computed as -17998s.

    A NEGATIVE age is the dangerous part: `stale` is `age > threshold`, so a negative age
    is never stale, and a sensor dead for minutes reported `running: True`. That is exactly
    the failure this feature exists to prevent, so the direction of the labelling is pinned
    here rather than left to a comment.
    """
    aware = status._aware(datetime.datetime(2026, 9, 18, 12, 0, 0))
    assert aware.tzinfo is not None, "a naive datetime was left naive"
    # The attached offset must be this machine's, not zero (unless the machine IS UTC).
    local_offset = datetime.datetime.now().astimezone().utcoffset()
    assert aware.utcoffset() == local_offset, (
        f"naive datetimes are being labelled {aware.utcoffset()} but local time is "
        f"{local_offset}; ages would be shifted by the difference"
    )


def test_an_aware_datetime_passes_through_unchanged():
    aware = datetime.datetime(2026, 9, 18, 12, 0, 0,
                              tzinfo=datetime.timezone(datetime.timedelta(hours=-5)))
    assert status._aware(aware) is aware


def test_a_negative_age_never_happens_for_a_recent_heartbeat():
    """The end-to-end consequence, with both sides in the same real timezone.

    A heartbeat written 'now' must read as roughly zero seconds old, not offset by any
    timezone difference -- and therefore must not be reported as stale or as not running.
    """
    chicago = datetime.timezone(datetime.timedelta(hours=-5))
    written = datetime.datetime.now().astimezone()
    row = _row(ts=written.astimezone(chicago), running=1)
    s = status.sensor_status(FakeClient([row]))
    assert s["age_s"] is not None
    assert s["age_s"] >= 0, (
        f"a just-written heartbeat read as {s['age_s']}s old; a negative age can never "
        f"exceed the staleness threshold, so a dead sensor would report running"
    )
    assert s["age_s"] < 5
    assert s["stale"] is False
    assert s["running"] is True

    # And far in the past in the same zone IS stale.
    old = _row(ts=(datetime.datetime.now() - datetime.timedelta(hours=2)).astimezone(chicago),
               running=1)
    s_old = status.sensor_status(FakeClient([old]))
    assert s_old["age_s"] > status.HEARTBEAT_STALE_S
    assert s_old["stale"] is True
    assert s_old["running"] is False, "a 2-hour-old heartbeat reported running"


def test_the_error_key_is_always_present():
    """The frontend does `if (s.error)`; an absent key is a different shape from null."""
    for client in (FakeClient([]), FakeClient(fail=True), FakeClient([_row()])):
        d = status.sensor_status(client, now=NOW)
        assert "error" in d


# ── schema application ──────────────────────────────────────────────────────────


def test_a_schema_file_ending_in_comments_applies_cleanly():
    """A trailing comment block must not become an "empty query".

    The splitter cuts on `;`, so everything after the last semicolon is a separate chunk --
    and for a file that ends in explanatory comments, that chunk is non-empty TEXT
    containing no SQL. ClickHouse rejects it with "Empty query (SYNTAX_ERROR)", and because
    apply_schema treats any failure as fatal, the whole migration fails.

    Hit for real: this file documents its design in a trailing comment, and the worker
    refused to start with "1 schema statement(s) failed; refusing to report success". Every
    schema file is checked, because the next one to end in a comment would fail the same way.
    """
    from weirvern.db import _SQL_SPLIT, _strip_sql_comments

    schema_dir = ROOT / "weirvern" / "schema"
    # The condition that triggers it: at least one file ends with a comment.
    assert any(p.read_text().rstrip().splitlines()[-1].strip().startswith("--")
               for p in schema_dir.glob("*.sql")), (
        "no schema file ends in a comment any more, so this test no longer exercises the "
        "bug it was written for"
    )

    for path in sorted(schema_dir.glob("*.sql")):
        statements = [s for s in (_strip_sql_comments(raw).strip()
                                  for raw in _SQL_SPLIT.split(path.read_text())) if s]
        assert statements, f"{path.name} produced no statements"
        for stmt in statements:
            assert stmt.strip(), f"{path.name} produced an empty statement"
            # A statement must contain SQL, not only comment text.
            assert not all(line.strip().startswith("--")
                           for line in stmt.splitlines()), (
                f"{path.name} produced a comment-only statement, which ClickHouse rejects "
                f"as an empty query and which fails the entire migration"
            )


def test_the_migration_is_idempotent():
    """Every statement must be safe to re-run: the schema Job runs on every apply."""
    schema_dir = ROOT / "weirvern" / "schema"
    for path in sorted(schema_dir.glob("*.sql")):
        for line in path.read_text().splitlines():
            stripped = line.split("--", 1)[0].strip()
            # A WORD BOUNDARY, not a bare prefix. `.startswith("CREATE")` also matches the column
            # name `created_at`, so every schema with that column failed this check while being
            # perfectly idempotent -- a false failure that trains people to ignore the test.
            if not re.match(r"CREATE\s", stripped, re.I):
                continue
            assert "IF NOT EXISTS" in stripped.upper(), (
                f"{path.name}: '{stripped[:60]}...' is not idempotent, so re-applying the "
                f"schema would fail the Job"
            )
