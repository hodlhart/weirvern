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


# Elements that are deliberately not written by JS, each for a reason. Without this
# list the check is noise and gets ignored, which is how a real orphan survives.
#   views/tabs/statusline: toggled by CSS class, not filled with data
#   h-hint: hint text set once in the markup
#   ev-notice-card: shown/hidden, not populated
_STRUCTURAL_IDS = {"view-anomalies", "view-evidence", "view-assets",
              "view-network", "view-models", "view-netflow", "view-zeek", "view-health",
              # view-discover: a structural section toggled by `showView`, like its siblings
              # above; its inner elements are what the scripts populate.
              "view-discover",
              # view-dns / view-blocked: same shape -- the sections are toggled; the
              # view scripts fill them.
              "view-dns",
              "view-blocked",
              #   view-settings: a static skeleton -- loadSettings creates every row
              #     into the st-* hosts, so the section itself is never written to
              "view-settings",
              #   view-logs: the same shape -- a structural section toggled by showView;
              #     its trail and audit tables are what the scripts fill.
              "view-logs",
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
              #   nw-filters: the Network map's filter bar wrapper. Its CHILDREN
              #     (#nw-ripple/#nw-family chips, #nw-subnet, #nw-find, #nw-sort) are the
              #     controls the scripts wire and re-press; the wrapper is layout and is
              #     never written to.
              "nw-filters",
              #   as-scope-note: static copy for the Assets inventory's monitored-only rule. The
              #     server enforces the scope; the span states it, so there is deliberately no
              #     client writer and the id is a test anchor, not an empty placeholder.
              "as-scope-note",
              #   wl-sheet-close / sl-rule-close: the sheets' close controls; sheets.js finds
              #     them by CLASS (.sheet-close), and they carry static text -- never populated
              #   wl-detail-title: the weirling sheet's aria-labelledby target; static text
              "wl-sheet-close", "sl-rule-close", "wl-detail-title",
              #   gate-submit / pw-submit / gate-token-submit: form submit buttons,
              #     handled by their forms' submit events rather than by a getElementById
              #     binding
              #   view-identity: a view SECTION, whose contents (#id-coverage, #id-table's
              #     tbody, #id-count, #id-empty, #id-detail) carry the data. It is
              #     referenced by showView's class toggle rather than by getElementById.
              "view-identity",
              #   view-sluice: the same shape -- a view SECTION toggled by class, whose
              #     contents carry the data (#sl-count, the rules
              #     table's tbody, #sl-empty, #sl-policies, #sl-criticality-note). Listed
              #     explicitly rather than implied by the pattern, so a future section that
              #     really is an orphan cannot hide behind its neighbours.
              "view-sluice",
              #   view-weirlings: the same shape again -- a view SECTION toggled by class,
              #     whose contents carry the data (#wl-summary, #wl-summary-note, the fleet
              #     table's tbody, #wl-count, #wl-empty, #wl-detail-card and its body). The
              #     section itself is never written to by id, which is correct.
              "view-weirlings",
              "gate-submit", "pw-submit", "gate-token-submit"}



def _orphans(html: str, scripts: str) -> set[str]:
    """The orphan scan itself, as a function, so a must-fire check can drive the SAME logic.

    A scanner whose rule is only exercised against the tree it passes on is a snapshot, not a
    guard: the widening below (family lookups) must be provably able to still report an id that
    nothing references.
    """
    ids = set(re.findall(r'id="([a-z][a-z0-9-]*)"', html))
    referenced = set(re.findall(r'getElementById\("([a-z][a-z0-9-]*)"\)', scripts))
    referenced |= set(re.findall(r'for="([a-z][a-z0-9-]*)"', html))
    # THE INFO PANELS' OWN VOCABULARY. The "i" buttons open their panel through
    # `data-info="<id>"` and `wireInfoButtons()`'s getElementById(btn.dataset.info), so the id
    # is referenced without ever appearing as a getElementById literal. This is a WIDENING of
    # the scan, exactly like the soc.js fix below -- the panels really are populated (their
    # prose is static markup) -- never an exemption: an id nothing references is still an orphan.
    referenced |= set(re.findall(r'data-info="([a-z][a-z0-9-]*)"', html))

    # ── FAMILY LOOKUPS, WIDENED (not exempted) ────────────────────────────────────────────────
    #
    # `getElementById(`wl-plan-${field}`)` builds the id from a family, and the loop that does it
    # fills EVERY member with the server's value -- so the family is a reference, exactly the way
    # the CSS-class check above already treats `"prefix-" + x`. Measured when the per-sensor plan
    # editor landed: the five `wl-plan-*` inputs were reported as orphans while their values were
    # being written on every panel open. Adding the ids to the exemption list would have been the
    # opposite of the fix this file's own docstring names; teaching the scanner the shape is the
    # same widening the soc.js case got. An id in NO family is still an orphan.
    families = set(re.findall(r"getElementById\(\s*`([a-z][a-z0-9-]*)-", scripts))
    families |= set(re.findall(r'getElementById\(\s*"([a-z][a-z0-9-]*-)"\s*\+', scripts))
    # `i not in scripts` is the pre-existing broad net (an id appearing anywhere in the JS text);
    # the `structural` set is the documented exemption list, kept as-is.
    return {i for i in ids
            if i not in referenced and i not in scripts and i not in _STRUCTURAL_IDS
            and not any(i.startswith(f) for f in families)}


def test_the_orphan_scanner_still_CATCHES_a_real_orphan():
    """THE MUST-FIRE. The family widening must not swallow an id outside every family, or the
    check would pass on a tree full of blank elements."""
    html = ('<div id="left-behind"></div>'
            '<input id="wl-plan-addr"><input id="wl-plan-targets">')
    scripts = 'getElementById(`wl-plan-${f}`)'
    assert _orphans(html, scripts) == {"left-behind"}, (
        "the scan no longer reports an id that nothing populates")


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
    scripts = "\n".join(p.read_text() for p in sorted(web.glob("*.js")))
    orphans = _orphans(html, scripts)
    assert not orphans, (
        f"HTML elements nothing populates: {sorted(orphans)}. An element that is declared, "
        f"never written to, and has no backend field renders as blank forever -- the "
        f"silent-empty pattern. Either populate it or remove it; if it is deliberately "
        f"structural, add it to the exemption list with a reason."
    )


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
    #
    # ASK FOR THE SAME DATE, NOT TODAY'S. The value under test is a September datetime, and
    # comparing its offset against `now()`'s makes the test calendar-dependent: it passed
    # until US DST ended on 2026-11-01 and has been red ever since, because September is
    # CDT (-5) while November is CST (-6). The assertion is about which timezone gets
    # attached, not about what the offset happens to be this week.
    local_offset = datetime.datetime(2026, 9, 18, 12, 0, 0).astimezone().utcoffset()
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
    from weirvern.db import split_sql_statements as db_split

    schema_dir = ROOT / "weirvern" / "schema"
    # The condition that triggers it: at least one file ends with a comment.
    assert any(p.read_text().rstrip().splitlines()[-1].strip().startswith("--")
               for p in schema_dir.glob("*.sql")), (
        "no schema file ends in a comment any more, so this test no longer exercises the "
        "bug it was written for"
    )

    for path in sorted(schema_dir.glob("*.sql")):
        statements = db_split(path.read_text())
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


# ── a failed query is not an empty result ──────────────────────────────────────────────────────
#
# MEASURED DEFECT (found by triaging an independent audit finding, 2026-09-23). `anomalies_detailed`
# caught every exception, logged at DEBUG, and returned []. The route above it HAS a proper failure
# path -- `except Exception: return self._error(503, ...)` -- which could never run, because the
# function never raised. So a broken query produced HTTP 200 with an empty array and the Anomalies
# view rendered its normal empty state.
#
# That is this project's named failure mode in its most consequential place: an operator looking at
# an empty triage queue on a deployment whose detection query is broken sees "nothing to review",
# which is a statement about the NETWORK rather than about the query. The only trace was a DEBUG log
# line, and no deployment runs at DEBUG.
class _BoomClient:
    """A client whose query always fails, standing in for an unreachable database."""

    def query(self, *a, **k):  # noqa: ANN002, ANN003
        raise RuntimeError("Code: 60. DB::Exception: Table weirvern.netflow_anomalies does not exist")


class _OkClient:
    """A client that answers with a fixed shape, so the success path is exercised too."""

    def query(self, *a, **k):  # noqa: ANN002, ANN003
        class R:
            column_names = ["detected_at", "src_addr", "anomaly_score"]
            result_rows = [("2026-09-23 00:00:00", "198.51.100.9", 0.9)]
        return R()


def test_a_failed_anomalies_query_RAISES_rather_than_reading_as_nothing():
    """The route's 503 path must be reachable.

    Asserting only that the function raises would be weak on its own -- the point is that the
    FAILURE reaches the caller, so the caller can say which it is. A function that returned None
    instead of raising would satisfy "does not return []" while still hiding the failure.
    """
    import pytest as _pytest

    from weirvern.admin import status as status_mod

    with _pytest.raises(Exception):  # noqa: B017, PT011
        status_mod.anomalies_detailed(_BoomClient())


def test_a_working_anomalies_query_still_returns_rows():
    """The converse, so the fix cannot pass by raising unconditionally."""
    from weirvern.admin import status as status_mod

    rows = status_mod.anomalies_detailed(_OkClient())
    assert len(rows) == 1, f"a working query returned {rows!r}"
    assert rows[0]["src_addr"] == "198.51.100.9"


def test_an_empty_result_and_a_failure_are_distinguishable():
    """THE INVARIANT THE PROJECT USES EVERYWHERE.

    Both cases must be tellable apart by the caller. An empty result is [] with no exception; a
    failure is an exception. If a future change makes the failure silent again, this test fails
    while the two above might not -- because it is the only one that compares them.
    """
    import pytest as _pytest

    from weirvern.admin import status as status_mod

    class Empty:
        def query(self, *a, **k):  # noqa: ANN002, ANN003
            class R:
                column_names = ["detected_at", "src_addr", "anomaly_score"]
                result_rows: list = []
            return R()

    empty = status_mod.anomalies_detailed(Empty())
    assert empty == [], f"an empty result should be an empty list, got {empty!r}"
    with _pytest.raises(Exception):  # noqa: B017, PT011
        status_mod.anomalies_detailed(_BoomClient())


def test_the_intercept_heartbeat_uses_the_SAME_identity_the_worker_does(monkeypatch):
    """A live report (2026-10-17): the hub's intercept heartbeat wrote under `Weirvern` -- the
    NODE's hostname, which a hostNetwork pod sees -- while the worker's heartbeat and the GUI's
    gate name derive from NODE_NAME `weirvern`. One hub, two ids differing only in case: the
    registered row read stale while fresh rows appeared under an undeclared name (a phantom
    sensor), and the local sensor could never be matched. sensor_id() must mirror
    worker._sensor_name's precedence: SENSOR_ID, then NODE_NAME, then the hostname."""
    monkeypatch.setenv("SENSOR_ID", "explicit-unit")
    monkeypatch.setenv("NODE_NAME", "weirvern")
    monkeypatch.setenv("HOSTNAME", "Weirvern")
    assert hb.sensor_id() == "explicit-unit"

    monkeypatch.delenv("SENSOR_ID")
    assert hb.sensor_id() == "weirvern", (
        "NODE_NAME must win over the hostname: in a hostNetwork pod the hostname is the "
        "NODE's own, and an id differing from every other writer by case alone splits the "
        "sensor into a stale registered row plus a phantom unregistered one")

    monkeypatch.delenv("NODE_NAME")
    assert hb.sensor_id() == "Weirvern", "a non-cluster run: the hostname IS the box"


def test_the_health_tab_no_longer_carries_a_weirling_card():
    """Operator, 2026-11-19: "can you remove weirling from the health tab?"

    Health is the pipeline's page. The sensor's state lives on the Weirlings tab, where a sensor is
    selected; a second partial copy here made two places to look for one fact.
    """
    root = ROOT
    html = (root / "weirvern" / "admin" / "web" / "index.html").read_text()
    js = (root / "weirvern" / "admin" / "web" / "soc.js").read_text()
    assert 'id="hp-sensor"' not in html
    assert "renderHealthSensor" not in js
    # the payload is still measured -- only the second rendering of it is gone
    assert "hp-checks" in html
