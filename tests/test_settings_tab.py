"""The Settings tab: effective configuration, read-only, secrets redacted.

WHY THIS FILE EXISTS. Settings is the one view that reads a configuration object, and a
configuration object is the one place in this codebase that holds CREDENTIALS. The GUI is served
on a LAN port with NO authentication, so "what this endpoint returns" is effectively public to
anyone who can reach the port -- which makes redaction a security property rather than a
formatting choice, and one that must be pinned by a test rather than trusted to review.

Three properties are asserted, in order of importance:

  1. A secret's VALUE never appears in the payload -- checked against the real value, so a
     redaction that silently stopped working fails loudly.
  2. An unset secret is distinguishable from a hidden one ("(not set)" vs "(set, N chars)").
     An operator debugging an authentication failure needs to tell those apart, and collapsing
     them would be the "empty looks the same as broken" pattern this project keeps fixing.
  3. The view is READ-ONLY. There is no write route, and the panel says so in words -- because
     a page that shows settings without stating its boundary invites the reader to hunt for a
     Save button that does not exist.
"""

from __future__ import annotations

import re
from pathlib import Path

from weirvern.admin import status

WEB = Path(__file__).resolve().parent.parent / "weirvern" / "admin" / "web"
SECRET = "sup3r-s3cr3t-value-do-not-leak"


class _Settings:
    """A settings object carrying a recognisable secret value."""

    clickhouse_password = SECRET
    pushover_token = SECRET
    clickhouse_user = "default"
    clickhouse_host = "clickhouse"
    clickhouse_port = 8123
    clickhouse_db = "weirvern"
    retrain_every_h = 6
    retrain_window_h = 72
    detect_interval_s = 300
    base_threshold = 0.35
    min_agreement = 0.33
    strong_signal = 0.85
    sensor_mode = "loch"
    capture_password = False
    pushover_enabled = True
    # Deliberately absent: pushover_user, so the "not set" path is exercised.


def _flat(payload: dict) -> dict[str, dict]:
    return {r["key"]: r for rows in payload["groups"].values() for r in rows}


# ── 1. the value must not leak ─────────────────────────────────────────────────────────────


def test_no_secret_value_appears_anywhere_in_the_payload():
    """The strongest check: search the SERIALISED payload for the real value."""
    import json

    payload = status.settings_overview(settings=_Settings(), namespace="weirvern")
    blob = json.dumps(payload)
    assert SECRET not in blob, (
        "a credential value appears in the settings payload. This GUI is served without "
        "authentication, so anything it returns is readable by anyone who can reach the port."
    )


def test_a_secret_is_reported_by_name_and_length_only():
    row = _flat(status.settings_overview(settings=_Settings()))["clickhouse_password"]
    assert row["secret"] is True
    assert row["value"] == f"(set, {len(SECRET)} chars)", row["value"]
    assert SECRET not in str(row["value"])


def test_redaction_is_by_NAME_PATTERN_so_a_new_secret_is_caught_automatically():
    """A deny-list of exact names would miss the next credential someone adds."""
    for name in ("api_token", "webhook_secret", "foo_password", "private_key",
                 "some_credential", "user_passwd"):
        assert status._redact(name, "hunter2") == "(set, 7 chars)", (
            f"{name} is not recognised as a secret. Redaction keys off the name pattern so a "
            f"credential added later is covered without editing a list of exact names."
        )


def test_an_ordinary_setting_is_shown_in_full():
    """Redaction must not be so aggressive that it hides the configuration."""
    row = _flat(status.settings_overview(settings=_Settings()))["retrain_every_h"]
    assert row["value"] == 6
    assert row["secret"] is False
    assert _flat(status.settings_overview(settings=_Settings()))["sensor_mode"]["value"] == "loch"


# ── 2. set vs unset must be distinguishable ────────────────────────────────────────────────


def test_an_unset_secret_reads_as_not_set_rather_than_as_hidden():
    """`(not set)` and `(set, N chars)` are different facts and must not collapse."""
    rows = _flat(status.settings_overview(settings=_Settings()))
    # Derived, not hardcoded: a second copy of the number is a copy that can drift.
    assert rows["pushover_token"]["value"] == f"(set, {len(SECRET)} chars)"   # present in stub
    assert rows["pushover_user"]["value"] == "(not set)"                      # absent in stub
    assert rows["pushover_token"]["secret"] is True
    assert rows["pushover_user"]["secret"] is True


def test_a_boolean_setting_reads_as_enabled_or_disabled():
    """A bare True/False in a config table reads as a raw value rather than a state."""
    rows = _flat(status.settings_overview(settings=_Settings()))
    assert rows["pushover_enabled"]["value"] == "enabled"
    assert rows["capture_password"]["value"] == "disabled"


# ── 3. read-only, and said so ──────────────────────────────────────────────────────────────


def test_there_is_no_write_route_for_settings():
    """The GUI must not accept a configuration write over an unauthenticated port."""
    src = (WEB.parent / "web.py").read_text()
    # Any POST/PUT handler would show up as a do_POST/do_PUT method.
    assert "def do_POST" not in src, (
        "web.py handles POST, so some route accepts a write. This GUI has no authentication and "
        "must stay read-only."
    )
    assert "def do_PUT" not in src and "def do_DELETE" not in src
    # And the settings route must be a GET-only read.
    i = src.find("def _settings")
    assert i > 0, "the settings handler is gone"
    body = src[i : i + 1400]
    assert "_json(" in body, "the settings handler does not return a JSON payload"
    assert "insert" not in body.lower() and "update " not in body.lower(), (
        "the settings handler appears to write something"
    )


def test_the_view_states_that_it_is_read_only_and_where_to_change_things():
    """A settings page that does not say this invites a hunt for a Save button."""
    app_js = (WEB / "app.js").read_text()
    index = (WEB / "index.html").read_text()
    assert "cannot change them" in index or "read-only" in index.lower(), (
        "the Settings markup does not state that it cannot change the configuration"
    )
    assert "weirvern config set" in index, (
        "the page does not say where the settings CAN be changed, which leaves the reader stuck"
    )
    assert "never in value" in app_js, (
        "the panel does not explain why a secret shows no value"
    )


# ── the tab restructure ────────────────────────────────────────────────────────────────────


def test_the_overview_tab_is_gone_and_health_is_the_landing_view():
    index = (WEB / "index.html").read_text()
    assert 'data-view="overview"' not in index, "the Overview tab is still in the nav"
    assert 'id="view-overview"' not in index, "the Overview section is still present"
    # Health must be FIRST and active, since it inherited the landing role.
    tabs = re.findall(r'class="tab([^"]*)" data-view="(\w+)"', index)
    assert tabs, "no tabs parsed -- update this test"
    assert tabs[0][1] == "health", f"the first tab is {tabs[0][1]!r}, expected health"
    assert "active" in tabs[0][0], "the first tab is not the active one"


def test_the_moved_panels_exist_on_the_health_tab():
    """Sensor and the health checks must be reachable after the move, not lost with Overview."""
    index = (WEB / "index.html").read_text()
    for element in ("hp-sensor", "hp-checks", "hp-ingest", "hp-tables"):
        assert f'id="{element}"' in index, (
            f"#{element} is missing from Health; the Overview removal lost a panel"
        )


def test_no_dead_references_to_the_removed_overview_remain():
    """A renderer targeting a removed element silently no-ops, which is worse than deleting it."""
    scripts = "\n".join(
        (WEB / name).read_text() for name in ("app.js", "soc.js", "assets.js")
    )
    code = re.sub(r"/\*.*?\*/", "", scripts, flags=re.S)
    code = re.sub(r"^\s*//.*$", "", code, flags=re.M)
    for dead in ("sensor-body", "overview-anomalies", "talkers-table", "talkers-chart",
                 "health-table", "loadOverview", "renderSensor"):
        assert dead not in code, (
            f"{dead!r} is still referenced in code but its element/function is gone -- it "
            f"would silently do nothing"
        )


def test_the_settings_tab_is_in_the_nav_and_is_its_own_section():
    index = (WEB / "index.html").read_text()
    assert 'data-view="settings"' in index, "the Settings tab is not in the nav"
    assert 'id="view-settings"' in index, "the Settings section does not exist"
    app_js = (WEB / "app.js").read_text()
    assert "loadSettings" in app_js, "nothing loads the Settings view"
    src = (WEB.parent / "web.py").read_text()
    assert '"/api/settings"' in src, "there is no /api/settings route"
