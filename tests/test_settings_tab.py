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
    pushover_api_token = SECRET
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
    # Real field names: the `pushover_user`/`pushover_token` spellings do not exist and read
    # "(not set)" even when Pushover is configured -- caught by reading the live endpoint.
    assert rows["pushover_api_token"]["value"] == f"(set, {len(SECRET)} chars)"
    assert rows["pushover_user_key"]["value"] == "(not set)"   # absent in this stub
    assert rows["pushover_api_token"]["secret"] is True
    assert rows["pushover_user_key"]["secret"] is True


def test_a_boolean_setting_reads_as_enabled_or_disabled():
    """A bare True/False in a config table reads as a raw value rather than a state."""
    rows = _flat(status.settings_overview(settings=_Settings()))
    assert rows["pushover_enabled"]["value"] == "enabled"
    # `capture_password` is NOT a Settings field (verified by grep) so it is no longer a row;
    # the boolean-rendering rule it used to exercise is covered by pushover_enabled above and by
    # test_a_boolean_is_never_treated_as_a_secret below.
    assert rows["pushover_enabled"]["secret"] is False


# ── 3. read-only, and said so ──────────────────────────────────────────────────────────────


def test_every_write_route_consults_A_GATE():
    """The invariant changed shape twice, and this test changed with it.

    It used to assert there was NO write route at all -- right while the GUI had no
    authentication. Then: every write route consults the auth gate. Now accounts exist, so
    there are two legitimate shapes and every route must have one of them:

      * an admin-gated write (`self._authorize()`), or
      * a session-gated account route (`/api/logout`, `/api/password` -- every account may
        sign out and change its own password), or
      * the sign-in door itself (`/api/login`), which cannot require a session because it is
        how a session is obtained; it carries its own throttle instead.

    An `_authorize()`-less route that is none of those is the defect: an unauthenticated
    configuration change. The allow-list is EXPLICIT so adding a new write route without a
    gate fails this test rather than passing quietly.
    """
    src = (WEB.parent / "web.py").read_text()

    # There must be a write surface, and it must be a POST (never a GET, which browsers and
    # prefetchers issue without intent).
    assert "def do_POST" in src, "no write surface exists"
    assert "def do_GET" in src
    for unsafe in ("def do_PUT", "def do_DELETE"):
        assert unsafe not in src, f"{unsafe} would be an unaudited write path"

    # Every POST route must be gated one way or another.
    SESSION_GATED = {"_logout", "_password"}
    DOOR = {"_login"}
    route = src[src.index("        def _route_post(self"):]
    route = route[:route.index("\n        def ", 10)]
    handlers = [ln.split("return self.")[1].strip().rstrip("()") for ln in route.splitlines()
                if "return self." in ln]
    assert handlers, "no POST routes parsed -- update this test"
    for name in handlers:
        body = src[src.index(f"        def {name}(self"):]
        body = body[:body.index("\n        def ", 10)]
        if name in DOOR:
            assert "throttle" in body or "Throttle" in body, (
                "the sign-in route carries no throttle, so passwords can be guessed at wire "
                "speed"
            )
            continue
        if name in SESSION_GATED:
            assert "_require_session()" in body, (
                f"the account route {name} does not require a session"
            )
            continue
        assert "self._authorize()" in body, (
            f"the write route {name} does not consult the auth gate, so it accepts an "
            f"unauthenticated configuration change"
        )

    # And the settings READ stays a read.
    i = src.find("def _settings")
    assert i > 0, "the settings handler is gone"
    body = src[i : i + 2200]
    assert "_json(" in body, "the settings handler does not return a JSON payload"


def test_the_view_states_when_it_is_read_only_and_when_it_is_not():
    """The settings page must state the boundary honestly -- BOTH states, because both are real.

    The copy used to assert unconditionally that the page could not change anything. That was
    true before the write path existed and became FALSE when it shipped: two static strings
    contradicted the auth card beside them (which correctly reported writes as enabled), and a
    reader had to guess which one the page meant. The rule now is that the strings reflect the
    server's `writes` answer, so the two cannot disagree.
    """
    app_js = (WEB / "app.js").read_text()
    index = (WEB / "index.html").read_text()
    # The markup states the conditional case, not a flat claim.
    assert "read-only" in index.lower(), (
        "the Settings markup does not mention the read-only case at all"
    )
    assert "cannot change them" not in index, (
        "the markup still asserts unconditionally that the page cannot change the values; with "
        "the token write path live that contradicts the auth card"
    )
    assert "weirvern config set" in index, (
        "the page does not say where the settings CAN be changed, which leaves the reader stuck"
    )
    # The rendered note must be conditional on the server's answer, not one fixed string.
    assert "writesOn" in app_js or "writes && data.writes.enabled" in app_js or \
        "data.writes" in app_js, (
        "the rendered note does not consult the server's `writes` state, so it can contradict it"
    )
    assert "never in value" in app_js, (
        "the panel does not explain why a secret shows no value"
    )


# ── the tab restructure ────────────────────────────────────────────────────────────────────


def test_the_overview_tab_is_gone_and_health_is_the_landing_view():
    """Health is the LANDING view (it inherited the role when Overview was removed) and it is
    no longer the FIRST tab.

    Those were two facts that happened to coincide while Health sat at the head of the nav, and
    this test asserted them as one. The operator asked for Health to sit between Models and
    Settings, which separates them: the landing view is not always the leftmost tab, and a tab
    bar whose active entry is not the first one is entirely ordinary.
    """
    index = (WEB / "index.html").read_text()
    assert 'data-view="overview"' not in index, "the Overview tab is still in the nav"
    assert 'id="view-overview"' not in index, "the Overview section is still present"
    tabs = re.findall(r'class="tab([^"]*)" data-view="(\w+)"', index)
    assert tabs, "no tabs parsed -- update this test"
    order = [k for _c, k in tabs]
    assert "health" in order, "the Health tab is not in the nav at all"
    active = [k for c, k in tabs if "active" in c]
    assert active == ["health"], (
        f"the landing tab is {active!r}, expected exactly ['health'] -- it inherited the landing "
        f"role from Overview"
    )
    # TH-3 regrouped the nav: Health now LEADS the first group (Operations) and Settings
    # closes the last (Console). The invariant this test keeps: the landing tab exists, is
    # active, and sits in the nav's first group -- the eye starts where the landing view is.
    assert "models" in order and "settings" in order, f"nav is {order}"
    first_group = re.search(r'data-group="([\w-]+)">.*?data-view="(\w+)"', index, re.S)
    assert first_group and first_group.group(2) == "health", (
        f"Health must lead the nav's first group, but the first group is {first_group!r}"
    )


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


def test_the_sensor_controls_live_in_the_weirlings_drill_down():
    """The operator, 2026-10-17: "Pull weirling settings out of settings tab... I want the
    weirlings tab to have each sensor its nics, a sonar button, and a mode selection. And
    status." This SUPERSEDES the 2026-10-16 "settings page behind a selector" design.

    The honest boundary is unchanged -- a runtime can only be changed on the box that runs the
    sensor -- so the drill-down shows the controls for the LOCAL row (the runtime's own box)
    and hides them, rather than lying, for every other selection.
    """
    index = (WEB / "index.html").read_text()
    settings = index.split('id="view-settings"')[1].split("</section>")[0]
    weirlings = index.split('id="view-weirlings"')[1].split("</section>")[0]
    for element in ("st-sensor", "st-sonar", "st-test", "wl-mode-select", "wl-runtime"):
        assert f'id="{element}"' in weirlings, f"#{element} is not in the Weirlings view"
        assert f'id="{element}"' not in settings, (
            f"#{element} is still mounted on the Settings page; the panel moved to the "
            f"sensor's drill-down"
        )
    assert 'id="st-wl-select"' not in settings, "the scrapped weirling selector survives"
    assert 'id="wl-id"' not in index, "the standalone register card survives"
    # The NICs must render per sensor -- the operator asked for them by name.
    assert "NICs" in (WEB / "weirlings.js").read_text()


# ── the version row, which reported a version the deployment was not running ───────────────
#
# Found by reading the LIVE endpoint rather than the tests: the Settings page said 0.4.0 while
# the deployment ran 0.5.6. The package's `__version__` literal had never been bumped, so the
# page confidently told an operator they were running a version they were not -- and a wrong
# version makes every other row on that page suspect. These tests pin the fix.


def test_the_version_row_comes_from_the_running_image_not_the_package_literal():
    """The running image is authoritative; the package literal drifts."""
    from weirvern.admin.runtime import ServiceState

    class _Backend:
        def ps(self):
            return [
                ServiceState(name="weirvern-gui", state="running",
                             image="weirvern-worker:9.9.9"),
                ServiceState(name="weirvern-worker", state="running",
                             image="weirvern-worker:9.9.9"),
            ]

    payload = status.settings_overview(settings=_Settings(), backend=_Backend())
    rows = _flat(payload)
    assert rows["version"]["value"] == "9.9.9", (
        "the version row did not read the running image. Report (unknown) rather than the "
        "package literal -- a plausible wrong version is worse than an absent one."
    )


def test_the_version_row_prefers_the_gui_image():
    """The page IS the GUI, so its own image is the closest answer."""
    from weirvern.admin.runtime import ServiceState

    class _Backend:
        def ps(self):
            return [
                ServiceState(name="weirvern-worker", state="running", image="weirvern-worker:1.1.1"),
                ServiceState(name="weirvern-gui", state="running", image="weirvern-worker:2.2.2"),
            ]

    rows = _flat(status.settings_overview(settings=_Settings(), backend=_Backend()))
    assert rows["version"]["value"] == "2.2.2"


def test_the_version_row_falls_back_to_the_package_literal_without_a_backend():
    """The GUI pod normally CANNOT reach the cluster.

    Measured: the image ships no `kubectl` and the Deployment sets
    automountServiceAccountToken: false, so the backend is None on the real deployment. Reporting
    "(unknown)" there would tell an operator nothing while they are trying to confirm what they
    are running -- and the live endpoint did exactly that until this fallback was added.

    The literal is safe to fall back to ONLY because a test now pins it to the image tag; that
    test is the reason this fallback is not the original bug again.
    """
    import weirvern

    rows = _flat(status.settings_overview(settings=_Settings(), backend=None))
    assert rows["version"]["value"] == weirvern.__version__


def test_the_measured_image_tag_wins_over_the_package_literal():
    """A measurement of what is deployed beats a statement about the code."""
    from weirvern.admin.runtime import ServiceState

    class _Backend:
        def ps(self):
            return [ServiceState(name="weirvern-gui", state="running",
                                 image="weirvern-worker:7.7.7")]

    rows = _flat(status.settings_overview(settings=_Settings(), backend=_Backend()))
    assert rows["version"]["value"] == "7.7.7"


def test_the_namespace_row_resolves_from_runtime_rather_than_rendering_unknown():
    """It read '(unknown)' live because the caller passed nothing. runtime.NAMESPACE is the
    single definition the backends use, so asking it cannot disagree with the cluster."""
    rows = _flat(status.settings_overview(settings=_Settings()))
    assert rows["namespace"]["value"] == "weirvern"


def test_no_row_is_reported_for_a_field_that_does_not_exist():
    """`capture_password` was listed and is NOT a Settings field -- it exists only in prose
    comments. A row with no field behind it shows '(not set)' forever, which is the
    silent-empty pattern this project keeps having to fix.

    `strong_signal` was in this list too, and the fix was the opposite one: rather than
    deleting the row, the field was given a REAL Settings attribute and wired into the
    ensemble, because the GUI advertised it as editable while nothing read the env var --
    an edit that validated and changed nothing. Both directions are covered here: a row
    must never exist without a field, and a field the GUI advertises must be readable.
    """
    from weirvern.config import Settings

    payload = status.settings_overview(settings=Settings())
    keys = {r["key"] for rows in payload["groups"].values() for r in rows}
    assert "capture_password" not in keys, (
        "capture_password is reported but is not a Settings field"
    )
    assert "strong_signal" in keys, (
        "strong_signal lost its settings row, but it is now a real Settings field the GUI "
        "advertises as editable -- removing the row would hide a working control"
    )
    # The settings object really carries it, so the row can never show '(not set)' for a
    # field that does not exist.
    assert hasattr(Settings(), "strong_signal")
    # Every remaining key must either BE a Settings attribute or be marked as env-only. A row
    # that is neither is a row with nothing behind it, which can only ever show "(not set)".
    payload_all = status.settings_overview(settings=Settings())
    offenders = []
    for rows in payload_all["groups"].values():
        for r in rows:
            if r["source"] == "setting" and not hasattr(Settings(), r["key"]):
                offenders.append(r["key"])
            elif r["source"] == "env" and hasattr(Settings(), r["key"]):
                offenders.append(r["key"] + " (marked env but IS a setting)")
    assert not offenders, (
        f"these rows misdeclare where their value comes from, so a blank renders the same as a "
        f"missing field: {offenders}"
    )
    # The env-only rows are legitimate but must be labelled.
    env_rows = {r["key"] for rows in payload_all["groups"].values() for r in rows
                if r["source"] == "env"}
    assert env_rows, "no env-sourced rows at all; the provenance field is not being set"
    for k in ("intercept_segment", "intercept_addr", "intercept_gateway"):
        assert k in env_rows, f"{k} should be reported as an env-sourced key"


def test_the_pushover_rows_use_the_real_field_names():
    """`pushover_user` does not exist; the fields are pushover_user_key / pushover_api_token.
    The wrong names read '(not set)' while Pushover was in fact configured."""
    rows = _flat(status.settings_overview(settings=_Settings()))
    for real in ("pushover_user_key", "pushover_api_token"):
        assert real in rows, f"{real} is missing from the Settings rows"
    assert "pushover_user" not in rows and "pushover_token" not in rows
    # The Pushover user KEY is a credential and must be treated as one.
    assert rows["pushover_user_key"]["secret"] is True


def test_the_package_version_matches_the_image_tag_declared_in_the_transformer():
    """The root cause of the wrong-version bug: nothing tied the two together.

    The image tag lives in k8s/kustomization.yaml and the package version in
    weirvern/__init__.py, and they drifted (0.4.0 vs 0.5.6) with no check to notice. A version
    that appears in three places must be asserted in one.
    """
    import re as _re

    import weirvern

    kustom = (Path(__file__).resolve().parent.parent / "k8s" / "kustomization.yaml").read_text()
    m = _re.search(r'name:\s*weirvern-worker\s*\n\s*newTag:\s*"([^"]+)"', kustom)
    assert m, "the image tag is no longer declared in kustomization.yaml"
    tag = m.group(1)
    assert weirvern.__version__ == tag, (
        f"weirvern/__init__.py says {weirvern.__version__} but the image tag is {tag}. Bump "
        f"both together -- the Settings page reports one and the deployment runs the other."
    )


def test_a_boolean_is_never_treated_as_a_secret():
    """`capture_password` name-matches "password" but is a switch, not a credential. Hiding it
    as "(not set)" removed exactly the fact an operator needs: are we capturing passwords?"""
    assert status._redact("capture_password", False) == "disabled"
    assert status._redact("capture_password", True) == "enabled"
    assert status._is_secret("capture_password") is True  # it IS name-flagged...
    # ...but the bool branch wins, so its VALUE is still reported. The two are different
    # questions: "is this sensitive" and "is this value a switch".
    assert status._redact("pushover_enabled", True) == "enabled"


def test_every_row_declares_where_its_value_came_from():
    """Provenance, so a blank is not ambiguous.

    Three rows for NON-EXISTENT fields rendered as "(not set)" and survived review, because
    "the field does not exist" and "the field is unset" looked identical. Now each row says
    whether it came from the settings object, the environment, or was derived.
    """
    payload = status.settings_overview(settings=_Settings(), backend=None)
    for rows in payload["groups"].values():
        for r in rows:
            assert r["source"] in ("setting", "env", "derived", "cluster"), (
                f"{r['key']} has source={r['source']!r}"
            )
    derived = {r["key"] for rows in payload["groups"].values() for r in rows
               if r["source"] == "derived"}
    for k in ("reverse_dns", "namespace", "version"):
        assert k in derived, f"{k} is computed, not read from Settings, so it must say 'derived'"


def test_rows_render_the_LIVE_configmap_when_the_caller_has_it():
    """THE MEASURED BUG. After an operator applied SENSOR_MODE=siphon (and the intercept
    was demonstrably running), the Settings tab still rendered `loch` -- because rows were
    built from the GUI pod's env, read once at startup, and a settings change restarts the
    WORKER, not the GUI. With the live ConfigMap passed in, the cluster's value wins."""
    live = {"SENSOR_MODE": "siphon", "INTERCEPT_SEGMENT": "198.51.100.0/24",
            "INTERCEPT_ADDR": "198.51.100.250", "INTERCEPT_GATEWAY": "198.51.100.1",
            "INTERCEPT_TARGETS": "*"}
    rows = _flat(status.settings_overview(settings=_Settings(), configmap=live))
    assert rows["sensor_mode"]["value"] == "siphon", (
        "the tab is rendering the pod's frozen startup view, not the cluster's live config"
    )
    assert rows["sensor_mode"]["source"] == "cluster"
    # The intercept plan rows were the OTHER half of the same report: they rendered blank
    # ("(not set)") although the cluster had a complete plan.
    assert rows["intercept_segment"]["value"] == "198.51.100.0/24"
    assert rows["intercept_addr"]["value"] == "198.51.100.250"
    assert rows["intercept_gateway"]["value"] == "198.51.100.1"
    assert rows["intercept_targets"]["value"] == "*"


def test_the_configmap_does_not_override_secrets_or_derived_rows():
    """A ConfigMap row for a secret does not exist, and `derived` rows (namespace, version,
    reverse_dns) come from their own sources by definition. Feeding a hostile map must not
    change either -- a secret value can never be smuggled into the payload this way."""
    hostile = {"PUSHOVER_API_TOKEN": "should-not-appear", "CLICKHOUSE_PASSWORD": "nor-this",
               "SENSOR_MODE": "siphon"}
    payload = status.settings_overview(settings=_Settings(), configmap=hostile)
    text = str(payload)
    assert "should-not-appear" not in text
    assert "nor-this" not in text
    rows = _flat(payload)
    # The secret rows still report set/not-set by their OWN path, never the map's value.
    assert rows["pushover_api_token"]["value"] == f"(set, {len(SECRET)} chars)"
    assert rows["pushover_api_token"]["source"] != "cluster"
    # Derived rows keep their sources.
    assert rows["version"]["source"] == "derived"


def test_without_a_configmap_the_previous_behavior_is_exact():
    """Workstation runs and tests pass None; the row sources then are the original three,
    so nothing about a cluster-less deployment changes."""
    rows = _flat(status.settings_overview(settings=_Settings()))
    assert rows["sensor_mode"]["source"] == "setting"
    assert rows["sensor_mode"]["value"] == "loch"
