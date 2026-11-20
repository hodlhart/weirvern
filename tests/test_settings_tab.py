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

from tests.support_routes import routed
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
    """Every write route refuses an anonymous caller.

    THE INVARIANT CHANGED SHAPE TWICE. It used to assert there was NO write route at all -- right
    while the GUI had no authentication. Then: every write route consults the auth gate, checked by
    grepping each handler for `self._authorize()`. The handler is retired, so the question is now
    asked BEHAVIOURALLY: build the real app over a context with no token and no accounts, POST to
    EVERY write route the URL map publishes, and require a refusal.

    WHY THIS IS STRONGER THAN THE GREP. A source search can be satisfied by a gate call in a branch
    that is never reached, or by a route that parses its body before gating. This drives the route
    in its most permissive deployment state -- the one where an unauthenticated write would be a
    configuration change -- and fails on anything but a 401/403. The allow-list is implicit and
    total: every POST is tested, so a new ungated write route fails here rather than passing
    quietly.
    """
    import re

    from tests.support_routes import _Ctx, flask_api_paths, flask_write_paths
    from weirvern.admin import flask_app

    # THERE MUST BE A WRITE SURFACE, AND IT MUST REFUSE THE UNSAFE VERBS. A PUT or DELETE accepted
    # here would be an unaudited write path.
    writes = flask_write_paths()
    assert writes, "no write surface exists"
    assert flask_api_paths(), "no read surface exists"

    app = flask_app.create_app(_Ctx(), secret_key="verbs")
    allowed = set()
    for rule in app.url_map.iter_rules():
        allowed |= set(rule.methods or ())
    # PUT AND PATCH ARE STILL BANNED OUTRIGHT -- nothing here needs them, and an accepted one would
    # be an unaudited write path. DELETE is legitimate now (`/api/scan-jobs/<id>` takes a queued
    # scan back), so it is not banned by verb: it is DRIVEN below with every other write route and
    # has to refuse an anonymous caller like the rest.
    for unsafe in ("PUT", "PATCH"):
        assert unsafe not in allowed, f"{unsafe} would be an unaudited write path"

    client = app.test_client()
    unrefused = []
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith("/api/"):
            continue
        verbs = set(rule.methods or ()) - {"GET", "HEAD", "OPTIONS"}
        if not verbs:
            continue
        # A parameterised rule is driven with a concrete value so it reaches its view; the body is
        # empty because the gate must answer BEFORE the body is read.
        path = re.sub(r"<[^>]+>", "probe", rule.rule)
        for verb in sorted(verbs):
            got = client.open(path, method=verb, json={})
            if got.status_code not in (401, 403):
                unrefused.append(f"{verb} {path} -> {got.status_code}: {got.data[:100]!r}")
    assert not unrefused, (
        f"these write routes answered an anonymous caller without refusing: {unrefused}. Each one "
        f"must consult requestauth.write_refusal (or the _gate_write/_write_json helper that is "
        f"its only wrapper) before doing anything else")

    # And the settings READ stays a read: a GET, answering the payload that carries the write state.
    got = client.get("/api/settings")
    assert got.status_code == 200, got.data
    assert "writes" in (got.get_json() or {}), "the settings read does not return a JSON payload"

    # THE SIGN-IN DOOR KEEPS ITS THROTTLE. It is the one route that cannot require a session, so a
    # refusal alone would not prove anything about guess-rate: the credential check must go through
    # `payloads.login`, which delegates to the shared, throttled `requestauth.authenticate`.
    admin = Path(__file__).resolve().parent.parent / "weirvern" / "admin"
    flask_py = (admin / "flask_app.py").read_text()
    login_view = flask_py.split("def api_login(", 1)[1].split("    @app.", 1)[0]
    assert "payloads.login(" in login_view, (
        "the sign-in route does not delegate to the shared credential check, so there is no "
        "throttle and passwords can be guessed at wire speed")
    payloads_py = (admin / "payloads.py").read_text()
    login_fetcher = payloads_py.split("def login(", 1)[1].split("\ndef ", 1)[0]
    assert "requestauth.authenticate(" in login_fetcher, (
        "the shared sign-in fetcher does not use requestauth.authenticate, where the throttle lives")


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
    # The operator moved Health to sit between Models and Settings. The landing view is
    # still Health, but it no longer leads the nav; the order is the invariant.
    assert "models" in order and "settings" in order, f"nav is {order}"
    assert order.index("models") < order.index("health") < order.index("settings"), (
        f"Health is not between Models and Settings: {order}"
    )


def test_the_moved_panels_exist_on_the_health_tab():
    """Sensor and the health checks must be reachable after the move, not lost with Overview."""
    index = (WEB / "index.html").read_text()
    for element in ("hp-checks", "hp-ingest", "hp-tables"):
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
    assert routed("/api/settings"), "there is no /api/settings route"


def test_the_local_weirlings_sheet_owns_its_settings_and_settings_does_not():
    """The operator, 2026-10-18: "remove weirling settings from the settings tab and move it to
    the weirling pop out on the weirling tab. Selecting a weirling opens the settings for that
    specific one."

    This REVERSES the pin that stood here earlier the same day, which said Settings owned the
    sensor controls. The 2026-10-17 attempt failed by DUPLICATING the grid into the sheet and
    leaving Settings' Sensor card empty; the answer is a MOVE -- the controls exist once, in the
    local weirling's sheet, and Settings keeps only what is not a weirling's (Detection, DNS,
    Sluice, Blocklists, Storage).
    """
    index = (WEB / "index.html").read_text()
    settings = index.split('id="view-settings"')[1].split("</section>")[0]
    weirlings = index.split('id="view-weirlings"')[1].split("</section>")[0]
    for element in ("st-sensor", "st-sonar", "st-test", "wl-mode-select"):
        assert f'id="{element}"' in weirlings, f"#{element} is not in the local weirling's sheet"
        assert f'id="{element}"' not in settings, (
            f"#{element} is still mounted on Settings; the controls were supposed to move, "
            f"not be copied"
        )
    # The moved controls live in the LOCAL section, never in the plan editor for a remote sensor.
    local = weirlings.split('id="wl-local-settings"')[1].split('id="wl-plan"')[0]
    for element in ("st-sensor", "st-sonar", "st-test", "wl-mode-select", "wl-stage-apply"):
        assert f'id="{element}"' in local, f"#{element} is outside the local settings section"
    # The duplicate disclosure and the standalone register card are still gone.
    assert 'id="wl-advanced"' not in index, "the duplicate Advanced disclosure survives"
    assert 'id="wl-runtime"' not in index, "the sheet's runtime wrapper survives"
    assert 'id="st-wl-select"' not in settings, "the scrapped weirling selector survives"
    assert 'id="wl-id"' not in index, "the standalone register card survives"
    # DNS-view behaviour moved out of the sensor group and off the weirlings view.
    assert 'id="st-dns"' in settings, "the DNS group has no card on Settings"
    assert 'id="st-dns"' not in weirlings, "the DNS group leaked onto the weirlings view"
    # The NICs must still render per sensor -- the operator asked for them by name.
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
    # THE OVERLAY MAY PIN A SHA TAG, AND THEN IT NAMES A BUILD RATHER THAN A RELEASE (issue #69).
    # What must never happen is a pin that matches neither: a number that drifts from the code, or
    # a floating tag. scripts/verify_versions.sh checks the same rule; this is the copy the suite
    # runs without shelling out.
    if tag.startswith("sha-"):
        assert _re.fullmatch(r"sha-[0-9a-f]{7,40}", tag), (
            f"the kustomize pin {tag!r} is not a sha-<commit> tag, so it names nothing reproducible"
        )
    else:
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
