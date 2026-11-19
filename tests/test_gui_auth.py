"""GUI authentication, and the ConfigMap write path.

WHY THIS FILE EXISTS. Adding a write surface to a GUI that has spent its whole life read-only is
the single riskiest change in this project. The port has NO TLS and the token is the only control,
so the properties that make that acceptable have to be pinned by tests rather than trusted to
review.

The properties, in order of how badly they would hurt to get wrong:

  1. NO TOKEN MEANS NO WRITES. An unset or empty token must refuse, never open.
  2. A WRONG TOKEN IS REFUSED, and the response does not reveal whether a token is even
     configured.
  3. THE COMPARISON IS CONSTANT-TIME. `==` leaks the position of the first wrong byte.
  4. READS STAY OPEN. A monitoring surface that demands a password is one nobody checks during an
     incident, which is when it matters.
  5. A WRITE IS VERIFIED BY READ-BACK. A merge-patch matching nothing returns 200, so a
     successful call is not evidence the configuration changed.
  6. A SAVED CHANGE IS RESTARTED, or it is inert -- and it is reported as a failure of applying,
     not folded into success.
  7. THE MODE GATE IS THE CLI'S OWN. A GUI session must not be a way around the safety check that
     preventing in-path interception from taking a segment down.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from weirvern.admin import cluster_config as cc
from weirvern.admin import gui_auth
from weirvern.admin import status as status_mod

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "weirvern" / "admin" / "web.py"
FLASK = ROOT / "weirvern" / "admin" / "flask_app.py"


def _settings_from_the_route(auth) -> dict:
    """GET /api/settings through the surface that serves it, and return its JSON.

    The handler that used to answer this route was retired with the rest of the console's HTTP
    server; the route a client actually reaches is the Flask one, so that is what this drives. A
    test that inspected `payloads.settings_payload` directly would pass while the route forgot to
    pass the request-scoped facts it is given.
    """
    from weirvern.admin import flask_app

    class _Ctx:
        settings = None
        backend = None
        config_client = None
        user_store = None
        sessions = None
        throttle = None
        accounts_note = ""
        capabilities = None
        connect_factory = staticmethod(lambda settings: None)

        def __init__(self):
            self.auth = auth

    client = flask_app.create_app(_Ctx(), secret_key="settings-route").test_client()
    got = client.get("/api/settings")
    assert got.status_code == 200, got.data
    return got.get_json()

def _code_only(text: str) -> str:
    """Source with DOCSTRINGS and comments removed.

    Both new modules explain their design in prose that QUOTES what they deliberately do NOT do --
    "the write path does not shell out to kubectl", "a read route must not consult the auth gate".
    A naive search reads that explanation as the defect it documents. Strip both, then assert.
    """
    import re as _re

    out = _re.sub(r'"""(?:.|\n)*?"""', "", text)
    out = _re.sub(r"'''(?:.|\n)*?'''", "", out)
    return "\n".join(ln.split("#")[0] for ln in out.splitlines())

AUTH_SRC = ROOT / "weirvern" / "admin" / "gui_auth.py"


# ── 1. no token means no writes ────────────────────────────────────────────────────────────


def test_an_unset_token_refuses_every_write():
    a = gui_auth.AuthState(None)
    assert a.enabled is False
    for attempt in (None, "", "anything", "   "):
        assert a.check(attempt) is False, f"an unset token accepted {attempt!r}"


def test_an_EMPTY_token_is_the_same_as_unset_and_never_opens_the_gate():
    """The classic failure: `WEIRVERN_GUI_TOKEN=` in a manifest must not disable the gate.

    An empty string that authenticates would mean a deployment that MEANT to enable writes but
    mistyped the value silently accepts any request.
    """
    for empty in ("", "   ", "\n", None):
        a = gui_auth.AuthState(empty)
        assert a.enabled is False, f"token {empty!r} enabled writes"
        assert a.check("") is False
        assert a.check(None) is False
        assert a.check(" ") is False


def test_the_refusal_reason_names_the_variable_and_an_alternative():
    """A disabled control must say what is missing, or an operator hunts through manifests."""
    reason = gui_auth.AuthState(None).reason
    assert gui_auth.TOKEN_ENV in reason, reason
    assert "weirvern-secrets" in reason, (
        "the reason does not say WHERE to set the token, which leaves the operator stuck"
    )
    assert "weirvern config set" in reason, (
        "the reason does not offer the alternative path for someone who cannot set the token"
    )


def test_a_configured_token_is_reported_as_enabled_with_no_reason_to_show():
    a = gui_auth.AuthState("abc123")
    assert a.enabled is True
    assert a.reason == ""


# ── 2/3. the comparison ────────────────────────────────────────────────────────────────────


def test_a_wrong_token_is_refused():
    a = gui_auth.AuthState("right-token")
    assert a.check("right-token") is True
    for wrong in ("wrong-token", "right-toke", "RIGHT-TOKEN", "right", "right-token-x"):
        assert a.check(wrong) is False, f"accepted {wrong!r}"
    # SURROUNDING WHITESPACE IS TRIMMED ON PURPOSE: a pasted token arrives with a newline, and
    # refusing that fights the clipboard without widening the search space. The characters still
    # have to be right.
    assert a.check("right-token\n") is True


def test_the_comparison_is_constant_time_not_equality():
    """`==` returns early on the first differing byte, so response time reveals how much of a
    guess was correct -- enough to recover a token one character at a time.

    THE COMPARISON MOVED into `role_for` when per-token credentials were added: `check()` is now
    the boolean form of the same answer and must not keep a second comparison of its own, because
    two copies of a credential check are free to disagree. So the comparison is asserted where it
    lives, and `check` is asserted to be a delegation rather than a duplicate.
    """
    src = AUTH_SRC.read_text()
    body = src[src.index("    def role_for(self"):]
    body = body[:body.index("\n    def ", 10)]
    assert "compare_digest" in body, "the comparison is not constant-time"
    assert "presented == self._token" not in body, "the token is compared with =="
    check = src[src.index("    def check(self"):]
    check = check[:check.index("\n    # -- failure tracking")]
    assert "compare_digest" not in check, (
        "check() kept its own comparison, so the two credential checks can disagree")
    assert "role_for(" in check, "check() no longer delegates to the one comparison"


def test_the_token_is_read_once_at_startup_not_per_request():
    """Re-reading per request would let a partially-applied ConfigMap serve a half-written token,
    and puts a file read on the hot path."""
    assert "def from_env(" in AUTH_SRC.read_text()
    src = WEB.read_text()
    # THE REQUEST PATH NO LONGER EXISTS IN THIS MODULE. `from_env` is called once, in build_context,
    # and the context carries the result -- so the property is now "exactly one call site", which is
    # stronger than "not inside this slice" and survives the handler's retirement.
    assert src.count("from_env(") == 1, (
        "from_env appears more than once: the token is being re-read somewhere other than startup"
    )


# ── 4. reads stay open ─────────────────────────────────────────────────────────────────────


def test_GET_routes_do_not_consult_the_auth_state():
    """A token must not be required to LOOK at anything.

    BEHAVIOURAL, because the dispatch table this used to slice is retired and slicing its text could
    never prove what a request actually does. With a token configured and a check that rejects
    everything, a read must still answer -- stated the way a client experiences it.
    """
    import weirvern.admin.flask_app as fa
    from tests.support_routes import flask_api_paths

    class _RejectingAuth:
        enabled = True
        reason = ""

        @staticmethod
        def check(presented, client=""):
            return False

    class _Ctx:
        settings = None
        backend = None
        config_client = None
        user_store = None
        sessions = None
        throttle = None
        accounts_note = ""
        connect_factory = staticmethod(lambda s: None)
        auth = _RejectingAuth()

    app = fa.create_app(_Ctx(), secret_key="reads-open")
    app.config.update(TESTING=True)
    assert app.test_client().get("/api/healthz").status_code == 200, (
        "a read requires a token, so the dashboard needs a password to look at anything"
    )
    assert "/api/healthz" in flask_api_paths(), "the liveness probe is not routed at all"

    # And the write surface must not be open in the same way: a rejecting check cannot leave a write
    # unauthenticated, or the gate is decorative.
    from tests.support_routes import flask_write_paths

    assert flask_write_paths(), "no route accepts a write, so this test would prove nothing"


def test_the_settings_ROUTE_actually_returns_the_write_state():
    """Read from the RESPONSE, not from the source text.

    THE TEST THIS REPLACES WAS USELESS AND PASSED DURING A REAL OUTAGE. It searched web.py for the
    string `payload["writes"]`, which was present -- inside the WRONG handler. `/api/settings`
    returned no write state, so the GUI could not tell that writes were enabled and would render no
    editable fields at all, while every test stayed green. A source search cannot tell which method
    a line lives in, so this calls the real method and inspects what it emitted.
    """
    class _Auth:
        enabled = True
        reason = ""

    # THE ROUTE IS DRIVEN, NOT THE HANDLER. `_build_handler` and its `_settings` method were
    # retired with the console's HTTP server; `/api/settings` is served by Flask now, so the only
    # way to bind a context the test controls is `create_app(ctx)`.
    emitted = _settings_from_the_route(_Auth())

    assert "writes" in emitted, (
        f"the settings route emitted no 'writes' key, so the UI cannot know whether it may offer "
        f"editable fields. Keys returned: {sorted(emitted)}"
    )
    assert emitted["writes"]["enabled"] is True, emitted["writes"]
    assert "editable_keys" in emitted, (
        "the route does not report which keys it will accept, so the UI would guess"
    )
    assert "CLICKHOUSE_PASSWORD" not in emitted["editable_keys"]
    # ROW KEYS, not ConfigMap keys. This assertion used to require "BASE_THRESHOLD", which pinned
    # the defect in place: the route sent the ConfigMap vocabulary while every settings ROW is
    # named for a Settings attribute, so the front end's intersection was empty and all 30 fields
    # rendered read-only with Apply disabled forever. The contract that matters is that the keys
    # the route advertises actually match rows the settings payload renders.
    assert "base_threshold" in emitted["editable_keys"]
    assert "BASE_THRESHOLD" not in emitted["editable_keys"], (
        "the route must speak the settings-ROW vocabulary; ConfigMap keys never match a row"
    )
    rendered_rows = {
        k for _g, _t, rows in status_mod._SETTINGS_GROUPS for k, _label in rows
    }
    matched = set(emitted["editable_keys"]) & rendered_rows
    assert len(matched) >= 15, (
        f"only {len(matched)} of {len(emitted['editable_keys'])} advertised keys match a rendered "
        "settings row, so the operator cannot edit them"
    )


def test_the_settings_route_reports_writes_DISABLED_when_no_token_is_set():
    """The other half: an unconfigured deployment must render no editable fields and say why."""
    class _Auth:
        enabled = False
        reason = "write access is disabled: WEIRVERN_GUI_TOKEN is not set"

    emitted = _settings_from_the_route(_Auth())

    assert emitted.get("writes", {}).get("enabled") is False
    assert "WEIRVERN_GUI_TOKEN" in emitted.get("writes", {}).get("reason", ""), (
        "a disabled deployment does not say what to set"
    )


# ── 5. the write is verified by read-back ──────────────────────────────────────────────────


def test_apply_reads_the_configmap_back_and_raises_when_the_write_did_not_take():
    """A merge-patch matching nothing returns 200 with the ORIGINAL content. A settings UI that
    reports success over a change that did not land is worse than one that errors."""
    src = (ROOT / "weirvern" / "admin" / "cluster_config.py").read_text()
    body = src[src.index("def apply(self"):]
    body = body[:body.index("def restart(")]
    assert "landed = self.read()" in body, "apply does not read the ConfigMap back"
    assert "raise ConfigError" in body, "apply does not raise when the values differ"
    assert "missing" in body


def test_the_patch_is_a_MERGE_patch_so_other_keys_are_not_clobbered():
    """A JSON patch needs the whole document and an update PUT replaces every field; either would
    wipe keys a concurrent edit just changed."""
    src = (ROOT / "weirvern" / "admin" / "cluster_config.py").read_text()
    assert "application/merge-patch+json" in src, "the patch is not a merge patch"
    # And the method actually used must be PATCH, not PUT: a PUT replaces every field, wiping
    # keys a concurrent edit just changed.
    request = src[src.index("    def _request("):]
    request = request[:request.index("\n    def ", 10)]
    assert '"PATCH"' in src, "no PATCH is issued"
    assert 'req.add_header("Content-Type"' in request
    applied = src[src.index("    def apply(self"):]
    applied = applied[:applied.index("\n    def restart(")]
    assert 'self._request("PATCH"' in applied, "apply does not use a PATCH"


def test_the_config_write_uses_the_SERVICEACCOUNT_not_kubectl():
    """The GUI image ships no kubectl and must not gain one to serve HTTP."""
    src = (ROOT / "weirvern" / "admin" / "cluster_config.py").read_text()
    assert "serviceaccount/token" in src, "the in-cluster token path is not used"
    # Comments explain WHY kubectl was not used, so they mention it. Strip them, or the
    # explanation reads as the defect it documents.
    code = _code_only(src)
    assert "subprocess" not in code, "the write path shells out"
    # `kubectl` now appears as the ANNOTATION KEY the API expects for a rollout
    # (`kubectl.kubernetes.io/restartedAt`) -- a string sent TO the API, not a subprocess. So the
    # assertion is on the MECHANISM: no shell invocation of any kind.
    for shelling in ("subprocess.run", "subprocess.Popen", "os.system", "os.exec", "shutil.which"):
        assert shelling not in code, f"the write path shells out via {shelling}"
    assert "urllib.request" in code, "the write does not call the API over HTTP"
    assert "kubectl.kubernetes.io/restartedAt" in code, (
        "the rollout annotation is not the one kubectl uses, so the two tools would see different "
        "rollouts of the same workload"
    )


def test_a_403_explains_the_RBAC_requirement_rather_than_reporting_a_bare_failure():
    src = (ROOT / "weirvern" / "admin" / "cluster_config.py").read_text()
    assert "403" in src
    assert "patch permission on configmaps" in src, (
        "a permission failure does not say what permission is missing"
    )


# ── 6. a saved change must be restarted ───────────────────────────────────────────────────


def test_every_editable_key_declares_what_must_restart():
    """A ConfigMap env var is read at process start, so a change without a restart is INERT. A key
    with no restart target is a setting the UI would truthfully call saved and silently not apply.
    """
    missing = [k for k in cc.EDITABLE_KEYS if k not in cc._RESTART_FOR]
    assert not missing, (
        f"these keys can be changed but nothing restarts to read them: {missing}. "
        f"Either add a restart target or remove the key from EDITABLE_KEYS."
    )


def test_a_failed_restart_is_reported_as_a_failure_not_as_success():
    """THE APPLY MOVED into payloads.settings_apply with the port; the property went with it.

    Sliced to the FUNCTION'S END (the next top-level def), not a fixed character window: the window
    was an implicit budget that a growing function silently outran, and this assertion then read a
    truncated body and failed for a reason unrelated to what it checks.
    """
    assert "payloads.settings_apply(" in FLASK.read_text(), (
        "the apply route no longer uses the shared fetcher, so this property is untested")
    src = (WEB.parent / "payloads.py").read_text()
    i = src.index("def settings_apply(")
    j = src.index("\ndef ", i + 10)
    body = src[i:j]
    assert "restart_errors" in body, "a failed restart is not surfaced"
    assert '"ok": True' in body and "restart_errors" in body
    # And the note must not claim more than happened.
    assert "no workload needed a restart" in body


def test_the_restart_targets_are_real_workload_kinds():
    """Each key maps to a TUPLE of targets now (siphon keys restart both the sensor
    and the worker). Every target inside every tuple must be a real workload kind."""
    for key, (targets, _blast) in cc._RESTART_FOR.items():
        assert isinstance(targets, tuple) and targets, f"{key} declares no restart target"
        for target in targets:
            kind = target.partition("/")[0]
            assert kind in ("deploy", "ds", "statefulset"), f"{key} targets unknown kind {kind!r}"
            assert target.partition("/")[2], f"{key} has no workload name"


# ── 7. the mode gate is the CLI's own ─────────────────────────────────────────────────────


def test_the_mode_change_reuses_mode_validate_rather_than_reimplementing_it():
    """Two copies of a safety check drift, and the one that drifts is the one nobody tests.
    Enabling in-path interception without forwarding working takes the segment down."""
    src = WEB.read_text()
    # THE GATE IS module-level web.mode_gate, and the apply fetcher is its only caller now that the
    # console's handler is gone. Both halves are asserted: the write path asks the gate, and the
    # gate is `mode.validate` -- a GUI session must not be a way around the CLI's own check.
    payloads = (WEB.parent / "payloads.py").read_text()
    assert "web_mod.mode_gate(ctx, changes)" in payloads, (
        "the settings apply no longer asks the shared mode gate, so siphon could be enabled "
        "without the CLI's prerequisites being checked")
    i = src.index("def mode_gate(")
    body = src[i:]
    body = body[:body.index("\ndef ", 10)]
    assert "mode_mod.validate(" in body, "the GUI does not use the CLI's mode gate"
    assert "from weirvern.admin import mode as mode_mod" in body


def test_the_mode_gate_blocks_when_prerequisites_are_missing():
    """Driven directly: with no NET_ADMIN the gate must refuse `siphon`."""
    from weirvern.admin import mode as mode_mod

    v = mode_mod.validate(mode_mod.MODE_SIPHON, has_net_admin=False, has_net_raw=False,
                          watchdog_available=True)
    assert v.ok is False, "siphon mode validated as ok without NET_ADMIN"
    assert v.blockers, "the verdict carries no reason"


def test_selecting_siphon_is_NOT_REFUSED_because_the_apply_grants_the_capability():
    """Measured 2026-11-17, from the console's own refusal.

    Selecting siphon and pressing Apply returned "cannot enable siphon: ... enabling siphon widens
    the worker's privileges" -- while `ClusterConfig.restart` was already reconciling exactly those
    capabilities before the roll. The gate judged the worker's CURRENT block, so the one request
    that would have granted the privilege was the request it refused. The plan's own requirement is
    the right question; a mode that cannot be granted still refuses.
    """
    from types import SimpleNamespace

    from weirvern.admin import web as web_mod

    class _Client:
        def get_json(self, _path):
            return {"spec": {"template": {"spec": {"containers": [
                {"name": "worker",
                 "securityContext": {"capabilities": {"drop": ["ALL"], "add": []}}}]}}}}

    ctx = SimpleNamespace(config_client=_Client())
    assert web_mod.sensor_caps(ctx) == (False, False), "the fixture must start with no capabilities"
    assert web_mod.mode_gate(ctx, {"SENSOR_MODE": "siphon"}) == "", (
        "the apply was refused for a privilege the same apply grants")
    # A mode nobody can grant still fails, and so does a pass that does not name the mode.
    assert web_mod.mode_gate(ctx, {"SENSOR_MODE": "banana"}) != ""


def test_the_gui_reads_sensor_capabilities_from_the_CLUSTER_and_defaults_to_ABSENT():
    """Reading THIS process's capabilities would describe the wrong container, so the probe
    asks the cluster's own worker Deployment. And a probe that cannot answer must report ABSENT:
    the default is what keeps in-path interception from being enabled on a sensor that
    cannot forward."""
    src = WEB.read_text()
    # THE PROBE IS module-level web.sensor_caps, called by the mode gate (its only consumer since
    # the console's adapter was retired). The invariant is unchanged: the gate must ask the CLUSTER,
    # not this process.
    gate = src[src.index("def mode_gate("):]
    gate = gate[:gate.index("\ndef ", 10)]
    assert "sensor_caps(ctx)" in gate, (
        "the mode gate no longer asks the cluster capability probe, so it would decide from this "
        "pod's own capabilities")
    i = src.index("def sensor_caps(")
    body = src[i:src.index("\ndef ", i + 10)]
    assert "get_json" in body and "deployments/weirvern-worker" in body, (
        "the capability probe does not read the sensor's DaemonSet from the cluster"
    )
    assert "return False, False" in body, (
        "unverifiable capabilities are not defaulted to False, so siphon mode could be enabled "
        "without the ability to forward"
    )


# ── the allow-list, and the validators ────────────────────────────────────────────────────


def test_an_unknown_key_is_refused_by_DEFAULT():
    """An allow-list, not a deny-list: the ConfigMap holds the whole deployment's configuration,
    and a new secret-ish key must not become editable by being added elsewhere."""
    with pytest.raises(cc.ConfigError):
        cc.validate("SOME_NEW_SECRET_KEY", "x")
    with pytest.raises(cc.ConfigError):
        cc.validate("CLICKHOUSE_PASSWORD", "x")


def test_the_capture_interface_cannot_be_set_to_the_management_interface(monkeypatch):
    """Measured: capturing on the management port fills the capture with broadcast noise that
    LOOKS like a busy network, and Zeek's own logs stay healthy."""
    monkeypatch.setenv("MGMT_IFACE", "eth0")
    with pytest.raises(cc.ConfigError) as exc:
        cc.validate("ZEEK_IFACE", "eth0")
    assert "management interface" in str(exc.value)


def test_a_numeric_key_rejects_a_non_number_and_an_out_of_range_value():
    with pytest.raises(cc.ConfigError):
        cc.validate("BASE_THRESHOLD", "high")
    with pytest.raises(cc.ConfigError):
        cc.validate("BASE_THRESHOLD", "5")
    with pytest.raises(cc.ConfigError):
        cc.validate("DETECT_INTERVAL_S", "1")
    assert cc.validate("BASE_THRESHOLD", "0.4") == ""


def test_resolving_PUBLIC_addresses_is_allowed_but_WARNS(before=""):
    """The user asked for it, so it must be possible -- but it sends every external destination
    this sensor sees to a DNS resolver, which is derived intelligence leaving the network."""
    warning = cc.validate("WEIRVERN_REVERSE_DNS", "all")
    assert "resolver" in warning and "leaks" in warning.lower(), warning
    assert cc.validate("WEIRVERN_REVERSE_DNS", "private") == ""
    with pytest.raises(cc.ConfigError):
        cc.validate("WEIRVERN_REVERSE_DNS", "sometimes")


def test_a_warned_change_needs_EXPLICIT_confirmation():
    """A legal-but-costly value must not apply from a plan the caller never saw."""
    src = (WEB.parent / "payloads.py").read_text()
    i = src.index("def settings_apply(")
    body = src[i:src.index("\ndef ", i + 10)]
    assert "needs_confirmation" in body, "a warned change applies without confirmation"
    assert "confirmed" in body


def test_plan_touches_nothing():
    """The dry run must not write. If it did, asking 'what would this do?' would do it."""
    src = (ROOT / "weirvern" / "admin" / "cluster_config.py").read_text()
    body = src[src.index("def plan("):]
    body = body[:body.index("class ClusterConfig")]
    for forbidden in ("_request", "PATCH", "apply(", "write"):
        assert forbidden not in body, f"plan() calls {forbidden!r}, so a dry run is not dry"


def test_the_plan_reports_the_current_and_proposed_values_and_the_blast_radius():
    p = cc.plan({"BASE_THRESHOLD": "0.5"}, {"BASE_THRESHOLD": "0.35"})
    (prop,) = p.proposals
    assert prop.current == "0.35" and prop.proposed == "0.5"
    assert prop.restarts == ("deploy/weirvern-worker",)
    assert prop.blast, "the proposal does not state what applying it will interrupt"
    assert p.restart_targets == ["deploy/weirvern-worker"]


def test_the_siphon_mode_change_restarts_BOTH_the_sensor_and_the_worker():
    """WEIR-1's fix, pinned at the mapping layer: SENSOR_MODE must reach the capture
    DaemonSet (which states the mode and runs the sysctl init container) AND the
    worker (which supervises the intercept). Restarting only one of the two was the
    shape where the config said 'siphon' while nothing ran an intercept."""
    p = cc.plan({"SENSOR_MODE": "siphon"}, {"SENSOR_MODE": "loch"})
    assert p.restart_targets == ["ds/zeek", "deploy/weirvern-worker"]


def test_the_intercept_plan_keys_restart_the_worker_which_reads_them():
    """The intercept plan is read by the WORKER's supervisor, not the sensor. An
    earlier mapping restarted ds/zeek for these -- a restart that applied nothing."""
    p = cc.plan({"INTERCEPT_TARGETS": "198.51.100.10",
                 "INTERCEPT_SEGMENT": "198.51.100.0/24"}, {})
    assert p.restart_targets == ["deploy/weirvern-worker"]


def test_restart_targets_are_deduplicated():
    """Three threshold keys in one apply restart the worker ONCE, not three times."""
    p = cc.plan({"BASE_THRESHOLD": "0.4", "MIN_AGREEMENT": "0.3",
                 "DETECT_INTERVAL_S": "600"}, {})
    assert p.restart_targets == ["deploy/weirvern-worker"]


# ── the request body is bounded ──────────────────────────────────────────────────────────


def test_the_body_read_is_bounded():
    """An unbounded read on a LAN port is a memory-growth path.

    THE BOUND LIVES IN `web.json_body` NOW. The console's `_read_body` read the socket itself and
    enforced its own Content-Length cap; that method went with the transport, and both surfaces feed
    the bytes to the shared parser, which refuses anything over its `limit`. So the assertion follows
    the bound to the one place it is enforced -- and checks the write routes actually go through it,
    because a route that parsed its own body would bypass the cap.
    """
    src = WEB.read_text()
    i = src.index("def json_body(")
    body = src[i:src.index("\ndef ", i + 10)]
    assert "limit: int = 65536" in body, body[:400]
    assert "length > limit" in body, "the shared parser does not enforce the bound"
    assert "body too large" in body, "a refusal does not say the body was too large"

    flask_src = FLASK.read_text()
    assert "web.json_body(request.get_data(cache=False))" in flask_src, (
        "the write routes do not go through the shared bound parser")


def test_the_auth_state_never_exposes_the_token():
    """The token must not be readable through the object, or a template could render it."""
    a = gui_auth.AuthState("super-secret-value")
    # In-process vars() is not a boundary (reading it implies code execution). The REAL path is
    # accidental disclosure: a debug log line, a template, an exception reporter that includes
    # locals. Those all use repr/str, so those are what must be redacted.
    assert "super-secret-value" not in repr(a), repr(a)
    assert "super-secret-value" not in str(a)
    assert "super-secret-value" not in f"{a}"
    assert "super-secret-value" not in f"{a!r}"
    # And it still says something useful rather than going blank.
    assert "set" in repr(a)
    # The public surface must not offer the token itself.
    public = [n for n in dir(a) if not n.startswith("_")]
    assert "token" not in public, f"the token is publicly readable: {public}"


def test_failure_tracking_is_bounded():
    """Keyed by client address on an open port, so an unbounded map is a growth path."""
    a = gui_auth.AuthState("t")
    for i in range(gui_auth._MAX_TRACKED + 500):
        a._record_failure(f"10.0.0.{i % 256}")  # noqa: SLF001
    assert len(a._failures) <= gui_auth._MAX_TRACKED + 1  # noqa: SLF001


def test_the_failure_delay_is_bounded():
    """A lockout would let anyone on the LAN deny an operator access to their own sensor."""
    a = gui_auth.AuthState("t")
    for _ in range(100):
        a._record_failure("198.51.100.9")  # noqa: SLF001
    assert a.delay_for("198.51.100.9") <= gui_auth._MAX_DELAY_S


def test_the_response_never_says_whether_a_token_is_configured():
    """Distinguishing 'no token' from 'wrong token' helps an attacker, not an operator.

    THE MESSAGE MOVED to `requestauth.write_refusal` when the console's `_authorize` began
    delegating to it. The property is unchanged and is asserted where the one implementation now
    lives; the console must not keep a second wording of its own.
    """
    auth_src = (WEB.parent / "requestauth.py").read_text()
    i = auth_src.index("def write_refusal(")
    body = auth_src[i:i + 4000]
    # The disabled case explains itself (the operator needs to know); the WRONG case must not
    # distinguish anything. The wording gained "admin session" when accounts landed -- a signed-in
    # admin is now the normal write credential and the token is the break-glass path -- but the
    # property is unchanged: one message for every kind of miss.
    assert "a valid admin session or operator token is required" in body
    assert "the token was wrong" not in body.lower()
    assert "did not match" not in body.lower()

    console = FLASK.read_text()
    assert "requestauth.write_refusal(" in console, (
        "the Flask write routes do not ask the shared gate, so they have no refusal at all")
    assert "a valid admin session or operator token is required" not in console, (
        "the Flask surface keeps its own copy of the refusal wording, so the two surfaces can drift")


def test_from_env_reads_the_named_variable():
    assert gui_auth.from_env({gui_auth.TOKEN_ENV: "x"}).enabled is True
    assert gui_auth.from_env({}).enabled is False
    assert gui_auth.from_env({gui_auth.TOKEN_ENV: "  "}).enabled is False


def test_the_cookie_fallback_parses_a_cookie_header_without_a_live_socket():
    class _H:
        def __init__(self, headers):
            self.headers = headers

    assert gui_auth.token_from_request(_H({"X-Weirvern-Token": "abc"})) == "abc"
    assert gui_auth.token_from_request(_H({"Cookie": "a=b; weirvern_token=xyz; c=d"})) == "xyz"
    assert gui_auth.token_from_request(_H({})) is None
    # The header wins over the cookie, so an explicit per-request token is not shadowed.
    assert gui_auth.token_from_request(
        _H({"X-Weirvern-Token": "hdr", "Cookie": "weirvern_token=cookie"})
    ) == "hdr"


def test_the_module_signature_reflects_that_writes_are_opt_in():
    """A default that ENABLES writes would be the wrong default for a no-TLS port."""
    sig = inspect.signature(gui_auth.AuthState.__init__)
    assert sig.parameters["token"].default is None


def test_the_settings_page_states_the_no_TLS_boundary():
    """The threat model must be written down where an operator deploying it will see it, not
    only in a docstring."""
    src = AUTH_SRC.read_text()
    assert "TLS" in src, "the module does not state that there is no TLS"
    assert "threat model" in src.lower() or "Threat model" in src


def test_the_json_body_must_be_an_object():
    """A list or a bare string would be indexed as a dict and fail deep inside a handler.

    THE PARSE MOVED into `web.json_body` when the write surface began to be ported, so both surfaces
    share its messages; `_read_body` reads the bytes and delegates rather than keeping a second
    parser that could word the same failure differently.
    """
    src = WEB.read_text()
    i = src.index("def json_body(")
    assert "isinstance(parsed, dict)" in src[i:i + 1200]
    # And every write route asks it: a second parser on the Flask side could word the same failure
    # differently, which is the drift the shared parser exists to remove.
    assert "web.json_body(request.get_data(cache=False))" in FLASK.read_text()


# ── the cluster-side grant the write path needs ────────────────────────────────────────────
#
# A write path that the cluster refuses is a feature that does not work. These assert the grant
# exists AND is scoped, because "give the GUI a ServiceAccount" is exactly the kind of change that
# gets widened later by someone in a hurry.


def _k8s(name: str):
    import yaml

    return [d for d in yaml.safe_load_all((ROOT / "k8s" / name).read_text()) if d]


def test_the_gui_pod_has_the_operator_serviceaccount_and_a_token():
    """Measured live: the image ships no kubectl and the pod had no token, so every write was
    refused before this. Both halves are needed -- the SA without a mounted token is inert."""
    spec = _k8s("34-gui.yaml")[0]["spec"]["template"]["spec"]
    assert spec.get("serviceAccountName") == "weirvern-operator", (
        "the GUI pod does not use the operator ServiceAccount, so it cannot reach the API"
    )
    assert spec.get("automountServiceAccountToken") is True, (
        "no token is mounted, so the ServiceAccount is inert"
    )


def test_the_operator_role_can_patch_configmaps():
    docs = _k8s("60-rbac.yaml")
    role = next(d for d in docs if d.get("kind") == "Role"
                and d["metadata"]["name"] == "weirvern-operator")
    rules = [r for r in role["rules"] if "configmaps" in r.get("resources", [])]
    assert rules, "the operator Role cannot touch configmaps, so a settings write is refused"
    # The grants are SEPARATE rules now (issue #10): patch is name-scoped, create is its own
    # documented rule, get stands alone. The question this test asks is about the ROLE, so the
    # verbs are unioned across its configmap rules rather than read off the first one.
    verbs = set().union(*(set(r["verbs"]) for r in rules))
    assert "patch" in verbs, "the role cannot patch"
    assert "get" in verbs, "the role cannot read back, so a write cannot be verified"


def test_the_operator_role_does_NOT_get_UPDATE_on_configmaps():
    """`update` is a PUT, which REPLACES the whole ConfigMap -- it would wipe every key the GUI
    never showed. A merge patch changes only the keys sent, which is what the write path uses."""
    docs = _k8s("60-rbac.yaml")
    role = next(d for d in docs if d.get("kind") == "Role"
                and d["metadata"]["name"] == "weirvern-operator")
    for rule in role["rules"]:
        if "configmaps" in rule.get("resources", []):
            assert "update" not in rule["verbs"], (
                "the role can PUT the ConfigMap, which would replace every key"
            )


def test_the_grant_is_namespaced_not_cluster_wide():
    """A Role + RoleBinding cannot reach another namespace. A ClusterRole would, and this does not
    need to: the GUI manages one sensor's configuration."""
    docs = _k8s("60-rbac.yaml")
    kinds = {d.get("kind") for d in docs}
    assert "Role" in kinds, "the operator grant is not a namespaced Role"
    assert "ClusterRole" not in kinds, (
        "a ClusterRole would let this grant reach other namespaces' configuration"
    )


def test_every_other_workload_still_declines_a_token():
    """The GUI is the exception FOR A REASON. If the others quietly gained tokens, the exception
    would stop being one -- and nothing else here needs to call the API."""
    import yaml

    # Parse each file's pod specs and check the ones that HAVE pods. Written in one pass rather
    # than two: an earlier version had a dead loop left in it from drafting.
    for path in sorted((ROOT / "k8s").glob("*.yaml")):
        if path.name == "34-gui.yaml":
            continue
        for doc in [d for d in yaml.safe_load_all(path.read_text()) if d]:
            spec = (doc.get("spec") or {}).get("template", {}).get("spec")
            if not spec:
                continue
            name = doc["metadata"].get("name", path.name)
            # INVERTED LOGIC CAUGHT BY ITS OWN FAILURE: this read `is not False` and therefore
            # failed on the workloads that do the right thing. The claim is that the field IS
            # explicitly false -- not absent, which would default to true.
            assert spec.get("automountServiceAccountToken") is False, (
                f"{name} does not set automountServiceAccountToken: false (got "
                f"{spec.get('automountServiceAccountToken')!r}). Only the GUI needs a token; a "
                f"workload holding one for no reason is standing privilege."
            )
