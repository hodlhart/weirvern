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

ROOT = Path(__file__).resolve().parent.parent
WEB = ROOT / "weirvern" / "admin" / "web.py"

def _code_only(text: str) -> str:
    """Source with DOCSTRINGS and comments removed.

    Both new modules explain their design in prose that QUOTES what they deliberately do NOT do --
    "the write path does not shell out to kubectl", "a read route must not consult the auth gate".
    A naive search reads that explanation as the defect it documents, which is the same trap the
    ATT&CK mapper's docstrings set earlier in this project. Strip both, then assert.
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
    guess was correct -- enough to recover a token one character at a time."""
    src = AUTH_SRC.read_text()
    body = src[src.index("    def check(self"):]
    body = body[:body.index("\n    def ", 10)]
    assert "compare_digest" in body, "the comparison is not constant-time"
    assert "presented == self._token" not in body, "the token is compared with =="


def test_the_token_is_read_once_at_startup_not_per_request():
    """Re-reading per request would let a partially-applied ConfigMap serve a half-written token,
    and puts a file read on the hot path."""
    assert "def from_env(" in AUTH_SRC.read_text()
    src = WEB.read_text()
    # The handler must not call from_env per request.
    handler = src[src.index("        def do_POST(self"):]
    handler = handler[:handler.index("\n        def _route_post")]
    assert "from_env(" not in handler, (
        "the request path re-reads the token from the environment; it must be read once"
    )


# ── 4. reads stay open ─────────────────────────────────────────────────────────────────────


def test_GET_routes_do_not_consult_the_auth_state():
    """A token must not be required to LOOK at anything."""
    src = WEB.read_text()
    # `_route` dispatches every READ route; it ends at the next method, `_static`.
    get_route = src[src.index("        def _route(self)"):]
    get_route = get_route[:get_route.index("\n        def _static(")]
    assert "_authorize" not in get_route, (
        "a read route consults the auth gate, so the dashboard needs a password"
    )
    # Strip comments first: the explanation of WHY reads stay open mentions auth, and a naive
    # search reads that prose as the defect it documents.
    assert "ctx.auth" not in _code_only(get_route), "a read route references the auth state"


def test_the_settings_read_reports_whether_writes_are_possible():
    """The UI has to know, or it cannot disable the controls or explain why."""
    src = WEB.read_text()
    i = src.index('payload["writes"]')
    snippet = src[i:i + 400]
    assert '"enabled"' in snippet and '"reason"' in snippet, snippet


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
    assert "kubectl" not in code, "the write path shells out to kubectl"
    assert "urllib.request" in code, "the write does not call the API over HTTP"


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
    src = WEB.read_text()
    i = src.index("def _settings_apply(")
    body = src[i:i + 4000]
    assert "restart_errors" in body, "a failed restart is not surfaced"
    assert '"ok": True' in body and "restart_errors" in body
    # And the note must not claim more than happened.
    assert "no workload needed a restart" in body


def test_the_restart_targets_are_real_workload_kinds():
    for key, (target, _blast) in cc._RESTART_FOR.items():
        kind = target.partition("/")[0]
        assert kind in ("deploy", "ds", "statefulset"), f"{key} targets unknown kind {kind!r}"
        assert target.partition("/")[2], f"{key} has no workload name"


# ── 7. the mode gate is the CLI's own ─────────────────────────────────────────────────────


def test_the_mode_change_reuses_mode_validate_rather_than_reimplementing_it():
    """Two copies of a safety check drift, and the one that drifts is the one nobody tests.
    Enabling in-path interception without forwarding working takes the segment down."""
    src = WEB.read_text()
    i = src.index("        def _mode_gate(self")
    body = src[i:]
    body = body[:body.index("\n        def ", 10)]
    assert "mode_mod.validate(" in body, "the GUI does not use the CLI's mode gate"
    assert "from weirvern.admin import mode as mode_mod" in body


def test_the_mode_gate_blocks_when_prerequisites_are_missing():
    """Driven directly: with no NET_ADMIN the gate must refuse `weir`."""
    from weirvern.admin import mode as mode_mod

    v = mode_mod.validate(mode_mod.MODE_WEIR, has_net_admin=False, has_net_raw=False,
                          watchdog_available=True)
    assert v.ok is False, "weir mode validated as ok without NET_ADMIN"
    assert v.blockers, "the verdict carries no reason"


def test_the_gui_does_not_assume_sensor_capabilities_it_cannot_verify():
    """Answering from THIS process's namespace would describe the wrong container. Absent a
    positive answer the gate must report False, which refuses rather than permits."""
    src = WEB.read_text()
    i = src.index("def _sensor_caps(")
    body = src[i:i + 1200]
    assert "return False, False" in body, (
        "unverifiable capabilities are not defaulted to False, so weir mode could be enabled "
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
    src = WEB.read_text()
    i = src.index("def _settings_apply(")
    body = src[i:i + 3000]
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
    assert prop.restarts == "deploy/weirvern-worker"
    assert prop.blast, "the proposal does not state what applying it will interrupt"
    assert p.restart_targets == ["deploy/weirvern-worker"]


def test_restart_targets_are_deduplicated():
    """Three threshold keys in one apply restart the worker ONCE, not three times."""
    p = cc.plan({"BASE_THRESHOLD": "0.4", "MIN_AGREEMENT": "0.3",
                 "DETECT_INTERVAL_S": "600"}, {})
    assert p.restart_targets == ["deploy/weirvern-worker"]


# ── the request body is bounded ──────────────────────────────────────────────────────────


def test_the_body_read_is_bounded():
    """An unbounded read on a LAN port is a memory-growth path."""
    src = WEB.read_text()
    i = src.index("def _read_body(")
    body = src[i:i + 900]
    assert "limit" in body and "Content-Length" in body
    assert "65536" in body or "limit:" in body, body[:400]


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
    """Distinguishing 'no token' from 'wrong token' helps an attacker, not an operator."""
    src = WEB.read_text()
    i = src.index("def _authorize(")
    body = src[i:i + 2000]
    # The disabled case explains itself (the operator needs to know); the WRONG case must not
    # distinguish anything.
    assert "a valid operator token is required" in body
    assert "the token was wrong" not in body.lower()
    assert "did not match" not in body.lower()


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
    """A list or a bare string would be indexed as a dict and fail deep inside a handler."""
    src = WEB.read_text()
    i = src.index("def _read_body(")
    assert "isinstance(parsed, dict)" in src[i:i + 900]


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
    verbs = set(rules[0]["verbs"])
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
