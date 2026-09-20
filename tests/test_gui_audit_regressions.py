"""The GUI/API defects the audit found, pinned.

The shape of every failure here is the same one this project keeps producing: something that
CANNOT BE MEASURED rendered identically to something measured to be ZERO. A dead settings form
looked like a settings form. A failed query looked like a quiet host. An unrunnable panel looked
like a panel with nothing in it. Each test asserts the distinction, not the pixels.
"""
from __future__ import annotations

from pathlib import Path

from weirvern.admin import cluster_config as cc
from weirvern.admin import status as status_mod

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text()
HTML = (ROOT / "weirvern" / "admin" / "web" / "index.html").read_text()


# ── the settings form that could never be edited ───────────────────────────────

def test_the_advertised_editable_keys_match_the_rows_the_ui_renders():
    """The route sent ConfigMap keys (BASE_THRESHOLD); every settings ROW is named for a Settings
    attribute (base_threshold). The intersection the front end computes was therefore EMPTY: all
    30 rows rendered read-only and Apply was disabled permanently.

    The whole token/plan/apply path was unreachable from the GUI while the server would have
    accepted a POST -- a feature that was "shipped" and invisible.
    """
    # The route emits ROW keys (web.py maps each ConfigMap key through to_row_key). Test what the
    # route actually sends, not the raw table -- asserting on the raw table would have passed while
    # the wire format was wrong, which is exactly how this shipped.
    rows = {k for _g, _t, entries in status_mod._SETTINGS_GROUPS for k, _label in entries}
    advertised = {cc.to_row_key(k) for k in cc.EDITABLE_KEYS}
    matched = advertised & rows
    assert len(matched) >= 15, (
        f"only {len(matched)} of {len(advertised)} advertised keys name a rendered settings row; "
        "the operator cannot edit the rest and nothing on screen says so"
    )


def test_every_editable_key_has_a_configmap_key_to_write():
    """Each advertised key must translate to a real ConfigMap key. Four differ by more than case
    (WEIRVERN_EXCLUDE_CIDRS), so a blanket .lower()/.upper() could not round-trip them."""
    for key in cc.EDITABLE_KEYS:
        row = cc.to_row_key(key)
        back = cc.to_configmap_key(row)
        assert back == key, f"{key} -> {row} -> {back} does not round-trip"
        assert row in {r for _g, _t, es in status_mod._SETTINGS_GROUPS for r, _l in es} or \
            row == "strong_signal", f"{row} names no settings row"


def test_the_row_to_configmap_table_covers_only_real_editable_keys():
    """A mapping entry for a key that is not editable, or a ConfigMap key no row can edit, is a
    silent no-op: the UI would offer it and the apply would reject it."""
    for row, cm in cc.ROW_TO_CONFIGMAP.items():
        assert cm in cc.EDITABLE_KEYS, f"{row} maps to {cm}, which is not editable"


def test_el_supports_value_so_inputs_are_not_blank():
    """el() handled class/text/title/attrs/on but NOT `value`. The settings builder passes
    `value: shown`, so every editable field would have rendered EMPTY -- the operator could not
    see the value they were about to change, and a stray keystroke could stage an empty string
    over a working setting. Latent behind the casing bug above."""
    assert "opts.value" in JS, (
        "el() has no `value` support, so an <input> built with a value renders blank"
    )
    # And the settings builder must be using it.
    assert "value: shown" in JS or "value: " in JS


# ── the panels that could not say why they were empty ───────────────────────────

def test_the_host_drilldown_carries_its_subquery_failures():
    """status.host_detail records a failed sub-query in `_errors`; host_payload dropped it, so a
    broken query rendered as "No flows from <addr>" -- identical to a host that sent nothing, on
    the view an analyst opens to answer exactly that question. The evidence view already threaded
    its errors through; this one did not."""
    src = (ROOT / "weirvern" / "admin" / "web_api.py").read_text()
    start = src.index("def host_payload(")
    body = src[start:src.index("\n\ndef ", start)]
    assert '"errors"' in body, "host_payload drops _errors, so a failed query looks like an empty host"


def test_the_host_view_renders_the_error_channel():
    """Carrying the errors is only half of it; the view must show them. A payload field no
    renderer reads is dead weight, which is the third shape of this same defect."""
    start = JS.index("async function loadHost(")
    body = JS[start:JS.index("\nasync function", start + 10)]
    assert "d.errors" in body, "the host view ignores the errors channel"
    assert "showDataError" in body, "the host view does not surface the failure"


def test_a_failed_query_and_an_empty_host_read_differently():
    """The two states must produce different text. This is the actual assertion of value; the
    two tests above are its preconditions."""
    start = JS.index("async function loadHost(")
    body = JS[start:JS.index("\nasync function", start + 10)]
    assert "could not be read" in body, (
        "a failed query and an empty host still produce the same message, so a broken query is "
        "indistinguishable from a quiet host"
    )


def test_the_evidence_payload_carries_attack_techniques():
    """The worker writes attack_techniques on every anomaly and the alert prints it, but the
    evidence query never SELECTed it -- so the one page an analyst opens to read the measurement
    behind an alert could never show a technique, while the front end asked for it every time."""
    src = (ROOT / "weirvern" / "admin" / "status.py").read_text()
    start = src.index("def alert_evidence(")
    body = src[start:src.index("\ndef ", start + 10)]
    assert "attack_techniques" in body, (
        "the evidence window query does not select attack_techniques, so the ATT&CK block in the "
        "GUI can never render"
    )
    assert "attack_label" in body


def test_the_auth_note_is_resolved_on_load():
    """#st-auth-note shipped as "checking…" and refreshAuthNote() only ran when a token button was
    clicked -- so the one card that says whether writes are possible reported a state that would
    never resolve. The orphaned-"loading…" defect, on the card that gates the whole write path."""
    start = JS.index("async function loadSettings(")
    body = JS[start:JS.index("\nasync function", start + 10)]
    assert "refreshAuthNote" in body, (
        "loadSettings does not resolve the auth note, so it stays at its initial text"
    )


# ── the document that was invalid ───────────────────────────────────────────────

def test_no_duplicate_element_ids_in_the_document():
    """The Assets view declared two cards with the same five ids. Only the first is reachable by
    getElementById, so the second card's Look up button was inert: an analyst typed an address
    and got nothing at all -- no request, no error, no spinner."""
    import re
    ids = re.findall(r'id="([A-Za-z0-9_-]+)"', HTML)
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert not dupes, f"duplicate element ids: {dupes} (getElementById silently picks the first)"


def test_every_id_the_js_looks_up_exists_in_the_document():
    """An id the JS writes to but the document does not declare is the orphan class: the panel
    silently never updates and reads as though it were still loading."""
    import re
    wanted = set(re.findall(r'getElementById\("([A-Za-z0-9_-]+)"\)', JS))
    present = set(re.findall(r'id="([A-Za-z0-9_-]+)"', HTML))
    # Ids the JS CREATES itself (attrs: { id: "..." }) are legitimately absent from the document;
    # only an id that nothing ever creates is an orphan.
    created = set(re.findall(r'id:\s*"([A-Za-z0-9_-]+)"', JS)) | set(re.findall(r"id:\s*'([A-Za-z0-9_-]+)'", JS))
    missing = sorted(wanted - present - created)
    assert not missing, f"the JS looks up ids that nothing defines or creates: {missing}"


# ── the harness must not prove things about payloads the server cannot send ─────

def test_the_harness_settings_stub_matches_what_the_server_advertises():
    """The jsdom harness passed 133 checks while the settings write path was unreachable, because
    its /api/settings stub declared `editable_keys` in a shape the server did not emit.

    A stub that flatters the front end only proves the front end works against fiction. This holds
    the harness to the server's own declaration, so the two cannot drift apart silently again --
    which is the failure mode, since nothing about a passing harness suggests its inputs are fake.
    """
    import re
    harness = (ROOT / "scripts" / "jsdom_render.js").read_text()
    start = harness.index("const SETTINGS_PAYLOAD")
    m = re.search(r"editable_keys:\s*\[([^\]]*)\]", harness[start:start + 1200])
    assert m, "the harness no longer declares editable_keys in its settings stub"
    offered = [k.strip().strip('"').strip("'") for k in m.group(1).split(",") if k.strip()]

    advertised = {cc.to_row_key(k) for k in cc.EDITABLE_KEYS}
    impossible = [k for k in offered if k not in advertised]
    assert not impossible, (
        f"the harness's settings stub offers keys the server cannot advertise: {impossible}. "
        "A check that passes on an impossible payload proves nothing about the product."
    )


# ── the harness reads the checkout it runs from ─────────────────────────────────

def test_the_dom_harness_reads_the_checkout_relative_to_itself():
    """The harness hardcoded a home-directory path for the web root and /tmp/node_modules/jsdom
    -- paths that exist on exactly one machine. Anywhere else it either died on the require before
    checking anything, or (worse) read a directory that was not the code under test. The web
    root must resolve relative to the harness file, and jsdom must resolve normally.
    """
    harness = (ROOT / "scripts" / "jsdom_render.js").read_text()
    web_line = next((ln for ln in harness.splitlines() if ln.startswith("const WEB =")), "")
    assert web_line, "no WEB assignment found in the harness"
    assert "/home/" not in web_line and "Documents" not in web_line, (
        f"the WEB root still contains a hardcoded home path: {web_line}"
    )
    assert "path.resolve(__dirname" in web_line, (
        "the web root is not resolved relative to the harness file, so it is machine-dependent"
    )
    # jsdom must be resolvable by the normal Node resolution (a local npm install). Check the
    # CODE, not comments: strip comment lines first, or the explanatory note about the old path
    # reads as the defect it documents.
    code = "\n".join(ln for ln in harness.splitlines() if not ln.strip().startswith(("//", "/*", "*")))
    assert '["jsdom", "/tmp/node_modules/jsdom"]' in code, (
        "the jsdom resolution no longer tries the local install first"
    )
    assert 'require("/tmp/node_modules/jsdom")' not in code, (
        "the harness still requires the old absolute path directly"
    )


# ── one definition per shared helper ────────────────────────────────────────────

def test_getJSON_is_defined_exactly_once():
    """getJSON existed in BOTH app.js and assets.js, and because script tags share one global
    scope the later declaration silently overrode the earlier for every call site -- so the
    error semantics of app.js's callers were decided by script load order. Functions do not
    collide loudly (a const would have been a SyntaxError), which is why nothing caught it.
    """
    import re
    web = ROOT / "weirvern" / "admin" / "web"
    defs = []
    for name in ("app.js", "soc.js", "assets.js"):
        src = (web / name).read_text()
        if re.search(r"^\s*async function getJSON\(", src, re.M) or \
           re.search(r"^\s*function getJSON\(", src, re.M):
            defs.append(name)
    assert defs == ["app.js"], (
        f"getJSON must be defined exactly once (in app.js, which loads first); found in {defs}. "
        "Two top-level definitions mean the later file's version silently wins."
    )


# ── the CSS tokens a few rules reference ────────────────────────────────────────

def test_every_css_custom_property_that_is_used_is_defined():
    """`.attack-meta` used var(--muted-foreground), `.setting-input` used var(--card), and
    `.chip .x:hover` used var(--danger) -- none of them defined in :root. An undefined custom
    property makes the whole declaration invalid, so the attack metadata inherited the body
    colour and the setting input rendered with no background: both look like styling choices
    rather than missing tokens.
    """
    import re
    css = (ROOT / "weirvern" / "admin" / "web" / "style.css").read_text()
    root = css[css.index(":root"):css.index("}", css.index(":root"))]
    defined = set(re.findall(r"(--[a-z0-9-]+)\s*:", root))
    # var(--name) or var(--name, fallback) -- only flag ones with NO fallback and no definition.
    used = {}
    for m in re.finditer(r"var\(\s*(--[a-z0-9-]+)\s*(,?)\s*([^)]*)\)", css):
        name, comma, fallback = m.group(1), m.group(2), m.group(3).strip()
        if not comma:            # a fallback exists: a missing definition degrades safely
            used.setdefault(name, fallback)
    missing = sorted(n for n in used if n not in defined)
    assert not missing, f"CSS custom properties used without definition or fallback: {missing}"
