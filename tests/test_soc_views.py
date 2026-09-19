"""The SOC views' chart code must not reference DOM nodes or helpers that do not exist.

WHY THIS EXISTS. The GUI has no bundler and no framework, so a typo in an element id or a
call to a helper that was never defined is not caught at build time -- it fails at RUNTIME,
in the browser, and the visible result is a panel that stays empty. That is the same failure
mode this project has shipped repeatedly in other forms: a permanently blank Top Talkers
panel, a permanently blank Zeek Services panel, a permanently blank Workloads panel. An
empty panel looks exactly like a quiet network.

So this test does three mechanical checks against the real files:

  A. every `getElementById("x")` / `querySelector("#x")` in soc.js has a matching id in
     index.html -- a chart drawn into a node that does not exist renders nowhere, silently
  B. every view name in the tab bar has a matching `<section id="view-NAME">` -- a tab that
     switches to nothing looks like a loading bug
  C. every helper soc.js calls from app.js is actually defined in app.js -- the two files
     are loaded in order with no module system, so a missing helper is a runtime TypeError
     that kills the whole view

None of this needs a browser or a cluster, so it runs in the gate.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

WEB = Path(__file__).resolve().parent.parent / "weirvern" / "admin" / "web"
SOC_JS = WEB / "soc.js"
APP_JS = WEB / "app.js"
HTML = WEB / "index.html"


def _html_ids() -> set[str]:
    return set(re.findall(r'\bid="([^"]+)"', HTML.read_text()))


def _ids_used_by(js: str) -> set[str]:
    text = (WEB / js).read_text()
    out = set(re.findall(r'getElementById\("([^"]+)"\)', text))
    out |= set(re.findall(r'querySelector\("#([A-Za-z0-9_-]+)', text))
    return out


def test_every_element_soc_js_targets_exists_in_the_document():
    """A chart pointed at a missing node draws nothing and says nothing."""
    have = _html_ids()
    wanted = _ids_used_by("soc.js")
    assert wanted, "soc.js targets no elements at all -- the parse probably failed"
    missing = sorted(wanted - have)
    assert not missing, (
        f"weirvern/admin/web/soc.js renders into {missing}, which no element in index.html "
        f"provides. Those panels would stay EMPTY FOREVER with no error shown -- the exact "
        f"'blank panel looks like a quiet network' defect. Available ids: {sorted(have)}"
    )


def test_app_js_does_not_target_removed_elements():
    """app.js must not dereference an element the document does not provide.

    THE WORKLOADS PANEL WAS DELETED, and any leftover reference is a null dereference:
    `document.querySelector("#workloads-table tbody")` returns null once the panel is gone,
    and the next `.replaceChildren()` throws -- killing the ENTIRE overview render, not just
    that panel. A removed panel must be removed from its renderer too.

    ELEMENTS THE JAVASCRIPT ITSELF CREATES are exempt, and that exemption is verified rather
    than assumed: `err-banner` is built by `el("div", { attrs: { id: "err-banner" } })` and
    then re-found with getElementById, so it is legitimately absent from index.html. Without
    this check the test would demand a static element that must not exist, and the fix would
    be to add a duplicate banner to the page.
    """
    app = APP_JS.read_text()
    have = _html_ids()
    created_by_js = set(re.findall(r'id:\s*"([A-Za-z0-9_-]+)"', app))
    missing = sorted(_ids_used_by("app.js") - have - created_by_js)
    assert not missing, (
        f"weirvern/admin/web/app.js still targets {missing}, which index.html does not "
        "provide and the script does not create. A null element throws on first use and "
        "blanks the whole view."
    )


def test_every_tab_has_a_matching_view_section():
    """A tab that switches to a non-existent section shows nothing and looks like a hang.

    VIEWS ARE A SUPERSET OF TABS, deliberately: `evidence` is a drill-down destination
    reached from an anomaly row, not a tab, so it has a section and no button. The check is
    therefore one-directional -- every TAB must have a section, but not every section needs
    a tab.
    """
    html = HTML.read_text()
    tabs = set(re.findall(r'data-view="([a-z]+)"', html))
    sections = set(re.findall(r'<section id="view-([a-z]+)"', html))
    assert tabs, "no tabs found -- the parse probably failed"
    orphan_tabs = sorted(tabs - sections)
    assert not orphan_tabs, (
        f"these tabs have no <section id='view-...'>: {orphan_tabs}. Clicking one switches to "
        "an empty pane that looks like a rendering failure."
    )


def test_soc_js_only_calls_helpers_that_exist():
    """soc.js has no module imports; a call to a missing helper is a runtime TypeError.

    THE CALL GRAPH IS PARSED PROPERLY RATHER THAN GREPPED, because a naive `name(` scan
    matches local variables and arrow-function parameters -- the first version of this test
    reported `fmt`, `label`, `value`, `xOf` and `onClick` as undefined helpers, all of which
    are parameters inside soc.js. A test that cries wolf gets its allow-list widened until it
    checks nothing, so the false positives are excluded by construction here:

      * arrow-function parameters (`(r) => ...`, `(a, b) => ...`)
      * locally declared consts/functions
      * anything preceded by `.` (a method call on an object)
    """
    app = APP_JS.read_text()

    def strip_comments(src: str) -> str:
        """Remove /* */ and // comments.

        ESSENTIAL, not tidiness: a regex scan over raw source matches PROSE. The first
        version of this test reported `Health`, `design`, `things` and `labels` as undefined
        functions -- all of them words from the explanatory comments in soc.js. The tempting
        fix is to widen the allow-list, and that is how a check quietly stops checking
        anything.
        """
        src = re.sub(r"/\*.*?\*/", "", src, flags=re.S)
        return re.sub(r"//[^\n]*", "", src)

    soc = strip_comments(SOC_JS.read_text())
    app = strip_comments(app)

    known = set(re.findall(r"^function ([A-Za-z_$][\w$]*)", app, re.M))
    known |= set(re.findall(r"^async function ([A-Za-z_$][\w$]*)", app, re.M))
    assets = strip_comments((SOC_JS.parent / "assets.js").read_text())
    known |= set(re.findall(r"^const ([A-Za-z_$][\w$]*)\s*=", app, re.M))
    known |= set(re.findall(r"^function ([A-Za-z_$][\w$]*)", soc, re.M))
    # `async function` must be matched separately: the plain pattern requires `function` at
    # the start of the line, so every async declaration was reported as an undefined call.
    # That is a false positive of exactly the kind that gets an allow-list widened.
    known |= set(re.findall(r"^async function ([A-Za-z_$][\w$]*)", soc, re.M))
    known |= set(re.findall(r"^const ([A-Za-z_$][\w$]*)\s*=", soc, re.M))
    # assets.js defines the Zeek drill-down soc.js calls when a log-volume bar is clicked.
    known |= set(re.findall(r"^function ([A-Za-z_$][\w$]*)", assets, re.M))
    known |= set(re.findall(r"^async function ([A-Za-z_$][\w$]*)", assets, re.M))
    known |= set(re.findall(r"^const ([A-Za-z_$][\w$]*)\s*=", assets, re.M))
    # Parameters of every arrow function, and of object-literal methods used as callbacks
    # (`onClick: (r) => ...` leaves `r` as a parameter, not a call).
    for params in re.findall(r"\(([^()]*)\)\s*=>", soc):
        for p in params.split(","):
            name = p.strip().split("=")[0].strip()
            if re.fullmatch(r"[A-Za-z_$][\w$]*", name):
                known.add(name)
    for single in re.findall(r"(?<![\w.])([A-Za-z_$][\w$]*)\s*=>", soc):
        known.add(single)
    # Locals declared anywhere (not only at column 0) inside soc.js.
    known |= set(re.findall(r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)", soc))
    known |= {
        "document", "window", "Math", "Object", "Array", "Number", "String", "JSON", "Date",
        "Set", "Map", "Promise", "Error", "Boolean", "isNaN", "parseInt", "parseFloat",
        "console", "setInterval", "clearInterval", "setTimeout", "encodeURIComponent",
        "decodeURIComponent", "alert", "fetch", "if", "for", "while", "switch", "catch",
        "return", "typeof", "function",
        # JS keywords that appear before `(` -- `for (const x of y)`, `if (cond)`, etc. These
        # are not calls and matching them is a parse artefact, not a missing helper.
        "of", "in", "new", "await", "yield", "do", "else",
    }

    called = set(re.findall(r"(?<![\w.$])([A-Za-z_$][\w$]*)\s*\(", soc))
    unresolved = sorted(called - known)
    assert not unresolved, (
        f"soc.js calls {unresolved}, which nothing defines. There is no module system here, "
        "so this is a runtime TypeError that takes the whole view down with no visible cause. "
        "(If a genuine browser global is missing, add it to the allow-list.)"
    )


def test_soc_js_is_served_and_loaded_after_app_js():
    """Order matters: soc.js calls app.js helpers at load time, so it must come second."""
    html = HTML.read_text()
    app_at = html.find("/app.js")
    soc_at = html.find("/soc.js")
    assert app_at != -1, "index.html does not load app.js"
    assert soc_at != -1, "index.html does not load soc.js -- the SOC views would be undefined"
    assert app_at < soc_at, (
        "soc.js is loaded BEFORE app.js. It uses chartFrame/svgEl/el from app.js, so the "
        "helpers would not exist yet."
    )
    served = (WEB.parent / "web.py").read_text()
    assert '"/soc.js"' in served, (
        "soc.js is not in STATIC_FILES, so the browser gets a 404 and every SOC view is blank"
    )


@pytest.mark.parametrize("endpoint", ["/api/netflow", "/api/zeek", "/api/health"])
def test_each_new_endpoint_is_routed(endpoint):
    """A view whose endpoint is not routed gets the 404 page, not an empty chart."""
    src = (WEB.parent / "web.py").read_text()
    assert f'"{endpoint}"' in src, f"{endpoint} is not routed in weirvern/admin/web.py"


def test_the_deep_health_endpoint_is_not_the_liveness_probe():
    """Pin the distinction the Health view depends on, so a later edit cannot merge them.

    /api/healthz must NOT read ClickHouse -- a probe that fails when the database is slow
    restarts the GUI and hides the real problem, which is documented in its own comment.
    /api/health exists precisely to read it. If someone "simplifies" these into one endpoint,
    either the probe starts restarting the GUI or the operator loses the only view that says
    whether data is still arriving.
    """
    src = (WEB.parent / "web.py").read_text()
    healthz_block = src.split('"/api/healthz"', 1)[1].split("return self._error", 1)[0]
    assert "_json({\"ok\": True})" in healthz_block, (
        "the liveness probe no longer returns a bare ok -- check it has not been wired to "
        "ClickHouse, which would let a slow database restart the GUI"
    )
    assert "soc_mod" not in healthz_block, (
        "the liveness probe now runs SOC queries; it must stay database-free"
    )
