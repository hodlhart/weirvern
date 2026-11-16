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

from tests.support_routes import routed

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

    def strip_noise(src: str) -> str:
        """Remove comments and the CONTENTS of string/regex literals in ONE pass.

        WHY ONE PASS AND NOT TWO. A naive scanner over raw source matches PROSE, so the
        comments and string contents have to go before the call graph is parsed -- but two
        independent regex passes cannot see each other's context, and that is a correctness
        bug, not a style choice. Measured: `re.sub(r"//[^\\n]*", ...)` eats the `//` inside
        `"http://www.w3.org/2000/svg"`, which leaves an unterminated quote; the string pass
        then swallows everything after it, INCLUDING `function svgEl` -- and this test
        reported `svgEl` as an undefined call, i.e. it accused the code of the scanner's
        own bug. (Earlier versions made the same mistake with comments, reporting `Health`,
        `design`, `labels` as missing helpers.) The tempting fix at each step is to widen
        the allow-list, which is how a check quietly stops checking anything.

        This was written once, with both literals consumed by the same walk:
          * comments: /* */ and // (a // INSIDE a string is not a comment);
          * strings: ' " ` -- contents blanked, because "3 decision(s) recorded" is not a
            call to `decision`;
          * template interpolations (`${fmt(x)}`) ARE code and are kept, so real calls
            inside them are still checked; they are emitted with a space on each side so
            two adjacent interpolations cannot fuse into a token neither of them wrote
            (`${name} — ${fmtTotal(x)}` once produced a call to `namefmtTotal`);
          * regex literals: emitted intact rather than parsed. They contain `(` and quotes
            and would otherwise derail the walk; a regex can never CALL a helper, so
            leaving its text in place cannot create a false positive for this test. The
            heuristic for "this / starts a regex, not a division" is the preceding
            non-space character: after an identifier, `)` or `]` a slash divides.
        """
        out: list[str] = []
        i, n = 0, len(src)
        prev = ""  # last significant char emitted, for the regex-vs-division decision
        while i < n:
            ch = src[i]
            if ch == "/" and src.startswith("/*", i):
                j = src.find("*/", i + 2)
                i = n if j == -1 else j + 2
                continue
            if ch == "/" and src.startswith("//", i):
                j = src.find("\n", i + 2)
                i = n if j == -1 else j
                continue
            if ch == "/" and prev not in ")]}$" and not (prev.isalnum() or prev == "_"):
                # Regex literal: consume it whole and emit it verbatim.
                j = i + 1
                in_class = False
                while j < n:
                    if src[j] == "\\":
                        j += 2
                        continue
                    if src[j] == "[":
                        in_class = True
                    elif src[j] == "]":
                        in_class = False
                    elif src[j] == "/" and not in_class:
                        j += 1
                        break
                    elif src[j] == "\n":
                        break  # not actually a regex after all; bail out
                    j += 1
                out.append(src[i:j])
                i = j
                prev = "/"
                continue
            if ch in "\"'`":
                quote = ch
                i += 1
                while i < n:
                    if src[i] == "\\":
                        i += 2
                        continue
                    if quote == "`" and src.startswith("${", i):
                        depth, j = 1, i + 2
                        while j < n and depth:
                            if src[j] == "{":
                                depth += 1
                            elif src[j] == "}":
                                depth -= 1
                            j += 1
                        # A SPACE ON EACH SIDE, OR ADJACENT INTERPOLATIONS FUSE. The template's
                        # literal text is dropped here, so `${name} — ${fmtTotal(total)}` used to
                        # emit `namefmtTotal(total)` as ONE token, and the test reported a missing
                        # helper called `namefmtTotal` -- a false positive about a line that is
                        # fine, which is how a guard gets switched off instead of fixed.
                        out.append(" ")
                        out.append(strip_noise(src[i + 2:j - 1]))
                        out.append(" ")
                        i = j
                        continue
                    if src[i] == quote:
                        i += 1
                        break
                    i += 1
                out.append('""')
                prev = '"'
                continue
            out.append(ch)
            if not ch.isspace():
                prev = ch
            i += 1
        return "".join(out)

    soc = strip_noise(SOC_JS.read_text())
    app = strip_noise(app)

    known = set(re.findall(r"^function ([A-Za-z_$][\w$]*)", app, re.M))
    known |= set(re.findall(r"^async function ([A-Za-z_$][\w$]*)", app, re.M))
    assets = strip_noise((SOC_JS.parent / "assets.js").read_text())
    known |= set(re.findall(r"^const ([A-Za-z_$][\w$]*)\s*=", app, re.M))
    known |= set(re.findall(r"^function ([A-Za-z_$][\w$]*)", soc, re.M))
    # `async function` must be matched separately: the plain pattern requires `function` at
    # the start of the line, so every async declaration was reported as an undefined call.
    # That is a false positive of exactly the kind that gets an allow-list widened.
    known |= set(re.findall(r"^async function ([A-Za-z_$][\w$]*)", soc, re.M))
    known |= set(re.findall(r"^const ([A-Za-z_$][\w$]*)\s*=", soc, re.M))
    # discover.js defines `discoverDrill`, which soc.js calls when a volume bucket is clicked
    # ("show me the rows behind this"). Widening the scan, not the allow-list -- the file is
    # scanned for definitions exactly like assets.js above.
    discover = strip_noise((SOC_JS.parent / "discover.js").read_text())
    known |= set(re.findall(r"^function ([A-Za-z_$][\w$]*)", discover, re.M))
    known |= set(re.findall(r"^async function ([A-Za-z_$][\w$]*)", discover, re.M))
    known |= set(re.findall(r"^const ([A-Za-z_$][\w$]*)\s*=", discover, re.M))
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
    assert routed(endpoint), f"{endpoint} is not routed by the application"


def test_the_deep_health_endpoint_is_not_the_liveness_probe():
    """Pin the distinction the Health view depends on, so a later edit cannot merge them.

    /api/healthz must NOT read ClickHouse -- a probe that fails when the database is slow
    restarts the GUI and hides the real problem, which is documented in its own comment.
    /api/health exists precisely to read it. If someone "simplifies" these into one endpoint,
    either the probe starts restarting the GUI or the operator loses the only view that says
    whether data is still arriving.
    """
    # The probe now lives on the surviving surface; its body is what must stay free of ClickHouse.
    src = (WEB.parent / "flask_app.py").read_text()
    healthz_block = src.split('@app.get("/api/healthz")', 1)[1].split("@app.", 1)[0]
    assert 'jsonify({"ok": True})' in healthz_block, (
        "the liveness probe no longer returns a bare ok -- check it has not been wired to "
        "ClickHouse, which would let a slow database restart the GUI"
    )
    assert "soc_mod" not in healthz_block, (
        "the liveness probe now runs SOC queries; it must stay database-free"
    )
