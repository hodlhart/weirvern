"""GitHub issue #63: Identity must not look like a windowed read it never performs.

The route reads the current `host_identity` verdict table; the verdict's own observation window
is seven days. The client used to send `hours` anyway, so the header could say 15 minutes while
the view answered seven days. These are source-level pins for the choice we made: a current
snapshot, no window argument, and copy that names both facts.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


def test_identity_requests_no_window():
    for name in ("app.js", "assets.js"):
        source = (WEB / name).read_text(encoding="utf-8")
        assert '"/api/identity"' in source, f"{name} no longer reads identity"
        assert "/api/identity?hours=" not in source, (
            f"{name} sends a window to the identity route that ignores it"
        )


def test_identity_ui_names_the_snapshot_and_its_own_window():
    html = (WEB / "index.html").read_text(encoding="utf-8")
    assert 'id="id-window"' in html
    assert "header range does not apply" in html or "header range does not apply" in (
        WEB / "app.js"
    ).read_text(encoding="utf-8")
    assert "7-day observation window" in html
