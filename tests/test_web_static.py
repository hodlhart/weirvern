"""The console's static allowlist, pinned against the page that uses it.

A new frontend file that is loaded by index.html but missing from STATIC_FILES 404s (or
401s anonymously) -- the exact class the box caught when palette.js shipped without its
entry. This test reads the SHIPPING html and the SHIPPING allowlist, not a copy.
"""
import re
from pathlib import Path

from weirvern.admin import web as web_mod


def test_every_script_and_asset_index_html_uses_is_served():
    root = Path(web_mod.__file__).resolve().parents[2]
    html = (root / "weirvern" / "admin" / "web" / "index.html").read_text()
    for src in re.findall(r'<script src="([^"]+)"', html):
        assert src in web_mod.STATIC_FILES, f"{src} is loaded by index.html but not served"
    for link in re.findall(r'<link[^>]+href="(/[^"]+)"', html):
        if link.endswith((".css", ".png", ".svg", ".ico")):
            assert link in web_mod.STATIC_FILES, f"{link} is linked by index.html but not served"
