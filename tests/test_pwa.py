"""The console as an installed web app: a named icon, a manifest and a safe worker.

Chrome/Edge install wants a manifest with 192 and 512 icons; iOS takes the apple-touch-icon
and the mobile-web-app meta tags. The logo already exists, but a browser will not use a page
icon as the launcher icon unless the manifest names it. These are source-level checks because
the failure is silent: the install happens and the launcher shows a generic screenshot.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


def _png_size(path: Path) -> tuple[int, int]:
    data = path.read_bytes()
    assert data[:8] == b"\x89PNG\r\n\x1a\n", f"{path} is not a PNG"
    return int.from_bytes(data[16:20], "big"), int.from_bytes(data[20:24], "big")


def test_the_manifest_is_valid_and_names_the_logo_at_install_sizes():
    raw = (WEB / "manifest.webmanifest").read_text()
    manifest = json.loads(raw)
    assert manifest["name"] == "Weirvern"
    assert manifest["short_name"]
    assert manifest["start_url"] == "/" and manifest["scope"] == "/"
    assert manifest["display"] == "standalone", "an installed console must not open as a browser tab"
    icons = {i["sizes"]: i for i in manifest["icons"]}
    for size in ("192x192", "512x512"):
        assert size in icons, f"the manifest has no {size} launcher icon"
        icon = icons[size]
        assert icon["type"] == "image/png"
        assert (WEB / icon["src"].lstrip("/")).is_file(), f"missing {icon['src']}"
        assert _png_size(WEB / icon["src"].lstrip("/")) == tuple(map(int, size.split("x")))
    assert _png_size(WEB / "apple-touch-icon.png") == (180, 180)


def test_the_manifest_icons_are_served_and_the_head_links_the_manifest():
    from weirvern.admin.web import STATIC_FILES

    for path, name in (("/manifest.webmanifest", "manifest.webmanifest"),
                       ("/apple-touch-icon.png", "apple-touch-icon.png"),
                       ("/icon-192.png", "icon-192.png"),
                       ("/icon-512.png", "icon-512.png"),
                       ("/sw.js", "sw.js")):
        assert path in STATIC_FILES, f"{path} is not in STATIC_FILES; the browser would 404"
        assert (WEB / name).is_file(), f"{name} is missing"

    html = (WEB / "index.html").read_text()
    assert 'rel="manifest" href="/manifest.webmanifest"' in html
    assert 'name="theme-color"' in html
    assert 'name="apple-mobile-web-app-capable"' in html
    assert 'rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png"' in html


def test_the_installed_shell_registers_a_network_only_worker():
    """NO CACHE **AND** NO FETCH HANDLER, and the second half is not a style choice.

    This check used to require `fetch(event.request)` inside the worker, which pinned the mechanism
    that broke Safari: a rejected `respondWith(fetch(...))` becomes a page-load failure ("FetchEvent
    .respondWith received an error: TypeError: Load failed") instead of letting the navigation reach
    the network. The property the check exists for is "the console is never served from a cache";
    a worker with no fetch handler satisfies it more completely than one that proxies, because there
    is no interception left to fail. Measured live: the fix shipped as a ConfigMap over this file,
    which is how a shipped defect and a shipped fix can both live outside the repository.
    """
    # COMMENTS ARE STRIPPED BEFORE SCANNING. The worker's own header explains WHY it has no fetch
    # handler and names respondWith while doing so, so a scan of the raw text matches the
    # explanation instead of the code -- the same trap the network-graph checks hit with a class
    # name inside a comment.
    raw = (WEB / "sw.js").read_text()
    worker = re.sub(r"/\*.*?\*/", "", raw, flags=re.S)
    worker = re.sub(r"^\s*//.*$", "", worker, flags=re.M)
    assert "caches" not in worker, "a cached dashboard can show stale health after a failure"
    assert "respondWith" not in worker, (
        "the worker intercepts fetch again; Safari turns a rejected respondWith into a page-load "
        "failure, which is the defect this file was hot-fixed for"
    )
    assert 'addEventListener("fetch"' not in worker, "a network-only worker has nothing to do with fetch"
    assert "skipWaiting" in worker and "clients.claim" in worker, (
        "the worker still has to install and take over, or the PWA shell never updates"
    )
    app = (WEB / "app.js").read_text()
    assert 'serviceWorker.register("/sw.js")' in app, "the installed app never registers its worker"
