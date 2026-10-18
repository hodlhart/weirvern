#!/usr/bin/env python3
"""The responsive audit (canon C-8/C-9/C-10): measures, it does not opine.

Drives a headless Chrome over the DevTools Protocol and reports, per view and per viewport:

  * document overflow            (page scrolls sideways at this width)
  * clipped text                 (a cell or label cuts its own content)
  * touch targets                (controls under 44/36px on the touch pass)
  * hover-only facts             (a `title` and no other accessible name)
  * unnamed controls             (no label, no aria-label, no aria-labelledby)
  * DOM size and API calls on load

and writes one screenshot per view/viewport as the visual evidence.

Usage:
  scripts/responsive_audit.py --url https://console --token-file ~/.weirvern_token \
      --out /tmp/audit [--views health,anomalies,weirlings] [--widths 1440x900,820x1180,390x844]

The token file is read once and never printed; it is sent as `X-Weirvern-Token` on every request
(the console's break-glass automation credential). No credential is stored by this script.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

try:
    import websockets
except ImportError:  # pragma: no cover - environment guard
    sys.exit("needs the `websockets` package (pip install websockets)")

DEFAULT_CHROME = os.environ.get(
    "CHROME",
    "/home/admin/.cache/ms-playwright/chromium-1234/chrome-linux64/chrome",
)

AUDIT_JS = r"""
(() => {
  const vis = (el) => {
    const r = el.getBoundingClientRect();
    const s = getComputedStyle(el);
    return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none';
  };
  const name = (el) => {
    const t = (el.innerText || '').trim();
    if (t) return t.slice(0, 40);
    const al = el.getAttribute('aria-label');
    if (al) return al.slice(0, 40);
    const lb = el.getAttribute('aria-labelledby');
    if (lb) { const n = document.getElementById(lb); if (n) return (n.innerText || '').slice(0, 40); }
    const lab = el.closest('label');
    if (lab) return (lab.innerText || '').slice(0, 40);
    return '';
  };
  const sel = (el) => el.tagName.toLowerCase() + (el.id ? '#' + el.id : '') +
    (el.className && typeof el.className === 'string'
      ? '.' + el.className.trim().split(/\s+/).slice(0,2).join('.') : '');

  const root = document.documentElement;
  const overflow = Math.max(0, root.scrollWidth - window.innerWidth);

  const clipped = [];
  for (const el of document.querySelectorAll('td, th, .cell, .kv dd, .kv dt, span, div')) {
    if (!vis(el) || !(el.innerText || '').trim()) continue;
    if (el.scrollWidth > el.clientWidth + 1 && getComputedStyle(el).overflow !== 'visible') {
      clipped.push(sel(el));
      if (clipped.length >= 8) break;
    }
  }

  const controls = [...document.querySelectorAll('button, a, input, select, textarea')].filter(vis);
  const small = [], verySmall = [];
  for (const el of controls) {
    const r = el.getBoundingClientRect();
    if (r.width < 44 || r.height < 44) small.push(sel(el) + ' ' + Math.round(r.width) + 'x' + Math.round(r.height));
    if (r.width < 36 || r.height < 36) verySmall.push(sel(el) + ' ' + Math.round(r.width) + 'x' + Math.round(r.height));
  }

  const hoverOnly = [], unnamed = [];
  for (const el of document.querySelectorAll('[title]')) {
    if (!vis(el)) continue;
    const label = name(el);
    if (!label) hoverOnly.push(sel(el) + ' :: ' + (el.getAttribute('title') || '').slice(0, 50));
    if (hoverOnly.length >= 8) break;
  }
  for (const el of controls) {
    if (!name(el) && !el.getAttribute('placeholder')) unnamed.push(sel(el));
    if (unnamed.length >= 8) break;
  }

  const wideGrids = [...document.querySelectorAll('table, .tablewrap')]
    .filter((el) => vis(el) && el.scrollWidth > el.clientWidth + 1).map(sel);

  const api = performance.getEntriesByType('resource')
    .filter((r) => r.name.includes('/api/')).length;

  return JSON.stringify({
    view: (document.querySelector('#tabs .tab.active') || {}).textContent || '',
    activeId: ((document.querySelector('#tabs .tab.active') || {}).getAttribute
               ? document.querySelector('#tabs .tab.active').getAttribute('data-view') : ''),
    overflow, clipped, small: small.slice(0, 8), smallCount: small.length,
    verySmall: verySmall.slice(0, 8), verySmallCount: verySmall.length,
    hoverOnly, hoverOnlyCount: hoverOnly.length, unnamed: unnamed.slice(0, 8),
    wideGrids, dom: document.querySelectorAll('*').length, api,
    errors: (window.__auditErr || []).slice(0, 5),
  });
})()
"""

HOOK_JS = """
window.__auditErr = [];
window.addEventListener('error', (e) => window.__auditErr.push(String(e.message || e)));
window.addEventListener('unhandledrejection', (e) => window.__auditErr.push('promise: ' + String(e.reason)));
"""


class CDP:
    def __init__(self, ws_url: str):
        self.ws_url = ws_url
        self.ws = None
        self.n = 0

    async def connect(self):
        self.ws = await websockets.connect(self.ws_url, max_size=64 * 1024 * 1024)
        return self

    async def call(self, method: str, params: dict | None = None) -> dict:
        if self.ws is None:
            raise RuntimeError("CDP.call before connect")
        self.n += 1
        mid = self.n
        await self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        while True:
            msg = json.loads(await self.ws.recv())
            if msg.get("id") == mid:
                if "error" in msg:
                    raise RuntimeError(f"{method}: {msg['error']}")
                return msg.get("result", {})

    async def close(self):
        if self.ws:
            await self.ws.close()


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_http(url: str, tries: int = 60) -> bool:
    for _ in range(tries):
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                if r.status == 200:
                    return True
        except Exception:  # noqa: BLE001
            time.sleep(0.25)
    return False


def new_target(port: int) -> str:
    req = urllib.request.Request(f"http://127.0.0.1:{port}/json/new?about:blank", method="PUT")
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)["webSocketDebuggerUrl"]


async def audit_one(cdp: CDP, base: str, view: str, width: int, height: int, shot: Path,
                    idx: int = 0) -> dict:
    mobile = width <= 720
    await cdp.call("Emulation.setDeviceMetricsOverride",
                   {"width": width, "height": height, "deviceScaleFactor": 1, "mobile": mobile})
    await cdp.call("Emulation.setTouchEmulationEnabled", {"enabled": mobile, "maxTouchPoints": 5})
    # A URL that differs by query forces a real navigation; a hash-only change would leave the
    # previous view on screen and every row would silently measure the same page.
    await cdp.call("Page.navigate", {"url": f"{base}/?qa={idx}#v={view}"})
    await asyncio.sleep(2.4)
    res = await cdp.call("Runtime.evaluate", {"expression": AUDIT_JS, "returnByValue": True})
    data = json.loads(res["result"]["value"])
    data["wanted"] = view
    data["mismatch"] = data.get("activeId") != view
    png = await cdp.call("Page.captureScreenshot", {"format": "png"})
    shot.parent.mkdir(parents=True, exist_ok=True)
    shot.write_bytes(base64.b64decode(png["data"]))
    data.update({"width": width, "height": height, "shot": str(shot)})
    return data


async def run(args) -> int:
    token = ""
    if args.token_file:
        token = Path(args.token_file).read_text(encoding="utf-8").strip()
    elif os.environ.get("WEIRVERN_TOKEN"):
        token = os.environ["WEIRVERN_TOKEN"]
    if not token:
        print("no token: pass --token-file (or WEIRVERN_TOKEN)", file=sys.stderr)
        return 2

    chrome = args.chrome or DEFAULT_CHROME
    if not Path(chrome).exists():
        print(f"chrome not found at {chrome} (set CHROME= or --chrome)", file=sys.stderr)
        return 2

    port = free_port()
    profile = Path(args.out) / "chrome-profile"
    shutil.rmtree(profile, ignore_errors=True)
    proc = subprocess.Popen(
        [chrome, "--headless=new", "--no-sandbox", "--disable-gpu", "--no-first-run",
         f"--remote-debugging-port={port}", f"--user-data-dir={profile}",
         "--window-size=1440,900", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not wait_http(f"http://127.0.0.1:{port}/json/version"):
            print("chrome did not expose the devtools endpoint", file=sys.stderr)
            return 2
        cdp = await CDP(new_target(port)).connect()
        try:
            await cdp.call("Page.enable")
            await cdp.call("Runtime.enable")
            await cdp.call("Network.enable")
            await cdp.call("Network.setExtraHTTPHeaders", {"headers": {"X-Weirvern-Token": token}})
            await cdp.call("Page.addScriptToEvaluateOnNewDocument", {"source": HOOK_JS})
            await cdp.call("Emulation.setDeviceMetricsOverride",
                           {"width": 1440, "height": 900, "deviceScaleFactor": 1, "mobile": False})

            results = []
            idx = 0
            for view in args.views:
                for w, h in args.widths:
                    idx += 1
                    shot = Path(args.out) / "shots" / f"{view}-{w}.png"
                    row = await audit_one(cdp, args.url.rstrip("/"), view, w, h, shot, idx)
                    results.append(row)
                    flag = "  !! measured " + str(row.get("activeId")) if row.get("mismatch") else ""
                    print(f"  {view:11s} {w:4d}  overflow={row['overflow']:3d}  clipped={len(row['clipped']):2d}"
                          f"  small={row['smallCount']:3d}  hover-only={row['hoverOnlyCount']:2d}"
                          f"  unnamed={len(row['unnamed']):2d}  dom={row['dom']:5d}  api={row['api']:2d}{flag}")
        finally:
            await cdp.close()
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    out = Path(args.out)
    (out / "audit.json").write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    worst_overflow = max((r["overflow"] for r in results), default=0)
    print(f"\n{len(results)} view/viewport pairs -> {out/'audit.json'}")
    print(f"worst horizontal overflow: {worst_overflow}px")
    print(f"screenshots: {out/'shots'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Responsive audit for the weirvern console")
    ap.add_argument("--url", default="http://weirvern.home:30088")
    ap.add_argument("--token-file", default="")
    ap.add_argument("--out", default="/tmp/wv-responsive-audit")
    ap.add_argument("--chrome", default="")
    ap.add_argument("--views", default="health,anomalies,logs,network,netflow,discover,dns,zeek,"
                                       "sluice,blocked,identity,weirlings,host,models,settings")
    ap.add_argument("--widths", default="1440x900,820x1180,390x844,320x640")
    args = ap.parse_args(argv)
    views = [v.strip() for v in args.views.split(",") if v.strip()]
    widths: list[tuple[int, int]] = []
    for pair in args.widths.split(","):
        w, _, h = pair.partition("x")
        widths.append((int(w), int(h)))
    args.views = views
    args.widths = widths
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
