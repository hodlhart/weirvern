# INF601 - Advanced Programming in Python
# Samuel Hart
# Final Project
"""Probe every GET API route and report which surfaces are empty.

The demo goal is a console where every view has something to show. This measures
that instead of eyeballing it: call each GET route, look for the payload's own
emptiness markers (count, rows, available, reason), and print one line per route.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
BASE = os.environ.get("WEIRVERN_API_URL", "http://127.0.0.1:8080")
TOKEN = os.environ.get("WEIRVERN_TOKEN", "")

# Query arguments the read routes need; anything absent gets no parameter.
PARAMS = {
    "/api/host": {"addr": "192.0.2.13"},
    "/api/evidence": {"addr": "192.0.2.13", "start": "2026-11-23T18:00:00+00:00"},
    "/api/incident": {"addr": "192.0.2.13", "start": "2026-11-23T18:00:00+00:00"},
    "/api/network/host": {"addr": "192.0.2.13"},
    "/api/zeek-log": {"log": "dns", "hours": 24, "limit": 5},
    "/api/weirlings/probe": {"hours": 24},
    "/api/watch": {"addr": "192.0.2.13"},
}

EMPTY_KEYS = ("count", "total", "n", "rows", "items", "points", "hosts", "flows")


def emptiness(payload) -> str:
    if not isinstance(payload, dict):
        if isinstance(payload, list):
            return "empty" if not payload else f"{len(payload)} item(s)"
        return "?"
    if payload.get("available") is False:
        return f"UNAVAILABLE: {str(payload.get('reason', ''))[:60]}"
    for key in EMPTY_KEYS:
        value = payload.get(key)
        if isinstance(value, int) and value == 0:
            return "empty (0)"
        if isinstance(value, (list, dict)) and len(value) == 0:
            return "empty ([])"
    for key in ("count", "total", "n"):
        value = payload.get(key)
        if isinstance(value, int):
            return f"{value} row(s)"
    return "has data"


def call(path: str, verb: str) -> tuple[int, object]:
    if verb != "GET":
        return 0, None
    query = PARAMS.get(path, {})
    url = BASE + path + (("?" + urlencode(query)) if query else "")
    req = Request(url, headers={"Accept": "application/json", "X-Weirvern-Token": TOKEN})
    try:
        with urlopen(req, timeout=20) as resp:
            return resp.status, json.loads(resp.read().decode())
    except HTTPError as exc:
        body = exc.read().decode(errors="replace")[:200]
        return exc.code, {"error": body}
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        return 0, {"error": str(exc)[:120]}


def main() -> int:
    routes = json.loads((ROOT / "tests" / "route_map.json").read_text())
    empty, total = 0, 0
    for name, spec in sorted(routes.items()):
        path, verb = spec["path"], spec["verb"]
        if verb != "GET" or "{" in path or "<" in path:
            continue
        status, payload = call(path, verb)
        total += 1
        if status != 200:
            error = payload.get("error", "") if isinstance(payload, dict) else ""
            state = f"HTTP {status}: {str(error)[:60]}"
        else:
            state = emptiness(payload)
        if state.startswith("empty") or state.startswith("UNAVAILABLE"):
            empty += 1
            print(f"  EMPTY  {name:28s} {path:38s} {state}")
        else:
            print(f"  ok     {name:28s} {path:38s} {state}")
    print(f"\n{total - empty}/{total} GET routes carry data; {empty} empty")
    return 0 if empty == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
