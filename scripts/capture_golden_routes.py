"""Record the console's responses as golden fixtures, while the console still exists.

WHY THIS RUNS BEFORE ANYTHING IS DELETED. The legacy HTTP handler is the oracle that
`tests/test_route_port_equivalence.py` compares Flask against. Retiring the handler without recording
what it answered first would destroy the only proof that the port is faithful, and no later refactor
could recover it. So the goldens are captured from the incumbent, committed, and only then is the
handler removed.

WHAT A GOLDEN IS. For each route, the exact status code and body the console produced with a known
stub in place, recorded twice: once with the read returning a benign value, and once with it raising.
The second one matters as much as the first, because this project's recurring defect is a failed read
rendered as a benign state, and the wording of those failures is part of the payload contract.

The stub target per route is derived mechanically -- handler -> payloads fetcher -> the single module
call that fetcher makes -- so this does not depend on a hand-maintained list drifting from the code.

Usage:
    python scripts/capture_golden_routes.py            # rewrite tests/golden/routes.json
    python scripts/capture_golden_routes.py --check    # compare, do not write
"""

from __future__ import annotations

import argparse
import importlib
import json
import pathlib
import sys
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from weirvern.admin import web  # noqa: E402


class _CM:
    def __init__(self, client):
        self.client = client

    def __enter__(self):
        return self.client

    def __exit__(self, *_a):
        return False


def _ctx():
    class _Auth:
        enabled = False
        reason = ""          # the real one carries it; without it Flask logs an AttributeError

        def check(self, presented, client=""):
            return False

    class _Ctx:
        settings = None
        backend = None
        config_client = None
        user_store = None
        sessions = None
        throttle = None
        accounts_note = ""
        auth = _Auth()

    _Ctx.connect_factory = staticmethod(lambda settings: _CM(object()))
    return _Ctx()


def _patch(dotted: str, value):
    """Set a target and return a function that puts the original back.

    The restore matters as much as the patch. Leaving every stub applied would mean the last route is
    measured with all 23 stubs in force, which is not the condition the replay test sets up, and the
    two would then disagree for reasons that have nothing to do with the port.
    """
    module, _, attr = dotted.rpartition(".")
    mod = importlib.import_module(module)
    original = getattr(mod, attr)
    setattr(mod, attr, value)

    def restore():
        setattr(mod, attr, original)

    return restore


def _get(port: int, path: str) -> tuple[int, str]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _boom(*_a, **_k):
    raise FileNotFoundError(2, "No such file or directory", "kubectl")


def capture(stub_value) -> dict:
    """Every stubbable route, recorded against the legacy handler."""
    targets = json.loads((ROOT / "tests/golden_targets.json").read_text())
    recorded: dict[str, dict] = {}
    legacy = web.GuiServer(_ctx(), host="127.0.0.1", port=0).start_background()
    try:
        port = legacy.port
        # ONE SERVER, PATCHED PER ROUTE. The payload functions read `status_mod.X` at call time, so
        # patching the module attribute is visible to both surfaces and no restart is needed.
        for path, spec in sorted(targets.items()):
            restore = _patch(spec["target"], stub_value)
            try:
                status, body = _get(port, path)
            finally:
                restore()
            recorded[path] = {"verb": spec["verb"], "target": spec["target"],
                              "status": status, "body": body}
    finally:
        legacy.stop()
    return recorded


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="compare against the committed goldens instead of writing")
    args = parser.parse_args(argv)

    golden_path = ROOT / "tests/golden/routes.json"
    fresh = {"ok": capture(lambda *_a, **_k: {}), "fail": capture(_boom)}

    if args.check:
        old = json.loads(golden_path.read_text()) if golden_path.exists() else {}
        diffs = [p for p in fresh["ok"] if old.get("ok", {}).get(p) != fresh["ok"][p]]
        diffs += [p for p in fresh["fail"] if old.get("fail", {}).get(p) != fresh["fail"][p]]
        print(f"  routes captured: {len(fresh['ok'])} ok / {len(fresh['fail'])} failing")
        if diffs:
            print(f"  DRIFT on {len(set(diffs))} route(s):")
            for p in sorted(set(diffs)):
                print(f"    {p}")
            return 1
        print("  no drift")
        return 0

    golden_path.parent.mkdir(parents=True, exist_ok=True)
    golden_path.write_text(json.dumps(fresh, indent=2, sort_keys=True) + "\n")
    print(f"  wrote {golden_path.relative_to(ROOT)}: {len(fresh['ok'])} routes x 2 branches")
    statuses: dict[int, int] = {}
    for spec in fresh["ok"].values():
        statuses[spec["status"]] = statuses.get(spec["status"], 0) + 1
    print("  status spread (benign stub): " + ", ".join(f"{k}: {v}" for k, v in sorted(statuses.items())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
