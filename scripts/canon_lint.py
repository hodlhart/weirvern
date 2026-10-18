#!/usr/bin/env python3
"""The canon ratchet (docs/design/canon.md §C-11).

Compares the live stylesheet and markup against `docs/design/canon.json` and against
`docs/design/canon_baseline.json`:

  * NEW violation       -> exit 1 (the gate goes red)
  * unchanged debt      -> exit 0, listed in the report
  * debt paid down      -> exit 0, reported so the baseline can shrink in the same commit

`--write-baseline` records today's debt. It is never a way to make a new violation pass: a human
writes the baseline once, and every later run compares against it.

Vocabulary (tab id + label vs the ledger) is STRICT — no baseline tolerance, because the ledger is
the thing that gives a surface its name.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"
DOCS = ROOT / "docs" / "design"
CANON = DOCS / "canon.json"
LEDGER = DOCS / "ledger.json"
BASELINE = DOCS / "canon_baseline.json"

HEX = re.compile(r"#[0-9a-fA-F]{3,8}\b")
FS = re.compile(r"font-size:\s*([0-9.]+px)")
FONT_SHORTHAND = re.compile(r"font:\s*([0-9.]+px)\s*/")
RADIUS = re.compile(r"border-radius:\s*([^;{}]+)")
TITLE_ATTR = re.compile(r"\btitle\s*=\s*\"")
TITLE_PROP = re.compile(r"\btitle:\s*[`\"]")
TAB = re.compile(r'data-view="([a-z0-9-]+)"\s*>([^<]+)<')
SECTION = re.compile(r'id="view-([a-z0-9-]+)"')


def strip_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.S)


def root_block(css: str) -> str:
    """The `:root { ... }` declaration block, brace-counted (not regex-nested)."""
    start = css.find(":root")
    if start < 0:
        return ""
    open_at = css.find("{", start)
    if open_at < 0:
        return ""
    depth = 0
    for i in range(open_at, len(css)):
        if css[i] == "{":
            depth += 1
        elif css[i] == "}":
            depth -= 1
            if depth == 0:
                return css[open_at : i + 1]
    return css[open_at:]


def collect(canon: dict) -> dict[str, Counter]:
    """Every violation as a multiset keyed by the value that caused it."""
    raw = (WEB / "style.css").read_text(encoding="utf-8")
    css = strip_comments(raw)
    block = root_block(css)
    outside = css.replace(block, "", 1)

    hexes = Counter(v.lower() for v in HEX.findall(outside))

    ramp = {f"{n}px" for n in canon["type"]["ramp_px"]}
    sizes = Counter(v for v in FS.findall(outside) if v not in ramp)
    sizes.update(v for v in FONT_SHORTHAND.findall(outside) if v not in ramp)

    allowed_r = {f"{n}px" for n in canon["radius"]["allowed_px"]}
    allowed_r |= set(canon["radius"]["allowed_special"])
    radii: Counter[str] = Counter()
    for value in RADIUS.findall(outside):
        for part in value.split():
            part = part.strip()
            if part.startswith("var(") or not part:
                continue
            if part not in allowed_r:
                radii[part] += 1

    markup = (WEB / "index.html").read_text(encoding="utf-8")
    hover = len(TITLE_ATTR.findall(markup))
    for js in sorted(WEB.glob("*.js")):
        hover += len(TITLE_PROP.findall(js.read_text(encoding="utf-8")))

    return {"hex": hexes, "font_size": sizes, "radius": radii, "hover_only": Counter({"titles": hover})}


def vocabulary() -> list[str]:
    """Tab id/label and view sections against the ledger. Strict, no baseline."""
    ledger = json.loads(LEDGER.read_text(encoding="utf-8"))
    known = {v["id"]: v for v in ledger["views"]}
    html = (WEB / "index.html").read_text(encoding="utf-8")
    problems: list[str] = []

    tabs = TAB.findall(html)
    seen: set[str] = set()
    for vid, label in tabs:
        label = label.strip()
        seen.add(vid)
        if vid not in known:
            problems.append(f"tab '{vid}' has no ledger entry")
            continue
        if known[vid]["label"] != label:
            problems.append(
                f"tab '{vid}' says {label!r}, the ledger says {known[vid]['label']!r}"
            )
        if not known[vid]["tab"]:
            problems.append(f"tab '{vid}' is marked tab:false in the ledger")

    for vid in SECTION.findall(html):
        if vid not in known:
            problems.append(f"section '#view-{vid}' has no ledger entry")

    for vid, entry in known.items():
        if entry["tab"] and vid not in seen:
            problems.append(f"ledger says tab '{vid}' exists, the markup has no such tab")

    return problems


def compare(current: dict[str, Counter], baseline: dict) -> tuple[list[str], list[str]]:
    """Return (new debt lines, paid-down lines)."""
    new: list[str] = []
    paid: list[str] = []
    for kind, counts in current.items():
        base = baseline.get(kind, {})
        for value, n in sorted(counts.items()):
            before = int(base.get(value, 0))
            if n > before:
                new.append(f"{kind}: {value!r} x{n} (baseline x{before})")
            elif n < before:
                paid.append(f"{kind}: {value!r} x{before} -> x{n}")
        for value, n in sorted(base.items()):
            if value not in counts and int(n) > 0:
                paid.append(f"{kind}: {value!r} x{n} -> gone")
    return new, paid


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Canon ratchet for the weirvern console")
    ap.add_argument("--write-baseline", action="store_true", help="record today's debt")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    canon = json.loads(CANON.read_text(encoding="utf-8"))
    current = collect(canon)

    if args.write_baseline:
        snapshot = {kind: dict(sorted(c.items())) for kind, c in current.items()}
        BASELINE.write_text(json.dumps(snapshot, indent=2) + "\n", encoding="utf-8")
        print(f"baseline written: {BASELINE.relative_to(ROOT)}")
        for kind, counts in current.items():
            print(f"  {kind}: {sum(counts.values())} violation(s) over {len(counts)} value(s)")
        return 0

    if not BASELINE.exists():
        print(f"missing {BASELINE.relative_to(ROOT)} — run with --write-baseline once", file=sys.stderr)
        return 2
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    new, paid = compare(current, baseline)
    vocab = vocabulary()

    if args.json:
        print(json.dumps({"new": new, "paid": paid, "vocabulary": vocab,
                          "counts": {k: sum(v.values()) for k, v in current.items()}}, indent=2))
    else:
        print("canon lint — " + str(ROOT.name))
        for kind, counts in current.items():
            print(f"  {kind:10s} {sum(counts.values()):4d} known-debt occurrence(s)")
        if paid:
            print("\n  debt paid down since the baseline:")
            for line in paid:
                print("   -", line)
        if vocab:
            print("\n  VOCABULARY (strict):")
            for line in vocab:
                print("   x", line)
        if new:
            print("\n  NEW DEBT (gate red):")
            for line in new:
                print("   x", line)
        else:
            print("\n  no new debt")

    if new or vocab:
        print("\nFAIL — the canon found new violations; fix them or justify a canon change", file=sys.stderr)
        return 1
    print("\nOK — no new debt" + (f"; {len(paid)} item(s) can be removed from the baseline" if paid else ""))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
