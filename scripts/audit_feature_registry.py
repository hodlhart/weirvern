#!/usr/bin/env python3
"""Check the source-to-feature registry against the ClickHouse schema.

The registry is a human document with one machine-readable block. This script answers the
question a reader cannot answer by eye: does every table the schema declares appear in the
registry, and is every status one of the agreed values?

It deliberately reads the schema source, not a live database: the contract must be checkable in
CI without a cluster. Unknown statuses and unknown table names are failures, not warnings.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "weirvern" / "schema"
REGISTRY = ROOT / "docs" / "design" / "source-feature-registry.md"

STATUSES = {"feature-now", "feature-planned", "join-only", "output", "excluded"}
CREATE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:weirvern\.)?([a-z][a-z0-9_]*)\b", re.I
)
ROW_RE = re.compile(r"^([a-z][a-z0-9_]*)\s*\|\s*([a-z-]+)\s*$", re.M)
BEGIN = "<!-- registry:begin -->"
END = "<!-- registry:end -->"


def schema_tables() -> set[str]:
    tables: set[str] = set()
    for path in sorted(SCHEMA_DIR.glob("*.sql")):
        text = path.read_text()
        text = re.sub(r"--[^\n]*", "", text)
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        tables.update(m.group(1) for m in CREATE_RE.finditer(text))
    return tables


def registry_rows(text: str) -> dict[str, str]:
    if BEGIN not in text or END not in text:
        raise ValueError("registry machine block markers are missing")
    block = text.split(BEGIN, 1)[1].split(END, 1)[0]
    rows: dict[str, str] = {}
    for match in ROW_RE.finditer(block):
        name, status = match.group(1), match.group(2)
        if name in rows:
            raise ValueError(f"table declared twice in the registry: {name}")
        rows[name] = status
    return rows


def audit(text: str | None = None) -> list[str]:
    text = REGISTRY.read_text() if text is None else text
    declared = schema_tables()
    try:
        rows = registry_rows(text)
    except ValueError as exc:
        return [str(exc)]
    problems: list[str] = []
    missing = sorted(declared - set(rows))
    if missing:
        problems.append("schema tables missing from the registry: " + ", ".join(missing))
    unknown = sorted(set(rows) - declared)
    if unknown:
        problems.append("registry names tables the schema does not declare: " + ", ".join(unknown))
    bad = sorted(name for name, status in rows.items() if status not in STATUSES)
    if bad:
        problems.append("unknown registry status for: " + ", ".join(bad))
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="exit non-zero if the registry drifts")
    parser.add_argument("--registry", type=Path, default=REGISTRY,
                        help="path to a registry document (for the guard test)")
    args = parser.parse_args(argv)

    text = args.registry.read_text()
    problems = audit(text)
    if problems:
        print("FEATURE REGISTRY CHECK FAILED")
        for problem in problems:
            print("  -", problem)
        return 1
    rows = registry_rows(text)
    print(f"FEATURE REGISTRY OK: {len(rows)} tables, "
          f"{len(schema_tables())} schema tables, no unknown statuses")
    return 0


if __name__ == "__main__":
    sys.exit(main())
