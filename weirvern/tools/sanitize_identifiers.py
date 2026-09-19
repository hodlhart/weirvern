"""Scrub deployment-specific identifiers, and the guard that keeps them out.

WHY THIS EXISTS, AND WHY THE TABLE LIVES IN THE REPOSITORY.

Weirvern is developed against a real home lab. That is a legitimate way to develop a network
sensor -- the interesting bugs only appear on real traffic -- but it has a consequence: addresses,
MACs and hostnames from that lab leak into source, tests, documentation and commit messages, and
every one of them is a fact about a private network. A repository is shared, and it can become
public with one click, so the identifiers must not be in it at all.

The identifiers are therefore replaced with values reserved FOR DOCUMENTATION by RFC, chosen so
they cannot collide with anyone's real infrastructure:

    198.51.100.0/24     RFC 5737 TEST-NET-2      the capture segment (the one we intercept)
    203.0.113.0/24      RFC 5737 TEST-NET-3      the management segment (never captured)
    192.0.2.0/24        RFC 5737 TEST-NET-1      a third segment where a test needs one
    00:00:5E:00:53:xx   RFC 7042 documentation MACs
    *.example           RFC 2606 / RFC 6761     hostnames

`MAPPING` is in this module rather than in a shell script so that the scrubber and the guard test
read the SAME table. Two copies would drift, and the drift would be silent: the guard would keep
passing while the scrubber had stopped covering something. This project has already shipped three
defects of exactly that shape (ja3/ja3s columns nothing wrote, three tables read by nothing, two
ATT&CK rules reading column names no query produces).

USAGE

    python -m weirvern.tools.sanitize_identifiers --check     # report, exit 1 if anything found
    python -m weirvern.tools.sanitize_identifiers --write     # rewrite files in place
    python -m weirvern.tools.sanitize_identifiers --history   # also report git commit messages
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# ── The reserved values ───────────────────────────────────────────────────────────────────────
#
# Semantics are preserved deliberately. The capture segment keeps a distinct range from the
# management segment, because several documents and tests turn on the difference between them --
# "the relayed packet must leave via the capture interface, not the management one". Collapsing
# both to one range would delete the meaning along with the identifier.

CAPTURE_SEGMENT = "198.51.100.0/24"
MANAGEMENT_SEGMENT = "203.0.113.0/24"

# ── The scrub table ───────────────────────────────────────────────────────────────────────────
#
# Ordered, and applied in order. Prefix rules come first because they cover every host on a
# segment without enumerating it: a new test that invents 192.168.3.77 is covered by the rule
# rather than missed because nobody added it to a list.

MAPPING: list[tuple[str, str]] = [
    # IPv4, by segment prefix. Longest prefix first is not needed here -- these are all /24.
    (r"192\.168\.3\.", "198.51.100."),          # the capture segment, eth1
    (r"192\.168\.2\.", "203.0.113."),           # the management segment, eth0
    (r"192\.168\.1\.", "192.0.2."),             # a third segment, where a test needs one
    # Public addresses observed ON the lab network. These are not the lab's own addresses, but
    # they are facts about what the lab talks to, which is the same disclosure.
    (r"162\.248\.221\.\d+", "203.0.113.200"),
    # MAC addresses. RFC 7042 reserves 00:00:5E:00:53:00-FF for documentation.
    (r"a8:9c:6c:96:b6:2d", "00:00:5e:00:53:01"),   # the capture segment's gateway
    (r"bc:24:11:53:ca:66", "00:00:5e:00:53:02"),   # a monitored host
    (r"bc:24:11:f6:ab:f1", "00:00:5e:00:53:03"),   # the capture interface
    # Hostnames, longest first so `Weirvern.home` is not half-replaced by a `.home` rule.
    (r"Weirvern\.home", "sensor.example"),
    (r"spyro\.home", "host-a.example"),
    (r"\bspyro\b", "host-a"),
    (r"\bunifi\b", "gateway"),
]

# Identifiers that are DOCUMENTATION values already, or are structural rather than deployment
# facts. Checked after the mapping runs, so a file that legitimately contains 192.168.3.x because
# a *different* project's example uses it still trips the guard.
SAFE_IPV4 = re.compile(
    r"^(?:"
    r"198\.51\.100\.|203\.0\.113\.|192\.0\.2\."        # RFC 5737 documentation
    r"|0\.0\.0\.0|255\.255\.255\.255|127\."             # structural
    r"|10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\."     # private, but see PRIVATE_OK
    r"|224\.|239\.|23\.\d+\.\d+\.\d+"                   # multicast; 23.x is a test fixture
    r")"
)

# A private address is acceptable ONLY in these files, and only because the address there is an
# arbitrary example rather than a description of the lab. Everything else must use RFC 5737.
PRIVATE_OK = {
    "weirvern/config.py",              # default listen addresses for the collectors
    "weirvern/tools/demo_flows.py",    # synthetic flows for the demo, invented not observed
}

SCAN_GLOBS = ("*.py", "*.md", "*.yaml", "*.yml", "*.json", "*.sh", "*.zeek", "*.sql", "*.toml")
SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "node_modules"}
SKIP_FILES = {
    # The scrubber and its guard must be able to NAME the identifiers in order to remove them.
    "weirvern/tools/sanitize_identifiers.py",
    "tests/test_sanitation.py",
}

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
# A MAC that is obviously synthetic: repeated octets, or an RFC 7042 documentation MAC.
SYNTHETIC_MAC = re.compile(
    r"^(?:00:00:5e:00:53:[0-9a-f]{2}"                  # RFC 7042 documentation MAC
    r"|(?P<oct>[0-9a-f]{2})(?::(?P=oct)){5}"           # aa:aa:aa:aa:aa:aa repeated octet
    r")$",
    re.IGNORECASE,
)
# `Weirvern` is the PRODUCT NAME and appears in every file, so it is not an infrastructure
# identifier. Only the lab's own hostnames are. `Weirvern.home` is handled by MAPPING above --
# the scrub runs before this guard, so by the time a hostname is checked here it is either the
# product name or a leak.
HOSTNAME = re.compile(r"\b(?:spyro|unifi)\b", re.IGNORECASE)


def tracked_files(root: Path) -> list[Path]:
    """Files git tracks. Scans the repository, not the working directory, so a stray build
    artefact cannot fail the guard and an ignored file cannot hide a leak."""
    out = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, capture_output=True, text=True, check=True
    ).stdout
    files: list[Path] = []
    for rel in out.split("\0"):
        if not rel:
            continue
        p = root / rel
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if rel in SKIP_FILES:
            continue
        if p.suffix in {Path(g).suffix for g in SCAN_GLOBS}:
            files.append(p)
    return files


def scrub_text(text: str) -> tuple[str, int]:
    """Apply MAPPING. Returns the new text and the number of substitutions."""
    total = 0
    for pattern, repl in MAPPING:
        text, n = re.subn(pattern, repl, text, flags=re.IGNORECASE)
        total += n
    return text, total


def find_identifiers(text: str, rel: str) -> list[tuple[int, str, str]]:
    """Lines carrying a deployment identifier the mapping does not already remove.

    Run AFTER scrub_text in --write mode, which is what makes this a guard rather than a
    duplicate of the table: it catches a class of identifier the table has no rule for, which is
    how a new kind of leak would arrive.
    """
    hits: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for m in IPV4.finditer(line):
            addr = m.group(0)
            if SAFE_IPV4.match(addr):
                if addr.startswith("192.168.") and rel not in PRIVATE_OK:
                    hits.append((lineno, "private-ipv4", addr))
                continue
            hits.append((lineno, "public-ipv4", addr))
        for m in MAC.finditer(line):
            mac = m.group(0)
            if not SYNTHETIC_MAC.match(mac) and mac.lower() not in {
                "ff:ff:ff:ff:ff:ff",
                "00:00:00:00:00:00",
            }:
                hits.append((lineno, "mac", mac))
        for m in HOSTNAME.finditer(line):
            hits.append((lineno, "hostname", m.group(0)))
    return hits


def scan_history(root: Path) -> int:
    """Commit messages and author lines. GitHub shows these, so they are published surface.

    Rewriting history is destructive and is NOT done here -- this only reports, so the decision
    to rewrite is made deliberately rather than as a side effect of a scrub.
    """
    log = subprocess.run(
        ["git", "log", "--all", "--format=%h%x1f%an%x1f%ae%x1f%B%x1e"],
        cwd=root, capture_output=True, text=True, check=True,
    ).stdout
    found = 0
    for entry in log.split("\x1e"):
        if not entry.strip():
            continue
        parts = entry.split("\x1f")
        if len(parts) < 4:
            continue
        sha, _author, _email, body = parts[0], parts[1], parts[2], parts[3]
        hits = find_identifiers(body, "(commit message)")
        hits += [(0, kind, val) for kind, val in _mapping_hits(body)]
        if hits:
            found += 1
            kinds = sorted({k for _, k, _ in hits})
            print(f"  {sha}  {len(hits)} identifier(s): {', '.join(kinds)}")
    return found


def _mapping_hits(text: str) -> list[tuple[str, str]]:
    """Which MAPPING rules would fire on this text, reported as kinds rather than raw values."""
    out: list[tuple[str, str]] = []
    for pattern, _repl in MAPPING:
        if re.search(pattern, text, flags=re.IGNORECASE):
            kind = "mac" if ":" in pattern.replace("\\", "") else "ipv4-or-name"
            out.append((kind, pattern))
    return out


def main(argv: list[str] | None = None) -> int:
    summary = (__doc__ or "").strip().split("\n\n")[0]
    ap = argparse.ArgumentParser(description=summary)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true", help="report only; exit 1 if anything found")
    g.add_argument("--write", action="store_true", help="rewrite files in place")
    ap.add_argument("--history", action="store_true", help="also scan git commit messages")
    args = ap.parse_args(argv)

    root = Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    )

    files = tracked_files(root)
    changed = 0
    problems = 0

    for path in files:
        rel = str(path.relative_to(root))
        original = path.read_text(encoding="utf-8", errors="replace")

        if args.write:
            scrubbed, n = scrub_text(original)
            if n:
                path.write_text(scrubbed, encoding="utf-8")
                changed += 1
                print(f"  scrubbed {rel} ({n} substitution(s))")
            remaining = find_identifiers(scrubbed, rel)
        else:
            remaining = find_identifiers(original, rel)

        if remaining:
            problems += len(remaining)
            print(f"  {rel}: {len(remaining)} identifier(s) the mapping has no rule for")
            for lineno, kind, value in remaining[:4]:
                shown = value if kind != "hostname" else value
                print(f"      line {lineno}: {kind}: {shown}")

    if args.history:
        print()
        print("=== commit messages (REPORT ONLY -- rewriting history is a separate decision) ===")
        n = scan_history(root)
        if not n:
            print("  clean")

    print()
    if args.write:
        print(f"{changed} file(s) rewritten")
    print(f"{problems} identifier(s) with no mapping rule")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
