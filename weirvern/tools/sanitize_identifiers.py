"""Scrub deployment-specific identifiers, and the guard that keeps them out.

WHY THIS EXISTS, AND WHY THE TABLE LIVES IN THE REPOSITORY.

Weirvern is developed against a real home lab. That is a legitimate way to develop a network
sensor -- the interesting bugs only appear on real traffic -- but it has a consequence: addresses,
MACs and hostnames from that lab leak into source, tests and documentation, and every one of them
is a fact about a private network. A repository is shared, and it can become public with one
click, so the identifiers must not be in it at all.

The first pass found 302 of them. They are replaced with values reserved FOR DOCUMENTATION by RFC,
chosen so they cannot collide with anyone's real infrastructure:

    198.51.100.0/24     RFC 5737 TEST-NET-2      the capture segment (the one we intercept)
    203.0.113.0/24      RFC 5737 TEST-NET-3      the management segment (never captured)
    192.0.2.0/24        RFC 5737 TEST-NET-1      a third segment where a test needs one
    00:00:5E:00:53:xx   RFC 7042 documentation MACs
    *.example           RFC 2606 / RFC 6761     hostnames

`MAPPING` is in this module rather than in a shell script so that the scrubber and the guard test
read the SAME table. Two copies would drift, and the drift would be silent: the guard would keep
passing while the scrubber had stopped covering something. This project has already shipped three
defects of exactly that shape (ja3/ja3s columns nothing wrote, three tables read by nothing, four
ATT&CK rules reading column names no query produces).

USAGE

    python -m weirvern.tools.sanitize_identifiers --check     # report; exit 1 if anything found
    python -m weirvern.tools.sanitize_identifiers --write     # rewrite files in place
    python -m weirvern.tools.sanitize_identifiers --history   # also report git commit messages
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

CAPTURE_SEGMENT = "198.51.100.0/24"
MANAGEMENT_SEGMENT = "203.0.113.0/24"

# ── The scrub table ───────────────────────────────────────────────────────────────────────────
#
# Ordered, and applied in order. Prefix rules cover every host on a segment without enumerating
# it: a new test that invents an address in a mapped range is covered by the rule rather than
# missed because nobody added it to a list.
#
# THE TRAILING OCTET IS CAPTURED AND RE-EMITTED. A rule that replaced only the prefix turned
# `10.0.0.0/16` into `198.51.100./16` and `10.0.0.5` into `198.51.100.` -- dropping the octet
# that carried the meaning and turning a valid CIDR into a parse error. That bug shipped into 23
# files before a test caught it. Every segment rule keeps its last octet for that reason.

MAPPING: list[tuple[str, str]] = [
    # The lab's own segments. eth1 was the capture side, eth0 the management side.
    #
    # THE WILDCARD FORM IS COVERED FIRST, and it has to be. Every rule below requires a DIGIT in
    # the last octet, so prose like "the 192.168.3.x segment" passed the guard untouched -- it
    # named the network just as plainly as a full address does, and it leaked into a commit
    # message where the digit-only rules could not see it. A description of a real segment is
    # still a description of a real segment, and commit messages are published surface.
    #
    # Verified: `192.168.3.x` and `192.168.2.x` are flagged by the guard and rewritten here.
    (r"192\.168\.3\.[xX*]", "198.51.100.x"),
    (r"192\.168\.2\.[xX*]", "203.0.113.x"),
    (r"192\.168\.1\.[xX*]", "192.0.2.x"),
    (r"192\.168\.3\.(\d+)", r"198.51.100.\1"),
    (r"192\.168\.2\.(\d+)", r"203.0.113.\1"),
    (r"192\.168\.1\.(\d+)", r"192.0.2.\1"),
    # A CGNAT/tailnet address -- a way INTO the lab, not just a host on it.
    (r"100\.98\.39\.(\d+)", r"100.64.0.\1"),
    # A PUBLIC address the lab was observed contacting. Mapped to 1.2.3.4 rather than to an
    # RFC 5737 value: 162.248.221.x was public, and TEST-NET ranges are classified private by
    # `ipaddress.is_private`, so mapping it there inverted the meaning of tests about public
    # addresses. 1.2.3.4 is public, invented, and universally understood as a placeholder.
    (r"162\.248\.221\.(\d+)", "1.2.3.4"),
    # Invented private fixtures in the tests. Not the lab's ranges, but a private address in a
    # committed fixture is indistinguishable from an observed one -- nothing marks it synthetic
    # to a reader.
    (r"10\.0\.0\.(\d+)", r"198.51.100.\1"),
    (r"10\.0\.5\.(\d+)", r"198.51.100.\1"),
    (r"10\.9\.9\.(\d+)", r"203.0.113.\1"),
    (r"10\.20\.30\.(\d+)", r"192.0.2.\1"),
    (r"10\.43\.0\.(\d+)", r"198.51.100.\1"),        # the platform's service CIDR, a default
    (r"172\.16\.5\.(\d+)", r"192.0.2.\1"),
    # MAC addresses. RFC 7042 reserves 00:00:5E:00:53:00-FF for documentation.
    (r"a8:9c:6c:96:b6:2d", "00:00:5e:00:53:01"),    # the capture segment's gateway
    (r"bc:24:11:53:ca:66", "00:00:5e:00:53:02"),    # a monitored host
    (r"bc:24:11:f6:ab:f1", "00:00:5e:00:53:03"),    # the capture interface
    # Hostnames, longest first so `sensor.example` is not half-replaced by a shorter rule.
    (r"Weirvern\.home", "sensor.example"),
    (r"spyro\.home", "host-a.example"),
    (r"\bspyro\b", "host-a"),
    (r"\bunifi\b", "gateway"),
    (r"derp\d+[a-z]*\.tailscale\.com", "relay.example.net"),
]

# ── Classifiers ───────────────────────────────────────────────────────────────────────────────

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")

# Addresses a PERSON TYPED rather than observed. This guard exists to catch facts about a real
# network, and a placeholder is not one. Each form below is one nobody's infrastructure uses:
#
#   a.a.a.a          one octet repeated -- 2.2.2.2, 8.8.8.8, 4.4.4.4
#   1.2.3.4          the canonical sequential placeholder
#   8.8.8.8/1.1.1.1  public resolvers, written in every networking document ever
#   93.184.216.34    example.com, reserved by RFC 2606 for documentation
#   100.64.0.x       CGNAT as a CODE CONSTANT (the range is tested by hand in revdns.py); the
#                    lab's own tailnet address was 100.98.39.x and is mapped away above
SYNTHETIC_IPV4 = re.compile(
    r"^(?:"
    r"(?P<oct>\d{1,3})(?:\.(?P=oct)){3}"
    r"|1\.2\.3\.4"
    r"|93\.184\.216\.34"
    r"|100\.64\.0\.\d+"
    r")$"
)

# RFC 5737 documentation ranges. Not real, and recognised as such by every reader and tool.
DOC_IPV4 = re.compile(r"^(?:198\.51\.100\.|203\.0\.113\.|192\.0\.2\.)")
# Structural addresses: binding, broadcast, loopback, multicast.
STRUCTURAL_IPV4 = re.compile(r"^(?:0\.0\.0\.0|255\.255\.255\.255|127\.|224\.|239\.)")
# ANY private range, in every RFC 1918 block plus CGNAT -- not only 192.168.x. An earlier version
# exempted 10/8 and 172.16/12 wholesale, which meant a lab address written in one of those ranges
# was never reported.
PRIVATE_IPV4 = re.compile(
    r"^(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.|"
    r"100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)"
)

# The CANONICAL private examples, allowed BY VALUE. A file-wide exemption was removed after it
# let a real address through (verified by injecting one and watching the guard stay silent); these
# are individual values, which is as narrow as an exemption can be.
#
# They are needed because `revdns.is_private` must be tested WITH a private address -- there is
# nothing else to test it against -- and `10.0.0.1` is the example in every networking document.
# None of them is an address this project was developed on.
UNIVERSAL_EXAMPLES = {
    "10.0.0.0", "10.0.0.1", "10.0.0.2",
    "172.16.0.0", "172.16.0.1", "172.16.0.5",
    "192.168.0.0", "192.168.0.1", "192.168.1.1",
    "100.64.0.0",
    # SOFTWARE DEFAULTS, not observations. These are the networks a stock Kubernetes install and a
    # stock Docker daemon choose for themselves, and the product has to name them to exclude its
    # own plumbing from the data it learns from. They are the same on every deployment, so they
    # describe the SOFTWARE rather than anyone's network -- which is what separates them from a
    # lab address.
    #
    # Added BY VALUE and per network, deliberately: the value-based list is as narrow as an
    # exemption gets, and a file-wide or range-wide allowance is what let a real address through
    # before. Verified these are the real defaults on the deployment's own node (cni0 10.42.0.1/24,
    # service CIDR 10.43.0.0/16, docker0 172.17.0.1/16) -- a drift here would make the exclusion
    # rules silently match nothing.
    "10.42.0.0", "10.42.0.1",
    "10.43.0.0", "10.43.0.1",
    "172.17.0.0", "172.17.0.1",
}

# A MAC that is obviously SYNTHETIC rather than captured -- the test is whether the octets look
# chosen by a person rather than observed on a wire. A REAL vendor prefix matches none of these,
# so it is still reported, which is the point of the guard.
#
# This comment deliberately does NOT name the hardware the mapped prefixes belong to. Stating
# "the gateway is a X" is a fact about a private network even without an address attached, and it
# is the kind of detail that looks harmless in a code comment.
SYNTHETIC_MAC = re.compile(
    r"^(?:"
    r"00:00:5e:00:53:[0-9a-f]{2}"                 # RFC 7042 documentation
    r"|aa:bb:cc:dd:ee:[0-9a-f]{2}"                # the fixture pattern this repo uses
    r"|11:22:33:44:55:66|de:ad:be:ef:00:01"       # canonical placeholders
    r"|(?P<moct>[0-9a-f]{2})(?::(?P=moct)){5}"    # a single repeated octet
    r")$",
    re.IGNORECASE,
)
STRUCTURAL_MAC = {"ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"}

# `Weirvern` is the PRODUCT NAME and appears in every file, so it is not an infrastructure
# identifier. Only the lab's own hostnames are. `Weirvern.home` is handled by MAPPING above --
# the scrub runs before this guard, so by the time a hostname is checked it is either the product
# name or a leak.
HOSTNAME = re.compile(r"\b(?:spyro|unifi)\b", re.IGNORECASE)

# ── File selection ────────────────────────────────────────────────────────────────────────────
#
# By GIT TRACKING, not by suffix. A suffix allowlist missed `Containerfile` (no extension) and
# `.env.example` (a doubled one). Both were tracked and both carried real segment addresses, so
# the guard reported the tree clean while two files still described the lab.

BINARY_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tgz", ".whl",
    ".woff", ".woff2", ".ttf", ".otf", ".so", ".o", ".a", ".pyc", ".db", ".sqlite",
}
SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", ".ruff_cache", "node_modules"}
SKIP_FILES = {
    # The scrubber and its guard must be able to NAME the identifiers in order to remove them,
    # and must contain the classifier patterns that describe what a real one looks like.
    "weirvern/tools/sanitize_identifiers.py",
    "tests/test_sanitation.py",
}


def tracked_files(root: Path) -> list[Path]:
    """Files git tracks. Scans the repository rather than the working directory, so a stray build
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
        if p.suffix.lower() in BINARY_SUFFIXES:
            continue
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
    """Lines carrying a deployment identifier.

    Run AFTER scrub_text in --write mode, which is what makes this a guard rather than a duplicate
    of the table: it catches a class of identifier the table has no rule for, which is how the
    next kind of leak would arrive.
    """
    hits: list[tuple[int, str, str]] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for m in IPV4.finditer(line):
            addr = m.group(0)
            if (
                SYNTHETIC_IPV4.match(addr)
                or DOC_IPV4.match(addr)
                or STRUCTURAL_IPV4.match(addr)
                or addr in UNIVERSAL_EXAMPLES
            ):
                continue
            if PRIVATE_IPV4.match(addr):
                hits.append((lineno, "private-ipv4", addr))
            else:
                hits.append((lineno, "public-ipv4", addr))
        for m in MAC.finditer(line):
            mac = m.group(0)
            if not SYNTHETIC_MAC.match(mac) and mac.lower() not in STRUCTURAL_MAC:
                hits.append((lineno, "mac", mac))
        for m in HOSTNAME.finditer(line):
            hits.append((lineno, "hostname", m.group(0)))
    return hits


def _mapping_hits(text: str) -> list[str]:
    """Which MAPPING rules would fire on this text, as rule indices rather than raw values."""
    return [p for p, _ in MAPPING if re.search(p, text, flags=re.IGNORECASE)]


def scan_history(root: Path) -> int:
    """Commit messages. GitHub shows these, so they are published surface.

    Rewriting history is destructive and is NOT done here -- this only reports, so the decision
    to rewrite is made deliberately rather than as a side effect of a scrub.
    """
    # `--branches`, NOT `--all`. `--all` includes refs/original/*, which `git filter-branch` creates
    # as a local backup of the PRE-rewrite state -- so a message that has been rewritten away still
    # appears here and the check reports a leak that no branch contains. Verified both ways: with
    # --all it flagged a commit that `git merge-base --is-ancestor` showed was not in main.
    log = subprocess.run(
        ["git", "log", "--branches", "--format=%h%x1f%B%x1e"],
        cwd=root, capture_output=True, text=True, check=True,
    ).stdout
    found = 0
    for entry in log.split("\x1e"):
        if not entry.strip():
            continue
        parts = entry.split("\x1f")
        if len(parts) < 2:
            continue
        sha, body = parts[0], parts[1]
        hits = find_identifiers(body, "(commit message)")
        patterns = _mapping_hits(body)
        if hits or patterns:
            found += 1
            kinds = sorted({k for _, k, _ in hits})
            detail = ", ".join(kinds) if kinds else f"{len(patterns)} mapped range(s)"
            print(f"  {sha}  {detail}")
    return found


def main(argv: list[str] | None = None) -> int:
    summary = (__doc__ or "").strip().split("\n\n")[0]
    ap = argparse.ArgumentParser(description=summary)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--check", action="store_true", help="report only; exit 1 if anything found")
    g.add_argument("--write", action="store_true", help="rewrite files in place")
    g.add_argument(
        "--filter", action="store_true",
        help="read stdin, write the scrubbed text to stdout (for `git filter-branch --msg-filter`)",
    )
    ap.add_argument("--history", action="store_true", help="also scan git commit messages")
    args = ap.parse_args(argv)

    if args.filter:
        # Used by scripts/scrub_git_messages.sh via `git filter-branch --msg-filter`. Sharing
        # MAPPING matters here: a second, hand-copied list in the shell script would drift from
        # this one, and the drift would be silent -- messages scrubbed by a stale table while the
        # file scrubber moved on.
        sys.stdout.write(scrub_text(sys.stdin.read())[0])
        return 0

    root = Path(
        subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    )

    changed = 0
    problems = 0

    for path in tracked_files(root):
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
            print(f"  {rel}: {len(remaining)} identifier(s) with no mapping rule")
            for lineno, kind, value in remaining[:4]:
                print(f"      line {lineno}: {kind}: {value}")

    if args.history:
        print()
        print("=== commit messages (REPORT ONLY -- rewriting history is a separate decision) ===")
        if not scan_history(root):
            print("  clean")

    print()
    if args.write:
        print(f"{changed} file(s) rewritten")
    print(f"{problems} identifier(s) with no mapping rule")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
