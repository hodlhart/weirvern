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
    python -m weirvern.tools.sanitize_identifiers --write     # rewrite PROSE only; see below
    python -m weirvern.tools.sanitize_identifiers --history   # also report git commit messages

--WRITE REFUSES TEST FILES. In a test, an address is the FIXTURE -- the value the assertion
compares against -- so rewriting it changes what the test asserts while leaving it green. Measured:
--write turned `10.0.0.0/8` into `198.51.100.0/8` inside a test, and the suite kept passing while
proving a different statement. --write therefore skips anything under `tests/`, any `test_*.py` /
`*_test.py` / `conftest.py`, and the jsdom harness's fixture bundle; it also leaves quoted literals
on an assertion line and raw/regex literals alone in every other file, and reports every skip.
--check still reads all of them: an identifier in a test is still a leak, and a human decides how
to replace it.
"""

from __future__ import annotations

import argparse
import difflib
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath

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
    # A second observed public endpoint (2026-10-16), same convention as the rule above. It
    # reached GitHub inside a COMMIT MESSAGE before this rule existed: the file scrubber and the
    # history scan cannot see a message that is written after the gate has already run, and the
    # gate was run before the commit. Both halves of that lesson are recorded here -- the rule,
    # and (in push_gated.sh's usage) commit first, publish second.
    (r"23\.82\.14\.(\d+)", "1.2.3.4"),
    # Invented private fixtures in the tests. Not the lab's ranges, but a private address in a
    # committed fixture is indistinguishable from an observed one -- nothing marks it synthetic
    # to a reader.
    (r"10\.0\.0\.(\d+)", r"198.51.100.\1"),
    (r"10\.0\.5\.(\d+)", r"198.51.100.\1"),
    (r"10\.9\.9\.(\d+)", r"203.0.113.\1"),
    # `10.20.30.0/24` is NOT rewritten, deliberately. It is the SYNTHETIC range this project's own
    # NetFlow generator emits ("Documentation-range hosts so this never emits a real address by
    # accident"), so it names nothing on anyone's network -- and rewriting it corrupted product code
    # and tests, because a legitimate reference to the test data was treated as a leak. It is
    # allowed by value in UNIVERSAL_EXAMPLES instead.
    # `10.43.0.0/16` is the k3s SERVICE CIDR -- a software default, identical on every
    # deployment, and one the product MUST name to exclude the cluster's own plumbing from what it
    # learns. It is therefore NOT scrubbed: the rule that used to rewrite it (10.43.0.N ->
    # 198.51.100.N) fired on the default and silently changed what the product excludes, because
    # the exclusion list contained the rewritten value. A scrubber must not edit behaviour.
    #
    # The addresses it used to catch are in `10.42.0.0/16` (the pod CIDR) and the service range's
    # .0/.1, both covered by UNIVERSAL_EXAMPLES by value. A real lab host in 10.43.0.0/16 would
    # still be flagged as private-ipv4 and must be handled by value if one ever appears.
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
# Structural addresses: binding, broadcast, loopback, multicast, and NETMASKS.
#
# A NETMASK IS A PROTOCOL CONSTANT, not a fact about anyone's network -- the same category
# as the limited broadcast address above. `255.255.255.0` describes the SHAPE of a network
# (it is a /24) and can never be assigned to a host, so it cannot leak anything about a real
# deployment. The forms are listed explicitly rather than as a `255.255.` prefix so the rule
# stays as narrow as the others; extend the list when the gate reports another mask form
# (255.255.255.254 etc.).
STRUCTURAL_IPV4 = re.compile(
    r"^(?:0\.0\.0\.0|255\.255\.255\.255|127\.|224\.|239\.|"
    r"255\.255\.255\.0|255\.255\.254\.0|255\.255\.255\.254|255\.255\.0\.0|255\.0\.0\.0|"
    # LINK-LOCAL. Assigned by the kernel itself when DHCP fails, so it is a statement about the
    # PROTOCOL rather than about anyone's network -- the same category as loopback and multicast.
    # The product must name it to exclude meaningless flow, and a guard that flags it is a guard
    # that gets switched off.
    r"169\.254\.)"
)
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
    # THE MASKED RESULT of 198.51.100.0/16, which `ipaddress` produces with strict=False. It
    # appears only where that over-match is explained and where it is asserted to be REFUSED -- it
    # is the output of a documented operation, not an observed address. Allowed by value, which is
    # as narrow as an exemption gets.
    "198.51.0.0", "198.51.0.1",
    # THE SYNTHETIC TEST RANGE, by value. Emitted only by this project's own generator, and
    # referenced in the docs and tests that explain the exclusion feature. A real address in this
    # range would still be reported as private-ipv4 -- only these exact values are allowed.
    "10.20.30.0",
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


# ── What --WRITE must never rewrite ──────────────────────────────────────────────────────────
#
# A REWRITE IS ONLY SAFE WHERE THE VALUE IS PROSE. In a test, an address is the FIXTURE -- the
# value the assertion is written against. Replacing it changes what the test asserts while leaving
# the suite green, which is worse than leaving the identifier in place: the run still passes and
# now proves a different statement. Measured: --write replaced `10.0.0.0/8` with
# `198.51.100.0/8` inside a test and nothing went red.
#
# The same reasoning applies, line by line, inside every other file: a quoted literal on an
# assertion line, and a raw/regex literal, are CODE that states a value, not prose that mentions
# one. So --write refuses test files outright and leaves those spans alone everywhere, reporting
# what it skipped. --check still reads all of them -- an identifier in a test is still a leak, and
# a human decides how to replace it.
TEST_DIR_PARTS = {"tests", "test"}
TEST_FILE = re.compile(r"^(?:test_.*\.py|.*_test\.py|conftest\.py)$")
# The jsdom harness's fixture bundle: every string in it is a DOM fixture or an assertion about
# one, and it is generated into a single 600 KB file where a global substitution is unreviewable.
PROTECTED_FIXTURES = {"scripts/jsdom_render.js"}

_ASSERTION_LINE = re.compile(
    r"^\s*(?:assert\b|self\.assert\w+|self\.fail\b|pytest\.(?:raises|warns|approx)\b|"
    r"raise\s+AssertionError\b)"
)
_REGEX_CALL = re.compile(
    r"\bre\.(?:compile|match|search|fullmatch|sub|subn|finditer|findall|split)\s*\("
)
_STRING_PREFIXES = {"r", "rb", "br", "rf", "fr", "b", "f", "u"}


def is_test_path(rel: str) -> bool:
    """True when --write must leave this path byte-identical.

    Deliberately broad: a test is anything under a `tests/`/`test/` path component, anything named
    `test_*.py`, `*_test.py` or `conftest.py`, and the jsdom fixture bundle. Missing a test costs
    an assertion; skipping a non-test only means a human reads the report and fixes it.
    """
    p = PurePosixPath(rel)
    if rel in PROTECTED_FIXTURES or p.name in {PurePosixPath(f).name for f in PROTECTED_FIXTURES}:
        return True
    if any(part in TEST_DIR_PARTS for part in p.parts[:-1]):
        return True
    return bool(TEST_FILE.match(p.name))


def _opens_literal(line: str, i: int) -> bool:
    """Whether the quote at `i` opens a string literal rather than sitting inside a word.

    `don't` in a comment must not start a span that swallows the rest of the line and hides a real
    address from the scrubber. A preceding identifier character is allowed only when it is a
    string prefix (`f"`, `r"`, `rb"`), and the prefix itself must not continue an identifier.
    """
    if i == 0:
        return True
    prev = line[i - 1]
    if not (prev.isalnum() or prev == "_"):
        return True
    k = i
    while k > 0 and (i - k) < 2 and line[k - 1].isalpha():
        k -= 1
    if line[k:i].lower() not in _STRING_PREFIXES:
        return False
    return k == 0 or not (line[k - 1].isalnum() or line[k - 1] == "_")


def _quoted_spans(line: str) -> list[tuple[int, int, bool]]:
    """(start, end, is_raw) for every string literal on the line.

    A scanner rather than a regex because escapes and triple quotes both appear in this tree and a
    regex that gets either wrong either eats code or protects the wrong span.
    """
    spans: list[tuple[int, int, bool]] = []
    i, n = 0, len(line)
    while i < n:
        ch = line[i]
        if ch not in "\"'" or not _opens_literal(line, i):
            i += 1
            continue
        raw = _literal_prefix(line, i).lower() in {"r", "rb", "br", "rf", "fr"}
        if line.startswith(ch * 3, i):
            end = line.find(ch * 3, i + 3)
            stop = n if end == -1 else end + 3
            spans.append((i, stop, raw))
            i = stop
            continue
        j = i + 1
        while j < n:
            if line[j] == "\\":
                j += 2
                continue
            if line[j] == ch:
                j += 1
                break
            j += 1
        spans.append((i, min(j, n), raw))
        i = max(j, i + 1)
    return spans


def _literal_prefix(line: str, start: int) -> str:
    k = start
    while k > 0 and (start - k) < 2 and line[k - 1].isalpha():
        k -= 1
    return line[k:start]


def _protected_spans(line: str) -> list[tuple[int, int, str]]:
    """Spans --write must not touch: quoted assertions, and raw/regex literals."""
    quoted = _quoted_spans(line)
    if not quoted:
        return []
    assertion = bool(_ASSERTION_LINE.match(line))
    regex = bool(_REGEX_CALL.search(line))
    out: list[tuple[int, int, str]] = []
    for start, end, raw in quoted:
        if assertion:
            out.append((start, end, "quoted assertion"))
        elif raw or regex:
            out.append((start, end, "regex literal"))
    return out


# ── THE CAPTURE RULE, IN THE PRODUCT MODULE SO THE GUARD AND ITS TEST SHARE ONE DEFINITION ──────
#
# A capture is a complete record of a real network, more revealing than any single address in it, and
# none may be committed. The rule lived only inside the guard, and the guard's own must-fire test
# carried a PRIVATE COPY of it (audit F112) -- so narrowing the guard could not fail that test, which
# is a proof that cannot fail on the thing it proves.
#
# A CAPTURE'S FORMAT IS NOT ITS LAST SUFFIX (audit F111). The set named ".pcap.gz" while the
# comparison used `Path(...).suffix`, which is ALWAYS the final component, so `conn.pcap.gz` had
# suffix ".gz" and was committable AND invisible to the guard. The rule below walks the WHOLE suffix
# chain, which catches every compression of every format without enumerating the cross-product.
_CAPTURE_BASES = frozenset({".pcap", ".pcapng", ".cap"})
_COMPRESSION_SUFFIXES = frozenset({".gz", ".zst", ".bz2", ".xz", ".zip", ".7z"})
# Source and documentation suffixes. A file NAMED for a capture that is code or prose is not a
# capture: `tests/test_capture_loss.py` and 007_sensor_capture.sql are about a metric.
_SOURCE_SUFFIXES = frozenset({
    ".py", ".sql", ".md", ".sh", ".js", ".css", ".html", ".yaml", ".yml", ".toml", ".cfg", ".json",
})
# Suffixes that actually carry recorded traffic.
_DATA_SUFFIXES = frozenset({".log", ".txt", ".tsv", ".csv", ".jsonl", ".ndjson", ".bin", ".dat"})


def is_capture_path(path: str) -> bool:
    """True when `path` names a packet capture, compressed or not, or a capture-shaped data file.

    Three cases, in order of certainty:
      1. a capture FORMAT, however it is compressed (`x.pcap`, `x.pcap.gz`, `x.pcap.zst`);
      2. a file NAMED for a capture whose suffix is neither source nor documentation code;
      3. a file NAMED for a capture with a data suffix (a raw recording under a descriptive name).

    `suffixes` is used rather than `suffix` for case 1, and that is the whole of F111: `conn.pcap.gz`
    has a LAST suffix of `.gz` and a suffix CHAIN of `['.pcap', '.gz']`.
    """
    p = PurePosixPath(path)
    suffixes = [s.lower() for s in p.suffixes]
    name = p.name.lower()
    if not suffixes:
        return False

    for i, s in enumerate(suffixes):
        if s in _CAPTURE_BASES and all(r in _COMPRESSION_SUFFIXES for r in suffixes[i + 1:]):
            return True

    last = suffixes[-1]
    if "capture" in name and last not in _SOURCE_SUFFIXES:
        return True
    return bool("capture" in name and last in _DATA_SUFFIXES and last not in _SOURCE_SUFFIXES)


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


def _apply_mapping(text: str) -> tuple[str, int]:
    total = 0
    for pattern, repl in MAPPING:
        text, n = re.subn(pattern, repl, text, flags=re.IGNORECASE)
        total += n
    return text, total


def scrub_text(text: str, *, protect_values: bool = False) -> tuple[str, int]:
    """Apply MAPPING. Returns the new text and the number of substitutions.

    With `protect_values`, quoted literals on an assertion line and raw/regex literals are left
    alone. That is what --write uses; --filter (commit messages) does not, because a message is
    prose throughout.
    """
    if not protect_values:
        return _apply_mapping(text)
    scrubbed, n, _ = scrub_text_guarded(text)
    return scrubbed, n


def scrub_text_guarded(text: str) -> tuple[str, int, list[tuple[int, str]]]:
    """Scrub prose, but never a quoted assertion or a regex literal.

    Returns (new_text, substitutions, protected) where each protected entry is (line number, the
    literal as written). A protected span is reported only when a rule WOULD have changed it --
    otherwise every raw string in the tree would print, and a report nobody reads is not a report.
    """
    out: list[str] = []
    total = 0
    protected: list[tuple[int, str]] = []
    for lineno, line in enumerate(text.splitlines(keepends=True), 1):
        spans = _protected_spans(line)
        if not spans:
            new, n = _apply_mapping(line)
            out.append(new)
            total += n
            continue
        pieces: list[str] = []
        pos = 0
        for start, end, _why in spans:
            piece, n = _apply_mapping(line[pos:start])
            pieces.append(piece)
            total += n
            literal = line[start:end]
            if _apply_mapping(literal)[1]:
                protected.append((lineno, literal))
            pieces.append(literal)
            pos = end
        piece, n = _apply_mapping(line[pos:])
        pieces.append(piece)
        total += n
        out.append("".join(pieces))
    return "".join(out), total, protected


def _print_diff(rel: str, before: str, after: str, *, limit: int = 20) -> None:
    """Show what a --write changed, so the rewrite can be reviewed rather than trusted."""
    diff = list(difflib.unified_diff(
        before.splitlines(keepends=True), after.splitlines(keepends=True),
        fromfile=f"a/{rel}", tofile=f"b/{rel}", n=1))
    for line in diff[:limit]:
        sys.stdout.write(line if line.endswith("\n") else line + "\n")
    if len(diff) > limit:
        print(f"  ... ({len(diff) - limit} more diff line(s))")


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
    skipped: list[str] = []
    protected_count = 0

    for path in tracked_files(root):
        rel = str(path.relative_to(root))
        original = path.read_text(encoding="utf-8", errors="replace")

        if args.write:
            # A TEST IS NOT PROSE. Its addresses are the fixtures the assertions are written
            # against; rewriting one changes what the test proves without failing it. Skip the
            # whole file, say so, and leave any identifier there for a human (--check reports it).
            if is_test_path(rel):
                skipped.append(rel)
                print(f"  skipped {rel} (test fixture -- assertions and regexes are never rewritten)")
                for lineno, kind, value in find_identifiers(original, rel)[:3]:
                    print(f"      note: line {lineno}: {kind}: {value} needs a human decision")
                continue
            scrubbed, n, protected = scrub_text_guarded(original)
            if n:
                path.write_text(scrubbed, encoding="utf-8")
                changed += 1
                print(f"  scrubbed {rel} ({n} substitution(s))")
                _print_diff(rel, original, scrubbed)
            for lineno, literal in protected:
                protected_count += 1
                print(f"  protected {rel}:{lineno}: {literal} "
                      f"(quoted assertion/regex -- left alone)")
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
        if skipped:
            print(f"{len(skipped)} test fixture(s) skipped -- assertions are not rewritten")
        if protected_count:
            print(f"{protected_count} protected value(s) left in place (quoted assertion/regex)")
    print(f"{problems} identifier(s) with no mapping rule")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
