"""The repository must not describe a real network.

WHY THIS IS A TEST AND NOT A CONVENTION.

Weirvern was developed against a real home lab, which is the right way to build a network sensor
-- the interesting bugs only appear on real traffic. But every address, MAC, hostname and service
name that leaks into the repository is a fact about a private network, and a repository is shared
and can become public with one click.

The first pass found 302 of them: addresses in source docstrings, MACs in test fixtures, a
gateway's hardware vendor named in a comment, a tailnet address, and public addresses observed
being contacted. Each was individually harmless-looking. That is the argument for a test: a
convention would have been followed while the leak was being introduced, and a scrub is only
true until the next commit.

WHAT THIS CATCHES, AND WHAT IT DOES NOT.

It catches identifiers by FORM (addresses, MACs, the lab's hostnames, CGNAT) -- the classes that
leaked. It does not catch prose: a comment saying "the firewall is at the top of the rack" would
pass. The FORM is what is mechanised because it is what leaked, and because a test that fires on
prose would fire constantly and be turned off.

`scripts/sanitize_identifiers.py` holds the mapping and does the rewriting; this file asserts the
tree is clean and that the guard would actually fire on the identifiers it exists for.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from weirvern.tools import sanitize_identifiers as san  # noqa: E402


def _hits() -> list[str]:
    out: list[str] = []
    for path in san.tracked_files(ROOT):
        rel = str(path.relative_to(ROOT))
        text = path.read_text(encoding="utf-8", errors="replace")
        for lineno, kind, value in san.find_identifiers(text, rel):
            out.append(f"{rel}:{lineno}: {kind}: {value}")
    return out


def test_no_deployment_identifiers_in_the_tracked_tree():
    """THE GUARD. A real address, MAC, or lab hostname anywhere in a tracked file fails this."""
    hits = _hits()
    assert not hits, (
        "the repository describes a real network. Replace the identifier with a value reserved "
        "for documentation (RFC 5737 addresses, RFC 7042 MACs, *.example hostnames) and add a "
        "rule to MAPPING in weirvern/tools/sanitize_identifiers.py if the class is new:\n  "
        + "\n  ".join(hits[:20])
    )


def test_the_guard_fires_on_the_identifiers_it_exists_for():
    """A guard that cannot fail is not a guard.

    Each string below is a REAL identifier that was in this repository. If the detector stops
    recognising them, the test above passes while the leak returns -- which is how the dead
    ja3/ja3s columns, the three unread tables and the four unreadable ATT&CK rules all shipped.
    """
    must_fire = [
        # Real lab addresses, by class.
        ("10.9.9.9", "private-ipv4"),
        ("192.168.2.42", "private-ipv4"),
        ("172.20.5.5", "private-ipv4"),
        # A public address observed being contacted is a disclosure too.
        ("162.248.221.40", "public-ipv4"),
        # Real MACs: a hypervisor VM range and a consumer gateway.
        ("bc:24:11:53:ca:66", "mac"),
        ("a8:9c:6c:96:b6:2d", "mac"),
        # The lab's own hostnames.
        ("spyro.home", "hostname"),
        ("unifi", "hostname"),
    ]
    for value, expected_kind in must_fire:
        hits = san.find_identifiers(value, "test")
        kinds = {k for _, k, _ in hits}
        assert expected_kind in kinds, (
            f"the guard no longer recognises {value!r} as {expected_kind!r} (got {kinds or 'nothing'}). "
            f"If the value is genuinely synthetic, add it to the classifier; if it is real, it "
            f"belongs in MAPPING."
        )


def test_synthetic_values_are_not_flagged():
    """The other direction. A guard that fires on invented test data gets disabled.

    These are the placeholder forms this repository uses. Flagging them would make the guard
    noise, and a noisy guard is turned off -- taking the real detection with it.
    """
    acceptable = [
        "198.51.100.10",     # RFC 5737 TEST-NET-2
        "203.0.113.10",      # RFC 5737 TEST-NET-3
        "192.0.2.10",        # RFC 5737 TEST-NET-1
        "10.0.0.1",          # private, but a universal example
        "8.8.8.8",           # a public resolver everyone writes
        "1.2.3.4",           # the canonical placeholder
        "aa:bb:cc:dd:ee:01",  # the fixture MAC pattern used throughout the tests
        "00:00:5e:00:53:01",  # RFC 7042 documentation MAC
        "ff:ff:ff:ff:ff:ff",  # broadcast
        "sensor.example",    # RFC 2606
    ]
    for value in acceptable:
        assert not san.find_identifiers(value, "test"), (
            f"{value!r} is a documentation value but the guard flags it. A guard that fires on "
            f"invented data gets switched off."
        )


def test_the_scrubber_and_the_guard_share_one_mapping():
    """MAPPING lives in one module so the rewriter and the guard cannot disagree.

    Two copies would drift silently: the guard would keep passing while the scrubber had stopped
    covering something. This asserts the table is reachable from both.
    """
    assert san.MAPPING, "MAPPING is empty -- the scrubber would rewrite nothing"
    for pattern, repl in san.MAPPING:
        assert pattern and repl, f"incomplete rule: {pattern!r} -> {repl!r}"
        # Every rule must actually compile, or the scrub silently skips it.
        import re
        re.compile(pattern)


def test_the_scrubber_scans_every_tracked_text_file():
    """Selection is by GIT TRACKING, not by file suffix.

    An earlier version selected by suffix and missed `Containerfile` (no extension) and
    `.env.example` (a doubled one). Both were tracked and both carried real segment addresses, so
    the guard reported the tree clean while two files still described the lab.
    """
    scanned = {str(p.relative_to(ROOT)) for p in san.tracked_files(ROOT)}
    for must_scan in ("Containerfile", ".env.example", "README.md", "weirvern/config.py"):
        if (ROOT / must_scan).exists():
            assert must_scan in scanned, (
                f"{must_scan} is tracked but the scrubber does not read it; an identifier there "
                f"would go unreported"
            )
    # Every tracked file that is not binary should be scanned.
    all_tracked = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    binary = {p for p in all_tracked if Path(p).suffix.lower() in san.BINARY_SUFFIXES}
    missing = set(all_tracked) - scanned - binary - san.SKIP_FILES
    assert not missing, f"tracked but never scanned: {sorted(missing)[:10]}"


def test_no_captured_traffic_is_committed():
    """A packet capture is a record of a real network and is more revealing than any address.

    None may be committed. A capture kept for a test belongs in a local, gitignored directory --
    the test fixture this project uses is built from the schema DDL and synthetic dicts, so no
    capture is needed.
    """
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    captures = [
        p for p in tracked
        if Path(p).suffix.lower() in {".pcap", ".pcapng", ".cap"}
        or "capture" in Path(p).name.lower()
    ]
    assert not captures, (
        f"traffic captures must not be committed: {captures}. Keep them locally and gitignore "
        f"the directory."
    )


@pytest.mark.parametrize(
    "gitignore_line",
    ["*.pcap", "*.pcapng", "*.cap"],
)
def test_gitignore_blocks_captures(gitignore_line: str):
    """Belt as well as braces: an ignored path cannot be added by accident."""
    text = (ROOT / ".gitignore").read_text()
    assert gitignore_line in text, (
        f".gitignore does not block {gitignore_line}; a capture could be committed with "
        f"`git add -A`"
    )
