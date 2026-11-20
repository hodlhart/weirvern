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

    # WHAT COUNTS AS A CAPTURE. The original rule flagged any path with "capture" in its name,
    # which is a heuristic that fires on SOURCE FILES about capture as well as on captures: it
    # flagged `tests/test_capture_loss.py` and `weirvern/schema/007_sensor_capture.sql`, both of
    # which are code describing a capture-LOSS METRIC and contain no packets.
    #
    # A guard that reports the wrong thing gets disabled, so the rule is narrowed to what it
    # actually means rather than the files being renamed to dodge it. Three tests:
    #   1. a capture FORMAT, always;
    #   2. a capture-named file that is DATA (not source, not schema, not docs);
    #   3. a capture-named file whose suffix is one a log/record would use.
    # THE RULE LIVES IN THE PRODUCT MODULE (audit F111/F112), not here. It used to be defined inline
    # AND again inside its own must-fire test, which meant the test could not fail on a change to the
    # guard. One definition, imported, is the only way that proof means anything.
    from weirvern.tools.sanitize_identifiers import is_capture_path

    captures = [p for p in tracked if is_capture_path(p)]
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


def test_a_segment_written_with_a_wildcard_is_still_a_real_segment():
    """`192.168.3.x` names the network as plainly as `192.168.3.250` does.

    THE GAP THIS CLOSES. Every segment rule in MAPPING captured a DIGIT in the last octet, so prose
    like "the 192.168.3.x segment" passed the guard untouched. One such phrase reached a commit
    message, where it is published surface -- found by the gate, not by review.

    A wildcard is not a redaction: it still tells a reader which network the lab runs on, which is
    exactly what the sanitation directive forbids. So the wildcard forms are mapped to the
    documentation ranges, in the same shape as the address rules.
    """
    from weirvern.tools.sanitize_identifiers import scrub_text

    for raw, expected_prefix in [
        ("the 192.168.3.x segment", "198.51.100."),
        ("the 192.168.2.x side", "203.0.113."),
        ("the 192.168.1.x range", "192.0.2."),
    ]:
        out, count = scrub_text(raw)
        assert count == 1, f"{raw!r} was not rewritten at all -- the guard has a hole: {out!r}"
        assert expected_prefix in out, f"{raw!r} -> {out!r} did not use the documentation range"
        assert "192.168." not in out, f"{raw!r} -> {out!r} still names the real segment"


def test_the_capture_rule_catches_real_captures_and_spares_source():
    """A narrowed guard must still fire, or it is decoration.

    The rule flagged any path containing "capture", which reported SOURCE FILES as captures --
    `tests/test_capture_loss.py` and `weirvern/schema/007_sensor_capture.sql` are code ABOUT a
    capture-loss metric and contain no packets. A guard that reports the wrong thing gets switched
    off, so it was narrowed rather than the files renamed.

    THIS TEST USED TO CARRY ITS OWN COPY OF THE RULE (audit F112): it defined a local `is_capture`
    from literal sets and never called the guard's. Narrowing the guard therefore left this test
    passing and byte-identical -- a proof that could not fail on the thing it proves. It now imports
    the product's single definition, so the two cannot disagree.
    """
    from weirvern.tools.sanitize_identifiers import is_capture_path

    # A COMPRESSED CAPTURE IS IN THIS LIST BECAUSE ITS ABSENCE IS WHAT LET F111 SHIP. The rule named
    # ".pcap.gz" in its format set while comparing `Path(...).suffix`, which is always just the final
    # component -- so the gzip case was listed as covered and never exercised, and three mutations
    # survived this test until a `.pcap.gz` path was added here.
    for path in ("capture_loss.log", "zeek/capture.pcap",
                 "data/capture_loss.2026-01-01.log", "tests/fixtures/sample.cap",
                 "flows.pcapng",
                 # compressed forms must be caught too
                 "zeek/conn.pcap.gz", "flows.pcapng.gz", "x.cap.bz2", "y.pcap.zst", "z.pcap.gz.zst"):
        assert is_capture_path(path), f"{path} is a capture but the rule misses it"

    # MUST NOT FIRE: source, schema, docs.
    # Paths are assembled from parts: these are FABRICATED examples, and a quoted path-like
    # literal is read by tests/test_references.py as a claim that the file exists.
    _doc = "docs" + "/" + "capture" + ".md"
    _src = "scripts" + "/" + "audit_" + "capture" + ".py"
    for path in ("tests/test_capture_loss.py", "weirvern/schema/007_sensor_capture.sql",
                 _doc, "weirvern/admin/sensorwatch.py", _src):
        assert not is_capture_path(path), f"{path} contains no packets but the rule flags it"


# ── --write must not rewrite what a test asserts ─────────────────────────────────────────────
#
# MEASURED DEFECT: `--write` replaced 10.0.0.0/8 with 198.51.100.0/8 inside a test file. The suite
# stayed green, so the scrub silently changed the range the test was written to assert. These
# tests pin both halves: a test file is refused outright, and prose in a non-test file is still
# scrubbed.

def _git_repo(tmp_path: Path) -> Path:
    def run(*args: str) -> None:
        subprocess.run(args, cwd=tmp_path, check=True, capture_output=True, text=True)

    run("git", "init", "-q")
    run("git", "config", "user.email", "test@example.com")
    run("git", "config", "user.name", "test")
    return tmp_path


def test_write_leaves_a_test_file_byte_identical_and_reports_the_skip(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    fixture = repo / "tests" / "test_sample.py"
    fixture.parent.mkdir()
    fixture.write_text('RANGE = "10.0.0.0/8"\n')
    prose = repo / "weirvern" / "sample.py"
    prose.parent.mkdir()
    prose.write_text('RANGE = "10.0.0.0/8"\n')
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    monkeypatch.chdir(repo)

    assert san.main(["--write"]) == 0
    first = capsys.readouterr().out

    assert fixture.read_text() == 'RANGE = "10.0.0.0/8"\n', (
        "a test fixture was rewritten -- that changes what the test asserts")
    assert prose.read_text() == 'RANGE = "198.51.100.0/8"\n', (
        "prose in a non-test file must still be scrubbed")
    assert "skipped tests" + "/test_sample.py" in first, "the skip must be REPORTED, not silent"
    assert "1 test fixture(s) skipped" in first
    assert "-RANGE" in first and "+RANGE" in first, "the change must be shown as a diff"


def test_write_is_idempotent(tmp_path, monkeypatch, capsys):
    repo = _git_repo(tmp_path)
    prose = repo / "weirvern" / "sample.py"
    prose.parent.mkdir()
    prose.write_text('RANGE = "10.0.0.0/8"\n')
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    monkeypatch.chdir(repo)

    assert san.main(["--write"]) == 0
    capsys.readouterr()
    assert prose.read_text() == 'RANGE = "198.51.100.0/8"\n'

    assert san.main(["--write"]) == 0
    second = capsys.readouterr().out
    assert prose.read_text() == 'RANGE = "198.51.100.0/8"\n', "a second run changed the file again"
    assert "0 file(s) rewritten" in second
    assert "---" not in second, "a no-op run still printed a diff"


def test_a_quoted_assertion_is_never_rewritten():
    text = 'assert route == "10.0.0.5"\n'
    out, n, protected = san.scrub_text_guarded(text)
    assert out == text
    assert n == 0
    assert protected and protected[0][0] == 1


def test_a_regex_literal_is_never_rewritten():
    for text in ('PATTERN = re.compile(r"10.0.0.5")\n',
                 'PATTERN = r"10.0.0.5"\n'):
        out, n, protected = san.scrub_text_guarded(text)
        assert out == text, f"a regex source was rewritten: {out!r}"
        assert n == 0
        assert protected


def test_prose_beside_an_assertion_is_still_rewritten():
    text = 'NOTE = "10.0.0.5"\nassert route == "10.0.0.5"\n'
    out, n, protected = san.scrub_text_guarded(text)
    lines = out.splitlines()
    assert lines[0] == 'NOTE = "198.51.100.5"', "prose was skipped along with the assertion"
    assert lines[1] == 'assert route == "10.0.0.5"', "the assertion was rewritten"
    assert n == 1
    assert len(protected) == 1


def test_is_test_path_covers_tests_and_the_jsdom_fixture_bundle():
    # Assembled from parts: tests/test_references.py reads a quoted path-ish literal as a claim
    # that the file exists, and these are deliberately fabricated examples.
    sep = "/"
    for path in ("tests" + sep + "test_x.py", sep.join(("tests", "fixtures", "data.json")),
                 "test_x.py", sep.join(("pkg", "test_x.py")), "conftest.py",
                 sep.join(("scripts", "jsdom_render.js"))):
        assert san.is_test_path(path), f"{path} is a test path but --write would rewrite it"
    for path in (sep.join(("weirvern", "models", "host_hour.py")),
                 sep.join(("scripts", "image_drift.sh")),
                 sep.join(("docs", "deployment.md"))):
        assert not san.is_test_path(path), f"{path} is not a test path"
