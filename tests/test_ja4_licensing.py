"""The vendored JA4 module, and the rule that keeps anything else out.

Weirvern uses JA4 (the BSD-3-Clause TLS client fingerprint) and nothing else from
the upstream fingerprinting ecosystem. The module is VENDORED into this repository
(zeek/vendor/ja4-zeek-scripts) and COPYed into the sensor image at build time --
no package manager, no network fetch, no second license in the tree.

WHY THE FIRST TEST IS A TOKEN SCAN. The failure this guards against is not a
runtime bug: it is a licensing and surface-hygiene fact that nothing else would
notice. A reference to a fingerprinting method this project does not use -- in a
comment, a docstring, a doc, an assertion -- is a claim about what the software
does, and the software does not do it. The scan runs over every git-tracked file,
so a new reference anywhere fails CI rather than shipping.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR = ROOT / "zeek" / "vendor" / "ja4-zeek-scripts"
NOTICE = VENDOR / "LICENSE-JA4"
ZEEK_CTR = ROOT / "zeek" / "Containerfile"
POLICY = ROOT / "k8s" / "zeek" / "weirvern-local.zeek"

# Tokens that must not appear ANYWHERE in the tracked tree. The scan is
# case-insensitive and whole-token: `ja4` itself is the thing we USE and must not
# match; these are the sibling methods and the vendor/package machinery around them.
BANNED = re.compile(
    r"ja4\+|ja4plus|\bja4ssh\b|\bja4ts\b|\bja4s\b|\bja4h\b|\bja4x\b|\bja4t\b|\bja4l\b|\bja4d\b"
    r"|prune-ja4|foxio license",
    re.IGNORECASE,
)


def _tracked_text_files() -> list[tuple[str, str]]:
    rels = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True,
                          text=True, check=True).stdout.split("\0")
    out = []
    for rel in rels:
        if not rel:
            continue
        p = ROOT / rel
        if any(part in {".git", ".venv", "node_modules", "__pycache__"} for part in p.parts):
            continue
        try:
            out.append((rel, p.read_text(encoding="utf-8", errors="replace")))
        except Exception:  # noqa: BLE001 - binary or unreadable files are not scanned
            continue
    return out


def test_no_unused_fingerprinting_tokens_anywhere_in_the_tracked_tree():
    """The software uses JA4 and nothing else. A reference to anything else is false.

    THE CHANGELOG IS SCANNED TOO, and it is not exempt: the operator asked for zero
    references, and a changelog that renames the removed machinery is still a document
    about this software. The only exemption is this file itself, which must name the
    tokens in order to scan for them -- the same self-exemption the identifier
    scrubber's guard carries, narrowed the same way (it is one file, named explicitly,
    and the must-fire test below proves the scan still works).
    """
    hits: list[str] = []
    for rel, text in _tracked_text_files():
        if rel == "tests/test_ja4_licensing.py":
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if BANNED.search(line):
                hits.append(f"{rel}:{i}: {line.strip()[:120]}")
    assert not hits, (
        "the tree references fingerprinting methods this project does not use, so the "
        "software's own description is false:\n  " + "\n  ".join(hits[:20])
    )


def test_the_guard_fires_on_the_tokens_it_exists_for():
    """A guard that cannot fail is not a guard."""
    for token in ("JA4+", "ja4plus", "ja4s", "JA4H", "prune-ja4plus", "FoxIO license"):
        assert BANNED.search(token), f"the scan no longer recognises {token!r}"
    # ...and it must NOT fire on the thing we use.
    assert not BANNED.search("ja4"), "the scan flags plain ja4, which is the supported module"
    assert not BANNED.search("ja4_orig"), "the scan flags ja4_orig, a stored column"


# ── the module itself, and its license ──────────────────────────────────────────

def test_the_vendored_module_is_present_and_complete():
    for rel in ("__load__.zeek", "config.zeek", "LICENSE-JA4",
                "ja4/__load__.zeek", "ja4/helpers.zeek", "ja4/main.zeek",
                "utils/common.zeek", "utils/ssl-consts.zeek"):
        assert (VENDOR / rel).exists(), f"the vendored module is missing {rel}"


def test_the_bsd_license_travels_with_the_module():
    """BSD-3-Clause requires retaining the notice in redistributions."""
    assert NOTICE.exists(), "zeek/vendor/ja4-zeek-scripts/LICENSE-JA4 is missing"
    text = NOTICE.read_text()
    assert "Redistributions of source code must retain" in text
    assert "FoxIO" in text


def test_the_sensor_image_copies_the_module_from_the_repository():
    """No package manager, no network fetch: the build is the repository."""
    text = ZEEK_CTR.read_text()
    assert "COPY vendor/ja4-zeek-scripts" in text, (
        "the Containerfile does not copy the vendored module"
    )
    # COMMENTS ARE STRIPPED FIRST. The file explains in prose why the package manager is
    # no longer used, and a naive scan reads that explanation as the thing it warns
    # against -- the same self-tripping shape this project has hit before.
    code = "\n".join(ln.split("#", 1)[0] for ln in text.splitlines())
    assert "zkg" not in code, (
        "the Containerfile still runs the package manager; the module is vendored now"
    )


def test_the_site_policy_loads_the_module_and_carries_no_disable_list():
    """The policy loads the package path the image provides, and there is nothing to
    disable -- the module contains only what it uses."""
    code = "\n".join(ln.split("#")[0] for ln in POLICY.read_text().splitlines())
    assert re.search(r"^@load\s+packages/ja4-zeek-scripts\s*$", code, re.M), (
        "the site policy does not load the ja4 module"
    )
    assert "redef FINGERPRINT" not in code, (
        "the site policy carries a disable list, which the vendored module does not need"
    )


def test_schema_stores_ja4_and_has_no_dead_ja3_columns():
    """ja3/ja3s were permanently empty: Zeek 9.x core ships no ja3 policy at all."""
    sql = (ROOT / "weirvern" / "schema" / "001_weirvern.sql").read_text()
    m = re.search(r"zeek_ssl\s*\((.*?)\n\)", sql, re.S)
    assert m is not None, "zeek_ssl DDL not found"
    body = m.group(1)
    cols = [ln.strip().split()[0] for ln in body.splitlines()
            if ln.strip() and not ln.strip().startswith("--")]
    for dead in ("ja3", "ja3s"):
        assert dead not in cols, (
            f"zeek_ssl.{dead} exists but Zeek 9.x never emits it, so it can never "
            f"populate -- a column that always reads NULL is worse than an absent one"
        )
    assert "ja4" in cols, "ja4 is not stored, so TLS fingerprinting is collected and lost"


def test_the_ssl_column_order_matches_the_mapper():
    """A DDL/INSERT column mismatch writes values into the WRONG columns, silently."""
    from weirvern.ingester import ZEEK_COLUMNS

    sql = (ROOT / "weirvern" / "schema" / "001_weirvern.sql").read_text()
    m = re.search(r"zeek_ssl\s*\((.*?)\n\)", sql, re.S)
    assert m is not None, "zeek_ssl DDL not found"
    ddl_cols = []
    for line in m.group(1).splitlines():
        line = line.split("--")[0].strip().rstrip(",")
        if not line:
            continue
        first = line.split()[0]
        if first.upper() in ("PRIMARY", "INDEX", "ORDER", "ENGINE", "PARTITION",
                             "TTL", "SETTINGS", "DEFAULT", "MATERIALIZED", "ALIAS"):
            continue
        ddl_cols.append(first)
    assert ddl_cols == ZEEK_COLUMNS["ssl"], (
        f"zeek_ssl DDL order and ZEEK_COLUMNS['ssl'] disagree.\n"
        f"  DDL   : {ddl_cols}\n"
        f"  mapper: {ZEEK_COLUMNS['ssl']}"
    )


def test_the_ssl_mapper_reads_ja4_not_ja3():
    """The mapper must read the field the module actually writes."""
    from weirvern.ingester import map_zeek_ssl

    row = map_zeek_ssl({
        "ts": "1789689741.76", "uid": "C1", "id.orig_h": "198.51.100.5",
        "id.resp_h": "1.1.1.1", "id.resp_p": "443", "version": "TLSv13",
        "cipher": "TLS_AES_128_GCM_SHA256", "server_name": "example.com",
        "ja4": "t130200_1302_234ea6891581",
        "ja4_o": "t13d1516h2_8daaf6152771_02713d6af862",
        "ja3": "THIS-MUST-BE-IGNORED",
    })
    assert row is not None
    assert row["ja4"] == "t130200_1302_234ea6891581"
    assert row["ja4_orig"].startswith("t13d1516h2")
    # A ja3 field in the input must not land anywhere in the output.
    assert "THIS-MUST-BE-IGNORED" not in str(row)


def test_the_sensor_image_does_not_override_ZEEKPATH():
    """Setting ZEEKPATH to share/zeek BREAKS the builtin plugins.

    The upstream zeek/zeek image leaves ZEEKPATH unset on purpose; pinning it hides the
    plugins under lib/zeek/plugins and Zeek dies at startup.
    """
    text = ZEEK_CTR.read_text()
    for line in text.splitlines():
        stripped = line.split("#", 1)[0]
        assert "ZEEKPATH=" not in stripped, (
            "the Containerfile sets ZEEKPATH, which breaks builtin plugin discovery in "
            "the zeek/zeek image. Leave it unset."
        )
