"""JA4 licensing and column-integrity tests.

WHY THESE EXIST: the licensing restriction here is not enforceable by a compiler or by a
runtime error. If someone enables a FoxIO-licensed JA4+ submodule, everything keeps
working perfectly -- log fields populate, tests pass -- and the only symptom is a license
violation. These tests are the only mechanism that can catch it.

The specific trap they guard: the package gates submodules with

    @if (JA4S_enabled) @load ./ja4s @endif

and `@if` is evaluated WHEN THE FILE IS LOADED, not when the option changes. So loading
the package first and disabling afterwards is SILENTLY IGNORED. We reproduced exactly
that: 28 of 28 ssl records carried a populated ja4s while the policy appeared to disable
it. Load order is therefore load-bearing, and a test asserting "the file contains
`redef FINGERPRINT::JA4S_enabled = F`" would pass while shipping FoxIO output. So the
assertions below are about ORDER, not presence.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "k8s" / "zeek" / "weirvern-local.zeek"
NOTICE = ROOT / "zeek" / "JA4-NOTICE"
ZEEK_CTR = ROOT / "zeek" / "Containerfile"
SCHEMA = ROOT / "weirvern" / "schema" / "001_weirvern.sql"

# Every option the package marks "FoxIO license required for JA4+". Sourced from the
# package's own config.zeek, which is the authority on the split.
FOXIO_OPTIONS = [
    "JA4S_enabled", "JA4H_enabled", "JA4L_enabled", "JA4SSH_enabled",
    "JA4T_enabled", "JA4TS_enabled", "JA4D_enabled",
]


def _policy() -> str:
    return POLICY.read_text()


def _executable_lines(text: str) -> list[str]:
    """Lines that Zeek actually evaluates -- comments stripped.

    Needed because this repo's convention is to explain a trap in a comment, and a
    comment mentioning `@load ja4-zeek-scripts` is not a load. An earlier test in this
    project was tripped by reading its own explanatory comment as code.
    """
    out = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.append(line)
    return out


# ── licensing: REMOVAL, which replaced the load order ───────────────────────────
#
# These three tests used to assert the disable LIST: that every FoxIO option was redefined
# to F in the site policy, and that the redefs appeared BEFORE the package was loaded.
#
# That design worked, and the ordering assertion genuinely caught a real defect -- the
# package evaluates `@if (JA4S_enabled)` at LOAD time, so a disable placed after the package
# had loaded was silently ignored and ja4s populated in 28 of 28 records while the config
# claimed it was off.
#
# It has been superseded by deletion at build time (zeek/prune-ja4plus.sh, exercised in
# tests/test_ja4_removal.py), for a reason worth stating: the disable list left the
# licensed code IN the image with a load ORDER as the only thing preventing its
# distribution. A three-line ordering property cannot be verified from configuration, and a
# package update changing a default is invisible to it. Removing the files has no ordering
# to get wrong.
#
# So the assertions below are now the inverse: the disables must be ABSENT, because their
# presence would mean the licensed code is back.


def test_the_site_policy_no_longer_carries_a_disable_list():
    """The absence of the disable list IS the guarantee.

    If someone re-adds `redef FINGERPRINT::JA4S_enabled = F`, that option no longer exists
    (it is deleted from the package's config.zeek at build time), so Zeek would abort with
    "redef used but not previously defined". More importantly its presence would signal that
    the licensed code had returned and was being switched off by configuration again.
    """
    lines = _executable_lines(_policy())
    disables = [ln for ln in lines if "FINGERPRINT::" in ln and "= F" in ln]
    assert not disables, (
        f"the site policy redefines FoxIO options again: {disables}. Those options are "
        f"DELETED from the package at build time (zeek/prune-ja4plus.sh), so this is either "
        f"a dead redef that will abort startup, or a sign the licensed code came back."
    )


def test_the_package_is_loaded_as_a_unit_with_no_ordering_requirement():
    """The old policy loaded `packages/ja4-zeek-scripts/config` separately so it could
    disable options in between. With the options gone, that indirection is only a way to get
    the order wrong."""
    lines = _executable_lines(_policy())
    assert any(re.match(r"^@load\s+packages/ja4-zeek-scripts\s*$", ln) for ln in lines), (
        "the policy does not load the ja4 package"
    )
    separate = [ln for ln in lines if "ja4-zeek-scripts/config" in ln]
    assert not separate, (
        f"the package config is still loaded separately ({separate}), which was only ever "
        f"needed to position the disables"
    )


def test_ja4plus_removal_is_documented_where_the_policy_is_read():
    """A future maintainer reading the policy must be able to find out that the submodules
    are absent on purpose -- otherwise the obvious 'fix' is to add them back."""
    text = _policy()
    assert "prune-ja4plus.sh" in text, (
        "the policy does not point at the prune script, so a reader cannot tell why the "
        "JA4+ submodules are missing"
    )


def test_options_are_module_qualified():
    """Bare `redef JA4S_enabled = F;` fails: the options are exported by FINGERPRINT."""
    text = _policy()
    for opt in FOXIO_OPTIONS:
        assert not re.search(rf"^\s*redef\s+{opt}\s*=", text, re.M), (
            f"{opt} is redefined without the FINGERPRINT:: module qualifier; it is "
            f"exported by that module, so an unqualified redef is an error"
        )


def test_ja4_itself_is_not_disabled():
    """The one member we ARE allowed to use must stay on.

    Disabling everything would be a trivially 'safe' way to pass the licensing tests while
    silently removing the feature -- the exact silent-failure mode this project keeps
    having to fix.
    """
    text = _policy()
    assert not re.search(r"redef\s+FINGERPRINT::JA4_enabled\s*=\s*F\s*;", text), (
        "JA4 itself (BSD-3-Clause) is disabled, which removes TLS fingerprinting "
        "entirely rather than restricting it to the permissive half"
    )


# ── the notice must actually ship ───────────────────────────────────────────────


def test_the_license_notice_exists_and_names_both_licenses():
    assert NOTICE.exists(), "zeek/JA4-NOTICE is missing"
    text = NOTICE.read_text()
    assert "BSD 3-Clause" in text or "BSD-3-Clause" in text
    assert "FoxIO License 1.1" in text
    assert "JA4+" in text


def test_the_sensor_image_copies_the_notice():
    """BSD-3-Clause requires retaining the notice in redistributions.

    Shipping the image without the notice is a license breach, so the COPY is asserted
    rather than assumed.
    """
    assert ZEEK_CTR.exists(), "zeek/Containerfile is missing"
    text = ZEEK_CTR.read_text()
    assert "JA4-NOTICE" in text, "the sensor image does not include the license notice"
    assert re.search(r"COPY\s+JA4-NOTICE", text), (
        "JA4-NOTICE is mentioned but never COPYed into the image"
    )


def test_the_sensor_image_installs_the_package_from_a_pinned_ref():
    """An unpinned zkg install makes builds irreproducible."""
    text = ZEEK_CTR.read_text()
    assert "foxio/ja4-zeek-scripts" in text
    assert "--force" in text, "zkg install must be non-interactive"
    assert "--noload" in text, (
        "zkg install loads the package by default, which would evaluate the @if gates "
        "before our site policy has disabled the FoxIO options"
    )
    assert "@latest" not in text and "master" not in text


def test_the_image_does_not_use_the_unmaintained_third_party_package():
    """anthonykasza/ja4 is pure BSD-3-Clause and would be a cleaner licensing position,
    but it FAILS ITS OWN UNIT TESTS on Zeek 9.0.0 (`zkg install` aborts with
    'test_command failed'), so it cannot be installed here. Recorded so nobody
    rediscovers it and 'simplifies' the image into something unbuildable.
    """
    text = ZEEK_CTR.read_text()
    assert "anthonykasza" not in text.replace(
        "# We therefore do NOT use the third-party `anthonykasza/ja4`", ""
    ), "the Containerfile installs the unmaintained third-party package"


# ── the schema must match what Zeek actually emits ──────────────────────────────


def test_schema_has_no_dead_ja3_columns():
    """ja3/ja3s were permanently empty: Zeek 9.x core ships no ja3 policy at all."""
    sql = SCHEMA.read_text()
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


def test_schema_has_ja4_but_not_ja4s():
    """ja4 is BSD-3-Clause and stored. ja4s is FoxIO License 1.1 and deliberately not."""
    sql = SCHEMA.read_text()
    m = re.search(r"zeek_ssl\s*\((.*?)\n\)", sql, re.S)
    assert m is not None, "zeek_ssl DDL not found"
    cols = [ln.strip().split()[0] for ln in m.group(1).splitlines()
            if ln.strip() and not ln.strip().startswith("--")]
    assert "ja4" in cols, "ja4 is not stored, so TLS fingerprinting is collected and lost"
    assert "ja4s" not in cols, (
        "ja4s is stored, but it is FoxIO License 1.1 -- not permissive for monetization. "
        "Weirvern ships JA4 only."
    )


def test_the_ssl_column_order_matches_the_mapper():
    """A DDL/INSERT column mismatch writes values into the WRONG columns, silently.

    This project has already had two bugs of exactly this shape (top_talkers reading
    columns from the wrong table; host_detail querying id_orig_h where the schema says
    src_addr), both of which produced empty panels rather than errors.
    """
    from weirvern.ingester import ZEEK_COLUMNS

    sql = SCHEMA.read_text()
    m = re.search(r"zeek_ssl\s*\((.*?)\n\)", sql, re.S)
    assert m is not None, "zeek_ssl DDL not found"
    body = m.group(1)
    ddl_cols = []
    for line in body.splitlines():
        line = line.split("--")[0].strip().rstrip(",")
        if not line:
            continue
        first = line.split()[0]
        if first.upper() in ("PRIMARY", "INDEX", "ORDER", "ENGINE", "PARTITION",
                             "TTL", "SETTINGS", "DEFAULT", "MATERIALIZED", "ALIAS"):
            continue
        ddl_cols.append(first)

    mapper_cols = ZEEK_COLUMNS["ssl"]
    assert ddl_cols == mapper_cols, (
        f"zeek_ssl DDL order and ZEEK_COLUMNS['ssl'] disagree.\n"
        f"  DDL   : {ddl_cols}\n"
        f"  mapper: {mapper_cols}"
    )


def test_the_ssl_mapper_reads_ja4_not_ja3():
    """The mapper must read the field Zeek actually writes."""
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
    plugins under lib/zeek/plugins and Zeek dies at startup with

        fatal error in builtin-plugins/__load__.zeek, line 3:
        can't find Zeek_JavaScript/__load__.zeek

    which reads like a broken image rather than a stray ENV. Verified by comparing the
    two images directly: upstream ZEEKPATH is empty, the derived image's was
    /usr/local/zeek/share/zeek, and the derived one crash-looped.
    """
    text = ZEEK_CTR.read_text()
    # Only flag an assignment, not a comment discussing it.
    for line in text.splitlines():
        stripped = line.split("#", 1)[0]
        assert "ZEEKPATH=" not in stripped, (
            "the Containerfile sets ZEEKPATH, which breaks builtin plugin discovery in "
            "the zeek/zeek image. Leave it unset."
        )
