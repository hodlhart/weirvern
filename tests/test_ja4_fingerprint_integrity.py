"""The JA4 plumbing must be honest: one real fingerprint, no phantoms, no inflated counts.

WHY THIS FILE EXISTS. The user's directive was "make sure ja4 is used in the ml". Checking that
turned up three separate defects, none of which any existing test could see, and all three of
which produced a *plausible number* for something that was not measured:

  1. THE PHANTOM FINGERPRINT. Zeek writes two different sentinels -- `-` for `#unset_field` and
     `(empty)` for `#empty_field` -- and `zeek_value()` normalised only the first. So
     `weirvern.zeek_ssl.ja4` stored the literal 7-character string `(empty)` on rows where Zeek
     produced no fingerprint, and `uniqExactIf(ja4, ja4 != '')` counted it as a REAL one. The
     `zeek_ja4_count` feature therefore reported 1 for hosts that had no fingerprint at all, and
     the T1573 TLS-downgrade rule compared against the text "(empty)".

  2. THE INFLATED CONNECTION BASELINE. The baseline query LEFT JOINed zeek_ssl onto zeek_conn, so
     one conn row became one row per matching SSL row. Measured live: 64,319 conn rows became
     93,048. `count() AS baseline_conn_count` was therefore counting conn x ssl PAIRS, so "is this
     many connections normal for this host" was inflated by whatever TLS the host happened to be
     doing -- and inflated MORE for the busiest hosts, which is the direction that hides an
     anomaly. `uniqExact` was unaffected, which is exactly why nothing looked broken.

  3. THE MISSING COLUMN. `detectors._zeek_clause` builds its training SELECT list by mapping over
     ZEEK_FEATURES and emitting `z.<name>`. A feature in that list with no matching column in the
     summary query makes EVERY detector's training query reference a column that does not exist,
     so training fails outright. Adding `zeek_ja4_novelty` created exactly that mismatch (51 names
     against 49 SQL aliases) until a placeholder column was added.

These tests are STATIC -- they read the generated SQL -- because all three are properties of the
generated text rather than of one execution, and because CI has no database.
"""

from __future__ import annotations

import re

import pytest

from weirvern import ingester
from weirvern.zeek_features import (
    JA4_REAL,
    JA4_REAL_ARRAY,
    ZEEK_FEATURES,
    zeek_baseline_ja4_sql,
    zeek_baseline_sql,
    zeek_window_summary_sql,
)

S, E = "2026-01-01 00:00:00", "2026-01-02 00:00:00"


@pytest.fixture(scope="module")
def summary() -> str:
    return zeek_window_summary_sql(S, E)


# ── 1. the sentinel ────────────────────────────────────────────────────────────────────────


def test_zeek_empty_sentinel_is_normalised_like_the_unset_one():
    """Zeek's `(empty)` must mean "no value", exactly as `-` does.

    Missing this stored the literal string "(empty)" as a TLS fingerprint.
    """
    assert ingester.ZEEK_EMPTY == "(empty)", "the empty_field sentinel changed"
    assert ingester.ZEEK_NULL == "-", "the unset_field sentinel changed"
    # Both sentinels, and the empty string, must normalise to None.
    for sentinel in ("-", "(empty)", ""):
        assert ingester.zeek_value(sentinel) is None, (
            f"zeek_value({sentinel!r}) must be None: either sentinel reaching the database as a "
            f"string makes a missing value look like a real one"
        )
    # And a real value must survive untouched.
    assert ingester.zeek_value("t13d1516h2_8daaf6152771_02713d6af862") == (
        "t13d1516h2_8daaf6152771_02713d6af862"
    )


def test_the_ja4_predicate_excludes_all_three_sentinels():
    """Historical rows predate the ingester fix, so the read layer must exclude them too."""
    for predicate in (JA4_REAL, JA4_REAL_ARRAY):
        for sentinel in ("''", "'-'", "'(empty)'"):
            assert f"!= {sentinel}" in predicate, (
                f"the fingerprint predicate does not exclude {sentinel}: {predicate}"
            )


def test_no_ja4_query_counts_a_sentinel_as_a_fingerprint(summary: str):
    """Every place that counts or collects fingerprints must use the shared predicate."""
    # A bare `ja4 != ''` is the bug: it accepts '(empty)'.
    bare = re.findall(r"ja4 != ''(?!\s*AND)", summary)
    assert not bare, (
        "the summary counts fingerprints with `ja4 != ''` alone, which accepts the '(empty)' "
        "sentinel. Use JA4_REAL so the definition cannot drift."
    )
    assert "ja4 != '(empty)'" in summary, "the summary does not guard against the (empty) sentinel"

    baseline = zeek_baseline_ja4_sql(S, E)
    assert "ja4 != '(empty)'" in baseline, "the ja4 baseline does not guard the sentinel"
    assert not re.findall(r"ja4 != ''(?!\s*AND)", baseline)


def test_the_array_predicate_is_the_one_the_SQL_actually_uses(summary: str):
    """The constants existing is not enough -- the generated SQL must interpolate them.

    WHY THIS IS SEPARATE. The first version of this file asserted that `JA4_REAL_ARRAY` mentions
    all three sentinels, which stays true even if the SQL stops using it. A mutation that replaced
    the array filter with a bare `x != ''` therefore passed every test -- the guard checked the
    definition rather than its use, so it could not fail. This asserts on the SQL text.

    Both the window summary and the baseline collect fingerprints as arrays, so both are checked.
    """
    for name, sql in (("the summary", summary), ("the ja4 baseline", zeek_baseline_ja4_sql(S, E))):
        # Every array filter over ja4 must carry all three exclusions.
        filters = re.findall(r"arrayFilter\(x -> ([^,]+),", sql)
        assert filters, f"{name} has no arrayFilter over ja4 -- update this test"
        for f in filters:
            for sentinel in ("''", "'-'", "'(empty)'"):
                assert f"x != {sentinel}" in f, (
                    f"{name} filters fingerprints with {f!r}, which does not exclude {sentinel}. "
                    f"The '(empty)' sentinel reaching the set makes a missing fingerprint look "
                    f"like a real client build."
                )


# ── 2. the inflated baseline ───────────────────────────────────────────────────────────────


def test_the_connection_baseline_does_not_join_the_ssl_table():
    """A LEFT JOIN onto zeek_ssl multiplies conn rows, inflating baseline_conn_count.

    Measured on the live deployment: 64,319 conn rows became 93,048 after the join.
    """
    sql = zeek_baseline_sql(S, E)
    assert "zeek_ssl" not in sql, (
        "the connection baseline joins zeek_ssl, which fans out one conn row per matching SSL "
        "row and inflates count() -- the comparison that decides whether a host's connection "
        "count is normal. Count each source in its own query."
    )
    assert "JOIN" not in sql.upper(), (
        "the connection baseline has no reason to join anything: service and connection counts "
        "both come from zeek_conn"
    )
    assert "baseline_conn_count" in sql and "baseline_service_count" in sql
    # The fingerprint baseline still exists -- it just lives in its own query.
    assert "zeek_ssl" in zeek_baseline_ja4_sql(S, E)


def test_the_fingerprint_baseline_ships_the_set_not_only_its_size():
    """Novelty needs an exact membership test; a count can only support a guess."""
    sql = zeek_baseline_ja4_sql(S, E)
    assert "baseline_ja4_set" in sql, (
        "the baseline ships only a COUNT. Novelty then has to assume which fingerprints were "
        "familiar, and that assumption overstates novelty on the hosts that use TLS most."
    )
    assert "baseline_ja4_count" in sql
    # Unbounded arrays are not acceptable from a per-host aggregate.
    assert "arraySlice" in sql, "the baseline fingerprint set must be capped"


# ── 3. the feature/column contract ─────────────────────────────────────────────────────────


def test_every_feature_in_ZEEK_FEATURES_has_a_column_in_the_summary(summary: str):
    """`detectors._zeek_clause` emits `z.<feature>` for every name in ZEEK_FEATURES.

    A name with no matching column makes all four detectors' training queries invalid, so
    training fails outright -- and the failure appears at training time, not at import.
    """
    # The outer SELECT's aliases.
    m = re.search(r"SELECT\s*\n(.*?)\n\s*FROM keys k", summary, re.S)
    assert m, "the summary's outer SELECT moved -- update this test"
    aliases = set(re.findall(r"AS\s+(zeek_\w+)", m.group(1)))

    missing = [f for f in ZEEK_FEATURES if f not in aliases]
    assert not missing, (
        f"ZEEK_FEATURES contains {missing}, which the summary query does not produce. "
        f"detectors._zeek_clause maps over this list to build `z.<name>`, so training would "
        f"reference a nonexistent column."
    )


def test_the_novelty_feature_is_declared_and_computed():
    """JA4 in the ML means more than a count of distinct values."""
    assert "zeek_ja4_novelty" in ZEEK_FEATURES, (
        "the fingerprint novelty feature is not in the feature list, so no model sees it"
    )
    # It must be APPENDED, per this module's own documented ordering rule: a model rebuilds its
    # vector by name, so inserting would silently reinterpret every later column.
    assert ZEEK_FEATURES.index("zeek_ja4_novelty") == len(ZEEK_FEATURES) - 1, (
        "zeek_ja4_novelty is not last. Appending keeps every pre-existing model's vector valid; "
        "inserting in the middle silently reinterprets the columns after it."
    )
    from weirvern.zeek_features import extract_zeek_features

    # With no baseline there is nothing to be novel against, so it must be 0.0 rather than guessed.
    row = {"ja4_set": "['a', 'b']", "zeek_conn_count": 1}
    vec = extract_zeek_features(row, baseline=None)
    assert vec["zeek_ja4_novelty"] == 0.0, (
        "novelty is claimed without a baseline to compare against; it must be 0.0 with none"
    )


def test_novelty_is_an_exact_membership_test_when_the_set_is_available():
    """One familiar + one unfamiliar fingerprint out of two is 0.5, not a guess."""
    from weirvern.zeek_features import extract_zeek_features

    row = {"ja4_set": "['known_fp', 'new_fp']", "zeek_conn_count": 1}
    baseline = {"baseline_ja4_set": "['known_fp']", "baseline_ja4_count": 1}
    vec = extract_zeek_features(row, baseline=baseline)
    assert vec["zeek_ja4_novelty"] == pytest.approx(0.5), (
        f"expected exactly half the fingerprints to be novel, got {vec['zeek_ja4_novelty']}"
    )

    # Nothing novel when every fingerprint is in the history.
    vec = extract_zeek_features(
        {"ja4_set": "['known_fp']", "zeek_conn_count": 1},
        baseline={"baseline_ja4_set": "['known_fp']", "baseline_ja4_count": 1},
    )
    assert vec["zeek_ja4_novelty"] == 0.0

    # A host with no fingerprints at all is not novel.
    vec = extract_zeek_features({"ja4_set": "[]", "zeek_conn_count": 1},
                                baseline={"baseline_ja4_set": "[]", "baseline_ja4_count": 0})
    assert vec["zeek_ja4_novelty"] == 0.0


def test_a_baseline_without_the_set_degrades_rather_than_manufacturing_novelty():
    """An older caller supplies only the count; the fallback must never OVERSTATE novelty."""
    from weirvern.zeek_features import extract_zeek_features

    row = {"ja4_set": "['a', 'b', 'c']", "zeek_conn_count": 1}
    # The host has used 2 distinct fingerprints before; we cannot say WHICH two.
    vec = extract_zeek_features(row, baseline={"baseline_ja4_count": 2})
    assert vec["zeek_ja4_novelty"] == pytest.approx(1 / 3), (
        "with only a count, novelty must be the conservative lower bound: at most "
        "len(seen) - count can be new. Claiming more invents alerts on ordinary hosts."
    )
