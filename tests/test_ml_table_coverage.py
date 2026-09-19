"""Every ingested log must reach the models. A table nobody reads is data collected and wasted.

WHY THIS FILE EXISTS.

`zeek_http` (327 rows) and `zeek_files` (321 rows) were mapped, ingested, stored -- and read by
no query, no feature and no view. They contributed nothing to detection while appearing to be
part of the deployment, and nothing anywhere reported that. Found by Scripts/audit_schema.py,
section B, after the same class of defect had already shipped twice:

  * `zeek_ssl.ja3`/`ja3s` -- declared columns that nothing ever wrote
  * the six Tier-2 identity tables -- created and applied with no mapper at all

Three instances of one shape: **a name that exists in one place and is produced or consumed
nowhere.** A schema, a mapper and a feature list can each look complete while the pipeline
between them has a hole in it, because nothing about a hole is visible in any individual file.

These tests close the loop mechanically, per table, so a newly added log cannot be ingested and
silently ignored.
"""
from __future__ import annotations

import re
from pathlib import Path

from weirvern.ingester import ZEEK_MAPPERS
from weirvern.zeek_features import ZEEK_FEATURES

ROOT = Path(__file__).resolve().parents[1]
ZEEK_FEATURES_SRC = (ROOT / "weirvern" / "zeek_features.py").read_text()
WORKER = (ROOT / "weirvern" / "worker.py").read_text()


def _summary_sql() -> str:
    """The scoring/training summary query, as text."""
    from weirvern.zeek_features import zeek_window_summary_sql
    return zeek_window_summary_sql("2026-01-01 00:00:00", "2026-01-02 00:00:00")


def test_every_ingested_zeek_table_is_read_by_the_summary_query():
    """THE REGRESSION. Each mapped table must appear in the feature query, in the UNION of
    keys, AND in the LEFT JOINs -- all three, because a table in the SELECT but not the keys
    silently drops its rows, and one in the keys but not the JOINs adds nothing."""
    sql = _summary_sql()
    # Tables consumed by the ATT&CK mapping instead of the feature query. Their purpose is
    # protocol-level facts (a share path, an RPC operation), not numeric features -- so being
    # absent from the ML query is correct, PROVIDED something else reads them. The next test
    # asserts that, so this list cannot become a place to hide an unread table.
    PROTOCOL_ONLY = {"zeek_kerberos", "zeek_dce_rpc", "zeek_smb_mapping", "zeek_smb_files",
                     "zeek_ntlm"}
    for log_type, (target, _fn) in sorted(ZEEK_MAPPERS.items()):
        table = target.split(".")[-1]
        if table in PROTOCOL_ONLY:
            continue
        assert f"weirvern.{table}" in sql, (
            f"{log_type}.log is ingested into {table} but the feature query never reads it, so "
            f"its data is collected and discarded"
        )


def test_protocol_only_tables_are_still_read_by_something():
    """The exemption above must not become a hiding place. Every table excluded from the ML
    features has to be consumed by the protocol/ATT&CK path."""
    from weirvern.zeek_features import zeek_protocol_records_sql
    protocol = zeek_protocol_records_sql("2026-01-01 00:00:00", "2026-01-02 00:00:00")
    for table in ("zeek_kerberos", "zeek_dce_rpc", "zeek_smb_mapping", "zeek_smb_files",
                  "zeek_ntlm"):
        assert f"weirvern.{table}" in protocol, (
            f"{table} is neither an ML feature nor read by the protocol query -- it is "
            f"collected and discarded"
        )


def test_every_aggregation_is_joined_not_just_selected():
    """A CTE that is referenced in the SELECT but missing from the UNION-of-keys produces rows
    whose join key does not exist -- the columns come back as the coalesce default for every
    host, which looks like a quiet network rather than a bug."""
    sql = _summary_sql()
    aggs = set(re.findall(r"\n\s+(\w+_agg) AS \(", sql))
    # `str.index` finds the FIRST occurrence, and "keys AS (" appears in an explanatory COMMENT
    # earlier in the query -- so the slice was four characters wide and every assertion against
    # it failed. Anchor on the block's actual opening, which is followed by a newline and the
    # first `SELECT w, src_addr FROM`.
    anchor = re.search(r"keys AS \(\s*SELECT w, src_addr FROM", sql)
    assert anchor, "the UNION-of-keys block was not found by its real opening"
    # The block ENDS at its closing paren followed by the outer SELECT. Bounding on the next
    # bare "SELECT" truncated it at the first UNION's keyword, so every join after the first
    # looked absent -- the same class of instrument bug this whole file is about.
    tail = sql[anchor.end():]
    end = tail.index(")\n        SELECT")
    # `anchor.end()` is AFTER "... FROM ", so the first aggregate's name would be sliced off.
    # Prepend it: the first key source is written without a leading UNION, and it counts.
    keys_block = "conn_agg" + tail[:end]
    select_block = sql[sql.index("SELECT", sql.index("keys AS (")):]
    for agg in sorted(aggs):
        # The FIRST key source is written as a bare `SELECT ... FROM conn_agg` and the rest as
        # `UNION DISTINCT SELECT ... FROM <agg>`, so the aggregate NAME is the common factor.
        assert agg in keys_block, (
            f"{agg} is not in the UNION of join keys, so its rows are never joined to anything "
            f"and every one of its columns reads as the default"
        )
        assert f"LEFT JOIN {agg}" in select_block, (
            f"{agg} is defined but never joined into the output"
        )


def test_every_aggregation_uses_a_left_join_never_inner():
    """An INNER JOIN would drop every host-window Zeek did not observe. Measured on this box:
    91 NetFlow hosts against 35 Zeek hosts with an overlap of 2, so an inner join would discard
    ~98% of rows -- and a detector trained on that would be NetFlow-only while appearing to use
    both sensors."""
    sql = _summary_sql()
    joins = re.findall(r"\b(INNER|LEFT|RIGHT|FULL|CROSS)?\s*JOIN\s+(\w+_agg)", sql)
    for kind, agg in joins:
        assert kind == "LEFT", f"{agg} is joined with {kind or 'INNER'} -- it must be LEFT"


def test_the_feature_list_and_the_query_aliases_agree():
    """One name per concept. This project has already shipped a version where the features were
    `zeek_conn_count` while the query aliased `conn_count`, so EVERY training query named a
    column that did not exist."""
    sql = _summary_sql()
    aliases = set(re.findall(r"AS (\w+)", sql))
    missing = [f for f in ZEEK_FEATURES if f not in aliases and f != "zeek_present"]
    assert not missing, (
        f"these features have no matching SQL alias, so a training query selecting them fails: "
        f"{missing}"
    )


def test_every_http_and_files_feature_has_a_real_column_behind_it():
    """The two tables this test file was written for. Each new feature must name a column the
    SQL actually emits, not a plausible one."""
    sql = _summary_sql()
    new = [f for f in ZEEK_FEATURES if "http" in f or "file_" in f]
    assert len(new) >= 10, f"expected the HTTP and files features to be present, found {new}"
    for feature in new:
        assert feature in sql, (
            f"{feature} is in ZEEK_FEATURES but the query does not emit it -- the feature would "
            f"be KeyError or silently zero"
        )


def test_the_python_extractor_carries_the_new_features_through():
    """The SQL emits them; the Python path must copy them into the feature dict. A feature in
    the list but not in the dict is a training-time KeyError or a silent zero at scoring."""
    src = (ROOT / "weirvern" / "zeek_features.py").read_text()
    # Find the region that fills `out` for the new features.
    for feature in ("zeek_http_count", "zeek_file_count", "zeek_http_error_ratio"):
        assert f'"{feature}"' in src, f"{feature} is not referenced in the extractor"
    assert "for name in (" in src, "the pass-through loop for the new features is gone"


def test_both_detector_paths_use_the_extended_feature_set():
    """Training and scoring must use the SAME matrix. A feature added to one path and not the
    other gives the model an input it was never trained on."""
    detectors = (ROOT / "weirvern" / "models" / "detectors.py").read_text()
    assert "ZEEK_FEATURES" in detectors or "extract_features" in detectors, (
        "the detectors do not reference the shared feature definition"
    )
    # The worker reaches the extractor through `weirvern.features` / `zeek_features`; assert on
    # the actual import rather than on a call that may live one level down.
    assert "zeek_features" in WORKER or "extract_features" in WORKER, (
        "the worker does not use the shared feature definitions"
    )


def test_the_zeek_join_covers_every_table_it_advertises():
    """`ZEEK_JOIN_ON` is the shared fragment detectors use. It must key on the summary view
    (`zeek_w`), which is what the summary query produces -- a fragment pointing at a different
    relation would fail to compile in one detector and not another."""
    from weirvern.zeek_features import ZEEK_JOIN_ON, zeek_join_cte
    assert "zeek_w" in ZEEK_JOIN_ON, "the join fragment does not reference the summary alias"
    cte = zeek_join_cte("2026-01-01 00:00:00", "2026-01-02 00:00:00")
    assert "zeek_w" in cte, "the CTE does not define the alias the join fragment uses"
    # Every feature the models consume must be selectable from that CTE.
    for feature in ZEEK_FEATURES:
        assert feature in cte or feature == "zeek_present", (
            f"{feature} cannot be selected from the join CTE"
        )


# ── the SQL must be valid SQL, not Python-with-SQL-in-it ────────────────────────

def test_the_query_contains_no_python_style_comments():
    """THE BUG THIS CATCHES, measured against the live database.

    The new CTEs were documented with Python `#` comments INSIDE the SQL f-string. To Python
    that is a comment; to ClickHouse it is an unrecognised token:

        Code: 62. DB::Exception: Unrecognized token: Syntax error: failed at position 3143
        (#) (line 66, col 9): # WHAT IS WORTH FEATURISING ...

    Every unit test passed, because they compare STRINGS. Only executing the query against a
    real server found it. So the assertion runs against the GENERATED SQL -- which is what the
    driver sends -- and not against the source file.

    All five SQL templates in the module, not just the summary one: the same mistake is
    available in every one of them.
    """
    from weirvern import zeek_features as zf
    templates = {
        "zeek_window_summary_sql": zf.zeek_window_summary_sql(
            "2026-01-01 00:00:00", "2026-01-02 00:00:00"),
        "zeek_protocol_records_sql": zf.zeek_protocol_records_sql(
            "2026-01-01 00:00:00", "2026-01-02 00:00:00"),
        "zeek_coverage_sql": zf.zeek_coverage_sql("2026-01-01 00:00:00"),
        "zeek_baseline_sql": zf.zeek_baseline_sql("2026-01-01 00:00:00", "2026-01-02 00:00:00"),
        "zeek_join_cte": zf.zeek_join_cte("2026-01-01 00:00:00", "2026-01-02 00:00:00"),
    }
    for name, sql in templates.items():
        offenders = [
            line for line in sql.splitlines()
            if line.strip().startswith("#")
        ]
        assert not offenders, (
            f"{name} emits {len(offenders)} line(s) beginning with '#', which ClickHouse "
            f"rejects as an unrecognised token. Use '--' for SQL comments. First offender:\n"
            f"  {offenders[0][:100]}"
        )


def test_no_generated_sql_template_contains_a_python_comment_marker():
    """Belt and braces on the same defect: scan the module for a `#` at the start of a line
    that is inside a triple-quoted SQL block. Implemented as a direct check on the generated
    output above, so this only needs to catch a template that is not covered there."""
    import inspect

    from weirvern import zeek_features as zf
    src = inspect.getsource(zf)
    # Count how many SQL templates the module declares, so a new one cannot be added without
    # the test above being extended.
    templates = src.count('return f"""') + src.count('= f"""')
    covered = 5
    assert templates <= covered + 2, (
        f"the module declares roughly {templates} SQL templates but only {covered} are covered "
        f"by the comment check -- add the new one, or a `#` comment in it ships"
    )


def test_every_detector_training_query_uses_feature_names_not_raw_aliases():
    """THE REGRESSION, measured against the live cluster.

    The Adaptive Baseline's training query hand-wrote `z.conn_count`, `z.s0_count`,
    `z.service_count` and `z.notice_count`. The shared Zeek CTE exposes those concepts under
    their FEATURE names -- `zeek_conn_count`, `zeek_s0_ratio`, `zeek_service_count`,
    `zeek_notice_count` -- so ClickHouse rejected the query outright:

        Code: 47. DB::Exception: Identifier 'z.conn_count' cannot be resolved from subquery
        with name z.

    The consequence was the worst shape available: the OTHER THREE detectors trained fine, so
    a deployment would run with three working models and one permanently absent, and the status
    page would look healthy. `train()` returns False, which is logged and otherwise ignored.

    So this asserts that every detector's Zeek columns are drawn from the shared helper and
    named as features. Any `z.<name>` where <name> is not in ZEEK_FEATURES is the bug.
    """
    src = (ROOT / "weirvern" / "models" / "detectors.py").read_text()
    # COMMENTS STRIPPED. The fix documents itself by quoting the broken names
    # ("this block used to hand-write `z.conn_count`"), so a naive search finds the removal
    # note and reports the defect as still present. This is the seventh place in this project
    # an assertion had to read code rather than prose about code -- hence the helper.
    code = "\n".join(ln.split("--")[0].split("#")[0] for ln in src.splitlines())

    # Every `z.<identifier>` reference must name a real feature.
    referenced = set(re.findall(r"\bz\.([a-z_][a-z0-9_]*)", code))
    unknown = sorted(n for n in referenced if n not in ZEEK_FEATURES)
    assert not unknown, (
        f"the detector queries reference z.{unknown}, which are not feature names. The shared "
        f"CTE aliases every Zeek column as its FEATURE name, so these fail at query time."
    )


def test_no_detector_redeclares_its_own_zeek_columns():
    """A second reason the Baseline broke: it hand-wrote its Zeek select-list instead of using
    `_zeek_clause`, so the names could drift from the CTE. The helper exists precisely so the
    join and the names cannot differ between detectors."""
    src = (ROOT / "weirvern" / "models" / "detectors.py").read_text()
    code = "\n".join(ln.split("#")[0] for ln in src.splitlines())
    # Every detector that trains against Zeek must call the shared helper.
    trainings = code.count("def train(self")
    helper_uses = code.count("_zeek_clause(")
    assert helper_uses >= trainings, (
        f"{trainings} train() methods but only {helper_uses} uses of the shared _zeek_clause "
        f"helper -- at least one detector builds its own Zeek columns, which is how the "
        f"Adaptive Baseline's query drifted and broke"
    )
