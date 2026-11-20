#!/usr/bin/env python3
"""ML COVERAGE AUDIT: is the ML actually using the bulk of what we collect?

WHY THIS IS A DIFFERENT QUESTION FROM audit_schema.py.

`audit_schema.py` answers "is every table read by SOMETHING" -- and it passes, because every Zeek
table is read by `zeek_features.py`, `status.py` or the GUI. But "read by something" is not "used
by the models":

  * a table read only by `zeek_features.py` for a protocol record contributes to hunting or
    display, not necessarily to a feature vector
  * a table read only by `status.py` or `app.js` contributes to a DISPLAY, not to a model
  * and a table whose rows are never sampled into a training window is collected and dropped

The user's question was "verify we are using the bulk of our data collection in the ml models". That
is a VOLUME question, not an existence question. A table with 12 rows matters less than one with
400,000, and a table used only for display is not used by the models at all however many rows it has.

So this measures three things:

  1. which tables the ML feature code actually reads (by parsing the SQL, not by grep)
  2. how many rows each table holds (from the live database)
  3. what fraction of collected DATA VOLUME reaches the models

Usage:
    python scripts/audit_ml_coverage.py              # code-side only, no cluster needed
    python scripts/audit_ml_coverage.py --live       # also read row counts from ClickHouse
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The modules that build FEATURE VECTORS. Deliberately excludes status.py (dashboard) and the
# web layer (display): reading a table there does not put it in a model, and conflating the two
# is exactly how "collected but unmodelled" hides.
ML_MODULES = [
    "weirvern/zeek_features.py",
    "weirvern/features.py",
    # THE DETECTORS ARE ML TOO, and leaving them out produced a false finding: this audit reported
    # `flows_aggregated_temporal`, `flows_aggregated_diversity` and `baseline_history` as "not modelled"
    # when `models/detectors.py` reads all three -- two as LEFT JOINs that feed the Adaptive Baseline
    # and cross-sectional feature vectors, one as the persisted baseline state. Together they are
    # ~14% of all
    # stored volume, so the omission moved the headline number by a third.
    #
    # The lesson is the point of this file: a coverage audit is only as good as its list of readers,
    # and a reader left off the list becomes a defect that does not exist.
    #
    # These are the REAL module paths, checked against the tree -- an earlier version listed
    # `models/ensemble.py` and `models/trainer.py`, which do not exist (guessed names), and the
    # reference test caught it. Inventing a path is worse than omitting one: the audit would silently
    # scan nothing and under-report coverage again.
    "weirvern/models/detectors.py",
    "weirvern/models/scoring.py",
    "weirvern/models/base.py",
]

# Modules that READ the data but do NOT feed a model. Listed so the report can name the difference
# rather than implying a table is modelled because something somewhere mentions it.
NON_ML_READERS = {
    "weirvern/admin/status.py": "dashboard",
    "weirvern/admin/web/app.js": "GUI",
    "weirvern/admin/web.py": "GUI API",
}

# A table also appears BARE, as a SQL identifier with no database prefix -- e.g.
# `branch("zeek_dce_rpc", ...)` builds `FROM weirvern.zeek_dce_rpc` by string formatting, and
# `zeek_smb_files`/`zeek_dce_rpc`/`zeek_kerberos`/`zeek_smb_mapping` are all named that way.
#
# Matching only the prefixed form made this audit UNDER-REPORT ML coverage: it listed four ingested
# tables as "read only by NOTHING" while the feature module was reading all four. An audit that
# produces a wrong answer is worse than no audit, because it sends someone to fix a non-problem --
# so the bare form is matched too, anchored to the table-name shape rather than any word.
BARE_TABLE_RE = re.compile(r"\bweirvern\.([a-z0-9_]+)\b|\b(zeek_[a-z0-9_]+|flows_aggregated)\b")
# Longest-first so `zeek_x509` is not reported as `zeek_x` -- a truncating alternation produced a
# wrong table name in an earlier pass, and a wrong name in an audit is worse than no audit.
CREATE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:weirvern\.)?([a-z][a-z0-9_]*)", re.I
)
# THE PREFIX IS OPTIONAL IN THE SCHEMA, and assuming it was present made this audit wrong twice over.
#
# `001_weirvern.sql` creates its tables UNPREFIXED (`CREATE TABLE IF NOT EXISTS flows`), because the
# database is selected before the schema runs; the later migration files use `weirvern.`. Matching
# only the prefixed form dropped every core table -- `flows`, `flows_aggregated`, `netflow_anomalies`,
# `ml_models` -- from the declared set, so the volume report showed 31 rows collected, called the
# models' coverage 61%, and labelled those core tables "modelled but NOT DECLARED".
#
# A schema audit that cannot see the schema's biggest tables is worse than useless: it reports a
# coverage number that is simply false.


def schema_tables() -> set[str]:
    """Table names declared by the schema.

    SQL COMMENTS ARE STRIPPED BEFORE MATCHING, and that is not cosmetic: the phrase
    "the CREATE TABLE in 001_weirvern.sql" inside an explanatory comment made this return `in` and
    `is` as table names. A junk name is worse than a missing one -- it inflates the declared set, so
    coverage arithmetic silently uses tables that do not exist.
    """
    tables: set[str] = set()
    for path in sorted((ROOT / "weirvern" / "schema").glob("*.sql")):
        text = path.read_text()
        # `--` to end of line, and /* ... */ blocks.
        text = re.sub(r"--[^\n]*", "", text)
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        for match in CREATE_RE.finditer(text):
            tables.add(match.group(1))
    return tables


def tables_read_by(rel_path: str, declared: set[str]) -> set[str]:
    """Which DECLARED TABLES does this module reference?

    The result is intersected with the schema's declared table names, and that intersection is the
    point rather than a tidy-up. Matching on the `zeek_` prefix alone also matches FEATURE names
    (`zeek_ssh_count`, `zeek_service_rarity`), helper names (`zeek_select_columns`,
    `zeek_window_summary_sql`) and CTE aliases (`zeek_w`) -- so a prefix-only scan reports coverage
    that does not exist. Only a name that is a real table in the schema counts as reading that table.
    """
    path = ROOT / rel_path
    if not path.exists():
        return set()
    found: set[str] = set()
    for m in BARE_TABLE_RE.finditer(path.read_text()):
        name = m.group(1) or m.group(2)
        if name in declared:
            found.add(name)
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true",
                    help="read row counts from ClickHouse (needs kubectl access)")
    ap.add_argument("--host", default="",
                    help="ssh host where the cluster lives, e.g. root@box (the cluster is remote)")
    args = ap.parse_args(argv)

    declared = schema_tables()
    ml = set()
    for mod in ML_MODULES:
        ml |= tables_read_by(mod, declared)

    non_ml: dict[str, list[str]] = {}
    for mod, label in NON_ML_READERS.items():
        for t in tables_read_by(mod, declared):
            non_ml.setdefault(t, []).append(label)

    print("=" * 78)
    print("TABLES FEEDING THE MODELS (read by the feature modules)")
    print("=" * 78)
    for t in sorted(ml):
        print(f"    {t}")

    print()
    print("=" * 78)
    print("COLLECTED BUT NOT MODELLED")
    print("=" * 78)
    gaps = sorted(declared - ml)
    if not gaps:
        print("    none: every declared table feeds a feature vector")
    for t in gaps:
        reads = ", ".join(sorted(set(non_ml.get(t, [])))) or "NOTHING"
        print(f"    {t:24s} read only by: {reads}")

    # Declared-but-never-seen and modelled-but-not-declared are both real defects: the first means a
    # query references a table that does not exist, the second means the schema is missing a file.
    phantom = sorted(ml - declared)
    if phantom:
        print()
        print("    !! modelled but NOT DECLARED in the schema (a query would fail):")
        for t in phantom:
            print(f"       {t}")

    if not args.live:
        print()
        print("NOTE: this is the code-side view. Data VOLUME is what decides whether the bulk is")
        print("      covered -- re-run with --live to weight each table by its actual row count.")
        return 0

    print()
    print("=" * 78)
    print("DATA VOLUME, AND HOW MUCH OF IT REACHES THE MODELS")
    print("=" * 78)
    counts = row_counts(sorted(declared), args.host)
    if counts is None:
        print("    could not read row counts (no kubectl / cluster unreachable)")
        return 1

    total = sum(counts.values())
    modelled = sum(c for t, c in counts.items() if t in ml)
    if total == 0:
        print("    every table is empty, so coverage cannot be judged from volume yet")
        return 0

    print(f"    {'table':26s} {'rows':>12s}  {'model?':>7s}  share")
    for t, c in sorted(counts.items(), key=lambda kv: -kv[1]):
        pct = 100.0 * c / total
        print(f"    {t:26s} {c:12,d}  {'YES' if t in ml else 'no':>7s}  {pct:5.1f}%")

    print()
    print(f"    TOTAL collected rows      : {total:,}")
    print(f"    rows the models can see   : {modelled:,}  ({100.0 * modelled / total:.1f}%)")
    print()
    # A RAW ROW COUNT IS NOT THE VERDICT, and reporting it as one would be a false finding.
    #
    # Three of the unmodelled tables are not gaps at all:
    #
    #   flows                       the raw NetFlow landing table (50% of all volume). It is fed
    #                               forward by MATERIALIZED VIEWs into flows_aggregated* -- which the
    #                               models DO read. Modelling raw flows directly is neither the
    #                               design nor desirable: the aggregates are the feature source, and
    #                               the raw table is the replay/audit trail. Counted as "not modelled"
    #                               it swings the headline by half.
    #   netflow_anomalies           the models' OUTPUT, read by the GUI and alerting. A model does not
    #   alert_events                read its own conclusions as features.
    #   ml_models, baseline_history model state, not input.
    #   sensor_status, schema_versions   operational metadata.
    #   ntlm_identity_daily         THE ONE GENUINE FINDING: a daily rollup maintained by a
    #                               materialized view and read by NOTHING -- not a model, not a rule,
    #                               not a panel. Collected and dropped.
    print("    READING THE NUMBER: the raw count above is NOT the verdict. Raw landing tables that are")
    print("    fed forward by materialized views into modelled aggregates (flows -> flows_aggregated*),")
    print("    model OUTPUT (netflow_anomalies, alert_events), model STATE (ml_models,")
    print("    baseline_history) and operational metadata (sensor_status, schema_versions) are all")
    print("    correctly absent from the feature vectors. Treating them as gaps inflates the shortfall")
    print("    by ~50 points.")
    print()
    if modelled / total >= 0.99:
        print("    VERDICT: the models see essentially all collected volume.")
    else:
        print("    VERDICT: see the per-table notes above. The tables genuinely worth acting on are")
        print("             those marked 'no' that are neither a raw landing table nor model")
        print("             output/state -- for those, either wire them in or stop collecting them.")
    return 0


def row_counts(tables: list[str], host: str = "") -> dict[str, int] | None:
    """Row count per table, from the live ClickHouse.

    THE CLUSTER IS REMOTE. This ran `kubectl` locally and failed with "no kubectl / cluster
    unreachable" -- which reads like the cluster being down, when the truth is that this workstation
    has no kubectl at all and the k3s node is a different machine. A failure that names the wrong
    cause sends someone to debug the wrong thing, so the transport is explicit and the error says
    which piece broke.

    `host` empty => run locally (for a workstation that does have a kubeconfig). Otherwise the query
    runs over ssh on that host, which is where the cluster actually lives.
    """
    # count() per table, one UNION ALL rather than a clever single statement: readable, and a
    # failure names the table it failed on.
    parts = " UNION ALL ".join(
        f"SELECT '{t}' AS tbl, count() AS n FROM weirvern.{t}" for t in tables
    )
    script = (
        "CH=$(kubectl -n weirvern get secret weirvern-secrets "
        "-o jsonpath='{.data.CLICKHOUSE_PASSWORD}' | base64 -d); "
        f"kubectl -n weirvern exec clickhouse-0 -c clickhouse -- clickhouse-client --password \"$CH\" "
        f"-q \"{parts} FORMAT TSV\""
    )
    cmd = ["bash", "-lc", script] if not host else ["ssh", "-o", "BatchMode=yes", host, script]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        err = (out.stderr or "") + (out.stdout or "")
        if "command not found" in err:
            where = host or "this machine"
            print(f"    !! no kubectl on {where}. The cluster lives elsewhere -- use --host <box>.")
        elif "Permission denied" in err or "publickey" in err:
            print(f"    !! ssh to {host!r} failed (auth)")
        else:
            print(f"    !! query failed: {err.strip().splitlines()[-1][:90] if err.strip() else 'no output'}")
        return None
    counts: dict[str, int] = {}
    for line in out.stdout.splitlines():
        bits = line.split("\t")
        if len(bits) == 2 and bits[1].isdigit():
            counts[bits[0]] = int(bits[1])
    return counts or None


if __name__ == "__main__":
    sys.exit(main())
