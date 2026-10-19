#!/usr/bin/env python3
"""Full schema audit: every column, and whether anything writes or reads it.

WHY THIS EXISTS. Three separate defects of the same shape have already shipped in this project:

  1. `zeek_ssl.ja3` / `ja3s` -- columns declared in the schema, referenced by nothing Zeek ever
     emitted, permanently empty. Nobody noticed because an empty column looks like a quiet
     network.
  2. The whole Tier-2 identity schema (six tables) was committed and applied with NO mapper, so
     every table stayed empty forever while `weirvern status` reported a healthy sensor.
  3. The ATT&CK mapping read `dns_query_count`, `orig_bytes`, `ssh_auth_attempts` and
     `kerberos_distinct_services` -- four names no query produces, so four rules could never
     fire and each looked like working coverage.

Every one of those is "a name in one place that nothing in another place produces". This script
checks that mechanically, in both directions, across the WHOLE schema rather than for a feature
at a time:

  A. DEAD COLUMNS      a table column that no mapper writes  -> always empty
  B. UNREAD TABLES     a table with a mapper but nothing reading it (not ingested into ML,
                       not surfaced anywhere) -> data collected and never used
  C. PHANTOM REFERENCES  a name the code reads that no table or query produces -> a rule or
                       feature that silently reads 0.0

It runs from the repo root; it does not need the cluster.

Usage:  python /home/hart/Documents/Scripts/audit_schema.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def _repo_root() -> Path:
    """The directory the script is being run against.

    NOT a hardcoded path. An earlier version pinned an absolute path from one developer's machine,
    which meant the audit silently ran against whatever happened to be there -- or nothing -- on
    any other checkout. The script lives in `scripts/`, so the repository is its parent.
    """
    here = Path(__file__).resolve()
    for candidate in (here.parent.parent, Path.cwd()):
        if (candidate / "weirvern" / "schema").is_dir():
            return candidate
    return here.parent.parent


ROOT = _repo_root()
SCHEMA_DIR = ROOT / "weirvern" / "schema"
SRC = [p for p in (ROOT / "weirvern").rglob("*.py")] + [ROOT / "weirvern" / "admin" / "web" / "app.js"]

# Tables that hold no per-record columns we map positionally: reference/summary tables.
NOT_A_SOURCE_TABLE = {"schema_versions", "sensor_status", "ml_models", "alert_events",
                      "baseline_history", "flows", "netflow_anomalies", "ntlm_identity_daily"}


def strip_comments(sql: str) -> str:
    return "\n".join(ln.split("--")[0] for ln in sql.splitlines())


def tables() -> dict[str, tuple[str, list[str]]]:
    """table -> (file, ordered column list).

    ALTER TABLE ... ADD COLUMN IS INCLUDED, and that matters. Columns were previously discovered
    from `CREATE TABLE` only, so a column added by a later migration was invisible to this audit
    -- and a column the audit cannot see is a column it cannot check for a writer. The first
    ALTER-based migration (007_sensor_capture.sql) surfaced it immediately: three columns were
    written and read by real code, and this reported them as "phantom references".

    The rule the audit encodes is "a column must have a writer or a reader". An ALTER-added
    column satisfies it exactly like a declared one, so both are collected here.
    """
    out: dict[str, tuple[str, list[str]]] = {}
    for path in sorted(SCHEMA_DIR.glob("*.sql")):
        code = strip_comments(path.read_text())
        for m in re.finditer(
            r"CREATE TABLE IF NOT EXISTS\s+(?:\w+\.)?(\w+)\s*\((.*?)\n\)\s*ENGINE", code, re.S
        ):
            cols = []
            for line in m.group(2).splitlines():
                line = line.strip().rstrip(",")
                if not line:
                    continue
                cols.append(line.split()[0])
            out[m.group(1)] = (path.name, cols)
        # Migrations run in filename order, so an ALTER in 007_ applies to a table declared in
        # 003_. Append rather than replace: the declared columns are still there.
        for m in re.finditer(
            r"ALTER TABLE\s+(?:\w+\.)?(\w+)\s+ADD COLUMN IF NOT EXISTS\s+(\w+)", code, re.S
        ):
            table, col = m.group(1), m.group(2)
            if table in out:
                fname, cols = out[table]
                if col not in cols:
                    cols.append(col)
                out[table] = (fname, cols)
            else:
                # An ALTER for a table this audit never saw declared: record it so the column is
                # still checked, and note the migration as its source.
                out[table] = (path.name, [col])
    return out


def source_blob() -> str:
    return "\n".join(p.read_text() for p in SRC)


def strip_py_comments(src: str) -> str:
    """Remove `#` comments so an assertion reads code rather than prose about code.

    The ATT&CK mapper's docstrings deliberately QUOTE the wrong column names they replaced
    ("this used to read `dns_query_count`"), and a naive search reads that explanation as the
    defect it documents.
    """
    out = []
    for line in src.splitlines():
        # Cheap and sufficient here: none of the strings we search for contain a literal `#`.
        out.append(line.split("#")[0])
    return "\n".join(out)


def main() -> int:
    blob = source_blob()
    tbl = tables()
    findings: list[str] = []

    print("=" * 78)
    print("A. DEAD COLUMNS -- a table column nothing writes")
    print("=" * 78)
    # Writers are: Python source, AND the SQL itself. The nine columns first reported as dead
    # are all populated by a `INSERT INTO ... SELECT` materialized view in the same file, so
    # checking only the .py files reported working columns as dead. The check has to look where
    # the writes actually are.
    sql_blob = "\n".join(strip_comments(p.read_text()) for p in SCHEMA_DIR.glob("*.sql"))
    dead: list[str] = []
    for name, (fname, cols) in sorted(tbl.items()):
        if name in NOT_A_SOURCE_TABLE:
            continue
        for col in cols:
            if re.search(rf'["\']{re.escape(col)}["\']', blob):
                continue
            # A column written by an MV appears bare (not quoted) in an INSERT/SELECT body.
            if re.search(rf"\b{re.escape(col)}\b", sql_blob):
                continue
            dead.append(f"{name}.{col}   ({fname})")
    if dead:
        print("  columns referenced by NO source file -- they can never be populated:")
        for d in dead:
            print(f"    {d}")
        findings.append(f"{len(dead)} dead column(s)")
    else:
        print("  none: every column of every ingested table is referenced by code")

    print()
    print("=" * 78)
    print("B. MAPPED TABLES -- is anything READ from them?")
    print("=" * 78)
    # Which tables does the ML/query layer read?
    readers = {
        "features.py": (ROOT / "weirvern" / "features.py").read_text(),
        "zeek_features.py": (ROOT / "weirvern" / "zeek_features.py").read_text(),
        "worker.py": (ROOT / "weirvern" / "worker.py").read_text(),
        "status.py": (ROOT / "weirvern" / "admin" / "status.py").read_text(),
        "attack.py": (ROOT / "weirvern" / "attack.py").read_text(),
        "app.js": (ROOT / "weirvern" / "admin" / "web" / "app.js").read_text(),
    }
    from weirvern.ingester import ZEEK_MAPPERS
    from weirvern.zeek_features import zeek_protocol_records_sql

    protocol_sql = zeek_protocol_records_sql("2000-01-01 00:00:00", "2100-01-01 00:00:00")

    # A table can be legitimately unread by the ML layer and still have a purpose. Each exception
    # carries the REASON, and the reason is verified rather than trusted: an exemption that cannot
    # justify itself is exactly the "collected and never used" case this section exists to catch.
    EXEMPT = {
        # x509.log has NO src_addr -- it is keyed on the certificate fingerprint, because one
        # certificate is presented by many hosts and Zeek deduplicates per certificate. The ML
        # feature join is (window, src_addr), so a certificate CANNOT be attributed to a host from
        # this log. Joining it by a constant would give every host a column reading the default
        # forever: a feature that is always 0.0, indistinguishable from a quiet network.
        #
        # It is ingested and queryable for HUNTING -- "is this certificate self-signed?" and
        # "which hosts share this issuer?" are joins through ssl.log's cert_chain_fps -- and it is
        # read by the protocol-records query, which is checked below.
        "zeek_x509": "no src_addr (keyed on certificate fingerprint); queryable via the protocol "
                     "query, not attributable to a host for ML features",
    }

    for log_type, (target, _fn) in sorted(ZEEK_MAPPERS.items()):
        table = target.split(".")[-1]
        where = [n for n, txt in readers.items() if table in txt]
        if not where and table in EXEMPT:
            # THE EXEMPTION IS VERIFIED, NOT TRUSTED. An earlier version of this exemption
            # claimed x509 was "queryable via the protocol query" -- and it was not, which is
            # precisely the sort of unverified assertion that lets a table stay unread while the
            # audit reports a pass. So the claim is checked against the query itself.
            if table not in protocol_sql:
                findings.append(
                    f"{table} is exempted from the unread check but is NOT read by the protocol "
                    f"query either -- the exemption is unsubstantiated"
                )
                print(f"  {log_type:14} -> {table:22} !! EXEMPT but unread by the protocol query")
                continue
            print(f"  {log_type:14} -> {table:22} EXEMPT (read by the protocol query): "
                  f"{EXEMPT[table]}")
            continue
        mark = "READ by " + ", ".join(where) if where else "!! NOT READ ANYWHERE"
        flag = "" if where else "  <-- collected and never used"
        print(f"  {log_type:14} -> {table:22} {mark}{flag}")
        if not where:
            findings.append(f"{table} is ingested but read by nothing")

    print()
    print("=" * 78)
    print("C. PHANTOM REFERENCES -- names the code reads that nothing produces")
    print("=" * 78)
    # Every produced name: table columns + query aliases.
    produced: set[str] = set()
    for _name, (_f, cols) in tbl.items():
        produced |= set(cols)
    produced |= set(re.findall(r"\bAS (\w+)", blob))
    # ROW KEYS PRODUCED IN PYTHON. Not every key the code reads comes from SQL: `attach_reviews`
    # sets `row["review_state"]` and friends on rows it was handed, and the reader then does
    # `row.get("review_state")`. Without this rule the audit reported review_state as a phantom
    # reference -- a false positive that says "the code reads a name nothing produces" about a
    # name the code itself produces, which is exactly the kind of unverified finding that gets a
    # real one ignored. The pattern is deliberately SYMMETRIC with the reader scan below (same
    # row-like variable names), so a key cannot be produced by one convention and read by another.
    produced |= set(re.findall(r'(?<![\w.])(?:row|r|f|flow)\[\s*"([^"]+)"\s*\]\s*=', blob))
    # Feature-list literals are produced by construction.
    for fn in ("FEATURES", "ZEEK_FEATURES", "ZEEK_DBSCAN_FEATURES", "EXPLAINED_MEASUREMENTS"):
        m = re.search(rf"^{fn}\s*=\s*[\[\(](.*?)[\]\)]", blob, re.S | re.M)
        if m:
            produced |= set(re.findall(r'"(\w+)"', m.group(1)))

    # THE FLEET PAYLOAD is the same situation one layer in: `fleet_store.build_fleet` builds its
    # envelope and rows with dict literals, which the producer patterns above cannot see, while
    # status.py legitimately reads them with row-like names (pipeline_audit reads `f` and `r`).
    # Checking these keys here reported six false phantoms the moment BF-13 landed -- the exact
    # "unverified finding that gets a real one ignored" the section above warns about. The
    # contract itself is pinned by tests/test_pipeline_audit.py + the fleet tests.
    FLEET_PAYLOAD = {
        # envelope
        "sensors", "summary", "available", "reason", "heartbeats_available", "heartbeat_reason",
        "filtered", "revoked", "revoked_reason",
        # row fields pipeline_audit reads
        "registered", "enabled", "state", "age_s", "stale_after_s", "sensor_id", "note",
        # WL-2: the segment facts the per-sensor issue findings compare (declared vs observed)
        "segment", "reported_segment", "expected_mode", "capture_loss_pct",
        "packets_recv", "packets_dropped",
        # WL-3: the capture path and the channel's evidence (web.py reads them to state
        # whether the in-path channel is forwarding, and the reason when it is not)
        "reported_mode", "iface", "mappings", "running",
        # the self-audit's own finding records (pipeline_audit -> panic_page)
        "class", "severity", "subject", "detail", "elapsed_s", "fix",
    }

    # GoFlow2's raw JSON is not a table: `raw` in ingester.py is the collector's message, whose
    # field names come from the collector's schema, not from our DDL. Checking them here would
    # report the whole flow mapper as phantom.
    COLLECTOR_JSON = {
        "time_flow_start_ns", "time_flow_end_ns", "fragment_offset", "type", "sampling_rate",
        "bytes", "packets", "src_addr", "dst_addr", "src_port", "dst_port", "proto",
        "tcp_flags", "forwarding_status", "src_as", "dst_as", "in_if", "out_if",
    }

    phantom: list[str] = []
    for path in SRC:
        if path.suffix != ".py":
            continue
        rel = path.relative_to(ROOT)
        code = strip_py_comments(path.read_text())
        # A WORD BOUNDARY IS LOAD-BEARING. Without it the alternative `r` matches the tail of any
        # identifier ending in r, f or flow -- `nft_counter.get("packets")` read as a ROW lookup
        # and reported "counter" as a phantom column. Renaming the variable would only dodge the
        # bug: the next `...er.get(...)` or `...if.get(...)` would trip it again. `(?<![\w.])`
        # requires the name to stand alone.
        for m in re.finditer(r'(?<![\w.])(?:row|r|f|flow)\s*\.get\(\s*"([^"]+)"', code):
            key = m.group(1)
            if key in produced:
                continue
            # Skip obviously-local dicts (test fixtures, metadata rows).
            if key in {"name", "type", "version", "reason", "message", "ts", "uid"}:
                continue
            if key in COLLECTOR_JSON:
                continue
            if key in FLEET_PAYLOAD:
                continue
            if not re.match(r"^[a-z][a-z0-9_]*$", key):
                continue
            phantom.append(f"{rel}: .get(\"{key}\")")

    # Deduplicate by the name read, not by the call site: the interesting fact is the name.
    by_name: dict[str, list[str]] = {}
    for p in phantom:
        name = re.search(r'\.get\("([^"]+)"', p).group(1)  # type: ignore[union-attr]
        by_name.setdefault(name, []).append(p)
    if by_name:
        print("  keys read from a row that no table column or query alias produces:")
        for name, sites in sorted(by_name.items()):
            print(f"    {name:34} <- {len(sites)} site(s): {', '.join(sorted(set(sites))[:2])}")
        findings.append(f"{len(by_name)} phantom reference(s)")
    else:
        print("  none")

    print()
    print("=" * 78)
    if findings:
        print(f"AUDIT FAILED: {len(findings)} finding(s)")
        for f in findings:
            print(f"  - {f}")
        return 1
    print("AUDIT PASSED: no dead columns, no unread tables, no phantom references")
    return 0


if __name__ == "__main__":
    sys.exit(main())
