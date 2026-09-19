"""ATT&CK rules must read values that something actually provides, ON THE ROW THEY GET.

WHY THIS EXISTS. Four rules were already found reading names no query produced, and each was
fixed by correcting the NAME. That fix was incomplete, and this file exists because of what it
missed: the rules read FLAT keys while the worker attached the values NESTED.

The defect, measured end to end before the fix:

    worker.py built each flow row as  f["_diversity"] = {...}, f["_zeek"] = {...}
    attack.py read                   row.get("unique_dst_ports"), row.get("port_entropy")

Nothing flattened the nesting, so every one of those reads returned None -> 0.0. A row that
satisfies the T1046 port-scan thresholds on every count -- 400 ports, entropy 8.4, 4 KB out,
300 destinations -- mapped to ONE technique instead of three:

    nested under _diversity   -> [T1018]
    merged flat               -> [T1046, T1595, T1018]

So a textbook port scan produced no discovery technique at all. Two further defects fell out of
the same audit:

  * `resp_bytes` has no source in `flows_aggregated` (it stores per-source volume only), so the
    exfiltration ratio was bytes_out/(bytes_out+0) == 1.0. That clears EXFIL_MIN_RATIO (0.9)
    unconditionally, so T1041 fired on EVERY large transfer -- a 50 MB backup was reported as
    exfiltration over C2. A rule that cannot fail is not a detection.
  * `attempts` / `successes` (SSH brute force) are aliased by the ZEEK protocol query, not by
    the flow row, so T1110 could never fire from `map_techniques`. Moved to
    `map_zeek_techniques`, where the rows carry per-connection auth counts.

WHAT THIS TEST DOES: for each mapping function it reconstructs the row shape the caller really
builds -- from the schema and the query aliases, not from the rules' own assumptions -- and
asserts that every key the rules read is reachable from it. A rule reading a name the row cannot
provide is a rule that can never fire, which looks exactly like a network with nothing to say.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _schema_columns(table: str) -> set[str]:
    sql = "\n".join(p.read_text() for p in sorted((ROOT / "weirvern" / "schema").glob("*.sql")))
    sql = re.sub(r"--[^\n]*", "", sql)
    m = re.search(
        r"CREATE TABLE (?:IF NOT EXISTS )?(?:weirvern\.)?" + re.escape(table) + r"\s*\((.*?)\n\)",
        sql, re.S,
    )
    if not m:
        return set()
    out: set[str] = set()
    for line in m.group(1).splitlines():
        first = (line.strip().rstrip(",").split() or [""])[0]
        if re.fullmatch(r"[a-z_][a-z0-9_]*", first):
            out.add(first)
    return out


def _function_body(name: str) -> str:
    """The source of one function in attack.py, up to the next top-level def.

    COMMENTS ARE STRIPPED, and that is essential rather than tidy. Several comments in
    `map_techniques` quote the OLD broken reads to explain why they were removed --
    `# There was an `or _f(row.get("orig_bytes"))` here` -- and a raw scan matches that prose
    and reports `orig_bytes` as a live read. The first version of this test did exactly that,
    producing four false positives out of six findings. A guard that cries wolf gets its
    allow-list widened until it checks nothing.
    """
    src = (ROOT / "weirvern" / "attack.py").read_text()
    start = src.index(f"def {name}(")
    rest = src[start + 10:]
    m = re.search(r"\ndef ", rest)
    body = src[start:start + 10 + (m.start() if m else len(rest))]
    body = re.sub(r"/\*.*?\*/", "", body, flags=re.S)
    return re.sub(r"#[^\n]*", "", body)


def _keys_read(body: str) -> set[str]:
    return set(re.findall(r'row\.get\("([a-z_]+)"\)', body)) | set(
        re.findall(r'r\.get\("([a-z_]+)"\)', body)
    )


def test_every_key_map_techniques_reads_is_on_the_row_worker_builds():
    """The volumetric row = flows_aggregated + the Zeek summary + the two other side-tables.

    ALL THREE SIDE-TABLES COUNT AS REACHABLE, because worker.py merges each one's columns into
    the row flat. The Zeek summary is the one that caught this test out: `zeek_dns_count`,
    `zeek_dns_failed_ratio` and `zeek_dns_mean_query_entropy` are aliases of
    `zeek_window_summary_sql`, NOT columns of `flows_aggregated`, so a reachable-set built from
    the schema alone reported three live rules as dead.

    The set is therefore built from BOTH sources -- the schema for the flow tables, and the
    query's own aliases for the Zeek summary. A rule reading a name from neither is the real
    defect, and that is what this asserts.
    """
    from weirvern.zeek_features import zeek_window_summary_sql

    reachable = (
        _schema_columns("flows_aggregated")
        | _schema_columns("flows_aggregated_diversity")
        | _schema_columns("flows_aggregated_temporal")
        | {"window_start", "window_end", "src_addr", "_diversity", "_temporal", "_zeek"}
    )
    # The Zeek summary's aliases: these arrive via f["_zeek"] and are merged flat.
    summary_sql = zeek_window_summary_sql("2026-01-01 00:00:00", "2026-01-02 00:00:00")
    reachable |= set(re.findall(r"\bAS ([a-z_][a-z0-9_]*)\b", summary_sql, re.I))

    read = _keys_read(_function_body("map_techniques"))
    missing = sorted(read - reachable)
    assert not missing, (
        f"map_techniques reads {missing}, which neither the flow tables, the Zeek summary query, "
        "nor any merged side-table provides. Those reads return None -> 0.0, so any rule gated "
        "on one can NEVER fire while looking like coverage. Either merge the value in or delete "
        "the rule."
    )


def test_every_key_map_zeek_techniques_reads_is_on_the_protocol_rows():
    """The protocol rows are built by zeek_protocol_records_sql's UNION, not by a table.

    The union pads every branch with `0 AS attempts, 0 AS successes` and the rest of the column
    names, so the ALIASES it declares are the row's keys -- plus `kind` and `src_addr`, which
    every branch selects.

    TWO SUBTLETIES, both verified rather than assumed:

      * `request_type` / `version` / `ja4` / `username` / `success` read as FALLBACKS behind a
        real alias. `# request_type AS operation` means the row's key is `operation`, and the
        rule reads `r.get("operation") or r.get("request_type")` -- the second half never
        matters. Such a read is not a defect, so it is listed here explicitly with the alias
        that satisfies it.
      * A name that is neither an alias nor such a fallback IS a defect: the rule silently
        reads nothing. That is how the NTLM branch (which aliased no username) and the absent
        SSL branch were found -- both had rules reading keys the union never produced.
    """
    from weirvern.zeek_features import zeek_protocol_records_sql

    sql = zeek_protocol_records_sql("2026-01-01 00:00:00", "2026-01-02 00:00:00")
    aliases = set(re.findall(r"\bAS ([a-z_][a-z0-9_]*)\b", sql, re.I))
    reachable = aliases | {"kind", "src_addr"}

    # name read -> the alias that actually carries it (verified against the query above).
    satisfied_by_alias = {
        "request_type": "operation",   # branch("zeek_kerberos", "... request_type AS operation ...")
    }
    body = _function_body("map_zeek_techniques")
    read = set(re.findall(r'r\.get\("([a-z_]+)"\)', body))
    missing = sorted(n for n in read - reachable if n not in satisfied_by_alias)
    assert not missing, (
        f"map_zeek_techniques reads {missing}, which the protocol-query union does not produce "
        f"under any name. Those reads always return None, so the rule can never fire. "
        f"Aliases available: {sorted(aliases)}"
    )
    # And each documented fallback must really be backed by its alias, or the exemption is a
    # quiet way to keep a dead rule alive.
    for name, alias in satisfied_by_alias.items():
        assert alias in aliases, (
            f"{name} is exempted on the grounds that {alias!r} carries it, but the union no "
            f"longer aliases {alias!r} -- so the read is dead and the exemption is stale."
        )


def test_the_union_carries_the_columns_the_zeek_rules_read():
    """The NTLM and SSL rules must have their columns SELECTed, not merely referencable.

    WHY THIS IS SEPARATE FROM THE TEST ABOVE. That one compares the rules' reads against the
    union's aliases, which catches a rule reading a name that is not declared. It does NOT catch
    a branch that declares the name but pads it with a constant -- which is exactly how the NTLM
    bug looked: the column existed in the union's shape (as `'' AS username` on every other arm)
    while the zeek_ntlm arm supplied nothing real, so `username` was always empty and the T1110
    guard never passed.

    Removing the ssl branch entirely and stubbing NTLM's username both left that test GREEN,
    which is how these assertions were found to be necessary: a guard that does not fail when the
    defect returns is not a guard.
    """
    from weirvern.zeek_features import zeek_protocol_records_sql

    sql = zeek_protocol_records_sql("2026-01-01 00:00:00", "2026-01-02 00:00:00")

    # The SSL arm must exist and select the real version/ja4 columns.
    assert "FROM weirvern.zeek_ssl" in sql, (
        "the protocol union has no zeek_ssl branch. T1573 reads `version` and `ja4` from TLS "
        "records, so without this arm the deprecated-TLS rule cannot fire at all."
    )
    ssl_arm = sql[sql.index("'zeek_ssl' AS kind"):sql.index("FROM weirvern.zeek_ssl")]
    for col in ("version", "ja4"):
        assert f"{col}, " in ssl_arm or f"{col} " in ssl_arm.replace("AS ", "AS_"), (
            f"the zeek_ssl arm does not select `{col}`, so T1573 reads an empty value"
        )
    assert "'' AS ja4" not in ssl_arm.split("FROM")[0], (
        "the zeek_ssl arm pads ja4 with an empty string instead of selecting the real column"
    )

    # The NTLM arm must supply username/success rather than padding them.
    assert "FROM weirvern.zeek_ntlm" in sql, "the protocol union has no zeek_ntlm branch"
    ntlm_arm = sql[sql.index("'zeek_ntlm' AS kind"):sql.index("FROM weirvern.zeek_ntlm")]
    assert "'' AS username" not in ntlm_arm, (
        "the zeek_ntlm arm pads `username` with an empty string. T1110's guard is "
        "`if r.get(\"username\")`, so a padded username means NTLM brute force can never be "
        "reported -- the defect this arm was added to fix."
    )
    assert "success" in ntlm_arm, "the zeek_ntlm arm does not carry `success`"


def test_the_side_tables_are_actually_merged_into_the_flow_row():
    """Pin the merge itself, because the rules silently depend on it.

    Without this, removing the merge leaves the ATT&CK tests passing (they call the mappers with
    hand-built rows) while production maps almost nothing -- the worst kind of green.
    """
    src = (ROOT / "weirvern" / "worker.py").read_text()
    assert "for k, v in got.items():" in src, (
        "worker.py no longer merges the side-tables into the flow row. The ATT&CK rules read "
        "those values as FLAT keys, so every rule depending on them goes silently dead. See the "
        "comment in worker.py for the measurement."
    )
    for side in ("_diversity", "_temporal", "_zeek"):
        assert f'"{side}"' in src, f"worker.py no longer attaches {side}"


def test_the_exfiltration_rule_does_not_claim_a_ratio_it_cannot_compute():
    """T1041 must not fire on volume alone at a confidence that implies evidence.

    `resp_bytes` has no source, so any ratio built from it is 1.0 by construction and clears the
    0.9 threshold unconditionally -- reporting every large transfer as exfiltration. The rule may
    still surface the volume, but at LOW confidence and saying why.
    """
    body = _function_body("map_techniques")
    assert 'row.get("resp_bytes")' not in body, (
        "map_techniques reads resp_bytes again. flows_aggregated has no inbound-bytes column, so "
        "this value is always 0 and any ratio computed from it is 1.0 -- which clears "
        "EXFIL_MIN_RATIO unconditionally and makes T1041 fire on every large transfer."
    )
    # Find the T1041 match and assert its confidence is low.
    m = re.search(r'TECHNIQUES\["T1041"\],\s*"(\w+)"', body)
    assert m, "T1041 is no longer mapped in map_techniques -- was it moved deliberately?"
    assert m.group(1) == "low", (
        f'T1041 is mapped at "{m.group(1)}" confidence, but the volumetric row cannot show '
        "asymmetry (no inbound-bytes column). Volume alone is not exfiltration; a backup "
        "uploading 50 MB would be reported as C2. Keep it low, or move the rule to where the "
        "Zeek orig/resp bytes are available."
    )


def test_ssh_brute_force_reads_the_counts_the_protocol_rows_carry():
    """T1110 from SSH needs auth_attempts/auth_success, which only the zeek_ssh branch aliases."""
    vol = _function_body("map_techniques")
    assert 'row.get("attempts")' not in vol, (
        "map_techniques reads `attempts` again, but the flow row has no such column -- the count "
        "comes from the ZEEK protocol query's zeek_ssh branch. The T1110 rule would never fire."
    )
    zeek = _function_body("map_zeek_techniques")
    assert 'r.get("attempts")' in zeek and 'r.get("successes")' in zeek, (
        "map_zeek_techniques does not read the SSH attempt counts, so moving the rule out of "
        "map_techniques removed the detection rather than fixing it."
    )
    assert 'TECHNIQUES["T1110"]' in zeek, "T1110 is no longer mapped anywhere"
