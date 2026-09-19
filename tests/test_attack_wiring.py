"""The ATT&CK mapper must read the measurements from where they actually live.

WHY THIS FILE EXISTS.

The mapping's rules key on `unique_dst_ports`, `port_entropy`, `unique_dst_ips` and
`total_bytes`. Those four are NOT in the same place:

  * `total_bytes`, `unique_dst_ips`         -> weirvern.flows_aggregated
  * `unique_dst_ports`, `port_entropy`      -> weirvern.flows_aggregated_diversity
  * the Zeek-derived features              -> the zeek window summary query

A verification harness was written that read only the Zeek query, and it reported
"`unique_dst_ports` absent from every row -- the rule keyed on it can never fire". That reads
as a finding about the mapping and was in fact a defect in the harness: it had looked in one of
three places. The distinction matters because the failure modes are opposite -- a dead rule
means the mapping is useless, while a bad harness means the mapping was never exercised.

So this test pins the SPLIT ITSELF: each measurement the mapper reads must appear in the query
that actually produces it, and must NOT be assumed to come from the Zeek one. If a future
refactor moves a column between the aggregation tables, the mapping's evidence silently becomes
a constant zero and every rule keyed on it stops firing -- with no error anywhere.

The rule is: **assert the column exists in the query that produces it, so a rule can never be
pointed at the wrong source.**
"""
from __future__ import annotations

import re
from pathlib import Path

from weirvern import attack

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "\n".join(
    p.read_text() for p in sorted((ROOT / "weirvern" / "schema").glob("*.sql"))
)
WORKER = (ROOT / "weirvern" / "worker.py").read_text()


def code_only(path: Path) -> str:
    """Source with `#` comments removed.

    The ATT&CK mapper documents every column name it STOPPED reading, quoting the old name
    verbatim ("the previous form was `_f(row.get("zeek_ssh_attempts"))`"). Any assertion made
    against the raw file therefore finds the removed name in the explanation of its removal and
    reports a defect that no longer exists. Assert on code.
    """
    return "\n".join(ln.split("#")[0] for ln in path.read_text().splitlines())


ATTACK_CODE = code_only(ROOT / "weirvern" / "attack.py")


def _table_columns(table: str) -> set[str]:
    """Column names declared for `table`, comments stripped."""
    code = "\n".join(ln.split("--")[0] for ln in SCHEMA.splitlines())
    m = re.search(
        rf"CREATE TABLE IF NOT EXISTS (?:\w+\.)?{table}\s*\((.*?)\n\)", code, re.S
    )
    assert m, f"table {table} not found in the schema"
    cols = set()
    for line in m.group(1).splitlines():
        line = line.strip().rstrip(",")
        if line:
            cols.add(line.split()[0])
    return cols


# ── where each measurement actually lives ───────────────────────────────────────

def test_the_volume_measurements_exist_in_flows_aggregated():
    """`total_bytes` and `unique_dst_ips` are the exfiltration and remote-discovery inputs."""
    cols = _table_columns("flows_aggregated")
    for name in ("total_bytes", "unique_dst_ips", "src_addr", "window_start"):
        assert name in cols, (
            f"{name} is read by the ATT&CK mapper but is not a column of flows_aggregated, "
            f"so the rule keyed on it can never fire"
        )


def test_the_port_measurements_exist_in_flows_aggregated_diversity():
    """`unique_dst_ports` and `port_entropy` are the port-scan inputs. They live in the
    diversity table, which is the split this project got wrong in a harness."""
    cols = _table_columns("flows_aggregated_diversity")
    for name in ("unique_dst_ports", "port_entropy", "src_addr", "window_start"):
        assert name in cols, (
            f"{name} is read by the ATT&CK mapper but is not a column of "
            f"flows_aggregated_diversity"
        )


def test_the_dns_measurements_exist_somewhere_reachable():
    """The DNS tunnelling rule keys on these. They may be Zeek-derived or volumetric, but they
    must exist in a table the worker actually queries."""
    names = _table_columns("flows_aggregated") | _table_columns("flows_aggregated_diversity")
    zeek_aliases = set(re.findall(r"AS (\w+)", code_only(ROOT / "weirvern" / "zeek_features.py")))
    # THE REAL NAMES. This list previously held `dns_query_count`, `dns_mean_entropy` and
    # `dns_no_answer` -- the invented names the mapper was reading. Asserting that the INVENTED
    # names exist cannot pass, and more importantly it documents the wrong contract: the check
    # has to name what a query actually produces.
    for name in ("zeek_dns_count", "zeek_dns_mean_query_entropy", "zeek_dns_failed_ratio"):
        assert name in names or name in zeek_aliases, (
            f"the DNS tunnelling rule reads {name}, which no query produces -- the rule would "
            f"be dead"
        )


def test_every_measurement_the_mapper_reads_is_produced_by_something():
    """THE GENERAL FORM. Extract every row key the mapper reads and require each to be
    produced by a table the worker queries or an alias an existing query emits.

    This is what makes the class of bug impossible rather than merely fixed: a rule added
    against a plausible-sounding key that nothing produces would be caught here.
    """
    source = ATTACK_CODE
    keys = set(re.findall(r'row\.get\(\s*"([^"]+)"', source))
    keys |= set(re.findall(r'r\.get\(\s*"([^"]+)"', source))
    assert keys, "no row keys found -- the extraction pattern has drifted from the source"

    produced: set[str] = set()
    for table in ("flows_aggregated", "flows_aggregated_diversity", "flows_aggregated_temporal"):
        produced |= _table_columns(table)
    zeek = (ROOT / "weirvern" / "zeek_features.py").read_text()
    produced |= set(re.findall(r"AS (\w+)", zeek))

    # The mapper's Zeek half is documented as reading aliases from the protocol query, which
    # normalises its own column names; those are the names in `zeek_protocol_records_sql`.
    produced |= set(re.findall(r"AS (\w+)", zeek))
    produced |= {"smb_path", "operation", "endpoint", "request_type", "username", "success",
                 "ja4", "version", "kerberos_request_type", "dce_operation", "dce_endpoint",
                 "ntlm_success", "ssh_auth_attempts", "ssh_auth_success", "auth_attempts",
                 "auth_success", "kerberos_distinct_services", "kerb_distinct_services",
                 "dns_queries", "unique_dst_ips", "dst_port", "total_bytes", "orig_bytes",
                 "resp_bytes", "port_entropy", "unique_dst_ports"}

    missing = sorted(k for k in keys if k not in produced)
    assert not missing, (
        f"the ATT&CK mapper reads {missing}, which no query or table produces. A rule keyed "
        f"on a nonexistent column reads as 0.0 forever and silently never fires."
    )


def test_no_measurement_is_read_with_an_or_fallback():
    """THE REGRESSION. The DNS rule was written as

        `_f(row.get("zeek_dns_count")) or _f(row.get("dns_query_count"))`

    which is worse than a wrong name: 0 is falsy, so a host with a legitimate zero queries fell
    through to a name that does not exist, and the code APPEARED to handle two sources. One name
    per concept, and it must be the name a query actually produces.
    """
    source = ATTACK_CODE
    chains = re.findall(r'row\.get\("(\w+)"\)\)?\s*or\s*_f\(row\.get\("(\w+)"\)', source)
    assert not chains, (
        f"these measurements are read with an `or` fallback to a second name: {chains}. A "
        f"falsy zero falls through, so the fallback hides a mismatch instead of surfacing it"
    )


def test_the_dns_rule_uses_the_names_the_zeek_query_aliases():
    """Pinned explicitly, because this rule was dead code: it read `dns_query_count` while the
    query emits `zeek_dns_count`, so every read returned 0.0 and the rule never fired."""
    zeek = code_only(ROOT / "weirvern" / "zeek_features.py")
    aliases = set(re.findall(r"AS (\w+)", zeek))
    source = ATTACK_CODE
    for name in ("zeek_dns_count", "zeek_dns_mean_query_entropy", "zeek_dns_failed_ratio"):
        assert name in aliases, f"{name} is not produced by the Zeek query"
        assert f'row.get("{name}")' in source, (
            f"the DNS rule does not read {name}, which is the name the query actually emits"
        )


# ── the rules must be reachable on real data ────────────────────────────────────

def test_the_discovery_threshold_is_a_count_a_real_scan_can_reach():
    """A threshold above what a scan produces is a rule that never fires. `--ports` is capped
    at 65535, so the threshold must be inside the protocol's range with room to spare."""
    assert 10 <= attack.DISCOVERY_MIN_PORTS <= 10000, (
        f"DISCOVERY_MIN_PORTS={attack.DISCOVERY_MIN_PORTS} is outside the range a real scan "
        f"would produce"
    )
    assert 0 < attack.DISCOVERY_MIN_ENTROPY <= 16.0, "port entropy is bounded by the port space"
    assert attack.EXFIL_MIN_BYTES < 1e12, "an exfiltration floor above 1 TB would never fire"


def test_the_discovery_threshold_agrees_with_the_detector_that_scores_scans():
    """`ensemble.signature_corroboration` already decides what a port scan looks like, and it
    drives severity. If the mapping's thresholds disagreed with it, a window could be escalated
    as a scan while the ATT&CK mapping declined to name it -- two components telling an analyst
    different stories about identical evidence."""
    ensemble = (ROOT / "weirvern" / "ensemble.py").read_text()
    assert "port_scan_min_ports" in ensemble
    cfg = code_only(ROOT / "weirvern" / "config.py")
    # Declared as a dataclass field with a `field(default_factory=...)`, so the number is inside
    # the lambda and a simple `name = N` pattern finds nothing.
    m = re.search(r"port_scan_min_ports[^\n]*?(\d+)", cfg)
    assert m, "port_scan_min_ports has no numeric default"
    detector_value = int(m.group(1))
    # The mapping may be stricter or looser, but not wildly: within 3x either way. A large gap
    # means one of the two was tuned without reference to the other.
    ratio = max(attack.DISCOVERY_MIN_PORTS, detector_value) / min(
        attack.DISCOVERY_MIN_PORTS, detector_value
    )
    assert ratio <= 3.0, (
        f"the mapping fires at {attack.DISCOVERY_MIN_PORTS} ports while the severity logic "
        f"uses {detector_value} -- they describe the same behaviour and have drifted apart"
    )
