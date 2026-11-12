"""DATA-0: the coverage contract must measure hosts, not just count rows."""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

from weirvern.models import data_contract

ROOT = Path(__file__).resolve().parents[1]


def _schema_tables() -> set[str]:
    tables = set()
    for path in (ROOT / "weirvern" / "schema").glob("*.sql"):
        text = re.sub(r"--[^\n]*", "", path.read_text())
        tables |= {m.group(1) for m in re.finditer(
            r"CREATE TABLE IF NOT EXISTS\s+(?:weirvern\.)?(\w+)", text, re.I)}
    return tables


class FakeClient:
    """Answers by shape: scopes, per-table counts, per-table distinct hosts."""

    def __init__(self, *, hosts_by_table, counts_by_table=None, broken=()):
        self.hosts_by_table = hosts_by_table
        self.counts_by_table = counts_by_table or {}
        self.broken = set(broken)

    def query(self, sql, parameters=None):
        if "network_scopes" in sql:
            return SimpleNamespace(result_rows=[("1", "203.0.113.0/24", "internal", 1, "full", "", "operator")])
        for table in self.broken:
            if table in sql:
                raise RuntimeError(f"{table} unavailable")
        # LONGEST NAME FIRST: "weirvern.flows" is a substring of "weirvern.flows_aggregated",
        # and the first fixture that matched would answer for the wrong table.
        if "SELECT count(), max(" in sql:
            for table in sorted(self.counts_by_table, key=len, reverse=True):
                if table in sql:
                    return SimpleNamespace(result_rows=[self.counts_by_table[table]])
            return SimpleNamespace(result_rows=[(0, None)])
        if "SELECT DISTINCT s.src_addr" in sql:
            for table in sorted(self.hosts_by_table, key=len, reverse=True):
                if table in sql:
                    return SimpleNamespace(result_rows=[(h,) for h in self.hosts_by_table[table]])
            return SimpleNamespace(result_rows=[])
        raise AssertionError(sql)


HOSTS = {"203.0.113.10", "203.0.113.11", "203.0.113.12"}
NOW = "2026-11-11 23:59:00"


def _healthy():
    return FakeClient(
        hosts_by_table={
            "weirvern.flows": HOSTS,
            "weirvern.flows_aggregated": HOSTS,
            "weirvern.zeek_conn": HOSTS,
            "weirvern.zeek_dns": {"203.0.113.10"},
            "weirvern.zeek_ssl": {"203.0.113.10"},
            "weirvern.zeek_notice": set(),
            "weirvern.ml_window_scores": HOSTS,
        },
        counts_by_table={
            "weirvern.flows": (1000, _now()),
            "weirvern.flows_aggregated": (500, _now()),
            "weirvern.zeek_conn": (400, _now()),
            "weirvern.zeek_dns": (40, _now()),
            "weirvern.zeek_ssl": (20, _now()),
            "weirvern.zeek_notice": (0, None),
            "weirvern.ml_window_scores": (900, _now()),
        },
    )


def _now():
    from datetime import UTC, datetime
    return datetime.now(UTC).replace(tzinfo=None)


def test_the_contract_is_machine_readable_and_names_only_real_tables():
    contract = data_contract.load_contract()
    assert contract["version"] and contract["window_hours"] == 24
    assert data_contract.validate_contract(contract, _schema_tables()) == []
    names = {s["name"] for s in contract["sources"]}
    assert {"flows", "zeek_dns", "zeek_ssl", "ml_window_scores"} <= names


def test_coverage_is_measured_against_monitored_hosts_not_row_counts():
    out = data_contract.inventory(_healthy())
    assert out["available"] is True
    assert out["population"]["hosts"] == 3
    assert out["population"]["monitored_scopes"] == ["203.0.113.0/24"]

    by_name = {s["name"]: s for s in out["sources"]}
    assert by_name["flows"]["coverage_pct"] == 100.0 and by_name["flows"]["usable"] is True
    # Two of three hosts never appear in DNS: 40 fresh rows do not make that coverage.
    assert by_name["zeek_dns"]["coverage_pct"] == 33.3
    assert by_name["zeek_dns"]["hosts_missing"] == 2
    assert by_name["zeek_dns"]["usable"] is False
    # Zero rows is 'not measured', never 0% and never a passing check.
    assert by_name["zeek_notice"]["state"] == "not measured"
    assert by_name["zeek_notice"]["coverage_pct"] == 0.0


def test_no_family_is_usable_when_its_source_is_absent_or_degraded():
    out = data_contract.inventory(_healthy())
    families = {f["name"]: f for f in out["families"]}
    assert families["flow"]["usable"] is True
    assert families["dns"]["usable"] is False
    assert "zeek_dns" in families["dns"]["reason"] and "33.3%" in families["dns"]["reason"]
    assert families["tls"]["usable"] is False
    assert families["temporal"]["usable"] is True


def test_an_unreadable_source_is_unknown_not_zero_coverage():
    client = _healthy()
    client.broken = {"weirvern.zeek_ssl"}
    out = data_contract.inventory(client)
    ssl = next(s for s in out["sources"] if s["name"] == "zeek_ssl")
    assert ssl["state"] == "unknown" and ssl["hosts_covered"] is None
    assert ssl["coverage_pct"] is None and ssl["usable"] is False


def test_every_monitored_host_says_which_channels_observed_it():
    out = data_contract.inventory(_healthy())
    hosts = {h["src_addr"]: h for h in out["hosts"]}
    assert set(hosts) == HOSTS
    quiet = hosts["203.0.113.11"]
    assert quiet["status"] == "covered"          # required sources saw it
    assert "weirvern.zeek_dns" not in quiet["covered_by"]
    assert "zeek_dns" in quiet["missing"]
    # A host absent from a REQUIRED source is explicitly not observed, not merely quiet.
    client = _healthy()
    client.hosts_by_table["weirvern.flows"] = {"203.0.113.10"}
    out2 = data_contract.inventory(client)
    missing = {h["src_addr"]: h for h in out2["hosts"] if h["src_addr"] != "203.0.113.10"}
    assert missing and all(h["status"] == "not observed" for h in missing.values())


def test_the_gap_report_names_hosts_and_flags_over_accepted_missingness():
    out = data_contract.inventory(_healthy())
    gap = next(g for g in out["gaps"] if g["source"] == "zeek_dns")
    assert gap["missing"] == 2 and gap["over_accepted"] is True
    assert gap["hosts"] == ["203.0.113.11", "203.0.113.12"]


def test_promotion_is_blocked_only_by_required_sources():
    out = data_contract.inventory(_healthy())
    assert out["promotion_ok"] is True       # DNS/TLS are optional for promotion
    client = _healthy()
    client.counts_by_table["weirvern.flows_aggregated"] = (0, None)
    out2 = data_contract.inventory(client)
    assert out2["promotion_ok"] is False
