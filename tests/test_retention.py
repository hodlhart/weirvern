"""Retention derived from free disk: the arithmetic, the control, and the read-back.

WHY THIS FILE EXISTS. The ripple layer measures a host against its own trailing history at
1h/6h/24h/7d scales with a 30-window minimum, so the tables need history. How much is not a
number someone picks: it is what the disk can afford.

    budget_bytes  = free_bytes * ratio / 100          # ratio default 40%
    bytes_per_day = bytes_on_disk / observed_days      # the managed tables, measured
    days          = floor(budget_bytes / bytes_per_day)

What is pinned here:

  * the default is AUTO, and auto derives exactly from (free bytes, bytes/day, ratio);
  * the 7-day floor and 365-day cap both hold, and the sentence says which bit;
  * auto re-derives when free space changes -- nobody edits a day count;
  * the ratio is bounded 10-70 and both ends are refused with the reason;
  * an explicit override above the measured budget is refused, with the budget named;
  * the Settings payload carries the ARITHMETIC, not just the resulting number;
  * the schema bootstraps the managed tables at the floor, and the startup migration
    converges them to the derived value (idempotently, one ALTER per table);
  * the read-back records the cluster's EFFECTIVE TTL and a disagreement is reported;
  * a failed ALTER names its table and leaves the previous value in place;
  * a viewer sees the value read-only and cannot write it;
  * audit/provenance tables are absent from the managed list, with their reasons stated.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

from weirvern import retention
from weirvern.admin import cluster_config as cc
from weirvern.admin import payloads, status

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "weirvern" / "schema"

GB = 1_000_000_000


# ── a ClickHouse stand-in, including the ways it can fail ─────────────────────────────────────


def _ddl(table: str, column: str, days: int | None) -> str:
    """A realistic `create_table_query`, as `system.tables` stores it."""
    clause = f"\nTTL {column} + INTERVAL {days} DAY" if days is not None else ""
    return (f"CREATE TABLE weirvern.{table}\n(\n    {column} DateTime\n)\n"
            f"ENGINE = MergeTree()\nPARTITION BY toYYYYMM({column})\n"
            f"ORDER BY ({column}){clause}")


class FakeCH:
    """Records DDL, answers `system.*` reads from explicit numbers.

    `fail` makes `command()` raise for a table (an ALTER the database refused); `ignore`
    makes it accept the statement and keep the old TTL (a read-back that disagrees). Both are
    real failure shapes and the report must distinguish them.
    """

    def __init__(self, days: dict[str, Any] | None = None, *,
                 free_bytes: int = 200 * GB, total_bytes: int = 400 * GB,
                 bytes_on_disk: int = 200 * GB, span_days: float = 100.0,
                 fail: set[str] | None = None, ignore: set[str] | None = None,
                 disk_name: str = "default") -> None:
        self.days = dict(days or {t.name: retention.MIN_RETENTION_DAYS
                                  for t in retention.RETENTION_TABLES})
        self.free_bytes = free_bytes
        self.total_bytes = total_bytes
        self.bytes_on_disk = bytes_on_disk
        self.span_days = span_days
        self.disk_name = disk_name
        self.fail = set(fail or ())
        self.ignore = set(ignore or ())
        self.commands: list[str] = []
        self.audit: list[tuple] = []

    def query(self, sql: str, parameters=None):  # noqa: ANN001 - duck-typed client
        if "system.disks" in sql:
            rows = [(self.disk_name, self.total_bytes, self.free_bytes)]
        elif "DISTINCT disk_name" in sql:
            rows = [(self.disk_name,)]
        elif "dateDiff" in sql:
            names = [t.name for t in retention.RETENTION_TABLES if t.name in self.days]
            span_s = int(self.span_days * 86400)
            if not names:
                rows = []
            else:
                share = self.bytes_on_disk // len(names)
                rows = [(name, share, span_s) for name in names]
                rows[0] = (names[0], self.bytes_on_disk - share * (len(names) - 1), span_s)
        elif "system.tables" in sql:
            rows = [(t.name, _ddl(t.name, t.column, self.days.get(t.name)))
                    for t in retention.RETENTION_TABLES if t.name in self.days]
        else:  # pragma: no cover - a new query shape should fail loudly, not silently
            raise AssertionError(f"unexpected query: {sql[:80]}")

        class _Result:
            result_rows = rows

        return _Result()

    def command(self, sql: str) -> None:
        self.commands.append(sql)
        match = re.match(r"ALTER TABLE (\w+) MODIFY TTL (.+?) \+ INTERVAL (\d+) DAY$", sql)
        assert match, f"unexpected DDL: {sql}"
        name = match.group(1)
        if name in self.fail:
            raise RuntimeError("ACCESS_DENIED: the user cannot ALTER this table")
        if name not in self.ignore:
            self.days[name] = int(match.group(3))

    def insert(self, table: str, data, column_names=None) -> None:  # noqa: ANN001
        self.audit.append((table, list(data), list(column_names or [])))


class _Conn:
    """The context-manager shape `ctx.connect_factory` returns."""

    def __init__(self, client) -> None:  # noqa: ANN001
        self.client = client

    def __enter__(self):
        return self.client

    def __exit__(self, *exc) -> bool:
        return False


# ── 1. the arithmetic ────────────────────────────────────────────────────────────────────────


def test_the_default_is_auto_with_a_40_percent_budget(monkeypatch):
    monkeypatch.delenv("DATA_RETENTION_DAYS", raising=False)
    monkeypatch.delenv("DATA_RETENTION_RATIO", raising=False)
    from weirvern.config import Settings

    assert retention.AUTO == "auto"
    assert retention.DEFAULT_RATIO_PERCENT == 40
    settings = Settings()
    assert retention.is_auto(settings.data_retention_days)
    assert settings.data_retention_ratio == 40


def test_derivation_is_exact_from_free_bytes_rate_and_ratio():
    """200 GB free x 40% = 80 GB; at 2 GB/day that is exactly 40 days."""
    m = retention.Measurement(disk_name="default", total_bytes=400 * GB, free_bytes=200 * GB,
                              bytes_on_disk=200 * GB, span_days=100.0)
    report = retention.derive(m, 40)
    assert report["available"] is True
    assert report["budget_bytes"] == 80 * GB
    assert report["bytes_per_day"] == pytest.approx(2 * GB)
    assert report["raw_days"] == pytest.approx(40.0)
    assert report["days"] == 40
    assert report["budget_days"] == 40
    assert report["floored"] is False and report["capped"] is False
    assert report["sentence"] == (
        "Auto — 40 days from 200 GB free at 2.0 GB/day (40% budget). Merge headroom kept.")


def test_the_floor_holds_and_the_sentence_says_what_the_disk_supports():
    """40 GB free x 40% = 16 GB; at 4 GB/day that supports only 4 days -> hold 7."""
    m = retention.Measurement(disk_name="default", total_bytes=400 * GB, free_bytes=40 * GB,
                              bytes_on_disk=400 * GB, span_days=100.0)
    report = retention.derive(m, 40)
    assert report["days"] == retention.MIN_RETENTION_DAYS == 7
    assert report["floored"] is True
    assert report["raw_days"] == pytest.approx(4.0)
    assert "disk supports 4.0 days" in report["sentence"]
    assert "holding the 7-day floor" in report["sentence"]


def test_the_cap_holds_at_365_days():
    m = retention.Measurement(disk_name="default", total_bytes=4000 * GB,
                              free_bytes=2000 * GB, bytes_on_disk=1 * GB, span_days=100.0)
    report = retention.derive(m, 40)
    assert report["raw_days"] > 365
    assert report["days"] == retention.MAX_RETENTION_DAYS == 365
    assert report["capped"] is True
    assert "capped at 365" in report["sentence"]


def test_auto_recomputes_when_free_space_changes():
    """The property that makes 'auto' worth having: nobody edits a day count."""
    base = retention.Measurement(disk_name="default", total_bytes=400 * GB,
                                 free_bytes=200 * GB, bytes_on_disk=200 * GB, span_days=100.0)
    tighter = retention.Measurement(disk_name="default", total_bytes=400 * GB,
                                    free_bytes=100 * GB, bytes_on_disk=200 * GB, span_days=100.0)
    assert retention.derive(base, 40)["days"] == 40
    assert retention.derive(tighter, 40)["days"] == 20


def test_a_rate_over_a_short_span_is_floored_so_it_cannot_explode():
    """Ten minutes of ingest extrapolated by a division-by-almost-zero would be nonsense."""
    m = retention.Measurement(disk_name="default", total_bytes=400 * GB, free_bytes=200 * GB,
                              bytes_on_disk=1 * GB, span_days=0.0001)
    assert m.observed_days == pytest.approx(retention.MIN_RATE_SPAN_DAYS)
    assert m.bytes_per_day == pytest.approx(24 * GB)


def test_the_measurement_ignores_the_epoch_sentinel_when_it_reads_the_span():
    """`min_time = toDateTime(0)` on a part with no minmax index is not 56 years of history."""

    class RecordingCH(FakeCH):
        def __init__(self) -> None:
            super().__init__()
            self.queries: list[str] = []

        def query(self, sql: str, parameters=None):  # noqa: ANN001 - duck-typed client
            self.queries.append(sql)
            return super().query(sql, parameters)

    ch = RecordingCH()
    measurement = retention.measure(ch)
    span_sql = next(sql for sql in ch.queries if "dateDiff" in sql)
    assert "minIf(min_time, rows > 0 AND min_time > toDateTime(0))" in span_sql
    assert "maxIf(max_time, rows > 0 AND max_time > toDateTime(0))" in span_sql
    assert measurement.span_days == pytest.approx(100.0)


def test_the_rate_divides_each_table_by_its_own_span():
    """A 7-day table and a 30-day table did not write their bytes over the same interval.

    The live box held 7-day aggregates beside 30-day Zeek logs. Dividing the whole 750 MB by
    the 34-day union span understated ingest ~5x; that understatement is what turns a derived
    window into a disk that fills before its TTL expires it.
    """

    class _Result:
        def __init__(self, rows) -> None:  # noqa: ANN001
            self.result_rows = rows

    class PerTableCH(FakeCH):
        def query(self, sql: str, parameters=None):  # type: ignore[override]  # noqa: ANN001
            if "dateDiff" in sql:
                return _Result([("short", 700_000_000, 7 * 86400),
                                ("long", 300_000_000, 30 * 86400)])
            return super().query(sql, parameters)

    measurement = retention.measure(PerTableCH())
    assert measurement.bytes_on_disk == 1_000_000_000
    assert measurement.span_days == pytest.approx(30.0)
    # 100 MB/day from the short table plus 10 MB/day from the long one.
    assert measurement.bytes_per_day == pytest.approx(110_000_000)


def test_auto_does_not_derive_from_less_than_a_day_of_history():
    """A ten-minute-old database is not evidence of a daily rate; the tables keep their TTL."""
    m = retention.Measurement(disk_name="default", total_bytes=400 * GB, free_bytes=200 * GB,
                              bytes_on_disk=2 * GB, span_days=0.25)
    report = retention.derive(m, 40)
    assert report["available"] is False
    assert report["days"] is None
    assert "a full day is needed" in report["reason"]
    assert "not derived yet" in report["sentence"]


def test_an_implausible_history_span_never_derives_a_window():
    """THE LIVE FAILURE, pinned: an epoch `min_time` made the span 56 years and derived 365.

    Free space and bytes are the measured live numbers (2026-11-19). The span is what
    `system.parts` reported before the epoch sentinel was filtered. A 365-day fallback from a
    56-year span is exactly the disk-filling setting this control exists to prevent, so the
    report must refuse to derive at all.
    """
    m = retention.Measurement(disk_name="default", total_bytes=105_089_261_568,
                              free_bytes=10_855_522_304, bytes_on_disk=749_477_326,
                              span_days=20_777.0)
    report = retention.derive(m, 40)
    assert report["available"] is False
    assert report["days"] is None
    assert report["budget_days"] is None
    assert "implausible" in report["reason"]
    assert "not derived yet" in report["sentence"]


def test_the_ratio_bounds_are_10_and_70_and_both_ends_are_refused():
    assert retention.MIN_RATIO_PERCENT == 10
    assert retention.MAX_RATIO_PERCENT == 70
    assert retention.normalise_ratio("10") == 10
    assert retention.normalise_ratio("70.0") == 70
    for bad in ("9", "71", "0", "10.5"):
        with pytest.raises(ValueError) as refused:
            retention.normalise_ratio(bad)
        assert "10" in str(refused.value) and "70" in str(refused.value)
    m = retention.Measurement("default", 400 * GB, 200 * GB, 200 * GB, 100.0)
    with pytest.raises(ValueError):
        retention.derive(m, 71)


def test_a_bigger_ratio_derives_a_longer_window():
    m = retention.Measurement("default", 400 * GB, 200 * GB, 200 * GB, 100.0)
    assert retention.derive(m, 40)["days"] == 40
    assert retention.derive(m, 70)["days"] == 70


# ── 2. the explicit override ─────────────────────────────────────────────────────────────────


def test_an_explicit_value_above_the_budget_is_refused_with_the_budget_named():
    m = retention.Measurement("default", 400 * GB, 200 * GB, 200 * GB, 100.0)
    report = retention.derive(m, 40)          # budget 40 days
    assert retention.budget_refusal(40, report) == ""
    refusal = retention.budget_refusal(300, report)
    assert "300 days" in refusal
    assert "measured budget is 40 day(s)" in refusal
    assert "Choose 40 or fewer" in refusal


def test_an_explicit_value_at_the_floor_is_allowed_even_when_the_disk_supports_less():
    """7 is the POLICY minimum; refusing it would make a small disk unusable."""
    m = retention.Measurement("default", 400 * GB, 40 * GB, 400 * GB, 100.0)
    report = retention.derive(m, 40)          # budget 4 days
    assert report["budget_days"] == 4
    assert retention.budget_refusal(7, report) == ""
    assert "measured budget is 4 day(s)" in retention.budget_refusal(8, report)


def test_explicit_days_keep_their_7_to_365_bounds():
    for bad in ("6", "366", "7.5", "many"):
        with pytest.raises(ValueError):
            retention.normalise_days(bad)
    assert retention.normalise_days("7") == 7
    assert retention.normalise_days("365") == 365
    assert cc.validate("DATA_RETENTION_DAYS", "7") == ""
    assert cc.validate("DATA_RETENTION_DAYS", "365") == ""
    assert cc.validate("DATA_RETENTION_DAYS", "auto") == ""
    for bad in ("6", "366"):
        with pytest.raises(cc.ConfigError) as refused:
            cc.validate("DATA_RETENTION_DAYS", bad)
        assert "7" in str(refused.value) and "365" in str(refused.value)


def test_the_ratio_is_validated_by_the_same_parser_the_derivation_uses():
    assert cc.validate("DATA_RETENTION_RATIO", "10") == ""
    assert cc.validate("DATA_RETENTION_RATIO", "70") == ""
    for bad in ("9", "71"):
        with pytest.raises(cc.ConfigError) as refused:
            cc.validate("DATA_RETENTION_RATIO", bad)
        assert "10" in str(refused.value) and "70" in str(refused.value)


# ── 3. the Settings payload carries the arithmetic ───────────────────────────────────────────


def _row(key: str, *, settings=None, retention_status=None) -> dict:
    rows = status.settings_overview(settings=settings, retention_status=retention_status)["groups"]
    for fields in rows.values():
        for row in fields:
            if row["key"] == key:
                return row
    raise AssertionError(f"{key} is not a rendered settings row")


def test_the_settings_row_carries_the_ARITHMETIC_not_just_the_result():
    m = retention.Measurement("default", 400 * GB, 200 * GB, 200 * GB, 100.0)
    report = retention.derive(m, 40)
    row = _row("data_retention_days", retention_status=report)
    carried = row["retention"]
    for field in ("free_bytes", "bytes_per_day", "ratio_percent", "budget_bytes",
                  "budget_days", "raw_days", "days", "sentence", "available"):
        assert field in carried, f"the Settings payload omits {field}, so the row cannot explain itself"
    assert carried["days"] == 40
    assert carried["free_bytes"] == 200 * GB
    assert "200 GB free" in carried["sentence"]
    # And the ratio row carries it too, so the number the operator edits is shown beside the
    # number it produced.
    assert _row("data_retention_ratio", retention_status=report)["retention"]["days"] == 40


def test_the_control_is_registered_bounded_and_explained():
    assert "DATA_RETENTION_DAYS" in cc.EDITABLE_KEYS
    assert "DATA_RETENTION_RATIO" in cc.EDITABLE_KEYS
    spec = cc.SETTING_CONTROLS["DATA_RETENTION_DAYS"]
    assert spec["control"] == "auto_number"
    assert (spec["min"], spec["max"], spec["step"]) == (7, 365, 1)
    assert spec["auto_value"] == "auto"
    ratio = cc.SETTING_CONTROLS["DATA_RETENTION_RATIO"]
    assert ratio["control"] == "number"
    assert (ratio["min"], ratio["max"]) == (10, 70)
    help_text = _row("data_retention_days")["help"].lower()
    assert "auto" in help_text and "destructive" in help_text
    assert "merge headroom" in _row("data_retention_ratio")["help"].lower()


def test_the_rows_declare_no_restart_and_state_their_effect():
    days_targets, days_blast = cc._RESTART_FOR["DATA_RETENTION_DAYS"]
    ratio_targets, _ = cc._RESTART_FOR["DATA_RETENTION_RATIO"]
    assert days_targets == () and ratio_targets == (), "retention must not roll a workload"
    assert "free disk" in days_blast and "expires" in days_blast


# ── 4. the startup migration and the schema bootstrap ────────────────────────────────────────


def _create_statement(table: str) -> str:
    """The comment-stripped CREATE TABLE statement for `table`, across the schema files."""
    for path in sorted(SCHEMA.glob("*.sql")):
        body = "\n".join(line.split("--", 1)[0] for line in path.read_text().splitlines())
        match = re.search(
            rf"CREATE TABLE IF NOT EXISTS\s+(?:weirvern\.)?{re.escape(table)}\b.*?;", body, re.S)
        if match:
            return match.group(0)
    raise AssertionError(f"{table} has no CREATE TABLE statement in {SCHEMA}")


def test_the_schema_bootstraps_every_managed_table_at_the_FLOOR():
    """A fresh database has no ingest to measure; the floor is the safe direction."""
    wrong = [t.name for t in retention.RETENTION_TABLES
             if not re.search(rf"TTL\s+{re.escape(t.ttl_expression())}\s*\+\s*INTERVAL\s+7\s+DAY",
                              _create_statement(t.name))]
    assert not wrong, f"these tables are not bootstrapped at the floor: {wrong}"


def test_every_managed_table_really_has_a_ttl_in_its_ddl():
    unbounded = [t.name for t in retention.RETENTION_TABLES
                 if "TTL" not in _create_statement(t.name)]
    assert not unbounded, f"managed tables with no TTL at all: {unbounded}"


def test_the_startup_migration_applies_the_DERIVED_value_to_every_listed_table():
    """Auto on the box: 200 GB free, 40% -> 80 GB; 2 GB/day -> 40 days."""
    ch = FakeCH({t.name: 7 for t in retention.RETENTION_TABLES})
    report = retention.ensure(ch, "auto", 40)
    assert report["ok"] is True, report
    assert report["requested_days"] == 40
    assert report["derivation"]["days"] == 40
    assert len(ch.commands) == len(retention.RETENTION_TABLES)
    for table in retention.RETENTION_TABLES:
        assert (f"ALTER TABLE {table.name} "
                f"MODIFY TTL {table.ttl_expression()} + INTERVAL 40 DAY") in ch.commands
    assert {row["effective_days"] for row in report["tables"]} == {40}


def test_the_migration_is_idempotent_and_leaves_a_correct_table_alone():
    ch = FakeCH({t.name: 40 for t in retention.RETENTION_TABLES})
    report = retention.ensure(ch, "auto", 40)
    assert report["ok"] is True
    assert ch.commands == [], "a table already at the derived TTL was rebuilt anyway"


def test_the_migration_does_nothing_when_auto_cannot_derive_yet():
    ch = FakeCH({t.name: 7 for t in retention.RETENTION_TABLES}, span_days=0.1)
    report = retention.ensure(ch, "auto", 40)
    assert report["applied"] is False
    assert report["requested_days"] is None
    assert ch.commands == [], "an underivable window must not shrink the tables to the floor"
    assert "not derived yet" in report["summary"]


def test_the_migration_honours_an_explicit_setting():
    ch = FakeCH({t.name: 7 for t in retention.RETENTION_TABLES})
    report = retention.ensure(ch, "90", 40)
    assert report["requested_days"] == 90
    assert all(row["effective_days"] == 90 for row in report["tables"])
    assert "INTERVAL 90 DAY" in ch.commands[0]


def test_apply_schema_runs_the_migration_with_the_settings_values(monkeypatch, tmp_path):
    """The schema Job and every worker start go through `apply_schema`."""
    from weirvern import db

    (tmp_path / "001_probe.sql").write_text("CREATE TABLE IF NOT EXISTS probe (ts DateTime);")
    monkeypatch.setattr(db, "SCHEMA_DIR", tmp_path)
    seen: list[tuple] = []
    monkeypatch.setattr(retention, "ensure", lambda client, days=None, ratio=None: (
        seen.append((days, ratio)) or {
            "ok": True, "applied": True, "tables": [], "changed": [], "failed": [],
            "missing": [], "mismatched": [], "summary": "ok", "requested_days": 7}))

    class _Settings:
        clickhouse_db = "weirvern"
        data_retention_days = "auto"
        data_retention_ratio = 55

    class _Client:
        def command(self, sql, parameters=None):  # noqa: ANN001
            return None

    db.apply_schema(_Client(), _Settings())
    assert seen == [("auto", 55)], f"apply_schema did not converge retention: {seen}"


# ── 5. the statement and the read-back ───────────────────────────────────────────────────────


def test_the_alter_statement_is_built_per_table_with_the_right_expression():
    for table in retention.RETENTION_TABLES:
        assert retention.alter_sql(table, 40) == (
            f"ALTER TABLE {table.name} MODIFY TTL {table.ttl_expression()} + INTERVAL 40 DAY")


def test_no_interval_can_exceed_the_derived_window_or_the_cap():
    """THE HARD GUARD: a fallback or a bad parse cannot build a longer interval.

    Asserted at the function that builds the ALTER, not only at its callers, so a future
    code path cannot bypass it by calling `alter_sql` directly.
    """
    table = retention.RETENTION_TABLES[0]
    assert "INTERVAL 39 DAY" in retention.alter_sql(table, 39, max_days=39)
    with pytest.raises(ValueError, match="derived window"):
        retention.alter_sql(table, 40, max_days=39)
    with pytest.raises(ValueError, match="derived window"):
        retention.alter_sql(table, 365, max_days=197)
    # The 365-day cap holds even when no derivation bound is supplied.
    with pytest.raises(ValueError):
        retention.alter_sql(table, 366)

    # And converge refuses before issuing a single ALTER.
    ch = FakeCH({t.name: 7 for t in retention.RETENTION_TABLES})
    with pytest.raises(ValueError, match="derived window"):
        retention.converge(ch, 40, bound_days=39)
    assert ch.commands == []


def test_a_derivation_bounds_the_interval_even_when_the_request_is_longer():
    """The derivation is the bound: 40 days cannot become a 365-day ALTER."""
    m = retention.Measurement("default", 400 * GB, 200 * GB, 200 * GB, 100.0)
    derivation = retention.derive(m, 40)
    assert derivation["days"] == 40
    ch = FakeCH({t.name: 7 for t in retention.RETENTION_TABLES})
    with pytest.raises(ValueError, match="derived window is 40"):
        retention.converge(ch, 365, derivation=derivation, bound_days=365)
    assert ch.commands == []


def test_the_module_only_ever_emits_MODIFY_TTL_statements():
    """LOWERING EXPIRES ROWS; it must never delete a partition out from under the operator.

    Asserted on the DDL the module can produce and on every command `converge` actually
    issues -- not on the prose around it (the docstring says "never DROP PARTITION", and a
    substring search over the source cannot tell a promise from a statement).
    """
    for table in retention.RETENTION_TABLES:
        sql = retention.alter_sql(table, 35).upper()
        assert sql.startswith("ALTER TABLE ")
        assert " MODIFY TTL " in sql
        for forbidden in ("DROP", "TRUNCATE", "DELETE"):
            assert forbidden not in sql, f"alter_sql emitted {forbidden}: {sql}"
    ch = FakeCH({t.name: 7 for t in retention.RETENTION_TABLES})
    retention.converge(ch, 9)
    assert ch.commands, "converge issued no DDL, so this check proved nothing"
    for sql in ch.commands:
        assert sql.startswith("ALTER TABLE ") and " MODIFY TTL " in sql
        assert "DROP" not in sql.upper() and "TRUNCATE" not in sql.upper()


def test_the_read_back_records_the_clusters_effective_ttl():
    ch = FakeCH({t.name: 7 for t in retention.RETENTION_TABLES})
    report = retention.converge(ch, 14)
    assert report["ok"] is True
    row = report["tables"][0]
    assert row["effective_days"] == 14
    assert row["expression"] == f"{row['column']} + INTERVAL 14 DAY"
    assert row["ok"] is True and row["error"] == ""


def test_a_read_back_mismatch_is_reported_rather_than_hidden():
    days = {t.name: 40 for t in retention.RETENTION_TABLES}
    ch = FakeCH(days, ignore={"zeek_http"})
    report = retention.converge(ch, 7)
    assert report["ok"] is False
    assert "zeek_http" in report["mismatched"]
    row = next(r for r in report["tables"] if r["table"] == "zeek_http")
    assert row["effective_days"] == 40, "the report shows what the cluster HAS, not what was asked"
    assert row["ok"] is False
    assert "40 days" in row["error"] and "not 7" in row["error"]
    assert "zeek_http" in report["summary"]


def test_a_failed_alter_names_the_table_and_leaves_the_previous_value_in_place():
    days = {t.name: 40 for t in retention.RETENTION_TABLES}
    ch = FakeCH(days, fail={"flows"})
    report = retention.converge(ch, 7)
    assert report["ok"] is False
    assert "flows" in report["failed"]
    row = next(r for r in report["tables"] if r["table"] == "flows")
    assert row["effective_days"] == 40, "a failed ALTER must not be reported as the new value"
    assert "ACCESS_DENIED" in row["error"]
    other = next(r for r in report["tables"] if r["table"] == "zeek_conn")
    assert other["effective_days"] == 7 and other["ok"] is True


def test_an_unreadable_ttl_emits_no_alter_and_records_the_read_failure():
    """NEVER CHOOSE A VALUE ON FAILURE. An unreadable TTL gets no ALTER at all."""
    days: dict[str, int | None] = {t.name: 40 for t in retention.RETENTION_TABLES}
    days["zeek_ssl"] = None                       # no table-level TTL clause to read
    ch = FakeCH(days)
    report = retention.converge(ch, 7)

    assert not any("zeek_ssl" in sql for sql in ch.commands), \
        "an unreadable TTL was ALTERed to a value nobody derived"
    assert report["ok"] is False
    assert report["unreadable"] == ["zeek_ssl"]
    assert "zeek_ssl" in report["unreadable_reasons"]
    row = next(r for r in report["tables"] if r["table"] == "zeek_ssl")
    assert row["changed"] is False
    assert row["ok"] is False
    assert row["effective_days"] is None, "the receipt must not invent a TTL it could not read"
    assert row["error"].startswith("NOT CHANGED: TTL unreadable")
    assert "NOT CHANGED (TTL unreadable): zeek_ssl" in report["summary"]


def test_a_parse_failure_on_one_table_does_not_stop_the_other_tables():
    """One unreadable table is left alone; the other fifteen are still corrected."""
    days: dict[str, int | None] = {t.name: 40 for t in retention.RETENTION_TABLES}
    days["zeek_notice"] = None
    ch = FakeCH(days)
    report = retention.converge(ch, 9)

    assert len(ch.commands) == len(retention.RETENTION_TABLES) - 1
    assert all("zeek_notice" not in sql for sql in ch.commands)
    assert {row["effective_days"] for row in report["tables"]
            if row["table"] != "zeek_notice"} == {9}
    untouched = next(r for r in report["tables"] if r["table"] == "zeek_notice")
    assert untouched["changed"] is False and untouched["effective_days"] is None
    assert "zeek_ssl" in report["changed"] and "zeek_ssh" in report["changed"]


def test_parse_ttl_reads_day_week_and_month_units():
    assert retention.parse_ttl("... TTL ts + INTERVAL 35 DAY")[0] == 35
    assert retention.parse_ttl("... TTL ts + INTERVAL 5 WEEK")[0] == 35
    assert retention.parse_ttl("... TTL ts + INTERVAL 1 MONTH")[0] == 30
    assert retention.parse_ttl("... ENGINE = MergeTree()")[0] is None
    assert retention.parse_ttl("... TTL ts + INTERVAL 6 HOUR")[0] is None


def test_parse_ttl_reads_the_normalised_form_clickhouse_stores():
    """ClickHouse rewrites `INTERVAL 365 DAY` as `toIntervalDay(365)` in `create_table_query`.

    Reading only the SQL spelling made every table this control had ever touched unreadable,
    which is how a read failure turned into a re-ALTER (and then the 365-day cap) on every
    worker start. Both spellings are the same TTL.
    """
    days, expression = retention.parse_ttl("... TTL ts + toIntervalDay(365)")
    assert days == 365
    assert expression == "ts + toIntervalDay(365)"
    assert retention.parse_ttl("... TTL toDateTime(timestamp) + toIntervalDay(7)")[0] == 7
    assert retention.parse_ttl("... TTL ts + toIntervalWeek(5)")[0] == 35
    assert retention.parse_ttl("... TTL ts + toIntervalMonth(1)")[0] == 30
    assert retention.parse_ttl("... TTL ts + toIntervalHour(6)")[0] is None


# ── 6. destructive marking and the apply path ────────────────────────────────────────────────


def test_lowering_retention_is_marked_destructive_in_the_payload_the_ui_renders():
    lowered = cc.plan({"data_retention_days": "7"},
                      {"DATA_RETENTION_DAYS": "40"}).proposals[0]
    assert lowered.destructive is True
    assert "DESTRUCTIVE" in lowered.warning
    assert "cannot be undone" in lowered.warning
    # And the route echoes it under the caller's key vocabulary, like every other field.
    class _Client:
        def read(self):
            return {"DATA_RETENTION_DAYS": "40"}

    class _Ctx:
        config_client = _Client()

    code, payload = payloads.settings_plan(_Ctx(), {"data_retention_days": "7"})
    assert code == 200
    proposal = payload["proposals"][0]
    assert proposal["key"] == "data_retention_days"
    assert proposal["destructive"] is True
    assert "DESTRUCTIVE" in proposal["warning"]


def test_lowering_against_the_DERIVED_window_is_destructive_even_when_the_stored_value_is_auto():
    """The plan is told what the cluster derived, so auto -> 7 is known to be a cut."""
    lowered = cc.plan({"data_retention_days": "7"},
                      {"DATA_RETENTION_DAYS": "auto"},
                      retention_now_days=40).proposals[0]
    assert lowered.destructive is True
    assert "40 days today" in lowered.warning


def test_raising_retention_is_not_destructive():
    raised = cc.plan({"data_retention_days": "90"},
                     {"DATA_RETENTION_DAYS": "40"}).proposals[0]
    assert raised.destructive is False
    assert raised.warning == ""
    # Switching TO auto is the safe direction and is never treated as a cut.
    to_auto = cc.plan({"data_retention_days": "auto"},
                      {"DATA_RETENTION_DAYS": "7"}).proposals[0]
    assert to_auto.destructive is False


def test_lowering_the_disk_budget_is_destructive_when_retention_is_auto():
    """A smaller share of free space derives a shorter window, which expires rows."""
    proposal = cc.plan({"data_retention_ratio": "10"},
                       {"DATA_RETENTION_DAYS": "auto",
                        "DATA_RETENTION_RATIO": "40"}).proposals[0]
    assert proposal.destructive is True
    assert "DISK BUDGET" in proposal.warning
    assert "cannot be undone" in proposal.warning


def test_lowering_the_disk_budget_is_NOT_destructive_in_manual_mode():
    """In manual mode the ratio only bounds what an override may ask for."""
    proposal = cc.plan({"data_retention_ratio": "10"},
                       {"DATA_RETENTION_DAYS": "30",
                        "DATA_RETENTION_RATIO": "40"}).proposals[0]
    assert proposal.destructive is False
    assert proposal.warning == ""


class _ConfigClient:
    """The ConfigMap writer, with the read-back the real one performs."""

    def __init__(self, data: dict[str, str]) -> None:
        self.data = dict(data)
        self.wrote: dict[str, str] = {}
        self.provenance: dict[str, str] = {}

    def read(self) -> dict[str, str]:
        return dict(self.data)

    def apply(self, changes, *, reason: str = "", by: str = ""):  # noqa: ANN001
        # THE REAL WRITER TRANSLATES ROW KEYS TO CONFIGMAP KEYS, so the fake must too: a
        # fake that writes "data_retention_days" would let a missing translation at the
        # boundary look like a working apply.
        self.wrote = {cc.to_configmap_key(k): str(v) for k, v in changes.items()}
        self.provenance = {"reason": reason, "by": by}
        self.data.update(self.wrote)
        return dict(self.data)

    def restart(self, target: str) -> None:
        raise AssertionError(f"retention must not restart {target}")


def _apply_ctx(data: dict[str, str]) -> Any:
    class _Ctx:
        config_client = _ConfigClient(data)
        settings = None
        backend = None
        user_store = None
        sessions = None

    return _Ctx()


def _connect_to(ch: FakeCH):
    return lambda: _Conn(ch)


def test_the_apply_derives_alters_every_table_and_reports_the_clusters_effective_ttl():
    """END TO END through `payloads.settings_apply`: derive, write, ALTER, read back, record."""
    ch = FakeCH({t.name: 7 for t in retention.RETENTION_TABLES})
    ctx = _apply_ctx({"DATA_RETENTION_DAYS": "auto", "DATA_RETENTION_RATIO": "40"})
    code, payload = payloads.settings_apply(
        ctx, _connect_to(ch), changes={"data_retention_days": "auto"}, confirmed=True,
        reason="re-derive after the disk resize", revert=False, actor="sam")

    assert code == 200, payload
    # The ConfigMap write is not the enforcement: every managed table was ALTERed to the
    # DERIVED value, and the report carries the arithmetic that chose it.
    assert len(ch.commands) == len(retention.RETENTION_TABLES)
    assert payload["retention"]["requested_days"] == 40
    assert payload["retention"]["derivation"]["days"] == 40
    assert payload["retention"]["derivation"]["free_bytes"] == 200 * GB
    assert payload["retention"]["ok"] is True
    assert {row["effective_days"] for row in payload["retention"]["tables"]} == {40}
    assert ctx.config_client.provenance == {"reason": "re-derive after the disk resize",
                                            "by": "sam"}
    assert ch.audit and ch.audit[-1][0] == "weirvern.fleet_audit"


def test_an_explicit_override_above_the_budget_is_refused_before_anything_is_written():
    ch = FakeCH({t.name: 7 for t in retention.RETENTION_TABLES})
    ctx = _apply_ctx({"DATA_RETENTION_DAYS": "auto", "DATA_RETENTION_RATIO": "40"})
    code, payload = payloads.settings_apply(
        ctx, _connect_to(ch), changes={"data_retention_days": "300"}, confirmed=True,
        reason="wants a year", revert=False, actor="sam")
    assert code == 400
    assert "measured budget is 40 day(s)" in payload["error"]
    assert ctx.config_client.wrote == {}, "a refused value must not reach the ConfigMap"
    assert ch.commands == [], "a refused value must not touch a table"


def test_an_explicit_override_inside_the_budget_is_applied_and_read_back():
    ch = FakeCH({t.name: 7 for t in retention.RETENTION_TABLES})
    ctx = _apply_ctx({"DATA_RETENTION_DAYS": "auto", "DATA_RETENTION_RATIO": "40"})
    code, payload = payloads.settings_apply(
        ctx, _connect_to(ch), changes={"data_retention_days": "30"}, confirmed=True,
        reason="keep a month", revert=False, actor="sam")
    assert code == 200, payload
    assert payload["retention"]["requested_days"] == 30
    assert {row["effective_days"] for row in payload["retention"]["tables"]} == {30}
    assert payload["retention"]["derivation"]["mode"] == "manual"
    assert "Manual — 30 days" in payload["retention"]["derivation"]["sentence"]


def test_an_out_of_range_explicit_value_is_refused_without_measuring_the_disk():
    """The value is refused by its own parser, not reported as a measurement failure."""
    ch = FakeCH({t.name: 7 for t in retention.RETENTION_TABLES})
    ctx = _apply_ctx({"DATA_RETENTION_DAYS": "auto", "DATA_RETENTION_RATIO": "40"})
    code, payload = payloads.settings_apply(
        ctx, _connect_to(ch), changes={"data_retention_days": "999"}, confirmed=True,
        reason="a year and a half", revert=False, actor="sam")
    assert code == 400
    assert "between 7 and 365" in payload["error"]
    assert ch.commands == []


def test_the_apply_accepts_the_CONFIGMAP_key_as_well_as_the_row_key():
    """An API caller may send DATA_RETENTION_DAYS; the budget check must still see it.

    Looking up only the row spelling falls back to the CURRENT value, which would skip the
    disk check on exactly the request that needs it.
    """
    ch = FakeCH({t.name: 7 for t in retention.RETENTION_TABLES})
    ctx = _apply_ctx({"DATA_RETENTION_DAYS": "auto", "DATA_RETENTION_RATIO": "40"})
    code, payload = payloads.settings_apply(
        ctx, _connect_to(ch), changes={"DATA_RETENTION_DAYS": "300"}, confirmed=True,
        reason="wants a year", revert=False, actor="sam")
    assert code == 400
    assert "measured budget is 40 day(s)" in payload["error"]


def test_changing_the_RATIO_re_derives_the_tables_without_touching_the_day_count():
    ch = FakeCH({t.name: 40 for t in retention.RETENTION_TABLES})
    ctx = _apply_ctx({"DATA_RETENTION_DAYS": "auto", "DATA_RETENTION_RATIO": "40"})
    code, payload = payloads.settings_apply(
        ctx, _connect_to(ch), changes={"data_retention_ratio": "70"}, confirmed=True,
        reason="the disk was grown", revert=False, actor="sam")
    assert code == 200, payload
    # 200 GB x 70% = 140 GB; at 2 GB/day that is 70 days.
    assert payload["retention"]["requested_days"] == 70
    assert {row["effective_days"] for row in payload["retention"]["tables"]} == {70}


def test_a_destructive_retention_change_without_a_reason_is_refused():
    ch = FakeCH({t.name: 40 for t in retention.RETENTION_TABLES})
    ctx = _apply_ctx({"DATA_RETENTION_DAYS": "auto", "DATA_RETENTION_RATIO": "40"})
    code, payload = payloads.settings_apply(
        ctx, _connect_to(ch), changes={"data_retention_days": "7"}, confirmed=True,
        reason="", revert=False, actor="sam")
    assert code == 400
    assert "destructive" in payload["error"]
    assert "reason is required" in payload["error"]
    assert ch.commands == [], "a refused change must not touch a table"


def test_a_warned_retention_change_still_needs_the_explicit_confirmation():
    ch = FakeCH({t.name: 40 for t in retention.RETENTION_TABLES})
    ctx = _apply_ctx({"DATA_RETENTION_DAYS": "auto", "DATA_RETENTION_RATIO": "40"})
    code, payload = payloads.settings_apply(
        ctx, _connect_to(ch), changes={"data_retention_days": "7"}, confirmed=False,
        reason="trimming", revert=False, actor="sam")
    assert code == 409
    assert payload["needs_confirmation"] is True
    assert payload["proposals"][0]["destructive"] is True


def test_an_apply_that_cannot_reach_clickhouse_still_reports_the_saved_setting():
    """The ConfigMap landed; the cluster was not touched. `ok` must be false, and say why."""
    def _boom():
        raise RuntimeError("clickhouse is unreachable")

    ctx = _apply_ctx({"DATA_RETENTION_DAYS": "auto", "DATA_RETENTION_RATIO": "40"})
    code, payload = payloads.settings_apply(
        ctx, _boom, changes={"data_retention_days": "auto"}, confirmed=True,
        reason="re-derive", revert=False, actor="sam")
    assert code == 200
    assert payload["applied"] == {"data_retention_days": "auto"}
    assert payload["ok"] is False
    assert payload["retention"]["ok"] is False
    assert "could not be read or changed" in payload["retention"]["summary"]


# ── 7. who may change it ──────────────────────────────────────────────────────────────────────


def _viewer_ctx():
    """A deployment with accounts on and a viewer session. The real Flask app is the surface."""
    from weirvern.admin import users as users_mod
    from weirvern.config import Settings

    class _Store:
        def has_users(self) -> bool:
            return True

    class _Sessions:
        def get(self, token: str):
            if token != "viewer-token":
                return None
            return users_mod.Identity(username="val", role=users_mod.ROLE_VIEWER)

    class _Auth:
        enabled = False
        reason = "write access is disabled"

    class _Config:
        """No live ConfigMap in this test: the pod's own Settings are the fallback."""

        def read(self):
            return {}

        def configmap_annotation(self, name: str) -> str:
            return ""

        def settings_drift(self):
            return []

    class _Ctx:
        settings = Settings()
        backend = None
        config_client = _Config()
        user_store = _Store()
        sessions = _Sessions()
        throttle = None
        accounts_note = ""
        capabilities = None
        auth = _Auth()
        connect_factory = staticmethod(lambda settings: _Conn(FakeCH()))

    return _Ctx()


def test_a_viewer_sees_the_retention_value_READ_ONLY():
    from weirvern.admin import flask_app

    app = flask_app.create_app(_viewer_ctx(), secret_key="retention-viewer")
    got = app.test_client().get("/api/settings", headers={"X-Weirvern-Session": "viewer-token"})
    assert got.status_code == 200, got.data
    payload = got.get_json()
    assert payload["writes"]["enabled"] is False
    assert "viewer" in payload["writes"]["reason"]
    row = next(r for rows in payload["groups"].values() for r in rows
               if r["key"] == "data_retention_days")
    assert row["value"] == "auto"
    # The arithmetic still ships, so a viewer sees the derived number without being able to
    # change it; the control renders disabled rather than disappearing.
    assert row["retention"]["days"] == 40
    assert payload["controls"]["data_retention_days"]["auto_value"] == "auto"


def test_a_non_admin_cannot_change_retention():
    """The write gate refuses a viewer BEFORE the body is read -- at the real route."""
    from weirvern.admin import flask_app

    app = flask_app.create_app(_viewer_ctx(), secret_key="retention-viewer")
    replied = app.test_client().post(
        "/api/settings/apply",
        data=json.dumps({"changes": {"data_retention_days": "7"}, "confirmed": True,
                         "reason": "trim it"}),
        content_type="application/json",
        headers={"X-Weirvern-Session": "viewer-token"})
    assert replied.status_code == 403, replied.data
    assert "viewer" in replied.get_json()["error"]


# ── 8. the exclusions ────────────────────────────────────────────────────────────────────────


def test_audit_and_provenance_tables_are_absent_from_the_managed_list():
    """Their retention is a legal/forensic decision, not a data-volume one."""
    managed = set(retention.table_names())
    for table in ("fleet_audit", "schema_versions", "model_actions", "ml_model_cards",
                  "ml_models", "host_watches", "network_scopes"):
        assert table not in managed, f"{table} must never expire on this control"
        assert table in retention.NEVER_EXPIRE, f"{table} is neither managed nor explained"
        assert len(retention.NEVER_EXPIRE[table]) > 20, f"{table}'s exclusion has no reason"


def test_the_unmanaged_list_states_why_each_table_is_not_here():
    managed = set(retention.table_names())
    overlap = managed & set(retention.UNMANAGED)
    assert not overlap, f"tables are both managed and excused: {overlap}"
    thin = [name for name, why in retention.UNMANAGED.items() if len(why.strip()) < 15]
    assert not thin, f"these exclusions have no real reason: {thin}"


def test_every_managed_table_says_why_it_is_on_the_list():
    thin = [t.name for t in retention.RETENTION_TABLES if len(t.why.strip()) < 20]
    assert not thin, f"managed tables with no stated reason: {thin}"


def test_the_ripple_inventory_never_claims_more_history_than_the_derived_window():
    """The per-spec 7/30/60/90 constants describe the DESIGN, not this box's TTL.

    `inventory(retention_days=...)` must cap every claim to what the tables actually keep,
    or the Models card advertises 90 days of identity history on a deployment holding 30.
    """
    from weirvern.models import ripple_evidence

    unscaled = {row["channel"]: row["retention_days"]
                for row in ripple_evidence.inventory()}
    assert unscaled["kerberos_volume"] == 90, "the design constant is still available"

    rows = ripple_evidence.inventory(retention_days=30)
    assert rows
    assert max(row["retention_days"] for row in rows) <= 30
    claims = {row["channel"]: row["retention_days"] for row in rows}
    assert claims["kerberos_volume"] == 30
    assert claims["ntlm_volume"] == 30
    assert claims["smb_file_volume"] == 30
    assert claims["dns_volume"] == 7

    tight = ripple_evidence.inventory(retention_days=3)
    assert all(row["retention_days"] <= 3 for row in tight)
    spec = next(item for item in ripple_evidence.SPECS
                if item.channel == "kerberos_volume")
    assert ripple_evidence.effective_lookback_days(spec, 7, 3) == 3


def test_the_documents_agree_with_the_control():
    """A doc that still promises a fixed 35 days is the retention equivalent of a lie."""
    runbook = (ROOT / "docs" / "runbooks" / "data-retention.md").read_text()
    for table in ("flows", "flows_window", "zeek_conn", "zeek_http", "ml_ripple_evidence"):
        assert f"`{table}`" in runbook, f"{table} is missing from the retention runbook"
    assert "auto" in runbook
    assert "7-365" in runbook or "7–365" in runbook
    assert "40%" in runbook and "70" in runbook
