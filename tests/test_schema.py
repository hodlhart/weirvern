"""Schema delivery tests.

These guard the failure that made a container deployment create zero tables:
the schema used to live outside the package, so an installed (non-editable)
wheel resolved SCHEMA_DIR to a non-existent path and apply_schema() silently
applied nothing while reporting success.

The important property is not just "the file exists" but "the code refuses to
claim success when it does not".
"""
from pathlib import Path

import pytest

from weirvern import db


class FakeCH:
    """Records commands so we can assert what would have been executed."""

    def __init__(self):
        self.commands: list[str] = []
        self.params: list = []

    def command(self, sql, **kwargs):
        self.commands.append(sql)
        self.params.append(kwargs.get("parameters"))


class FakeSettings:
    clickhouse_db = "weirvern"


def _apply(monkeypatch, tmp_path, client, files: dict[str, str] | None = None):
    """Point SCHEMA_DIR at a temp dir and run apply_schema.

    The fakes stand in for the clickhouse-connect Client and the real Settings;
    both are only used for `.command()` and `.clickhouse_db` here. They are cast
    rather than typed because a test double is not a Client, and pretending
    otherwise would require a full mock of an external library.
    """
    from typing import Any, cast

    monkeypatch.setattr(db, "SCHEMA_DIR", tmp_path)
    for name, text in (files or {}).items():
        (tmp_path / name).write_text(text)
    db.apply_schema(cast(Any, client), cast(Any, FakeSettings()))


# --- the packaged schema exists ----------------------------------------------
def test_schema_dir_is_inside_the_package():
    """SCHEMA_DIR must resolve inside the weirvern package, not to a repo-level
    directory. A repo-level path works in a checkout and breaks in a wheel,
    which is exactly how the silent-empty-schema bug reached a container."""
    package_root = Path(db.__file__).resolve().parent
    assert db.SCHEMA_DIR == package_root / "schema"  # noqa: SIM300 - reads better this way
    assert package_root in db.SCHEMA_DIR.parents


def test_schema_file_is_present_and_non_trivial():
    files = sorted(db.SCHEMA_DIR.glob("*.sql"))
    assert files, f"no .sql files in {db.SCHEMA_DIR}"
    text = files[0].read_text()
    # Sanity floor: an empty or truncated schema would "apply" successfully.
    assert len(text) > 5000, "schema looks truncated"
    assert "CREATE TABLE" in text
    assert "IF NOT EXISTS" in text, "schema must be idempotent for re-application"


def test_schema_is_declared_as_package_data():
    """Without the package-data declaration the .sql file is absent from an
    installed wheel even though it sits inside the package directory."""
    root = Path(__file__).resolve().parents[1]
    pyproject = (root / "pyproject.toml").read_text()
    assert "[tool.setuptools.package-data]" in pyproject
    assert "schema/*.sql" in pyproject, (
        "the schema is not declared as package data, so it will be missing from "
        "an installed wheel"
    )


# --- apply_schema refuses to report a false success --------------------------
def test_apply_schema_raises_when_dir_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(db, "SCHEMA_DIR", tmp_path / "nope")
    with pytest.raises(RuntimeError, match="schema directory not found"):
        db.apply_schema(FakeCH(), FakeSettings())


def test_apply_schema_raises_when_dir_empty(monkeypatch, tmp_path):
    """An empty directory is the exact shape of the original bug: zero files,
    zero tables, but a successful return."""
    monkeypatch.setattr(db, "SCHEMA_DIR", tmp_path)
    with pytest.raises(RuntimeError, match=r"no \*\.sql files"):  # * is literal in the message
        db.apply_schema(FakeCH(), FakeSettings())


def test_apply_schema_creates_database_before_anything_else(monkeypatch, tmp_path):
    """On a fresh volume the database does not exist, so the CREATE DATABASE must
    be the first statement or everything after it fails with UNKNOWN_DATABASE."""
    fake = FakeCH()
    _apply(monkeypatch, tmp_path, fake,
           {"001_test.sql": "CREATE TABLE IF NOT EXISTS t (a Int8);\n"})
    assert fake.commands[0].startswith("CREATE DATABASE IF NOT EXISTS")


def test_apply_schema_executes_statements_from_the_file(monkeypatch, tmp_path):
    fake = FakeCH()
    _apply(monkeypatch, tmp_path, fake, {"001_test.sql": (
        "CREATE TABLE IF NOT EXISTS a (x Int8);\n"
        "CREATE TABLE IF NOT EXISTS b (y Int8);\n"
    )})
    joined = "\n".join(fake.commands)
    assert "CREATE TABLE IF NOT EXISTS a" in joined
    assert "CREATE TABLE IF NOT EXISTS b" in joined


def test_apply_schema_tolerates_already_exists(monkeypatch, tmp_path):
    """Re-applying must be safe: the schema Job runs against a live database."""
    class Exists(FakeCH):
        def command(self, sql, **kwargs):
            self.commands.append(sql)
            if "CREATE VIEW" in sql:
                raise RuntimeError("Table v already exists")

    # must not raise
    _apply(monkeypatch, tmp_path, Exists(),
           {"001_test.sql": "CREATE VIEW IF NOT EXISTS v AS SELECT 1;\n"})


def test_apply_schema_records_a_version(monkeypatch, tmp_path):
    fake = FakeCH()
    _apply(monkeypatch, tmp_path, fake,
           {"001_test.sql": "CREATE TABLE IF NOT EXISTS t (a Int8);\n"})
    assert any("schema_versions" in c for c in fake.commands)


def test_apply_schema_fails_loudly_when_a_statement_fails(monkeypatch, tmp_path):
    """THE BUG: apply_schema used to log and CONTINUE past every failed
    statement, so a schema that created nothing returned successfully and
    `weirvern init-db` printed 'schema applied — N objects' from whatever tables
    happened to exist. The schema Job then reported Completed against an empty
    database.

    A schema bootstrap that cannot say "I failed" is worse than one that crashes.
    """
    class OneFail(FakeCH):
        def command(self, sql, **kwargs):
            self.commands.append(sql)
            if "bad" in sql:
                raise RuntimeError("syntax error near 'bad'")

    fake = OneFail()
    with pytest.raises(RuntimeError, match=r"schema statement\(s\) failed"):
        _apply(monkeypatch, tmp_path, fake, {"001_test.sql": (
            "CREATE TABLE IF NOT EXISTS bad (x Int8);\n"
            "CREATE TABLE IF NOT EXISTS good (y Int8);\n"
        )})
    # One bad statement must not abandon the rest: apply what we can, then report.
    assert any("good" in c for c in fake.commands), (
        "remaining statements must still be attempted before failing"
    )


def test_a_comment_line_ending_in_a_semicolon_does_not_split_a_statement():
    """REGRESSION, measured on the box 2026-10-16: schema/018's comment line ended in a
    semicolon, and the splitter -- which cut BEFORE comments were stripped -- broke the CREATE
    TABLE mid-column-list. ClickHouse answered code 62, apply_schema refused to report success,
    and the worker crash-looped: a comment, taking down a deploy. Comments are stripped first
    now, through one shared helper; this pins the order."""
    from weirvern.db import split_sql_statements

    text = (
        "CREATE TABLE IF NOT EXISTS t\n(\n    a String,\n"
        "    -- the version;\n"
        "    b DateTime DEFAULT now()\n)\nENGINE = ReplacingMergeTree(b)\nORDER BY a;\n"
        "-- trailing comment;\n"
    )
    statements = split_sql_statements(text)
    assert len(statements) == 1, statements
    assert "a String" in statements[0] and "b DateTime" in statements[0], (
        "the comment's semicolon split the statement")
    assert "--" not in statements[0]

def test_a_hostile_database_name_is_refused_before_it_reaches_SQL():
    """Issue #29: CLICKHOUSE_DB was interpolated into DDL unvalidated, unlike the identifiers
    around it. A hostile value must die at the boundary, with the setting named."""
    for bad in ("weirvern; DROP TABLE x", "weirvern`", "1weirvern", "", "wei vern",
                "weirvern) --", "weirvern'"):
        with pytest.raises(ValueError) as ei:
            db.validated_db_name(bad)
        assert "CLICKHOUSE_DB" in str(ei.value), f"{bad!r} was refused without naming the setting"
    assert db.validated_db_name("weirvern") == "weirvern"
    assert db.validated_db_name("w_2") == "w_2"


def test_connect_validates_the_name_BEFORE_any_network_call(monkeypatch):
    """The connect path builds a bootstrap client FIRST; the validation must happen before
    that, or a misconfigured value is already on the wire. Measured by making the client
    factory explode: a ValueError proves the order."""
    from types import SimpleNamespace

    def _boom(*a, **kw):
        raise AssertionError("the client factory was reached before validating the name")

    monkeypatch.setattr(db.clickhouse_connect, "get_client", _boom)
    settings = SimpleNamespace(clickhouse_host="127.0.0.1", clickhouse_port=8123,
                               clickhouse_user="u", clickhouse_password="p",
                               clickhouse_db="bad; DROP", http_url="http://example.invalid")
    with pytest.raises(ValueError):
        db.connect(settings, retries=1, delay_s=0)
