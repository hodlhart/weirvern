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


def test_apply_schema_continues_past_a_failing_statement(monkeypatch, tmp_path):
    """One bad statement must not abandon the remaining tables — a partially
    created schema is worse than a logged warning."""
    class OneFail(FakeCH):
        def command(self, sql, **kwargs):
            self.commands.append(sql)
            if "bad" in sql:
                raise RuntimeError("syntax error near 'bad'")

    fake = OneFail()
    _apply(monkeypatch, tmp_path, fake, {"001_test.sql": (
        "CREATE TABLE IF NOT EXISTS bad (x Int8);\n"
        "CREATE TABLE IF NOT EXISTS good (y Int8);\n"
    )})
    assert any("good" in c for c in fake.commands)
