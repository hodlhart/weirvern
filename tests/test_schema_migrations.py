"""Schema migrations must actually reach an existing database.

WHY THIS FILE EXISTS.

The ATT&CK columns were added to the `netflow_anomalies` CREATE TABLE in 001_weirvern.sql.
That is where the column list belongs, and on the deployed system it did nothing at all:

    ClickHouse exception, code: 47
    Unknown expression identifier `attack_techniques` in
    SELECT attack_techniques FROM weirvern.netflow_anomalies

`apply_schema` does run every *.sql file on every start, but `CREATE TABLE IF NOT EXISTS` is a
no-op once the table exists -- so editing a column list is invisible on any database that
already has the table. The failure is precisely inverted by deployment age: a fresh install
gets the column, an upgrade silently does not, and the code that reads it fails at runtime on
the customer's box rather than in the developer's build.

The general rule this pins: **a column added to an existing table needs a numbered migration
that ALTERs, in addition to the DDL edit.** These tests check that rule mechanically, so the
next person to add a column cannot skip it by not knowing about it.
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

SCHEMA = Path(__file__).resolve().parents[1] / "weirvern" / "schema"


def _files() -> dict[str, str]:
    return {p.name: p.read_text() for p in sorted(SCHEMA.glob("*.sql"))}


# ── the specific regression ─────────────────────────────────────────────────────

def test_an_alter_migration_exists_for_the_attack_columns():
    """The exact defect that was measured on the deployed cluster."""
    sql = _files()
    alters = "\n".join(v for k, v in sql.items() if k.startswith("005_"))
    assert alters, "no 005_ migration exists"
    for column in ("attack_techniques", "attack_label"):
        assert re.search(rf"ADD COLUMN IF NOT EXISTS\s+{column}\b", alters), (
            f"{column} was added to the CREATE TABLE but no migration ALTERs it, so an "
            f"existing deployment never gets the column"
        )


def test_migrations_are_idempotent():
    """apply_schema runs EVERY file on EVERY start, and the schema Job runs on every deploy.
    A non-idempotent ALTER would fail the second time and, worse, could fail the schema Job."""
    for name, sql in _files().items():
        if not name.startswith(("004_", "005_", "006_")):
            continue
        for stmt in re.findall(r"ALTER TABLE[^;]*;", sql):
            assert "IF NOT EXISTS" in stmt or "IF EXISTS" in stmt, (
                f"{name} has a non-idempotent ALTER: {stmt.strip()[:80]}...\n"
                f"apply_schema re-runs every file, so this would fail on the second start"
            )


def test_every_schema_file_parses_into_complete_statements():
    """The splitter is `;` at end of line. A statement without a trailing semicolon is silently
    dropped by some drivers or concatenated with the next one, and the error surfaces as an
    unrelated syntax complaint."""
    for name, sql in _files().items():
        code = "\n".join(ln.split("--")[0] for ln in sql.splitlines())
        statements = [s.strip() for s in code.split(";") if s.strip()]
        assert statements, f"{name} contains no statements"
        for stmt in statements:
            head = stmt.split()[0].upper()
            assert head in {
                "CREATE", "ALTER", "INSERT", "DROP", "SET", "SELECT", "OPTIMIZE", "RENAME",
            }, f"{name} has an unexpected statement head {head!r}"


# ── the general rule, stated once ───────────────────────────────────────────────

def test_every_column_read_by_the_worker_is_created_somewhere():
    """A column the code SELECTs must exist in a CREATE TABLE or an ALTER migration. This is
    the check that would have caught the ATT&CK defect before it reached the cluster: the
    worker inserted attack_techniques while no ALTER created it on an existing database.

    Bounded to the anomaly table, which is the one this pattern has actually bitten.
    """
    created = set()
    for sql in _files().values():
        for m in re.finditer(
            r"(?:CREATE TABLE IF NOT EXISTS|ADD COLUMN IF NOT EXISTS)\s+(?:\w+\.)?(\w+)", sql
        ):
            created.add(m.group(1))
    assert "attack_techniques" in created
    assert "attack_label" in created

    worker = (Path(__file__).resolve().parents[1] / "weirvern" / "worker.py").read_text()
    assert "netflow_anomalies" in worker, "the worker no longer writes the anomaly table"
    # The column must actually be READ by the worker, not merely mentioned: if the insert no
    # longer carries it, the migration is adding a column nothing populates.
    # Target the ANOMALY INSERT specifically. Two earlier versions of this line looked at the
    # wrong statement -- first the ml_models insert (the first `client.insert` in the file),
    # then a SELECT against netflow_anomalies -- and so failed while asserting nothing about
    # the insert at all. Anchoring on the full insert call is what makes the check real.
    # The column LIST is now a module-level tuple (_ANOMALY_COLUMNS) so the row/column arity can
    # be checked at the insert site. Follow it: the point of this assertion is that the column is
    # actually POPULATED, not that its name appears in a particular window of text.
    cols_start = worker.index("_ANOMALY_COLUMNS")
    cols_end = worker.index(")", cols_start)
    assert "attack_techniques" in worker[cols_start:cols_end], (
        "the worker does not pass attack_techniques on the anomaly insert, so the column would "
        "always hold its default and the migration would be pointless"
    )
    assert "attack_label" in worker[cols_start:cols_end]

    # AND THE OTHER HALF, which nothing checked before and which is how the two drifted: the ROW
    # must supply a value for every column name. Asserting only that the name appears let the row
    # fall two values short, so every insert raised ProgrammingError inside the worker loop -- a
    # total detection outage that the status page reported as a quiet network.
    # Count with the AST, not a regex over text: the row literal contains nested calls
    # (json.dumps(...), datetime.now()) and a comma-split cannot tell an argument separator from
    # an element separator. An off-by-one here would make this guard lie in the quiet direction.
    tree = ast.parse(worker)
    n_values = None
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "append" and node.args
                and isinstance(node.args[0], ast.List)):
            n_values = len(node.args[0].elts)
    assert n_values is not None, "could not find the anomaly row literal"
    n_columns = len(re.findall(r'"([a-z_]+)"', worker[cols_start:cols_end]))
    assert n_values == n_columns, (
        f"the anomaly insert writes {n_values} values against {n_columns} column names; "
        "a positional INSERT must agree in length and order or every insert raises"
    )


def test_the_original_table_definition_stays_in_step_with_the_migration():
    """A fresh install must get the right column list from the CREATE TABLE, and an upgrade
    must get it from the ALTER. If the two drift, the two kinds of deployment diverge -- which
    is the same class of bug as the one this file was written for, one level up."""
    base = _files()["001_weirvern.sql"]
    create = re.search(
        r"CREATE TABLE IF NOT EXISTS netflow_anomalies\s*\((.*?)\n\)\s*ENGINE", base, re.S
    )
    assert create, "netflow_anomalies CREATE TABLE not found"
    table_body = create.group(1)
    for column in ("attack_techniques", "attack_label"):
        assert re.search(rf"^\s*{column}\s", table_body, re.M), (
            f"{column} is missing from the CREATE TABLE, so a FRESH install would not have "
            f"it even though the migration would add it to an existing one"
        )


def test_the_migration_records_its_version():
    """Without this an operator cannot tell which schema state a deployment is in -- and the
    whole point of a migration is to be able to answer that question."""
    sql = _files()["005_attack_techniques.sql"]
    assert "schema_versions" in sql, "the migration does not record itself"
    assert "005_attack_techniques" in sql


def test_alter_targets_are_fully_qualified():
    """`apply_schema` connects with a default database, but an ALTER relying on that default
    breaks the moment the Job or a CLI runs with a different one -- and the failure is
    "unknown table", which reads like the table is missing rather than mis-scoped."""
    for name, sql in _files().items():
        for stmt in re.findall(r"ALTER TABLE\s+(\S+)", sql):
            assert "." in stmt, f"{name} ALTERs an unqualified table name: {stmt}"
