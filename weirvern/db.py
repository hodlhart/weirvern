"""ClickHouse client wrapper and schema bootstrap.

Lesson: the legacy pod did `CREATE TABLE IF NOT EXISTS` by embedding a giant
YAML-escaped SQL in a configmap, and schema drift caused the "0 baselines"
class of bugs. Schema now lives in a real .sql file under weirvern/schema/,
applied idempotently, and logged in weirvern.schema_versions.

WHY THE SQL LIVES INSIDE THE PACKAGE: the schema is applied by the container
image's own `weirvern init-db` (see k8s/50-schema-job.yaml), so the file must
be present in an installed wheel. It previously sat in a repo-level
`clickhouse/init/` directory, which resolved correctly when running from a
checkout (editable install) and to a non-existent
`site-packages/clickhouse/init` in a real install — verified failing. The schema
Job would then have applied nothing and reported success.
"""
from __future__ import annotations

import logging
import re
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import clickhouse_connect
from clickhouse_connect.driver.client import Client

from weirvern.config import Settings

logger = logging.getLogger(__name__)

# Resolved relative to THIS file, so it is correct in a checkout, in an editable
# install, and in an installed wheel alike.
SCHEMA_DIR = Path(__file__).resolve().parent / "schema"

# Split on top-level semicolons (statements are simple; no quotes-with-semicolons
# are used in the schema files).
_SQL_SPLIT = re.compile(r";\s*$", re.MULTILINE)


def connect(settings: Settings, retries: int = 30, delay_s: float = 5.0) -> Client:
    """Connect with retry (ClickHouse takes longer than the worker to boot).

    Two-phase: bind to `default` and CREATE DATABASE if missing, then return a
    client bound to the weirvern database. Verified failure mode on a fresh
    volume: binding straight to a non-existent database raises UNKNOWN_DATABASE
    for every retry, so the worker died before apply_schema() could create it.
    """
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            bootstrap = clickhouse_connect.get_client(
                host=settings.clickhouse_host,
                port=settings.clickhouse_port,
                username=settings.clickhouse_user,
                password=settings.clickhouse_password,
                database="default",
            )
            bootstrap.command(f"CREATE DATABASE IF NOT EXISTS {settings.clickhouse_db}")
            bootstrap.close()
            client = clickhouse_connect.get_client(
                host=settings.clickhouse_host,
                port=settings.clickhouse_port,
                username=settings.clickhouse_user,
                password=settings.clickhouse_password,
                database=settings.clickhouse_db,
            )
            client.command("SELECT 1")
            return client
        except Exception as exc:  # noqa: BLE001 - retry loop catches everything
            last_err = exc
            if attempt % 5 == 4:
                logger.warning("ClickHouse connection attempt %d/%d failed: %s", attempt + 1, retries, exc)
            time.sleep(delay_s)
    raise RuntimeError(f"Could not connect to ClickHouse at {settings.http_url}: {last_err}")


def apply_schema(client: Client, settings: Settings) -> None:
    """Apply every *.sql file in SCHEMA_DIR idempotently (IF NOT EXISTS everywhere).

    Raises if there is nothing to apply. A schema directory that is empty or
    missing must be a loud failure: the previous behaviour globbed zero files,
    applied nothing, and returned successfully, so the schema Job would report
    completion while creating not a single table — verified against a
    non-editable install, where the path resolved outside the package.
    """
    client.command(f"CREATE DATABASE IF NOT EXISTS {settings.clickhouse_db}")

    if not SCHEMA_DIR.is_dir():
        raise RuntimeError(
            f"schema directory not found: {SCHEMA_DIR}. The packaged .sql files "
            f"are missing from this installation, so no tables can be created."
        )
    sql_files = sorted(SCHEMA_DIR.glob("*.sql"))
    if not sql_files:
        raise RuntimeError(
            f"no *.sql files in {SCHEMA_DIR}; refusing to report success without "
            f"applying a schema."
        )

    applied = []
    failures: list[tuple[str, str]] = []
    for sql_path in sql_files:
        statements = [s.strip() for s in _SQL_SPLIT.split(sql_path.read_text()) if s.strip()]
        for stmt in statements:
            # Statements are idempotent (CREATE IF NOT EXISTS); still skip VIEWs
            # that already exist without erroring on the `CREATE VIEW IF NOT EXISTS`.
            try:
                client.command(stmt)
            except Exception as exc:  # noqa: BLE001
                if "already exists" in str(exc).lower():
                    continue
                first_line = stmt.splitlines()[0][:90]
                failures.append((first_line, str(exc)[:200]))
                logger.warning("Schema statement failed: %s\n  %s", first_line, exc)
        applied.append(sql_path.name)

    # Fail loudly if ANY statement failed, for the same reason an empty schema
    # directory is fatal: this function previously logged and continued past every
    # error, so a schema that created zero tables returned successfully and
    # `weirvern init-db` printed "schema applied — N objects" from whatever it
    # found. The schema Job then reported Completed with an empty database.
    # A schema bootstrap that cannot say "I failed" is worse than one that crashes.
    if failures:
        detail = "; ".join(f"{stmt}: {err}" for stmt, err in failures[:3])
        raise RuntimeError(
            f"{len(failures)} schema statement(s) failed; refusing to report "
            f"success. First failures: {detail}"
        )

    logger.info("Applied schema files: %s", ", ".join(applied))
    try:
        client.command(
            "INSERT INTO weirvern.schema_versions (applied_at, version) VALUES (now(), %s)",
            parameters=[f"v0.1-{','.join(applied)}"],
        )
    except Exception:  # noqa: BLE001
        logger.warning("Could not record schema version (table may not exist yet after first run)")


def fetch_rows(client: Client, query: str, **params) -> Sequence[Sequence[Any]]:
    """Run a query and return raw rows. Queries must qualify tables with
    `weirvern.` (client is bound to the weirvern database)."""
    return client.query(query, parameters=params).result_rows


def fetch_rows_named(client: Client, query: str, **params) -> tuple[list[str], Sequence[Sequence[Any]]]:
    """Run a query and return (column_names, rows). Prefer over positional
    column assumptions — schema order drift silently corrupts dict(zip(...))
    mappings (a lesson from the legacy positional configmaps)."""
    result = client.query(query, parameters=params)
    return list(result.column_names), result.result_rows
