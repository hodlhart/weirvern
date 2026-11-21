"""The sink's AGE is the measurement that names a dead ingest.

THE DEFECT (measured 2026-11-21). NetFlow ingest stopped at 2026-11-20 23:33 and nothing said
so for eighteen hours. Every surface was self-consistent: goflow2 stayed Ready because its
liveness probe is its own /metrics endpoint; the ingester logged `Ingested 0 flow records` on
every pass; and the detection sweep logged that it had examined nothing. Each line described a
component's own last action, and none of them was the age of the data.

These tests pin the four things that make the guard real:

  * a fresh row is FRESH, and a row older than one detection bucket is STALLED -- the two are
    different states with different remedies;
  * an empty table is NO_DATA, not "stalled" and not "fine";
  * a read that fails is UNREADABLE (`ok is None`), never a pass;
  * the worker emits ERROR while stalled and WARNING on recovery, and Health carries the same
    measurement under a named probe.
"""
from __future__ import annotations

import inspect
import logging

import pytest

from weirvern import ingest_freshness as freshness
from weirvern.admin import status as status_mod


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    """Answers the one aggregate `measure` sends; anything else is a test bug."""

    def __init__(self, row=None, *, error: Exception | None = None):
        self.row = row
        self.error = error
        self.sql: list[str] = []

    def query(self, sql, parameters=None):  # noqa: ANN001, ANN201
        self.sql.append(sql)
        if self.error is not None:
            raise self.error
        return _Result([self.row])


# ── the decision table ───────────────────────────────────────────────────────────────────────

def test_a_recent_row_is_fresh():
    verdict = freshness.classify(42.0, 300.0, rows=759_000,
                                 newest="2026-11-21 17:53:10.436")
    assert verdict.state == freshness.FRESH
    assert verdict.ok is True
    assert "42s old" in verdict.detail()
    assert "advancing" in verdict.detail()


def test_a_row_older_than_one_bucket_is_stalled_and_says_the_age():
    verdict = freshness.classify(64_800.0, 300.0, rows=759_000)
    assert verdict.state == freshness.STALLED
    assert verdict.ok is False
    assert "18.0h old" in verdict.detail()
    # THE REMEDY IS IN THE SENTENCE, not left to the reader.
    assert "INGEST HAS STOPPED" in verdict.detail()
    assert "goflow2" in verdict.detail() and "ds/zeek -c tap" in verdict.detail()


def test_an_empty_table_is_no_data_not_a_stall():
    """"Nothing has ever arrived" and "it stopped arriving" are different faults."""
    verdict = freshness.classify(None, 300.0, rows=0)
    assert verdict.state == freshness.NO_DATA
    assert verdict.ok is False
    assert "no flow has ever been ingested" in verdict.detail()


def test_a_boundary_reading_is_fresh_not_stalled():
    verdict = freshness.classify(300.0, 300.0, rows=10)
    assert verdict.state == freshness.FRESH


def test_a_read_error_is_undecidable_and_never_a_pass():
    verdict = freshness.measure(_Client(error=RuntimeError("table does not exist")))
    assert verdict.state == freshness.UNREADABLE
    assert verdict.ok is None, "an unreadable sink is not evidence of health"
    assert "table does not exist" in verdict.detail()


# ── the measurement ──────────────────────────────────────────────────────────────────────────

def test_measure_reads_one_aggregate_and_keeps_clickhouses_age():
    client = _Client((759_027, "2026-11-21 17:53:10.436", 42))
    verdict = freshness.measure(client)
    assert verdict.state == freshness.FRESH
    assert verdict.age_s == 42.0
    assert verdict.rows == 759_027
    assert verdict.newest == "2026-11-21 17:53:10.436"
    # ONE query, over the raw sink: not a window scan, and not a count that grows with history.
    assert len(client.sql) == 1
    assert "FROM weirvern.flows" in client.sql[0]
    assert "dateDiff" in client.sql[0]


# ── the worker's line ───────────────────────────────────────────────────────────────────────

def test_the_worker_line_is_error_while_stalled(caplog):
    verdict = freshness.classify(64_800.0, 300.0, rows=100)
    with caplog.at_level(logging.INFO, logger="weirvern.ingest_freshness"):
        carried = freshness.log_verdict(verdict, True)
    assert carried is False
    records = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert records, "a stalled ingest must be an ERROR, not an INFO among ingest passes"
    assert "FLOW INGEST STALLED" in records[-1].getMessage()
    assert "18.0h" in records[-1].getMessage()


def test_recovery_is_a_warning_an_operator_can_find(caplog):
    verdict = freshness.classify(12.0, 300.0, rows=100)
    with caplog.at_level(logging.INFO, logger="weirvern.ingest_freshness"):
        carried = freshness.log_verdict(verdict, False)
    assert carried is True
    levels = [r.levelno for r in caplog.records]
    assert logging.WARNING in levels and logging.ERROR not in levels
    assert any("RECOVERED" in r.getMessage() for r in caplog.records)


def test_a_fresh_cycle_is_info_not_silence(caplog):
    verdict = freshness.classify(12.0, 300.0, rows=100)
    with caplog.at_level(logging.INFO, logger="weirvern.ingest_freshness"):
        freshness.log_verdict(verdict, True)
    assert [r.levelno for r in caplog.records] == [logging.INFO]
    assert "Flow ingest fresh" in caplog.records[0].getMessage()


# ── the two surfaces are wired, not merely available ────────────────────────────────────────

def test_the_health_probe_carries_the_verdict():
    probe = status_mod._ingest_freshness_probe(_Client((10, "2026-11-21 17:53:10", 240)))
    assert probe.name == "ingest_freshness"
    assert probe.ok is True
    assert probe.value["state"] == freshness.FRESH
    assert probe.value["age_s"] == 240.0


def test_collect_health_registers_the_flow_ingest_probe():
    source = inspect.getsource(status_mod.collect_health)
    assert "_ingest_freshness_probe(client)" in source, (
        "the freshness probe exists but Health never runs it")


def test_the_worker_runs_the_shared_measurement_every_cycle():
    from weirvern import worker  # noqa: PLC0415 - the import is the assertion

    source = inspect.getsource(worker.main)
    assert "ingest_freshness.log_verdict(" in source
    assert "ingest_freshness.measure(" in source
    # It must sit in the CYCLE, ahead of the sweep, or a stalled sink is only noticed when a
    # detector happens to look.
    assert source.index("ingest_freshness.log_verdict") < source.index(
        "detection_sweep(client, detectors, settings, cfg)")


@pytest.mark.parametrize("state,expected", [
    (freshness.FRESH, True), (freshness.STALLED, False),
    (freshness.NO_DATA, False), (freshness.UNREADABLE, None),
])
def test_ok_is_tristate(state, expected):
    verdict = freshness.Freshness(state=state, limit_s=300.0)
    assert verdict.ok is expected
