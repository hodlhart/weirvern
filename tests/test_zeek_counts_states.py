"""A zero in the Zeek panel must say WHY it is zero.

WHY THIS FILE EXISTS. The user reported "the zeek dashboard is not fully populating". The
dashboard was telling the truth and looked broken anyway, which is the failure this file prevents.

Measured on the deployment: `zeek_http` held 389 rows, `zeek_ssh` 188 and `zeek_files` 378, but
none of them inside the default 24-hour window -- their newest rows were ~40 hours old. The
panel showed `0` for each and gave no indication that rows existed at all, so a wall of zeros
read as "the ingester is broken" when the real state was "this segment produced no HTTP in the
last day". Those need different responses from an operator and must not look the same.

The three states a count can be in:

  active         rows in the window
  idle           rows exist, but none in the window  -> widen the window
  empty-forever  no row has EVER landed             -> a policy or analyzer question

Only the third is worth investigating as a defect, and before this change all three rendered as
an identical `0`.
"""

from __future__ import annotations

import inspect
from pathlib import Path

from weirvern.admin import soc

WEB = Path(__file__).resolve().parent.parent / "weirvern" / "admin" / "web"
SOC_JS = (WEB / "soc.js").read_text()


class _Row(tuple):
    pass


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    """Answers zeek_counts' query with a chosen (in_window, total, last_ts) triple."""

    def __init__(self, per_table):
        self.per_table = per_table
        self.seen_sql: list[str] = []

    def query(self, sql, parameters=None):
        self.seen_sql.append(sql)
        for table, triple in self.per_table.items():
            if f"weirvern.{table}" in sql:
                return _Result([triple])
        return _Result([(0, 0, None)])


def _counts(per_table, hours=24):
    return soc.zeek_counts(_Client(per_table), hours=hours)


# ── the three states ───────────────────────────────────────────────────────────────────────


def test_a_log_with_rows_only_outside_the_window_is_reported_idle_not_empty():
    """This is the exact case that made the dashboard look broken."""
    import datetime

    last = datetime.datetime(2026, 1, 1, 12, 0, 0)
    d = _counts({"zeek_http": (0, 389, last)})
    row = next(p for p in d["points"] if p["log"] == "http")
    assert row["rows"] == 0, "the in-window count must stay honest"
    assert row["total"] == 389, "the all-time total must be available, or zero is unreadable"
    assert row["state"] == "idle", (
        f"a log with rows but none in the window is 'idle', not 'empty'; got {row['state']!r}"
    )
    assert row["last_ts"].startswith("2026-01-01"), "when it was last written must be reported"


def test_a_log_that_never_produced_a_row_is_reported_empty_forever():
    """A different fact from a quiet window, and the only one worth investigating as a defect."""
    d = _counts({"zeek_ntlm": (0, 0, None)})
    row = next(p for p in d["points"] if p["log"] == "ntlm")
    assert row["state"] == "empty-forever"
    assert row["total"] == 0
    assert row["last_ts"] == ""


def test_a_log_with_rows_in_the_window_is_reported_active():
    import datetime

    d = _counts({"zeek_conn": (45373, 65443, datetime.datetime(2026, 1, 2, 3, 0, 0))})
    row = next(p for p in d["points"] if p["log"] == "conn")
    assert row["state"] == "active"
    assert row["rows"] == 45373


def test_the_count_query_gets_all_three_numbers_in_one_pass():
    """One query per log, not three: the panel asks about eighteen logs on every load."""
    client = _Client({"zeek_http": (0, 389, None)})
    soc.zeek_counts(client, hours=24)
    # One query per entry in ZEEK_LOGS.
    assert len(client.seen_sql) == len(soc.ZEEK_LOGS), (
        f"expected one query per log, got {len(client.seen_sql)}"
    )
    # And each must select all three facts.
    for sql in client.seen_sql:
        for col in ("in_window", "total", "last_ts"):
            assert col in sql, f"the count query does not select {col!r}: {sql[:120]}"


# ── the view must state it ─────────────────────────────────────────────────────────────────


def test_the_view_explains_idle_and_never_written_logs_separately():
    """The data is only useful if the panel says it out loud."""
    code = SOC_JS
    # It must distinguish the two kinds of zero.
    assert "idle" not in code or "total" in code, (
        "soc.js reads the counts without using the total, so it cannot tell the states apart"
    )
    assert "recorded nothing in this window but" in code, (
        "soc.js does not explain logs that are idle: a zero with no explanation is the bug"
    )
    assert "NEVER produced a row" in code, (
        "soc.js does not distinguish 'never produced a row' from 'quiet window'"
    )
    # And it must offer the remedy for the idle case rather than leaving the reader stuck.
    assert "widen the window" in code, (
        "the idle message does not tell the operator what to do about it"
    )


def test_the_backend_defines_the_state_words_so_consumers_cannot_drift():
    """The state is computed server-side; the browser reads it rather than re-deriving it."""
    src = inspect.getsource(soc.zeek_counts)
    for state in ("empty-forever", "idle", "active"):
        assert state in src, (
            f"zeek_counts does not emit the {state!r} state. Computing it in the browser instead "
            f"would let every consumer describe the same log differently."
        )
    # The panel must use the shipped word.
    assert 'p.state' in SOC_JS or "state" in SOC_JS
