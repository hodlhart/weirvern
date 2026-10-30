"""The episode writer's SQL shape and insert arity, without a live ClickHouse."""
from __future__ import annotations

from datetime import datetime, timedelta

from weirvern.config import Settings
from weirvern.episodes import EPISODE_COLUMNS, refresh

BASE = datetime(2026, 10, 30, 0, 0, 0)


class Result:
    def __init__(self, columns, rows):
        self.column_names = columns
        self.result_rows = rows


class FakeClient:
    def __init__(self):
        self.inserts = []

    def query(self, sql, parameters=None):
        if "FROM weirvern.netflow_anomalies" in sql:
            return Result(
                ["detected_at", "window_start", "window_end", "src_addr", "anomaly_score", "severity"],
                [
                    [BASE + timedelta(minutes=6), BASE, BASE + timedelta(minutes=5),
                     "192.0.2.10", 0.99, "high"],
                    [BASE + timedelta(minutes=11), BASE + timedelta(minutes=5),
                     BASE + timedelta(minutes=10), "192.0.2.10", 0.70, "high"],
                ],
            )
        if "FROM weirvern.host_roles" in sql:
            return Result(["host", "role"], [["192.0.2.10", "workstation"]])
        if "FROM weirvern.alert_episodes" in sql:
            return Result(["src_addr", "episode_start", "page_window", "pageable",
                           "page_reason", "paged_at"], [])
        raise AssertionError(sql)

    def insert(self, table, rows, column_names=None):
        self.inserts.append((table, rows, column_names))


def test_refresh_writes_one_episode_with_all_columns():
    client = FakeClient()
    summary = refresh(client, Settings())
    assert summary == {"episodes": 1, "pageable": 1}
    table, rows, columns = client.inserts[-1]
    assert table == "weirvern.alert_episodes"
    assert columns == EPISODE_COLUMNS
    assert len(rows[0]) == len(EPISODE_COLUMNS)
    assert rows[0][columns.index("occurrences")] == 2
    assert rows[0][columns.index("pageable")] == 1
    assert rows[0][columns.index("role")] == "workstation"
