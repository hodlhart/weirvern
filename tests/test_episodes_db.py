"""The episode writer's SQL shape and insert arity, without a live ClickHouse."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from weirvern.config import Settings
from weirvern.episodes import EPISODE_COLUMNS, refresh

BASE = datetime.now().replace(microsecond=0) - timedelta(hours=1)


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


class WindowClient:
    """A fake that can slide the anomaly window between two refreshes."""

    def __init__(self, rounds, episodes=None):
        self.rounds = rounds
        self.round_index = 0
        self.episodes = {(row[0], row[1]): dict(zip(EPISODE_COLUMNS, row, strict=False))
                         for row in (episodes or [])}

    def query(self, sql, parameters=None):
        if "FROM weirvern.netflow_anomalies" in sql:
            rows = self.rounds[min(self.round_index, len(self.rounds) - 1)]
            self.round_index += 1
            return Result(
                ["detected_at", "window_start", "window_end", "src_addr", "anomaly_score",
                 "severity"], rows)
        if "FROM weirvern.host_roles" in sql:
            return Result(["host", "role"], [["198.51.100.10", "workstation"]])
        if "FROM weirvern.alert_episodes" in sql:
            rows = [[row[col] for col in EPISODE_COLUMNS] for row in self.episodes.values()]
            return Result(EPISODE_COLUMNS, rows)
        raise AssertionError(sql)

    def insert(self, table, rows, column_names=None):
        for row in rows:
            item = dict(zip(column_names, row, strict=False))
            key = (item["src_addr"], item["episode_start"])
            self.episodes[key] = item


def _anomaly_rows(start):
    return [
        [start + timedelta(minutes=1), start, start + timedelta(minutes=5),
         "198.51.100.10", 0.95, "high"],
        [start + timedelta(minutes=6), start + timedelta(minutes=5), start + timedelta(minutes=10),
         "198.51.100.10", 0.96, "high"],
        [start + timedelta(minutes=11), start + timedelta(minutes=10), start + timedelta(minutes=15),
         "198.51.100.10", 0.97, "high"],
    ]


def _prior_episode(start):
    values = {
        "src_addr": "198.51.100.10", "episode_start": start,
        "episode_end": start + timedelta(minutes=15),
        "first_detected": start, "last_detected": start + timedelta(minutes=15),
        "occurrences": 3, "window_count": 3, "max_score": 0.97, "severity": "high",
        "severity_rank": 3, "role": "workstation", "page_window": start,
        "pageable": 1, "page_reason": "within-budget", "paged_at": None,
        "updated_at": start,
    }
    return [values[col] for col in EPISODE_COLUMNS]


def test_a_sliding_window_does_not_create_a_second_active_episode():
    first = _anomaly_rows(BASE)
    second = _anomaly_rows(BASE + timedelta(minutes=5))
    client = WindowClient([first, second])

    first_summary = refresh(client, Settings())
    second_summary = refresh(client, Settings())

    active = [row for row in client.episodes.values()
              if row["page_reason"] != "superseded"]
    assert first_summary["episodes"] == 1
    assert second_summary["episodes"] == 1
    assert len(active) == 1, "the sliding window inserted another active episode"
    assert active[0]["episode_start"] == BASE, "the canonical start moved with the window"


def test_overlapping_prior_rows_are_marked_superseded_without_deleting_history():
    client = WindowClient([_anomaly_rows(BASE)], episodes=[
        _prior_episode(BASE),
        _prior_episode(BASE + timedelta(minutes=5)),
    ])
    summary = refresh(client, Settings())

    active = [row for row in client.episodes.values()
              if row["page_reason"] != "superseded"]
    superseded = [row for row in client.episodes.values()
                  if row["page_reason"] == "superseded"]
    assert summary["episodes"] == 1
    assert len(active) == 1
    assert active[0]["episode_start"] == BASE
    assert len(superseded) == 1, "the older duplicate was not marked as history"
    assert superseded[0]["episode_start"] == BASE + timedelta(minutes=5)


def test_merge_normalises_aware_prior_timestamps():
    from weirvern.episodes import merge_with_previous
    episodes = [{"src_addr": "198.51.100.10",
                 "episode_start": BASE, "episode_end": BASE + timedelta(minutes=5),
                 "first_detected": BASE, "last_detected": BASE + timedelta(minutes=5),
                 "occurrences": 1, "window_count": 1, "max_score": 0.9, "severity": "high",
                 "severity_rank": 3, "role": "workstation", "page_window": BASE,
                 "pageable": 0, "page_reason": "", "paged_at": None}]
    prior = {"src_addr": "198.51.100.10",
             "episode_start": (BASE + timedelta(minutes=5)).replace(tzinfo=UTC),
             "episode_end": (BASE + timedelta(minutes=10)).replace(tzinfo=UTC),
             "first_detected": BASE.replace(tzinfo=UTC),
             "last_detected": (BASE + timedelta(minutes=10)).replace(tzinfo=UTC),
             "occurrences": 2, "window_count": 2, "max_score": 0.95, "severity": "critical",
             "severity_rank": 4, "role": "workstation", "page_window": BASE.replace(tzinfo=UTC),
             "pageable": 1, "page_reason": "within-budget", "paged_at": None,
              "updated_at": BASE.replace(tzinfo=UTC)}
    merged, superseded = merge_with_previous(episodes, [prior])
    assert merged[0]["episode_start"] == BASE
    assert merged[0]["episode_end"] == BASE + timedelta(minutes=10)
    assert merged[0]["severity"] == "critical"
    assert len(superseded) == 1  # the aware prior row is history, not a second active episode
