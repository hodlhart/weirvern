"""The episode writer's SQL shape and insert arity, without a live ClickHouse."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from weirvern.config import Settings
from weirvern.episodes import EPISODE_COLUMNS, claim, refresh

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
    """A fake that can slide the anomaly window between two refreshes.

    It models the COLUMN, not a Python list: DateTime64(3) with no declared zone stores an
    instant and the driver reads it back aware in the server's zone. Every value it keeps is
    normalised that way, so a key written from an aware UTC row matches the same instant a
    naive-UTC fixture represents.
    """

    TIME_COLUMNS = ("episode_start", "episode_end", "first_detected", "last_detected",
                    "page_window", "paged_at", "updated_at")

    def __init__(self, rounds, episodes=None):
        self.rounds = rounds
        self.round_index = 0
        self.episodes = {}
        for row in (episodes or []):
            self._store(dict(zip(EPISODE_COLUMNS, row, strict=False)))

    @staticmethod
    def _as_read(value):
        if not isinstance(value, datetime):
            return value
        moment = value.replace(tzinfo=UTC) if value.tzinfo is None else value
        return moment.astimezone()

    def _store(self, item):
        for col in self.TIME_COLUMNS:
            item[col] = self._as_read(item.get(col))
        self.episodes[(item["src_addr"], item["episode_start"])] = item

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
            self._store(dict(zip(column_names or EPISODE_COLUMNS, row, strict=False)))


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
    assert active[0]["episode_start"].astimezone(UTC).replace(tzinfo=None) == BASE, (
        "the canonical start moved with the window")


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
    assert active[0]["episode_start"].astimezone(UTC).replace(tzinfo=None) == BASE
    assert len(superseded) == 1, "the older duplicate was not marked as history"
    assert (superseded[0]["episode_start"].astimezone(UTC).replace(tzinfo=None)
            == BASE + timedelta(minutes=5))


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
    assert merged[0]["episode_end"] == (BASE + timedelta(minutes=10)).replace(tzinfo=UTC)
    assert merged[0]["severity"] == "critical"
    assert len(superseded) == 1  # the aware prior row is history, not a second active episode


def test_prior_duplicates_are_collapsed_even_before_the_current_episode():
    from weirvern.episodes import merge_with_previous
    current_start = BASE + timedelta(hours=2)
    current = {"src_addr": "198.51.100.10", "episode_start": current_start,
               "episode_end": current_start + timedelta(minutes=5),
               "first_detected": current_start, "last_detected": current_start + timedelta(minutes=5),
               "occurrences": 1, "window_count": 1, "max_score": 0.9, "severity": "high",
               "severity_rank": 3, "role": "workstation", "page_window": current_start,
               "pageable": 0, "page_reason": "", "paged_at": None}
    old_start = BASE - timedelta(hours=2)
    prior_one = {"src_addr": "198.51.100.10", "episode_start": old_start,
                 "episode_end": old_start + timedelta(minutes=30),
                 "first_detected": old_start, "last_detected": old_start + timedelta(minutes=30),
                 "occurrences": 3, "window_count": 3, "max_score": 0.9, "severity": "high",
                 "severity_rank": 3, "role": "workstation", "page_window": old_start,
                 "pageable": 1, "page_reason": "within-budget", "paged_at": None,
                 "updated_at": old_start}
    prior_two = {**prior_one, "episode_start": old_start + timedelta(minutes=5),
                 "episode_end": old_start + timedelta(minutes=35),
                 "first_detected": old_start + timedelta(minutes=5),
                 "last_detected": old_start + timedelta(minutes=35)}
    _, superseded = merge_with_previous([current], [prior_one, prior_two])
    assert len(superseded) == 1
    assert superseded[0]["episode_start"] == old_start + timedelta(minutes=5)


def test_overlapping_rebuilt_episodes_are_collapsed_before_insert():
    from weirvern.episodes import merge_with_previous
    first = {"src_addr": "198.51.100.10", "episode_start": BASE,
             "episode_end": BASE + timedelta(minutes=20),
             "first_detected": BASE, "last_detected": BASE + timedelta(minutes=20),
             "occurrences": 4, "window_count": 4, "max_score": 0.8, "severity": "medium",
             "severity_rank": 2, "role": "workstation", "page_window": BASE,
             "pageable": 0, "page_reason": "", "paged_at": None}
    second = {**first, "episode_start": BASE + timedelta(minutes=10),
              "episode_end": BASE + timedelta(minutes=30),
              "first_detected": BASE + timedelta(minutes=10),
              "last_detected": BASE + timedelta(minutes=30)}
    merged, superseded = merge_with_previous([first, second], [])
    assert len(merged) == 1
    assert merged[0]["episode_start"] == BASE
    assert merged[0]["episode_end"] == BASE + timedelta(minutes=30)
    assert not superseded


def test_inserted_episode_times_are_aware_utc():
    """WV-ML-08: a naive value is stored as LOCAL wall clock, six hours off on this host."""
    client = FakeClient()
    refresh(client, Settings())
    _, rows, columns = client.inserts[-1]

    for name in ("episode_start", "episode_end", "first_detected", "last_detected",
                 "page_window", "updated_at"):
        value = rows[0][columns.index(name)]
        assert value.utcoffset() == timedelta(0), f"{name} was sent naive: {value!r}"

    assert rows[0][columns.index("episode_start")] == BASE.replace(tzinfo=UTC), (
        "the instant moved while being made aware")


class ClaimClient:
    """Returns the row the driver would give back: aware in the server's zone."""

    COLUMNS = [col for col in EPISODE_COLUMNS if col != "updated_at"]

    def __init__(self, row):
        self.row = row
        self.queries = []
        self.inserts = []

    def query(self, sql, parameters=None):
        self.queries.append((sql, parameters))
        return Result(self.COLUMNS, [self.row] if self.row else [])

    def insert(self, table, rows, column_names=None):
        self.inserts.append((table, rows, column_names))


def _claim_row(at):
    local = at.replace(tzinfo=UTC).astimezone()
    return ("198.51.100.10", local, local + timedelta(minutes=5), local,
            local + timedelta(minutes=5), 3, 3, 0.99, "critical", 4, "server", local,
            1, "within-budget", None)


def test_claim_formats_the_instant_in_the_column_zone_and_pages_once():
    at = BASE
    client = ClaimClient(_claim_row(at))

    assert claim(client, {"src_addr": "198.51.100.10", "window_start": at}, Settings())

    sql, parameters = client.queries[0]
    assert "parseDateTime64BestEffort" in sql, "a String compared lexically is not a comparison"
    expected = at.replace(tzinfo=UTC).astimezone().strftime("%Y-%m-%d %H:%M:%S.%f")
    assert parameters["at"] == expected

    table, rows, columns = client.inserts[-1]
    assert rows[0][columns.index("page_reason")] == "paged"
    assert rows[0][columns.index("paged_at")].utcoffset() == timedelta(0)


def test_claim_without_an_episode_logs_unknown(caplog):
    client = ClaimClient(None)
    with caplog.at_level("INFO", logger="weirvern.episodes"):
        assert claim(client, {"src_addr": "198.51.100.10", "window_start": BASE}, Settings())

    assert "no episode covers 198.51.100.10" in caplog.text
