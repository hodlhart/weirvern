"""The queue contract: an episode is an incident only when it has evidence.

The review's P0 finding was that the console showed every scored row as work. These tests pin
the narrower contract: high/critical AND pageable AND at least one named feature or independent
family. Everything else remains reachable as a lead.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

from weirvern.admin.status import episodes_recent

BASE = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)


class Result:
    def __init__(self, columns, rows):
        self.column_names = columns
        self.result_rows = rows


class Client:
    def __init__(self, evidence):
        self.evidence = evidence
        self.fail_evidence = False

    def query(self, sql, parameters=None, **kwargs):
        if "alert_episodes" in sql:
            return Result(
                ["src_addr", "episode_start", "episode_end", "first_detected", "last_detected",
                 "occurrences", "window_count", "max_score", "severity", "severity_rank", "role",
                 "page_window", "pageable", "page_reason", "paged_at", "updated_at"],
                [
                    ("198.51.100.1", BASE, BASE + timedelta(minutes=10), BASE, BASE + timedelta(minutes=10),
                     3, 3, 0.99, "critical", 4, "server", BASE, 1, "within-budget", None, BASE),
                    ("198.51.100.2", BASE + timedelta(minutes=1), BASE + timedelta(minutes=9), BASE,
                     BASE + timedelta(minutes=9), 2, 2, 0.70, "medium", 2, "workstation",
                     BASE + timedelta(minutes=1), 1, "within-budget", None, BASE),
                    ("198.51.100.3", BASE + timedelta(minutes=2), BASE + timedelta(minutes=8), BASE,
                     BASE + timedelta(minutes=8), 1, 1, 0.95, "high", 3, "server",
                     BASE + timedelta(minutes=2), 1, "within-budget", None, BASE),
                ],
            )
        if "netflow_anomalies" in sql:
            if self.fail_evidence:
                raise RuntimeError("evidence table unavailable")
            return Result(
                ["src_addr", "window_start", "primary_deviation_feature", "strong_families"],
                [
                    ("198.51.100.1", BASE, "bytes_z", 2),
                    ("198.51.100.2", BASE + timedelta(minutes=1), "unique_dst_ips", 1),
                    ("198.51.100.3", BASE + timedelta(minutes=2), "", 0),
                ],
            )
        raise AssertionError(f"unexpected query: {sql}")


def test_incident_requires_high_severity_pageable_and_measured_evidence():
    payload = episodes_recent(Client({}))

    assert payload["available"] is True
    assert payload["counts"] == {"episodes": 3, "incidents": 1, "leads": 2, "pageable": 3}
    assert [row["src_addr"] for row in payload["incidents"]] == ["198.51.100.1"]
    assert payload["incidents"][0]["primary_feature"] == "bytes_z"
    assert payload["incidents"][0]["queue_reason"] == "pageable high/critical with measured evidence"

    leads = {row["src_addr"]: row for row in payload["leads"]}
    assert leads["198.51.100.2"]["queue_reason"] == "low/medium observation"
    assert leads["198.51.100.3"]["queue_reason"] == "model-only: no named feature or strong family"
    assert all(row["queue"] == "lead" for row in leads.values())


def test_a_broken_evidence_read_is_explicit_and_never_invites_paging():
    client = Client({})
    client.fail_evidence = True
    payload = episodes_recent(client)

    assert payload["available"] is True
    assert payload["incidents"] == []
    assert payload["counts"]["incidents"] == 0
    assert "evidence_error" in payload
    assert all(row["queue"] == "lead" for row in payload["leads"])
