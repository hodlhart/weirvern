"""Network scope resolution: declared, longest-prefix, and honest about unclassified."""
from __future__ import annotations

import pytest

from weirvern.networks import (
    filter_monitored,
    is_monitored,
    normalize_scope,
    resolve,
)


def _scope(cidr, label="internal", monitored=True, policy="full", id="a"):
    return normalize_scope(cidr, label=label, monitored=monitored, policy=policy,
                           scope_id=id)


def test_longest_prefix_beats_a_broader_declaration():
    scopes = [
        _scope("198.51.100.0/24", "internal", True, "full", "a"),
        _scope("198.51.100.128/26", "dmz", True, "full", "b"),
    ]
    assert resolve("198.51.100.150", scopes).label == "dmz"
    assert resolve("198.51.100.10", scopes).label == "internal"


def test_unmatched_is_unclassified_not_guessed_external():
    scopes = [_scope("198.51.100.0/24")]
    assert resolve("203.0.113.9", scopes) is None
    assert filter_monitored([{"src_addr": "203.0.113.9"}], scopes)[1]["unclassified"] == 1


def test_external_can_be_monitored_but_defaults_to_observe():
    external = normalize_scope("203.0.113.0/24", label="external", monitored=True)
    assert external.policy == "observe"
    assert is_monitored(external) is False
    explicit = normalize_scope("203.0.113.0/24", label="external", monitored=True,
                               policy="aggregate")
    assert is_monitored(explicit) is True


def test_monitored_and_policy_are_independent():
    assert is_monitored(_scope("192.0.2.0/24", label="vpn", monitored=True)) is True
    assert is_monitored(_scope("192.0.2.0/24", label="vpn", monitored=False)) is False
    assert is_monitored(_scope("192.0.2.0/24", label="vpn", monitored=True,
                               policy="observe")) is False


def test_invalid_cidr_and_label_are_rejected():
    with pytest.raises(ValueError):
        normalize_scope("not-a-network")
    with pytest.raises(ValueError):
        normalize_scope("198.51.100.0/24", label="production")


def test_filter_monitored_keeps_only_monitored_rows_and_reports_counts():
    scopes = [_scope("198.51.100.0/24", "internal", True, "full", "a"),
              _scope("203.0.113.0/24", "external", True, "observe", "b")]
    rows = [{"src_addr": "198.51.100.7"}, {"src_addr": "203.0.113.4"},
            {"src_addr": "192.0.2.9"}]
    kept, summary = filter_monitored(rows, scopes)
    assert [r["src_addr"] for r in kept] == ["198.51.100.7"]
    assert summary["unclassified"] == 1
    assert summary["kept"] == 1


def test_ipv6_resolves_without_a_version_collision():
    scopes = [_scope("2001:db8::/32", "internal", True, "full", "a")]
    assert resolve("2001:db8::1", scopes).label == "internal"
    assert resolve("203.0.113.1", scopes) is None


def test_training_filter_is_empty_without_declarations_and_follows_monitored():
    from weirvern.networks import training_filter_sql
    # No declarations: legacy training, exactly as before the feature existed.
    assert training_filter_sql([]) == ""
    scopes = [_scope("198.51.100.0/24", "internal", True, "full", "a"),
              _scope("203.0.113.0/24", "external", True, "observe", "b")]
    predicate = training_filter_sql(scopes)
    assert "198.51.100.0/24" in predicate
    assert "203.0.113.0/24" not in predicate
    assert predicate.startswith("AND (")
    # A declaration set with nothing monitored must not fall back to training on everything.
    assert training_filter_sql([_scope("198.51.100.0/24", monitored=False)]) == "AND 0"


def test_catch_all_monitored_scope_is_flagged_not_rejected():
    broad = normalize_scope("0.0.0.0/0", label="external", monitored=True, policy="aggregate")
    assert broad.warning, "a monitored catch-all must be flagged as dangerous"
    observed = normalize_scope("0.0.0.0/0", label="external", monitored=False, policy="observe")
    assert observed.warning == "", "an observed catch-all is not an alerting risk"
