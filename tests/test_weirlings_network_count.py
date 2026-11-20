"""Declared networks and observed segments are TWO facts, never one number.

Operator (2026-11-20): "weirlings tab says we only have 1 network, but we have 2." The tile had
counted only the segments a sensor reported, so a scope declared in Settings with no NIC behind
it disappeared from the count while staying visible in the declaration list. These pins keep
both counts in the payload and keep the declared-but-unobserved scope named.

The observed set is produced ONCE, by `fleet.summarise`, and rides the summary as
`networks_list`; the payload copies it rather than parsing the serialised rows again (their
`plan` object does not carry the per-NIC plans, so a second derivation would undercount).
"""
from __future__ import annotations

from weirvern import fleet, networks


def _scope(cidr: str, *, label: str = "internal", monitored: bool = True):
    return networks.normalize_scope(cidr, label=label, monitored=monitored,
                                    policy="full" if monitored else "observe")


def test_the_two_counts_are_reported_side_by_side():
    scopes = [_scope("198.51.100.0/24", label="dmz"), _scope("192.0.2.0/24")]
    cov = networks.coverage(scopes, ["198.51.100.0/24"])
    assert cov["available"] is True
    assert cov["declared"] == 2
    assert cov["declared_monitored"] == 2
    assert cov["observed"] == 1
    assert cov["observed_segments"] == ["198.51.100.0/24"]


def test_a_declared_but_unobserved_network_is_named_not_folded_into_a_count():
    scopes = [_scope("198.51.100.0/24"), _scope("192.0.2.0/24", label="internal")]
    cov = networks.coverage(scopes, ["198.51.100.0/24"])
    assert [u["cidr"] for u in cov["unobserved"]] == ["192.0.2.0/24"]
    assert cov["unobserved"][0]["label"] == "internal"
    assert [s["observed"] for s in cov["scopes"]] == [True, False]


def test_observation_is_overlap_not_string_equality():
    """A sensor reporting a narrower /25 still observes the declared /24."""
    scopes = [_scope("198.51.100.0/24")]
    assert networks.coverage(scopes, ["198.51.100.128/25"])["scopes"][0]["observed"] is True
    wider = [_scope("198.51.100.128/25")]
    assert networks.coverage(wider, ["198.51.100.0/24"])["scopes"][0]["observed"] is True
    other = [_scope("198.51.100.0/24")]
    assert networks.coverage(other, ["203.0.113.0/24"])["scopes"][0]["observed"] is False


def test_a_non_address_segment_is_not_counted_as_a_network():
    """`mtls verification` is a prose label from an old registration, not a subnet."""
    cov = networks.coverage([], ["mtls verification", "", "198.51.100.0/24"])
    assert cov["observed"] == 1
    assert cov["observed_segments"] == ["198.51.100.0/24"]


def test_the_summary_carries_every_observed_segment_it_counts():
    """The list and the count come from the same walk, so they cannot disagree.

    Covers all three sources: the declared `segment`, the sensor's `reported_segment`, and the
    plan's own `segment`.
    """
    health = [
        fleet.SensorHealth(sensor_id="edge-a", state=fleet.STATE_ALIVE,
                           segment="198.51.100.0/24", reported_segment="198.51.100.0/24",
                           plan=fleet.SensorPlan(segment="")),
        fleet.SensorHealth(sensor_id="edge-b", state=fleet.STATE_ALIVE,
                           segment="", reported_segment="192.0.2.0/24",
                           plan=fleet.SensorPlan(segment="203.0.113.0/24")),
    ]
    summary = fleet.summarise(health)
    assert summary["networks_list"] == ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"]
    assert summary["networks"] == len(summary["networks_list"]) == 3
