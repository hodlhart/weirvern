"""The plan the operator chose decides the capabilities the worker is granted.

The bug these pin: an applied plan came up unable to open a capture socket because the
Deployment still dropped every capability, and the operator had no way to know from the UI
that a second, invisible step was required.
"""
from __future__ import annotations

from weirvern.admin import cluster_config as cc


def test_a_passive_sensor_gets_nothing():
    caps = cc.required_capabilities({"SENSOR_MODE": "loch", "NETFLOW_MODE": "auto",
                                     "SIPHON_NETFLOW": "0", "CHANNEL_NETFLOW": "off"})
    assert caps == set()


def test_an_active_tap_needs_only_the_capture_socket():
    caps = cc.required_capabilities({"SENSOR_MODE": "loch", "NETFLOW_MODE": "active"})
    assert caps == {"NET_RAW"}
    assert "NET_ADMIN" not in caps


def test_a_siphon_needs_both_and_that_is_strictly_more():
    siphon = cc.required_capabilities({"SENSOR_MODE": "siphon"})
    active = cc.required_capabilities({"NETFLOW_MODE": "active"})
    assert siphon == {"NET_RAW", "NET_ADMIN"}
    assert siphon > active


def test_the_legacy_siphon_flag_implies_siphon():
    assert cc.required_capabilities({"SENSOR_MODE": "loch", "SIPHON_NETFLOW": "1"}) == {
        "NET_RAW", "NET_ADMIN"}


def test_a_channel_selection_needs_the_capture_socket():
    assert cc.required_capabilities({"CHANNEL_NETFLOW": "upstream"}) == {"NET_RAW"}


def test_the_patch_is_surgical_and_refuses_the_wrong_container():
    ops = cc.capability_patch(0, "worker", {"NET_RAW"}, has_capabilities=True)
    assert ops[0] == {"op": "test", "path": "/spec/template/spec/containers/0/name",
                      "value": "worker"}
    assert ops[1]["op"] == "replace"
    assert ops[1]["value"] == {"drop": ["ALL"], "add": ["NET_RAW"]}


def test_a_container_with_no_capability_block_gets_one_added():
    ops = cc.capability_patch(2, "worker", set(), has_capabilities=False)
    assert ops[1]["op"] == "add"
    assert ops[1]["value"] == {"drop": ["ALL"]}


def test_passive_patch_drops_everything_and_adds_nothing():
    ops = cc.capability_patch(0, "worker", set(), has_capabilities=True)
    assert ops[1]["value"] == {"drop": ["ALL"]}
