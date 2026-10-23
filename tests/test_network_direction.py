"""Direction, honestly (the operator, 2026-10-16): "I think you have this directionally backwards,
and that the source port of overseerr going outbound".

The measured case: 198.51.100.194:51334 -> 203.0.113.46:443 (the request) plus the reply
443 -> 51334. The panel presented the REPLY as the connection, with the ephemeral ports under
it. These pin the merge, the port-based initiator rule, and the refusals to guess."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "weirvern" / "admin" / "web"


def _edge(src, dst, ports, bytes_, flows, first="2026-10-16T13:00:00", last="2026-10-16T13:01:00",
          ttl_min=0, ttl_max=0, src_ports=None):
    return {"source": src, "target": dst, "ports": list(ports), "src_ports": list(src_ports or []),
            "bytes": bytes_, "flows": flows,
            "first_seen": first, "last_seen": last, "ttl_min": ttl_min, "ttl_max": ttl_max}


def test_the_outbound_call_merges_initiator_first():
    from weirvern.admin.assets import _merge_direction_pairs

    out = _merge_direction_pairs([
        _edge("203.0.113.46", "198.51.100.194", [51334, 49806], 5582, 16,
              ttl_min=50, ttl_max=50, src_ports=[443]),
        _edge("198.51.100.194", "203.0.113.46", [443], 5794, 18,
              ttl_min=63, ttl_max=63, src_ports=[51334, 49806]),
    ])
    assert len(out) == 1
    e = out[0]
    assert e["source"] == "198.51.100.194", "the side that dialled port 443 is the source"
    assert e["target"] == "203.0.113.46"
    assert e["ports"] == [443], "the edge's ports are the SERVICE ports"
    assert e["source_ports"] == [51334, 49806], "the initiator's ephemeral ports"
    assert e["bytes_source"] == 5794 and e["bytes_target"] == 5582
    assert e["flows"] == 34 and e["reply_seen"] is True
    assert e["direction"] == "request/reply"


def test_both_halves_in_the_same_range_are_not_merged_and_claim_no_direction():
    from weirvern.admin.assets import _merge_direction_pairs

    out = _merge_direction_pairs([
        _edge("198.51.100.9", "198.51.100.10", [51000], 10, 1),
        _edge("198.51.100.10", "198.51.100.9", [52000], 20, 2),
    ])
    assert len(out) == 2, "an undecidable pair keeps both halves"
    assert all("not claimed" in e["direction"] for e in out)


def test_a_lone_reply_says_what_it_is_instead_of_impersonating_a_request():
    from weirvern.admin.assets import _merge_direction_pairs

    out = _merge_direction_pairs([
        _edge("203.0.113.46", "198.51.100.194", [51334], 104, 2, src_ports=[443]),
    ])
    assert len(out) == 1 and out[0]["reply_seen"] is False
    e = out[0]
    assert (e["source"], e["target"]) == ("198.51.100.194", "203.0.113.46")
    assert "reply half" in e["direction"] and e["source_ports"] == [51334]


def test_a_user_port_above_1024_is_not_a_service():
    """32768-49151 are IANA USER ports; the old boundary read them as services.

    A port shape with no known service on either side must leave direction unclaimed.
    """
    from weirvern.admin.assets import _merge_direction_pairs

    out = _merge_direction_pairs([
        _edge("a", "b", [10021], 1, 1, src_ports=[32767]),
        _edge("b", "a", [28715], 1, 1, src_ports=[10022]),
    ])
    assert len(out) == 2, "two user-port sides must not be merged into a request/reply"
    assert all("not claimed" in e["direction"] for e in out)


def test_ttl_is_carried_per_end_so_each_host_is_placed_by_its_own_packets():
    from weirvern.admin.assets import _merge_direction_pairs

    out = _merge_direction_pairs([
        _edge("203.0.113.46", "198.51.100.194", [51334], 5, 1,
              ttl_min=50, ttl_max=50, src_ports=[443]),
        _edge("198.51.100.194", "203.0.113.46", [443], 9, 1,
              ttl_min=63, ttl_max=63, src_ports=[51334]),
    ])
    e = out[0]
    assert e["source_ttl_max"] == 63 and e["target_ttl_max"] == 50


def test_the_panel_renders_the_direction_and_the_source_ports():
    js = (WEB / "assets.js").read_text()
    assert "source ports ${srcPorts}" in js
    assert "opened by the source" in js
    assert "opened it, " in js, "the bytes-each-way sentence is built from bytes_source/bytes_target"
    assert "edge.direction" in js
