"""The settings receipt: one record per key, verified by what the read-back shows.

WHY THIS FILE EXISTS. The apply response used to collapse N separate intentions into one
"saved:" line. When a write half-landed, the operator could not tell WHICH value failed or
why -- the same defect the staged-settings research names in every product that ships a
page-level Apply with no per-item record. The receipt is the fix: per key, the value, the
verdict and the reason, with `ok` computed from a READ-BACK rather than from the call having
returned.

WHAT THESE TESTS PIN:
  * every requested key gets a record; ok rides the read-back, not the call
  * no read-back source means NOT ok -- never assumed
  * a failure names the reason on the failing key and leaves the landed keys ok
  * the fresh-read path (`after`) disagrees with the apply's own result, and it wins
  * the route emits the receipt on BOTH paths and re-reads after a refusal
"""
from __future__ import annotations

from pathlib import Path

from weirvern.admin import cluster_config as cc

ROOT = Path(__file__).resolve().parents[1]


def test_every_requested_key_gets_a_record():
    items = cc.receipt_items({"base_threshold": "0.5", "sensor_mode": "siphon"},
                             {"BASE_THRESHOLD": "0.5", "SENSOR_MODE": "siphon"})
    assert [i["key"] for i in items] == ["base_threshold", "sensor_mode"]
    assert all(i["ok"] for i in items)
    assert all(i["error"] == "" for i in items)


def test_ok_rides_the_read_back_not_the_call():
    items = cc.receipt_items({"base_threshold": "0.5"}, {"SENSOR_MODE": "loch"})
    assert items[0]["ok"] is False, (
        "the apply returned, but the read-back does not show the value -- that is not ok"
    )
    assert items[0]["error"], "a missing value must carry a reason"


def test_no_read_back_source_means_not_ok_never_assumed():
    items = cc.receipt_items({"base_threshold": "0.5"}, None)
    assert items[0]["ok"] is False


def test_a_failure_names_the_reason_and_leaves_landed_keys_ok():
    items = cc.receipt_items(
        {"base_threshold": "0.5", "sensor_mode": "siphon"},
        None, after={"BASE_THRESHOLD": "0.5", "SENSOR_MODE": "loch"},
        error="read-back: SENSOR_MODE did not land")
    by = {i["key"]: i for i in items}
    assert by["base_threshold"]["ok"] is True
    assert by["sensor_mode"]["ok"] is False
    assert "did not land" in by["sensor_mode"]["error"]


def test_values_are_normalised_like_the_write_path():
    items = cc.receipt_items({"base_threshold": " 0.5 "}, {"BASE_THRESHOLD": "0.5"})
    assert items[0]["value"] == "0.5"
    assert items[0]["ok"] is True


def test_the_route_emits_the_receipt_on_both_paths():
    """THE APPLY MOVED into payloads.settings_apply with the port; the receipt went with it.

    Both paths still owe one: a failed write must say which keys landed, and that means re-reading
    rather than guessing.
    """
    src = (ROOT / "weirvern" / "admin" / "web.py").read_text()
    assert "payloads.settings_apply(" in src, "the apply route no longer uses the shared fetcher"
    body = (ROOT / "weirvern" / "admin" / "payloads.py").read_text()
    body = body[body.index("def settings_apply("):]
    body = body[:body.index("\ndef ")]
    assert '"items"' in body and '"at"' in body, "the receipt is gone from the apply response"
    assert body.count("receipt_items") >= 2, (
        "the refusal path lost its receipt -- a failed write must still say which keys landed"
    )
    assert "after = client.read()" in body, (
        "the refusal path no longer re-reads; the per-item verdict would be a guess"
    )
