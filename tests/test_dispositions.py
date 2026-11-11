"""CE-2: every shadow channel has one explicit disposition; no blank, no automatic promote."""
from __future__ import annotations

from pathlib import Path

from weirvern.models import dispositions

ROOT = Path(__file__).resolve().parents[1]


def test_every_channel_has_one_valid_disposition():
    record = dispositions.build_record()
    assert len(record["channels"]) == len(dispositions.INVENTORY)
    assert not [x for x in record["channels"] if x["disposition"] not in dispositions.DISPOSITIONS]
    assert record["promotions"] == []


def test_promotion_without_evidence_is_refused():
    bad = ({"channel": "X", "disposition": "promote"},)
    try:
        dispositions.build_record(inventory=bad)
    except ValueError as exc:
        assert "generated-ground-truth" in str(exc)
    else:
        raise AssertionError("promote without evidence was accepted")


def test_merge_requires_a_named_consumer():
    bad = ({"channel": "X", "disposition": "merge"},)
    try:
        dispositions.build_record(inventory=bad)
    except ValueError as exc:
        assert "consumer" in str(exc)
    else:
        raise AssertionError("merge without a consumer was accepted")


def test_retirement_requires_a_reason():
    bad = ({"channel": "X", "disposition": "retire"},)
    try:
        dispositions.build_record(inventory=bad)
    except ValueError as exc:
        assert "reason" in str(exc)
    else:
        raise AssertionError("retire without a reason was accepted")


def test_the_inventory_is_exposed_on_the_models_surface():
    web = (ROOT / "weirvern" / "admin" / "web_api.py").read_text()
    assert "dispositions" in web
