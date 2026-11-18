"""The staged review, in the operator's language.

WHY THIS FILE EXISTS. The console stored the intercept plan as JSON keyed by NIC and printed that
JSON, verbatim, in the pending-changes list: `intercept_plans -> {"eth1":{...},"eth2":{...}}`. An
operator staging eth2 read the string left to right, saw `eth1` first, and concluded the console was
about to apply the change to the wrong port -- twice, and reasonably (operator report, 2026-11-18).
That is not a formatting nit: it is the review step failing at its only job.

WHAT THESE TESTS PIN:
  * the review names the NIC that MOVES, not every NIC in the blob (`eth2: adds siphon ...`)
  * an untouched plan reads `no change`, so a review cannot imply work that is not happening
  * a NIC leaving the plan is stated as removed
  * the per-NIC sheet view describes only its own NIC, and says so when that NIC is absent
  * the formatter is actually WIRED into the two lists and the receipt -- an unused helper would
    pass every case above while the operator still reads JSON

The pure functions are extracted from the shipping `app.js` by name and run under node; there is no
copy to drift.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "weirvern" / "admin" / "web" / "app.js"


def _review_text() -> dict[str, str]:
    node = shutil.which("node") or ""
    if not node:
        pytest.skip("node is not installed here; CI runs the jsdom harness on the same source")
    proc = subprocess.run(
        [node, str(ROOT / "scripts" / "plan_review_text.js")],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert proc.returncode == 0, proc.stderr or proc.stdout
    return json.loads(proc.stdout)


def test_the_review_names_the_nic_that_moves():
    """eth2 is the only difference; eth1 must not appear in the sentence about what changes."""
    got = _review_text()["adds_eth2"]
    assert got == "eth2: adds siphon 198.51.100.0/24, address 198.51.100.233, gateway 198.51.100.1", (
        "the operator staged eth2 and must read eth2 -- the old line led with eth1's JSON"
    )
    assert "eth1" not in got, "an unchanged NIC in the diff is what made the change look misaimed"


def test_an_unchanged_plan_says_no_change():
    assert _review_text()["no_change"] == "no change"


def test_a_removed_nic_is_stated():
    assert _review_text()["removes_eth2"] == "eth2: removed"


def test_a_moved_address_is_a_change_to_the_same_nic():
    assert _review_text()["changes_address"] == (
        "eth1: changes to siphon 192.0.2.0/24, address 192.0.2.20, gateway 192.0.2.1"
    )


def test_the_sheet_describes_only_its_own_nic():
    got = _review_text()
    assert got["plan_one_nic"] == "siphon 198.51.100.0/24, address 198.51.100.233, gateway 198.51.100.1"
    assert got["plan_absent_nic"] == "not intercepted", (
        "a NIC with no plan is not the same as a NIC that is off -- say what is true"
    )


def test_the_whole_plan_stays_available_for_the_settings_list():
    got = _review_text()["plan_all"]
    assert "eth1: siphon 192.0.2.0/24, address 192.0.2.19, gateway 192.0.2.1" in got
    assert "eth2: siphon 198.51.100.0/24, address 198.51.100.233, gateway 198.51.100.1" in got


def test_unreadable_input_is_shown_not_swallowed():
    got = _review_text()
    assert got["plan_empty"] == "no NICs"
    assert got["plan_unparsable"] == "not json", (
        "a value the formatter cannot parse must still reach the operator verbatim"
    )


def test_the_formatter_is_wired_into_both_lists_and_the_receipt():
    """A helper that nothing calls passes every test above and fixes nothing."""
    src = APP_JS.read_text(encoding="utf-8")
    assert 'if (key === "intercept_plans") return describePlan(value, nic);' in src, (
        "the NIC-scoped sheet list must humanize the plan"
    )
    assert "const shown = readableValue(key, STAGE.changes[key], \"\", was);" in src, (
        "the Settings staged list must humanize the plan, as a diff"
    )
    assert 'readableValue(item.key, item.value, "")' in src, (
        "the after-apply receipt must humanize the plan too -- the write is what the operator checks"
    )
