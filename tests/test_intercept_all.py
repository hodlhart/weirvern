"""`--all`: intercept every host on the segment, deliberately.

WHY THIS IS NOT JUST `only=None`.

Interception makes this process the PATH for everything it intercepts: a crash is an outage for
every host in the set. So the set has to be chosen on purpose. Without a flag, "all of them" is
what you get by OMISSION -- you simply do not pass `--hosts` -- which means the most dangerous
configuration is also the one you reach without deciding anything.

`--all` makes it a stated intent, and demands `--seconds` with it: a whole-segment intercept that
never ends leaves every host dependent on a process that someone has to remember to stop.

The case this exists for: a segment with no interactive users. Servers tolerate a brief
interruption in a way that a person on a laptop does not.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from weirvern.admin import cli as cli_mod  # noqa: E402

# ── direct tests of the scope rules ───────────────────────────────────────────────────────────
#
# Called directly rather than through cmd_intercept. On a host without CAP_NET_ADMIN the mode gate
# refuses before the scope rules are reached -- correct ordering, since a host that cannot
# intercept should say that first -- but it means the rules are unreachable via the CLI here.

def _scope(**overrides):
    import argparse
    base = dict(hosts=None, all_hosts=False, seconds=None)
    base.update(overrides)
    return cli_mod._resolve_host_scope(argparse.Namespace(**base))


def test_scope_all_without_seconds_is_refused():
    only, refusal = _scope(all_hosts=True)
    assert refusal is not None, (
        "--all without --seconds was allowed, leaving an unbounded whole-segment intercept where "
        "every host depends on this process until someone stops it"
    )
    assert "--seconds" in refusal


def test_scope_all_with_hosts_is_refused():
    only, refusal = _scope(all_hosts=True, seconds=60, hosts=["198.51.100.5"])
    assert refusal is not None, "--all and --hosts were both accepted"
    assert "Pick one" in refusal


def test_scope_all_with_seconds_is_allowed_and_selects_everything():
    only, refusal = _scope(all_hosts=True, seconds=60)
    assert refusal is None
    assert only == set(), "`only` empty means 'every host the sweep finds', which is the intent"


def test_scope_named_hosts_pass_through():
    only, refusal = _scope(hosts=["198.51.100.5", "198.51.100.6"])
    assert refusal is None
    assert only == {"198.51.100.5", "198.51.100.6"}


def test_scope_no_flags_means_all_and_is_allowed_for_backwards_compatibility():
    """Omitting both flags keeps the previous behaviour: intercept what the sweep finds.

    This is why `--all` demands `--seconds`: the unbounded form is still reachable by omission, and
    the flag is what makes it a stated intent. Documented rather than changed, because altering it
    would break every existing invocation.
    """
    only, refusal = _scope()
    assert refusal is None
    assert only == set()


# ── the segment-size ceiling ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("segment,expected", [("198.51.100.0/24", True), ("198.51.100.0/21", False)])
def test_segment_size_guard_still_bounds_all(segment: str, expected: bool):
    """`--all` inherits the size guard: a /21 is refused by parse_cidr before any of this runs.

    Poisoning thousands of ARP entries is not something anyone means to do, so the ceiling stays
    regardless of how explicitly the operator asked for "everything".
    """
    from weirvern.admin.intercept import parse_cidr

    try:
        parse_cidr(segment)
        accepted = True
    except ValueError:
        accepted = False
    assert accepted is expected, f"{segment}: expected accepted={expected}"
