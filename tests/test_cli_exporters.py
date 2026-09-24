"""`weirvern exporters` -- which devices are sending flow records, and would my allow-list accept them.

WHY THIS FILE EXISTS (glm-5.3 review): the command had NO test at all, and the fix for
`_exporter_permitted` returning a reason instead of a bool introduced a specific trap here. The
display tested it for truthiness, and EVERY non-empty string is truthy -- so "rejected" would have
printed as "accepted", inverting the one column an operator reads to decide whether they wrote the
allow-list correctly. Nothing caught it because nothing drove the command.

The command is driven through its real body: `db.connect` and `get_settings` are imported INSIDE the
function, so patching them at their source modules is what reaches it.
"""
from __future__ import annotations

import argparse
import contextlib
import io

import pytest

from weirvern.admin import cli
from weirvern.fleet import FleetError  # noqa: F401  (imported for symmetry with the other cli tests)


class _Client:
    def __init__(self, rows):
        self.rows = rows

    def query(self, _sql):
        return self

    @property
    def result_rows(self):
        return list(self.rows)

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


class _Settings:
    def __init__(self, allow):
        self.flow_exporter_allow = allow


@pytest.fixture
def run_exporters(monkeypatch):
    """Drive the real command and return its stdout, with the ClickHouse read stubbed."""

    def _run(rows, allow, settings_obj=None):
        from weirvern import config as config_mod
        from weirvern import db

        monkeypatch.setattr(db, "connect", lambda *_a, **_k: _Client(rows))
        monkeypatch.setattr(config_mod, "get_settings",
                            lambda: settings_obj or _Settings(allow))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            rc = cli.cmd_exporters(argparse.Namespace())
        return rc, buf.getvalue()

    return _run


def test_a_REJECTED_address_is_not_printed_as_accepted(run_exporters):
    """THE TRAP. Testing the verdict for truthiness marks everything accepted, including rejections --
    which is the one thing this column exists to tell the operator."""
    import datetime as _dt

    rows = [("198.51.100.9", 10, _dt.datetime(2026, 1, 1)),
            ("203.0.113.9", 5, _dt.datetime(2026, 1, 1))]
    rc, out = run_exporters(rows, allow="198.51.100.0/24")

    assert rc == 0, out
    listed = [ln for ln in out.splitlines() if ln.strip().startswith("198.") or ln.strip().startswith("203.")]
    assert len(listed) == 2, out

    inside = next(ln for ln in listed if "198.51.100.9" in ln)
    outside = next(ln for ln in listed if "203.0.113.9" in ln)
    assert "accepted" in inside, inside
    assert "REJECTED" in outside, (
        f"an address OUTSIDE the allow-list was not marked REJECTED. The verdict is a string now, "
        f"and every non-empty string is truthy, so a truthiness test prints 'accepted' for "
        f"rejections. line: {outside!r}"
    )


def test_an_address_the_list_cannot_check_says_so(run_exporters):
    """An operator reading this to decide "did I write the list correctly" needs to know when the
    list was never consulted, rather than seeing it flattened into "accepted"."""
    import datetime as _dt

    rows = [("not-an-ip", 3, _dt.datetime(2026, 1, 1))]
    rc, out = run_exporters(rows, allow="198.51.100.0/24")
    assert rc == 0, out
    line = next(ln for ln in out.splitlines() if "not-an-ip" in ln)
    assert "admitted" in line, (
        f"an address the allow-list cannot parse was reported the same as one it verified. line: "
        f"{line!r}"
    )


def test_the_command_still_reports_a_normal_window(run_exporters):
    """The other direction, so the marks cannot be 'everything is suspicious'."""
    import datetime as _dt

    rows = [("198.51.100.9", 10, _dt.datetime(2026, 1, 1))]
    rc, out = run_exporters(rows, allow="198.51.100.0/24")
    assert rc == 0, out
    assert "accepted" in out
    assert "REJECTED" not in out
    assert "admitted" not in out


def test_with_no_allow_list_no_address_is_marked(run_exporters):
    """With the filter off there is no verdict to show, and marking everything 'accepted' would
    imply a check that did not happen."""
    import datetime as _dt

    rows = [("203.0.113.9", 4, _dt.datetime(2026, 1, 1))]
    rc, out = run_exporters(rows, allow="")
    assert rc == 0, out
    line = next(ln for ln in out.splitlines() if "203.0.113.9" in ln)
    assert "accepted" not in line and "REJECTED" not in line, (
        f"an ungated deployment marked an address with a verdict, implying a check that did not "
        f"happen. line: {line!r}"
    )
