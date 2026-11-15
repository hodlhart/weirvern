"""A failed read is worded by what was OBSERVED, not by the layer we assume broke.

WV1-20. Every data path in `web.py` reported `cannot reach ClickHouse: {exc}` regardless of cause,
39 sites. Measured on a box with no database and no kubectl:

    /api/health -> "data_error": "cannot reach ClickHouse: [Errno 2] No such file or directory:
                   'kubectl'"

The cause was a missing binary and the message asserted a database fault. `cli.py` already records
this exact confusion as a known trap that "sends you looking" in the wrong place, and the GUI went
on producing it.

The contract these tests hold is narrow on purpose: name ClickHouse for a connection-shaped
failure, and for anything else say only that the data could not be read. The exact wording of the
non-connection branch is not pinned beyond that, because the point is what it must NOT claim.
"""

import pytest

from weirvern.admin.web import read_failure


def test_a_missing_binary_does_not_blame_the_database():
    """The measured case. A FileNotFoundError for kubectl is not a ClickHouse fault, and saying so
    sends an operator to check a database that is fine."""
    text = read_failure(FileNotFoundError(2, "No such file or directory", "kubectl"))

    assert "ClickHouse" not in text, f"a missing binary was reported as a database fault: {text!r}"
    assert "could not read the data" in text, text
    # The cause itself must survive, or the message is honest and useless.
    assert "kubectl" in text, f"the observed cause was dropped: {text!r}"
    assert "FileNotFoundError" in text, f"the exception type was dropped: {text!r}"


def test_a_connection_failure_still_names_clickhouse():
    """The one case the old wording was right for. It must not be lost in the sweep."""
    text = read_failure(ConnectionError("connection refused"))

    assert text.startswith("cannot reach ClickHouse:"), text
    assert "connection refused" in text, text


@pytest.mark.parametrize("exc", [
    ConnectionRefusedError("Connection refused"),
    TimeoutError("query timed out"),
    OSError("No route to host"),
    RuntimeError("Failed to establish a new connection: [Errno -2]"),
    RuntimeError("HTTPConnectionPool(host='clickhouse', port=8123): Max retries exceeded"),
])
def test_connection_shaped_failures_name_clickhouse(exc):
    assert read_failure(exc).startswith("cannot reach ClickHouse:"), read_failure(exc)


@pytest.mark.parametrize("exc", [
    PermissionError(13, "Permission denied"),
    ValueError("bad value"),
    KeyError("rows"),
    OSError(28, "No space left on device"),
])
def test_other_failures_do_not(exc):
    text = read_failure(exc)
    assert "ClickHouse" not in text, f"{type(exc).__name__} was reported as a database fault: {text!r}"
    assert text, "an empty reason renders as no reason at all"


def test_no_exception_still_says_something():
    """The bare `reason: "cannot reach ClickHouse"` sites had no exception in scope. They now say
    the data could not be read, which is true and does not blame a specific layer."""
    text = read_failure(None)

    assert "ClickHouse" not in text, text
    assert text.strip(), "the fallback reason is empty"


def test_the_39_sites_are_gone():
    """A guard, because this defect was 39 copies of one string and a new data path would copy it
    again. The helper itself may say it; nothing else in the module may."""
    import pathlib
    import re

    src = pathlib.Path("weirvern/admin/web.py").read_text()
    hits = [line for line in src.splitlines()
            if "cannot reach ClickHouse" in line and not line.lstrip().startswith("#")]
    # The helper's own connect branch is the only permitted occurrence.
    assert len(hits) == 1, f"an inline ClickHouse claim is back: {hits}"
    assert re.search(r"return f\"cannot reach ClickHouse: \{detail\}\"", hits[0]), hits
