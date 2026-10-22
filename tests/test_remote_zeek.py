"""Remote Zeek log shipping: parsed records, a persisted cursor, and the hub's own mapper.

A remote unit's logs historically stopped at its own disk; the gateway accepted NetFlow only.
These tests pin the shipper's two safety properties: it sends only complete records, and it
advances a file's cursor only after the gateway accepted the batch, so a failed upload is
retried rather than silently skipped.
"""
from __future__ import annotations

import json

import pytest

from weirvern.admin import sensor_agent


class _FakeGateway:
    is_gateway = True

    def __init__(self):
        self.calls = []

    def send_zeek(self, log_type, records):
        self.calls.append((log_type, list(records)))
        return len(records)


def _dns_log(tmp_path):
    path = tmp_path / "dns.log"
    path.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.resp_h\tproto\ttrans_id\tquery\tqtype\trcode\tanswers\n"
        "2026-10-22T00:00:00Z\tC1\t198.51.100.20\t198.51.100.1\tudp\t7\texample.test\t1\t0\t203.0.113.9\n"
        "2026-10-22T00:00:01Z\tC2\t198.51.100.20\t198.51.100.1\tudp\t8\texample.test\t1\t0\t203.0.113.9\n"
    )
    return path


def test_ships_complete_dns_records_and_does_not_repeat_them(tmp_path):
    _dns_log(tmp_path)
    client = _FakeGateway()
    state = tmp_path / "offsets.json"
    assert sensor_agent._ship_zeek_once(client, root=str(tmp_path), state_path=str(state)) == 2
    assert [c[0] for c in client.calls] == ["dns"]
    assert client.calls[0][1][0]["query"] == "example.test"
    assert sensor_agent._ship_zeek_once(client, root=str(tmp_path), state_path=str(state)) == 0, (
        "the cursor must prevent a second upload of the same records")


def test_a_partial_line_is_left_for_the_next_pass(tmp_path):
    path = tmp_path / "dns.log"
    path.write_text(
        "#separator \\x09\n"
        "#fields\tts\tuid\tid.orig_h\tid.resp_h\tproto\ttrans_id\tquery\tqtype\trcode\tanswers\n"
        "2026-10-22T00:00:00Z\tC1\t198.51.100.20\t198.51.100.1\tudp\t7\texample.test\t1\t0\t203.0.113.9\n"
        "2026-10-22T00:00:01Z\tC2\t198.51.100.20\t198.51.100.1\tudp\t8"
    )
    client = _FakeGateway()
    assert sensor_agent._ship_zeek_once(client, root=str(tmp_path),
                                       state_path=str(tmp_path / "offsets.json")) == 1
    # Finish the line; the next pass must send only the completed record.
    with path.open("a") as fh:
        fh.write("\texample.test\t1\t0\t203.0.113.9\n")
    assert sensor_agent._ship_zeek_once(client, root=str(tmp_path),
                                       state_path=str(tmp_path / "offsets.json")) == 1
    assert [len(c[1]) for c in client.calls] == [1, 1]


def test_an_upload_failure_does_not_advance_the_cursor(tmp_path):
    _dns_log(tmp_path)
    state = tmp_path / "offsets.json"

    class _Broken:
        is_gateway = True

        def send_zeek(self, log_type, records):
            raise RuntimeError("gateway down")

    with pytest.raises(RuntimeError, match="gateway down"):
        sensor_agent._ship_zeek_once(_Broken(), root=str(tmp_path), state_path=str(state))
    # No record cursor is committed when the upload fails; the next pass resends the batch.
    assert not state.exists() or not any(
        (v.get("offset") or 0) > 0 for v in json.loads(state.read_text()).values()
        if isinstance(v, dict))
    client = _FakeGateway()
    assert sensor_agent._ship_zeek_once(client, root=str(tmp_path), state_path=str(state)) == 2
