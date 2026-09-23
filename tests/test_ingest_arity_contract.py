"""One unparseable record must not end a log type forever, and the count must not lie.

── WHY THIS FILE EXISTS (audit F013, CONFIRMED BY RUNNING IT) ───────────────────────────────────

Two defects in the Zeek write path, both measured before fixing.

1. THE MAPPER/COLUMNS CONTRACT WAS ENFORCED NOWHERE AT RUNTIME. The write is positional:

       batch.append([row.get(c) for c in columns])

   so a column the mapper does not produce becomes `None`, and a key the mapper produces that no
   column names is DROPPED. Neither is an error anywhere. The two tables ARE compared in the test
   suite, for the log types the tests enumerate -- coverage by enumeration, which does not survive a
   new log type or a new field, and which the production path did not share.

2. THE POISON PILL, which is what makes the first defect dangerous rather than theoretical. An
   exception from `client.insert` escaped `tail_zeek_log` BEFORE `state.note_read(...)` ran, so the
   cursor never advanced. Measured with an insert that rejects the batch:

       pass 1 RAISED: DB::Exception: Cannot parse input: expected column of type String
       state.offset after the failure: 0

       pass 2 re-reads from offset 0 and hits the SAME row again -> RAISED AGAIN

   ONE record ends that log type permanently: the worker's loop catches the exception, logs it, and
   retries the same line forever. So a mapper/columns drift does not merely corrupt a row -- it can
   stop ingestion of a whole Zeek log type, silently, with the only symptom being a warning that
   repeats every cycle.

WHAT THESE TESTS PIN: that a rejected batch costs only the rejected rows, that the cursor always
advances past them, that the reported count is what LANDED rather than what was attempted, and that
a mapper/columns disagreement stops the write instead of corrupting it.
"""

from __future__ import annotations

import pathlib

import pytest

from weirvern.ingester import (
    ZEEK_COLUMNS,
    ZEEK_MAPPERS,
    IngesterError,
    ZeekTailState,
    tail_zeek_log,
)

# The real conn.log field list, copied from a live sensor's header. A shortened or guessed fixture
# is how the earlier ingester tests passed vacuously (three versions of them did).
CONN_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
    "orig_bytes", "resp_bytes", "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
    "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes", "tunnel_parents",
]


def _row(i: int, uid: str = "") -> str:
    return "\t".join([
        "1700000000.000000", uid or f"C{i}", "198.51.100.5", "1234", "203.0.113.9", "80",
        "tcp", "http", "0.1", "100", "200", "SF", "-", "-", "0", "ShAdDaF", "2", "150", "2", "250",
        "-",
    ])


def _write_log(tmp_path: pathlib.Path, rows: list[str], name: str = "conn.log") -> pathlib.Path:
    """A conn.log in the real Zeek header shape.

    `#separator` carries the SPACE then an ESCAPED \\x09, and `#empty_field` a real tab -- both
    copied from a live header, because getting them wrong is how three earlier versions of the
    ingester tests asserted things about an empty list.
    """
    f = tmp_path / name
    header = [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        f"#path\t{name.split('.')[0]}",
        "#open\t2026-09-23-00-00-00",
        "#fields\t" + "\t".join(CONN_FIELDS),
        "#types\t" + "\t".join(["string"] * len(CONN_FIELDS)),
    ]
    f.write_text("\n".join(header + rows) + "\n")
    return f


class _Rejecting:
    """An insert that fails the way a schema or value mismatch does.

    `bad_uid` rejects that one row; `reject_batch` rejects any multi-row batch, which is how a
    single bad value inside a batch manifests -- ClickHouse rejects the whole insert.
    """

    def __init__(self, bad_uid: str | None = None, reject_batch: bool = False,
                 reject_all: bool = False) -> None:
        self.bad_uid = bad_uid
        self.reject_batch = reject_batch
        self.reject_all = reject_all
        self.rows_attempted: list[str] = []

    def insert(self, table, batch, column_names=None):
        if self.reject_all:
            raise Exception("Code: 53. DB::Exception: Cannot parse input")
        if len(batch) > 1 and self.reject_batch:
            raise Exception("Code: 53. DB::Exception: Cannot parse input: expected column")
        self.rows_attempted.append(batch[0][1])
        if self.bad_uid and batch[0][1] == self.bad_uid:
            raise Exception("Code: 53. DB::Exception: bad value in row")

    def query(self, *a, **kw):
        class _R:
            result_rows: list = []

        return _R()


# ── the poison pill ─────────────────────────────────────────────────────────────────────────

def test_a_rejected_BATCH_does_not_wedge_the_cursor(tmp_path):
    """THE DEFECT. The cursor must advance, or every later pass fails on the same line forever."""
    f = _write_log(tmp_path, [_row(1), _row(2), _row(3)])
    client = _Rejecting(reject_batch=True)

    inserted, offset, _, _ = tail_zeek_log(client, str(f), state=ZeekTailState())

    assert offset == f.stat().st_size, (
        f"the cursor stopped at {offset} of {f.stat().st_size} after a batch failure, so this log "
        f"would be re-read and re-failed on every pass -- one bad record ending a whole log type"
    )
    assert inserted == 3, f"every row was good once tried individually: inserted={inserted}"


def test_only_the_REJECTED_row_is_lost(tmp_path):
    """The trade this makes deliberately: one bad row must not cost its neighbours."""
    f = _write_log(tmp_path, [_row(1), _row(2), _row(3)])
    client = _Rejecting(bad_uid="C2", reject_batch=True)

    inserted, offset, _, _ = tail_zeek_log(client, str(f), state=ZeekTailState())

    assert inserted == 2, (
        f"inserted={inserted}; the two GOOD rows must land and only the rejected one be lost"
    )
    assert offset == f.stat().st_size, "the cursor must still advance past the rejected row"
    assert client.rows_attempted == ["C1", "C2", "C3"], (
        f"the rows were not retried individually: {client.rows_attempted}"
    )


def test_a_second_pass_does_NOT_retry_the_rejected_row(tmp_path):
    """The point of advancing: the bad record is BEHIND us, not retried forever. A cursor that
    advances but a loop that re-reads would look fixed while behaving identically."""
    f = _write_log(tmp_path, [_row(1), _row(2), _row(3)])
    client = _Rejecting(bad_uid="C2", reject_batch=True)

    _, offset, inode, header = tail_zeek_log(client, str(f), state=ZeekTailState())

    resumed = ZeekTailState(offset=offset, inode=inode,
                            separator=header[0], fields=list(header[1]))
    client.rows_attempted.clear()
    inserted2, offset2, _, _ = tail_zeek_log(client, str(f), state=resumed)

    assert inserted2 == 0, f"the second pass re-ingested {inserted2} row(s)"
    assert not client.rows_attempted, (
        f"the second pass retried rows that were already handled: {client.rows_attempted}"
    )
    assert offset2 == f.stat().st_size


def test_EVERY_row_rejected_still_advances(tmp_path):
    """The hardest case: nothing lands at all. The cursor must STILL advance, because a log type
    that is entirely unparseable is exactly when a stuck cursor is least recoverable."""
    f = _write_log(tmp_path, [_row(1), _row(2)])
    client = _Rejecting(reject_all=True)

    inserted, offset, _, _ = tail_zeek_log(client, str(f), state=ZeekTailState())

    assert inserted == 0, f"nothing should have been counted as inserted: {inserted}"
    assert offset == f.stat().st_size, (
        f"the cursor stopped at {offset} with every row rejected, so this log type can never "
        f"progress past data it cannot parse"
    )


def test_the_reported_COUNT_is_what_LANDED_not_what_was_attempted(tmp_path):
    """A count that includes rejected rows is a confident number about work that did not happen --
    the failure class this whole campaign keeps finding. Measured before the fix: three rows with
    the middle one rejected reported `inserted: 3`."""
    f = _write_log(tmp_path, [_row(1), _row(2), _row(3)])
    client = _Rejecting(bad_uid="C2", reject_batch=True)

    inserted, _, _, _ = tail_zeek_log(client, str(f), state=ZeekTailState())

    assert inserted == 2, (
        f"inserted={inserted} but only 2 rows actually landed. A total that counts rejected rows "
        f"is a number about a write that did not happen"
    )


def test_a_healthy_write_is_still_a_single_batch_call(tmp_path):
    """The retry must not become the normal path: a working insert is ONE call, so the cost of the
    fix is zero on the healthy case."""
    f = _write_log(tmp_path, [_row(1), _row(2), _row(3)])
    calls: list[int] = []

    class _Client:
        def insert(self, table, batch, column_names=None):
            calls.append(len(batch))

        def query(self, *a, **kw):
            class _R:
                result_rows: list = []

            return _R()

    inserted, _, _, _ = tail_zeek_log(_Client(), str(f), state=ZeekTailState())
    assert inserted == 3
    assert calls == [3], f"a healthy write made {len(calls)} insert call(s): {calls}"


# ── the mapper/columns contract ─────────────────────────────────────────────────────────────

def test_a_mapper_that_DROPS_a_column_stops_the_write(tmp_path, monkeypatch):
    """DEFECT 1. A column with no value from the mapper writes None with no error, so the check has
    to stop the write instead. Verified through the REAL writer, with the mapper broken rather than
    the check stubbed."""
    f = _write_log(tmp_path, [_row(1)])
    real = ZEEK_MAPPERS["conn"][1]

    def lossy(rec):
        out = real(rec)
        # Drop a column the table requires, as a field rename would.
        out.pop("conn_state", None)
        return out

    table, _ = ZEEK_MAPPERS["conn"]
    monkeypatch.setitem(ZEEK_MAPPERS, "conn", (table, lossy))

    client = _Rejecting()
    with pytest.raises(IngesterError) as exc:
        tail_zeek_log(client, str(f), state=ZeekTailState())
    assert "conn_state" in str(exc.value), (
        f"the error does not name the column that has no value: {exc.value}"
    )


def test_a_mapper_with_an_EXTRA_key_stops_the_write(tmp_path, monkeypatch):
    """The other direction: a key no column names is silently DROPPED, so a renamed field would
    stop being stored with nothing to show for it."""
    f = _write_log(tmp_path, [_row(1)])
    real = ZEEK_MAPPERS["conn"][1]

    def extra(rec):
        out = real(rec)
        out["a_field_no_column_knows"] = "x"
        return out

    table, _ = ZEEK_MAPPERS["conn"]
    monkeypatch.setitem(ZEEK_MAPPERS, "conn", (table, extra))

    with pytest.raises(IngesterError) as exc:
        tail_zeek_log(_Rejecting(), str(f), state=ZeekTailState())
    assert "a_field_no_column_knows" in str(exc.value), (
        f"the error does not name the key with no column: {exc.value}"
    )


def test_the_CURRENT_mappers_all_satisfy_the_contract():
    """THE CHECK MUST NOT FIRE ON A HEALTHY PRODUCT. This is the same invariant the suite asserts
    elsewhere, restated here so the runtime check and the static one cannot disagree -- if a mapper
    and its columns drift, exactly one of these tests fails and the message says which."""
    empty = {name: "" for name in CONN_FIELDS}
    for log_type, (_table, mapper) in sorted(ZEEK_MAPPERS.items()):
        if log_type not in ZEEK_COLUMNS:
            continue
        # Build a record from the mapper's own needs: any field it reads, plus the common ones.
        probe = dict(empty)
        for field in ("id.orig_h", "id.resp_h", "orig_h", "resp_h", "ts", "uid", "mac", "client_addr",
                      "server_addr", "assigned_addr", "host_name", "domain", "software", "version",
                      "unparsed_version", "fingerprint", "ja4", "server_name", "cipher", "subject",
                      "issuer", "id", "method", "uri", "user_agent", "status_code", "referrer",
                      "proto", "service", "conn_state", "community_id", "query", "qtype_name",
                      "rcode_name", "answers", "note", "msg", "sub", "name", "resp_p", "orig_p"):
            probe[field] = ""
        try:
            row = mapper(probe)
        except Exception:  # noqa: BLE001 - a mapper may legitimately need a field this probe lacks
            continue
        if row is None:
            continue
        keys = set(row) - {"_observation"}
        missing = [c for c in ZEEK_COLUMNS[log_type] if c not in keys]
        assert not missing, (
            f"{log_type}: {missing} have no value from the mapper, so the positional INSERT would "
            f"write nulls. Fix the mapper or ZEEK_COLUMNS[{log_type!r}] together."
        )


def test_the_count_is_right_when_the_BATCH_FLUSHES_mid_file(tmp_path):
    """THE FLUSH BOUNDARY, and mutation testing found this gap: nothing asserted the count on the
    path that inserts a full batch and then a remainder.

    `tail_zeek_log` accumulates until `BATCH_SIZE` and inserts, then inserts the remainder at the
    end. Both call sites must use what LANDED. An earlier form added `len(batch)` at the flush site
    -- correct for a healthy insert, and wrong the moment a batch is partially rejected, which is
    exactly when the number matters.
    """
    from weirvern import ingester as ing

    # A file larger than one batch, so both the flush and the remainder run.
    count = ing.BATCH_SIZE + 3
    f = _write_log(tmp_path, [_row(i) for i in range(count)])

    class _PickyBatch:
        """Every multi-row batch fails; individual rows land except the rejected one."""

        def __init__(self, bad_uid: str) -> None:
            self.bad_uid = bad_uid
            self.batch_calls = 0

        def insert(self, table, batch, column_names=None):
            if len(batch) > 1:
                self.batch_calls += 1
                raise Exception("Code: 53. DB::Exception: Cannot parse input")
            if batch[0][1] == self.bad_uid:
                raise Exception("Code: 53. DB::Exception: bad value")

        def query(self, *a, **kw):
            class _R:
                result_rows: list = []

            return _R()

    client = _PickyBatch(bad_uid="C2")
    inserted, offset, _, _ = tail_zeek_log(client, str(f), state=ZeekTailState())

    assert client.batch_calls >= 1, (
        "no multi-row batch was attempted, so this test did not exercise the flush path"
    )
    assert inserted == count - 1, (
        f"inserted={inserted} for {count} rows with exactly one rejected; the flush path and the "
        f"remainder path must both report what LANDED"
    )
    assert offset == f.stat().st_size, "the cursor must advance past every row either way"


# ── ZEEK'S JSON OUTPUT WAS READ BY A TSV PARSER (audit F064) ─────────────────────────────────
#
# CONFIRMED BY RUNNING IT. `tail_zeek_dir` has always listed BOTH `conn.log` and `conn.log.json` as
# supported filenames, but `tail_zeek_log` read every line as TSV. A JSON file has no `#` header, so
# `fields` stayed empty and every line hit the "data before header" branch: read, discarded, cursor
# advanced. Measured with a real two-row conn.log.json:
#
#     inserted: 0 of 2 rows
#     cursor advanced: 832 of 832
#
# So an operator who switched Zeek to JSON output got empty tables, no error, and a warning
# repeating once per line -- the supported-filename list and the parser disagreed.

def _json_log(tmp_path: pathlib.Path, n: int = 2, name: str = "conn.log.json") -> pathlib.Path:
    """Zeek's JSON output: one JSON object per line, no header."""
    import json

    f = tmp_path / name
    rows = [
        {
            "ts": 1700000000.0 + i, "uid": f"C{i}", "id.orig_h": "198.51.100.5",
            "id.orig_p": 1234 + i, "id.resp_h": "203.0.113.9", "id.resp_p": 80,
            "proto": "tcp", "service": "http", "duration": 0.1, "orig_bytes": 100,
            "resp_bytes": 200, "conn_state": "SF", "local_orig": None, "local_resp": None,
            "missed_bytes": 0, "history": "ShAdDaF", "orig_pkts": 2, "orig_ip_bytes": 150,
            "resp_pkts": 2, "resp_ip_bytes": 250, "tunnel_parents": [],
        }
        for i in range(n)
    ]
    f.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return f


def test_a_json_log_INGESTS_instead_of_being_silently_dropped(tmp_path):
    """THE DEFECT. Every line was skipped and the cursor advanced past all of it."""
    f = _json_log(tmp_path)
    client = _Rejecting()

    inserted, offset, _, _ = tail_zeek_log(client, str(f), state=ZeekTailState())

    assert inserted == 2, (
        f"a conn.log.json ingested {inserted} of 2 rows. `tail_zeek_dir` lists .log.json as a "
        f"supported filename, so this file is read and thrown away -- empty tables, no error"
    )
    assert offset == f.stat().st_size


def test_a_json_log_produces_the_SAME_row_as_the_tsv_form(tmp_path):
    """ONE INPUT CONTRACT, NOT TWO. The mappers are shared, so the same record in either format must
    land identically -- otherwise the JSON path is a second shape that only Zeek's JSON
    configuration exercises, which is where a null becomes the string "None"."""
    import json

    rec = {
        "ts": 1700000000.0, "uid": "C1", "id.orig_h": "198.51.100.5", "id.orig_p": 1234,
        "id.resp_h": "203.0.113.9", "id.resp_p": 80, "proto": "tcp", "service": "http",
        "duration": 0.1, "orig_bytes": 100, "resp_bytes": 200, "conn_state": "SF",
        "local_orig": None, "local_resp": None, "missed_bytes": 0, "history": "ShAdDaF",
        "orig_pkts": 2, "orig_ip_bytes": 150, "resp_pkts": 2, "resp_ip_bytes": 250,
        "tunnel_parents": [],
    }
    jf = tmp_path / "conn.log.json"
    jf.write_text(json.dumps(rec) + "\n")

    # The same record as Zeek's TSV writer would emit it.
    tf = _write_log(tmp_path, [_row(1)])
    # `_row` uses uid C1 and the same addresses/ports; align the remaining fields.
    fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto",
              "service", "duration", "orig_bytes", "resp_bytes", "conn_state", "local_orig",
              "local_resp", "missed_bytes", "history", "orig_pkts", "orig_ip_bytes", "resp_pkts",
              "resp_ip_bytes", "tunnel_parents"]
    vals = ["1700000000.000000", "C1", "198.51.100.5", "1234", "203.0.113.9", "80", "tcp", "http",
            "0.100000", "100", "200", "SF", "-", "-", "0", "ShAdDaF", "2", "150", "2", "250", "-"]
    header = [
        "#separator \\x09", "#set_separator\t,", "#empty_field\t(empty)", "#unset_field\t-",
        "#path\tconn", "#open\t2026-09-23-00-00-00",
        "#fields\t" + "\t".join(fields), "#types\t" + "\t".join(["string"] * len(fields)),
    ]
    tf.write_text("\n".join(header + ["\t".join(vals)]) + "\n")

    def read_one(path):
        class _C:
            def __init__(self):
                self.rows = []
                self.cols = None

            def insert(self, table, batch, column_names=None):
                self.rows.extend(batch)
                self.cols = column_names

            def query(self, *a, **kw):
                class _R:
                    result_rows: list = []

                return _R()

        c = _C()
        tail_zeek_log(c, str(path), state=ZeekTailState())
        assert c.rows, f"{path.name} ingested nothing"
        return dict(zip(c.cols, c.rows[0], strict=False))

    jrow, trow = read_one(jf), read_one(tf)
    for col in ZEEK_COLUMNS["conn"]:
        assert jrow.get(col) == trow.get(col), (
            f"column {col!r} differs between the JSON and TSV forms of the same record: "
            f"json={jrow.get(col)!r} tsv={trow.get(col)!r}. The mappers are shared, so a difference "
            f"here means the JSON path is a second input shape nothing else exercises."
        )


def test_the_value_normaliser_matches_zeek_TSV_conventions():
    """`null`, booleans and set-valued lists must arrive as the strings the TSV path produces:
    Zeek's own TSV writer emits T/F for booleans and a comma-joined set, so the two formats have to
    agree or a column's contents depend on which output mode the sensor runs."""
    from weirvern.ingester import _json_field_value

    assert _json_field_value(None) == "", "a JSON null must read as absent, not as 'None'"
    assert _json_field_value(True) == "T", "Zeek's TSV writer emits T for true"
    assert _json_field_value(False) == "F", "Zeek's TSV writer emits F for false"
    assert _json_field_value([]) == "", "an empty set is an absent value"
    assert _json_field_value(["a", "b"]) == "a,b", "a set joins with Zeek's set separator"
    assert _json_field_value(80) == "80"
    assert _json_field_value("x") == "x", "a string passes through unchanged"


def test_a_MALFORMED_json_line_is_reported_not_silently_skipped(tmp_path, caplog):
    """A line that is not valid JSON must be named. Silently skipping it would reproduce the defect
    this fix is for -- with the difference that the failure would now be this code's fault."""
    import logging

    f = tmp_path / "conn.log.json"
    f.write_text('{"ts": 1700000000.0, "uid": "C1", "id.orig_h": "198.51.100.5", '
                 '"id.resp_h": "203.0.113.9", "proto": "tcp"}\n'
                 "{ this is not json\n")

    # A CLIENT THAT ACCEPTS, deliberately. `_Rejecting()` would reject the single valid row and the
    # count would be 0 for a reason that has nothing to do with JSON -- which is exactly what an
    # earlier version of this test asserted and failed on.
    class _Accepting:
        def __init__(self):
            self.rows = []

        def insert(self, table, batch, column_names=None):
            self.rows.extend(batch)

        def query(self, *a, **kw):
            class _R:
                result_rows: list = []

            return _R()

    with caplog.at_level(logging.WARNING, logger="weirvern.ingester"):
        inserted, offset, _, _ = tail_zeek_log(_Accepting(), str(f), state=ZeekTailState())

    assert inserted == 1, f"the valid row was not ingested: inserted={inserted}"
    assert any("not valid JSON" in r.getMessage() for r in caplog.records), (
        "a malformed JSON line was skipped with no warning naming it"
    )
    assert offset == f.stat().st_size, (
        "the cursor did not advance past the malformed line, so it would be retried forever"
    )


def test_a_TSV_log_renamed_to_dot_json_json_log_is_REFUSED_visibly(tmp_path):
    """The misconfiguration this branch makes possible: a TSV log with a .json suffix is read as
    JSON and every line fails. It must be reported, not silently ingested as nothing."""
    f = _write_log(tmp_path, [_row(1), _row(2)], name="conn.log.json")
    client = _Rejecting()

    inserted, offset, _, _ = tail_zeek_log(client, str(f), state=ZeekTailState())

    assert inserted == 0, "a TSV file was somehow ingested through the JSON path"
    assert offset == f.stat().st_size, "the cursor must advance, or the file is re-read forever"
