"""Capture loss reaches the GUI as a measurement, and NULL stays distinct from 0.0.

WHY THIS FILE EXISTS. `sensorwatch.capture_loss()` has read Zeek's capture_loss.log for a while,
but the number only ever became a SENTENCE inside `sensor_status.failures` and was never stored.
So no panel could show it as a figure, and the operator's real question -- "is this sensor
dropping packets?" -- was answerable only by pattern-matching English prose.

That matters more than it looks. A sensor dropping 60% of packets is HEALTHY everywhere else:
logs are written, rows are ingested, every panel renders. Capture loss is the only field that
says the sensor is blind to most of what is on the wire, which is why it is now a column.

The property worth pinning is the NULL/0.0 distinction, because collapsing it would recreate the
exact bug this project keeps fixing: an UNMEASURED sensor reading as a perfect one.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = ROOT / "weirvern" / "schema"
STATUS = ROOT / "weirvern" / "admin" / "status.py"
WATCH = ROOT / "weirvern" / "admin" / "sensorwatch.py"


# ── the column exists and is nullable ──────────────────────────────────────────────────────


def test_the_capture_loss_column_is_nullable():
    """NULL must mean NOT MEASURED, which 0.0 cannot express."""
    sql = (SCHEMA / "007_sensor_capture.sql").read_text()
    code = "\n".join(line.split("--", 1)[0] for line in sql.splitlines())
    assert "capture_loss_pct Nullable(Float32)" in code, (
        "capture_loss_pct must be Nullable. A non-nullable column forces an unmeasured sensor "
        "to store 0.0, which reads as a perfect sensor -- the silent-empty pattern."
    )
    # The counters are Nullable too: measured live, this Zeek build's capture_loss.log has no
    # pkts_recv/pkts_drop field, so a NOT NULL count would report 0 packets for a busy sensor.
    assert "packets_recv Nullable(UInt64)" in code, code[-400:]
    assert "packets_dropped Nullable(UInt64)" in code


def test_the_migration_is_ADDITIVE_so_it_can_run_against_a_live_table():
    """The heartbeats table exists in every deployment already; CREATE TABLE IF NOT EXISTS
    would silently do nothing to it (a documented trap in this project)."""
    sql = (SCHEMA / "007_sensor_capture.sql").read_text()
    assert "ALTER TABLE" in sql, "column additions must be an ALTER, not a fresh CREATE"
    assert "ADD COLUMN IF NOT EXISTS" in sql, "the ALTER must be idempotent"


def test_the_migration_parses_into_the_expected_statements():
    """The runner splits on `;` and strips comments; a schema file that ends in a comment once
    failed the whole migration with 'Empty query'. Verify this file survives that path."""
    import sys

    sys.path.insert(0, str(ROOT))
    from weirvern import db

    sql = (SCHEMA / "007_sensor_capture.sql").read_text()
    stmts = db.split_sql_statements(sql)
    assert len(stmts) == 3, f"expected 3 ALTERs, parsed {len(stmts)}"
    for s in stmts:
        code = db._strip_sql_comments(s).strip()
        assert code.startswith("ALTER TABLE"), code[:60]
        assert "--" not in code, "a comment leaked into executable SQL"


# ── the WRITE carries it ───────────────────────────────────────────────────────────────────


def test_heartbeat_accepts_and_STORES_the_capture_fields():
    src = STATUS.read_text()
    sig = src[src.index("def heartbeat("):]
    sig = sig[:sig.index(") -> bool:")]
    for param in ("capture_loss_pct", "packets_recv", "packets_dropped"):
        assert param in sig, f"heartbeat() does not accept {param}"


def test_a_missing_measurement_is_written_as_NULL_not_zero():
    """The single most important assertion here.

    `0 if x is None else x` would look careful and be wrong: it makes an unmeasured sensor
    indistinguishable from one that measured zero loss.
    """
    src = STATUS.read_text()
    body = src[src.index("def heartbeat("):]
    body = body[:body.index("except Exception as exc")] if "except Exception" in body else body
    assert "None if capture_loss_pct is None else float(capture_loss_pct)" in body, (
        "the write must pass None through as NULL rather than coercing it to 0.0"
    )
    assert re.search(r"capture_loss_pct[^\n]*or 0", body) is None, (
        "`or 0` on the loss would collapse not-measured into measured-zero"
    )


def test_the_new_columns_are_last_in_the_positional_insert():
    """NEW COLUMNS GO LAST. A clickhouse-connect insert matches values to names by POSITION, so
    inserting a column in the middle would silently shift every field after it."""
    src = STATUS.read_text()
    i = src.index("column_names=[\"sensor_id\"")
    names = src[i:src.index("]", i)]
    order = re.findall(r'"(\w+)"', names)
    # THE EARLIER BATCH STAYS BEFORE THE NEWEST. The channel columns are the most recent
    # addition (068_weirling_channel.sql), so they are the ones that must be last now; a
    # subsequent addition must extend THIS assertion rather than move an older column.
    assert order[-9:] == ["capture_loss_pct", "packets_recv", "packets_dropped",
                          "host_stats", "interfaces",
                          "channel_active", "channel_upstream", "channel_downstream",
                          "channel_bridge"], (
        f"the newest columns are not last in column_names: {order}"
    )
    # And the value tuples must have the same length as the names.
    v = src.index("[[sensor_id, mode, iface")
    values_blob = src[v:src.index("]]", v)]
    assert len(re.findall(r"^[^#]*?[,\]]$", values_blob, re.M)) >= 1


# ── the OBSERVER produces it ───────────────────────────────────────────────────────────────


def test_sensorwatch_returns_the_counter_alongside_the_percentage():
    """One log line, one read: a percentage shown beside packets must describe those packets."""
    src = WATCH.read_text()
    assert "def capture_counters(" in src, "the packet counters are not read at all"
    body = src[src.index("def observe("):]
    assert "capture_counters()" in body, (
        "observe() does not call capture_counters(), so the counters never reach the heartbeat"
    )
    for key in ("capture_loss_pct", "packets_recv", "packets_dropped"):
        assert f'"{key}"' in body, f"observe() does not publish {key}"


def test_observe_output_fits_the_heartbeat_signature():
    """The caller passes observe() straight through with `**`, so a key the signature does not
    accept is a TypeError every 15 seconds -- and a key it does not send is a column that stays
    empty forever."""
    import inspect
    import sys

    sys.path.insert(0, str(ROOT))
    from weirvern.admin import sensorwatch, status

    obs = sensorwatch.observe()
    params = set(inspect.signature(status.heartbeat).parameters) - {"client", "sensor_id"}
    extra = set(obs) - params
    assert not extra, f"observe() returns keys heartbeat() rejects: {sorted(extra)}"
    for key in ("capture_loss_pct", "packets_recv", "packets_dropped"):
        assert key in params, f"heartbeat() has no parameter for {key}"


# ── the READER exposes it ──────────────────────────────────────────────────────────────────


def test_the_reader_selects_and_exposes_the_capture_fields():
    src = STATUS.read_text()
    q = src[src.index("FROM weirvern.sensor_status FINAL") - 400:]
    q = q[:q.index("FROM weirvern.sensor_status FINAL")]
    for col in ("capture_loss_pct", "packets_recv", "packets_dropped"):
        assert col in q, f"the reader does not SELECT {col}, so the column is written and unseen"
        # Slice the WHOLE out.update({...}) block by braces, not by a fixed character count: a
        # magic window silently stops covering the block as it grows.
        start = src.index("out.update({")
        end = src.index("return out", start)
        assert f'"{col}"' in src[start:end], (
            f"the reader does not expose {col} on the returned dict"
        )


def test_the_reader_preserves_NULL_as_None():
    """`float(x or 0)` on the way out would undo the column's whole purpose."""
    src = STATUS.read_text()
    i = src.index('"capture_loss_pct": (None if')
    snippet = src[i:i + 200]
    assert "None if" in snippet and "is None" in snippet, snippet
    assert "or 0" not in snippet, f"the read coerces NULL to zero: {snippet}"


def test_a_per_mode_row_carries_its_loss_too():
    """The `others` rows exist to compare MODES on one sensor; a mode that is dropping packets
    is exactly what a comparison is for, so the field belongs on both."""
    src = STATUS.read_text()
    i = src.index('others.append({')
    snippet = src[i:src.index("})", i)]
    assert "capture_loss_pct" in snippet, (
        "per-mode rows omit capture loss, so a comparison cannot show which mode dropped packets"
    )


# ── the counters, against the field set the SENSOR ACTUALLY WRITES ─────────────────────────
#
# The FIELD NAMES below are Zeek's, which are public and documented; the VALUES are invented.
# Measured on the live node, this build's capture_loss.log declares
#     #fields  ts  ts_delta  peer  gaps  acks  percent_lost
# and has NO pkts_recv/pkts_drop column. Code that assumed those fields read nothing and returned
# 0, which reports "zero packets received" for a sensor receiving millions -- the same
# not-measured/measured-zero confusion the nullable percentage column exists to prevent.
#
# No value here comes from the sensor: a real log line is a record of a real network and must not
# be committed, which is what tests/test_sanitation.py enforces.

LIVE_FIELDS = "ts\tts_delta\tpeer\tgaps\tacks\tpercent_lost"
LIVE_ROW = "1000000000.000000\t900.000000\tpeer0\t0\t0\t0.0"


def _write_loss(tmp_path, fields=LIVE_FIELDS, rows=(LIVE_ROW,)):
    f = tmp_path / "capture_loss.log"
    f.write_text("#separator \\x09\n#fields\t" + fields + "\n" + "\n".join(rows) + "\n")
    return f


def test_counters_use_the_REAL_field_set_and_do_not_report_zero_when_absent(tmp_path):
    """The live field set has no pkts_recv, so the reader must not claim a measured zero."""
    import sys

    sys.path.insert(0, str(ROOT))
    from weirvern.admin import sensorwatch

    _write_loss(tmp_path)
    recv, dropped = sensorwatch.capture_counters(log_dir=tmp_path)
    # The fallback reads `acks`/`gaps`, which ARE present, so a real value is available here.
    assert recv == 0 and dropped == 0, (recv, dropped)
    assert recv is not None, "the count must be a number when a real field supplies it"


def test_counters_return_None_when_the_log_has_no_counter_field_at_all(tmp_path):
    """A log with only the percentage must yield None, NOT 0."""
    import sys

    sys.path.insert(0, str(ROOT))
    from weirvern.admin import sensorwatch

    _write_loss(tmp_path, fields="ts\tts_delta\tpercent_lost", rows=("1000000000.000000\t900.000000\t0.0",))
    recv, dropped = sensorwatch.capture_counters(log_dir=tmp_path)
    assert recv is None and dropped is None, (
        f"an absent counter field must read as unmeasured (None), got {(recv, dropped)}. "
        f"Returning 0 reports 'zero packets received' for a sensor that is receiving traffic."
    )


def test_counters_prefer_pkts_recv_when_the_log_HAS_it(tmp_path):
    """Other Zeek builds do write these fields; the fallback must not shadow them."""
    import sys

    sys.path.insert(0, str(ROOT))
    from weirvern.admin import sensorwatch

    _write_loss(tmp_path, fields="ts\tpkts_recv\tpkts_drop\tpercent_lost",
                rows=("1000000000.000000\t9000000\t12\t0.3",))
    recv, dropped = sensorwatch.capture_counters(log_dir=tmp_path)
    assert (recv, dropped) == (9000000, 12), (recv, dropped)


def test_the_counter_is_passed_through_as_null_when_unmeasured():
    """heartbeat() must not coerce None to 0 on the way into a Nullable column."""
    src = (ROOT / "weirvern" / "admin" / "status.py").read_text()
    assert "_opt_count(packets_recv)" in src, (
        "the counters are coerced on write; an unmeasured count becomes a measured zero"
    )
    body = src[src.index("def _opt_count("):]
    body = body[:body.index("def heartbeat(")]
    # STRIP DOCSTRINGS AND COMMENTS FIRST. `_opt_count`'s own docstring QUOTES the wrong pattern
    # it replaced ("max(0, int(value or 0))` looked defensive and was wrong"), and a naive search
    # reads that explanation as the defect it documents -- the same trap this project hit with the
    # ATT&CK mapper's docstrings.
    import re as _re

    code = _re.sub(r'""".*?"""', "", body, flags=_re.S)
    code = "\n".join(ln.split("#")[0] for ln in code.splitlines())
    assert "if value is None:" in code, code[:300]
    assert "value or 0" not in code, (
        f"`or 0` collapses not-measured into measured-zero: {code[:300]}"
    )
