"""Zeek log parsing tests.

Zeek's TSV format is header-driven: `#fields` names the columns and data lines
map positionally onto it. A given Zeek build may emit different field sets, so
these tests pin the header-driven behaviour rather than a hardcoded column
order — a hardcoded order silently shifts every value when Zeek changes schema.
"""
import os
import tempfile

from weirvern.ingester import (
    ZEEK_COLUMNS,
    ZEEK_MAPPERS,
    ZeekTailState,
    _label_entropy,
    map_zeek_conn,
    map_zeek_dns,
    map_zeek_notice,
    map_zeek_ssl,
    parse_zeek_header,
    tail_zeek_dir,
    tail_zeek_log,
    zeek_value,
)


class FakeCH:
    def __init__(self):
        self.tables = {}
        self.insert_calls = 0

    def insert(self, table, data, column_names=None, **kw):
        self.insert_calls += 1
        self.tables.setdefault(table, [])
        self.tables[table].extend(data)


# --- header parsing ----------------------------------------------------------
CONN_HEADER = """#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tconn
#open\t2026-09-15-00-00-00
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\torig_pkts\tresp_pkts\tconn_state\thistory
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tcount\tcount\tstring\tstring
"""


def test_parse_header_extracts_separator_and_fields():
    sep, fields = parse_zeek_header(CONN_HEADER.strip().split("\n"))
    assert sep == "\t"
    assert fields[:3] == ["ts", "uid", "id.orig_h"]
    assert "conn_state" in fields
    assert len(fields) == 15


def test_parse_header_survives_missing_fields_line():
    sep, fields = parse_zeek_header(["#separator \\x09", "#path\tconn"])
    assert sep == "\t"
    assert fields == []


def test_zeek_value_null_sentinel():
    assert zeek_value("-") is None
    assert zeek_value("") is None
    assert zeek_value("TCP") == "TCP"


# --- per-log mapping ---------------------------------------------------------
def _conn_rec():
    return {
        "ts": "1789447100.123456", "uid": "C1", "id.orig_h": "198.51.100.10",
        "id.orig_p": "51000", "id.resp_h": "8.8.8.8", "id.resp_p": "443",
        "proto": "tcp", "service": "ssl", "duration": "1.5", "orig_bytes": "1000",
        "resp_bytes": "2000", "orig_pkts": "10", "resp_pkts": "12",
        "conn_state": "SF", "history": "ShADadfF",
    }


def test_map_zeek_conn():
    row = map_zeek_conn(_conn_rec())
    assert row["src_addr"] == "198.51.100.10"
    assert row["src_port"] == 51000
    assert row["dst_port"] == 443
    assert row["proto"] == "tcp"
    assert row["orig_bytes"] == 1000
    assert row["conn_state"] == "SF"


def test_map_zeek_conn_rejects_unset_addresses():
    rec = _conn_rec()
    rec["id.orig_h"] = "-"
    assert map_zeek_conn(rec) is None
    rec = _conn_rec()
    rec["id.resp_h"] = "-"
    assert map_zeek_conn(rec) is None


def test_map_zeek_conn_handles_garbage_numbers():
    rec = _conn_rec()
    rec["orig_bytes"] = "-"
    rec["duration"] = "(empty)"
    row = map_zeek_conn(rec)
    assert row["orig_bytes"] == 0
    assert row["duration"] == 0.0


def test_map_zeek_dns_computes_entropy():
    """DNS tunnelling shape: long, high-entropy labels."""
    benign = map_zeek_dns({"ts": "1", "id.orig_h": "198.51.100.5", "query": "www.google.com", "qtype": "1"})
    tunnel = map_zeek_dns({
        "ts": "1", "id.orig_h": "198.51.100.5",
        "query": "aGVsbG8gd29ybGQgdGhpcyBpcyBhIHR1bm5lbA.exfil.example.com", "qtype": "16",
    })
    assert benign["query_len"] < tunnel["query_len"]
    assert tunnel["query_entropy"] > benign["query_entropy"]
    assert tunnel["query_entropy"] > 3.0


def test_map_zeek_dns_rejects_unset_src():
    assert map_zeek_dns({"ts": "1", "id.orig_h": "-", "query": "x.com"}) is None


def test_label_entropy_bounds():
    assert _label_entropy("") == 0.0
    assert _label_entropy("aaaa") == 0.0          # single distinct char
    assert _label_entropy("abcdefgh") > 2.9       # 8 distinct chars -> log2(8)=3
    # entropy uses the longest label, not the whole name
    assert _label_entropy("a.bbbbbbbb.c") == _label_entropy("bbbbbbbb")


def test_map_zeek_ssl_extracts_ja4():
    """JA4, not JA3: Zeek 9.x core ships no ja3 policy, so ja3 never populated.

    Renamed from test_map_zeek_ssl_extracts_ja3 rather than deleted, because the old
    assertion encoded a real mistake -- it asserted a field that could never arrive.
    """
    row = map_zeek_ssl({
        "ts": "1", "uid": "S1", "id.orig_h": "198.51.100.9", "id.resp_h": "1.2.3.4",
        "id.resp_p": "443", "version": "TLSv13", "cipher": "TLS_AES_256_GCM_SHA384",
        "server_name": "c2.example.net", "ja4": "t130200_1302_234ea6891581",
        "ja4_o": "t13d1516h2_8daaf6152771_02713d6af862",
        "ja3": "THIS-MUST-BE-IGNORED",
        "validation_status": "ok", "established": "T",
    })
    assert row is not None
    assert row["ja4"] == "t130200_1302_234ea6891581"
    assert row["ja4_orig"].startswith("t13d1516h2")
    assert row["server_name"] == "c2.example.net"
    assert row["established"] == 1
    # ja4s is FoxIO License 1.1 and is not stored; a ja3 field must not be smuggled in.
    assert "ja4s" not in row
    assert "THIS-MUST-BE-IGNORED" not in str(row)


def test_map_zeek_notice():
    row = map_zeek_notice({
        "ts": "1", "uid": "N1", "src": "198.51.100.10", "dst": "198.51.100.99",
        "note": "Scan::Port_Scan", "msg": "198.51.100.10 scanned 100 ports",
        "sub": "100 ports", "actions": "Notice::ACTION_LOG", "suppress_for": "3600",
    })
    assert row["note"] == "Scan::Port_Scan"
    assert row["src_addr"] == "198.51.100.10"
    assert row["suppress_for"] == 3600.0


# --- file tailing ------------------------------------------------------------
# The conn field list Zeek emits, hoisted so the rotation tests and the older
# tests share one definition. Repeated inline copies drift.
_CONN_FIELDS = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                "proto", "service", "duration", "orig_bytes", "resp_bytes",
                "orig_pkts", "resp_pkts", "conn_state", "history"]


def _write_zeek_log(directory, name, records, extra_fields=None):
    """Write a Zeek TSV log named exactly `name` + `.log`.

    `name` is the full basename without the extension, so a ROTATED file is
    written by passing Zeek's real name ('conn.2026-09-15-00-00-00') and the live
    file by passing 'conn'. Getting this wrong is how the earlier suite ended up
    testing only `<type>.log` and never noticing that rotated files were never
    read.
    """
    path = os.path.join(directory, f"{name}.log")
    with open(path, "w") as fh:
        fh.write("#separator \\x09\n")
        fh.write("#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n")
        fh.write(f"#path\t{name}\n#open\t2026-09-15-00-00-00\n")
        fh.write("#fields\t" + "\t".join(extra_fields or []) + "\n")
        fh.write("#types\t" + "\t".join(["string"] * len(extra_fields or [])) + "\n")
        for rec in records:
            fh.write("\t".join(rec) + "\n")
    return path


def test_tail_zeek_conn_inserts_rows():
    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                  "proto", "service", "duration", "orig_bytes", "resp_bytes",
                  "orig_pkts", "resp_pkts", "conn_state", "history"]
        recs = [
            ["1789447100.0", "C1", "198.51.100.5", "5000", "8.8.8.8", "443", "tcp", "ssl",
             "1.0", "100", "200", "2", "3", "SF", "ShAD"],
            ["1789447101.0", "C2", "198.51.100.6", "5001", "1.1.1.1", "53", "udp", "dns",
             "0.1", "50", "60", "1", "1", "SF", "Dd"],
        ]
        path = _write_zeek_log(d, "conn", recs, fields)
        n, off, ino, _hdr = tail_zeek_log(fake, path, state=ZeekTailState())
        assert n == 2
        assert len(fake.tables["weirvern.zeek_conn"]) == 2
        assert fake.tables["weirvern.zeek_conn"][0][2] == "198.51.100.5"


def test_tail_zeek_log_no_duplicates_on_second_pass():
    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                  "proto", "service", "duration", "orig_bytes", "resp_bytes",
                  "orig_pkts", "resp_pkts", "conn_state", "history"]
        path = _write_zeek_log(d, "conn", [["1.0", "C1", "198.51.100.5", "1", "2.2.2.2", "80",
                                           "tcp", "http", "0", "1", "1", "1", "1", "SF", "h"]], fields)
        st = ZeekTailState()
        n1, _, _, _ = tail_zeek_log(fake, path, state=st)
        n2, _, _, _ = tail_zeek_log(fake, path, state=st)
        assert n1 == 1
        assert n2 == 0  # no duplicate re-ingest


def test_tail_zeek_log_holds_back_partial_line():
    """Same data-loss protection as the JSONL tailer, PLUS the cached header.

    A resumed Zeek read starts mid-file, so the `#fields` header is no longer in
    front of the data; without caching it the completed record is silently
    dropped (verified bug).
    """
    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                  "proto", "service", "duration", "orig_bytes", "resp_bytes",
                  "orig_pkts", "resp_pkts", "conn_state", "history"]
        path = _write_zeek_log(d, "conn", [], fields)
        with open(path, "a") as fh:
            fh.write("1.0\tC1\t198.51.100.5\t1\t2.2.2.2\t80\ttcp\thttp\t0\t1\t1\t1\t1\tSF\th\n")
            fh.write("2.0\tC2\t198.51.100.6\t2\t3.3")  # partial, no newline
        st = ZeekTailState()
        n1, _, _, _ = tail_zeek_log(fake, path, state=st)
        assert n1 == 1
        with open(path, "a") as fh:
            fh.write(".3.3\t80\ttcp\thttp\t0\t1\t1\t1\t1\tSF\th\n")
        n2, _, _, _ = tail_zeek_log(fake, path, state=st)
        assert n2 == 1, "completed record after partial write was lost"


def test_tail_zeek_dir_walks_relevant_logs():
    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        conn_fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
                       "proto", "service", "duration", "orig_bytes", "resp_bytes",
                       "orig_pkts", "resp_pkts", "conn_state", "history"]
        notice_fields = ["ts", "uid", "src", "dst", "note", "msg", "sub", "actions", "suppress_for"]
        _write_zeek_log(d, "conn", [["1.0", "C1", "198.51.100.5", "1", "2.2.2.2", "80",
                                     "tcp", "http", "0", "1", "1", "1", "1", "SF", "h"]], conn_fields)
        _write_zeek_log(d, "notice", [["1.0", "N1", "198.51.100.5", "198.51.100.9", "Scan::Port_Scan",
                                       "scanned", "s", "log", "3600"]], notice_fields)
        # an unrelated log type must be ignored
        _write_zeek_log(d, "weird", [["1.0", "W1"]], ["ts", "uid"])
        total, state = tail_zeek_dir(fake, d)
        assert total == 2
        assert "weirvern.zeek_conn" in fake.tables
        assert "weirvern.zeek_notice" in fake.tables
        assert "conn.log" in state
        # second pass, unchanged files -> nothing new
        total2, _ = tail_zeek_dir(fake, d, state)
        assert total2 == 0


def test_tail_zeek_dir_reads_rotated_files():
    """THE BUG THIS GUARDS: rotation naming.

    `_zeek_log_names` used to glob `<type>.1.log`, `<type>.2.log`, ... — a naming
    Zeek does not produce. Zeek names rotated files BY TIMESTAMP:

        Log::default_rotation_date_format = '%Y-%m-%d-%H-%M-%S'
        (scripts/base/frameworks/logging/main.zeek:170, used at :719)

    so `conn.1.log` never exists and the real files are
    `conn.2026-09-15-00-00-00.log`. With hourly rotation on a real sensor that
    meant the tailer read only the live file and almost every record was lost.

    Why the existing suite missed it: `_write_zeek_log` only ever creates
    `<name>.log`, so no test ever put a rotated file on disk. Hardcoding the
    function to match only `<type>.log` passed the whole suite. That is what made
    this mutation-blind, and it is why these tests use Zeek's real names.
    """
    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        fields = _CONN_FIELDS
        # Two rotated files and the live one, exactly as Zeek leaves them.
        _write_zeek_log(d, "conn.2026-09-15-00-00-00", [  # oldest
            ["1.0", "R1", "198.51.100.7", "1", "2.2.2.2", "80", "tcp", "http",
             "0", "1", "1", "1", "1", "SF", "h"]], fields)
        _write_zeek_log(d, "conn.2026-09-15-01-00-00", [
            ["2.0", "R2", "198.51.100.8", "1", "3.3.3.3", "80", "tcp", "http",
             "0", "1", "1", "1", "1", "SF", "h"]], fields)
        _write_zeek_log(d, "conn", [  # live
            ["3.0", "L1", "198.51.100.9", "1", "4.4.4.4", "80", "tcp", "http",
             "0", "1", "1", "1", "1", "SF", "h"]], fields)

        total, state = tail_zeek_dir(fake, d)

        assert total == 3, (
            f"expected 3 conn records across the rotated and live files, got "
            f"{total}; rotated logs named <type>.<timestamp>.log are being missed"
        )
        srcs = {row[2] for row in fake.tables["weirvern.zeek_conn"]}
        assert srcs == {"198.51.100.7", "198.51.100.8", "198.51.100.9"}
        # Every distinct file must be tracked separately, or a rotation would
        # resume at the wrong offset.
        assert len([k for k in state if k.startswith("conn.")]) == 3


def test_tail_zeek_dir_rotated_files_are_read_oldest_first():
    """Ordering matters for the anomaly windows: records must reach ClickHouse in
    timestamp order, or a window can close before late records land in it.

    Oldest is decided by NAME (the timestamp Zeek embedded), not by mtime, which
    is more reliable here: a copied or restored log directory keeps the name but
    not the original mtime.
    """
    fake = FakeCH()
    with tempfile.TemporaryDirectory() as d:
        fields = _CONN_FIELDS
        # Deliberately create them in an order that does NOT match their names,
        # and give the newest name the OLDEST mtime, so an mtime sort fails.
        _write_zeek_log(d, "conn.2026-09-15-02-00-00", [
            ["3.0", "C", "198.51.100.30", "1", "2.2.2.2", "80", "tcp", "http",
             "0", "1", "1", "1", "1", "SF", "h"]], fields)
        _write_zeek_log(d, "conn.2026-09-15-00-00-00", [
            ["1.0", "A", "198.51.100.10", "1", "2.2.2.2", "80", "tcp", "http",
             "0", "1", "1", "1", "1", "SF", "h"]], fields)
        _write_zeek_log(d, "conn.2026-09-15-01-00-00", [
            ["2.0", "B", "198.51.100.20", "1", "2.2.2.2", "80", "tcp", "http",
             "0", "1", "1", "1", "1", "SF", "h"]], fields)
        os.utime(os.path.join(d, "conn.2026-09-15-02-00-00.log"), (1000, 1000))

        total, _ = tail_zeek_dir(fake, d)
        assert total == 3
        order = [row[2] for row in fake.tables["weirvern.zeek_conn"]]
        assert order == ["198.51.100.10", "198.51.100.20", "198.51.100.30"], (
            f"rotated files must be read oldest-first by name, got {order}"
        )


def test_zeek_log_names_does_not_match_a_longer_type_prefix():
    """`conn` must not match `conn_summary.log`, and an unrelated type's rotated
    file must not match either. Both are silent-corruption bugs: the wrong
    mapper would be applied to the wrong header and every field would shift.
    """
    from weirvern.ingester import _zeek_log_names

    with tempfile.TemporaryDirectory() as d:
        for name in ["conn.log", "conn.2026-09-15-00-00-00.log",
                     "conn_summary.log", "conn_summary.2026-09-15-00-00-00.log",
                     "dns.log", "dns.2026-09-15-00-00-00.log",
                     "conn.log.json", "conn.2026-09-15-00-00-00.log.json"]:
            open(os.path.join(d, name), "w").close()

        got = set(_zeek_log_names(d, "conn"))
        assert got == {"conn.2026-09-15-00-00-00.log", "conn.log.json",
                       "conn.log", "conn.2026-09-15-00-00-00.log.json"}, got
        # The other type's files must not leak in.
        assert not any("summary" in n for n in got)
        assert not any(n.startswith("dns.") or n == "dns.log" for n in got)


def test_zeek_log_names_is_bounded_by_depth():
    """A directory that accumulated far more rotations than the retention window
    must not make one pass read unbounded files (the pass would eventually outlast
    the sweep interval). Depth keeps the working set finite.
    """
    from weirvern.ingester import _zeek_log_names

    with tempfile.TemporaryDirectory() as d:
        for i in range(30):
            open(os.path.join(d, f"conn.2026-09-15-{i:02d}-00-00.log"), "w").close()
        open(os.path.join(d, "conn.log"), "w").close()

        got = _zeek_log_names(d, "conn", depth=5)
        assert len(got) == 6, f"depth=5 should yield 5 rotated + 1 live, got {len(got)}"
        # The live file must always be included, however deep the trimming.
        assert "conn.log" in got


def test_mappers_cover_all_declared_tables():
    for log_type, (table, _) in ZEEK_MAPPERS.items():
        assert table.startswith("weirvern.zeek_")
        assert log_type in ZEEK_COLUMNS

