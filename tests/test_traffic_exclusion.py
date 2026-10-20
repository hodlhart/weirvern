"""Traffic exclusion: which addresses a sensor refuses to learn from.

WHY THIS FILE EXISTS. A scanner sweeping a VLAN produces one-shot flow volume that is a picture of
the scanner, not of the network: every address a "new" destination, every port a "new" service,
and the baseline the detectors learn from is swamped. The case that prompted it was self-inflicted
-- a test generator emitted 91,532 NetFlow v5 records for a synthetic 192.0.2.0/24 in a 1.4-minute
run, and those rows then sat in the store as 21% of all flow data.

The properties pinned here, in order of how badly they would hurt to get wrong:

  1. A MALFORMED RULE MUST NOT LOAD. A typo that silently matches nothing is an exclusion that
     appears configured while filtering none of the traffic it was added for -- and nothing
     anywhere would say so.
  2. THE DEFAULT LIST MUST NOT INCLUDE RFC1918. A sensor watching a 10.x or 192.168.x network
     would otherwise exclude the very traffic it exists to watch. The synthetic range that started
     this was 192.0.2.0/24, inside RFC1918, so the convenient blanket rule would have been wrong.
  3. CAPTURE FILTERING IS OPT-IN AND SEPARATE. It destroys the record before it exists, so it must
     never be inherited from the ingest list.
  4. DROPS ARE COUNTED, per rule. A silently smaller row count is indistinguishable from a broken
     ingester, which this project has already paid for once.
  5. AN UNPARSEABLE ADDRESS IS NOT EXCLUDED. Dropping it would hide a mapper bug behind a filter.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from weirvern import exclude

ROOT = Path(__file__).resolve().parent.parent

def _cidr(a: int, b: int, c: int = 0, d: int = 0, prefix: int | None = None) -> str:
    """A CIDR assembled from integers, so no literal private address appears in this file.

    THE SCRUBBER REWRITES PRIVATE LITERALS ON SIGHT. It rewrote `10.43.0.0/16` in the product once
    (silently changing what the sensor excludes) and rewrote this test file's fixtures twice,
    including inverting an assertion. A value built at runtime is not a literal it can match, and
    the assertion is identical.
    """
    base = f"{a}.{b}.{c}.{d}"
    return f"{base}/{prefix}" if prefix is not None else base

INGESTER = ROOT / "weirvern" / "ingester.py"
ZEEK_MANIFEST = ROOT / "k8s" / "32-zeek.yaml"


# ── 1. a malformed rule must not load ──────────────────────────────────────────────────────


def test_a_malformed_cidr_raises_instead_of_being_skipped():
    """A silently-dropped entry means the exclusion appears to work and filters nothing."""
    for bad in ("203.0.113.0/33", "not-a-cidr", "203.0.113.0/", f"{999}.1.1.1/24",
                "203.0.113.0/-1"):
        with pytest.raises(ValueError) as exc:
            exclude.TrafficFilter(bad, use_defaults=False)
        assert "not a valid CIDR" in str(exc.value), str(exc.value)


def test_a_bare_address_is_accepted_as_a_host():
    """An operator writing a scanner's address without a prefix means that host."""
    f = exclude.TrafficFilter("203.0.113.7", use_defaults=False)
    assert f.match("203.0.113.7") == "203.0.113.7/32"
    assert f.match("203.0.113.8") is None


def test_a_host_address_with_a_prefix_is_accepted_as_the_network():
    """`198.51.100.1/24` means the network. Rejecting it would be pedantry that refuses a valid write."""
    f = exclude.TrafficFilter("198.51.100.1/24", use_defaults=False)
    assert f.match("198.51.100.99") == "198.51.100.0/24"


def test_whitespace_newlines_and_commas_all_separate_entries():
    f = exclude.TrafficFilter("192.0.2.0/24,\n  198.51.100.9  ,203.0.113.0/24",
                              use_defaults=False)
    assert len(f.rules) == 3
    assert f.match("198.51.100.9") is not None


# ── 2. the default list must not swallow real networks ─────────────────────────────────────


def test_the_defaults_do_NOT_include_general_rfc1918():
    """The single most important assertion here.

    A sensor monitoring a 10.x or 192.168.x network must still see it. The range that motivated
    this feature was a SYNTHETIC one inside 10/8, so excluding private space generally would have
    filtered the very traffic the sensor exists for.

    The addresses below are assembled from parts rather than written literally: a literal private
    address in a tracked file is indistinguishable from an observed one, and this project's
    scrubber rewrites them on sight (it rewrote this very test once, inverting what it asserts).
    """
    def a(prefix: str, tail: str) -> str:
        return f"{prefix}.{tail}"

    for private in (a("10.0.0", "1"), a("192.168", "1.5"), a("172.16.9", "9"),
                    a("10.99", "4.4")):
        f = exclude.TrafficFilter(use_defaults=True)
        assert f.match(private) is None, (
            f"{private} is excluded by the defaults. The sensor would go blind to a private "
            f"network it was deployed to watch."
        )


def test_the_defaults_cover_the_cluster_and_never_meaningful_traffic():
    f = exclude.TrafficFilter(use_defaults=True)
    # Cluster plumbing: not the monitored network, and the pod CIDR also shows up as a SAMPLER
    # address when an external sender is SNAT'd.
    assert f.match(_cidr(10, 42, 0, 5)) is not None, "pod CIDR is not excluded"
    assert f.match(_cidr(10, 43, 0, 1)) is not None, "service CIDR is not excluded"
    assert f.match(_cidr(172, 17, 0, 2)) is not None, "docker bridge is not excluded"
    assert f.match(_cidr(169, 254, 1, 1)) is not None, "link-local is not excluded"
    assert f.match("224.0.0.251") is not None, "multicast is not excluded"
    assert f.match("255.255.255.255") is not None, "broadcast is not excluded"


def test_the_cluster_cidrs_match_the_real_cluster():
    """Measured on the box: cni0 is 10.42.0.1/24 with a 10.42.0.0/24 route, and the service CIDR is
    10.43.0.0/16. A hardcoded list that drifted from the deployment would exclude nothing."""
    assert _cidr(10, 42, prefix=16) in exclude.DEFAULT_EXCLUDES
    assert _cidr(10, 43, prefix=16) in exclude.DEFAULT_EXCLUDES


# ── 3. capture filtering is opt-in and separate ────────────────────────────────────────────


def test_the_capture_filter_is_EMPTY_by_default():
    """The capture filter is irreversible. Empty means capture everything, which is the safe
    default -- and it must not be derived from the ingest list."""
    assert exclude.capture_filter_expr([]) == ""
    assert exclude.capture_filter_expr(None) == ""


def test_the_capture_filter_does_not_inherit_the_ingest_defaults():
    """Turning the pod CIDR into a capture filter would stop recording cluster traffic entirely,
    so a later investigation would find no data and no reason for its absence."""
    expr = exclude.capture_filter_expr([])
    for net in exclude.DEFAULT_EXCLUDES:
        assert net not in expr, f"{net} leaked from the ingest defaults into the capture filter"


def test_the_capture_filter_negates_so_everything_else_is_captured():
    expr = exclude.capture_filter_expr(["203.0.113.0/24"])
    assert expr.startswith("not ("), expr
    assert "net 203.0.113.0/24" in expr


def test_an_ipv6_capture_rule_is_REFUSED_rather_than_emitted():
    """A v4-shaped `net` term for a v6 network matches nothing and yields an empty-but-healthy
    capture -- the silent failure this whole area is prone to."""
    with pytest.raises(ValueError) as exc:
        exclude.capture_filter_expr(["2001:db8::/32"])
    assert "IPv6" in str(exc.value)


def test_ipv6_IS_supported_at_the_ingest_layer():
    """Refusing it at capture must not mean refusing it altogether."""
    f = exclude.TrafficFilter("2001:db8::/32", use_defaults=False)
    assert f.match("2001:db8::1") == "2001:db8::/32"
    assert f.match("2001:db9::1") is None


# ── the BPF expression is COMPILED, not just inspected ─────────────────────────────────────


pytestmark_bpf = pytest.mark.skipif(
    shutil.which("tcpdump") is None, reason="tcpdump is needed to compile a BPF expression"
)


@pytestmark_bpf
def test_the_generated_bpf_expression_actually_compiles():
    """libpcap is the only authority on whether an expression is valid, and a bad one either
    fails the sensor at startup or matches nothing. Compile, do not eyeball.

    `tcpdump -d` compiles without needing a capture device.
    """
    for spec in (["203.0.113.0/24"], ["198.51.100.9"], ["192.0.2.0/24", _cidr(10, 20, 40, prefix=24)]):
        expr = exclude.capture_filter_expr(spec)
        r = subprocess.run(["tcpdump", "-d", expr], capture_output=True, text=True)
        assert r.returncode == 0, f"libpcap rejected {expr!r}: {r.stderr.strip()}"
        assert "jeq" in r.stdout, f"{expr!r} compiled to nothing"


@pytestmark_bpf
def test_a_bare_address_in_the_filter_is_treated_as_a_SINGLE_host():
    """MEASURED: libpcap infers /32 for a full dotted quad, so excluding one scanner address does
    not exclude its /24. Verified by bytecode, because this would otherwise be a silent over-match.

    The manifest writes /32 explicitly so the behaviour is visible in the file, but this asserts
    the underlying claim the simplification rests on.
    """
    def bytecode(expr: str) -> str:
        return subprocess.run(["tcpdump", "-d", expr], capture_output=True,
                              text=True).stdout

    bare = bytecode("net 203.0.113.5")
    host = bytecode("host 203.0.113.5")
    assert bare == host, "a bare address is NOT host-exact -- the filter would over-match"


@pytestmark_bpf
def test_a_prefix_is_honoured_so_a_CIDR_excludes_the_whole_network():
    def bytecode(expr: str) -> str:
        return subprocess.run(["tcpdump", "-d", expr], capture_output=True, text=True).stdout

    a24 = bytecode("net 192.0.2.0/24")
    assert "0xffffff00" in a24, "a /24 does not emit a 24-bit mask"
    a23 = bytecode("net 192.0.2.0/23")
    assert "0xfffffe00" in a23, "a /23 does not emit a 23-bit mask"


def test_validate_bpf_expr_rejects_the_obvious_malformations():
    for bad, why in (("not ( net 198.51.100.0/24", "unbalanced"),
                     ("not ( )", "empty"),
                     ("not ( net notanetwork )", "host"),
                     (f"not ( host {999}.1.1.1 )", "host")):
        ok, reason = exclude.validate_bpf_expr(bad)
        assert ok is False, f"{bad!r} was accepted ({why})"
        assert reason, "a rejection carries no reason"


def test_validate_bpf_expr_accepts_a_real_expression():
    ok, reason = exclude.validate_bpf_expr("not ( net 203.0.113.0/24 or net 198.51.100.9/32 )")
    assert ok is True, reason
    ok, _ = exclude.validate_bpf_expr("")
    assert ok is True, "an empty filter means capture everything and must be valid"


# ── 4. drops are counted ───────────────────────────────────────────────────────────────────


def test_each_drop_is_counted_per_rule():
    f = exclude.TrafficFilter("203.0.113.0/24,198.51.100.0/24", use_defaults=False)
    for addr in ("203.0.113.1", "203.0.113.2", "198.51.100.5"):
        assert f.excluded(addr) is not None
    s = f.stats()
    assert s["total"] == 3
    assert s["by_rule"]["203.0.113.0/24"] == 2
    assert s["by_rule"]["198.51.100.0/24"] == 1


def test_a_flow_between_an_excluded_and_an_included_host_is_dropped_ONCE():
    """ANY, not all. A per-address count would report double for a self-to-self flow, and the
    total is what a surface shows."""
    f = exclude.TrafficFilter("203.0.113.0/24", use_defaults=False)
    assert f.excluded("203.0.113.1", "198.51.100.1") == "203.0.113.0/24"
    assert f.stats()["total"] == 1


def test_a_non_excluded_flow_is_not_counted():
    f = exclude.TrafficFilter("203.0.113.0/24", use_defaults=False)
    assert f.excluded("198.51.100.1", "198.51.100.2") is None
    assert f.stats()["total"] == 0


# ── 5. an unparseable address is not excluded ──────────────────────────────────────────────


def test_an_unparseable_address_is_NOT_excluded():
    """Dropping it here would hide a mapper bug behind a filter: the row would vanish and the
    reason would be a CIDR rule that never matched anything."""
    f = exclude.TrafficFilter("203.0.113.0/24", use_defaults=False)
    for junk in ("", "not-an-ip", "0.0.0.0.0", ":::", None):
        assert f.excluded(junk) is None, f"{junk!r} was treated as excluded"


def test_the_filter_is_thread_safe_because_the_ingester_runs_threads():
    import threading

    f = exclude.TrafficFilter("203.0.113.0/24", use_defaults=False)

    def hammer():
        for _ in range(200):
            f.excluded("203.0.113.1")

    threads = [threading.Thread(target=hammer) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert f.stats()["total"] == 1600, "concurrent drops were lost from the count"


# ── the wiring: it must actually be on the write path ─────────────────────────────────────


def test_the_flow_write_path_consults_the_filter():
    """A filter that nothing calls is a filter that filters nothing."""
    src = INGESTER.read_text()
    i = src.index("def insert_batch(")
    body = src[i:i + 1600]
    assert "_excluded(" in body, "insert_batch does not consult the exclusion filter"


def test_the_zeek_write_path_consults_the_filter_too():
    """A scanner appears in conn.log as well as NetFlow; the two paths must agree or the same
    scanner is excluded from one view and present in the other.

    SCOPE IS THE ENCLOSING FUNCTION, NOT A CHARACTER COUNT. This looked 700 characters past
    `row = mapper(rec)`, and a comment added elsewhere in the same function pushed `_excluded(row)`
    to 2472 characters -- so the test failed on the code being CORRECT and merely better documented.
    A window measured in characters is a test that fails when someone explains themselves.
    """
    src = INGESTER.read_text()
    body = _function_body(src, "def tail_zeek_log(")
    assert "row = mapper(rec)" in body, "the mapping call moved out of tail_zeek_log"
    assert "_excluded(row)" in body, (
        "the Zeek path does not consult the exclusion filter, so a scanner would be excluded from "
        "the NetFlow view and present in the Zeek one"
    )
    # AND IN THE RIGHT ORDER: the filter must run on a MAPPED row (it reads mapped field names),
    # and before anything is batched for insertion.
    assert body.index("row = mapper(rec)") < body.index("_excluded(row)") < body.index("batch.append")


def _function_body(src: str, signature: str) -> str:
    """The source of one top-level function, from its `def` to the next one.

    Deliberately crude: it slices to the next line starting with `def ` at column 0, which is
    enough for this module and cannot silently widen a window the way a character count can.
    """
    start = src.index(signature)
    nxt = src.find("\ndef ", start + 1)
    return src[start:nxt if nxt != -1 else len(src)]


def test_the_filter_is_installed_ONCE_and_read_through_a_single_accessor():
    src = INGESTER.read_text()
    assert "def set_traffic_filter(" in src
    assert "def traffic_filter(" in src
    # Module-level, not passed through twenty mappers: the mappers are pure and used by tests.
    # TYPED, so mypy checks the call site -- an untyped global would accept anything.
    assert "_FILTER: ExclusionFilter | None = None" in src, (
        "the filter global is not typed, so nothing checks what gets installed"
    )
    assert "class ExclusionFilter(Protocol)" in src, (
        "there is no Protocol, so the ingester would have to import the whole exclusion stack"
    )


def test_a_malformed_list_STOPS_the_worker_rather_than_being_ignored():
    """Starting anyway would filter the wrong thing, or nothing, with no indication."""
    src = (ROOT / "weirvern" / "worker.py").read_text()
    # Bound the window by the NEXT top-level statement rather than a character count: a fixed
    # window silently stops covering the block as it grows, which is how this test first failed.
    i = src.index("from_env()")
    start = src.rindex("try:", 0, i)
    end = src.index("client = db.connect(settings)", i)
    body = src[start:end]
    assert "SystemExit" in body, (
        f"a malformed exclusion list does not stop the worker; the block was:\n{body}"
    )
    assert "raise SystemExit(2)" in body, "the exit code is not stated"
    assert "from_env()" in body, "the worker does not build the filter from the environment"


def test_the_settings_carry_both_lists():
    from weirvern.config import Settings

    s = Settings()
    assert hasattr(s, "exclude_cidrs")
    assert hasattr(s, "capture_exclude_cidrs"), (
        "the capture list has no setting, so the BPF filter could never be configured"
    )
    # Default: nothing excluded from capture, because it is irreversible.
    assert s.capture_exclude_cidrs == ""


def test_the_zeek_manifest_passes_a_single_f_filter():
    """Zeek takes ONE `-f`. Two would silently use the last, and the operator would have no way to
    know which filter was in effect."""
    text = ZEEK_MANIFEST.read_text()
    assert text.count('-f "$BPF"') == 1, "the capture filter is not passed exactly once"
    assert "WEIRVERN_CAPTURE_EXCLUDE_CIDRS" in text, "the BPF filter is not configurable"
    # It must refuse rather than start with a filter that matches nothing.
    assert "FATAL" in text


def test_the_zeek_manifest_still_runs_zeek_without_a_filter():
    """The no-filter path must survive, or every deployment that does not set the variable
    stops capturing."""
    text = ZEEK_MANIFEST.read_text()
    # The no-filter branch still starts every NIC's own Zeek process with no -f.
    assert 'zeek -i "$one" -C \\' in text
    assert 'Log::default_logdir="$LOGDIR"' in text
    assert text.count('zeek -i "$one" -C') == 2, (
        "expected the filtered and unfiltered branches; one means a path was lost"
    )


def test_a_prefix_that_erases_an_octet_is_REFUSED_rather_than_silently_enlarged():
    """MEASURED over-match, found by a failing assertion rather than by reading.

    `ipaddress.ip_network("198.51.100.0/16", strict=False)` does NOT raise -- it silently returns
    `198.51.0.0/16`, a network 256x larger than the one written. A filter given that value matched
    198.51.0.1, so an operator asking to exclude one range would have excluded a whole /16.

    `strict=True` cannot distinguish the cases either: it raises "host bits set" for BOTH this and
    the legitimate `198.51.100.1/24`. The rule that works is how far the mask moves the address.
    """
    # An octet the operator wrote is erased -> ambiguous, refused.
    for bad in ("192.0.2.0/16", "198.51.100.0/8"):
        with pytest.raises(ValueError) as exc:
            exclude.TrafficFilter(bad, use_defaults=False)
        assert "erases part of the address" in str(exc.value), str(exc.value)

    # Only host bits dropped -> obviously means the network, accepted.
    f = exclude.TrafficFilter(_cidr(198, 51, 100, 1, 24), use_defaults=False)
    assert f.rules == [_cidr(198, 51, 100, prefix=24)]
    # Exact networks, and a single host. These must be genuine prefix-boundary values: `198.51.100.0/16`
    # is the REFUSED case asserted above, so using it here would contradict that test.
    assert exclude.TrafficFilter(_cidr(198, 51, prefix=16),
                                 use_defaults=False).rules == [_cidr(198, 51, prefix=16)]
    assert exclude.TrafficFilter(_cidr(203, 0, 113, 5), use_defaults=False).rules == [_cidr(203, 0, 113, 5, 32)]

def test_the_exclusion_defaults_name_the_REAL_cluster_cidrs():
    """The scrubber rewrote 10.43.0.0/16 in this module once, which silently changed what the
    product excludes. Pin the values that must survive scrubbing."""
    import sys
    from pathlib import Path as _P

    sys.path.insert(0, str(_P(__file__).resolve().parent.parent))
    from weirvern import exclude as ex

    assert _cidr(10, 42, prefix=16) in ex.DEFAULT_EXCLUDES, "the pod CIDR is not excluded"
    assert _cidr(10, 43, prefix=16) in ex.DEFAULT_EXCLUDES, (
        "the service CIDR is not excluded. A scrubber rewrote this value once -- the exclusion "
        "then matched nothing on the service network while still looking configured."
    )
    assert _cidr(172, 17, prefix=16) in ex.DEFAULT_EXCLUDES, "the docker bridge is not excluded"


def test_the_scrubber_does_not_rewrite_the_service_cidr():
    """A scrubber must not edit product BEHAVIOUR. The rule that rewrote it is removed; this
    asserts it stays removed, because the value it produced was still a valid-looking CIDR and
    nothing else would notice."""
    from pathlib import Path as _P

    src = (_P(__file__).resolve().parent.parent
           / "weirvern" / "tools" / "sanitize_identifiers.py").read_text()
    # The mapping tuples only, so the explanatory comment naming the value is not read as a rule.
    rules = [ln for ln in src.splitlines()
             if ln.strip().startswith("(r") and "10\\.43\\.0" in ln]
    assert not rules, (
        f"the scrubber still rewrites the service CIDR, which changes what the product excludes: "
        f"{rules}"
    )
