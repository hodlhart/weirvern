"""Every address the UI shows must carry a hostname where one can be resolved.

The rule the product states: a hostname is shown ALONGSIDE the source IP, never
instead of it. The IP is the fact an operator correlates against a firewall or a DHCP
lease; the name is the convenience. Dropping either one loses something.

These tests guard the second half of that rule, which is easier to get wrong than the
first: it is not enough to send a hostname for the ROW'S OWN host, because an analyst
reading the alert-evidence tables is looking at destinations. A column of bare IPs makes
them resolve addresses by hand, which is the work the UI exists to remove.
"""
from __future__ import annotations

import re
from pathlib import Path

WEB = Path(__file__).resolve().parent.parent / "weirvern" / "admin" / "web" / "app.js"
API = Path(__file__).resolve().parent.parent / "weirvern" / "admin" / "web_api.py"


def _hostcell_calls() -> list[tuple[int, str]]:
    """Every hostCell(...) call site with its line number and argument text."""
    src = WEB.read_text()
    out = []
    for m in re.finditer(r"hostCell\(([^)]*)\)", src):
        # Skip the definition itself.
        line_start = src.rfind("\n", 0, m.start()) + 1
        line = src[line_start:src.find("\n", m.start())]
        if "function hostCell" in line:
            continue
        out.append((src[:m.start()].count("\n") + 1, m.group(1)))
    return out


def test_every_host_cell_attempts_a_hostname():
    """A call that passes only an address can never show a name, so the row is IP-only
    even when reverse DNS would have resolved it."""
    calls = _hostcell_calls()
    assert calls, "no hostCell call sites found; did the renderer change shape?"
    bare = [(ln, args) for ln, args in calls if "," not in args]
    assert not bare, (
        f"these hostCell calls pass no hostname, so those rows can only ever show a "
        f"bare IP: {bare}"
    )


def test_the_api_resolves_destination_hostnames_for_evidence():
    """The evidence tables are read line by line, so their destinations need names. The
    API must provide them rather than relying on the browser."""
    src = API.read_text()
    assert "evidence_rows" in src, (
        "evidence_payload does not resolve destination hostnames; the flows and Zeek "
        "tables in the alert pivot would show bare IPs"
    )
    # And it must be used for BOTH address-bearing tables. Checked against the whole
    # module rather than a slice of it: an earlier version sliced from `def
    # evidence_payload` to the next `def`, which stopped at the NESTED `def rows` and
    # found zero uses -- a false failure caused by the test, not the code.
    whole = API.read_text()
    assert whole.count("evidence_rows(") >= 3, (
        f"expected a definition plus at least two call sites, found "
        f"{whole.count('evidence_rows(')}"
    )
    for table in ('"flows": evidence_rows(', '"zeek_conn": evidence_rows('):
        assert table in whole, f"{table.strip()} is missing, so that table shows bare IPs"


def test_the_drill_down_suppresses_a_self_referential_destination_label():
    """On a host drill-down every destination row is 'something this host talked to'.
    When the destination IS the host being viewed, repeating its name in every row is
    noise; `sameAs` reduces those to the plain IP while leaving other destinations
    fully labelled."""
    src = WEB.read_text()
    assert "sameAs" in src, "hostCell has no self-reference suppression"
    # The drill-down destination column must pass it.
    drill = [ln for ln, args in _hostcell_calls() if "d.src_addr" in args]
    assert drill, "the drill-down destination column does not pass sameAs"


def test_hostname_never_replaces_the_ip():
    """The stated rule, asserted directly: an address is always rendered somewhere, even
    when a hostname is present."""
    src = WEB.read_text()
    fn = src[src.find("function hostCell"):]
    fn = fn[:fn.find("\n}")]
    assert "el(\"span\", { class: \"ip\", text: addr })" in fn, (
        "hostCell no longer renders the IP alongside the name"
    )
    # The no-hostname path must still render the address rather than an empty cell.
    assert 'class: "host"' in fn and "text: addr" in fn


def test_host_cell_escapes_via_the_el_helper_not_innerHTML():
    """Hostnames come from DNS, which an attacker on the LAN can answer. Building rows
    with innerHTML would let a crafted PTR record run script in the analyst's browser at
    the moment they are investigating that host."""
    src = WEB.read_text()
    fn = src[src.find("function hostCell"):]
    fn = fn[:fn.find("\n}")]
    assert "innerHTML" not in fn, "hostCell builds HTML from a DNS-derived string"
    assert "el(" in fn
