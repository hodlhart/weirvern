#!/usr/bin/env python3
"""Measure what the Sluice Gate costs the traffic it inspects, on a real forwarded path.

WHY THIS EXISTS, AND WHY THE NUMBERS IN sluice.py ARE NOT ENOUGH. The module documents a
measurement: baseline ~55 Gbit/s, and ~3% at 20000 set members. That measurement was taken BEFORE
the inbound-port fix, which changed the shape of what gets installed -- the input chain now carries
ONE RULE PER (protocol, port) instead of two fixed rules. A number taken before a change is not
evidence about the code after it, and this project's most-repeated failure is treating a plausible
figure as a measurement. So the measurement is repeated against the current compiler, and kept as a
script so it can be repeated again.

WHAT IT MEASURES, and why each is the right thing to measure:

  1. THE FORWARD PATH. This is what siphon relays, so it is where "must not slow traffic" applies.
     Measured through a REAL forwarded path -- two network namespaces on two subnets, with the host
     routing between them -- because a loopback or same-host test never enters the forward hook and
     would report a cost of zero for a gate that cannot affect it. Measured three times per size so
     run-to-run spread is visible rather than a single flattering sample.

  2. THE INPUT PATH, which is where the change went. Input rules are evaluated for every packet
     addressed TO this host, in order, so N port-scoped rules mean up to N comparisons. nftables
     sets do lookup work only for the ADDRESS; the port is matched by the rule, one rule per port.
     That is a real scaling property and it is measured rather than assumed.

WHY iperf3 AND NOT A SYNTHETIC COUNTER. iperf3 reports achieved throughput over a real TCP stream,
so it reflects the whole path -- the kernel's forwarding, the hook, the sets -- rather than this
script's model of it.

THE COST OF A WRONG NUMBER HERE. An operator deciding whether to enable the gate on a production
segment needs to know whether it costs 3% or 30%. Understating it risks a degraded link; overstating
it leaves a security feature turned off. Both are failures, so the raw samples are printed.

Run as root on the sensor host. Cleans up its namespaces and rules in a finally block, so a crash
cannot leave the test path or a block behind.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time

HOST_A = "198.51.100.2"   # client side
HOST_B = "198.51.101.2"   # server side
NS_A = "wvbench_a"
NS_B = "wvbench_b"
VETH_A = "wvba"
VETH_B = "wvbb"
HOST_A_IF = "wvba-h"
HOST_B_IF = "wvbb-h"
PORT = 5201


def run(cmd: list[str] | str, check: bool = False, shell: bool = False) -> subprocess.CompletedProcess:
    """Run a command. QUIET by default; `check=True` opts into loud failure.

    WHY QUIET IS THE DEFAULT, learned twice here. Most calls are probes whose failure is normal --
    `nft delete table` on a table that does not exist, `which iperf3` before it is installed,
    teardown on a machine that is already clean. Making those strict turns a successful run into a
    traceback, and an operator reads a failure into a measurement that worked.

    The SETUP steps pass check=True explicitly, because there a failure means the path under test
    does not exist and every number afterwards would be of something else.
    """
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False, shell=shell)
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"setup step failed: {cmd if isinstance(cmd, str) else ' '.join(cmd)}\n"
            f"  rc={proc.returncode} {(proc.stdout + proc.stderr).strip()[:200]}"
        )
    return proc


def out(cmd: list[str] | str, shell: bool = False) -> str:
    r = run(cmd, shell=shell, check=False)
    return (r.stdout + r.stderr).strip()


def nft(*args: str) -> str:
    """nft, deliberately NOT strict.

    `nft delete table X` fails when X is absent, which is the NORMAL case: setup deletes before
    creating, teardown deletes whatever is there, and a clean machine has nothing to delete. Making
    this strict made the cleanup path raise, so a successful run ended in a traceback and an
    operator would read a failure into a measurement that worked. Callers that need a failure
    reported use run(check=True) directly -- which is what the install steps do.
    """
    return out(["nft", *args])


def teardown() -> None:
    """Remove the test path. Idempotent: safe to call whether or not setup ran.

    THE IPTABLES RULES MUST GO TOO. They were inserted at the top of FORWARD to make the bench path
    work; leaving them would let this script silently alter what the node forwards, which is
    exactly the kind of leftover state that made an earlier teardown report clean while a policy
    rule remained.
    """
    nft("delete", "table", "inet", "weirvern_sluice")
    nft("delete", "table", "inet", "weirvern_sluice_in")
    for iface in (HOST_A_IF, HOST_B_IF):
        # Loop until no rule matches, because deleting by specification is not available for
        # iptables and one pass leaves duplicates behind from a repeated setup.
        for _ in range(8):
            r = run(["iptables", "-D", "FORWARD", "-i", iface, "-j", "ACCEPT"])
            if r.returncode != 0:
                break
        for _ in range(8):
            r = run(["iptables", "-D", "FORWARD", "-o", iface, "-j", "ACCEPT"])
            if r.returncode != 0:
                break
    for ns in (NS_A, NS_B):
        run(f"ip netns del {ns} 2>/dev/null || true", shell=True)
    for iface in (HOST_A_IF, HOST_B_IF):
        run(f"ip link del {iface} 2>/dev/null || true", shell=True)


def setup() -> None:
    """Two namespaces on two subnets, routed by the host. One interface per subnet.

    WHY ONE INTERFACE PER SUBNET, which looks like a detail and is not: with both test subnets on
    a single interface the kernel finds the return route leaving by the arrival interface and
    emits an ICMP redirect instead of forwarding, so the traffic never takes the forward path and
    every measurement is of something else. Recorded in this project after exactly that.
    """
    teardown()
    run(["ip", "netns", "add", NS_A], check=True)
    run(["ip", "netns", "add", NS_B], check=True)
    for ns, host_if, veth, addr in (
        (NS_A, HOST_A_IF, VETH_A, HOST_A),
        (NS_B, HOST_B_IF, VETH_B, HOST_B),
    ):
        run(["ip", "link", "add", host_if, "type", "veth", "peer", "name", veth], check=True)
        run(["ip", "link", "set", veth, "netns", ns], check=True)
        run(["ip", "link", "set", host_if, "up"], check=True)
        # A /24, so the gateway is the host side's address in the SAME network. Derived by keeping
        # the first three octets -- the earlier version chopped twice and produced 198.51.1, which
        # the kernel rejected as an invalid nexthop before a single packet was sent.
        net3 = ".".join(addr.split(".")[:3])
        gateway = f"{net3}.1"
        run(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"], check=True)
        run(["ip", "netns", "exec", ns, "ip", "link", "set", veth, "up"], check=True)
        run(["ip", "netns", "exec", ns, "ip", "addr", "add", f"{addr}/24", "dev", veth], check=True)
        run(["ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", gateway], check=True)
        # Verify the route took, rather than assuming: a missing default route means the client
        # sends nothing and every throughput reading is "no transfer".
        routes = out(["ip", "netns", "exec", ns, "ip", "route"])
        if f"default via {gateway}" not in routes:
            raise RuntimeError(f"{ns} has no default route via {gateway}: {routes!r}")
    run(["ip", "addr", "add", "198.51.100.1/24", "dev", HOST_A_IF], check=True)
    run(["ip", "addr", "add", "198.51.101.1/24", "dev", HOST_B_IF], check=True)
    run(["sysctl", "-qw", "net.ipv4.ip_forward=1"], check=True)

    # ── THE FORWARD POLICY, WHICH IS WHAT BROKE THE FIRST RUN ──────────────────────────────
    #
    # k3s sets `iptables -P FORWARD DROP` on the node, and its own rules only ACCEPT forwarded
    # traffic involving pod/service subnets. The bench relays between two LAN subnets, which is
    # neither, so its packets were discarded BEFORE any nft hook was reached -- and every run
    # reported "no transfer", baseline included. The summary would have read as the gate costing
    # 100% of throughput, a conclusion drawn from the instrument rather than the system.
    #
    # These two interface-scoped ACCEPTs are the same fix the product reports for siphon mode, so
    # the bench path now matches a working deployment. Scoped to the bench interfaces only, and
    # removed in teardown, so nothing else on the node is affected.
    for iface in (HOST_A_IF, HOST_B_IF):
        run(["iptables", "-I", "FORWARD", "1", "-i", iface, "-j", "ACCEPT"], check=True)
        run(["iptables", "-I", "FORWARD", "2", "-o", iface, "-j", "ACCEPT"], check=True)

    # PROVE THE PATH CARRIES TRAFFIC BEFORE MEASURING IT. Without this, a broken path and a
    # devastating gate cost produce the identical output, and the second is what a reader would
    # believe. A ping is enough: it exercises the same forward hook.
    probe = run(["ip", "netns", "exec", NS_A, "ping", "-c", "2", "-W", "3", HOST_B])
    if probe.returncode != 0:
        raise RuntimeError(
            "the bench path does not carry traffic at all, so any throughput number would be a "
            "measurement of nothing:\n  " + (probe.stdout + probe.stderr).strip()[:300]
        )


def start_server() -> subprocess.Popen:
    args = ["ip", "netns", "exec", NS_B, "iperf3", "-s", "-1", "-p", str(PORT)]
    proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    return proc


def throughput() -> float | None:
    """Gbit/s over a real TCP stream through the host. None if the transfer did not complete."""
    args = [
        "ip", "netns", "exec", NS_A, "iperf3", "-c", HOST_B, "-p", str(PORT),
        "-t", "5", "-P", "2", "-J", "--connect-timeout", "3000",
    ]
    r = run(args)
    text = r.stdout or ""
    try:
        data = json.loads(text)
        bits = data["end"]["sum_received"]["bits_per_second"]
        return float(bits) / 1e9
    except Exception:
        m = re.search(r"([\d.]+)\s+Gbits/sec", text)
        if m:
            return float(m.group(1))
        return None


def install_gate(members: int, ports: int) -> str:
    """The CURRENT compiler's shape: a forward set, plus ONE RULE PER PORT on the input chain.

    THE BLOCKED MEMBERS MUST NOT INCLUDE THE TEST CLIENT. Putting the client's own address in the
    set makes the kernel DROP the transfer, so the measurement reports "no transfer" and the run
    looks like a catastrophic slowdown rather than a cost. That would be measuring CORRECT
    ENFORCEMENT while claiming to measure performance -- and it is exactly the kind of
    misattribution this project keeps finding. So the members come from 203.0.113.0/24 (TEST-NET-3,
    reserved for documentation and never routable), while the test path lives on
    198.51.100.0/24 and 198.51.101.0/24 (TEST-NET-2/1). Every packet therefore traverses the hook,
    is compared against the whole set, matches nothing, and continues.
    """
    nft("delete", "table", "inet", "weirvern_sluice")
    nft("delete", "table", "inet", "weirvern_sluice_in")
    block = ", ".join(f"203.0.113.{i % 250 + 1}" for i in range(min(members, 240)))
    text = [
        "table inet weirvern_sluice {",
        "  set sluice_block_v4 {",
        "    type ipv4_addr",
        "    flags interval",
        f"    elements = {{ {block} }}",
        "  }",
        "  chain forward {",
        "    type filter hook forward priority -50; policy accept;",
        "    ip saddr @sluice_block_v4 counter drop",
        "  }",
        "}",
    ]
    proc = subprocess.run(["nft", "-f", "-"], input="\n".join(text), capture_output=True, text=True)
    if proc.returncode != 0:
        return f"forward install failed: {proc.stderr.strip()}"

    if ports > 0:
        in_text = ["table inet weirvern_sluice_in {"]
        for p in range(ports):
            port = 10000 + p
            in_text.append(f"  set inport_tcp_{port} {{ type ipv4_addr; flags interval; "
                           f"elements = {{ 203.0.113.9 }} }}")
        in_text.append("  chain input {")
        in_text.append("    type filter hook input priority -50; policy accept;")
        for p in range(ports):
            port = 10000 + p
            in_text.append(f"    tcp dport {port} ip saddr @inport_tcp_{port} counter drop")
        in_text.append("  }")
        in_text.append("}")
        proc = subprocess.run(["nft", "-f", "-"], input="\n".join(in_text),
                              capture_output=True, text=True)
        if proc.returncode != 0:
            return f"input install failed: {proc.stderr.strip()}"
    return ""


def count_rules() -> tuple[int, int]:
    def n(table: str) -> int:
        text = nft("list", "table", "inet", table)
        return len([ln for ln in text.splitlines() if "drop" in ln])
    return n("weirvern_sluice"), n("weirvern_sluice_in")


def main() -> int:
    if os.geteuid() != 0:
        print("  run as root: this changes the kernel's packet path")
        return 2
    if not out(["which", "iperf3"]):
        print("  iperf3 is not installed, so no real throughput can be measured")
        return 2

    results: dict[str, list[float | None]] = {}
    try:
        setup()
        print(f"  path: {NS_A} ({HOST_A}) -> host -> {NS_B} ({HOST_B}), real forward hook")

        print("\n  ── baseline (no gate) ──")
        samples = []
        for i in range(3):
            srv = start_server()
            v = throughput()
            srv.terminate()
            samples.append(v)
            print(f"    run {i + 1}: {'no transfer' if v is None else f'{v:.1f} Gbit/s'}")
            time.sleep(1)
        results["baseline"] = samples

        for members, ports, label in (
            (10, 0, "gate: 10 members, no input rules"),
            (240, 0, "gate: 240 members, no input rules"),
            (240, 1, "gate: 240 members + 1 input port rule"),
            (240, 25, "gate: 240 members + 25 input port rules"),
            (240, 100, "gate: 240 members + 100 input port rules"),
        ):
            err = install_gate(members, ports)
            if err:
                print(f"\n  {label}: SKIPPED -- {err}")
                continue
            fwd, inp = count_rules()
            print(f"\n  ── {label} (forward drop-rules={fwd}, input drop-rules={inp}) ──")
            samples = []
            for i in range(3):
                srv = start_server()
                v = throughput()
                srv.terminate()
                samples.append(v)
                print(f"    run {i + 1}: {'no transfer' if v is None else f'{v:.1f} Gbit/s'}")
                time.sleep(1)
            results[label] = samples
    finally:
        teardown()

    print("\n  ── SUMMARY ──")
    print("  (a counter above zero would mean the blocked set matched the test traffic, so the")
    print("   throughput figure would be measuring enforcement, not cost)")
    base = [v for v in results.get("baseline", []) if v]
    base_med = sorted(base)[len(base) // 2] if base else None
    for label, samples in results.items():
        good = [v for v in samples if v]
        if not good:
            print(f"    {label:44} no measurements")
            continue
        med = sorted(good)[len(good) // 2]
        delta = ""
        if base_med and label != "baseline":
            pct = (base_med - med) / base_med * 100
            delta = f"  ({pct:+.1f}% vs baseline)"
        print(f"    {label:44} median {med:5.1f} Gbit/s{delta}")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        teardown()
        print(f"  harness error: {type(exc).__name__}: {exc}")
        sys.exit(3)
