#!/usr/bin/env python3
"""Does an `in`-direction rule honor its PORT, or block the whole source?

WHY THIS IS THE QUESTION. The end-to-end proof passed, but its drop counter moved by 29-38 packets
for a SINGLE connect attempt on loopback. A dropped SYN should count 1-4 packets (initial plus
retransmissions). A number that large means packets were counted that the test did not send, and the
candidate explanations are very different in severity:

  (a) the port is NOT part of the compiled input rule, so blocking 127.0.0.1 on port 9471 actually
      drops every packet FROM 127.0.0.1 to this node. That would be a serious defect: the operator
      asks to block one port and gets the whole source, on the INPUT hook, for every service.
  (b) the port IS honored and the extra packets are retransmissions or unrelated loopback noise
      that the rule happens to match.

DECISIVE EXPERIMENT. Block the source on ONE port, then connect to that port (must fail) and to a
DIFFERENT port (must succeed). If the different port also fails, (a) is true.

The rule is written the way the GUI writes it -- through sluice_store -- and armed through the same
enforcement_pass the worker runs, so a defect anywhere in that path is in scope.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time

PORT_BLOCKED = 9473
PORT_CONTROL = 9474
SRC = "127.0.0.1"


def nft(*args: str) -> str:
    proc = subprocess.run(["nft", *args], capture_output=True, text=True)
    return (proc.stdout + proc.stderr).strip()


def sluice_rules() -> list[str]:
    """Every rule in the sluice tables, verbatim -- the compiled text, not a summary."""
    out = nft("list", "ruleset")
    lines, keep = [], False
    for line in out.splitlines():
        if "weirvern_sluice" in line:
            keep = True
        if keep:
            lines.append(line.rstrip())
    return lines


def listener(port: int, ready: threading.Event) -> None:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(4)
    ready.set()
    end = time.time() + 20
    while time.time() < end:
        try:
            srv.settimeout(0.5)
            c, _ = srv.accept()
            c.close()
        except (TimeoutError, OSError):
            pass
    srv.close()


def attempt(port: int, timeout: float = 1.5) -> str:
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        return "CONNECTED"
    except TimeoutError:
        return "timed out"
    except ConnectionRefusedError:
        return "refused"
    except OSError as exc:
        return f"error:{type(exc).__name__}"
    finally:
        s.close()


def main() -> int:
    from weirvern import sluice_store
    from weirvern.config import get_settings
    from weirvern.db import connect
    from weirvern.sluice import NftBackend, SluiceSupervisor, enforcement_pass

    settings = get_settings()
    sup = SluiceSupervisor(
        iface=settings.zeek_iface or "eth1",
        mgmt_iface=settings.mgmt_iface or "eth0",
        backend=NftBackend(),
    )

    # Both ports get a listener, so a SUCCESSFUL connect is a real connect and not a refusal
    # being misread as a drop.
    for p in (PORT_BLOCKED, PORT_CONTROL):
        ev = threading.Event()
        threading.Thread(target=listener, args=(p, ev), daemon=True).start()
        ev.wait(3)

    with connect(settings, retries=3) as client:
        for stale in (r.rule_id for r in sluice_store.load_live_rules(client)
                      if r.created_by == "portcheck"):
            sluice_store.revoke_rule(client, stale, by="portcheck")

        rule = sluice_store.create_rule(
            client, src_cidr=SRC, protocol="tcp", dst_port=PORT_BLOCKED, direction="in",
            ttl_minutes=3, created_by="portcheck",
            reason="port-scoping check",
        )
        state = enforcement_pass(sluice_store, sup, client=client,
                                 sensor="portcheck", policy="off", max_block_s=180,
                                 detections=None, sensor_mode="siphon")
        print(f"  pass: {state.state} active={state.rules_active}")

        print("\n  ── THE COMPILED INPUT RULE, VERBATIM ──")
        for line in sluice_rules():
            print(f"    {line}")

        print("\n  ── DOES THE PORT APPEAR IN THE COMPILED RULE? ──")
        text = "\n".join(sluice_rules())
        port_present = str(PORT_BLOCKED) in text
        control_absent = str(PORT_CONTROL) not in text
        print(f"    blocked port {PORT_BLOCKED} present in ruleset: {port_present}")
        print(f"    control port {PORT_CONTROL} absent from ruleset: {control_absent}")

        print("\n  ── THE DECISIVE TEST ──")
        before = attempt(PORT_BLOCKED)
        control = attempt(PORT_CONTROL)
        print(f"    connect to the BLOCKED port {PORT_BLOCKED}: {before}")
        print(f"    connect to the CONTROL port {PORT_CONTROL}: {control}")

        sup.disarm()
        after_control = attempt(PORT_CONTROL)
        print(f"    control port after disarm:               {after_control}")
        sluice_store.revoke_rule(client, rule.rule_id, by="portcheck")

    print()
    if control != "CONNECTED":
        print("  VERDICT: OVER-BLOCKING -- the control port was ALSO blocked, so an `in` rule")
        print("  blocks the whole source rather than the port the operator asked for.")
        return 1
    if before == "CONNECTED":
        print("  VERDICT: NOT ENFORCING -- the blocked port still connected.")
        return 1
    print("  VERDICT: PORT-SCOPED -- the blocked port was dropped and an unrelated port from the")
    print("  same source still connected, so the rule means what the operator asked for.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"  harness error: {type(exc).__name__}: {exc}")
        sys.exit(3)
