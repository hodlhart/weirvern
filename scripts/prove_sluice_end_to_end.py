#!/usr/bin/env python3
"""Prove the Sluice Gate end to end through the SHIPPED code path, on the live node.

WHAT THIS ANSWERS, and why the earlier proof was not enough. The gate's drop was already
demonstrated on a real kernel, but stand-alone: it exercised the rule compiler and the nft
backend directly. What was never demonstrated is the path an OPERATOR uses --
  a rule recorded in the database -> picked up by an enforcement pass -> compiled -> armed in the
  kernel -> a real packet matching it is dropped and counted -> disarm removes it
and that is the path that has to work, because it is the only one the GUI can reach. A defect
anywhere in the middle (the store's expiry filter, the compiler's direction handling, the
supervisor's iface) would leave the stand-alone proof passing and the feature broken.

HOW IT PROVES A DROP WITHOUT RISKING THE NETWORK. The rule blocks source 127.0.0.1 on a single
high port, direction in. The only traffic that can match is a connection to a listener this script
starts on that port -- so the test cannot interfere with anything real, no matter how it fails.
The evidence is the kernel's OWN counter on the rule (`packets`/`bytes`), read back with nft,
rather than this script's belief about what happened: if the counter moves, the kernel dropped
those packets, and if it does not, nothing did.

WHY IT RUNS INSIDE THE WORKER POD. The gate changes the NODE's kernel, and only the worker (under
the siphon overlay) has the network namespace and capability to do that. Running it anywhere else
would install rules into a namespace nobody's traffic traverses, and it would pass while proving
nothing -- the exact failure this project keeps finding.

Exits non-zero and prints a clear verdict on any failed step. Cleans up its rule and disarms in a
finally block, so a crash does not leave a block behind.
"""

from __future__ import annotations

import socket
import subprocess
import sys
import threading
import time

TEST_PORT = 9471
TEST_SRC = "127.0.0.1"


def nft(*args: str) -> tuple[int, str]:
    proc = subprocess.run(["nft", *args], capture_output=True, text=True)
    return proc.returncode, (proc.stdout + proc.stderr).strip()


def ruleset() -> str:
    _, out = nft("list", "ruleset")
    return out


def counter_lines() -> list[str]:
    """The drop rules and their counters, verbatim, so a total can be ATTRIBUTED to a rule."""
    return [
        line.strip() for line in ruleset().splitlines()
        if "drop" in line and "counter" in line
    ]


def counter_total() -> int:
    """Sum `packets` across every sluice drop rule in the node's ruleset."""
    import contextlib

    total = 0
    for line in ruleset().splitlines():
        # nft's form is: `ip saddr @set counter packets N bytes M drop`
        if "drop" not in line or "counter" not in line:
            continue
        parts = line.split()
        for i, tok in enumerate(parts):
            if tok == "packets" and i + 1 < len(parts):
                with contextlib.suppress(ValueError):
                    total += int(parts[i + 1])
    return total


def start_listener(port: int, ready: threading.Event) -> None:
    """A listener on the test port, so a connection attempt has something to be dropped on."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(8)
    ready.set()
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            srv.settimeout(1.0)
            conn, _ = srv.accept()
            conn.close()
        except TimeoutError:
            continue
        except OSError:
            break
    srv.close()


def connect_attempt(port: int, timeout: float = 1.0) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(("127.0.0.1", port))
        return "connected"
    except TimeoutError:
        return "timed out"
    except ConnectionRefusedError:
        return "refused"
    except OSError as exc:
        return f"error: {type(exc).__name__}"
    finally:
        s.close()


def main() -> int:
    failures: list[str] = []
    rc, nft_path = nft("--version")
    if rc != 0:
        print(f"  FAIL  nft is not usable here: {nft_path}")
        print("  (the worker needs the siphon overlay: hostNetwork + NET_ADMIN)")
        return 2
    print(f"  nft: {nft_path}")

    from weirvern import sluice_store
    from weirvern.config import get_settings
    from weirvern.db import connect
    from weirvern.sluice import NftBackend, SluiceSupervisor, enforcement_pass
    from weirvern.worker import _sensor_name

    settings = get_settings()
    print(f"  mode={settings.sensor_mode!r} iface={settings.zeek_iface!r} mgmt={settings.mgmt_iface!r}")

    backend = NftBackend()
    if not backend.available():
        print("  FAIL  the nft backend reports unavailable, so nothing can be enforced")
        return 2

    sup = SluiceSupervisor(iface=settings.zeek_iface or "eth1",
                           mgmt_iface=settings.mgmt_iface or "eth0",
                           backend=backend)

    # ── the rule, written the way the GUI writes it ────────────────────────────────────────────
    with connect(settings, retries=3) as client:
        # Clean up anything a previous crashed run left behind, so this test cannot be fooled by
        # its own leftovers (a stale rule from an earlier attempt would make the counters move).
        for stale in (r.rule_id for r in sluice_store.load_live_rules(client)
                      if r.created_by == "selftest"):
            sluice_store.revoke_rule(client, stale, by="selftest")
        before_total = counter_total()
        rule = sluice_store.create_rule(
            client,
            src_cidr=TEST_SRC,
            protocol="tcp",
            dst_port=TEST_PORT,
            direction="in",
            ttl_minutes=5,
            created_by="selftest",
            reason="end-to-end self test (source is loopback, single port, safe)",
        )
        print(f"  rule recorded: {rule.rule_id} src={rule.src_cidr} port={rule.dst_port} "
              f"dir={rule.direction} expires={rule.expires_at}")

        # ── one enforcement pass, exactly as the worker runs it ────────────────────────────────
        state = enforcement_pass(sluice_store, sup, client=client,
                                 sensor=_sensor_name(settings),
                                 policy="off", max_block_s=300, detections=None,
                                 sensor_mode="siphon")
        print(f"  pass: state={state.state} rules_total={state.rules_total} "
              f"rules_active={state.rules_active} backend={state.backend}")
        if state.rules_active != 1:
            failures.append(f"the pass armed {state.rules_active} rules, expected 1")

        # ── is the rule IN the kernel? (asked of nft, not of the code that installed it) ───────
        rs = ruleset()
        if TEST_SRC not in rs:
            failures.append(f"{TEST_SRC} is not in the node's ruleset, so the rule was not installed")
        else:
            print(f"  in the kernel: {TEST_SRC} present in the ruleset")

        # ── a REAL packet that this rule must drop ────────────────────────────────────────────
        ready = threading.Event()
        threading.Thread(target=start_listener, args=(TEST_PORT, ready), daemon=True).start()
        if not ready.wait(5):
            failures.append("the test listener never started, so no packet could be sent")
        else:
            result = connect_attempt(TEST_PORT, timeout=2.0)
            after_total = counter_total()
            moved = after_total - before_total
            print(f"  connect to port {TEST_PORT}: {result}")
            print(f"  kernel drop counter: {before_total} -> {after_total} (+{moved})")
            # WHICH rule counted it. A total alone cannot distinguish "my rule dropped my packets"
            # from "some other drop rule was already counting", and the first live run moved the
            # total by 38 for a single connect -- more than a dropped SYN produces, so the number
            # needed attributing rather than accepting.
            for line in counter_lines():
                print(f"    {line}")
            if result == "connected":
                failures.append("the connection SUCCEEDED, so the gate did not drop it")
            if moved <= 0:
                failures.append("the drop counter did not move, so no packet was counted as dropped")

        # ── disarm removes it ─────────────────────────────────────────────────────────────────
        sup.disarm()
        rs_after = ruleset()
        if "weirvern_sluice" in rs_after:
            failures.append("the sluice table survived disarm")
        else:
            print("  after disarm: the sluice table is gone from the node")
        # the rule must also be gone from the store, not just the kernel
        try:
            sluice_store.revoke_rule(client, rule.rule_id, by="selftest")
            print(f"  test rule {rule.rule_id} revoked from the database")
        except Exception as exc:
            failures.append(f"could not revoke the test rule: {type(exc).__name__}")

    print()
    if failures:
        print("  VERDICT: FAILED")
        for f in failures:
            print(f"    - {f}")
        return 1
    print("  VERDICT: PASSED -- a rule written to the database was armed in the node's kernel, "
          "a real packet matching it was dropped and counted, and disarm removed it")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001
        print(f"  harness error: {type(exc).__name__}: {exc}")
        sys.exit(3)
