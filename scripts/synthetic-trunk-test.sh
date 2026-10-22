#!/bin/sh
# synthetic-trunk-test.sh -- prove the trunk adapter against a real kernel, without a switch.
#
# A pair of veth devices stands in for (sensor port <-> switch trunk). One end carries
# synthetic 802.1Q-tagged frames; the other is the capture parent the trunk manager observes.
# This exercises the same code path as a physical trunk: tag capture, VLAN device creation,
# capture on a VLAN device, then removal when the port goes back to untagged.
#
# It requires root (NET_ADMIN + NET_RAW), but it never touches an existing interface: names
# are derived from this shell's PID, and every device and state file it creates is removed on
# exit. It changes no sysctl, route, firewall rule or production NIC.
#
# Run from a checkout or from the installed tree:
#   sudo sh scripts/synthetic-trunk-test.sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "synthetic-trunk-test: needs root (NET_ADMIN + NET_RAW); nothing was changed" >&2
    exit 2
fi

ROOT="${WEIRVERN_ROOT:-$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)}"
SUF="$$"
PARENT="wv${SUF}a"
PEER="wv${SUF}b"
STATE="$(mktemp -d "${TMPDIR:-/tmp}/wv-trunk-test.XXXXXX")"
LOG="$STATE/detect.log"

cleanup() {
    for vid in 10 20 30; do
        ip link del "$PARENT.$vid" >/dev/null 2>&1 || true
    done
    ip link del "$PARENT" >/dev/null 2>&1 || true
    rm -rf "$STATE"
}
trap cleanup EXIT INT TERM

if [ -d "/sys/class/net/$PARENT" ] || [ -d "/sys/class/net/$PEER" ]; then
    echo "synthetic-trunk-test: $PARENT or $PEER already exists; refusing to touch it" >&2
    exit 2
fi

send_tagged() {
    python3 - "$PEER" 10 20 30 <<'PY'
import socket
import struct
import sys
import time

peer = sys.argv[1]
vlans = [int(v) for v in sys.argv[2:]]
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
sock.bind((peer, 0))
dst = b"\xff\xff\xff\xff\xff\xff"
src = b"\x00\x00\x5e\x00\x53\x01"
for vid in vlans:
    for _ in range(25):
        # 802.1Q: TPID 0x8100, TCI (PCP/DEI/VID), then an ordinary IPv4 ethertype.
        frame = dst + src + b"\x81\x00" + struct.pack("!H", vid & 0x0FFF) + b"\x08\x00" + b"\x00" * 46
        sock.send(frame)
        time.sleep(0.004)
sock.close()
PY
}

echo "== creating synthetic trunk $PARENT <-> $PEER"
ip link add "$PARENT" type veth peer name "$PEER"
ip link set "$PARENT" up
ip link set "$PEER" up

echo "== observing tags (10, 20, 30) for 5s"
PYTHONPATH="$ROOT" python3 -m weirvern.admin.trunk detect \
    --parent "$PARENT" --state "$STATE" --seconds 5 >"$LOG" 2>&1 &
DETECT=$!
sleep 1
send_tagged
wait "$DETECT"

python3 - "$STATE" "$PARENT" <<'PY'
import json
import os
import pathlib
import sys

state = json.loads((pathlib.Path(sys.argv[1]) / "trunk.json").read_text())
parent = sys.argv[2]
assert state["vlans"] == [10, 20, 30], state
assert state["ifaces"] == [f"{parent}.10", f"{parent}.20", f"{parent}.30"], state
assert state["managed"] == state["ifaces"], state
for name in state["ifaces"]:
    assert os.path.isdir(f"/sys/class/net/{name}"), f"missing VLAN device {name}"
print("tagged state:", state["vlans"], "->", state["ifaces"])
PY

echo "== capturing on $PARENT.10 while tagged frames flow"
PYTHONPATH="$ROOT" python3 - "$PARENT.10" "$STATE/probe.json" <<'PY' &
import json
import sys
from weirvern.admin.probe import run_capture_probe

print(json.dumps(run_capture_probe(sys.argv[1], seconds=5)), file=open(sys.argv[2], "w"))
PY
PROBE=$!
sleep 1
send_tagged
wait "$PROBE"

python3 - "$STATE/probe.json" <<'PY'
import json
import sys

probe = json.load(open(sys.argv[1]))
assert probe.get("ok") is True, probe
assert probe.get("observed") is True, probe
print("VLAN capture probe:", {"packets_recv": probe.get("packets_recv"),
                              "packets_dropped": probe.get("packets_dropped"),
                              "observed": probe.get("observed")})
PY

echo "== observing silence for 3s (back to an access port)"
PYTHONPATH="$ROOT" python3 -m weirvern.admin.trunk detect \
    --parent "$PARENT" --state "$STATE" --seconds 3 >"$STATE/detect-untagged.log" 2>&1

python3 - "$STATE" "$PARENT" <<'PY'
import json
import os
import pathlib
import sys

state = json.loads((pathlib.Path(sys.argv[1]) / "trunk.json").read_text())
parent = sys.argv[2]
assert state["vlans"] == [], state
assert state["ifaces"] == [parent], state
for vid in (10, 20, 30):
    assert not os.path.isdir(f"/sys/class/net/{parent}.{vid}"), f"{parent}.{vid} was not removed"
print("untagged state:", state["ifaces"])
PY

echo "SYNTHETIC TRUNK: PASS -- tags discovered, VLAN devices created and captured, then removed"
