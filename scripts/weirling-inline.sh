#!/bin/sh
# weirling-inline.sh -- a reviewed, EXPLICIT two-NIC transparent bridge helper.
#
# This is not a mode switch and is never called automatically by the capture helper. An inline
# unit is a different deployment: two dedicated, address-free NICs are enslaved to a Linux
# bridge; the bridge forwards at L2 and the sensor captures on it. Nothing here changes a sysctl,
# a firewall rule or a route.
#
# SAFETY RULES, all enforced before a mutation:
#   * exactly two distinct ports;
#   * neither is the default-route (management) port;
#   * neither has an IPv4 address -- a bridge port with an address is not a dedicated inline port;
#   * a bridge this helper did not create is never deleted;
#   * the bridge name fits Linux's 15-character interface limit.
#
# Usage:
#   weirling-inline.sh status   --id ID --bridge wvbr-ID --port-a eth1 --port-b eth2
#   weirling-inline.sh dry-run  --id ID --bridge wvbr-ID --port-a eth1 --port-b eth2
#   weirling-inline.sh create   ...   (root)
#   weirling-inline.sh teardown ...   (root)
#
# `dry-run` is deliberately the safe default for a human reading this script; `create` must be
# asked for by name. The helper prints the exact commands it would run.
set -eu

STATE_DIR="${WEIRVERN_INLINE_STATE:-/var/lib/weirvern-weirling}"
SYS_ROOT="${WEIRVERN_SYS_ROOT:-/sys/class/net}"

action="${1:-status}"
[ $# -gt 0 ] && shift

ID=""
BRIDGE=""
PORT_A=""
PORT_B=""

die() { printf 'weirling-inline: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --id) ID="${2:?--id needs a value}"; shift 2 ;;
        --bridge) BRIDGE="${2:?--bridge needs a value}"; shift 2 ;;
        --port-a) PORT_A="${2:?--port-a needs a value}"; shift 2 ;;
        --port-b) PORT_B="${2:?--port-b needs a value}"; shift 2 ;;
        -h|--help) sed -n '1,35p' "$0"; exit 0 ;;
        *) die "unknown argument: $1" ;;
    esac
done

[ -n "$ID" ] || die "--id is required"
case "$ID" in *[!A-Za-z0-9_.-]*) die "--id may contain only letters, digits, dot, dash and underscore" ;; esac
BRIDGE="${BRIDGE:-wvbr-$ID}"
[ "${#BRIDGE}" -le 15 ] || die "bridge name '$BRIDGE' is longer than Linux's 15-character limit; pass --bridge"
case "$BRIDGE" in *[!A-Za-z0-9_.-]*) die "bridge name contains characters Linux does not allow" ;; esac
[ -n "$PORT_A" ] && [ -n "$PORT_B" ] || die "--port-a and --port-b are required"
[ "$PORT_A" != "$PORT_B" ] || die "--port-a and --port-b must be different NICs"
for p in "$PORT_A" "$PORT_B"; do
    [ "$p" != "lo" ] || die "loopback is not an inline port"
    [ -d "$SYS_ROOT/$p" ] || die "no such interface: $p"
done

# The default-route port is the management path. Never enslave it into a bridge.
MGMT="$(ip route show default 2>/dev/null | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1)"
if [ -n "$MGMT" ] && { [ "$PORT_A" = "$MGMT" ] || [ "$PORT_B" = "$MGMT" ]; }; then
    die "REFUSING: '$MGMT' carries the default route (management path); an inline bridge must use dedicated ports"
fi
for p in "$PORT_A" "$PORT_B"; do
    if ip -4 -o addr show dev "$p" 2>/dev/null | grep -q 'inet '; then
        die "REFUSING: $p has an IPv4 address; inline ports must be dedicated and address-free"
    fi
done

STATE="$STATE_DIR/inline-$ID.state"
BRIDGE_EXISTS=0
[ -d "/sys/class/net/$BRIDGE" ] && BRIDGE_EXISTS=1
MANAGED=0
[ -f "$STATE" ] && MANAGED=1

print_cmds() {
    printf 'ip link add name %s type bridge\n' "$BRIDGE"
    printf 'ip link set %s up\n' "$BRIDGE"
    printf 'ip link set %s master %s\n' "$PORT_A" "$BRIDGE"
    printf 'ip link set %s master %s\n' "$PORT_B" "$BRIDGE"
    printf 'ip link set %s up\n' "$PORT_A"
    printf 'ip link set %s up\n' "$PORT_B"
}

case "$action" in
    dry-run)
        say "# DRY RUN -- no mutation. Proposed inline bridge for $ID:"
        print_cmds
        say "# bridge=$BRIDGE port-a=$PORT_A port-b=$PORT_B state=$STATE"
        ;;
    create)
        [ "$(id -u)" -eq 0 ] || die "create needs root (ip link changes)"
        [ "$BRIDGE_EXISTS" -eq 0 ] || die "bridge '$BRIDGE' already exists; refusing to adopt it"
        [ "$MANAGED" -eq 0 ] || die "state $STATE already exists but bridge '$BRIDGE' does not; inspect before recreating"
        mkdir -p "$STATE_DIR"
        print_cmds | while IFS= read -r cmd; do
            say "+ $cmd"
            sh -c "$cmd"
        done
        printf 'id=%s\nbridge=%s\nport_a=%s\nport_b=%s\ncreated=%s\n' \
            "$ID" "$BRIDGE" "$PORT_A" "$PORT_B" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$STATE"
        chmod 0600 "$STATE" 2>/dev/null || true
        say "inline bridge $BRIDGE created: $PORT_A <-> $PORT_B"
        ;;
    status)
        say "id:     $ID"
        say "bridge: $BRIDGE ($([ "$BRIDGE_EXISTS" -eq 1 ] && echo present || echo absent))"
        say "state:  $STATE ($([ "$MANAGED" -eq 1 ] && echo managed || echo untracked))"
        if [ "$BRIDGE_EXISTS" -eq 1 ]; then
            ip -o link show master "$BRIDGE" 2>/dev/null || true
            ip -o link show "$BRIDGE" 2>/dev/null || true
        fi
        ;;
    teardown)
        [ "$(id -u)" -eq 0 ] || die "teardown needs root (ip link changes)"
        [ "$MANAGED" -eq 1 ] || die "no state at $STATE; refusing to delete a bridge this helper did not create"
        [ "$BRIDGE_EXISTS" -eq 1 ] || die "state exists but bridge '$BRIDGE' is absent; nothing to tear down"
        say "+ ip link set $PORT_A nomaster"
        ip link set "$PORT_A" nomaster
        say "+ ip link set $PORT_B nomaster"
        ip link set "$PORT_B" nomaster
        say "+ ip link del $BRIDGE"
        ip link del "$BRIDGE"
        rm -f "$STATE"
        say "inline bridge $BRIDGE removed; $PORT_A and $PORT_B are no longer enslaved"
        ;;
    *)
        die "unknown action '$action' (expected status|dry-run|create|teardown)"
        ;;
esac
