#!/bin/sh
# deploy-weirling.sh -- put a WEIRLING (one sensor unit) on another box.
#
# WHAT IT IS FOR: sensors throughout a network. The hub keeps the database and the GUI; a
# weirling is a capture port on some other machine, reporting into the hub under its own id.
# This script runs WHERE YOU ARE (laptop or the hub), reaches the hub and the target over
# ssh, and leaves two containers on the target, plus a small local helper to operate them:
#
#   weirvern-capture-<id>   Zeek on one dedicated NIC (host network, NET_RAW only)
#   weirvern-agent-<id>     the heartbeat: observes the capture's logs, writes sensor_status
#   /usr/local/bin/weirvern-weirling   status / start / stop, ON the target
#
# PREFER AN INDEPENDENT CAPTURE PORT; SUPPORT A SINGLE-NIC HOST. With no --iface the first
# port that is up, physical, not loopback and not the default route is chosen. A host with one
# NIC has no such port, so --allow-management-nic nominates the management NIC instead and the
# unit starts DEGRADED: it sees only that host's own traffic, not the segment, and on wireless
# not even other stations' frames. The cost is printed at deploy time and at every start.
#
# THE MANAGEMENT NIC IS STILL THE WRONG PLACE TO CAPTURE, and it is still the wrong place to
# ENFORCE, which is a harder rule: capture is a read, enforcement on the box's own uplink takes
# the box out of the network. --gate therefore REFUSES the management NIC unconditionally, and
# its check does not consult --allow-management-nic. --gate combined with --allow-management-nic
# is refused outright on a single-NIC host.
#
# IT DOES NOT REGISTER THE SENSOR -- EXCEPT BY ENROLLMENT. With the default mTLS transport the
# one-time token's enrollment creates the fleet row (note: "adopted by mTLS enrollment").
# --legacy-clickhouse has no such step, so its row appears as UNREGISTERED until an operator says
# whose it is. That is the view's entire point.
#
# THE TRANSPORT IS mTLS BY DEFAULT: the agent enrolls once, then writes heartbeats, plans,
# flows and Zeek records through the hub gateway with a client certificate. No database
# credential is written to the target. `--legacy-clickhouse` is the explicit migration path
# for a hub whose gateway is not reachable yet; it opens clickhouse-external with --expose.
#
# USAGE
#   scripts/deploy-weirling.sh --hub root@hub --target root@sensor-box \
#          --iface eth1 --sensor-id weirvern-eth1 [--expose] [--dry-run] [--yes]
#   scripts/deploy-weirling.sh --target root@sensor-box --iface eth1 \
#          --sensor-id weirvern-eth1 --remove [--purge]
#
#   --hub         ssh destination of the weirvern hub (images, ClickHouse, the site policy)
#   --target      ssh destination of the new sensor box; "local" = this machine
#   --iface       the capture port on the target. OMIT IT to let the script prefer the first
#                 up, physical port that is not the management NIC
#   --allow-management-nic  accept the target's management NIC as the capture port, for a host
#                 with only one NIC. The unit starts DEGRADED (host traffic only). Refused in
#                 combination with --gate
#   --sensor-id   the fleet identity this weirling reports under ([a-z0-9-], max 64)
#   --expose      allow patching clickhouse-external to a NodePort when the target is not
#                 the hub (needed for the agent to reach the database)
#   --gate        ALSO install the ENFORCEMENT GATE on this box. The rules are fleet-wide; the
#                 gate is what makes them stop traffic, and it only works where the box is IN
#                 THE PATH. Same requirements as the hub: SLUICE_ENABLED=1, a VERIFIED path (the
#                 box's own channel bridge, or a live siphon intercept), never the management NIC,
#                 and a ruleset that could be read. A gate that cannot meet them reports DEGRADED
#                 and blocks nothing -- it does not guess.
#   --gate-iface  the interface traffic TRAVERSES on the target (its bridge, or the intercept
#                 port). Required with --gate, and refused if it is the management NIC. This is
#                 NOT the capture port.
#   --netflow     ALSO run the NetFlow/sFlow COLLECTOR on this box, and ship what it receives into
#                 the hub's `flows` table (goflow2 on 2055/6343 -> the unit's agent -> ClickHouse).
#                 This is how an exporter somewhere else in the network gets its records into
#                 Weirvern without a route to the hub. Inert until an exporter is pointed at it.
#   --mtls        Accepted for compatibility; mTLS is now the DEFAULT.
#   --mtls-token  use this already-issued one-time token instead of asking the hub CLI.
#   --agent-image override the agent image. Default: `weirvern-scan:<worker tag>` when the hub
#                 has it (Nmap + raw-socket file capabilities, so the unit can scan), otherwise
#                 the worker image, which reports `nmap missing` and claims nothing.
#   --legacy-clickhouse
#                 Explicitly opt OUT of mTLS and give the unit a ClickHouse credential. This is
#                 a migration path for a hub whose gateway is not yet reachable; it is not the
#                 default and must be asked for.
#   --inline      This unit captures on an EXISTING two-NIC bridge. The bridge must be created
#                 first with scripts/weirling-inline.sh; this flag validates it and disables the
#                 trunk probe (a bridge is not a trunk parent). It does not create a bridge.
#   --no-trunk    Do not run the trunk/VLAN probe. Use with a manually managed bridge if you do
#                 not pass --inline.
#   --remove      stop and remove the containers on the target (logs kept; --purge too)
#   --purge       with --remove: also delete the env file, helper and log directory
#   --dry-run     run every CHECK (including the refusals) and print the plan; change nothing
#   --yes         skip the interactive confirmation before the first change
set -eu

HUB=""
TARGET=""
IFACE=""
SENSOR_ID=""
SEGMENT=""
EXPOSE=0
ALLOW_MGMT=0
GATE=0
GATE_IFACE=""
NETFLOW=0
INLINE=0
NO_TRUNK=0
MTLS=1
MTLS_TOKEN=""
AGENT_IMAGE=""
REMOVE=0
PURGE=0
DRY=0
YES=0

die() { printf 'deploy-weirling: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --hub) HUB="${2:?--hub needs a value}"; shift 2 ;;
        --target) TARGET="${2:?--target needs a value}"; shift 2 ;;
        --iface) IFACE="${2:?--iface needs a value}"; shift 2 ;;
        --sensor-id) SENSOR_ID="${2:?--sensor-id needs a value}"; shift 2 ;;
        --segment) SEGMENT="${2:?--segment needs a value}"; shift 2 ;;
        --expose) EXPOSE=1; shift ;;
        --allow-management-nic) ALLOW_MGMT=1; shift ;;
        --gate) GATE=1; shift ;;
        --netflow) NETFLOW=1; shift ;;
        --mtls) MTLS=1; shift ;;
        --mtls-token) MTLS_TOKEN="${2:?--mtls-token needs a value}"; MTLS=1; shift 2 ;;
        --agent-image) AGENT_IMAGE="${2:?--agent-image needs a value}"; shift 2 ;;
        --legacy-clickhouse) MTLS=0; shift ;;
        --gate-iface) GATE_IFACE="${2:?--gate-iface needs a value}"; shift 2 ;;
        --inline) INLINE=1; NO_TRUNK=1; shift ;;
        --no-trunk) NO_TRUNK=1; shift ;;
        --remove) REMOVE=1; shift ;;
        --purge) PURGE=1; shift ;;
        --dry-run) DRY=1; shift ;;
        --yes) YES=1; shift ;;
        -h|--help) sed -n '2,/^set -eu$/p' "$0" | sed 's/^# \{0,1\}//' | sed '$d'; exit 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

[ -n "$TARGET" ] || die "--target is required (or \"local\")"
if [ "$REMOVE" = "0" ]; then
    [ -n "$HUB" ] || die "--hub is required for an install (images, ClickHouse, the site policy)"
    [ -n "$SENSOR_ID" ] || die "--sensor-id is required -- it is the fleet identity"
fi

[ -n "$SENSOR_ID" ] || die "--sensor-id is required (it is the fleet identity)"
if [ "$PURGE" = "1" ] && [ "$REMOVE" = "0" ]; then
    die "--purge only makes sense together with --remove"
fi
if [ "$GATE" = "1" ] && [ "$REMOVE" = "0" ] && [ -z "$GATE_IFACE" ]; then
    # REFUSED RATHER THAN DEFAULTED. The obvious default -- the capture port -- is a mirror: rules
    # installed there match nothing that matters, and the operator would be told a segment is
    # blocked by a gate that is only decorating a span port.
    die "--gate needs --gate-iface: the interface traffic TRAVERSES on this box (its bridge, or the
    intercept port) -- not the capture port, which is a mirror and enforces nothing."
fi
case "$SENSOR_ID" in
    *[!a-z0-9-]*) die "sensor id must be [a-z0-9-] only (got '$SENSOR_ID')" ;;
esac
[ "${#SENSOR_ID}" -le 64 ] || die "sensor id is longer than 64 characters"

# rsh <dest> <cmd...>: "local" runs here. Kept trivial on purpose -- every remote step in
# this script is one visible command, so an operator reading the dry-run output can copy it.
rsh() {
    _dest="$1"; shift
    if [ "$_dest" = "local" ]; then
        sh -c "$*"
    else
        ssh -o BatchMode=yes -o ConnectTimeout=8 "$_dest" "$*"
    fi
}

# A credential this script generates: 24 random bytes as hex. No openssl dependency.
rand_hex() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 24
    else
        od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
    fi
}

# ── the remove path, first: it needs none of the hub discovery ─────────────────────────────
if [ "$REMOVE" = "1" ]; then
    step "remove weirling '$SENSOR_ID' from $TARGET"
    if [ "$DRY" = "1" ]; then
        say "  would run on $TARGET: weirvern-weirling stop  (docker rm -f the two containers)"
        [ "$PURGE" = "1" ] && say "  --purge: would also delete the env file, helper and logs"
        exit 0
    fi
    # The helper is generated per weirling; if it is gone, fall back to plain docker names.
    rsh "$TARGET" "if [ -x /usr/local/bin/weirvern-weirling ]; then weirvern-weirling stop; \
                    else docker rm -f weirvern-capture-$SENSOR_ID weirvern-agent-$SENSOR_ID weirvern-gate-$SENSOR_ID >/dev/null 2>&1 || true; fi"
    if [ "$PURGE" = "1" ]; then
        rsh "$TARGET" "rm -f /etc/weirvern-weirling.env /usr/local/bin/weirvern-weirling; \
                       rm -rf /var/lib/weirvern-weirling"
        say "  purged env, helper and logs"
    else
        say "  containers removed; logs kept under /var/lib/weirvern-weirling (use --purge to drop them)"
    fi
    say "  the fleet row will show the sensor as STALE once its last heartbeat ages out"
    # REVOKING ONE SENSOR MUST NOT ROTATE THE OTHERS (HD-25). The credential is per sensor, so
    # dropping its user ends this weirling's access and leaves every other sensor shipping.
    CH_USER="wv_$(printf '%s' "$SENSOR_ID" | tr '-' '_')"
    if [ -n "$HUB" ]; then
        rsh "$HUB" "kubectl -n weirvern exec -i clickhouse-0 -- clickhouse-client --query 'DROP USER IF EXISTS ${CH_USER}'" \
            || say "  warning: could not drop ${CH_USER} on the hub -- run: DROP USER IF EXISTS ${CH_USER}"
        rsh "$HUB" "f=/var/lib/weirvern/sensor-credentials.tsv; [ -f \"\$f\" ] && awk -F '\t' -v id='$SENSOR_ID' '\$1 != id' \"\$f\" > \"\$f.tmp\" && mv \"\$f.tmp\" \"\$f\"" || true
        say "  credential ${CH_USER} dropped (other weirlings unaffected)"
    else
        say "  no --hub given: drop the credential yourself with: DROP USER IF EXISTS ${CH_USER}"
    fi
    exit 0
fi

# ── reachability ───────────────────────────────────────────────────────────────────────────
step "reaching the hub and the target"
rsh "$HUB" "true" || die "cannot ssh to the hub ($HUB)"
rsh "$TARGET" "true" || die "cannot ssh to the target ($TARGET)"
say "  hub:    $HUB ok"
say "  target: $TARGET ok"

# ── the capture port, ON THE TARGET, before anything is created ────────────────────────────
step "checking the capture port on the target"
rsh "$TARGET" "test -e /sys/class/net/$IFACE" \
    || die "$TARGET has no interface '$IFACE' -- check the NIC is attached and up"
DEFROUTE="$(rsh "$TARGET" "ip route show default 2>/dev/null | head -1" \
    | sed -n 's/.*dev \([^ ]*\).*/\1/p' | head -1)"
if [ -z "$DEFROUTE" ]; then
    # AN UNKNOWN REFUSES, same as the agent: a capture we cannot prove is off the management
    # path must not start. The operator can name the port and re-run once `ip route` works.
    die "could not determine the target's default-route interface; refusing to guess (is iproute2 installed?)"
fi
# ── PREFER AN INDEPENDENT PORT; SUPPORT A SINGLE-NIC HOST ─────────────────────────────────────
#
# A host with one NIC has no dedicated port, and a sensor that will not start there is not a
# sensor. The preference is expressed as SELECTION: with no --iface, take the first port that is
# up, physical, not loopback and not the management NIC. Only if there is no such port does the
# management NIC become a candidate, and then only with --allow-management-nic.
#
# THE GATE IS DELIBERATELY NOT RELAXED WITH IT. Capturing on the management NIC is a read.
# Enforcing there is the box's own uplink, so it takes out the machine doing the blocking. The
# gate keeps its unconditional refusal further down, and it does not consult $ALLOW_MGMT.
if [ -z "$IFACE" ]; then
    IFACE="$(rsh "$TARGET" "for d in /sys/class/net/*; do \
        n=\${d##*/}; \
        [ \"\$n\" = lo ] && continue; \
        [ \"\$n\" = '$DEFROUTE' ] && continue; \
        [ \"\$(cat \"\$d/operstate\" 2>/dev/null)\" = up ] || continue; \
        [ -e \"\$d/device\" ] || continue; \
        echo \"\$n\"; break; done" | tr -d '\r')"
    if [ -n "$IFACE" ]; then
        say "  no --iface given; chose '$IFACE' (up, physical, not the management port)"
    fi
fi

if [ -z "$IFACE" ]; then
    if [ "$ALLOW_MGMT" = "1" ]; then
        IFACE="$DEFROUTE"
        say "  no independent port exists on $TARGET; using the management NIC '$IFACE' as allowed"
    else
        die "no independent capture port on $TARGET -- '$DEFROUTE' is the management NIC and is \
not used for capture by default. Name a port with --iface, or, if this host has only one NIC, \
pass --allow-management-nic to accept a DEGRADED sensor that sees only its own traffic."
    fi
fi

if [ "$IFACE" = "$DEFROUTE" ]; then
    if [ "$ALLOW_MGMT" != "1" ]; then
        die "REFUSING: '$IFACE' is the target's management NIC (default route). Use a dedicated \
capture port, or pass --allow-management-nic if this host has only one NIC."
    fi
    if [ "$GATE" = "1" ]; then
        die "--gate cannot be combined with --allow-management-nic: capturing on the management \
NIC is a read, but ENFORCING on it is this box's own uplink. Point the gate at the interface \
traffic traverses, or leave the gate off this unit."
    fi
    say "  !! capture port: $IFACE is the MANAGEMENT NIC -- DEGRADED sensor (accepted explicitly)"
    say "     it sees only this host's own traffic plus broadcast/multicast, not the segment"
    say "     on wireless it does not even see other stations' frames"
    say "     its logs are host telemetry: they include the DNS names and peers this box uses"
else
    say "  capture port: $IFACE (target's management port is $DEFROUTE -- untouched)"
fi
case "$IFACE" in lo) die "REFUSING: 'lo' is the loopback interface" ;; esac

if [ "$INLINE" = "1" ]; then
    # INLINE IS A TOPOLOGY, NOT A MODE. The bridge must already exist and have exactly two
    # enslaved, address-free ports. This script does not create one: `scripts/weirling-inline.sh`
    # does that, visibly, and a unit deployment must not silently rewire a host.
    rsh "$TARGET" "ip -d link show '$IFACE' 2>/dev/null | grep -q 'bridge'" \
        || die "--inline needs '$IFACE' to be an existing Linux bridge; create it first with scripts/weirling-inline.sh"
    PORT_COUNT="$(rsh "$TARGET" "ip -o link show master '$IFACE' 2>/dev/null | wc -l" | tr -d ' ')"
    [ "$PORT_COUNT" = "2" ] \
        || die "--inline needs exactly two ports enslaved to '$IFACE' (found ${PORT_COUNT:-0}); create the bridge with scripts/weirling-inline.sh"
    rsh "$TARGET" "ip -4 -o addr show dev '$IFACE' 2>/dev/null | grep -q 'inet '" \
        && die "--inline bridge '$IFACE' has an IPv4 address; an inline bridge must be transparent and address-free"
    [ "$GATE" = "1" ] && die "--gate on an inline bridge is not implemented yet; do not claim bridge enforcement"
    say "  inline bridge: $IFACE (two enslaved ports; trunk probe disabled)"
fi

# ── docker on the target ────────────────────────────────────────────────────────────────────
rsh "$TARGET" "command -v docker >/dev/null 2>&1" \
    || die "docker is not installed on $TARGET. Install it first (e.g. 'apt-get install -y docker.io'), then re-run."
say "  docker: present on the target"

# ── discover what the hub runs (tags and endpoints come from the RUNNING deployment) ───────
step "reading the hub's deployment"
WORKER_IMG="$(rsh "$HUB" "kubectl -n weirvern get deploy weirvern-worker -o jsonpath='{.spec.template.spec.containers[0].image}'")"
ZEEK_IMG="$(rsh "$HUB" "kubectl -n weirvern get ds zeek -o jsonpath='{.spec.template.spec.containers[0].image}'")"
SITE_CM="$(rsh "$HUB" "kubectl -n weirvern get cm -o name | grep zeek-site | head -1")"
SITE_CM="${SITE_CM#configmap/}"
[ -n "$WORKER_IMG" ] && [ -n "$ZEEK_IMG" ] && [ -n "$SITE_CM" ] \
    || die "could not read the hub's image tags / site policy ConfigMap -- is the deployment up?"
# THE SCAN IMAGE IS WHAT LETS THIS WEIRLING SCAN. Scanning is executed by weirlings, so the
# agent container must carry Nmap; the hub builds `weirvern-scan:<same tag>` (install.sh) and
# this script resolves it from the running worker's tag. If the hub does not have it, the unit
# still deploys -- and its agent reports `nmap missing`, which the hub shows instead of
# pretending the unit can scan.
#
# THE IMAGE IS READ FROM THE STORE `docker save` READS. This script transfers with
# `docker save` on the hub, so checking k3s's containerd was not enough: an image present only
# in containerd (the runtime) could be announced as available and then fail the transfer. Docker
# is checked first; if only containerd has it, it is copied into docker once, on the hub, before
# the transfer. `--agent-image` is the escape hatch for a tag that does not follow the worker's.
WORKER_TAG="${WORKER_IMG##*:}"
SCAN_IMG="weirvern-scan:$WORKER_TAG"
if [ -n "$AGENT_IMAGE" ]; then
    AGENT_IMG="$AGENT_IMAGE"
    say "  scan image: $AGENT_IMG (explicit --agent-image)"
elif rsh "$HUB" "docker image inspect '$SCAN_IMG' >/dev/null 2>&1"; then
    AGENT_IMG="$SCAN_IMG"
    say "  scan image: $AGENT_IMG (nmap-capable; this weirling can claim manual scans)"
elif rsh "$HUB" "k3s ctr images ls 2>/dev/null | grep -q '$SCAN_IMG'"; then
    say "  scan image: $SCAN_IMG is in the hub's containerd but not its docker; copying it for transfer"
    if rsh "$HUB" "k3s ctr images export /tmp/$(basename "$SCAN_IMG" | tr ':' '-').tar '$SCAN_IMG' \
                   && docker load -i /tmp/$(basename "$SCAN_IMG" | tr ':' '-').tar \
                   && rm -f /tmp/$(basename "$SCAN_IMG" | tr ':' '-').tar" >/dev/null 2>&1; then
        AGENT_IMG="$SCAN_IMG"
        say "  scan image: $AGENT_IMG (nmap-capable; this weirling can claim manual scans)"
    else
        AGENT_IMG="$WORKER_IMG"
        say "  scan image: $SCAN_IMG could not be copied from containerd to docker on the hub"
        say "              this unit will report 'nmap missing' and will not claim scans"
    fi
else
    AGENT_IMG="$WORKER_IMG"
    say "  scan image: $SCAN_IMG not found on the hub; this unit will report 'nmap missing'"
    say "              build it with: docker build -t $SCAN_IMG -f Containerfile.scanner . && k3s ctr images import -"
fi
say "  images: $WORKER_IMG , $ZEEK_IMG"
say "  site policy: $SITE_CM"

# ── the transport endpoint as seen FROM THE TARGET ─────────────────────────────────────────
# THE DIRECT PATH (default): clickhouse-external. The in-cluster `clickhouse` Service is
# HEADLESS (clusterIP: None -- MEASURED: the first version of this script read the literal
# string "None" out of it and shipped that into the agent's config, where it retried forever),
# so it offers no stable address even to a client on the hub itself. clickhouse-external is
# the door built for outside clients; when it has no NodePort yet, --expose opens one and this
# script says exactly what it changed (revert by re-applying k8s/).
HUB_LAN="$(rsh "$HUB" "hostname -I" | tr ' ' '\n' | grep -E '^[0-9]+\.' | head -1)"
[ -n "$HUB_LAN" ] || die "could not determine the hub's LAN address"
if [ "$MTLS" = "1" ]; then
    # THE mTLS PATH: one outbound HTTPS door and a client certificate. No database
    # credential is written to the target. The gateway must already be deployed; this
    # script refuses to invent a second transport when it is absent.
    INGEST_PORT="$(rsh "$HUB" "kubectl -n weirvern get svc weirvern-ingest -o jsonpath='{.spec.ports[0].nodePort}'" 2>/dev/null || true)"
    [ -n "$INGEST_PORT" ] || die "the hub has no weirvern-ingest NodePort; its default mTLS edge is missing. Re-run the hub installer (scripts/bootstrap-mtls.sh + k8s/) before adopting."
    INGEST_HOST="${HUB##*@}"
    # The default installer puts every node IPv4 in the server certificate's SAN, so an
    # address is valid here as well as a hostname. Do not reject either form.
    GATEWAY_URL="https://${INGEST_HOST}:${INGEST_PORT}"
    say "  gateway for the agent: $GATEWAY_URL (mTLS; no database credential)"
else
    CH_HOST="$HUB_LAN"
    CH_PORT="$(rsh "$HUB" "kubectl -n weirvern get svc clickhouse-external -o jsonpath='{.spec.ports[0].nodePort}'")"
    if [ -z "$CH_PORT" ]; then
        if [ "$EXPOSE" = "1" ]; then
            if [ "$DRY" = "1" ]; then :; else
                # Change ONLY the type and let Kubernetes assign the nodePort, then read it back.
                printf '{"spec":{"type":"NodePort"}}\n' | rsh "$HUB" "cat > /tmp/weirvern-expose.json"
                rsh "$HUB" "kubectl -n weirvern patch svc clickhouse-external --type merge --patch-file /tmp/weirvern-expose.json" >/dev/null
                CH_PORT="$(rsh "$HUB" "kubectl -n weirvern get svc clickhouse-external -o jsonpath='{.spec.ports[0].nodePort}'")"
                [ -n "$CH_PORT" ] || die "the service did not get a nodePort; check 'kubectl -n weirvern get svc clickhouse-external'"
            fi
            say "  clickhouse-external opened as NodePort $CH_PORT (a change on the hub; revert by re-applying k8s/)"
        else
            die "clickhouse-external has no NodePort; the agent needs a door from the target. Re-run with --expose (or open one yourself)."
        fi
    fi
    say "  ClickHouse for the agent: hub $CH_HOST : $CH_PORT via clickhouse-external"
fi

if [ "$DRY" = "1" ]; then
    step "DRY RUN -- plan for weirling \"$SENSOR_ID\" on $TARGET"
    say "  1. stream $ZEEK_IMG , $WORKER_IMG and $AGENT_IMG from $HUB to $TARGET (docker save | docker load)"
    if [ "$MTLS" = "1" ]; then
        say "  2. obtain a one-time adoption token and enroll a local key/CSR over mTLS"
        say "     write /etc/weirvern-weirling.env (gateway URL + certificate paths only)"
    else
        say "  2. write /etc/weirvern-weirling.env (0600: ClickHouse endpoint + credentials from the hub's Secret)"
    fi
    say "  3. install the site policy from ConfigMap $SITE_CM and a local helper /usr/local/bin/weirvern-weirling"
    say "  4. start weirvern-capture-$SENSOR_ID (Zeek on $IFACE, host network, NET_RAW) and"
    say "     weirvern-agent-$SENSOR_ID (heartbeats, restart unless-stopped)"
    say "  5. verify a fresh heartbeat for \"$SENSOR_ID\" lands in the hub's database"
    if [ "$MTLS" = "1" ]; then
        say "  then: the token enrollment registers the sensor; no separate Adopt click is needed"
    else
        say "  then: register it in the Weirlings view -- it appears as UNREGISTERED until you do"
    fi
    exit 0
fi

if [ "$YES" = "0" ]; then
    printf 'Install weirling "%s" on %s capturing %s? [y/N] ' "$SENSOR_ID" "$TARGET" "$IFACE"
    read -r ans || ans=""
    case "$ans" in y|Y|yes|YES) : ;; *) die "not confirmed" ;; esac
fi

# ── ship the images (streamed; nothing lands on the machine running THIS script) ──────────
if [ "$NETFLOW" = "1" ]; then
    # THE COLLECTOR IS AN UPSTREAM IMAGE the hub pulls for itself; the target pulls the same tag
    # rather than streaming it from the hub, because nothing here has been patched or pinned for a
    # site policy the way the Zeek image is. Visible step, so the network fetch is a decision the
    # operator watched rather than a surprise on start.
    step "fetching the flow collector image on the target"
    rsh "$TARGET" "docker pull netsampler/goflow2:v2.2.6 >/dev/null 2>&1" \
        || die "could not pull netsampler/goflow2:v2.2.6 on the target -- check its network access"
    say "  collector image: netsampler/goflow2:v2.2.6"
fi

step "shipping the images to the target"
rsh "$HUB" "docker save $ZEEK_IMG $WORKER_IMG $AGENT_IMG" | rsh "$TARGET" "docker load" >/dev/null
say "  loaded: $ZEEK_IMG , $WORKER_IMG , $AGENT_IMG"

if [ "$MTLS" = "1" ]; then
    # ── adoption: one token in, one certificate out ─────────────────────────────────────────
    step "adopting the weirling over mTLS"
    rsh "$TARGET" "mkdir -p /etc/weirvern-weirling/pki && chown 0:0 /etc/weirvern-weirling/pki && chmod 0700 /etc/weirvern-weirling/pki"
    ROOT_B64="$(rsh "$HUB" "kubectl -n weirvern get secret weirling-root -o jsonpath='{.data.root-ca\.crt}'")"
    [ -n "$ROOT_B64" ] || die "the hub has no weirling-root Secret; its default mTLS PKI is missing. Re-run the hub installer (scripts/bootstrap-mtls.sh) before adopting."
    printf '%s' "$ROOT_B64" | rsh "$TARGET" "base64 -d > /etc/weirvern-weirling/pki/root-ca.crt && chown 0:0 /etc/weirvern-weirling/pki/root-ca.crt && chmod 0644 /etc/weirvern-weirling/pki/root-ca.crt"
    if [ -z "$MTLS_TOKEN" ]; then
        TOKEN_JSON="$(rsh "$HUB" "kubectl -n weirvern exec deploy/weirvern-gui -- weirvern weirlings token --sensor-id '$SENSOR_ID' --mode loch --segment '$SEGMENT' --json")" \
            || die "could not obtain an enrollment token from the hub's GUI; issue one and re-run with --mtls-token"
        MTLS_TOKEN="$(printf '%s' "$TOKEN_JSON" | sed -n 's/.*"token": *"\([^"]*\)".*/\1/p' | tail -1)"
        [ -n "$MTLS_TOKEN" ] || die "the hub returned no token; issue one and re-run with --mtls-token"
    fi
    # THE KEY IS GENERATED ON THE TARGET. The hub sees only the CSR; the token appears in
    # this one docker run and is not written to the target's env file.
    rsh "$TARGET" "docker run --rm --network host --user 0:0 --entrypoint python3 \
        -v /etc/weirvern-weirling:/etc/weirvern-weirling \
        $WORKER_IMG -m weirvern.weirling_client enroll \
        --hub '$GATEWAY_URL' --token '$MTLS_TOKEN' --sensor-id '$SENSOR_ID' \
        --dir /etc/weirvern-weirling/pki --root-ca /etc/weirvern-weirling/pki/root-ca.crt \
        --segment '$SEGMENT'" \
        || die "the target could not enroll with $GATEWAY_URL; check the gateway, DNS, and the token"
    rsh "$TARGET" "test -s /etc/weirvern-weirling/pki/weirling.crt && test -s /etc/weirvern-weirling/pki/weirling.key" \
        || die "enrollment returned success but the certificate or key is missing"
    say "  adopted: certificate issued, private key stays on the target"
    {
        printf 'WEIRLING_GATEWAY_URL=%s\n' "$GATEWAY_URL"
        printf 'WEIRLING_CLIENT_CERT=/etc/weirvern-weirling/pki/weirling.crt\n'
        printf 'WEIRLING_CLIENT_KEY=/etc/weirvern-weirling/pki/weirling.key\n'
        printf 'WEIRLING_ROOT_CA=/etc/weirvern-weirling/pki/root-ca.crt\n'
    } | rsh "$TARGET" "cat > /etc/weirvern-weirling.env && chmod 0600 /etc/weirvern-weirling.env"
else
    # The agent retries forever by design, so a wrong address would spin silently until someone
    # reads its logs -- the first live install DID exactly that (the headless-service address
    # "None" went into its config). Knock on the door now, with the real client, before anything
    # is started.
    step "checking the target can reach ClickHouse"
    rsh "$TARGET" "docker run --rm --network host --entrypoint python3 $WORKER_IMG -c 'import urllib.request; urllib.request.urlopen(\"http://$CH_HOST:$CH_PORT/ping\", timeout=5); print(\"reachable\")'" \
        || die "the target cannot reach ClickHouse at $CH_HOST:$CH_PORT -- open the door (--expose) or fix the route, then re-run"
    say "  ClickHouse answers at $CH_HOST:$CH_PORT"

    # ── creds + site policy on the target ───────────────────────────────────────────────────
    step "writing the target's configuration"
    # PER-WEIRLING CLICKHOUSE CREDENTIAL (HD-25, GitHub #25). This used to copy the HUB's own
    # ClickHouse user and password to every sensor: one compromised weirling yielded the database
    # credential for the whole deployment, and revoking one sensor meant rotating all of them.
    # Now each sensor gets its own user, INSERT-only on the weirvern database (flows, the zeek_*
    # tables and sensor_status all go through that one code path), and the password is generated
    # here, written only to the target's 0600 env file, and never printed.
    CH_USER="wv_$(printf '%s' "$SENSOR_ID" | tr '-' '_')"
    CH_PASS="$(rand_hex)"
    CRED_SQL="CREATE USER IF NOT EXISTS ${CH_USER} IDENTIFIED WITH sha256_password BY '${CH_PASS}';
ALTER USER ${CH_USER} IDENTIFIED WITH sha256_password BY '${CH_PASS}';
GRANT INSERT ON weirvern.* TO ${CH_USER};"
    printf '%s\n' "$CRED_SQL" | rsh "$HUB" "kubectl -n weirvern exec -i clickhouse-0 -- clickhouse-client --multiquery" \
        || die "could not create the per-weirling ClickHouse user ${CH_USER} on the hub -- refusing to fall back to the hub's shared credential"
    # WHICH USER BELONGS TO WHICH SENSOR, so one sensor can be revoked without touching the rest.
    rsh "$HUB" "install -d -m 0700 /var/lib/weirvern && printf '%s\t%s\t%s\n' '$SENSOR_ID' '$CH_USER' \"\$(date -u +%Y-%m-%dT%H:%M:%SZ)\" >> /var/lib/weirvern/sensor-credentials.tsv && chmod 0600 /var/lib/weirvern/sensor-credentials.tsv" \
        || say "  warning: could not record the sensor credential in /var/lib/weirvern/sensor-credentials.tsv"
    say "  credential: ${CH_USER} (INSERT only, per sensor)"
    {
        printf 'CLICKHOUSE_HOST=%s\n' "$CH_HOST"
        printf 'CLICKHOUSE_PORT=%s\n' "$CH_PORT"
        printf 'CLICKHOUSE_USER=%s\n' "$CH_USER"
        printf 'CLICKHOUSE_PASSWORD=%s\n' "$CH_PASS"
        # THE LAB ESCAPE, WRITTEN OUT LOUD. `sensor_agent.connect` now refuses to touch ClickHouse
        # unless this is set, because the deployment rule is that every hub/weirling message crosses
        # the mTLS gateway. --legacy-clickhouse is the migration path for a hub whose gateway is not
        # reachable yet, so the flag is set here, in the file that also carries the credential it
        # justifies -- one file to delete when the sensor is enrolled properly.
        printf 'WEIRLING_ALLOW_DIRECT_CLICKHOUSE=1\n'
    } | rsh "$TARGET" "cat > /etc/weirvern-weirling.env && chmod 0600 /etc/weirvern-weirling.env"
fi

POLICY="$(rsh "$HUB" "kubectl -n weirvern get cm $SITE_CM -o go-template='{{index .data \"weirvern-local.zeek\"}}'")"
[ -n "$POLICY" ] || die "the site policy ConfigMap came back empty -- refusing to install a policy-less sensor"
rsh "$TARGET" "mkdir -p /etc/weirvern-weirling/site /var/lib/weirvern-weirling/logs"
printf '%s\n' "$POLICY" | rsh "$TARGET" "cat > /etc/weirvern-weirling/site/weirvern-local.zeek"
say "  env file (0600) + site policy written"

# ── the local helper + the containers ───────────────────────────────────────────────────────
# The helper is generated here with concrete values so the target stays self-operable:
# `weirvern-weirling status|start|stop` needs no knowledge of the hub.
step "installing the helper and starting the weirling"
rsh "$TARGET" "cat > /usr/local/bin/weirvern-weirling && chmod 0755 /usr/local/bin/weirvern-weirling" <<HELPER
#!/bin/sh
# weirvern-weirling -- generated by deploy-weirling.sh for identity "$SENSOR_ID" ($IFACE).
set -eu
ID='$SENSOR_ID'; IFACE='$IFACE'; MGMT='$DEFROUTE'; ALLOW_MGMT='$ALLOW_MGMT'
ZEEK_IMG='$ZEEK_IMG'; WORKER_IMG='$WORKER_IMG'; AGENT_IMG='$AGENT_IMG'
NETFLOW='$NETFLOW'; GOFLOW_IMG='netsampler/goflow2:v2.2.6'
LOGDIR=/var/lib/weirvern-weirling/logs; FLOWDIR=/var/lib/weirvern-weirling/flows
PKIDIR=/etc/weirvern-weirling/pki
ENVF=/etc/weirvern-weirling.env
# The mTLS agent runs as root only because the remote Sonar ARP probe needs an
# effective NET_RAW capability, which Docker does not grant to a non-root UID.
AGENT_USER='10001:10001'
[ "$MTLS" = "1" ] && AGENT_USER='0:0'
# Every unit owns one trunk-state directory. It survives a restart so the next probe can
# remove VLAN devices this unit created when the port is moved back to an access port.
TRUNKSTATE="/var/lib/weirvern-weirling/trunk-\$ID"
[ "$INLINE" = "1" ] && TRUNKSTATE="/var/lib/weirvern-weirling/inline-\$ID"
case "\${1:-status}" in
  status) docker ps --filter "name=weirvern-.*-\$ID" --format '{{.Names}} {{.Status}}' ;;
  stop)   docker rm -f "weirvern-capture-\$ID" "weirvern-agent-\$ID" "weirvern-gate-\$ID" "weirvern-netflow-\$ID" >/dev/null 2>&1 || true ;;
  start)
    NOW="\$(ip route show default 2>/dev/null | sed -n 's/.*dev \\([^ ]*\\).*/\\1/p' | head -1)"
    if [ "\$IFACE" = "\$MGMT" ] || [ "\$IFACE" = "\$NOW" ]; then
      if [ "\$ALLOW_MGMT" != "1" ]; then
        echo "weirvern-weirling: REFUSING to capture on '\$IFACE' -- management NIC." >&2
        echo "  This host has only one NIC? Reinstall with --allow-management-nic to accept a" >&2
        echo "  DEGRADED sensor that sees only its own traffic." >&2
        exit 1
      fi
      echo "weirvern-weirling: capturing on the MANAGEMENT NIC '\$IFACE' -- DEGRADED, accepted." >&2
      echo "  Sees this host's own traffic only. Not the segment. Not other stations." >&2
    fi
    docker rm -f "weirvern-capture-\$ID" "weirvern-agent-\$ID" "weirvern-gate-\$ID" "weirvern-netflow-\$ID" >/dev/null 2>&1 || true
    # TRUNK IS THE DEFAULT, NOT A MODE. Sonar's observation is run before capture starts:
    # no tags -> the state file names the parent; tags -> it names one VLAN device per tag and
    # this helper creates them in the host namespace with NET_ADMIN. The capture command then
    # reads the same state file, so an access port and a trunk take the identical path.
    # --inline/--no-trunk skip this: a bridge is not a trunk parent, and creating VLAN devices
    # on the bridge would be a second topology nobody asked for.
    mkdir -p "\$TRUNKSTATE"
    chmod 0755 "\$TRUNKSTATE" 2>/dev/null || true
    if [ "$NO_TRUNK" = "0" ]; then
    docker run --rm --network host --user 0:0 --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW \
      --security-opt no-new-privileges -v "\$TRUNKSTATE":/state -e MGMT_IFACE="\$MGMT" \
      --entrypoint python3 "\$WORKER_IMG" -m weirvern.admin.trunk detect \
      --parent "\$IFACE" --state /state --seconds "\${TRUNK_DETECT_S:-12}" \
      >/tmp/weirvern-trunk-\$ID.log 2>&1 || echo "weirvern-trunk: probe failed; capture will use \$IFACE (see /tmp/weirvern-trunk-\$ID.log)"
    fi
    docker run -d --name "weirvern-capture-\$ID" --restart unless-stopped \\
      --network host --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges \\
      -v "\$LOGDIR":/zeek/logs -v /etc/weirvern-weirling/site:/zeek/site:ro \\
      -v "\$TRUNKSTATE":/state:ro -e FALLBACK_IFACE="$IFACE" \\
      --entrypoint /bin/sh "$ZEEK_IMG" -c 'set -eu; IFACES=\$(cat /state/ifaces 2>/dev/null || true); : "\${IFACES:=\$FALLBACK_IFACE}"; PIDS=""; for one in \$IFACES; do [ -e /sys/class/net/\$one ] || { echo "no such interface: \$one" >&2; exit 1; }; mkdir -p /zeek/logs/\$one; zeek -i \$one -C /zeek/site/weirvern-local.zeek Log::default_rotation_interval=1hr Log::default_logdir=/zeek/logs/\$one & PIDS="\$PIDS \$!"; done; trap "kill \$PIDS 2>/dev/null; wait" TERM INT; wait' >/dev/null
    if [ "\$NETFLOW" = "1" ]; then
      # THE COLLECTOR. Runs the hub's own collector image with the hub's own arguments, so a record
      # written here is the record the hub writes for its exporters; the agent above ships them into
      # the same flows table. uid 100 is the image's own user and the directory is chowned to it --
      # no root needed, unlike the in-cluster unit (a hostPath there cannot be chowned by a pod).
      mkdir -p "\$FLOWDIR"
      chown 100:10001 "\$FLOWDIR" 2>/dev/null || true
      docker run -d --name "weirvern-netflow-\$ID" --restart unless-stopped \\
        --network host --user 100:10001 --security-opt no-new-privileges \\
        -v "\$FLOWDIR":/flows \\
        "\$GOFLOW_IMG" -listen netflow://:2055,sflow://:6343 -format json \\
        -transport file -transport.file /flows/flows.jsonl >/dev/null
    fi
    docker run -d --name "weirvern-agent-\$ID" --restart unless-stopped \\
      --network host --env-file "\$ENVF" --user "\$AGENT_USER" \\
      --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \\
      -e SENSOR_ID="\$ID" -e ZEEK_IFACE="\$IFACE" -e ZEEK_LOG_DIR=/zeek/logs \\
      -e MGMT_IFACE="\$MGMT" -e TRUNK_STATE_DIR=/state -e TRUNK_DISABLE="$NO_TRUNK" \\
      -e WEIRLING_NETFLOW="\$NETFLOW" -e WEIRLING_FLOW_FILE=/flows/flows.jsonl \\
      -v "\$LOGDIR":/zeek/logs:ro -v "\$FLOWDIR":/flows:ro \\
      -v "\$TRUNKSTATE":/state \\
      -v "\$PKIDIR":"\$PKIDIR":ro \\
      -v /etc/os-release:/etc/os-release:ro \\
      --entrypoint python3 "$AGENT_IMG" -m weirvern.admin.sensor_agent >/dev/null
    # NOTE ON THE EXPANSIONS: this whole block was written by the deploy script (the heredoc is
    # unquoted), so \$GATE and \$GATE_IFACE are decided NOW, while \$ID and \$GATE_IF are left
    # for the target's own runtime.
    if [ "$GATE" = "1" ]; then
      # THE GATE. Same image, same code path as the hub's (WEIRVERN_ROLE=gate): it reads the shared
      # rules and enforces them HERE, with the hub's own checks -- enabled, a VERIFIED path, a
      # readable ruleset, never the management NIC. It derives nothing: the hub is the single
      # writer, and a second deriver would mint a second rule for one detection.
      #
      # NET_ADMIN because installing a ruleset is the job; everything else is dropped, and
      # no-new-privileges stays on.
      GATE_IF='$GATE_IFACE'
      if [ "\$GATE_IF" = "\$MGMT" ] || [ "\$GATE_IF" = "\$NOW" ]; then
        echo "weirvern-gate: REFUSING to enforce on '\$GATE_IF' -- management NIC" >&2; exit 1
      fi
      docker run -d --name "weirvern-gate-\$ID" --restart unless-stopped \\
        --network host --user 0:0 --cap-drop ALL --cap-add NET_ADMIN --security-opt no-new-privileges \\
        --env-file "\$ENVF" \\
        -e WEIRVERN_ROLE=gate -e SENSOR_ID="\$ID" \\
        -e SLUICE_ENABLED=1 -e SLUICE_IFACE="\$GATE_IF" \\
        -e SLUICE_INTERVAL_S=60 -e SLUICE_MAX_BLOCK_S=3600 \\
        --entrypoint python3 "\$WORKER_IMG" -m weirvern.worker >/dev/null
      echo "weirvern-weirling \$ID: gate enforcing on \$GATE_IF (rules come from the hub)"
    else
      echo "weirvern-weirling \$ID: started (capture + agent; no gate -- pass --gate to enforce here)"
    [ "\$NETFLOW" = "1" ] && echo "  netflow: collector on 2055/6343 -- point an exporter here and the records land in the hub"
    # THE BRANCH MUST END TRUE. As a bare test-and-echo, a unit without --netflow ended the
    # start branch with status 1, so weirvern-weirling start returned 1 and deploy-weirling.sh
    # aborted (set -e) before its heartbeat check -- on every unit that was not a collector.
    true
    fi
    ;;
  *) echo "usage: weirvern-weirling [status|start|stop]" >&2; exit 2 ;;
esac
HELPER
rsh "$TARGET" "weirvern-weirling start"
say "  started"

# ── verify: the container can ACTUALLY scan, not just "the container started" ────────────────
# The readiness line is the fleet's measured fact, so the installer measures it here instead of
# letting the operator discover `nmap missing` in the console later. Both halves are checked: the
# binary and the capability that decides connect vs SYN/UDP.
step "verifying the agent's scan capability"
NMAP_LINE=""
i=0
while [ "$i" -lt 6 ]; do
    NMAP_LINE="$(rsh "$TARGET" "docker exec weirvern-agent-$SENSOR_ID nmap --version 2>/dev/null | head -1" || true)"
    [ -n "$NMAP_LINE" ] && break
    i=$((i + 1)); sleep 2
done
CAPS="$(rsh "$TARGET" "docker inspect --format '{{json .HostConfig.CapAdd}}' weirvern-agent-$SENSOR_ID 2>/dev/null" || true)"
if [ -n "$NMAP_LINE" ]; then
    UID_IN="$(rsh "$TARGET" "docker exec weirvern-agent-$SENSOR_ID id -u 2>/dev/null" || true)"
    GETCAP_LINE="$(rsh "$TARGET" "docker exec weirvern-agent-$SENSOR_ID getcap /usr/bin/nmap 2>/dev/null" || true)"
    HAVE_BOTH=0
    case "$CAPS" in *NET_RAW*) case "$CAPS" in *NET_ADMIN*) HAVE_BOTH=1 ;; esac ;; esac
    FILE_CAPS=0
    case "$GETCAP_LINE" in *cap_net_raw*) case "$GETCAP_LINE" in *cap_net_admin*) FILE_CAPS=1 ;; esac ;; esac
    if [ "$HAVE_BOTH" = "1" ] && { [ "$UID_IN" = "0" ] || [ "$FILE_CAPS" = "1" ]; }; then
        MODE="syn/udp"
    else
        MODE="connect"
    fi
    NMAP_VER="$(printf '%s' "$NMAP_LINE" | sed -n 's/.*version \([0-9][0-9.]*\).*/\1/p')"
    say "  scan: $NMAP_LINE"
    say "  capabilities: ${CAPS:-none reported}; uid ${UID_IN:-unknown}; file caps ${GETCAP_LINE:-none}"
    say "  readiness will read: $SENSOR_ID can scan (nmap ${NMAP_VER:-unknown}, $MODE)"
    [ "$MODE" = "syn/udp" ] || say "  WARNING: raw-socket capability is incomplete; this unit can only run connect scans."
else
    say "  WARNING: the agent container has no nmap; this unit will report 'nmap missing' and"
    say "           will not claim scans. It must run $SCAN_IMG (Containerfile.scanner), not the"
    say "           worker image; rebuild and re-run, or pass --agent-image."
fi

# ── verify: a FRESH heartbeat for this id in the hub's database ─────────────────────────────
step "verifying the heartbeat reaches the hub"
i=0
while [ "$i" -lt 12 ]; do
    n="$(rsh "$HUB" "kubectl -n weirvern exec clickhouse-0 -- clickhouse-client -q \"SELECT count() FROM weirvern.sensor_status WHERE sensor_id = '$SENSOR_ID' AND ts > now() - INTERVAL 45 SECOND\"" 2>/dev/null | tail -1)"
    [ "${n:-0}" -gt 0 ] 2>/dev/null && break
    i=$((i + 1)); sleep 5
done
if [ "${n:-0}" -gt 0 ] 2>/dev/null; then
    say "  heartbeat OK: \"$SENSOR_ID\" is reporting (iface $IFACE)"
    say ""
    if [ "$MTLS" = "1" ]; then
        say "NEXT: the enrollment registered \"$SENSOR_ID\" -- confirm it in the Weirlings view."
    else
        say "NEXT: open the Weirlings view and register \"$SENSOR_ID\" -- the row shows as"
        say "      UNREGISTERED until you say whose it is."
    fi
    say "      Operate it on the target with:"
    say "      weirvern-weirling status|start|stop   (logs under /var/lib/weirvern-weirling)"
else
    die "no fresh heartbeat after 60s -- check on the target: weirvern-weirling status; docker logs weirvern-agent-$SENSOR_ID; docker logs weirvern-capture-$SENSOR_ID"
fi
