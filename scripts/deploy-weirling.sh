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
# THE MANAGEMENT NIC IS NEVER A CAPTURE PORT (Samuel's standing rule): the target's
# default-route interface is REFUSED, not warned about, on both sides of the wire.
#
# IT DOES NOT REGISTER THE SENSOR. Registration is an operator's declaration in the Weirlings
# view ("who is this and whose is it"); the row appears as UNREGISTERED until someone says so.
# That is the view's entire point.
#
# THE TRANSPORT IS DIRECT: the agent writes sensor_status into the hub's ClickHouse. When the
# target is not the hub, that needs clickhouse-external reachable from the target -- pass
# --expose to let this script open the NodePort (it prints exactly what it changed), or open
# it yourself. The documented durable alternative (a broker) is a later design change.
#
# USAGE
#   scripts/deploy-weirling.sh --hub root@hub --target root@sensor-box \
#          --iface eth1 --sensor-id weirvern-eth1 [--expose] [--dry-run] [--yes]
#   scripts/deploy-weirling.sh --target root@sensor-box --iface eth1 \
#          --sensor-id weirvern-eth1 --remove [--purge]
#
#   --hub         ssh destination of the weirvern hub (images, ClickHouse, the site policy)
#   --target      ssh destination of the new sensor box; "local" = this machine
#   --iface       the DEDICATED capture port on the target (never its management NIC)
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
#   --remove      stop and remove the containers on the target (logs kept; --purge too)
#   --purge       with --remove: also delete the env file, helper and log directory
#   --dry-run     run every CHECK (including the refusals) and print the plan; change nothing
#   --yes         skip the interactive confirmation before the first change
set -eu

HUB=""
TARGET=""
IFACE=""
SENSOR_ID=""
EXPOSE=0
GATE=0
GATE_IFACE=""
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
        --expose) EXPOSE=1; shift ;;
        --gate) GATE=1; shift ;;
        --gate-iface) GATE_IFACE="${2:?--gate-iface needs a value}"; shift 2 ;;
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
    [ -n "$IFACE" ] || die "--iface is required -- which DEDICATED port does this weirling capture?"
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
if [ "$IFACE" = "$DEFROUTE" ]; then
    die "REFUSING: '$IFACE' is the target's management NIC (default route). Use a dedicated capture port."
fi
case "$IFACE" in lo) die "REFUSING: 'lo' is the loopback interface" ;; esac
say "  capture port: $IFACE (target's management port is $DEFROUTE -- untouched)"

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
say "  images: $WORKER_IMG , $ZEEK_IMG"
say "  site policy: $SITE_CM"

# ── the ClickHouse endpoint as seen FROM THE TARGET ─────────────────────────────────────────
# ONE DOOR FOR EVERY TARGET: clickhouse-external. The in-cluster `clickhouse` Service is
# HEADLESS (clusterIP: None -- MEASURED: the first version of this script read the literal
# string "None" out of it and shipped that into the agent's config, where it retried forever),
# so it offers no stable address even to a client on the hub itself. clickhouse-external is
# the door built for outside clients; when it has no NodePort yet, --expose opens one and this
# script says exactly what it changed (revert by re-applying k8s/).
CH_HOST="$(rsh "$HUB" "hostname -I" | tr ' ' '\n' | grep -E '^[0-9]+\.' | head -1)"
[ -n "$CH_HOST" ] || die "could not determine the hub's LAN address"
CH_PORT="$(rsh "$HUB" "kubectl -n weirvern get svc clickhouse-external -o jsonpath='{.spec.ports[0].nodePort}'")"
if [ -z "$CH_PORT" ]; then
    if [ "$EXPOSE" = "1" ]; then
        P_NAME="$(rsh "$HUB" "kubectl -n weirvern get svc clickhouse-external -o jsonpath='{.spec.ports[0].name}'")"
        P_PORT="$(rsh "$HUB" "kubectl -n weirvern get svc clickhouse-external -o jsonpath='{.spec.ports[0].port}'")"
        P_TARGET="$(rsh "$HUB" "kubectl -n weirvern get svc clickhouse-external -o jsonpath='{.spec.ports[0].targetPort}'")"
        if [ "$DRY" = "1" ]; then :; else
            # Change ONLY the type and let Kubernetes assign the nodePort, then read it back.
            # (The first version rebuilt the whole ports list and tripped over `targetPort:
            # http` -- a NAMED container port, i.e. a string, which interpolated as bare JSON
            # and became "invalid character 'h' looking for beginning of value".)
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

if [ "$DRY" = "1" ]; then
    step "DRY RUN -- plan for weirling \"$SENSOR_ID\" on $TARGET"
    say "  1. stream $ZEEK_IMG and $WORKER_IMG from $HUB to $TARGET (docker save | docker load)"
    say "  2. write /etc/weirvern-weirling.env (0600: ClickHouse endpoint + credentials from the hub's Secret)"
    say "  3. install the site policy from ConfigMap $SITE_CM and a local helper /usr/local/bin/weirvern-weirling"
    say "  4. start weirvern-capture-$SENSOR_ID (Zeek on $IFACE, host network, NET_RAW) and"
    say "     weirvern-agent-$SENSOR_ID (heartbeats, restart unless-stopped)"
    say "  5. verify a fresh heartbeat for \"$SENSOR_ID\" lands in the hub's database"
    say "  then: register it in the Weirlings view -- it appears as UNREGISTERED until you do"
    exit 0
fi

if [ "$YES" = "0" ]; then
    printf 'Install weirling "%s" on %s capturing %s? [y/N] ' "$SENSOR_ID" "$TARGET" "$IFACE"
    read -r ans || ans=""
    case "$ans" in y|Y|yes|YES) : ;; *) die "not confirmed" ;; esac
fi

# ── ship the images (streamed; nothing lands on the machine running THIS script) ──────────
step "shipping the images to the target"
rsh "$HUB" "docker save $ZEEK_IMG $WORKER_IMG" | rsh "$TARGET" "docker load" >/dev/null
say "  loaded: $ZEEK_IMG , $WORKER_IMG"

# The agent retries forever by design, so a wrong address would spin silently until someone
# reads its logs -- the first live install DID exactly that (the headless-service address
# "None" went into its config). Knock on the door now, with the real client, before anything
# is started.
step "checking the target can reach ClickHouse"
rsh "$TARGET" "docker run --rm --network host --entrypoint python3 $WORKER_IMG -c 'import urllib.request; urllib.request.urlopen(\"http://$CH_HOST:$CH_PORT/ping\", timeout=5); print(\"reachable\")'" \
    || die "the target cannot reach ClickHouse at $CH_HOST:$CH_PORT -- open the door (--expose) or fix the route, then re-run"
say "  ClickHouse answers at $CH_HOST:$CH_PORT"

# ── creds + site policy on the target ───────────────────────────────────────────────────────
step "writing the target's configuration"
# The password goes from the hub's Secret into the target's 0600 env file; it is never printed.
CH_USER="$(rsh "$HUB" "kubectl -n weirvern get cm weirvern-env -o go-template='{{index .data \"CLICKHOUSE_USER\"}}'" || true)"
CH_USER="${CH_USER:-weirvern}"
{
    printf 'CLICKHOUSE_HOST=%s\n' "$CH_HOST"
    printf 'CLICKHOUSE_PORT=%s\n' "$CH_PORT"
    printf 'CLICKHOUSE_USER=%s\n' "$CH_USER"
    printf 'CLICKHOUSE_PASSWORD=%s\n' "$(rsh "$HUB" "kubectl -n weirvern get secret weirvern-secrets -o jsonpath='{.data.CLICKHOUSE_PASSWORD}' | base64 -d")"
} | rsh "$TARGET" "cat > /etc/weirvern-weirling.env && chmod 0600 /etc/weirvern-weirling.env"

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
ID='$SENSOR_ID'; IFACE='$IFACE'; MGMT='$DEFROUTE'
ZEEK_IMG='$ZEEK_IMG'; WORKER_IMG='$WORKER_IMG'
LOGDIR=/var/lib/weirvern-weirling/logs; ENVF=/etc/weirvern-weirling.env
case "\${1:-status}" in
  status) docker ps --filter "name=weirvern-.*-\$ID" --format '{{.Names}} {{.Status}}' ;;
  stop)   docker rm -f "weirvern-capture-\$ID" "weirvern-agent-\$ID" "weirvern-gate-\$ID" >/dev/null 2>&1 || true ;;
  start)
    NOW="\$(ip route show default 2>/dev/null | sed -n 's/.*dev \\([^ ]*\\).*/\\1/p' | head -1)"
    if [ "\$IFACE" = "\$MGMT" ] || [ "\$IFACE" = "\$NOW" ]; then
      echo "weirvern-weirling: REFUSING to capture on '\$IFACE' -- management NIC" >&2; exit 1
    fi
    docker rm -f "weirvern-capture-\$ID" "weirvern-agent-\$ID" "weirvern-gate-\$ID" >/dev/null 2>&1 || true
    docker run -d --name "weirvern-capture-\$ID" --restart unless-stopped \\
      --network host --cap-drop ALL --cap-add NET_RAW --security-opt no-new-privileges \\
      -v "\$LOGDIR":/zeek/logs -v /etc/weirvern-weirling/site:/zeek/site:ro \\
      --entrypoint /bin/sh "$ZEEK_IMG" -c "set -eu; IFACE='$IFACE'; [ -e /sys/class/net/$IFACE ] || exit 1; exec zeek -i $IFACE -C /zeek/site/weirvern-local.zeek Log::default_rotation_interval=1hr Log::default_logdir=/zeek/logs" >/dev/null
    docker run -d --name "weirvern-agent-\$ID" --restart unless-stopped \\
      --network host --env-file "\$ENVF" \\
      -e SENSOR_ID="\$ID" -e ZEEK_IFACE="\$IFACE" -e ZEEK_LOG_DIR=/zeek/logs \\
      -v "\$LOGDIR":/zeek/logs:ro \\
      --entrypoint python3 "\$WORKER_IMG" -m weirvern.admin.sensor_agent >/dev/null
    # NOTE ON THE EXPANSIONS: this whole block was written by the deploy script (the heredoc is
    # unquoted), so `$GATE` and `$GATE_IFACE` are decided NOW, while `\$ID` and `\$GATE_IF` are left
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
        --network host --cap-drop ALL --cap-add NET_ADMIN --security-opt no-new-privileges \\
        --env-file "\$ENVF" \\
        -e WEIRVERN_ROLE=gate -e SENSOR_ID="\$ID" \\
        -e SLUICE_ENABLED=1 -e SLUICE_IFACE="\$GATE_IF" \\
        -e SLUICE_INTERVAL_S=60 -e SLUICE_MAX_BLOCK_S=3600 \\
        --entrypoint python3 "\$WORKER_IMG" -m weirvern.worker >/dev/null
      echo "weirvern-weirling \$ID: gate enforcing on \$GATE_IF (rules come from the hub)"
    else
      echo "weirvern-weirling \$ID: started (capture + agent; no gate -- pass --gate to enforce here)"
    fi
    ;;
  *) echo "usage: weirvern-weirling [status|start|stop]" >&2; exit 2 ;;
esac
HELPER
rsh "$TARGET" "weirvern-weirling start"
say "  started"

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
    say "NEXT: open the Weirlings view and register \"$SENSOR_ID\" -- the row shows as"
    say "      UNREGISTERED until you say whose it is. Operate it on the target with:"
    say "      weirvern-weirling status|start|stop   (logs under /var/lib/weirvern-weirling)"
else
    die "no fresh heartbeat after 60s -- check on the target: weirvern-weirling status; docker logs weirvern-agent-$SENSOR_ID; docker logs weirvern-capture-$SENSOR_ID"
fi
