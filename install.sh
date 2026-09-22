#!/usr/bin/env bash
# Weirvern one-command installer for a single-node Ubuntu server.
#
#   curl -fsSL https://raw.githubusercontent.com/hodlhart/weirvern/main/install.sh | sudo bash
#   # or, from a checkout:
#   sudo ./install.sh [--siphon] [--zeek-iface ens19] [--mgmt-iface ens18]
#
# WHAT IT DOES, in the order it matters. Run it again and it converges: every step
# checks before changing anything, and nothing here ever overwrites a credential or
# a trained model.
#
#   1. Installs the three tools the deployment needs and nothing more: docker (IMAGE
#      BUILDER ONLY), k3s (the runtime), kustomize (the manifest assembler).
#   2. Gets the repository onto the machine (uses this checkout when run from one).
#   3. Prepares the node: host directories, the sensor-node label, the capture and
#      management interfaces.
#   4. Builds both images and imports them into k3s's own containerd. THIS IS THE
#      STEP PEOPLE GET WRONG: a k3s node cannot pull `weirvern-worker:0.8.0` from
#      anywhere -- the image is built locally and imported, which is also why docker
#      is a builder and k3s is the runtime, never the other way round.
#   5. Applies the manifests, creates the Secret if it does not exist yet (a random
#      ClickHouse password; never regenerated once set), and restarts the readers so
#      the Secret they mount actually exists.
#   6. Waits for real readiness -- the schema Job completing and every pod Ready --
#      and says which pod is not, rather than exiting 0 into a half-deployment.
#   7. With --siphon, also applies the siphon overlay so the in-path mode's
#      capabilities exist BEFORE anyone flips the switch in Settings. Without it the
#      GUI's mode gate refuses siphon, correctly, and that refusal looks like a bug.
#
# WHAT IT DELIBERATELY DOES NOT DO: configure Pushover (needs your credentials),
# choose an intercept target (that takes local knowledge -- the installer prints the
# command that surveys a segment), or enable siphon mode (a deliberate act, taken in
# Settings once you have seen the segment).
set -euo pipefail

# ── configuration ─────────────────────────────────────────────────────────────────
REPO_URL="${WEIRVERN_REPO:-https://github.com/hodlhart/weirvern.git}"
INSTALL_DIR="${WEIRVERN_DIR:-/opt/weirvern}"
NAMESPACE="weirvern"
KUSTOMIZE_VERSION="v5.7.1"
K3S_READY_TIMEOUT=180
PODS_READY_TIMEOUT=420
SCHEMA_TIMEOUT=300

SIPHON=0
NO_BUILD=0
ZEEK_IFACE_FLAG=""
MGMT_IFACE_FLAG=""

usage() {
    sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
    cat <<'EOF'

Options:
  --siphon              also apply overlays/siphon/ (grants the capabilities the
                        in-path mode needs; the mode is still switched in Settings)
  --zeek-iface IFACE    the capture interface (default: auto-detect -- the UP
                        interface that is NOT carrying the default route)
  --mgmt-iface IFACE    the management interface (default: the default-route one)
  --no-build            skip building images (re-import images you already built)
  --dir PATH            install location for the checkout (default /opt/weirvern)
  -h, --help            this help
EOF
}

log()  { printf '\n\033[1m>>> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[32mok\033[0m %s\n' "$*"; }
warn() { printf '    \033[33mwarn\033[0m %s\n' "$*"; }
die()  { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --siphon)        SIPHON=1 ;;
        --no-build)      NO_BUILD=1 ;;
        --zeek-iface)    ZEEK_IFACE_FLAG="${2:?--zeek-iface needs an interface name}"; shift ;;
        --mgmt-iface)    MGMT_IFACE_FLAG="${2:?--mgmt-iface needs an interface name}"; shift ;;
        --dir)           INSTALL_DIR="${2:?--dir needs a path}"; shift ;;
        -h|--help)       usage; exit 0 ;;
        *)               die "unknown option: $1 (try --help)" ;;
    esac
    shift
done

# ── preflight ─────────────────────────────────────────────────────────────────────
log "Preflight"
[ "$(id -u)" = "0" ] || die "run as root (sudo ./install.sh): the installer wires up k3s, docker and node sysctls"
[ "$(uname -s)" = "Linux" ] || die "this installer targets Linux"
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|aarch64) : ;;
    *) die "unsupported architecture $ARCH; the images are built for amd64/arm64" ;;
esac
# ClickHouse ships as an x86-64-v3 (AVX2) build since 26.6, and the manifest pins 26.8.
# A VM whose CPU model MASKS AVX2 -- Proxmox's default 'kvm64' is the common one --
# crash-loops it with "Illegal instruction (core dumped)" while every other pod waits
# on it: a deployment that looks broken for a reason nothing in the cluster states.
# Refuse HERE, where the remedy can be named. (Found by the blank-box dogfood on a
# Proxmox VM; an LXC never shows it because containers see the host CPU directly.)
if [ "$ARCH" = "x86_64" ] && ! grep -qw avx2 /proc/cpuinfo; then
    die "this CPU lacks AVX2 (x86-64-v3), which the pinned ClickHouse image requires.
      VM: set the CPU type to 'host' (Proxmox: VM -> Hardware -> Processors -> Type)
      and STOP/START the VM -- a guest reboot does not apply a CPU model change.
      Bare metal: x86-64-v3 means Haswell-era (2013) or newer."
fi
command -v systemctl >/dev/null || die "systemd is required (k3s and docker run as services)"
ok "$( (. /etc/os-release && echo "$PRETTY_NAME") || true) on $(uname -m)"

if [ "$(df -Pk / | awk 'NR==2{print $4}')" -lt 15000000 ]; then
    warn "less than ~15 GB free on /; ClickHouse wants a real data volume"
fi

export DEBIAN_FRONTEND=noninteractive
if ! command -v curl >/dev/null || ! command -v git >/dev/null; then
    log "Installing base tools (curl, git)"
    apt-get update -qq
    apt-get install -y -qq curl git ca-certificates
fi

# ── docker: IMAGE BUILDER ONLY ────────────────────────────────────────────────────
# WHY DOCKER AT ALL, when k3s ships its own containerd: a Kubernetes node cannot
# build an image, and this deployment runs locally-built images (no registry). Docker
# exists here solely to produce them; `k3s ctr images import` (below) is what makes
# them runnable. Nothing in the cluster talks to the Docker daemon.
log "Docker (image builder)"
if command -v docker >/dev/null; then
    ok "already installed: $(docker --version)"
else
    apt-get update -qq
    apt-get install -y -qq docker.io
    systemctl enable --now docker >/dev/null
    ok "installed: $(docker --version)"
fi
systemctl is-active --quiet docker || { systemctl start docker; }

# ── k3s: the runtime ──────────────────────────────────────────────────────────────
log "k3s (Kubernetes runtime)"
if command -v k3s >/dev/null; then
    ok "already installed: $(k3s --version | head -1)"
else
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server" sh -
    ok "installed: $(k3s --version | head -1)"
fi
if [ ! -f /root/.kube/config ]; then
    mkdir -p /root/.kube
    cp /etc/rancher/k3s/k3s.yaml /root/.kube/config
    ok "kubeconfig copied to /root/.kube/config"
fi
# Wait for the node to be Ready BEFORE anything is applied: applying into a cluster
# whose API server is still coming up produces a wall of connection errors that look
# like a broken deployment.
deadline=$(( $(date +%s) + K3S_READY_TIMEOUT ))
until kubectl get nodes 2>/dev/null | grep -q ' Ready '; do
    [ "$(date +%s)" -lt "$deadline" ] || die "the k3s node did not become Ready in ${K3S_READY_TIMEOUT}s (journalctl -u k3s | tail -50)"
    sleep 3
done
ok "node Ready: $(kubectl get nodes --no-headers | awk '{print $1" "$2}')"

# ── kustomize ─────────────────────────────────────────────────────────────────────
# Needed for overlays/ (kubectl's built-in kustomize cannot build them against a
# directory that references its own base) and for the repo's own test suite.
log "kustomize"
if command -v kustomize >/dev/null; then
    ok "already installed: $(kustomize version)"
else
    case "$(uname -m)" in
        x86_64) karch=amd64 ;;
        aarch64) karch=arm64 ;;
    esac
    tmp=$(mktemp -d)
    curl -sfL -o "$tmp/kustomize.tgz" \
        "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2F${KUSTOMIZE_VERSION}/kustomize_${KUSTOMIZE_VERSION}_linux_${karch}.tar.gz"
    tar xzf "$tmp/kustomize.tgz" -C "$tmp"
    install -m 0755 "$tmp/kustomize" /usr/local/bin/kustomize
    rm -rf "$tmp"
    ok "installed: $(kustomize version)"
fi

# ── the checkout ──────────────────────────────────────────────────────────────────
# Runs from an existing checkout when there is one (this script's own directory), and
# clones/updates $INSTALL_DIR otherwise. `git pull` is deliberately NOT used on an
# existing checkout: the operator may have local edits (interfaces, settings), and a
# silent pull over them is how a working deployment becomes confusing.
log "Repository"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SELF_DIR/k8s/kustomization.yaml" ]; then
    PROJECT_DIR="$SELF_DIR"
    ok "using this checkout: $PROJECT_DIR"
elif [ -f "$INSTALL_DIR/k8s/kustomization.yaml" ]; then
    PROJECT_DIR="$INSTALL_DIR"
    ok "using existing checkout: $PROJECT_DIR"
else
    if [ -d "$INSTALL_DIR" ]; then
        die "$INSTALL_DIR exists but does not look like a weirvern checkout; remove it or pass --dir"
    fi
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
    PROJECT_DIR="$INSTALL_DIR"
    ok "cloned to $PROJECT_DIR"
fi
cd "$PROJECT_DIR"

WORKER_TAG=$(awk -F'"' '/newTag/ {print $2; exit}' k8s/kustomization.yaml)
ZEEK_TAG=$(awk '/image: weirvern-zeek/ {sub(/.*weirvern-zeek:/, ""); print; exit}' k8s/32-zeek.yaml)
[ -n "$WORKER_TAG" ] && [ -n "$ZEEK_TAG" ] || die "could not read the image tags from k8s/ (is this a full checkout?)"
ok "images this deployment expects: weirvern-worker:$WORKER_TAG, weirvern-zeek:$ZEEK_TAG"

# ── node preparation ──────────────────────────────────────────────────────────────
log "Node preparation"
# The worker image bakes uid/gid 10001 (`useradd --system --uid 10001`), and the
# hostPaths it reads and Zeek writes into must be group-writable by that gid. Two
# traps, both caught by dogfooding on a blank box (the old dev box had both from a
# previous image build -- exactly why a blank-slate run was worth doing):
#   (a) on a fresh machine neither the user NOR the group exists yet, so
#       `install -g 10001` dies with "invalid group";
#   (b) DO NOT NAME IT "weirvern". Ubuntu gives every human account a private group
#       of the same name, so a host whose admin login is "weirvern" already owns
#       that name (at gid 1000) -- `groupadd weirvern` then collides and kills the
#       run. The contract is the NUMERIC gid (all the containers ever see); the
#       name is cosmetic, so pick one nothing else uses.
if ! getent group 10001 >/dev/null 2>&1; then
    groupadd -g 10001 weirvern-app 2>/dev/null \
        || groupadd -g 10001 weirvern-host 2>/dev/null \
        || die "gid 10001 is free but no candidate group name was; create a group at gid 10001 and re-run"
fi
if ! getent passwd 10001 >/dev/null 2>&1; then
    # Cosmetic on the host (no host process runs as it; containers use the numeric
    # gid), so a failure here is a warning, never a dead run.
    useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin weirvern-app 2>/dev/null \
        || useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin weirvern-host 2>/dev/null \
        || warn "no host user at uid 10001 (harmless: nothing on the host runs as it)"
fi
# hostPath volumes are NOT chowned by kubelet, so the directories the sensors write
# into must exist with the right group before the pods start; otherwise Zeek crashes
# on an unwritable log dir and the symptom is "the sensor is not capturing".
install -d -m 2775 -g 10001 /var/lib/weirvern/flows /var/lib/weirvern/zeek
ok "host directories ready (/var/lib/weirvern/{flows,zeek}, group 10001)"

# ── interfaces ────────────────────────────────────────────────────────────────────
# TWO INTERFACES, TWO JOBS, and the installer picks sensible defaults because the
# failure of getting this wrong is silent: a sensor on the management port captures
# broadcast noise and looks healthy. The default-route interface is the management
# port by definition; the capture port is the other UP interface.
log "Sensor interfaces"
DEFROUTE_IFACE=$(ip route show default | awk '/default/ {print $5; exit}')
[ -n "$DEFROUTE_IFACE" ] || die "could not determine the default-route interface"

if [ -n "$MGMT_IFACE_FLAG" ]; then
    MGMT_IFACE="$MGMT_IFACE_FLAG"
else
    MGMT_IFACE="$DEFROUTE_IFACE"
fi

if [ -n "$ZEEK_IFACE_FLAG" ]; then
    ZEEK_IFACE="$ZEEK_IFACE_FLAG"
else
    # Any other UP, non-virtual interface. `ip -brief link` lists every link; filter
    # to physical-ish names (en*/eth*) that are UP, excluding lo, docker, flannel and
    # the management port itself.
    ZEEK_IFACE=""
    for cand in $(ip -brief link | awk '$2=="UP" {print $1}'); do
        case "$cand" in
            lo|docker*|flannel*|cni*|veth*|br-*) continue ;;
        esac
        if [ "$cand" != "$MGMT_IFACE" ]; then
            ZEEK_IFACE="$cand"
            break
        fi
    done
fi

if [ -z "$ZEEK_IFACE" ] || [ "$ZEEK_IFACE" = "$MGMT_IFACE" ]; then
    warn "only one usable interface found; setting the capture interface to '$MGMT_IFACE'"
    warn "this works for a first look but the capture will be thin: a management port"
    warn "sees this host's own traffic plus broadcast, not the network. Add a second NIC"
    warn "(or a switch SPAN/mirror) and re-run with --zeek-iface when you have one."
    ZEEK_IFACE="$MGMT_IFACE"
else
    ok "management: $MGMT_IFACE   capture: $ZEEK_IFACE"
fi

# Write the interfaces into the ConfigMap source in the TREE, not just the live
# object: `kubectl apply -k` re-syncs the ConfigMap from the tree on every apply, so
# a live-only edit is reverted by the next deploy -- the documented trap.
python3 - "$PROJECT_DIR/k8s/20-configmap-env.yaml" "$ZEEK_IFACE" "$MGMT_IFACE" <<'PYEOF'
import re, sys
path, zeek, mgmt = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
text = re.sub(r'(?m)^(\s*)ZEEK_IFACE: ".*"$', rf'\g<1>ZEEK_IFACE: "{zeek}"', text)
text = re.sub(r'(?m)^(\s*)MGMT_IFACE: ".*"$', rf'\g<1>MGMT_IFACE: "{mgmt}"', text)
open(path, "w").write(text)
print(f"    set ZEEK_IFACE={zeek} MGMT_IFACE={mgmt} in k8s/20-configmap-env.yaml")
PYEOF

# The node label is what pins goflow2, the worker and the sensor to this machine.
# Without it on a single-node cluster everything still lands here (it is the only
# node) -- but on any cluster with more than one node, an unlabelled sensor captures
# nothing while looking fully healthy.
kubectl label node "$(kubectl get nodes --no-headers | awk 'NR==1{print $1}')" \
    weirvern.io/sensor-node=true --overwrite >/dev/null
ok "node labelled weirvern.io/sensor-node=true"

# ── images ────────────────────────────────────────────────────────────────────────
if [ "$NO_BUILD" = "1" ]; then
    log "Images (build skipped)"
else
    log "Building images (this is the slow step; the Zeek image downloads a package)"
    # The Zeek build context is zeek/, NOT the repo root -- it COPYs its prune and
    # verify scripts from there, and building from the root fails on a missing file.
    docker build -q -t "weirvern-worker:$WORKER_TAG" -f Containerfile . >/dev/null
    ok "built weirvern-worker:$WORKER_TAG"
    docker build -q -t "weirvern-zeek:$ZEEK_TAG" -f zeek/Containerfile zeek/ >/dev/null
    ok "built weirvern-zeek:$ZEEK_TAG"
fi

log "Importing images into k3s's containerd"
# THE step that makes locally-built images runnable. `docker save | k3s ctr images
# import -` copies them into the runtime k3s actually uses; skipping it produces
# ImagePullBackOff on a node that has the image in a different daemon.
docker save "weirvern-worker:$WORKER_TAG" | k3s ctr images import - >/dev/null
docker save "weirvern-zeek:$ZEEK_TAG" | k3s ctr images import - >/dev/null
ok "imported $(k3s ctr images ls 2>/dev/null | grep -c 'weirvern-') weirvern image(s)"

# ── deploy ────────────────────────────────────────────────────────────────────────
log "Applying manifests"
kubectl apply -k k8s/ >/dev/null
ok "namespace, workloads and the schema Job applied"

# THE SECRET IS CREATED AFTER THE APPLY AND NEVER SHIPPED AS A MANIFEST. A committed
# Secret manifest is overwritten with placeholders on every later `kubectl apply -k`,
# silently wiping credentials; this block creates it once and leaves it alone forever
# after (re-running the installer must not rotate a password the database already has).
log "Secret"
if kubectl -n "$NAMESPACE" get secret weirvern-secrets >/dev/null 2>&1; then
    ok "weirvern-secrets already exists -- left untouched"
else
    CH_PASSWORD=$(openssl rand -base64 24)
    kubectl -n "$NAMESPACE" create secret generic weirvern-secrets \
        --from-literal=CLICKHOUSE_PASSWORD="$CH_PASSWORD" \
        --from-literal=PUSHOVER_USER_KEY='' \
        --from-literal=PUSHOVER_API_TOKEN='' >/dev/null
    ok "created weirvern-secrets (ClickHouse password generated; Pushover left empty = log-only)"
fi

# The schema Job and the pods that mount the Secret were applied before it existed,
# so the Job must be replaced (Jobs are immutable once created -- a plain re-apply of
# a CHANGED job fails while the rest of the apply silently succeeds, which is how a
# half-rollout looks like a full one) and the readers restarted to pick it up.
log "Re-applying for the schema Job and restarting readers"
kubectl -n "$NAMESPACE" delete job weirvern-schema --ignore-not-found >/dev/null
kubectl apply -k k8s/ >/dev/null
kubectl -n "$NAMESPACE" rollout restart deploy/weirvern-worker deploy/weirvern-gui >/dev/null 2>&1 || \
    warn "rollout restart failed; the worker will still recover on its own within ~30s"

if [ "$SIPHON" = "1" ]; then
    # ORDER: the overlay extends the base, so the base must exist first.
    log "Applying the siphon overlay"
    kubectl apply -k overlays/siphon/ >/dev/null
    ok "siphon capabilities granted (zeek: NET_RAW+NET_ADMIN; worker: hostNetwork+NET_RAW+NET_ADMIN)"
    ok "the mode itself stays 'loch' until you switch it in Settings -- nothing is"
    ok "intercepted by applying this overlay"
fi

# ── wait for real readiness ───────────────────────────────────────────────────────
log "Waiting for the deployment"
deadline=$(( $(date +%s) + SCHEMA_TIMEOUT ))
while :; do
    st=$(kubectl -n "$NAMESPACE" get job weirvern-schema -o jsonpath='{.status.succeeded}' 2>/dev/null || true)
    [ "${st:-0}" = "1" ] && break
    [ "$(date +%s)" -lt "$deadline" ] || die "the schema Job did not complete in ${SCHEMA_TIMEOUT}s (kubectl -n $NAMESPACE logs job/weirvern-schema)"
    sleep 4
done
ok "schema applied (the Job ran weirvern init-db)"

deadline=$(( $(date +%s) + PODS_READY_TIMEOUT ))
while :; do
    notready=$(kubectl -n "$NAMESPACE" get pods --no-headers 2>/dev/null \
        | grep -v -E '([0-9]+)/\1\s+Running|Completed' || true)
    [ -z "$notready" ] && break
    if [ "$(date +%s)" -ge "$deadline" ]; then
        warn "these pods are not ready after ${PODS_READY_TIMEOUT}s:"
        printf '%s\n' "$notready" | sed 's/^/      /'
        warn "the deployment is up but incomplete; investigate before using it"
        break
    fi
    sleep 5
done
[ -z "${notready:-}" ] && ok "every pod is Ready"

# ── verify ────────────────────────────────────────────────────────────────────────
log "Verification"
NODEPORT=$(kubectl -n "$NAMESPACE" get svc weirvern-gui -o jsonpath='{.spec.ports[0].nodePort}' 2>/dev/null || echo 30088)
NODE_IP=$(hostname -I | awk '{print $1}')
if curl -sf --max-time 5 "http://127.0.0.1:${NODEPORT}/api/healthz" >/dev/null; then
    ok "the GUI answers on port $NODEPORT"
else
    warn "the GUI did not answer on 127.0.0.1:$NODEPORT yet (give it another minute)"
fi

log "Admin account"
# The bootstrap password is LOGGED ONCE, at WARNING, by the GUI pod that created the
# store -- this is the only moment it exists outside the database. Surfacing it here
# is the difference between "sign in with the password from the logs" and a support
# question. It is shown only when the log carries it (a fresh deployment). The full
# history: `kubectl -n $NAMESPACE logs deploy/weirvern-gui | grep 'initial admin'`.
ADMIN_LINE=$(kubectl -n "$NAMESPACE" logs deploy/weirvern-gui --tail=4000 2>/dev/null \
    | grep 'created the initial admin account' | tail -1 || true)
if [ -n "$ADMIN_LINE" ]; then
    echo
    echo "    $(printf '%s' "$ADMIN_LINE" | sed 's/.*username:/username:/')"
    echo "    (shown once; change it after signing in)"
else
    ok "no bootstrap password in the log: accounts already exist (sign in with your admin, or use the break-glass token door on the sign-in screen)"
fi

cat <<EOF

───────────────────────────────────────────────────────────────────────────────
 Weirvern is up.

   GUI (sign-in)   http://${NODE_IP}:${NODEPORT}/   (or http://$(hostname):${NODEPORT}/)
   Namespace       kubectl -n ${NAMESPACE} get pods
   Logs            kubectl -n ${NAMESPACE} logs deploy/weirvern-worker -f

 Next steps
   1. Sign in as 'admin' (password above, if this was a fresh install).
   2. Settings -> sensor: confirm the interfaces (${ZEEK_IFACE} capture / ${MGMT_IFACE} management).
   3. NetFlow exporters (if you have any): point them at ${NODE_IP}:32055 (NetFlow)
      and ${NODE_IP}:32063 (sFlow) -- the NODEPORTs, not 2055/6343.

EOF

if [ "$SIPHON" = "1" ]; then
    cat <<EOF
   In-path mode (siphon) -- the overlay is applied, so the mode gate will open:
   4. Survey the segment you want before trusting it (run on this host):
        sudo /opt/weirvern/.venv/bin/weirvern intercept --dry-run \\
             --iface ${ZEEK_IFACE} --segment <CIDR> --our-ip <free addr> --gateway <gw>
      ...or without a local venv:
        kubectl -n ${NAMESPACE} exec deploy/weirvern-worker -- \\
             python -m weirvern.admin.cli intercept --dry-run --iface ${ZEEK_IFACE} ...
   5. Settings -> sensor -> mode: 'siphon', fill in intercept segment / address /
      gateway / targets ('*' for a whole segment), Apply. The worker starts the
      supervised intercept; the sensor panel shows hosts and mappings once forged.
EOF
fi
echo "───────────────────────────────────────────────────────────────────────────────"
