#!/usr/bin/env bash
# The installer's SELECTION PHASE: ask the operator what this deployment should do, then apply it.
#
# WHY THIS EXISTS, AND WHY IT IS SEPARATE FROM install.sh.
#
# The installer already detected the interfaces and confirmed them, then verified the GUI answered,
# then PRINTED NEXT STEPS AND EXITED. Everything after bring-up -- which mode the sensor runs in,
# which traffic to ignore, whether the ensemble may block -- was left for the operator to find in
# the GUI. That is a deployment that has been INSTALLED but not BROUGHT ONLINE: it is running, and
# it is not doing what the operator wanted.
#
# So this phase asks the questions that decide what the system DOES, shows the consequence of each
# answer, and applies them to the ConfigMap. It is a separate file because it is a separate
# concern: install.sh gets the software onto the machine, this decides what the software does. A
# reader looking for "how do I change what the sensor captures" should not have to read through
# image builds and k3s installation to find it.
#
# EVERY QUESTION IS ANSWERABLE WITH ENTER. A one-click install must not become a questionnaire: a
# default is offered for each, the default is shown, and pressing Enter repeatedly produces a
# working deployment with the documented defaults. The choices exist for the operator who has an
# opinion, not as a toll on the one who does not.
#
# WHAT THIS DELIBERATELY DOES NOT ASK.
#   - Pushover credentials. They are secrets, and a secret typed into an install prompt lands in a
#     shell history and a terminal scrollback. The GUI's Settings is where they go.
#   - Whether to enable siphon mode. A mode is switched once the operator has SEEN the segment;
#     asking at install time is asking before they have looked. The overlay question below only
#     grants the capability.
#   - Anything with a sensible answer for every deployment. Only questions where a wrong answer
#     costs something are asked.
#
# Sourced by install.sh, and also runnable on its own to change the answers later:
#   sudo sh scripts/install_selections.sh

set -uo pipefail

# ── the ConfigMap writer, shared by every question below ─────────────────────────────────────
#
# THE CONFIGMAP IS THE SOURCE OF TRUTH FOR THE CLUSTER, and writing it (rather than a live object)
# is what makes an answer survive the next `kubectl apply -k`. The project learned this the hard
# way: a live-only edit is reverted by the next apply, so a setting that was "changed" silently
# returns to its old value -- the operator sees their change work, then stop working.
selection_set() {
    # selection_set KEY VALUE
    local key="$1" value="$2" file="${PROJECT_DIR:-.}/k8s/20-configmap-env.yaml"
    [ -f "$file" ] || { warn "cannot set $key: $file is missing"; return 1; }
    python3 - "$file" "$key" "$value" <<'PYEOF'
import re, sys
path, key, value = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(path).read()
# Quote the value so a CIDR list containing colons or spaces cannot break the YAML.
escaped = value.replace('"', '\\"')
pattern = rf'(?m)^(\s*){re.escape(key)}: ".*"$'
new = rf'\g<1>{key}: "{escaped}"'
if re.search(pattern, text):
    text = re.sub(pattern, new, text, count=1)
else:
    # A key the ConfigMap does not declare yet is appended to the data block rather than silently
    # dropped -- a setting that is asked for and not written is worse than not asking.
    text = text.rstrip() + f"\n  {key}: \"{escaped}\"\n"
open(path, "w").write(text)
print(f"    set {key}={value}")
PYEOF
}

# The current value of a key, so the prompt can show it as the default rather than a guess.
selection_current() {
    local key="$1" file="${PROJECT_DIR:-.}/k8s/20-configmap-env.yaml"
    [ -f "$file" ] || { echo ""; return; }
    python3 - "$file" "$key" <<'PYEOF'
import re, sys
path, key = sys.argv[1], sys.argv[2]
m = re.search(rf'(?m)^\s*{re.escape(key)}:\s*"?([^"\n]*)"?\s*$', open(path).read())
print(m.group(1).strip() if m else "")
PYEOF
}

# ask <question> <current> [choices...]
# Returns the answer in ASK_REPLY. Enter keeps `current`. A non-TTY run keeps it too, and SAYS SO.
ask() {
    local question="$1" current="$2"; shift 2
    local choices=("$@")
    ASK_REPLY="$current"
    if [ ! -t 0 ]; then
        printf '    %s -> %s (stdin is not a terminal; keeping the value)\n' "$question" "$current"
        return 0
    fi
    if [ "${SELECTIONS_ASSUME_YES:-0}" = "1" ]; then
        printf '    %s -> %s (--yes)\n' "$question" "$current"
        return 0
    fi
    while :; do
        if [ "${#choices[@]}" -gt 0 ]; then
            printf '    %s [%s]\n      (options: %s): ' "$question" "$current" "$(printf '%s ' "${choices[@]}")"
        else
            printf '    %s [%s]: ' "$question" "$current"
        fi
        local answer=""
        read -r answer || answer=""
        [ -z "$answer" ] && { ASK_REPLY="$current"; return 0; }
        if [ "${#choices[@]}" -gt 0 ]; then
            for c in "${choices[@]}"; do
                [ "$answer" = "$c" ] && { ASK_REPLY="$answer"; return 0; }
            done
            warn "'$answer' is not one of: $(printf '%s ' "${choices[@]}")"
            continue
        fi
        ASK_REPLY="$answer"
        return 0
    done
}

# ── the questions ────────────────────────────────────────────────────────────────────────────

selection_sensor_mode() {
    local cur; cur="$(selection_current SENSOR_MODE)"; [ -n "$cur" ] || cur="loch"
    cat <<'EOF'

    HOW THIS SENSOR WATCHES.
      loch    passive: it listens on the capture interface and never touches traffic. Nothing on
              the network can tell it is there, and it cannot break anything. This is what most
              deployments want, and it is the default.
      siphon  in-path: it puts itself between the segment and its gateway so traffic flows THROUGH
              it. That is what makes blocking (the Sluice Gate) possible on that segment -- and it
              means this host is now part of the network's path, so a crash there is an outage
              there. Choose it only once you have run the dry-run survey below and read what it
              would change.
EOF
    ask "sensor mode" "$cur" loch siphon
    selection_set SENSOR_MODE "$ASK_REPLY"
    if [ "$ASK_REPLY" = "siphon" ]; then
        cat <<EOF

    siphon needs the capability overlay, which the installer applies with --siphon. If you did not
    pass it, apply it now (this grants capabilities -- it does NOT start intercepting):
        kubectl apply -k ${PROJECT_DIR:-.}/overlays/siphon/

    And BEFORE trusting it, survey the segment:
        kubectl -n ${NAMESPACE:-weirvern} exec deploy/weirvern-worker -- \\
          python -m weirvern.admin.cli intercept --dry-run --iface ${ZEEK_IFACE:-eth1}
EOF
    fi
}

selection_exclusions() {
    local cur; cur="$(selection_current WEIRVERN_EXCLUDE_CIDRS)"
    cat <<'EOF'

    TRAFFIC TO IGNORE when counting flows. NetFlow exporters report EVERYTHING, including the
    chatter between your own infrastructure -- DNS to a local resolver, backups, monitoring polls.
    Left in, that steady noise becomes the baseline, and a real anomaly has to be louder than it to
    be seen. Excluding it makes the baseline describe the network you actually care about.

    Comma-separated CIDRs, or empty for none. Common choices: a backup server, a monitoring host,
    a management subnet. This is reversible and takes effect immediately.
EOF
    ask "exclude CIDRs" "$cur"
    selection_set WEIRVERN_EXCLUDE_CIDRS "$ASK_REPLY"
}

selection_criticality() {
    local cur; cur="$(selection_current SLUICE_CRITICALITY)"; [ -n "$cur" ] || cur="off"
    cat <<'EOF'

    MAY THE ENSEMBLE'S VERDICTS BLOCK TRAFFIC?
      off     detections alert; nothing is ever blocked. The default, because a monitoring tool
              that starts stopping traffic before anyone has looked at what it sees would be a
              surprise -- and because "the model said so" is not by itself grounds to cut a host
              off a network.
      high    block only what the ensemble called high severity with strong agreement, for 30
              minutes. The conservative choice: a host that looks like a scanner stops scanning,
              and a wrong call costs half an hour.
      medium  block medium and above for 15 minutes. Catches more; will occasionally pause a host
              that was merely unusual.
      strict  block anything flagged, for 5 minutes. For an isolated lab segment. Expect false
              positives: unusual is not the same as hostile.

    Blocking itself is a separate switch (SLUICE_ENABLED) and stays off until you turn it on in
    the Sluice Gate tab. This setting only says what would be eligible.
EOF
    ask "criticality policy" "$cur" off high medium strict
    selection_set SLUICE_CRITICALITY "$ASK_REPLY"
    if [ "$ASK_REPLY" != "off" ]; then
        cat <<EOF

    NOTE: derived blocks are CAPPED by SLUICE_MAX_BLOCK_S (currently $(selection_current SLUICE_MAX_BLOCK_S || echo 3600) seconds),
    so no policy can produce a longer block than that. Raise the cap if you want the policy's own
    duration to apply in full.
EOF
    fi
}

# ── the phase ────────────────────────────────────────────────────────────────────────────────

run_selections() {
    cat <<'EOF'

    ───────────────────────────────────────────────────────────────────────────────
     Bringing the system online

     Everything is installed and running. These questions decide what it DOES. Press
     Enter at any of them to keep the default shown in brackets -- a repeated Enter
     produces a working deployment with the documented defaults.

     Every answer is written to the cluster ConfigMap, so it survives the next
     `kubectl apply -k`. Each can be changed later in the GUI's Settings, or by
     re-running this phase.
    ───────────────────────────────────────────────────────────────────────────────
EOF
    selection_sensor_mode
    selection_exclusions
    selection_criticality
}

# Runnable on its own, to revisit the answers after bring-up.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    log()  { printf '\n\033[1m>>> %s\033[0m\n' "$*"; }
    ok()   { printf '    \033[32mok\033[0m %s\n' "$*"; }
    warn() { printf '    \033[33mwarn\033[0m %s\n' "$*"; }
    die()  { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }
    PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
    NAMESPACE="${NAMESPACE:-weirvern}"
    [ "$(id -u)" = "0" ] || die "run as root: it rewrites the cluster ConfigMap"
    run_selections
    log "Applying"
    if kubectl apply -k "$PROJECT_DIR/k8s/" >/dev/null 2>&1; then
        ok "manifests applied; the ConfigMap change is now live"
        ok "the worker picks up settings changes on its next cycle (within ~5 minutes)"
    else
        warn "could not apply the manifests -- the ConfigMap is written but not yet active"
        warn "run: kubectl apply -k $PROJECT_DIR/k8s/"
    fi
fi
