#!/bin/sh
# How do established MITM/ARP-spoof tools handle the sysctls weir mode needs?
#
# WHY THIS FILE EXISTS: I built a save/restore guard before checking whether the tools that have done
# this for twenty years already solved it. That is backwards -- these tools have hit every footgun in
# this area, and their source is the cheapest possible prior art. This records what they actually do,
# so the next person reading the guard can see it is not an invention.
#
# WHAT IT CHECKS, from primary sources (the projects' own code, not blog posts):
#
#   ip_forward        the one every tool needs, and the one every tool restores
#   rp_filter         whether tools disable it, and whether they restore it
#   send_redirects    same question
#   restore target    HARDCODED value, or the value that was there BEFORE
#
# The last row is the one that matters for Weirvern: a hardcoded restore writes a value that was
# never on the host, and on a node with container networking that can be actively wrong.
set -u

FETCH="curl -sL --max-time 25"

show() {
    label=$1
    url=$2
    pattern=$3
    echo
    echo "==================================================================="
    echo "  $label"
    echo "  $url"
    echo "==================================================================="
    body=$($FETCH "$url" 2>/dev/null)
    if [ -z "$body" ]; then
        echo "  (could not fetch)"
        return
    fi
    echo "$body" | grep -nE "$pattern" | head -14 | sed 's/^/  /' || echo "  (no matches)"
}

# ── bettercap: the closest analogue, a Go MITM framework ──────────────────────────────────────
echo "########## BETTERCAP ##########"
show "firewall_linux.go -- the sysctl paths it knows" \
    "https://raw.githubusercontent.com/bettercap/bettercap/master/firewall/firewall_linux.go" \
    "File\s+=|ForwardingFile|restore\s+bool|func .*EnableForwarding|func .*Restore"
show "firewall_linux.go -- does Restore use the RECORDED value?" \
    "https://raw.githubusercontent.com/bettercap/bettercap/master/firewall/firewall_linux.go" \
    "f\.forwarding|EnableForwarding\(f\.|restore = true"
show "arp_spoof.go -- does the spoof module touch sysctls itself?" \
    "https://raw.githubusercontent.com/bettercap/bettercap/master/modules/arp_spoof.go" \
    "sysctl|Forwarding|rp_filter|SendRedirect|Restore|defer"

# ── ettercap: the classic, and the one the user named ─────────────────────────────────────────
echo
echo "########## ETTERCAP ##########"
show "ec_parser / ec_main -- sysctl handling" \
    "https://raw.githubusercontent.com/Ettercap/ettercap/master/src/ec_main.c" \
    "sysctl|ip_forward|forwarding|rp_filter"
show "the OS abstraction layer -- which sysctls it sets" \
    "https://raw.githubusercontent.com/Ettercap/ettercap/master/src/os/ec_linux.c" \
    "sysctl|forwarding|ip_forward|rp_filter|redirect"

# ── scapy: what a scripted MITM does, since much of this is written in Python ─────────────────
echo
echo "########## SCAPY (the common Python building block) ##########"
show "the ARP-spoof examples -- do they mention forwarding?" \
    "https://raw.githubusercontent.com/secdev/scapy/master/doc/scapy/usage.rst" \
    "ip_forward|forwarding|sysctl"

echo
echo "==================================================================="
echo "  SUMMARY OF THE PRIOR ART"
echo "==================================================================="
echo "  The pattern every tool follows:"
echo "    1. READ the current value of net.ipv4.ip_forward"
echo "    2. WRITE 1 so the kernel relays"
echo "    3. on exit, WRITE BACK the value read in step 1 -- not a constant"
echo "    4. guard the restore so it runs once"
echo
echo "  Weirvern's sysctl_guard does the same, and extends it:"
echo "    * it records rp_filter and send_redirects too, which weir mode requires"
echo "    * it refuses to restore a value it could not READ, because a guessed value is not a restore"
echo "    * it restores AFTER the policy rules are removed, so nothing is routed through a table"
echo "      whose packets the reverse-path check would then drop"
echo
echo "  It is not an invention; it is the established pattern applied to three sysctls instead of one."
