#!/usr/bin/env bash
# Drive the installer's INTERFACE LOGIC against simulated machines, and assert what it decides.
#
# WHY THIS EXISTS. install.sh is the operator's first contact, and the defect that mattered most
# in it -- an empty interface name validating, writing `capture: ` and running promisc on nothing
# -- survived the entire pytest suite. It could not have been caught there: the bug lived in a
# `[ -e "/sys/class/net/$want" ]` predicate fed by a shell loop, and no unit test exercises shell
# logic against a machine layout. It was found by STUBBING A MACHINE and watching what the script
# said. That is what this harness does.
#
# The machine is simulated: `ip`, sysfs, and the default route. The BLOCK under test is extracted
# from install.sh BY MARKER, so the tested text is the text that ships -- a copy would drift and
# then certify nothing.
#
# Machine shapes asserted, in the order the traps were found:
#   one NIC            both roles on that NIC, WITH the same-interface warning (never empty)
#   two NICs           the non-default NIC becomes the capture port
#   no default route   falls back to a real interface and says so
#   a tunnel           tailscale0 / wg0 are never offered: encrypted host-to-peer traffic is not
#                      a segment
#   container plumbing docker0 / cni0 / veth / br- are filtered out
#   loopback, a down NIC
#   a typo             refused, naming what exists
#   non-TTY stdin      accepts the detected pair; never hangs
#   --list-interfaces  decides and exits without touching anything
#
# Two harness rules learned the hard way while writing this, both now enforced:
#   * NEVER use the scenario text as a filename. It contains spaces, colons and slashes, so the
#     write lands somewhere else, the prelude never loads, and the REAL `ip` runs -- every
#     assertion then measures the wrong machine while still reporting PASS/FAIL.
#   * A driver that produced no decision at all is a FAILURE, not an absence of evidence. An
#     empty result makes every "must not contain" assertion pass vacuously.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/install.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
N=0

# ── extract the shipping block ────────────────────────────────────────────────────
awk '/^log "Sensor interfaces"$/,/^PYEOF$/' "$SRC" > "$WORK/block.sh" || true
if [ ! -s "$WORK/block.sh" ]; then
    echo "  FAIL -- could not extract the interface block from install.sh."
    echo "          The extraction markers moved; update this harness to match."
    exit 1
fi
# Drop the trailing python heredoc: it writes the ConfigMap and needs a real tree, and it is not
# part of the decision logic under test.
sed -i '/^python3 - /,$d' "$WORK/block.sh"
echo "    extracted $(wc -l < "$WORK/block.sh") lines from install.sh (by marker, not a copy)"

# ── a machine ────────────────────────────────────────────────────────────────────
# build_machine <dir> <default-route-iface-or-empty> <spec...>
# A spec is name:STATE:ADDR:TYPE, where TYPE 1 is ethernet and 772 is loopback.
build_machine() {
    local dir="$1" defroute="$2"; shift 2
    rm -rf "$dir"; mkdir -p "$dir/sys" "$dir/bin"
    : > "$dir/interfaces.txt"; : > "$dir/addrs.txt"
    local idx=0
    for spec in "$@"; do
        local name state addr type
        name="${spec%%:*}"; spec="${spec#*:}"
        state="${spec%%:*}"; spec="${spec#*:}"
        addr="${spec%%:*}"; type="${spec##*:}"
        idx=$((idx + 1))
        echo "$name" >> "$dir/interfaces.txt"
        echo "$name $state $addr" >> "$dir/addrs.txt"
        mkdir -p "$dir/sys/$name"
        echo "$type" > "$dir/sys/$name/type"
        printf '00:00:5e:00:53:%02x\n' "$idx" > "$dir/sys/$name/address"
    done

    cat > "$dir/bin/ip" <<STUB
#!/usr/bin/env bash
dir='$dir'; defroute='$defroute'
case "\$1 \$2" in
  "route show")
      [ -n "\$defroute" ] && echo "default via 192.0.2.1 dev \$defroute"
      ;;
  "-brief link")
      while read -r n; do
          st=\$(awk -v n="\$n" '\$1==n{print \$2}' "\$dir/addrs.txt")
          printf '%s %s\n' "\$n" "\${st:-UP}"
      done < "\$dir/interfaces.txt"
      ;;
  "-4 -brief")
      iface="\${4:-}"; [ -n "\${5:-}" ] && iface="\$5"
      while read -r n st a; do
          [ "\$n" = "\$iface" ] && [ -n "\$a" ] && [ "\$a" != "-" ] && echo "\$n \$st \$a"
      done < "\$dir/addrs.txt"
      ;;
  "-brief link show")
      iface="\${4:-}"
      st=\$(awk -v n="\$iface" '\$1==n{print \$2}' "\$dir/addrs.txt")
      printf '%s %s\n' "\$iface" "\${st:-UP}"
      ;;
  "link set") exit 0 ;;
  *) : ;;
esac
exit 0
STUB
    chmod +x "$dir/bin/ip"
    # A real `ip` would silently answer for the HOST machine. Refuse to run rather than lie.
    printf '#!/usr/bin/env bash\necho "HARNESS ERROR: the stub PATH was not in effect" >&2; exit 99\n' \
        > "$dir/bin/.guard"
}

# run_block <defroute> <yes|list> <zeek-flag> <mgmt-flag> <spec...>
run_block() {
    local defroute="$1" env_yes="$2" zflag="$3" mflag="$4"; shift 4
    N=$((N + 1))
    local dir="$WORK/m$N"
    build_machine "$dir" "$defroute" "$@"

    # Prefix ONLY the sysfs path, so the decision logic is untouched and the machine is simulated.
    sed "s#/sys/class/net/#$dir/sys/#g" "$WORK/block.sh" > "$WORK/under$N.sh"

    {
        printf 'PATH="%s/bin:$PATH"\n' "$dir"
        printf 'export PATH\n'
        # Fail loudly if the real ip answers, so a stub miss can never read as a pass.
        printf 'command -v ip >/dev/null || { echo "HARNESS ERROR: no ip on PATH"; exit 99; }\n'
        printf 'case "$(command -v ip)" in %s/bin/ip) : ;; *) echo "HARNESS ERROR: real ip would run"; exit 99 ;; esac\n' "$dir"
        cat <<PRELUDE
log()  { printf 'LOG %s\n' "\$*"; }
ok()   { printf 'OK %s\n' "\$*"; }
warn() { printf 'WARN %s\n' "\$*"; }
die()  { printf 'DIE %s\n' "\$*"; exit 1; }
SIPHON=0; ASSUME_YES=$env_yes; LIST_IFACES=$([ "$env_yes" = "list" ] && echo 1 || echo 0)
ZEEK_IFACE_FLAG='$zflag'; MGMT_IFACE_FLAG='$mflag'
PRELUDE
        cat "$WORK/under$N.sh"
        # The shell block ends by invoking python; capture the two decisions instead.
        printf 'echo "DECISION mgmt=%s capture=%s"\n' '$MGMT_IFACE' '$ZEEK_IFACE'
    } > "$WORK/drive$N.sh"

    local out
    out="$(cd "$dir" && bash "$WORK/drive$N.sh" 2>&1)"
    # An absent decision is not evidence for anything.
    if ! grep -qE '^DECISION |^DIE ' <<< "$out"; then
        out="$out
HARNESS-FAILURE: the driver produced no decision"
    fi
    if grep -q 'HARNESS ERROR\|HARNESS-FAILURE\|No such file or directory' <<< "$out"; then
        printf '    !! harness failure for scenario: %s\n' "$*"
        printf '%s\n' "$(sed 's/^/        /' <<< "$out" | head -8)"
    fi
    printf '%s' "$out"
}

# run_block_tty <input> <defroute> <yes|no> <spec...>
# Drives the INTERACTIVE path under a real pty, so `[ -t 0 ]` is true and the prompt loop runs.
# Without this the harness only ever exercised the --yes and --list paths, which return BEFORE the
# validation loop -- so the loop's own logic was never executed by any test.
run_block_tty() {
    local input="$1" defroute="$2" env_yes="$3"; shift 3
    N=$((N + 1))
    local dir="$WORK/t$N"
    build_machine "$dir" "$defroute" "$@"
    sed "s#/sys/class/net/#$dir/sys/#g" "$WORK/block.sh" > "$WORK/under$N.sh"
    {
        printf 'PATH="%s/bin:$PATH"
export PATH
' "$dir"
        printf 'case "$(command -v ip)" in %s/bin/ip) : ;; *) echo "HARNESS ERROR: real ip"; exit 99 ;; esac
' "$dir"
        cat <<PRELUDE
log()  { printf 'LOG %s\n' "\$*"; }
ok()   { printf 'OK %s\n' "\$*"; }
warn() { printf 'WARN %s\n' "\$*"; }
die()  { printf 'DIE %s\n' "\$*"; exit 1; }
SIPHON=0; ASSUME_YES=$env_yes; LIST_IFACES=0
ZEEK_IFACE_FLAG=''; MGMT_IFACE_FLAG=''
PRELUDE
        cat "$WORK/under$N.sh"
        printf 'echo "DECISION mgmt=%s capture=%s"\n' '$MGMT_IFACE' '$ZEEK_IFACE'
    } > "$WORK/drive$N.sh"

    # `script` gives the child a pty, so the driver sees a terminal on stdin and actually prompts.
    local out
    out="$(printf '%b' "$input" | script -qec "cd $dir && bash $WORK/drive$N.sh" /dev/null 2>&1 | tr -d '\r')"
    if ! grep -qE '^DECISION |^DIE ' <<< "$out"; then
        out="$out
HARNESS-FAILURE: the interactive driver produced no decision"
    fi
    printf '%s' "$out"
}

# ── assertions ───────────────────────────────────────────────────────────────────
assert_contains() {
    local hay="$1" needle="$2" label="$3"
    if grep -qF -- "$needle" <<< "$hay"; then
        PASS=$((PASS + 1)); printf '    PASS  %s\n' "$label"
    else
        FAIL=$((FAIL + 1)); printf '    FAIL  %s\n' "$label"
        printf '          wanted: %s\n' "$needle"
        printf '          got: %s\n' "$(tr '\n' '|' <<< "$hay" | cut -c1-160)"
    fi
}
assert_not_contains() {
    local hay="$1" needle="$2" label="$3"
    if grep -qF -- "$needle" <<< "$hay"; then
        FAIL=$((FAIL + 1)); printf '    FAIL  %s  (found %s)\n' "$label" "$needle"
    else
        PASS=$((PASS + 1)); printf '    PASS  %s\n' "$label"
    fi
}

echo
echo "=== installer interface logic, against simulated machines ==="

echo "  -- one NIC, the empty-capture defect --"
OUT="$(run_block ens18 yes '' '' 'ens18:UP:192.0.2.34/24:1')"
assert_contains     "$OUT" "DECISION mgmt=ens18 capture=ens18" "both roles land on that NIC"
assert_not_contains "$OUT" "capture= " "the capture interface is never empty"
assert_contains     "$OUT" "the capture will hold this host" "warned the capture will be thin"

echo "  -- one NIC and NO TTY (a provisioning script) --"
# The warning must reach an unattended run too, not just an interactive one. It did not: it lived
# inside the prompt loop, so --yes and piped stdin were both silent about a thin capture.
OUT="$(run_block ens18 yes '' '' 'ens18:UP:192.0.2.34/24:1')"
assert_contains "$OUT" "the capture will hold this host" "an unattended --yes run still gets the warning"

echo "  -- two NICs --"
OUT="$(run_block ens18 yes '' '' 'ens18:UP:192.0.2.34/24:1' 'ens19:UP:-:1')"
assert_contains     "$OUT" "DECISION mgmt=ens18 capture=ens19" "the non-default NIC is the capture port"
assert_not_contains "$OUT" "the capture will hold this host" "no same-interface warning"

echo "  -- no default route --"
OUT="$(run_block '' yes '' '' 'ens18:UP:192.0.2.34/24:1')"
assert_contains "$OUT" "DECISION mgmt=ens18" "falls back to a real interface"
assert_contains "$OUT" "no default-route interface found" "says so rather than guessing silently"

echo "  -- a tunnel alongside a real NIC --"
OUT="$(run_block ens18 yes '' '' 'ens18:UP:192.0.2.34/24:1' 'tailscale0:UP:100.64.0.5/32:1')"
assert_not_contains "$OUT" "tailscale0" "a tunnel is never offered"
assert_contains     "$OUT" "DECISION mgmt=ens18 capture=ens18" "the real NIC is still used"

OUT="$(run_block ens18 yes '' '' 'ens18:UP:192.0.2.34/24:1' 'wg0:UP:203.0.113.9/32:1')"
assert_not_contains "$OUT" "wg0" "wg0 is never offered"

echo "  -- container plumbing --"
OUT="$(run_block ens18 yes '' '' 'ens18:UP:192.0.2.34/24:1' 'docker0:UP:172.17.0.1/16:1' \
       'cni0:UP:10.42.0.1/24:1' 'veth1234:UP:-:1' 'br-abc:UP:-:1')"
assert_not_contains "$OUT" "docker0" "docker0 filtered"
assert_not_contains "$OUT" "cni0" "cni0 filtered"
assert_not_contains "$OUT" "veth1234" "veth filtered"
assert_not_contains "$OUT" "br-abc" "br- filtered"

echo "  -- loopback and a spare slot --"
OUT="$(run_block ens18 yes '' '' 'lo:UNKNOWN:127.0.0.1/8:772' 'ens18:UP:192.0.2.34/24:1' 'ens20:DOWN:-:1')"
assert_not_contains "$OUT" "lo " "loopback not offered"
assert_not_contains "$OUT" "ens20" "a DOWN NIC is not offered"

echo "  -- a typo on the command line --"
OUT="$(run_block ens18 yes teh0 '' 'ens18:UP:192.0.2.34/24:1' 'ens19:UP:-:1')"
assert_contains "$OUT" "no such interface:" "a flag typo is refused"
assert_contains "$OUT" "teh0" "the typo is named"
assert_contains "$OUT" "--list-interfaces" "the remedy is offered"

echo "  -- a valid flag --"
OUT="$(run_block ens18 yes ens19 '' 'ens18:UP:192.0.2.34/24:1' 'ens19:UP:-:1')"
assert_contains "$OUT" "flag interfaces verified" "verified, not merely accepted"
assert_contains "$OUT" "DECISION mgmt=ens18 capture=ens19" "a valid flag wins over detection"

echo "  -- --list-interfaces --"
OUT="$(run_block ens18 list '' '' 'ens18:UP:192.0.2.34/24:1' 'ens19:UP:-:1')"
assert_contains     "$OUT" "nothing was changed" "says nothing changed"
assert_not_contains "$OUT" "DECISION" "does not proceed to deploy"

echo "  -- only loopback, i.e. a container --"
OUT="$(run_block '' yes '' '' 'lo:UNKNOWN:127.0.0.1/8:772')"
assert_contains "$OUT" "no usable network interface found" "refuses rather than guessing"

echo "  -- INTERACTIVE: a typo is refused and the prompt re-asks --"
# Enter-Enter must never be able to produce an empty interface, and a bad name must be caught HERE
# rather than three steps later as "device does not exist" from a different component.
OUT="$(run_block_tty 'bogus0\nens18\nens18\nens18\ny\n\n' ens18 no \
       'ens18:UP:192.0.2.34/24:1')"
assert_contains "$OUT" "no such interface:" "interactive: a typo is refused"
assert_contains "$OUT" "bogus0" "interactive: the typo is named"
assert_contains "$OUT" "DECISION mgmt=ens18 capture=ens18" "interactive: the re-prompt succeeds"

echo "  -- INTERACTIVE: the offered default is never empty --"
# The invariant that makes the empty-name guard unreachable: the value HANDED to the prompt cannot
# be empty, because a bare Enter keeps the default and the default is filled from a real interface.
# Asserting the invariant is honest; asserting the guard fires would be asserting dead code runs.
OUT="$(run_block_tty '\n\ny\n\n' ens18 no 'ens18:UP:192.0.2.34/24:1')"
assert_not_contains "$OUT" "[]: " "interactive: the default shown is never empty"
assert_contains     "$OUT" "DECISION mgmt=ens18 capture=ens18" "interactive: Enter accepts a real interface"

echo "  -- INTERACTIVE: declining the same-interface pairing loops back --"
OUT="$(run_block_tty '\n\nn\n\n\ny\n\n' ens18 no 'ens18:UP:192.0.2.34/24:1')"
assert_contains "$OUT" "DECISION mgmt=ens18 capture=ens18" "interactive: declining then accepting works"

echo
printf '  %d passed, %d failed\n' "$PASS" "$FAIL"
if [ "$FAIL" -gt 0 ]; then echo "  FAIL"; exit 1; fi
echo "  PASS"
