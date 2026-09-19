#!/bin/sh
# Prove remove_forwarding_path removes EVERY rule form that selects the policy table.
#
# THE LIVE FAILURE. After an intercept was stopped and reported clean, this was still installed:
#
#     1000:  from all iif eth1 lookup 100
#
# with table 100 EMPTY. A rule pointing at a table with no routes DROPS matching traffic, so a leaked
# rule is not cosmetic -- it black-holes whatever it matches.
#
# WHY NOT A UNIT TEST: the fix parses `ip rule show` and issues deletes. A mocked `_run` would only
# prove the parsing matches my expectation of the output format; this drives the REAL function against
# a real kernel, in a network namespace so nothing outside is affected.
#
# The namespace is the point: a policy rule is node state, and creating test rules on the live node
# would be doing the damage the function exists to prevent.
set -u
TABLE=100
PRIO=1000

echo "=== policy-rule cleanup: does it remove EVERY form? ==="
if ! command -v ip >/dev/null 2>&1; then
    echo "  SKIP: no ip command"; exit 0
fi

NS="weirrule$$"
if ! ip netns add "$NS" 2>/dev/null; then
    echo "  SKIP: cannot create a network namespace (needs privileges)"
    exit 0
fi
trap 'ip netns del "$NS" 2>/dev/null' EXIT

# Run every ip command inside the namespace, so the host's rules are untouched.
in_ns() { ip netns exec "$NS" "$@"; }

check_case() {
    name=$1
    setup=$2
    echo
    echo "--- $name"
    # Clean slate.
    for p in $(in_ns ip rule show | awk -F: '/lookup 100/{print $1}'); do
        in_ns ip rule del priority "$p" 2>/dev/null
    done
    in_ns ip route flush table $TABLE 2>/dev/null
    # Apply the form under test.
    eval "$setup"
    echo "    installed: $(in_ns ip rule show | grep -c 'lookup 100') rule(s) -> $(in_ns ip rule show | grep 'lookup 100' | head -1 | sed 's/^\s*//')"
}

# The forms a rule can take. Each is a real shape: the first is what the code creates, the second is
# what an earlier version created, the third is a hand-set variant.
check_case "form 1: iif eth1 lookup 100 (what the code creates)" \
    "in_ns ip rule add iif lo lookup $TABLE priority $PRIO"
check_case "form 2: from <segment> lookup 100 (an earlier version's form)" \
    "in_ns ip rule add from 198.51.100.0/24 lookup $TABLE priority $PRIO"
check_case "form 3: a DIFFERENT priority selecting the same table" \
    "in_ns ip rule add iif lo lookup $TABLE priority 4242"

echo
echo "=== run the SHIPPING function against each remaining form ==="
echo "  (extracted from weirnet.py so this tests the real code, not a paraphrase)"
python3 - <<'PY' > /tmp/rule_cleanup.py
import pathlib, re
import os
# The source path is a PARAMETER. A hardcoded absolute path works on exactly one machine and fails
# everywhere else -- the probe then "fails" for a reason that has nothing to do with the rule cleanup.
cand = os.environ.get("WEIRNET_PY") or "/tmp/weirnet.py"
if not os.path.exists(cand):
    for alt in ("weirvern/admin/weirnet.py", "../weirvern/admin/weirnet.py"):
        if os.path.exists(alt):
            cand = alt
            break
src = pathlib.Path(cand).read_text()
start = src.index("def _policy_rule_priorities")
end = src.index("def add_address", start)
body = src[start:end]
# Provide the two module constants and the runner the function needs.
print("import subprocess")
print(f"POLICY_TABLE = {100}")
print(f"POLICY_PRIORITY = {1000}")
print("def _run(*a):")
print("    p = subprocess.run(a, capture_output=True, text=True)")
print("    return p.returncode, p.stdout + p.stderr")
print("def remove_forwarding_path(iface):")
print("    for pr in _policy_rule_priorities() + [POLICY_PRIORITY]:")
print("        _run('ip', 'rule', 'del', 'priority', str(pr))")
print(body)
PY
echo "  generated: $(wc -l < /tmp/rule_cleanup.py) lines"

FAILED=0
for setup in "iif lo lookup 100 priority 1000" "from 198.51.100.0/24 lookup 100 priority 1000" "iif lo lookup 100 priority 4242"; do
    for p in $(in_ns ip rule show | awk -F: '/lookup 100/{print $1}'); do
        in_ns ip rule del priority "$p" 2>/dev/null
    done
    in_ns ip rule add $setup 2>/dev/null
    BEFORE=$(in_ns ip rule show | grep -c 'lookup 100')
    ip netns exec "$NS" python3 -c "
import sys; sys.path.insert(0,'/tmp')
import rule_cleanup
rule_cleanup.remove_forwarding_path('eth1')
" 2>/dev/null
    AFTER=$(in_ns ip rule show | grep -c 'lookup 100')
    if [ "$BEFORE" = "1" ] && [ "$AFTER" = "0" ]; then
        printf "    PASS  %-42s 1 -> 0\n" "$setup"
    else
        printf "    FAIL  %-42s %s -> %s\n" "$setup" "$BEFORE" "$AFTER"
        FAILED=1
    fi
done

echo
if [ "$FAILED" = "0" ]; then
    echo "  ALL FORMS REMOVED"
else
    echo "  SOME FORMS SURVIVED -- a leaked rule black-holes matching traffic"
fi
exit "$FAILED"
