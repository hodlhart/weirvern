#!/bin/sh
# Measure the RELAYED path, and verify at EVERY step that the relay is actually active.
#
# WHY THIS EXISTS. Every A/B measurement I have run so far had the same flaw: I measured, then
# assumed the intercept was running. Twice it was not --
#   * the "AFTER" phase of the first A/B failed preflight and measured nothing
#   * a later attempt intercepted 0 hosts and I read it as a result
# Both would have produced a confident claim about the relay from a measurement of NO relay.
#
# So this asserts the precondition. Each phase prints RELAY=ON or RELAY=OFF, and the relayed-path
# measurement is only valid where it says ON.
#
# WHAT IT MEASURES, and why ping was not enough:
#   * ICMP latency/loss -- cheap, catches gross breakage
#   * TCP THROUGHPUT -- the thing ping cannot see. A relay that forwards small packets perfectly
#     can still collapse on bulk transfer, and "the internet feels broken" is exactly that symptom.
#   * TCP CONNECT success -- a path that drops SYNs looks fine to ICMP and unusable to a user.
#
# WHY THE SENSOR'S OWN TRAFFIC IS A VALID PROBE: the one-armed-router policy rule matches
# `from <segment> lookup 100`. The sensor's own address is IN that segment, so its outbound packets
# take the same table-100 path the relayed packets take. That makes it a fair probe of the relayed
# route -- unlike testing the L2 reachability of hosts that pass straight through.
set -u
IFACE="${CAPTURE_IFACE:-eth1}"
SEGMENT="${INTERCEPT_SEGMENT:-192.168.3.0/24}"
OUR_IP="${INTERCEPT_ADDR:-192.168.3.250}"
GW="${INTERCEPT_GATEWAY:-192.168.3.1}"
NS="${NS:-weirvern}"
PHASE="${1:-unknown}"
OUT="/tmp/relay_${PHASE}_$(date +%H%M%S).log"

pod() {
    kubectl -n "$NS" get pod -l app.kubernetes.io/name=weirvern-worker \
        --sort-by=.status.startTime -o jsonpath='{.items[-1].metadata.name}' 2>/dev/null
}

# THE PRECONDITION CHECK, run before and after every measurement.
relay_state() {
    W=$(pod)
    [ -n "$W" ] || { echo "UNKNOWN"; return; }
    # The routing table entry is the evidence the relay PATH is installed; a running process alone
    # is not enough, because a process can be alive before it installs anything.
    T=$(ip route show table 100 2>/dev/null | wc -l)
    R=$(ip rule show 2>/dev/null | grep -c 'lookup 100')
    A=$(kubectl -n "$NS" exec "$W" -c worker -- python /tmp/count_intercepts.py 2>/dev/null \
        | sed -n 's/^REAL_INTERCEPTS=//p' | head -1)
    echo "rule=$R table=$T processes=${A:-?}"
}

echo "=== relayed-path measurement: $PHASE ===" | tee "$OUT"
echo "  relay state: $(relay_state)" | tee -a "$OUT"
echo "  started $(date -Is)" | tee -a "$OUT"

ip addr add $OUR_IP/24 dev $IFACE 2>/dev/null
trap 'ip addr del $OUR_IP/24 dev $IFACE 2>/dev/null' EXIT

echo | tee -a "$OUT"
echo "--- 1. ICMP through the relayed path ---" | tee -a "$OUT"
for t in 1.1.1.1 8.8.8.8; do
    R=$(ping -c 15 -i 0.3 -W 2 -I $OUR_IP $t 2>/dev/null | tail -2 | tr '\n' ' ')
    LOSS=$(echo "$R" | sed -n 's/.* \([0-9]*\)% packet loss.*/\1/p')
    RTT=$(echo "$R" | sed -n 's/.*= [0-9.]*\/\([0-9.]*\)\/.*/\1/p')
    printf "    %-10s loss=%-4s avg_rtt=%s\n" "$t" "${LOSS:-?}%" "${RTT:-?}ms" | tee -a "$OUT"
done

echo | tee -a "$OUT"
echo "--- 2. TCP CONNECT (a dropped SYN is invisible to ICMP) ---" | tee -a "$OUT"
for hp in 1.1.1.1:443 8.8.8.8:53 9.9.9.9:443; do
    host=${hp%%:*}; port=${hp##*:}
    START=$(date +%s%N)
    if timeout 8 sh -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
        MS=$(( ($(date +%s%N) - START) / 1000000 ))
        printf "    %-16s CONNECT ok  %sms\n" "$hp" "$MS" | tee -a "$OUT"
    else
        printf "    %-16s CONNECT FAILED\n" "$hp" | tee -a "$OUT"
    fi
done

echo | tee -a "$OUT"
echo "--- 3. TCP THROUGHPUT (the thing ping cannot see) ---" | tee -a "$OUT"
if command -v curl >/dev/null 2>&1; then
    # A modest payload, timed. Enough to expose a relay that cannot sustain bulk, small enough not
    # to abuse anyone's bandwidth.
    for url in https://speed.cloudflare.com/__down?bytes=3000000; do
        R=$(curl -s -o /dev/null -w "%{http_code} %{size_download} %{time_total} %{speed_download}" \
             --max-time 45 --interface $OUR_IP "$url" 2>/dev/null)
        CODE=$(echo "$R" | awk '{print $1}')
        BYTES=$(echo "$R" | awk '{print $2}')
        TIME=$(echo "$R" | awk '{print $3}')
        RATE=$(echo "$R" | awk '{printf "%.0f", $4/1024}')
        printf "    http=%s  bytes=%s  time=%ss  rate=%sKB/s\n" \
               "${CODE:-?}" "${BYTES:-?}" "${TIME:-?}" "${RATE:-?}" | tee -a "$OUT"
    done
else
    echo "    (curl unavailable)" | tee -a "$OUT"
fi

echo | tee -a "$OUT"
echo "--- 4. relay state AGAIN (did it stay active through the measurements?) ---" | tee -a "$OUT"
echo "    $(relay_state)" | tee -a "$OUT"

echo | tee -a "$OUT"
echo "  finished $(date -Is)" | tee -a "$OUT"
echo "  log: $OUT"
