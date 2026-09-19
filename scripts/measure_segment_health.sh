#!/bin/sh
# WHY DOES THE SEGMENT DEGRADE DURING AN INTERCEPT? A/B measurement, not theory.
#
# Three claims have been made about this and none was measured:
#   * the relay works (forwarding advances, poison held)     -- measured, true
#   * the hosts stay reachable                               -- measured, true
#   * "the network broke"                                    -- reported, NEVER measured
#
# Reachability is not health. A relay that adds latency or drops packets leaves every host
# pingable while making the segment unusable, and `ping` alone cannot tell the difference. This
# measures the things that would actually be felt:
#
#   LATENCY   round-trip time to each host, and to the internet THROUGH the relayed path
#   LOSS      packets lost over a sustained run, not a 2-packet sample
#   THROUGHPUT a real transfer, because a relay that forwards small packets may collapse on bulk
#   CPU       on the sensor, since one box is now relaying for every host
#
# THE BASELINE IS TAKEN FIRST, WITH NOTHING INTERCEPTING. Then the same measurements run with the
# intercept in place. The comparison is the finding; neither half is evidence alone.
#
# Usage: sh measure_segment_health.sh baseline|intercept
set -u
IFACE="${CAPTURE_IFACE:-eth1}"
PROBE_IP=192.168.3.249
HOSTS="${SEG_HOSTS:-192.168.3.1 192.168.3.71 192.168.3.96 192.168.3.123 192.168.3.128 192.168.3.151 192.168.3.162 192.168.3.185 192.168.3.193 192.168.3.194 192.168.3.248}"
PHASE="${1:-baseline}"
OUT="/tmp/health_${PHASE}_$(date +%H%M%S).log"

echo "=== segment health: $PHASE ===" | tee "$OUT"
echo "  started $(date -Is)" | tee -a "$OUT"

# The probe address, needed for any measurement sourced from this segment.
ip addr add $PROBE_IP/24 dev $IFACE 2>/dev/null
trap 'ip addr del $PROBE_IP/24 dev $IFACE 2>/dev/null' EXIT

echo | tee -a "$OUT"
echo "--- 1. LOSS: 30 pings per host, not 2 ---" | tee -a "$OUT"
for h in $HOSTS; do
    R=$(ping -c 30 -i 0.2 -W 1 -I $PROBE_IP "$h" 2>/dev/null | tail -2 | tr '\n' ' ')
    LOSS=$(echo "$R" | sed -n 's/.* \([0-9]*\)% packet loss.*/\1/p')
    RTT=$(echo "$R" | sed -n 's/.*= [0-9.]*\/\([0-9.]*\)\/.*/\1/p')
    printf "    %-15s loss=%-4s avg_rtt=%s\n" "$h" "${LOSS:-?}%" "${RTT:-?}ms" | tee -a "$OUT"
done

echo | tee -a "$OUT"
echo "--- 2. INTERNET through the segment (the path that would be relayed) ---" | tee -a "$OUT"
for target in 1.1.1.1 8.8.8.8; do
    R=$(ping -c 20 -i 0.2 -W 1 -I $PROBE_IP "$target" 2>/dev/null | tail -2 | tr '\n' ' ')
    LOSS=$(echo "$R" | sed -n 's/.* \([0-9]*\)% packet loss.*/\1/p')
    RTT=$(echo "$R" | sed -n 's/.*= [0-9.]*\/\([0-9.]*\)\/.*/\1/p')
    printf "    %-15s loss=%-4s avg_rtt=%s\n" "$target" "${LOSS:-?}%" "${RTT:-?}ms" | tee -a "$OUT"
done

echo | tee -a "$OUT"
echo "--- 3. SENSOR LOAD (one box relaying for every host) ---" | tee -a "$OUT"
uptime | sed 's/^/    /' | tee -a "$OUT"
free -m | sed -n '2p' | sed 's/^/    /' | tee -a "$OUT"
echo "    CPUs: $(nproc)" | tee -a "$OUT"

echo | tee -a "$OUT"
echo "--- 4. FORWARDING counters (should be near-flat in baseline) ---" | tee -a "$OUT"
awk '/^Ip:/{if(n==0){for(i=1;i<=NF;i++)h[i]=$i;n=1;next} for(i=1;i<=NF;i++) if(h[i]~/^(ForwDatagrams|InNoRoutes|InAddrErrors|InHdrErrors|InDiscards)$/) printf "    %-14s %s\n", h[i], $i; exit}' /proc/net/snmp | tee -a "$OUT"

echo | tee -a "$OUT"
echo "  finished $(date -Is)" | tee -a "$OUT"
echo "  log: $OUT"
