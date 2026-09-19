#!/bin/sh
# DOES AN INTERCEPT BREAK DNS INSIDE THE CLUSTER? A falsifiable A/B on the one symptom observed.
#
# THE OBSERVATION THAT MOTIVATES THIS. During intercept runs I repeatedly saw, from INSIDE pods:
#
#     Failed to resolve 'clickhouse' (Temporary failure in name resolution)
#     Unexpected Http Driver Exception
#     net/http: TLS handshake timeout   (against the API server)
#
# and none of it while nothing was intercepting. That is a correlation between the intercept and
# cluster-internal breakage, which is a much better candidate for "the network broke" than the relay
# itself -- the relay measurably does not degrade the path (0% loss, same RTT, 2277 vs 1771 KB/s).
#
# WHY THIS IS THE RIGHT SHAPE OF TEST: it is falsifiable in both directions. If DNS works equally
# well with and without the intercept, the correlation was coincidence and I say so.
#
# WHY IT COULD PLAUSIBLY BE CAUSED BY AN INTERCEPT: the intercept, on a hostNetwork pod, makes these
# changes to the NODE's network stack -- the same stack the cluster's DNS and API traffic use:
#
#     ip_forward=1                     the node now routes
#     rp_filter=0                      reverse-path filtering off GLOBALLY
#     send_redirects=0                 the node stops sending ICMP redirects
#     ip rule from <segment> lookup 100
#     an address on the capture interface
#
# A node that suddenly forwards and routes can have its DNS replies take a different path, and
# `conntrack`/`rp_filter` interactions with pod networking are a known source of exactly this
# symptom. That is a hypothesis to TEST, not a claim.
set -u
NS="${NS:-weirvern}"
PHASE="${1:-unknown}"
OUT="/tmp/dns_${PHASE}_$(date +%H%M%S).log"

pod() {
    kubectl -n "$NS" get pod -l app.kubernetes.io/name=weirvern-worker \
        --sort-by=.status.startTime -o jsonpath='{.items[-1].metadata.name}' 2>/dev/null
}

relay_state() {
    R=$(ip rule show 2>/dev/null | grep -c 'lookup 100')
    T=$(ip route show table 100 2>/dev/null | wc -l)
    echo "rule=$R table=$T"
}

echo "=== cluster DNS health: $PHASE ===" | tee "$OUT"
echo "  relay: $(relay_state)" | tee -a "$OUT"
echo "  node sysctls: ip_forward=$(sysctl -n net.ipv4.ip_forward 2>/dev/null) " \
     "all.rp_filter=$(sysctl -n net.ipv4.conf.all.rp_filter 2>/dev/null) " \
     "all.send_redirects=$(sysctl -n net.ipv4.conf.all.send_redirects 2>/dev/null)" | tee -a "$OUT"

W=$(pod)
if [ -z "$W" ]; then
    echo "  no worker pod; cannot test in-pod DNS" | tee -a "$OUT"
    exit 1
fi

echo | tee -a "$OUT"
echo "--- 1. DNS from INSIDE a pod, 10 attempts (this is the symptom observed) ---" | tee -a "$OUT"
OK=0; FAIL=0
i=1
while [ $i -le 10 ]; do
    R=$(timeout 15 kubectl -n "$NS" exec "$W" -c worker -- python -c "
import socket
try:
    print('ok', socket.gethostbyname('clickhouse'))
except Exception as e:
    print('FAIL', type(e).__name__)
" 2>/dev/null | tail -1)
    case "$R" in
      ok*) OK=$((OK+1)); printf "    %2d  ok      %s\n" "$i" "${R#ok }" | tee -a "$OUT" ;;
      *)   FAIL=$((FAIL+1)); printf "    %2d  FAIL    %s\n" "$i" "$R" | tee -a "$OUT" ;;
    esac
    i=$((i+1))
done
echo "    ---- ok=$OK fail=$FAIL of 10" | tee -a "$OUT"

echo | tee -a "$OUT"
echo "--- 2. the API server, from the node (TLS handshake timeouts were seen here) ---" | tee -a "$OUT"
AOK=0; AFAIL=0
i=1
while [ $i -le 5 ]; do
    if timeout 12 kubectl get --raw /healthz >/dev/null 2>&1; then
        AOK=$((AOK+1)); printf "    %2d  healthz ok\n" "$i" | tee -a "$OUT"
    else
        AFAIL=$((AFAIL+1)); printf "    %2d  healthz FAIL\n" "$i" | tee -a "$OUT"
    fi
    i=$((i+1))
done
echo "    ---- ok=$AOK fail=$AFAIL of 5" | tee -a "$OUT"

echo | tee -a "$OUT"
echo "--- 3. relay state at the END (did it hold through the run?) ---" | tee -a "$OUT"
echo "    $(relay_state)" | tee -a "$OUT"
echo | tee -a "$OUT"
echo "  RESULT $PHASE: in_pod_dns ok=$OK/$((OK+FAIL))  api ok=$AOK/$((AOK+AFAIL))" | tee -a "$OUT"
echo "  log: $OUT"
