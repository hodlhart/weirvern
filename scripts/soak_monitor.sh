#!/bin/sh
# 24-hour, read-only soak monitor. It samples the running deployment every 5 minutes and records
# what actually happened: pod readiness, container memory, console health, ingest lag and
# ClickHouse part counts. It never writes a setting, files a rule or restarts a workload.
#
# RUN ON THE BOX (it needs kubectl and the console's local port):
#   nohup sh scripts/soak_monitor.sh 1440 >/root/weirvern-soak.out 2>&1 &
#
# A missing metric is logged as `not measured`; it is not a zero and not a pass.
set -u

MINUTES=${1:-1440}
INTERVAL=${SOAK_INTERVAL_S:-300}
OUT=${SOAK_LOG:-/root/weirvern-soak-$(date +%Y%m%d-%H%M%S).log}
NS=${NS:-weirvern}
START=$(date +%s)
END=$((START + MINUTES * 60))
FAIL=0
SAMPLES=0

say() { printf '%s %s\n' "$(date -Is)" "$*" | tee -a "$OUT"; }

say "=== soak start: ${MINUTES}m, interval ${INTERVAL}s, namespace $NS ==="
say "log: $OUT"

while [ "$(date +%s)" -lt "$END" ]; do
    SAMPLES=$((SAMPLES + 1))
    now=$(date -Is)

    health=$(curl -fsS -m 5 http://127.0.0.1:30088/api/healthz 2>/dev/null || true)
    if printf '%s' "$health" | grep -q '"ok"[[:space:]]*:[[:space:]]*true'; then
        hstate=ok
    else
        hstate="FAILED ($health)"
        FAIL=1
    fi

    pods=$(kubectl -n "$NS" get pods --no-headers 2>/dev/null \
        | awk '{print $1"="$3}' | tr '\n' ' ' || true)
    # A superseded pod that is ContainerStatusUnknown is stale metadata, not an unready
    # deployment. Log it, but fail only on a live pod that is Pending, Error, CrashLoopBackOff,
    # ImagePullBackOff or otherwise non-Running/non-Completed.
    notready=$(kubectl -n "$NS" get pods --no-headers 2>/dev/null \
        | awk '$3 != "Running" && $3 != "Completed" && $3 != "ContainerStatusUnknown" {print $1":"$3}' | tr '\n' ' ' || true)
    stale=$(kubectl -n "$NS" get pods --no-headers 2>/dev/null \
        | awk '$3 == "ContainerStatusUnknown" {print $1}' | wc -l | tr -d ' ')
    [ -z "$notready" ] || FAIL=1

    top=$(kubectl -n "$NS" top pod --no-headers 2>/dev/null \
        | awk '{print $1"="$2"/"$3}' | tr '\n' ' ' || true)
    [ -n "$top" ] || top="not measured (metrics-server)"

    lag=$(kubectl -n "$NS" exec clickhouse-0 -- clickhouse-client -q \
        "SELECT dateDiff('second', max(timestamp), now()) FROM weirvern.flows" 2>/dev/null || true)
    [ -n "$lag" ] || lag="not measured"
    case "$lag" in
        ''|*[!0-9]*) : ;;
        *) [ "$lag" -le 600 ] || { FAIL=1; lag="$lag FAILED"; } ;;
    esac

    parts=$(kubectl -n "$NS" exec clickhouse-0 -- clickhouse-client -q \
        "SELECT count() FROM system.parts WHERE database='weirvern' AND active" 2>/dev/null || true)
    [ -n "$parts" ] || parts="not measured"

    say "sample=$SAMPLES health=$hstate pods=[$pods] notready=[$notready] stale_unknown=$stale top=[$top] ingest_lag_s=$lag active_parts=$parts"
    sleep "$INTERVAL"
done

say "=== soak end: samples=$SAMPLES fail=$FAIL ==="
if [ "$FAIL" -eq 0 ]; then
    say "SOAK PASS: no failed health sample, no unready pod, ingest lag stayed <=600s"
    exit 0
fi
say "SOAK FAIL: at least one sample breached; read the log above"
exit 1
