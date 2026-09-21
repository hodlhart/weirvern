#!/bin/sh
# ONE-HOUR siphon-mode stress test, exercising the whole project workflow end to end.
#
# WHAT THIS IS FOR. Every piece of siphon mode has been verified in isolation: the poison frame
# on a real host, the forwarding policy route, the watchdog arithmetic, the in-cluster
# capabilities. Nothing has run all of it CONTINUOUSLY for an hour, and continuous operation is
# where the interesting failures are:
#
#   * ARP caches age. A one-shot poison that works for 30 seconds proves nothing about whether
#     the refresh loop actually holds the intercept -- the target's real gateway traffic
#     refreshes its entry, and the refresh interval is what competes with it.
#   * The watchdog's stall detector only has an opinion over time. Its quiet-network protection
#     was fixed after it fired on a healthy segment; an hour is the first chance to see whether
#     that fix holds when the LAN is genuinely idle for stretches.
#   * The address lease and the policy route persist for an hour. Anything that leaks (a rule
#     accumulating, a sysctl drifting) is invisible in a 25-second run.
#
# WHAT IT MEASURES, and why each matters:
#   1. forwarding counters over time  -- the relay must keep working, not just start
#   2. ARP cache of the target over time -- the intercept must HOLD, not just take
#   3. watchdog refresh/restore counts -- the mechanism that makes it hold
#   4. end-to-end project flow        -- does traffic reaching us become rows, features, and
#                                        (if it warrants it) a detection
#
# SAFETY, because this runs against a LIVE segment for an hour:
#   * it is time-boxed and restores unconditionally, in a trap, on every exit path
#   * it prints a heartbeat every 2 minutes so a hang is visible rather than silent
#   * the watchdog fails open, so a broken relay restores the segment rather than blackholing it
#   * it verifies the segment is healthy AFTER teardown, not merely that teardown ran
set -u

DURATION_MIN=${1:-60}
# Empty = every host the sweep finds. The segment-health probes below also cover the whole
# set, because "the segment is healthy afterwards" should be a claim about the segment.
TARGET=""
INTERCEPT_SCOPE="--all"
# THE SEGMENT, GATEWAY AND ADDRESS COME FROM THE ENVIRONMENT.
#
# These were hardcoded to one deployment's network, which put a real segment in the repository and
# meant the harness would test the WRONG network anywhere else -- while reporting success. They are
# required now: a stress test that silently scans someone else's segment is worse than one that
# refuses to start.
SEGMENT="${INTERCEPT_SEGMENT:?set INTERCEPT_SEGMENT (e.g. 198.51.100.0/24)}"
GW="${INTERCEPT_GATEWAY:?set INTERCEPT_GATEWAY}"
OUR_IP="${INTERCEPT_ADDR:?set INTERCEPT_ADDR}"
IFACE="${CAPTURE_IFACE:-${ZEEK_IFACE:-eth1}}"
NS=weirvern
OUT=/tmp/siphon_stress_$(date +%Y%m%d_%H%M%S).log

resolve_pod() {
  kubectl -n $NS get pod -l app.kubernetes.io/name=weirvern-worker \
      --sort-by=.status.startTime -o jsonpath='{.items[-1].metadata.name}' 2>/dev/null
}


# STAMP THE SCRIPT'S OWN DIGEST. Several old logs in /tmp came from superseded versions of this
# harness, and one shows a failure that has since been fixed -- indistinguishable from a current
# log when read side by side. This makes "which version produced this log" answerable from the log.
SELF_DIGEST=$(sha256sum "$0" 2>/dev/null | cut -c1-12)
echo "=== siphon stress test: ${DURATION_MIN} minutes on $SEGMENT (scope: ALL swept hosts) ===" | tee "$OUT"
echo "  harness    : $(basename "$0") sha256:${SELF_DIGEST:-unknown}" | tee -a "$OUT"
echo "  started    : $(date -Is)" | tee -a "$OUT"
echo "  log: $OUT"
echo

W=$(resolve_pod)
[ -n "$W" ] || { echo "FATAL: no worker pod"; exit 1; }
echo "  worker pod: $W" | tee -a "$OUT"
echo

# ── the unconditional restore ──────────────────────────────────────────────────
# Registered BEFORE anything changes, so an interrupt during setup is still covered.
# The pod is re-resolved on EVERY use, because a rollout during the run renames it. An earlier
# version captured one name at start; when the worker was rolled mid-test the teardown failed with
# "pods ... not found" and left the capture address assigned. A teardown that can fail because a
# pod was rescheduled is not a teardown.

cleanup() {
  echo "" | tee -a "$OUT"
  echo "=== CLEANUP (every exit path) ===" | tee -a "$OUT"
  W=$(resolve_pod)
  # Stop the detached intercept through its own tool: it sends SIGINT so the watchdog's handler
  # withdraws every forged mapping, and it waits for the process to actually go.
  if [ -n "$W" ]; then
    kubectl -n $NS exec "$W" -c worker -- python /tmp/intercept_detached.py --stop 2>&1 | tail -2 | sed 's/^/  /' | tee -a "$OUT"
  fi
  if [ -z "$W" ]; then
    echo "  no worker pod to run the in-pod teardown; relying on the host-side cleanup below" \
        | tee -a "$OUT"
  fi
  kubectl -n $NS exec "$W" -c worker -- python -c "
from weirvern.config import Settings
from weirvern.admin.siphonnet import remove_forwarding_path, remove_address, check_forwarding
import logging; logging.disable(logging.CRITICAL)
try:
    remove_forwarding_path('$IFACE')
    print('  forwarding path removed')
except Exception as e:
    print('  forwarding path removal:', e)
try:
    remove_address('$IFACE', '$OUR_IP', '$SEGMENT')
    print('  address $OUR_IP withdrawn')
except Exception as e:
    print('  address withdrawal:', e)
# Report what is left, so a partial teardown is VISIBLE rather than assumed -- the failure this
# script's own teardown just exhibited.
try:
    st = check_forwarding('$IFACE')
    print(f'  forwarding checks after teardown: ip_forward={st.ip_forward} '
          f'rp_filter_off={st.rp_filter_off} rule={st.rule_installed} '
          f'table={st.table_installed}')
    if st.problems:
        print(f'  REMAINING PROBLEMS: {st.problems}')
    else:
        print('  no forwarding problems remain')
except Exception as e:
    print('  forwarding state check failed:', e)
" 2>&1 | tee -a "$OUT"
  # The host may also have leftovers from an earlier run, OR the in-pod teardown may not have run
  # at all (pod rolled mid-test). Clear both here so an unreachable pod cannot leave the host
  # configured: a leftover address keeps a route and keeps accepting traffic for a segment the
  # operator never asked to be involved in.
  if ip addr del $OUR_IP/24 dev $IFACE 2>/dev/null; then
    echo "  (host-side address removed)" | tee -a "$OUT"
  fi
  # Also REMOVE the policy rule, not merely flush the table. A leftover `ip rule` sends ALL traffic
  # arriving on the interface to table 100 -- which, once the address is gone, is a table with no
  # routes. This is what left a live intercept's routing in place when the in-pod teardown failed.
  if ip rule del from $SEGMENT lookup 100 2>/dev/null; then
    echo "  (host-side policy rule removed)" | tee -a "$OUT"
  fi
  ip rule del from $SEGMENT lookup 100 2>/dev/null && echo "  (host-side rule also removed)" | tee -a "$OUT"
  ip route flush table 100 2>/dev/null && echo "  (host-side table 100 flushed)" | tee -a "$OUT"
  echo "  ip_forward=$(sysctl -n net.ipv4.ip_forward) rp_filter=$(sysctl -n net.ipv4.conf.all.rp_filter) send_redirects=$(sysctl -n net.ipv4.conf.all.send_redirects)" | tee -a "$OUT"
  # State that must be EMPTY after a clean teardown. Printed with the value, not a pass/fail, so a
  # partial teardown is visible in the log instead of being inferred.
  echo "  eth1 address : '$(ip -o -4 addr show $IFACE 2>/dev/null | awk '{print $4}' | tr -d '\n')'  (must be empty)" | tee -a "$OUT"
  echo "  rule lookup100: $(ip rule show 2>/dev/null | grep -c 'lookup 100')  (must be 0)" | tee -a "$OUT"
  echo "  table 100     : $(ip route show table 100 2>/dev/null | wc -l)  (must be 0)" | tee -a "$OUT"

  # LOUD IF ANYTHING REMAINS -- the orphan that prompted this was silent. The teardown reported a
  # clean segment from the parts it could check while an intercept kept running in the pod.
  REMAIN_ADDR=$(ip -o -4 addr show $IFACE 2>/dev/null | wc -l)
  REMAIN_RULE=$(ip rule show 2>/dev/null | grep -c 'lookup 100')
  if [ "$REMAIN_ADDR" != "0" ] || [ "$REMAIN_RULE" != "0" ]; then
    echo "  !! TEARDOWN INCOMPLETE: $REMAIN_ADDR address(es) and $REMAIN_RULE rule(s) remain on $IFACE." | tee -a "$OUT"
    echo "     A live intercept may still be running in the pod. Check with:" | tee -a "$OUT"
    echo "       kubectl -n $NS exec <worker> -c worker -- python /tmp/intercept_detached.py --status" | tee -a "$OUT"
  fi
}
trap cleanup EXIT INT TERM

# ── baseline the segment BEFORE touching it ────────────────────────────────────
echo "=== pre-test segment health (so a later failure is attributable) ===" | tee -a "$OUT"
ip addr add $OUR_IP/24 dev $IFACE 2>/dev/null
sleep 1
SEG_HOSTS=$(kubectl -n $NS exec "$W" -c worker -- python /tmp/sweep_probe.py 2>/dev/null \
    | sed -n 's/^    \([0-9.]*\).*/\1/p' | tr '\n' ' ')
if [ -z "$(echo $SEG_HOSTS | tr -d ' ')" ]; then
  echo "  WARNING: the sweep found no hosts. On a live segment that is almost always the" | tee -a "$OUT"
  echo "  probe's fault (a request sourced from 0.0.0.0 is ignored), not an empty network." | tee -a "$OUT"
fi
echo "  hosts swept: $(echo $SEG_HOSTS | wc -w)" | tee -a "$OUT"
for h in $SEG_HOSTS; do
  if ping -c 2 -W 2 -I $IFACE "$h" >/dev/null 2>&1; then echo "    $h up" | tee -a "$OUT";
  else echo "    $h DOWN" | tee -a "$OUT"; fi
done
echo "  gateway real MAC:        $(ip neigh show $GW dev $IFACE 2>/dev/null || echo 'none')" | tee -a "$OUT"
echo "  forwarding counters before: ForwDatagrams=$(awk '/^Ip:/{if(n==0){for(i=1;i<=NF;i++)h[i]=$i;n=1;next} for(i=1;i<=NF;i++) if(h[i]=="ForwDatagrams") print $i+0; exit}' /proc/net/snmp)" | tee -a "$OUT"
ip addr del $OUR_IP/24 dev $IFACE 2>/dev/null
echo

# ── start the intercept, DETACHED INSIDE THE POD, for the full duration ───────────────────────
#
# WHY NOT `kubectl exec ... &` ANY MORE. That captured the LOCAL kubectl pid, and the exec stream
# does not survive an hour:
#
#     E0919 02:17:04 "Copying stderr failed" err="read tcp 127.0.0.1:55636->127.0.0.1:6443:
#                     i/o timeout"
#
# Three runs died at 4m for this reason, and the harness called it "intercept exited early" --
# true of the CLIENT, meaningless about the intercept. `intercept_detached.py` starts the process
# in its own session inside the pod, so nothing depends on a client staying connected.
echo "=== starting weirvern intercept DETACHED for ${DURATION_MIN} minutes ===" | tee -a "$OUT"
kubectl -n $NS exec "$W" -c worker -- python /tmp/intercept_detached.py \
    --iface $IFACE --segment $SEGMENT --our-ip $OUR_IP --gateway $GW \
    $INTERCEPT_SCOPE --seconds $((DURATION_MIN * 60)) 2>&1 | tee -a "$OUT" | tail -2

# ── sample loop: bounded by REAL ELAPSED TIME, not an iteration count ────────────────────────────
#
# WHY THIS CHANGED. The loop was `SAMPLES=$((DURATION_MIN/2))` iterations of `sleep 120`, assuming
# each iteration costs 2 minutes. It does not: every iteration shells out through `kubectl exec` for
# the liveness check and the counters, and the API server's latency varies from under a second to
# MINUTES. Measured: a single `count_intercepts` exec took 166s once, and a 60-minute run had logged
# only 3 samples after 18 minutes of wall-clock.
#
# That mattered more than a mislabelled column. The intercept is bounded by WALL-CLOCK
# (`--seconds 3600`), but the loop was bounded by ITERATION COUNT. With iterations costing ~3.5
# minutes, 30 of them need ~105 minutes -- so the sampler outlived the intercept by ~45 minutes and
# its tail samples would show a stopped intercept. That is MY harness stopping the subject, and it
# would have been reported as the system failing the hour.
#
# Now the loop runs until the intercept's own deadline (minus a margin to observe the restore), and
# `elapsed` is computed from real time. A measurement must report the thing it measured.
START_EPOCH=$(date +%s)
DEADLINE=$(( START_EPOCH + DURATION_MIN * 60 ))
# Stop sampling this many seconds before the intercept's own deadline, so the final samples show it
# still healthy and the teardown is observed rather than raced.
SAMPLE_UNTIL=$(( DEADLINE - 60 ))
echo "=== sampling until the intercept's own deadline (real time, not iteration count) ===" | tee -a "$OUT"
printf "  %-8s %-9s %-9s %-9s %-24s\n" "elapsed" "ForwDat" "InNoRt" "InAddr" "note" | tee -a "$OUT"

POISON_HOLDS=0
# Intervals where the forwarding counter did NOT move. Deliberately NOT called "lost": see the
# sample-loop comment -- idle and relay-stalled are indistinguishable from here.
POISON_UNKNOWN=0
HB_AGE=""
HB_MODE=""
# Times the heartbeat check itself failed. Reported: a run with many unreadable checks is weakly
# evidenced even when it completes.
HB_UNREADABLE=0   # total failures across the run
HB_STREAK=0       # consecutive failures, reset on a readable check
FORW_PREV=""
FORW_BEFORE=$(awk '/^Ip:/{if(n==0){for(i=1;i<=NF;i++)h[i]=$i;n=1;next} for(i=1;i<=NF;i++) if(h[i]=="ForwDatagrams") print $i+0; exit}' /proc/net/snmp)
# INITIALISED DELIBERATELY. The first iteration reads LAST_ITER, and under `set -u` an unset
# variable ABORTS the script before a single sample -- which produces a zero-sample run whose
# teardown then reports a clean segment. That is the "a run that tested nothing looked like a
# success" failure this file already warns about, and an uninitialised counter is one way to
# reintroduce it.
LAST_ITER=0
i=0
while [ "$(date +%s)" -lt "$SAMPLE_UNTIL" ]; do
  # Sleep the INTERVAL minus whatever the last iteration's checks cost, so the cadence is roughly
  # regular without the expensive probes stretching it. Guarded: a slow iteration must not make this
  # negative and busy-loop.
  NOW=$(date +%s)
  WAIT=$(( 120 - (NOW - LAST_ITER) ))
  [ "$LAST_ITER" -eq 0 ] && WAIT=120
  [ "$WAIT" -gt 0 ] && sleep "$WAIT"
  LAST_ITER=$(date +%s)
  i=$((i+1))
  ELAPSED=$(( (LAST_ITER - START_EPOCH) / 60 ))
  # Is the intercept still alive? Asked of the SENSOR'S OWN HEARTBEAT, not a local pid.
  # Is the intercept still alive? THREE STATES, NOT TWO.
  #
  #   ALIVE   a fresh heartbeat was read          -> keep going
  #   DEAD    a heartbeat was read and is stale   -> break
  #   UNKNOWN the check itself could not reach ClickHouse -> keep going and COUNT it
  #
  # Conflating UNKNOWN with DEAD is a false negative, and it cost a real run: a transient DNS
  # failure inside the cluster made this check unreadable, the sampler STOPPED a healthy intercept
  # (the last sample showed forwarding +438, poison held), and because the teardown could not exec
  # either, the intercept was left RUNNING and unmonitored -- eth1 with its address, rule 100 and
  # table 100 all still installed. A monitoring call that failed converted a blip into a live
  # in-path intercept with nothing watching it.
  #
  # The rule this violated: an inability to MEASURE is not evidence of a failure.
  #
  # ── THIRD ATTEMPT, AND WHY THE FIRST TWO FAILED ────────────────────────────────────────────────
  #
  # Attempt 1: heartbeat only, staleness > 60s -> DEAD. Stopped a LIVE intercept (06:10:25, node
  # verified in-path: intercepts=1, rule100=1, table100=1). The heartbeat is database-backed, and a
  # database that is slow or briefly unresolvable returns an OLD row rather than nothing -- so the
  # check landed in DEAD, not UNKNOWN.
  #
  # Attempt 2: log age (`LOG_AGE`) as primary, on the reasoning that the intercept writes its log
  # continuously. MEASURED AND WRONG: the log is written ONCE at startup and never grows --
  # `size` stayed at exactly 3543 bytes across three probes while `mtime` aged 5s -> 35s -> 65s.
  # So LOG_AGE measures "time since the intercept started", not liveness, and it stopped the run at
  # 2m again. A signal that cannot distinguish alive from dead is not a signal; asserting it works
  # without measuring was the error, and the measurement is two lines.
  #
  # Attempt 3, current: `REAL_INTERCEPTS` from count_intercepts.py, which walks /proc for the
  # intercept's own argv. NO DATABASE, and validated against a known-live intercept:
  #
  #     probe 1: intercepts=1 rule100=1
  #     probe 2: intercepts=1 rule100=1
  #     probe 3: intercepts=1 rule100=1
  #
  # Three states, honestly: 1 = ALIVE, 0 = DEAD (positive evidence of absence, which the pid check
  # cannot give across a process boundary), unreadable = UNKNOWN and the run continues.
  STATUS_RAW=$(kubectl -n $NS exec "$W" -c worker -- python /tmp/intercept_detached.py --status 2>/dev/null) || STATUS_RAW=""
  HB_RAW=$(echo "$STATUS_RAW" | sed -n 's/^HEARTBEAT=\([0-9.]*\)s ago mode=\(.*\)/\1 \2/p' | head -1)
  HB_AGE=$(echo "$HB_RAW" | awk '{print $1}')
  HB_MODE=$(echo "$HB_RAW" | awk '{print $2}')

  # The primary signal: is the intercept PROCESS alive? Positional-argv matching, no database.
  NPROC=$(kubectl -n $NS exec "$W" -c worker -- python /tmp/count_intercepts.py 2>/dev/null \
          | sed -n 's/^REAL_INTERCEPTS=\([0-9]*\)$/\1/p' | head -1)

  if [ "${NPROC:-}" = "1" ]; then
    LIVENESS=ALIVE
  elif [ "${NPROC:-}" = "0" ]; then
    LIVENESS=DEAD
  else
    LIVENESS=UNKNOWN
  fi

  case "$LIVENESS" in
    DEAD)
      echo "  !! no intercept process at ${ELAPSED}m (count_intercepts=0) -- it has stopped." | tee -a "$OUT"
      echo "     This is positive evidence, not a failed check: /proc was read and nothing matched." | tee -a "$OUT"
      break
      ;;
    UNKNOWN)
      HB_UNREADABLE=$((HB_UNREADABLE + 1))
      HB_STREAK=$((HB_STREAK + 1))
      echo "  ${ELAPSED}m  liveness UNKNOWN (count_intercepts unreadable; streak $HB_STREAK, total $HB_UNREADABLE)" | tee -a "$OUT"
      echo "       -- NOT treating this as a stopped intercept: an unanswerable check is not evidence" | tee -a "$OUT"
      if [ "$HB_STREAK" -ge 3 ]; then
        echo "  !! liveness UNKNOWN for $HB_STREAK consecutive samples (${ELAPSED}m): treating the" | tee -a "$OUT"
        echo "     intercept as DEAD after repeated unreadable checks." | tee -a "$OUT"
        break
      fi
      ;;
    ALIVE)
      HB_STREAK=0
      ;;
  esac
  # Forwarding counters: the relay must still be moving packets.
  #
  # RESOLVED BY FIELD NAME, not by position. The first version used fixed columns and printed
  # EMPTY for a demonstrably working intercept (ForwDatagrams was 272,959 at the time). The
  # header line of /proc/net/snmp names every field, so there is no reason to depend on order --
  # and the order IS kernel-version dependent.
  read -r FORW INNOR INARRT <<EOF
$(awk '/^Ip:/{
     if (n == 0) { for (i=1;i<=NF;i++) h[i]=$i; n=1; next }
     for (i=1;i<=NF;i++) {
       if (h[i] == "ForwDatagrams") f=$i
       if (h[i] == "InAddrErrors")  a=$i
       if (h[i] == "OutNoRoutes")   o=$i
     }
     print f+0, o+0, a+0; exit
   }' /proc/net/snmp)
EOF
  # ── WHAT ACTUALLY INDICATES THE POISON IS STILL HELD ─────────────────────────
  #
  # The first version sampled `ip neigh show $TARGET` ON THIS HOST. That is the SENSOR's ARP
  # cache for the target, which says nothing about whether the TARGET is poisoned -- the whole
  # point of the intercept is to convince the TARGET that the GATEWAY lives at our MAC. Reading
  # our own cache measured the wrong machine entirely and reported "poison LOST" twice while the
  # intercept was working perfectly (144 refresh cycles, clean restore).
  #
  # This box cannot read another host's ARP cache, so the honest proxy is the forwarding counter
  # ADVANCING between samples: the kernel only forwards datagrams that arrived here because a
  # remote host sent them to our MAC. That is the same evidence the dataplane proof used.
  if [ -z "$FORW_PREV" ]; then
    NOTE="baseline sample"
  elif [ "$FORW" -gt "$FORW_PREV" ]; then
    DELTA=$((FORW - FORW_PREV)); NOTE="forwarding: +$DELTA (relay active)"
    POISON_HOLDS=$((POISON_HOLDS+1))
  else
    # NOT "POISON LOST". This branch is only "the forwarding counter did not move in this
    # interval", and that has (at least) two causes the harness cannot tell apart from here:
    #
    #   * the segment was IDLE -- no host sent anything off-link, so there was nothing to relay
    #   * the relay is genuinely broken -- traffic is flowing but not through us
    #
    # The earlier label said "idle or lost" in the log but counted into a variable called
    # POISON_LOST, which then printed as "poison held in N sample(s), LOST in M". That reads as
    # observed poison loss and is NOT: it is an unmeasured interval being reported as a measurement.
    # Same class of error as the four other instruments in this project that produced confident
    # numbers for things they never measured.
    #
    # Distinguishing them needs positive evidence of ARP state on a peer DURING the interval (read
    # the peer's cache, or confirm traffic is arriving while the counter is flat). Until the harness
    # does that, the honest word is UNKNOWN.
    NOTE="no forwarding this interval (IDLE or relay-stalled -- harness cannot distinguish)"
    POISON_UNKNOWN=$((POISON_UNKNOWN+1))
  fi
  FORW_PREV=$FORW
  printf "  %-8s %-9s %-9s %-9s %-24s\n" "${ELAPSED}m" "$FORW" "$INNOR" "$INARRT" "$NOTE" | tee -a "$OUT"
done

# ── the watchdog's own account of the hour ─────────────────────────────────────
echo "" | tee -a "$OUT"
echo "=== what the watchdog reported over the hour ===" | tee -a "$OUT"
tail -25 /tmp/siphon_intercept.out | sed 's/^/    /' | tee -a "$OUT"
echo

# ── does traffic that reached us become project data? ──────────────────────────
echo "=== end-to-end: did the intercepted traffic reach ClickHouse? ===" | tee -a "$OUT"
kubectl -n $NS exec "$W" -c worker -- python -c "
from weirvern.config import Settings
from weirvern.db import connect
c = connect(Settings())
for q, label in [
    ('SELECT count() FROM weirvern.zeek_conn WHERE ts >= now() - INTERVAL 1 HOUR', 'zeek_conn last hour'),
    ('SELECT count() FROM weirvern.flows_aggregated WHERE window_start >= now() - INTERVAL 1 HOUR', 'flow windows last hour'),
    ('SELECT count() FROM weirvern.netflow_anomalies WHERE detected_at >= now() - INTERVAL 1 HOUR', 'anomalies last hour'),
    ('SELECT count() FROM weirvern.ml_models WHERE trained_at >= now() - INTERVAL 1 HOUR', 'retrains last hour'),
]:
    try:
        print(f'  {label:28} {c.query(q).result_rows[0][0]}')
    except Exception as e:
        print(f'  {label:28} query failed: {str(e)[:60]}')
# The newest anomaly with its technique label, if any was produced.
try:
    r = c.query('SELECT src_addr, severity, attack_label FROM weirvern.netflow_anomalies ORDER BY detected_at DESC LIMIT 1').result_rows
    if r:
        print(f'  most recent anomaly:         {r[0][0]} severity={r[0][1]} techniques={r[0][2] or \"(none matched)\"}')
except Exception as e:
    print('  anomaly lookup failed:', str(e)[:60])
" 2>&1 | sed 's/^/  /' | tee -a "$OUT"

# ── teardown, then verify the SEGMENT is healthy -- not merely that teardown ran ──
echo "" | tee -a "$OUT"
echo "=== waiting for the intercept to finish and restore ===" | tee -a "$OUT"
# Wait for the DETACHED intercept to finish and restore. There is no local pid to wait on,
# so its own status is polled. It is bounded by --seconds, so this always terminates.
for _ in $(seq 1 $((DURATION_MIN * 2 + 10))); do
  S=$(kubectl -n $NS exec "$W" -c worker -- python /tmp/intercept_detached.py --status \
      2>/dev/null | sed -n 's/^PID_ALIVE=\([0-9]*\)/\1/p' | head -1)
  [ "$S" = "0" ] && break
  sleep 30
done
tail -8 /tmp/siphon_intercept.out | sed 's/^/    /' | tee -a "$OUT"
echo

echo "=== POST-TEST segment health (the part that matters) ===" | tee -a "$OUT"
ip addr add $OUR_IP/24 dev $IFACE 2>/dev/null
sleep 2
DOWN=0
for h in $SEG_HOSTS; do
  if ping -c 2 -W 2 -I $IFACE "$h" >/dev/null 2>&1; then echo "    $h up" | tee -a "$OUT";
  else echo "    $h DOWN" | tee -a "$OUT"; DOWN=$((DOWN + 1)); fi
done
echo "  hosts down after: $DOWN of $(echo $SEG_HOSTS | wc -w)" | tee -a "$OUT"
echo "  === ARP cache after: every host must be back on the REAL gateway MAC === " | tee -a "$OUT"
for h in $SEG_HOSTS; do
  # `ip neigh show <addr>` already starts with the address, so it is not printed twice.
  echo "    $(ip neigh show $h dev $IFACE 2>/dev/null || echo "$h no entry")" | tee -a "$OUT"
done
echo "  (must be the GATEWAY's MAC, not ours and not empty)" | tee -a "$OUT"
ip addr del $OUR_IP/24 dev $IFACE 2>/dev/null

echo "" | tee -a "$OUT"
echo "=== SUMMARY ===" | tee -a "$OUT"
if [ "$POISON_HOLDS" = "0" ] && [ "$POISON_UNKNOWN" = "0" ]; then
  echo "  !! NO SAMPLES COLLECTED -- this run tested nothing. The teardown below is clean, and a" | tee -a "$OUT"
  echo "     clean teardown is NOT evidence the intercept worked. Find why the loop stopped." | tee -a "$OUT"
fi
echo "  forwarding observed active in $POISON_HOLDS sample(s); no movement in $POISON_UNKNOWN" | tee -a "$OUT"
echo "  (a 'no movement' interval means the counter did not move -- IDLE segment or a stalled relay;" | tee -a "$OUT"
echo "   this harness cannot tell those apart, so it does NOT claim the poison was lost)" | tee -a "$OUT"
echo "  last heartbeat mode: ${HB_MODE:-n/a} (age ${HB_AGE:-n/a})" | tee -a "$OUT"
# The TOTAL, not the streak. Reporting the streak here claimed "full" evidence for a run that ended
# on a readable check despite having failures earlier -- a false claim of good evidence.
echo "  heartbeat checks that FAILED TO READ: $HB_UNREADABLE total (longest streak: see above)" | tee -a "$OUT"
echo "  evidence quality: $([ "$HB_UNREADABLE" -eq 0 ] && echo full || echo PARTIAL)" | tee -a "$OUT"
echo "  ForwDatagrams at start: $FORW_BEFORE" | tee -a "$OUT"
echo "  full log: $OUT"
