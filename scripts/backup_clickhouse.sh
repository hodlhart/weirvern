#!/bin/sh
# Back up the weirvern database with ClickHouse's OWN backup engine, onto the deployment's
# own PVC -- and restore it into a scratch database you can verify.
#
# WHY THIS SHAPE (issue #16). The operations page used to say "snapshot the PVCs with your
# storage provisioner" -- advice that cannot be followed anywhere this stack actually runs
# (the shipped storage class is `local-path`; it offers no snapshots), with no restore
# procedure at all. ClickHouse's BACKUP engine needs no storage support: it writes a
# portable artifact under /var/lib/clickhouse/backups/<name> on the clickhouse PVC, and
# `RESTORE ... AS` brings it back into a SCRATCH database, so the restore can be verified
# against the live table counts without touching production.
#
# The server refuses a backup to a disk it has not been told about ("backups.allowed_disk
# ... is not set"). k8s/30-clickhouse.yaml ships that allow-list as the
# weirvern-clickhouse-config ConfigMap; a cluster older than that needs the manifest applied
# BEFORE this script can work.
#
# Usage:
#   scripts/backup_clickhouse.sh                  # full database backup, timestamped name
#   scripts/backup_clickhouse.sh --name <name>    # full database backup, chosen name
#   scripts/backup_clickhouse.sh --list           # what backups exist on the PVC
#   scripts/backup_clickhouse.sh --restore <name> # into weirvern_restore + count parity
#   scripts/backup_clickhouse.sh --prune <name>   # delete one backup from the PVC
#
# Requires: kubectl, with access to the cluster running the weirvern namespace.
set -eu

NAMESPACE="${WEIRVERN_NAMESPACE:-weirvern}"
POD="${WEIRVERN_CLICKHOUSE_POD:-clickhouse-0}"   # stable name: a StatefulSet pod
DISK="default"
BASE="backups"                                   # relative to the disk root (see the manifest)

die() { echo "error: $*" >&2; exit 1; }

ch() { kubectl -n "$NAMESPACE" exec "$POD" -- clickhouse-client -q "$1"; }
in_pod() { kubectl -n "$NAMESPACE" exec "$POD" -- sh -c "$1"; }
in_pod_stdin() { kubectl -n "$NAMESPACE" exec -i "$POD" -- sh -c "$1"; }
counts_query() {
    printf "%s\n" "flows" "netflow_anomalies" "flows_aggregated" |
    while read -r table; do
        ch "SELECT '$table', count() FROM weirvern.$table FORMAT TSV"
    done
}
restored_counts_query() {
    printf "%s\n" "flows" "netflow_anomalies" "flows_aggregated" |
    while read -r table; do
        ch "SELECT '$table', count() FROM weirvern_restore.$table FORMAT TSV"
    done
}

valid_name() {
    case "${1:-}" in
        "" | */* | *..* | *' '* | *'/'*) return 1 ;;
        *) return 0 ;;
    esac
}

cmd_backup() {
    name=$1
    valid_name "$name" || die "refusing the backup name '$name'"
    # Counts BEFORE and AFTER the backup. `flows` is high-write and has a short TTL;
    # the backup is a consistent set of parts but the live table can grow while it runs,
    # so no single post-hoc count is the snapshot boundary. TTL-free tables must match
    # exactly; the append-only flow table must fall inside the pre/post range.
    counts_before=$(counts_query)
    ch "BACKUP DATABASE weirvern TO Disk('$DISK', '$BASE/$name')"
    counts_after=$(counts_query)
    in_pod_stdin "cat > '/var/lib/clickhouse/$BASE/$name.counts'" <<EOF
pre
$counts_before
post
$counts_after
EOF
    echo "backup written: /var/lib/clickhouse/$BASE/$name (on the clickhouse PVC)"
    echo "  size: $(in_pod "du -sh /var/lib/clickhouse/$BASE/$name | cut -f1")"
    echo "  pre/post snapshot counts:"
    printf '%s\n' "$counts_before" "$counts_after" | sed 's/^/    /' 
}

cmd_list() {
    in_pod "ls -1 /var/lib/clickhouse/$BASE 2>/dev/null || echo '(no backups yet)'"
}

cmd_restore() {
    name=$1
    valid_name "$name" || die "refusing the backup name '$name'"
    ch "DROP DATABASE IF EXISTS weirvern_restore"
    ch "RESTORE DATABASE weirvern AS weirvern_restore FROM Disk('$DISK', '$BASE/$name')"
    echo "restored into the SCRATCH database weirvern_restore"
    manifest="/var/lib/clickhouse/$BASE/$name.counts"
    if in_pod "test -f '$manifest'"; then
        expected=$(in_pod "cat '$manifest'")
        actual=$(restored_counts_query)
        pre=$(printf '%s\n' "$expected" | awk '/^pre$/{on=1;next} /^post$/{on=0} on')
        post=$(printf '%s\n' "$expected" | awk '/^post$/{on=1;next} on')
        echo "snapshot vs restored (pre/post backup bounds):"
        printf '%s\n' "$pre" | sed 's/^/  pre      /'
        printf '%s\n' "$post" | sed 's/^/  post     /'
        printf '%s\n' "$actual" | sed 's/^/  restored /'
        ok=1
        for table in flows netflow_anomalies flows_aggregated; do
            p=$(printf '%s\n' "$pre" | awk -v t="$table" '$1==t{print $2}')
            q=$(printf '%s\n' "$post" | awk -v t="$table" '$1==t{print $2}')
            a=$(printf '%s\n' "$actual" | awk -v t="$table" '$1==t{print $2}')
            [ -n "$p" ] && [ -n "$q" ] && [ -n "$a" ] || { echo "MISSING count for $table" >&2; ok=0; continue; }
            case "$table" in
                flows|flows_aggregated)
                    # These tables have TTLs (3d raw, 7d aggregates). A restore can
                    # legitimately drop rows that expired between backup and restore;
                    # exact parity is not a valid invariant for them.
                    [ "$a" -gt 0 ] 2>/dev/null && [ "$a" -le "$q" ] 2>/dev/null || { echo "OUT OF RANGE $table: restored $a, snapshot max $q" >&2; ok=0; }
                    echo "  TTL table $table: restored $a <= snapshot post $q (expired rows may be absent)"
                    ;;
                *)
                    if [ "$p" = "$q" ]; then
                        [ "$a" = "$p" ] || { echo "MISMATCH $table: restored $a, snapshot $p" >&2; ok=0; }
                    else
                        [ "$a" -ge "$p" ] 2>/dev/null && [ "$a" -le "$q" ] 2>/dev/null || { echo "OUT OF RANGE $table: restored $a, expected $p..$q" >&2; ok=0; }
                    fi
                    ;;
            esac
        done
        [ "$ok" = 1 ] || { echo "MISMATCH: restored snapshot is outside the backup-time bounds" >&2; exit 1; }
        echo "PASS: restored snapshot is within the pre/post backup bounds (exact for TTL-free tables)."
    else
        echo "WARNING: no snapshot .counts file for '$name'; this backup predates snapshot-count verification."
        echo "Live-now counts are shown for context only; they are NOT a valid snapshot comparison:"
        ch "SELECT 'flows' AS table, count() AS live_now FROM weirvern.flows \
UNION ALL SELECT 'netflow_anomalies', count() FROM weirvern.netflow_anomalies \
UNION ALL SELECT 'flows_aggregated', count() FROM weirvern.flows_aggregated"
    fi
    echo
    echo "inspect freely, then drop the scratch:"
    echo "  kubectl -n $NAMESPACE exec $POD -- clickhouse-client -q 'DROP DATABASE weirvern_restore'"
}

cmd_prune() {
    name=$1
    valid_name "$name" || die "refusing the backup name '$name'"
    in_pod "test -d /var/lib/clickhouse/$BASE/$name" || die "no such backup: $name"
    in_pod "rm -rf /var/lib/clickhouse/$BASE/$name /var/lib/clickhouse/$BASE/$name.counts"
    echo "pruned $BASE/$name"
}

usage() {
    sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
}

case "${1:-}" in
    "")
        cmd_backup "weirvern-$(date -u +%Y%m%d-%H%M%S)"
        ;;
    --name)
        [ $# -ge 2 ] || die "--name needs a value"
        cmd_backup "$2"
        ;;
    --list) cmd_list ;;
    --restore)
        [ $# -ge 2 ] || die "--restore needs a backup name (see --list)"
        cmd_restore "$2"
        ;;
    --prune)
        [ $# -ge 2 ] || die "--prune needs a backup name (see --list)"
        cmd_prune "$2"
        ;;
    -h | --help) usage ;;
    *) die "unknown argument: $1 (see --help)" ;;
esac
