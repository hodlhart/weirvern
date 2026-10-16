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

valid_name() {
    case "${1:-}" in
        "" | */* | *..* | *' '* | *'/'*) return 1 ;;
        *) return 0 ;;
    esac
}

cmd_backup() {
    name=$1
    valid_name "$name" || die "refusing the backup name '$name'"
    ch "BACKUP DATABASE weirvern TO Disk('$DISK', '$BASE/$name')"
    echo "backup written: /var/lib/clickhouse/$BASE/$name (on the clickhouse PVC)"
    echo "  size: $(in_pod "du -sh /var/lib/clickhouse/$BASE/$name | cut -f1")"
}

cmd_list() {
    in_pod "ls -1 /var/lib/clickhouse/$BASE 2>/dev/null || echo '(no backups yet)'"
}

cmd_restore() {
    name=$1
    valid_name "$name" || die "refusing the backup name '$name'"
    ch "DROP DATABASE IF EXISTS weirvern_restore"
    ch "RESTORE DATABASE weirvern AS weirvern_restore FROM Disk('$DISK', '$BASE/$name')"
    echo "restored into the SCRATCH database weirvern_restore; live vs restored:"
    ch "SELECT 'flows' AS table, (SELECT count() FROM weirvern.flows) AS live, \
(SELECT count() FROM weirvern_restore.flows) AS restored \
UNION ALL SELECT 'netflow_anomalies', (SELECT count() FROM weirvern.netflow_anomalies), \
(SELECT count() FROM weirvern_restore.netflow_anomalies) \
UNION ALL SELECT 'flows_aggregated', (SELECT count() FROM weirvern.flows_aggregated), \
(SELECT count() FROM weirvern_restore.flows_aggregated)"
    echo
    echo "the two columns must match, table for table. Inspect freely, then drop the scratch:"
    echo "  kubectl -n $NAMESPACE exec $POD -- clickhouse-client -q 'DROP DATABASE weirvern_restore'"
}

cmd_prune() {
    name=$1
    valid_name "$name" || die "refusing the backup name '$name'"
    in_pod "test -d /var/lib/clickhouse/$BASE/$name" || die "no such backup: $name"
    in_pod "rm -rf /var/lib/clickhouse/$BASE/$name"
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
