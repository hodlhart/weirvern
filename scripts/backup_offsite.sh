#!/bin/sh
# Pull a ClickHouse backup off the Weirvern host, encrypt it, and keep a bounded
# local history. This is the off-cluster leg that `backup_clickhouse.sh` does not
# provide: that script writes to the ClickHouse PVC, which is in the same failure
# domain as the database it protects.
#
# Usage:
#   scripts/backup_offsite.sh                 # create a fresh backup and pull it
#   scripts/backup_offsite.sh <backup-name>  # pull an existing backup by name
#
# Environment:
#   WEIRVERN_REMOTE_HOST   ssh target, default root@sensor.example
#   WEIRVERN_REMOTE_REPO   checkout on the target, default /opt/weirvern
#   WEIRVERN_BACKUP_DIR    local destination, default /home/admin/weirvern-backups
#   WEIRVERN_BACKUP_KEY    passphrase file, default /home/admin/.weirvern-backup.key
#   WEIRVERN_BACKUP_KEEP   local copies to keep, default 14
#
# The key is deliberately not stored in this repository or in the cluster. Keep a
# copy somewhere other than the backup destination; a key beside the ciphertext is
# not encryption, it is packaging.
set -eu
umask 077

REMOTE="${WEIRVERN_REMOTE_HOST:-root@sensor.example}"
REMOTE_REPO="${WEIRVERN_REMOTE_REPO:-/opt/weirvern}"
DEST="${WEIRVERN_BACKUP_DIR:-/home/admin/weirvern-backups}"
KEY="${WEIRVERN_BACKUP_KEY:-/home/admin/.weirvern-backup.key}"
KEEP="${WEIRVERN_BACKUP_KEEP:-14}"
REMOTE_KEEP="${WEIRVERN_BACKUP_REMOTE_KEEP:-7}"

die() { echo "error: $*" >&2; exit 1; }
[ -r "$KEY" ] || die "backup key not readable: $KEY (create one with: openssl rand -base64 32 > $KEY; chmod 600 $KEY)"
[ -s "$KEY" ] || die "backup key is empty: $KEY"
mkdir -p "$DEST"

if [ "$#" -ge 1 ]; then
    NAME="$1"
else
    NAME="weirvern-$(date -u +%Y%m%d-%H%M%S)"
    ssh "$REMOTE" "cd '$REMOTE_REPO' && sh scripts/backup_clickhouse.sh --name '$NAME'" >/dev/null
fi

case "$NAME" in
    ""|*/*|*..*) die "refusing backup name: $NAME" ;;
esac

# The remote tar runs INSIDE the ClickHouse container, where the backup lives.
# stderr is left visible: a missing pod or a failed tar must not look like a
# successful encrypted file.
TMP="$DEST/.$NAME.tar.gz.gpg.part"
OUT="$DEST/$NAME.tar.gz.gpg"
ssh "$REMOTE" "kubectl -n weirvern exec clickhouse-0 -- tar czf - -C /var/lib/clickhouse/backups '$NAME'" \
    | gpg --batch --yes --symmetric --cipher-algo AES256 --passphrase-file "$KEY" >"$TMP"
mv "$TMP" "$OUT"

# Verify the archive decrypts and is a readable gzip stream; do not call an
# unopened ciphertext a backup.
gpg --batch --yes --decrypt --passphrase-file "$KEY" "$OUT" 2>/dev/null \
    | tar tzf - >/dev/null || die "encrypted backup did not decrypt to a readable tar: $OUT"

BYTES=$(wc -c <"$OUT" | tr -d ' ')
DIGEST=$(sha256sum "$OUT" | awk '{print $1}')

# Model artifacts are a separate small backup. They must travel with the data:
# restoring ClickHouse without the matching model set is a different deployment.
MODELS_TMP="$DEST/.$NAME-models.tar.gz.gpg.part"
MODELS_OUT="$DEST/$NAME-models.tar.gz.gpg"
ssh "$REMOTE" "kubectl -n weirvern exec deploy/weirvern-worker -- tar czf - -C / models" \
    | gpg --batch --yes --symmetric --cipher-algo AES256 --passphrase-file "$KEY" >"$MODELS_TMP"
mv "$MODELS_TMP" "$MODELS_OUT"
gpg --batch --yes --decrypt --passphrase-file "$KEY" "$MODELS_OUT" 2>/dev/null \
    | tar tzf - >/dev/null || die "encrypted model backup did not decrypt to a readable tar: $MODELS_OUT"
MODELS_BYTES=$(wc -c <"$MODELS_OUT" | tr -d ' ')
MODELS_DIGEST=$(sha256sum "$MODELS_OUT" | awk '{print $1}')

{
    echo "backup: $NAME"
    echo "encrypted_file: $OUT"
    echo "sha256: $DIGEST"
    echo "bytes: $BYTES"
    echo "models_file: $MODELS_OUT"
    echo "models_sha256: $MODELS_DIGEST"
    echo "models_bytes: $MODELS_BYTES"
    echo "remote: $REMOTE"
    echo "created_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >"$DEST/$NAME.manifest"

# Keep a bounded local history. `ls -1t` is intentional: names are timestamped
# and the manifest is not a backup. Only .gpg files count.
COUNT=0
for old in $(ls -1t "$DEST"/*.tar.gz.gpg 2>/dev/null || true); do
    COUNT=$((COUNT + 1))
    if [ "$COUNT" -gt "$KEEP" ]; then
        base=$(basename "$old" .tar.gz.gpg)
        rm -f "$old" "$DEST/$base-models.tar.gz.gpg" "$DEST/$base.manifest"
        echo "pruned: $old"
    fi
done

# The ClickHouse PVC is a second retention surface. Keep it bounded too; the
# off-cluster copy is the durable history, not the PVC.
OLD_REMOTE=$(ssh "$REMOTE" "cd '$REMOTE_REPO' && sh scripts/backup_clickhouse.sh --list | sort | head -n -$REMOTE_KEEP" 2>/dev/null || true)
for old_name in $OLD_REMOTE; do
    case "$old_name" in
        ""|*/*|*..*) continue ;;
    esac
    ssh "$REMOTE" "cd '$REMOTE_REPO' && sh scripts/backup_clickhouse.sh --prune '$old_name'" >/dev/null 2>&1 || true
    echo "pruned remote: $old_name"
done

echo "offsite backup: $OUT"
echo "sha256: $DIGEST"
echo "bytes: $BYTES"
