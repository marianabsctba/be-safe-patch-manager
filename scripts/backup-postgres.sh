#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${BACKUP_DIR:-$ROOT_DIR/backups}"
RUNTIME_DIR="${PATCH_MANAGER_RUNTIME_DIR:-$ROOT_DIR/runtime}"
STATUS_FILE="$RUNTIME_DIR/backup-status.json"
mkdir -p "$OUT_DIR" "$RUNTIME_DIR"
chmod 700 "$OUT_DIR" "$RUNTIME_DIR" 2>/dev/null || true
umask 077

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
FINAL="$OUT_DIR/patchmgr-$STAMP.dump"
TMP="$FINAL.tmp"

cleanup() {
  rm -f "$TMP"
}
trap cleanup EXIT

echo "Creating PostgreSQL backup: $FINAL"

docker compose exec -T db sh -eu -c '
  export PGPASSWORD="$POSTGRES_PASSWORD"
  pg_dump     -U "$POSTGRES_USER"     -d "$POSTGRES_DB"     --format=custom     --no-owner     --no-privileges
' > "$TMP"

if [ ! -s "$TMP" ]; then
  echo "Backup vazio. Abortando." >&2
  exit 1
fi

docker compose exec -T db pg_restore --list < "$TMP" >/dev/null
mv "$TMP" "$FINAL"
sha256sum "$FINAL" > "$FINAL.sha256"

EPOCH="$(date -u +%s)"
ISO_TIME="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
SIZE_BYTES="$(wc -c < "$FINAL" | tr -d ' ')"
SHA256="$(awk '{print $1}' "$FINAL.sha256")"
STATUS_TMP="$STATUS_FILE.tmp"

cat > "$STATUS_TMP" <<JSON
{"status":"ok","epoch":$EPOCH,"time":"$ISO_TIME","file":"$(basename "$FINAL")","size_bytes":$SIZE_BYTES,"sha256":"$SHA256"}
JSON
chmod 600 "$STATUS_TMP"
mv "$STATUS_TMP" "$STATUS_FILE"

trap - EXIT
echo "Backup concluído."
echo "$FINAL"
echo "$FINAL.sha256"
