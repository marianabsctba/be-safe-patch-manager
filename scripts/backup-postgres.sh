#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

OUT_DIR="${BACKUP_DIR:-$ROOT_DIR/backups}"
mkdir -p "$OUT_DIR"
chmod 700 "$OUT_DIR" 2>/dev/null || true
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

trap - EXIT
echo "Backup concluído."
echo "$FINAL"
echo "$FINAL.sha256"
