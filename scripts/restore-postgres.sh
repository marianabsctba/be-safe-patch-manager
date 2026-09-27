#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -ne 1 ]; then
  echo "Uso: CONFIRM_RESTORE=YES $0 /caminho/patchmgr-YYYYMMDDTHHMMSSZ.dump" >&2
  exit 1
fi

if [ "${CONFIRM_RESTORE:-}" != "YES" ]; then
  echo "Restore bloqueado. Defina CONFIRM_RESTORE=YES explicitamente." >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

BACKUP="$1"
if [ ! -f "$BACKUP" ]; then
  echo "Backup não encontrado: $BACKUP" >&2
  exit 1
fi

CHECKSUM="$BACKUP.sha256"
if [ -f "$CHECKSUM" ]; then
  (
    cd "$(dirname "$BACKUP")"
    sha256sum -c "$(basename "$CHECKSUM")"
  )
else
  echo "AVISO: arquivo .sha256 não encontrado; integridade externa não foi validada." >&2
fi

docker compose exec -T db pg_restore --list < "$BACKUP" >/dev/null

echo "Parando Patch Manager antes do restore..."
docker compose stop patch-manager

restore_ok=false
cleanup() {
  if [ "$restore_ok" != "true" ]; then
    echo "Restore falhou. O Patch Manager permanece parado para revisão." >&2
  fi
}
trap cleanup EXIT

docker compose exec -T db sh -eu -c '
  export PGPASSWORD="$POSTGRES_PASSWORD"
  pg_restore     -U "$POSTGRES_USER"     -d "$POSTGRES_DB"     --clean     --if-exists     --no-owner     --no-privileges     --single-transaction
' < "$BACKUP"

restore_ok=true
trap - EXIT

echo "Restore concluído. Iniciando Patch Manager..."
docker compose start patch-manager
echo "Restore finalizado."
