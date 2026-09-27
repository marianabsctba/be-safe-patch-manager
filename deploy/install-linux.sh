#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Uso: sudo $0 https://patch.exemplo [tag]"
  echo "Opcional para automação: PATCH_ENROLLMENT_TOKEN."
  echo "mTLS: PATCH_CLIENT_CERT, PATCH_CLIENT_KEY e opcional PATCH_CA_CERT."
  echo "Update assinado: PATCH_UPDATE_PUBLIC_KEY (chave publica Ed25519)."
  exit 1
fi

SERVER_URL="$1"
TAG="${2:-piloto}"

case "$SERVER_URL" in
  https://*) ;;
  *)
    echo "SERVER_URL deve usar https://." >&2
    exit 1
    ;;
esac

if [ -n "${PATCH_ENROLLMENT_TOKEN:-}" ]; then
  ENROLL="$PATCH_ENROLLMENT_TOKEN"
else
  read -r -s -p "Enrollment token: " ENROLL
  echo
fi

if [ -z "$ENROLL" ]; then
  echo "Enrollment token vazio." >&2
  exit 1
fi

CLIENT_CERT_SOURCE="${PATCH_CLIENT_CERT:-}"
CLIENT_KEY_SOURCE="${PATCH_CLIENT_KEY:-}"
CA_CERT_SOURCE="${PATCH_CA_CERT:-}"
UPDATE_PUBLIC_KEY_SOURCE="${PATCH_UPDATE_PUBLIC_KEY:-}"

if { [ -n "$CLIENT_CERT_SOURCE" ] && [ -z "$CLIENT_KEY_SOURCE" ]; } || { [ -z "$CLIENT_CERT_SOURCE" ] && [ -n "$CLIENT_KEY_SOURCE" ]; }; then
  echo "PATCH_CLIENT_CERT e PATCH_CLIENT_KEY devem ser informados juntos." >&2
  exit 1
fi

for SOURCE in "$CLIENT_CERT_SOURCE" "$CLIENT_KEY_SOURCE" "$CA_CERT_SOURCE" "$UPDATE_PUBLIC_KEY_SOURCE"; do
  if [ -n "$SOURCE" ] && [ ! -f "$SOURCE" ]; then
    echo "Arquivo TLS não encontrado: $SOURCE" >&2
    exit 1
  fi
done

BASE=/opt/patch-manager-agent
CONFIG_DIR=/etc/patch-manager
TLS_DIR="$CONFIG_DIR/tls"
UPDATE_TRUST_DIR="$CONFIG_DIR/update-trust"
UPDATE_STAGING_DIR="/var/lib/patch-manager/updates"
ACTIVATION_STATE="/var/lib/patch-manager/activation.json"
RELEASES_DIR="$BASE/releases"

AGENT_SOURCE="$(dirname "$0")/../agent/patch_agent.py"
AGENT_VERSION="$(python3 - "$AGENT_SOURCE" <<'PY'
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text(encoding="utf-8")
match = re.search(r'^AGENT_VERSION = "([^"]+)"
CLIENT_CERT=""
CLIENT_KEY=""
CA_CERT=""

if [ -n "$CLIENT_CERT_SOURCE" ]; then
  CLIENT_CERT="$TLS_DIR/agent.crt"
  CLIENT_KEY="$TLS_DIR/agent.key"
  cp "$CLIENT_CERT_SOURCE" "$CLIENT_CERT"
  cp "$CLIENT_KEY_SOURCE" "$CLIENT_KEY"
  chmod 644 "$CLIENT_CERT"
  chmod 600 "$CLIENT_KEY"
fi

if [ -n "$CA_CERT_SOURCE" ]; then
  CA_CERT="$TLS_DIR/server-ca.crt"
  cp "$CA_CERT_SOURCE" "$CA_CERT"
  chmod 644 "$CA_CERT"
fi

UPDATE_PUBLIC_KEY=""
if [ -n "$UPDATE_PUBLIC_KEY_SOURCE" ]; then
  UPDATE_PUBLIC_KEY="$UPDATE_TRUST_DIR/agent-update-public.pem"
  cp "$UPDATE_PUBLIC_KEY_SOURCE" "$UPDATE_PUBLIC_KEY"
  chmod 644 "$UPDATE_PUBLIC_KEY"
fi

python3 - "$CONFIG_DIR/agent.json" "$SERVER_URL" "$ENROLL" "$TAG" "$CA_CERT" "$CLIENT_CERT" "$CLIENT_KEY" "$UPDATE_PUBLIC_KEY" "$UPDATE_STAGING_DIR" "$BASE" "$ACTIVATION_STATE" <<'PY'
import json
import sys

path, server_url, enrollment, tag, ca_cert, client_cert, client_key, update_public_key, update_staging_dir, agent_base_dir, activation_state_file = sys.argv[1:]
data = {
    "server_url": server_url,
    "enrollment_token": enrollment,
    "agent_id": "",
    "agent_token": "",
    "tags": [tag],
    "poll_seconds": 60,
    "scan_every_seconds": 1800,
    "tls_verify": True,
    "ca_cert": ca_cert,
    "client_cert": client_cert,
    "client_key": client_key,
    "update_public_key": update_public_key,
    "update_check_seconds": 21600,
    "update_staging_dir": update_staging_dir,
    "agent_base_dir": agent_base_dir,
    "activation_state_file": activation_state_file,
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, ensure_ascii=False, indent=2)
PY

chmod 600 "$CONFIG_DIR/agent.json"
unset ENROLL PATCH_ENROLLMENT_TOKEN PATCH_UPDATE_PUBLIC_KEY || true

cp "$(dirname "$0")/systemd/patch-manager-agent.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable patch-manager-agent
systemctl restart patch-manager-agent
systemctl --no-pager status patch-manager-agent || true
, text, re.MULTILINE)
if not match:
    raise SystemExit("AGENT_VERSION nao encontrado")
print(match.group(1))
PY
)"
RELEASE_DIR="$RELEASES_DIR/$AGENT_VERSION"

mkdir -p "$BASE" "$RELEASES_DIR" "$RELEASE_DIR" "$CONFIG_DIR" "$TLS_DIR" "$UPDATE_TRUST_DIR" "$UPDATE_STAGING_DIR"
chmod 755 "$BASE" "$RELEASES_DIR" "$RELEASE_DIR"
chmod 700 "$CONFIG_DIR" "$TLS_DIR" "$UPDATE_TRUST_DIR" "$UPDATE_STAGING_DIR"

cp "$AGENT_SOURCE" "$RELEASE_DIR/patch_agent.py"
cp "$(dirname "$0")/../agent/requirements.txt" "$RELEASE_DIR/requirements.txt"
cp "$(dirname "$0")/../agent/agent_launcher.py" "$BASE/agent_launcher.py"
chmod 700 "$RELEASE_DIR/patch_agent.py" "$BASE/agent_launcher.py"
chmod 600 "$RELEASE_DIR/requirements.txt"

python3 -m venv "$BASE/.venv"
"$BASE/.venv/bin/pip" install -r "$RELEASE_DIR/requirements.txt"

python3 - "$BASE/current" "$RELEASE_DIR" <<'PY'
import os
import sys
from pathlib import Path

current = Path(sys.argv[1])
target = Path(sys.argv[2]).resolve()
temporary = current.with_name(".current.install.tmp")
temporary.unlink(missing_ok=True)
os.symlink(os.path.relpath(target, current.parent), temporary)
os.replace(temporary, current)
PY

CLIENT_CERT=""
CLIENT_KEY=""
CA_CERT=""

if [ -n "$CLIENT_CERT_SOURCE" ]; then
  CLIENT_CERT="$TLS_DIR/agent.crt"
  CLIENT_KEY="$TLS_DIR/agent.key"
  cp "$CLIENT_CERT_SOURCE" "$CLIENT_CERT"
  cp "$CLIENT_KEY_SOURCE" "$CLIENT_KEY"
  chmod 644 "$CLIENT_CERT"
  chmod 600 "$CLIENT_KEY"
fi

if [ -n "$CA_CERT_SOURCE" ]; then
  CA_CERT="$TLS_DIR/server-ca.crt"
  cp "$CA_CERT_SOURCE" "$CA_CERT"
  chmod 644 "$CA_CERT"
fi

UPDATE_PUBLIC_KEY=""
if [ -n "$UPDATE_PUBLIC_KEY_SOURCE" ]; then
  UPDATE_PUBLIC_KEY="$UPDATE_TRUST_DIR/agent-update-public.pem"
  cp "$UPDATE_PUBLIC_KEY_SOURCE" "$UPDATE_PUBLIC_KEY"
  chmod 644 "$UPDATE_PUBLIC_KEY"
fi

python3 - "$CONFIG_DIR/agent.json" "$SERVER_URL" "$ENROLL" "$TAG" "$CA_CERT" "$CLIENT_CERT" "$CLIENT_KEY" "$UPDATE_PUBLIC_KEY" "$UPDATE_STAGING_DIR" <<'PY'
import json
import sys

path, server_url, enrollment, tag, ca_cert, client_cert, client_key, update_public_key, update_staging_dir = sys.argv[1:]
data = {
    "server_url": server_url,
    "enrollment_token": enrollment,
    "agent_id": "",
    "agent_token": "",
    "tags": [tag],
    "poll_seconds": 60,
    "scan_every_seconds": 1800,
    "tls_verify": True,
    "ca_cert": ca_cert,
    "client_cert": client_cert,
    "client_key": client_key,
    "update_public_key": update_public_key,
    "update_check_seconds": 21600,
    "update_staging_dir": update_staging_dir,
}
with open(path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, ensure_ascii=False, indent=2)
PY

chmod 600 "$CONFIG_DIR/agent.json"
unset ENROLL PATCH_ENROLLMENT_TOKEN PATCH_UPDATE_PUBLIC_KEY || true

cp "$(dirname "$0")/systemd/patch-manager-agent.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now patch-manager-agent
systemctl --no-pager status patch-manager-agent || true
