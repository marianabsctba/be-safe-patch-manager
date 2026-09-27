#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
  echo "Uso: sudo $0 https://patch.exemplo [tag]"
  echo "Opcional para automação: defina PATCH_ENROLLMENT_TOKEN no ambiente."
  exit 1
fi

SERVER_URL="$1"
TAG="${2:-piloto}"

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

BASE=/opt/patch-manager-agent
mkdir -p "$BASE" /etc/patch-manager
cp "$(dirname "$0")/../agent/patch_agent.py" "$BASE/patch_agent.py"
cp "$(dirname "$0")/../agent/requirements.txt" "$BASE/requirements.txt"
python3 -m venv "$BASE/.venv"
"$BASE/.venv/bin/pip" install -r "$BASE/requirements.txt"
cat > /etc/patch-manager/agent.json <<JSON
{
  "server_url": "$SERVER_URL",
  "enrollment_token": "$ENROLL",
  "agent_id": "",
  "agent_token": "",
  "tags": ["$TAG"],
  "poll_seconds": 60,
  "scan_every_seconds": 1800,
  "tls_verify": true
}
JSON
chmod 600 /etc/patch-manager/agent.json
unset ENROLL PATCH_ENROLLMENT_TOKEN || true
cp "$(dirname "$0")/systemd/patch-manager-agent.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now patch-manager-agent
systemctl --no-pager status patch-manager-agent || true
