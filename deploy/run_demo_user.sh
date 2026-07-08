#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${APP_DIR}"

export A2_HOST="${A2_HOST:-127.0.0.1}"
export A2_PORT="${A2_PORT:-8765}"
export A2_RULES_FILE="${A2_RULES_FILE:-${APP_DIR}/deploy/security_rules.json}"
export A2_ADMIN_USER="${A2_ADMIN_USER:-admin}"
export A2_ADMIN_PASSWORD="${A2_ADMIN_PASSWORD:-a2admin123}"
export A2_OPERATOR_USER="${A2_OPERATOR_USER:-operator}"
export A2_OPERATOR_PASSWORD="${A2_OPERATOR_PASSWORD:-a2operator123}"
export A2_AUDITOR_USER="${A2_AUDITOR_USER:-auditor}"
export A2_AUDITOR_PASSWORD="${A2_AUDITOR_PASSWORD:-a2auditor123}"

mkdir -p data

echo "Starting A2 SecOps Agent demo mode..."
echo "URL: http://${A2_HOST}:${A2_PORT}"
echo "Login: admin / ${A2_ADMIN_PASSWORD}"
echo
python3 backend/app/main.py
