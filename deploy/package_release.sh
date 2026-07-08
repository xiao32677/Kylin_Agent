#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-$(date +%Y%m%d-%H%M%S)}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${PROJECT_ROOT}/dist"
STAGE_DIR="${DIST_DIR}/a2-secops-agent"
ZIP_PATH="${DIST_DIR}/a2-secops-agent-release-${VERSION}.zip"

rm -rf "${STAGE_DIR}"
mkdir -p "${STAGE_DIR}" "${DIST_DIR}"

for item in backend frontend deploy tests README.md OFFLINE_DEPLOY.md .env.example; do
  if [[ -e "${PROJECT_ROOT}/${item}" ]]; then
    cp -a "${PROJECT_ROOT}/${item}" "${STAGE_DIR}/"
  fi
done

find "${STAGE_DIR}" -type d -name "__pycache__" -prune -exec rm -rf {} +
find "${STAGE_DIR}" -type f \( -name "*.pyc" -o -name ".DS_Store" -o -name "Thumbs.db" \) -delete
rm -rf "${STAGE_DIR}/dist"
rm -f "${STAGE_DIR}/data/a2_agent.sqlite3" "${STAGE_DIR}/data/audit_events.jsonl"

if command -v zip >/dev/null 2>&1; then
  (cd "${DIST_DIR}" && zip -qr "${ZIP_PATH}" a2-secops-agent)
else
  tar -C "${DIST_DIR}" -czf "${ZIP_PATH%.zip}.tar.gz" a2-secops-agent
  echo "zip not found, created ${ZIP_PATH%.zip}.tar.gz"
  exit 0
fi

echo "Release package created: ${ZIP_PATH}"
