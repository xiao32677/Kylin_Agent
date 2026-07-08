#!/usr/bin/env bash
set -euo pipefail

APP_NAME="a2-secops-agent"
APP_DIR="/opt/${APP_NAME}"
SERVICE_NAME="${APP_NAME}.service"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run with sudo: sudo bash deploy/update_local.sh" >&2
  exit 1
fi

if [[ ! -d "${APP_DIR}" ]]; then
  echo "${APP_DIR} does not exist. Run sudo bash deploy/install_kylin.sh first." >&2
  exit 1
fi

stamp="$(date +%Y%m%d%H%M%S)"
backup_dir="/opt/${APP_NAME}-backup-${stamp}"
mkdir -p "${backup_dir}"

for item in backend frontend tests README.md; do
  if [[ -e "${APP_DIR}/${item}" ]]; then
    cp -a "${APP_DIR}/${item}" "${backup_dir}/"
  fi
done

systemctl stop "${SERVICE_NAME}" || true

rm -rf "${APP_DIR}/backend" "${APP_DIR}/frontend" "${APP_DIR}/tests" "${APP_DIR}/README.md"
cp -a "${SOURCE_DIR}/backend" "${APP_DIR}/backend"
cp -a "${SOURCE_DIR}/frontend" "${APP_DIR}/frontend"
cp -a "${SOURCE_DIR}/tests" "${APP_DIR}/tests"
cp -a "${SOURCE_DIR}/README.md" "${APP_DIR}/README.md"

chown -R root:ops-agent "${APP_DIR}/backend" "${APP_DIR}/frontend" "${APP_DIR}/tests" "${APP_DIR}/README.md"
find "${APP_DIR}/backend" "${APP_DIR}/frontend" "${APP_DIR}/tests" -type d -exec chmod 0750 {} +
find "${APP_DIR}/backend" "${APP_DIR}/frontend" "${APP_DIR}/tests" -type f -exec chmod 0640 {} +
chmod 0640 "${APP_DIR}/README.md"

install -m 0640 -o root -g root "${SOURCE_DIR}/deploy/sudoers/${APP_NAME}" "/etc/sudoers.d/${APP_NAME}"
visudo -cf "/etc/sudoers.d/${APP_NAME}" >/dev/null
install -m 0644 -o root -g root "${SOURCE_DIR}/deploy/systemd/${APP_NAME}.service" "/etc/systemd/system/${SERVICE_NAME}"

systemctl daemon-reload
systemctl restart "${SERVICE_NAME}"
systemctl --no-pager --full status "${SERVICE_NAME}" || true

echo "Update complete. Backup: ${backup_dir}"
