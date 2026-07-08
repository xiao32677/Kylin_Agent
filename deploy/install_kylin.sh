#!/usr/bin/env bash
set -euo pipefail

APP_NAME="a2-secops-agent"
APP_USER="ops-agent"
APP_GROUP="ops-agent"
APP_DIR="/opt/${APP_NAME}"
CONF_DIR="/etc/${APP_NAME}"
ENV_FILE="${CONF_DIR}/${APP_NAME}.env"
RULES_FILE="${CONF_DIR}/security_rules.json"
SERVICE_FILE="/etc/systemd/system/${APP_NAME}.service"
SUDOERS_FILE="/etc/sudoers.d/${APP_NAME}"
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

ensure_env_var() {
  local key="$1"
  local value="$2"
  if ! grep -Eq "^[[:space:]]*(export[[:space:]]+)?${key}=" "${ENV_FILE}" 2>/dev/null; then
    printf "%s='%s'\n" "${key}" "${value}" >> "${ENV_FILE}"
  fi
}

normalize_env_file() {
  local tmp_file
  tmp_file="$(mktemp)"
  sed -E 's/^[[:space:]]*export[[:space:]]+//' "${ENV_FILE}" > "${tmp_file}"
  install -m 0640 -o root -g "${APP_GROUP}" "${tmp_file}" "${ENV_FILE}"
  rm -f "${tmp_file}"
}

if [[ "${EUID}" -ne 0 ]]; then
  echo "请用 root 运行：sudo bash deploy/install_kylin.sh" >&2
  exit 1
fi

if ! getent group "${APP_GROUP}" >/dev/null; then
  groupadd --system "${APP_GROUP}"
fi

if ! id "${APP_USER}" >/dev/null 2>&1; then
  useradd --system --gid "${APP_GROUP}" --home-dir "/var/lib/${APP_NAME}" --create-home --shell /usr/sbin/nologin "${APP_USER}"
fi

install -d -m 0750 -o root -g "${APP_GROUP}" "${APP_DIR}"
install -d -m 0750 -o "${APP_USER}" -g "${APP_GROUP}" "${APP_DIR}/data"
install -d -m 0750 -o root -g "${APP_GROUP}" "${CONF_DIR}"

rm -rf "${APP_DIR}/backend" "${APP_DIR}/frontend" "${APP_DIR}/tests" "${APP_DIR}/README.md"
cp -a "${SOURCE_DIR}/backend" "${APP_DIR}/backend"
cp -a "${SOURCE_DIR}/frontend" "${APP_DIR}/frontend"
cp -a "${SOURCE_DIR}/tests" "${APP_DIR}/tests"
cp -a "${SOURCE_DIR}/README.md" "${APP_DIR}/README.md"
chown -R root:"${APP_GROUP}" "${APP_DIR}/backend" "${APP_DIR}/frontend" "${APP_DIR}/tests" "${APP_DIR}/README.md"
find "${APP_DIR}/backend" "${APP_DIR}/frontend" "${APP_DIR}/tests" -type d -exec chmod 0750 {} +
find "${APP_DIR}/backend" "${APP_DIR}/frontend" "${APP_DIR}/tests" -type f -exec chmod 0640 {} +
chmod 0640 "${APP_DIR}/README.md"
chown -R "${APP_USER}:${APP_GROUP}" "${APP_DIR}/data"

if [[ ! -f "${ENV_FILE}" ]]; then
  if [[ -f "/home/xiao/.a2-secops-agent.env" ]]; then
    install -m 0640 -o root -g "${APP_GROUP}" "/home/xiao/.a2-secops-agent.env" "${ENV_FILE}"
  else
    cat > "${ENV_FILE}" <<'EOF'
DEEPSEEK_API_KEY=''
DEEPSEEK_BASE_URL='https://api.deepseek.com'
DEEPSEEK_MODEL='deepseek-v4-flash'
EOF
    {
      printf "A2_ADMIN_USER='%s'\n" "${A2_ADMIN_USER:-admin}"
      printf "A2_ADMIN_PASSWORD='%s'\n" "${A2_ADMIN_PASSWORD:-a2admin123}"
    } >> "${ENV_FILE}"
    chown root:"${APP_GROUP}" "${ENV_FILE}"
    chmod 0640 "${ENV_FILE}"
  fi
fi
normalize_env_file
ensure_env_var "A2_OPERATOR_USER" "operator"
ensure_env_var "A2_OPERATOR_PASSWORD" "a2operator123"
ensure_env_var "A2_AUDITOR_USER" "auditor"
ensure_env_var "A2_AUDITOR_PASSWORD" "a2auditor123"
ensure_env_var "A2_DESKTOP_OWNER" "xiao"
ensure_env_var "A2_RULES_FILE" "${RULES_FILE}"
normalize_env_file

if [[ ! -f "${RULES_FILE}" ]]; then
  install -m 0640 -o root -g "${APP_GROUP}" "${SOURCE_DIR}/deploy/security_rules.json" "${RULES_FILE}"
fi

install -m 0640 -o root -g root "${SOURCE_DIR}/deploy/sudoers/${APP_NAME}" "${SUDOERS_FILE}"
visudo -cf "${SUDOERS_FILE}" >/dev/null

install -m 0644 -o root -g root "${SOURCE_DIR}/deploy/systemd/${APP_NAME}.service" "${SERVICE_FILE}"

for desktop in /home/xiao/桌面 /home/xiao/Desktop; do
  if [[ -d "${desktop}" ]]; then
    if command -v setfacl >/dev/null 2>&1; then
      setfacl -m "u:${APP_USER}:x" /home/xiao || true
      setfacl -m "u:${APP_USER}:rwx" -m "d:u:${APP_USER}:rwx" "${desktop}" || true
    fi
  fi
done

pkill -u xiao -f "${APP_NAME}/backend/app/main.py" || true
pkill -u xiao -f "python3 backend/app/main.py" || true

systemctl daemon-reload
systemctl enable "${APP_NAME}.service"
systemctl restart "${APP_NAME}.service"
systemctl --no-pager --full status "${APP_NAME}.service" || true

echo "安装完成："
echo "  服务: systemctl status ${APP_NAME}"
echo "  地址: http://<服务器IP>:8765"
echo "  默认登录: ${A2_ADMIN_USER:-admin} / ${A2_ADMIN_PASSWORD:-a2admin123}"
echo "  正式部署请在 ${ENV_FILE} 中修改 A2_ADMIN_PASSWORD、A2_OPERATOR_PASSWORD 和 A2_AUDITOR_PASSWORD 后重启服务"
