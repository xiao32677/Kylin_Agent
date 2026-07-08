#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${APP_DIR}"

mkdir -p data
echo "Demo-user update is file replacement only."
echo "If an old demo process is running, stop it with Ctrl+C in that terminal, then run:"
echo "  bash deploy/run_demo_user.sh"
