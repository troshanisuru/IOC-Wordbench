#!/usr/bin/env bash
# Builds and installs IOC Workbench desktop app on Linux
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

PYTHON_BIN="${PROJECT_ROOT}/.venv/bin/python"
if [[ ! -x "${PYTHON_BIN}" ]]; then
    python3 -m venv "${PROJECT_ROOT}/.venv"
    "${PROJECT_ROOT}/.venv/bin/pip" install -r requirements-dev.txt
fi

"${PYTHON_BIN}" installers/build_app.py

BIN_DIR="${HOME}/.local/bin"
APP_DIR="${HOME}/.local/share/applications"
mkdir -p "${BIN_DIR}" "${APP_DIR}"

install -m 0755 "dist/IOC-Workbench-Linux" "${BIN_DIR}/ioc-workbench"

cat > "${APP_DIR}/ioc-workbench.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=IOC Workbench
Comment=VirusTotal & AbuseIPDB Security Indicator Analyzer
Exec=${BIN_DIR}/ioc-workbench
Terminal=false
Categories=Security;Network;Utility;
EOF

chmod 0644 "${APP_DIR}/ioc-workbench.desktop"

echo ""
echo "=========================================================="
echo " IOC Workbench installed for Linux!"
echo " Executable:       ${BIN_DIR}/ioc-workbench"
echo " Desktop Entry:    ${APP_DIR}/ioc-workbench.desktop"
echo " Installer Tarball:${PROJECT_ROOT}/dist/IOC-Workbench-Linux-Installer.tar.gz"
echo "=========================================================="
