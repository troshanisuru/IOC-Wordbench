#!/usr/bin/env bash
# Builds and installs IOC Workbench.app on macOS (plus creates the .dmg installer)
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${PROJECT_ROOT}"

PYTHON_BIN="${PROJECT_ROOT}/.venv/bin/python"
if [[ ! -x "${PYTHON_BIN}" ]]; then
    python3 -m venv "${PROJECT_ROOT}/.venv"
    "${PROJECT_ROOT}/.venv/bin/pip" install -r requirements-dev.txt
fi

"${PYTHON_BIN}" installers/build_app.py

INSTALL_DIR="/Applications"
if [[ ! -w "${INSTALL_DIR}" ]]; then
    INSTALL_DIR="${HOME}/Applications"
    mkdir -p "${INSTALL_DIR}"
fi

rm -rf "${INSTALL_DIR}/IOC Workbench.app"
cp -R "dist/IOC Workbench.app" "${INSTALL_DIR}/IOC Workbench.app"

echo ""
echo "=========================================================="
echo " IOC Workbench installed to: ${INSTALL_DIR}/IOC Workbench.app"
echo " ZIP Installer ready at:     ${PROJECT_ROOT}/dist/IOC-Workbench-macOS-Installer.zip"
echo "=========================================================="
