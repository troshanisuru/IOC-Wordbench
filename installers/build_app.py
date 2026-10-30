#!/usr/bin/env python3
"""Cross-platform standalone application & installer builder for IOC Workbench.

Produces:
- macOS:   dist/IOC Workbench.app  +  dist/IOC-Workbench-macOS-Installer.dmg
- Windows: dist/IOC-Workbench.exe  (single-file standalone GUI executable)
- Linux:   dist/IOC-Workbench-Linux + dist/IOC-Workbench-Linux-Installer.tar.gz
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = PROJECT_ROOT / "dist"
BUILD_DIR = PROJECT_ROOT / "build"
ASSETS_DIR = PROJECT_ROOT / "assets"
ENTRYPOINT = PROJECT_ROOT / "run_desktop_app.py"
SAMPLE_FILE = PROJECT_ROOT / "data" / "input" / "sample_iocs.txt"

os.environ.setdefault("PYINSTALLER_CONFIG_DIR", str(BUILD_DIR / ".pyinstaller_cache"))

import PyInstaller.__main__


def _ensure_icons() -> None:
    """Ensures icon assets exist, generating them if missing."""
    icon_png = ASSETS_DIR / "icon.png"
    if not icon_png.is_file():
        from installers.generate_icon import main as gen_icons

        gen_icons()


def _clean_previous() -> None:
    """Removes previous PyInstaller build and dist directories."""
    for folder in (BUILD_DIR, DIST_DIR):
        if folder.exists():
            shutil.rmtree(folder)


def _common_pyinstaller_args() -> list[str]:
    """Returns PyInstaller arguments shared across macOS, Linux, and Windows."""
    _ensure_icons()
    args = [
        str(ENTRYPOINT),
        "--noconfirm",
        "--clean",
        "--windowed",
        "--collect-all",
        "customtkinter",
        "--distpath",
        str(DIST_DIR),
        "--workpath",
        str(BUILD_DIR),
        "--specpath",
        str(BUILD_DIR),
        "--exclude-module",
        "pytest",
        "--exclude-module",
        "pandas",
        "--exclude-module",
        "numpy",
    ]
    sep = ";" if sys.platform.startswith("win") else ":"
    if SAMPLE_FILE.is_file():
        args.extend(["--add-data", f"{SAMPLE_FILE}{sep}data/input"])
    if (ASSETS_DIR / "icon.png").is_file():
        args.extend(["--add-data", f"{ASSETS_DIR}{sep}assets"])
    return args


def build_macos() -> None:
    """Builds the macOS .app bundle and packages a drag-and-drop .dmg installer."""
    print("[1/2] Building macOS Application Bundle (IOC Workbench.app)...")
    args = _common_pyinstaller_args() + [
        "--onedir",
        "--name",
        "IOC Workbench",
        "--osx-bundle-identifier",
        "com.vtiocchecker.workbench",
    ]
    icon_icns = ASSETS_DIR / "icon.icns"
    if icon_icns.is_file():
        args.extend(["--icon", str(icon_icns)])
    PyInstaller.__main__.run(args)

    app_path = DIST_DIR / "IOC Workbench.app"
    if not app_path.exists():
        raise RuntimeError(f"Expected macOS app bundle not found at {app_path}")

    print("[2/2] Packaging macOS Installers (.zip & .dmg)...")
    zip_path = DIST_DIR / "IOC-Workbench-macOS-Installer.zip"
    if zip_path.exists():
        zip_path.unlink()
    subprocess.run(
        [
            "ditto",
            "-c",
            "-k",
            "--sequesterRsrc",
            "--keepParent",
            str(app_path),
            str(zip_path),
        ],
        check=True,
    )

    dmg_path = DIST_DIR / "IOC-Workbench-macOS-Installer.dmg"
    if dmg_path.exists():
        dmg_path.unlink()

    dmg_created = False
    try:
        subprocess.run(
            [
                "hdiutil",
                "create",
                "-volname",
                "IOC Workbench Installer",
                "-srcfolder",
                str(app_path),
                "-ov",
                "-format",
                "UDZO",
                str(dmg_path),
            ],
            check=True,
            capture_output=True,
        )
        dmg_created = dmg_path.is_file()
    except (subprocess.CalledProcessError, OSError):
        dmg_created = False

    print(f"\nSuccess! Built macOS installation packages:\n  - App Bundle:    {app_path}\n  - ZIP Installer: {zip_path}")
    if dmg_created:
        print(f"  - DMG Installer: {dmg_path}")


def build_windows() -> None:
    """Builds a standalone single-file Windows .exe executable."""
    print("[1/1] Building standalone Windows executable (IOC-Workbench.exe)...")
    args = _common_pyinstaller_args() + [
        "--onefile",
        "--name",
        "IOC-Workbench",
    ]
    icon_ico = ASSETS_DIR / "icon.ico"
    if icon_ico.is_file():
        args.extend(["--icon", str(icon_ico)])
    PyInstaller.__main__.run(args)
    exe_path = DIST_DIR / "IOC-Workbench.exe"
    print(f"\nSuccess! Built standalone Windows executable:\n  - {exe_path}")


def build_linux() -> None:
    """Builds a standalone Linux executable and packages a desktop installer archive."""
    print("[1/2] Building standalone Linux executable (IOC-Workbench-Linux)...")
    args = _common_pyinstaller_args() + [
        "--onefile",
        "--name",
        "IOC-Workbench-Linux",
    ]
    icon_png = ASSETS_DIR / "icon.png"
    if icon_png.is_file():
        args.extend(["--icon", str(icon_png)])
    PyInstaller.__main__.run(args)

    bin_path = DIST_DIR / "IOC-Workbench-Linux"
    if not bin_path.exists():
        raise RuntimeError(f"Expected Linux binary not found at {bin_path}")
    bin_path.chmod(0o755)

    print("[2/2] Packaging Linux Desktop Installer (IOC-Workbench-Linux-Installer.tar.gz)...")
    staging = BUILD_DIR / "linux_installer"
    if staging.exists():
        shutil.rmtree(staging)
    staging.mkdir(parents=True, exist_ok=True)

    shutil.copy2(bin_path, staging / "IOC-Workbench-Linux")
    if icon_png.is_file():
        shutil.copy2(icon_png, staging / "ioc-workbench.png")

    install_script = staging / "install.sh"
    install_script.write_text(
        """#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_DIR="${HOME}/.local/bin"
APP_DIR="${HOME}/.local/share/applications"
ICON_DIR="${HOME}/.local/share/icons/hicolor/256x256/apps"

mkdir -p "${BIN_DIR}" "${APP_DIR}" "${ICON_DIR}"
install -m 0755 "${SCRIPT_DIR}/IOC-Workbench-Linux" "${BIN_DIR}/ioc-workbench"
if [ -f "${SCRIPT_DIR}/ioc-workbench.png" ]; then
    install -m 0644 "${SCRIPT_DIR}/ioc-workbench.png" "${ICON_DIR}/ioc-workbench.png"
fi

cat > "${APP_DIR}/ioc-workbench.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=IOC Workbench
Comment=VirusTotal & AbuseIPDB Security Indicator Analyzer
Exec=${BIN_DIR}/ioc-workbench
Icon=ioc-workbench
Terminal=false
Categories=Security;Network;Utility;
EOF

chmod 0644 "${APP_DIR}/ioc-workbench.desktop"
echo "IOC Workbench installed successfully!"
echo "  Executable: ${BIN_DIR}/ioc-workbench"
echo "  Desktop Launcher: ${APP_DIR}/ioc-workbench.desktop"
""",
        encoding="utf-8",
    )
    install_script.chmod(0o755)

    tar_path = DIST_DIR / "IOC-Workbench-Linux-Installer.tar.gz"
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(staging, arcname="IOC-Workbench-Linux-Installer")

    print(
        f"\nSuccess! Built Linux packages:\n  - Executable: {bin_path}\n  - Installer Archive: {tar_path}"
    )


def main() -> int:
    _clean_previous()
    if sys.platform == "darwin":
        build_macos()
    elif sys.platform.startswith("win"):
        build_windows()
    elif sys.platform.startswith("linux"):
        build_linux()
    else:
        print(f"Unsupported platform '{sys.platform}', running generic onefile build...")
        args = _common_pyinstaller_args() + ["--onefile", "--name", "IOC-Workbench"]
        PyInstaller.__main__.run(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
