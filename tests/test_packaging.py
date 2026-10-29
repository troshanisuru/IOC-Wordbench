"""Unit tests for cross-platform desktop packaging and installer builder."""

from __future__ import annotations

from pathlib import Path
import pytest

from installers import build_app


def test_common_pyinstaller_args() -> None:
    args = build_app._common_pyinstaller_args()
    assert "--windowed" in args
    assert "customtkinter" in args
    assert any("sample_iocs.txt" in a for a in args)


def test_build_windows_invokes_onefile_exe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called_args: list[str] = []
    monkeypatch.setattr(build_app, "DIST_DIR", tmp_path / "dist")
    monkeypatch.setattr(build_app, "BUILD_DIR", tmp_path / "build")
    monkeypatch.setattr(
        "PyInstaller.__main__.run", lambda args: called_args.extend(args)
    )

    build_app.build_windows()
    assert "--onefile" in called_args
    assert "IOC-Workbench" in called_args


def test_build_linux_creates_tar_installer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dist_dir = tmp_path / "dist"
    build_dir = tmp_path / "build"
    dist_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(build_app, "DIST_DIR", dist_dir)
    monkeypatch.setattr(build_app, "BUILD_DIR", build_dir)

    def _fake_pyinstaller(args: list[str]) -> None:
        (dist_dir / "IOC-Workbench-Linux").write_text("#!/bin/sh\n", encoding="utf-8")

    monkeypatch.setattr("PyInstaller.__main__.run", _fake_pyinstaller)

    build_app.build_linux()
    assert (dist_dir / "IOC-Workbench-Linux").is_file()
    assert (dist_dir / "IOC-Workbench-Linux-Installer.tar.gz").is_file()
