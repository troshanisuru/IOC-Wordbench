"""Unit tests for the desktop API settings page and configuration workflow."""

from __future__ import annotations

from pathlib import Path
import pytest

from vt_ioc_checker.config import get_api_settings_raw, save_api_settings
from vt_ioc_checker.gui import WorkbenchApp


def test_settings_page_instantiation_and_load(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies that SettingsPage initializes properly and populates fields from .env."""
    env_file = tmp_path / ".env"
    save_api_settings(
        env_file,
        vt_api_key="vt_test_key_12345",
        vt_rpm=15,
        abuse_api_key="abuse_test_key_67890",
        abuse_rpm=120,
    )
    monkeypatch.setattr("vt_ioc_checker.gui._env_path", lambda: env_file)

    # Instantiate the application off-screen
    app = WorkbenchApp()
    try:
        assert "settings" in app.pages
        settings_page = app.pages["settings"]

        # Check that settings page values match the env file
        assert settings_page.vt_key_var.get() == "vt_test_key_12345"
        assert settings_page.vt_rpm_var.get() == "15"
        assert settings_page.abuse_key_var.get() == "abuse_test_key_67890"
        assert settings_page.abuse_rpm_var.get() == "120"

        # Check navigation
        app.show("settings")
        assert app.nav["settings"].cget("fg_color") == "#2563EB"
    finally:
        app.destroy()


def test_app_close_button_handler(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies that clicking the close / cut window button invokes _close without AttributeError."""
    env_file = tmp_path / ".env"
    monkeypatch.setattr("vt_ioc_checker.gui._env_path", lambda: env_file)

    app = WorkbenchApp()
    # Trigger the WM_DELETE_WINDOW close handler directly
    app._close()


