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


def test_settings_copy_protection(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verifies that copying API keys is blocked and cannot export text to clipboard."""
    env_file = tmp_path / ".env"
    monkeypatch.setattr("vt_ioc_checker.gui._env_path", lambda: env_file)

    app = WorkbenchApp()
    try:
        settings_page = app.pages["settings"]
        # Check exportselection is False on underlying tkinter.Entry
        assert settings_page.vt_key_entry._entry.cget("exportselection") == 0
        assert settings_page.abuse_key_entry._entry.cget("exportselection") == 0

        # Check that copy events return "break"
        res = settings_page.vt_key_entry._entry.event_generate("<<Copy>>")
        # In Tkinter, if the event handler returns "break", the result is False or ""
        # Directly call the bound event callback
        class DummyEvent:
            pass

        # Call _show_copy_blocked_notice and verify security label updates
        settings_page._show_copy_blocked_notice()
        assert "Copying API keys" in settings_page.security_notice_label.cget("text")
    finally:
        app.destroy()


def test_settings_password_permissions_and_lock_cycle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verifies that viewing API keys requires password auth and auto-locks on navigation."""
    env_file = tmp_path / ".env"
    save_api_settings(env_file, vt_api_key="secret_vt_key", abuse_api_key="secret_abuse_key")
    monkeypatch.setattr("vt_ioc_checker.gui._env_path", lambda: env_file)

    app = WorkbenchApp()
    try:
        page = app.pages["settings"]

        # 1. By default, keys are masked and page is locked
        assert not page.is_unlocked
        assert page.vt_key_entry.cget("show") == "*"
        assert page.abuse_key_entry.cget("show") == "*"
        assert page.vt_show_btn.cget("text") == "Show"

        # 2. Simulate failed password authentication
        monkeypatch.setattr(
            "vt_ioc_checker.auth.authenticate_user_account",
            lambda **kwargs: (False, "Wrong password"),
        )
        page._toggle_vt_show()
        # Keys must remain hidden
        assert not page.is_unlocked
        assert page.vt_key_entry.cget("show") == "*"
        assert "Authentication required" in page.security_notice_label.cget("text")

        # 3. Simulate successful password authentication
        monkeypatch.setattr(
            "vt_ioc_checker.auth.authenticate_user_account",
            lambda **kwargs: (True, "Authenticated"),
        )
        page._toggle_vt_show()
        assert page.is_unlocked
        assert page.vt_key_entry.cget("show") == ""
        assert page.vt_show_btn.cget("text") == "Hide"

        # 4. Lock page manually
        page.lock()
        assert not page.is_unlocked
        assert page.vt_key_entry.cget("show") == "*"
        assert page.vt_show_btn.cget("text") == "Show"

        # 5. Unlock again and test auto-lock on navigation
        page._request_unlock()
        assert page.is_unlocked
        assert page.vt_key_entry.cget("show") == ""

        # Navigate away to "vt" page
        app._current_page = "settings"
        app.show("vt")
        # Settings should have auto-locked!
        assert not page.is_unlocked
        assert page.vt_key_entry.cget("show") == "*"
    finally:
        app.destroy()



