"""Unit tests for user account authentication and credential security."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock
import pytest

from vt_ioc_checker.auth import (
    authenticate_user_account,
    get_current_os_username,
    verify_system_password,
    _authenticate_macos_system_dialog,
)


def test_get_current_os_username() -> None:
    uname = get_current_os_username()
    assert isinstance(uname, str)
    assert len(uname) > 0


def test_verify_system_password_empty() -> None:
    assert not verify_system_password("any_user", "")


def test_verify_system_password_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    # Mock subprocess.run for macOS dscl / Linux sudo
    class MockCompletedProcess:
        def __init__(self, code: int):
            self.returncode = code
            self.stdout = ""
            self.stderr = ""

    monkeypatch.setattr(
        "subprocess.run",
        lambda cmd, **kwargs: MockCompletedProcess(0 if "correct_pass" in cmd or kwargs.get("input") == "correct_pass\n" else 10),
    )

    assert verify_system_password("testuser", "correct_pass")
    assert not verify_system_password("testuser", "wrong_pass")


def test_authenticate_macos_system_dialog_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    class MockCompletedProcess:
        def __init__(self, code: int, stderr: str = ""):
            self.returncode = code
            self.stdout = ""
            self.stderr = stderr

    # Success case
    monkeypatch.setattr("subprocess.run", lambda cmd, **kwargs: MockCompletedProcess(0))
    ok, msg = _authenticate_macos_system_dialog("test prompt")
    assert ok is True

    # User cancelled case
    monkeypatch.setattr("subprocess.run", lambda cmd, **kwargs: MockCompletedProcess(1, stderr="User canceled."))
    ok, msg = _authenticate_macos_system_dialog("test prompt")
    assert ok is False
    assert "cancelled" in msg.lower()

    # Generic error case
    monkeypatch.setattr("subprocess.run", lambda cmd, **kwargs: MockCompletedProcess(1, stderr="execution error"))
    ok, msg = _authenticate_macos_system_dialog("test prompt")
    assert ok is None


def test_authenticate_user_account_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    # Test when system auth succeeds
    monkeypatch.setattr(
        "vt_ioc_checker.auth._authenticate_macos_system_dialog",
        lambda prompt: (True, "Authenticated"),
    )
    ok, msg = authenticate_user_account("test")
    assert ok is True

    # Test when system auth is cancelled
    monkeypatch.setattr(
        "vt_ioc_checker.auth._authenticate_macos_system_dialog",
        lambda prompt: (False, "User cancelled."),
    )
    ok, msg = authenticate_user_account("test")
    assert ok is False
