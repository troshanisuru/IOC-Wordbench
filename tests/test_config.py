"""Unit tests for configuration loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from vt_ioc_checker.config import ConfigError, load_settings


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensures environment variables do not leak into tests."""
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("VT_REQUESTS_PER_MINUTE", raising=False)


def test_t1_valid_file(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_bytes("VT_API_KEY=abc123\nVT_REQUESTS_PER_MINUTE=10\n".encode("utf-8"))
    settings = load_settings(env_file)
    assert settings.api_key == "abc123"
    assert settings.requests_per_minute == 10


def test_t2_bom_crlf(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_bytes("\ufeffVT_API_KEY=abc123\r\n".encode("utf-8"))
    settings = load_settings(env_file)
    assert settings.api_key == "abc123"
    assert settings.requests_per_minute == 4


def test_t3_env_var_wins_over_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_bytes("VT_API_KEY=fromfile\n".encode("utf-8"))
    monkeypatch.setenv("VT_API_KEY", "fromenv")
    settings = load_settings(env_file)
    assert settings.api_key == "fromenv"


def test_t4_env_var_set_file_not_exist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VT_API_KEY", "fromenv")
    settings = load_settings(tmp_path / "does_not_exist.env")
    assert settings.api_key == "fromenv"


def test_t5_no_env_no_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ConfigError, match="VT_API_KEY is not set"):
        load_settings(tmp_path / "does_not_exist.env")
    with pytest.raises(ConfigError, match="VT_API_KEY is not set"):
        load_settings()


def test_t6_placeholder_api_key(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_bytes("VT_API_KEY=your_virustotal_api_key_here\n".encode("utf-8"))
    with pytest.raises(ConfigError, match="placeholder"):
        load_settings(env_file)


@pytest.mark.parametrize(
    ("rpm_val", "expected_match"),
    [
        ("abc", "whole number"),
        ("4.5", "whole number"),
        ("0", "between 1 and 1000"),
        ("1001", "between 1 and 1000"),
        ("-5", "between 1 and 1000"),
    ],
)
def test_t7_invalid_requests_per_minute(
    tmp_path: Path, rpm_val: str, expected_match: str
) -> None:
    env_file = tmp_path / ".env"
    content = f"VT_API_KEY=abc123\nVT_REQUESTS_PER_MINUTE={rpm_val}\n"
    env_file.write_bytes(content.encode("utf-8"))
    with pytest.raises(ConfigError, match=expected_match):
        load_settings(env_file)


def test_t8_secrets_never_leak(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_bytes(
        "VT_API_KEY=supersecretkey123\nVT_REQUESTS_PER_MINUTE=abc\n".encode("utf-8")
    )
    with pytest.raises(ConfigError) as exc_info:
        load_settings(env_file)
    assert "supersecretkey123" not in str(exc_info.value)

    env_file_valid = tmp_path / ".env_valid"
    env_file_valid.write_bytes("VT_API_KEY=supersecretkey123\n".encode("utf-8"))
    settings = load_settings(env_file_valid)
    assert "supersecretkey123" not in repr(settings)
    assert "supersecretkey123" not in str(settings)


def test_t9_double_quotes(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_bytes('VT_API_KEY="abc123"\n'.encode("utf-8"))
    settings = load_settings(env_file)
    assert settings.api_key == "abc123"


def test_t10_empty_value(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_bytes("VT_API_KEY=\n".encode("utf-8"))
    with pytest.raises(ConfigError, match="VT_API_KEY is not set"):
        load_settings(env_file)


def test_t11_default_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_bytes("VT_API_KEY=abc123\n".encode("utf-8"))
    settings = load_settings()
    assert settings.api_key == "abc123"


def test_t12_env_var_with_spaces(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("VT_API_KEY", "  abc123  ")
    settings = load_settings(tmp_path / "does_not_exist.env")
    assert settings.api_key == "abc123"


def test_get_and_save_api_settings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env_file = tmp_path / ".env"
    from vt_ioc_checker.config import get_api_settings_raw, save_api_settings

    # Initial empty
    data = get_api_settings_raw(env_file)
    assert data["vt_status"] == "Not configured"
    assert data["abuse_status"] == "Not configured"

    # Save VT and Abuse
    save_api_settings(
        env_file,
        vt_api_key="new_vt_key",
        vt_rpm=10,
        abuse_api_key="new_abuse_key",
        abuse_rpm=90,
    )

    data2 = get_api_settings_raw(env_file)
    assert data2["vt_api_key"] == "new_vt_key"
    assert data2["vt_rpm"] == 10
    assert data2["vt_status"] == "Ready"
    assert data2["abuse_api_key"] == "new_abuse_key"
    assert data2["abuse_rpm"] == 90
    assert data2["abuse_status"] == "Ready"


def test_test_api_connections_mocked(monkeypatch: pytest.MonkeyPatch) -> None:
    from vt_ioc_checker.config import test_abuseipdb_api_connection, test_vt_api_connection

    # Test empty or placeholder
    ok, msg = test_vt_api_connection("")
    assert not ok
    assert "empty" in msg

    ok, msg = test_abuseipdb_api_connection("your_abuseipdb_api_key_here")
    assert not ok
    assert "placeholder" in msg

    # Mock success
    class MockResp:
        def __init__(self, code):
            self.status_code = code

    monkeypatch.setattr("requests.get", lambda url, headers, timeout: MockResp(200))
    ok, msg = test_vt_api_connection("valid_key")
    assert ok
    assert "valid" in msg.lower()

    ok, msg = test_abuseipdb_api_connection("valid_key")
    assert ok
    assert "valid" in msg.lower()


def test_security_hardening_env_permissions_and_newline_injection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import os
    import stat
    from vt_ioc_checker.config import (
        save_api_settings,
        test_abuseipdb_api_connection,
        test_vt_api_connection,
    )
    from vt_ioc_checker.vt_client import build_analysis_url

    env_file = tmp_path / ".env"

    with pytest.raises(ValueError, match="newline"):
        save_api_settings(env_file, vt_api_key="bad_key\nINJECTED=1")

    with pytest.raises(ValueError, match="newline"):
        save_api_settings(env_file, abuse_api_key="bad_key\r\nINJECTED=1")

    ok, msg = test_vt_api_connection("bad\nkey")
    assert not ok
    assert "control characters" in msg

    ok, msg = test_abuseipdb_api_connection("bad\rkey")
    assert not ok
    assert "control characters" in msg

    save_api_settings(env_file, vt_api_key="safe_vt_key")
    if os.name == "posix":
        mode = stat.S_IMODE(env_file.stat().st_mode)
        assert mode == 0o600

    # Verify build_analysis_url rejects path traversal and query injection
    with pytest.raises(ValueError, match="Invalid analysis_id"):
        build_analysis_url("../ip_addresses/1.2.3.4?foo=bar")
    with pytest.raises(ValueError, match="Invalid analysis_id"):
        build_analysis_url("abc?foo=bar")
    assert build_analysis_url("u-12345-67890") == "https://www.virustotal.com/api/v3/analyses/u-12345-67890"



