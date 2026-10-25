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
