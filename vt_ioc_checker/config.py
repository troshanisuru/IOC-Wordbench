"""Loads settings (API key, rate limit) from environment / .env."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path

from dotenv import dotenv_values

DEFAULT_REQUESTS_PER_MINUTE = 4
PLACEHOLDER_API_KEY = "your_virustotal_api_key_here"
DEFAULT_ABUSEIPDB_REQUESTS_PER_MINUTE = 60
PLACEHOLDER_ABUSEIPDB_API_KEY = "your_abuseipdb_api_key_here"


class ConfigError(Exception):
    """Raised for any configuration loading or validation problem."""


@dataclass(frozen=True)
class Settings:
    """Application configuration settings for VirusTotal."""

    api_key: str = field(repr=False)
    requests_per_minute: int


@dataclass(frozen=True)
class AbuseIPDBSettings:
    """Application configuration settings for AbuseIPDB."""

    api_key: str = field(repr=False)
    requests_per_minute: int


def _read_env_file(env_path: str | Path | None = None) -> dict[str, str | None]:
    """Reads key-value pairs from a .env file if it exists."""
    env_file = Path(env_path) if env_path is not None else Path.cwd() / ".env"
    if env_file.is_file():
        try:
            return dotenv_values(env_file, encoding="utf-8-sig")
        except (UnicodeDecodeError, OSError):
            raise ConfigError(
                "The .env file could not be read as UTF-8 text. Save it as UTF-8 (in Notepad: Save As, Encoding: UTF-8) and try again."
            ) from None
    return {}


def _lookup_setting(
    name: str, file_values: dict[str, str | None]
) -> str:
    """Returns a stripped setting value from environment variables or .env file."""
    env_val = os.environ.get(name)
    if env_val is not None and env_val.strip():
        return env_val.strip()
    f_val = file_values.get(name)
    if f_val is not None and f_val.strip():
        return f_val.strip()
    return ""


def load_settings(env_path: str | Path | None = None) -> Settings:
    """Loads and validates VirusTotal configuration from environment variables and an env file."""
    file_values = _read_env_file(env_path)

    api_key = _lookup_setting("VT_API_KEY", file_values)
    if not api_key:
        raise ConfigError(
            "VT_API_KEY is not set. Copy .env.example to .env and put your VirusTotal API key in it."
        )
    if api_key == PLACEHOLDER_API_KEY:
        raise ConfigError(
            "VT_API_KEY still has the placeholder value. Put your real VirusTotal API key in .env."
        )

    rpm_text = _lookup_setting("VT_REQUESTS_PER_MINUTE", file_values)
    if not rpm_text:
        rpm = DEFAULT_REQUESTS_PER_MINUTE
    else:
        try:
            rpm = int(rpm_text)
        except ValueError:
            raise ConfigError(
                f"VT_REQUESTS_PER_MINUTE must be a whole number, got '{rpm_text}'."
            )
        if rpm < 1 or rpm > 1000:
            raise ConfigError(
                "VT_REQUESTS_PER_MINUTE must be between 1 and 1000."
            )

    return Settings(api_key=api_key, requests_per_minute=rpm)


def load_abuseipdb_settings(
    env_path: str | Path | None = None,
) -> AbuseIPDBSettings:
    """Loads and validates AbuseIPDB configuration from environment variables and an env file."""
    file_values = _read_env_file(env_path)

    api_key = _lookup_setting("ABUSEIPDB_API_KEY", file_values)
    if not api_key:
        raise ConfigError(
            "ABUSEIPDB_API_KEY is not set. Copy .env.example to .env and put your AbuseIPDB API key in it."
        )
    if api_key == PLACEHOLDER_ABUSEIPDB_API_KEY:
        raise ConfigError(
            "ABUSEIPDB_API_KEY still has the placeholder value. Put your real AbuseIPDB API key in .env."
        )

    rpm_text = _lookup_setting("ABUSEIPDB_REQUESTS_PER_MINUTE", file_values)
    if not rpm_text:
        rpm = DEFAULT_ABUSEIPDB_REQUESTS_PER_MINUTE
    else:
        try:
            rpm = int(rpm_text)
        except ValueError:
            raise ConfigError(
                f"ABUSEIPDB_REQUESTS_PER_MINUTE must be a whole number, got '{rpm_text}'."
            )
        if rpm < 1 or rpm > 1000:
            raise ConfigError(
                "ABUSEIPDB_REQUESTS_PER_MINUTE must be between 1 and 1000."
            )

    return AbuseIPDBSettings(api_key=api_key, requests_per_minute=rpm)
