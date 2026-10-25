"""Loads settings (API key, rate limit) from environment / .env."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path

from dotenv import dotenv_values

DEFAULT_REQUESTS_PER_MINUTE = 4
PLACEHOLDER_API_KEY = "your_virustotal_api_key_here"


class ConfigError(Exception):
    """Raised for any configuration loading or validation problem."""


@dataclass(frozen=True)
class Settings:
    """Application configuration settings."""

    api_key: str = field(repr=False)
    requests_per_minute: int


def load_settings(env_path: str | Path | None = None) -> Settings:
    """Loads and validates configuration from environment variables and an env file."""
    env_file = Path(env_path) if env_path is not None else Path.cwd() / ".env"
    file_values = (
        dotenv_values(env_file, encoding="utf-8-sig") if env_file.is_file() else {}
    )

    def _get(name: str) -> str:
        env_val = os.environ.get(name)
        if env_val is not None and env_val.strip():
            return env_val.strip()
        f_val = file_values.get(name)
        if f_val is not None and f_val.strip():
            return f_val.strip()
        return ""

    api_key = _get("VT_API_KEY")
    if not api_key:
        raise ConfigError(
            "VT_API_KEY is not set. Copy .env.example to .env and put your VirusTotal API key in it."
        )
    if api_key == PLACEHOLDER_API_KEY:
        raise ConfigError(
            "VT_API_KEY still has the placeholder value. Put your real VirusTotal API key in .env."
        )

    rpm_text = _get("VT_REQUESTS_PER_MINUTE")
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
