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


def _load_service_settings(
    prefix: str,
    default_rpm: int,
    placeholder_key: str,
    cls: type[Any],
    env_path: str | Path | None = None,
) -> Any:
    file_values = _read_env_file(env_path)
    service_name = "VirusTotal" if prefix == "VT" else "AbuseIPDB"
    key_name = f"{prefix}_API_KEY"
    rpm_name = f"{prefix}_REQUESTS_PER_MINUTE"

    api_key = _lookup_setting(key_name, file_values)
    if not api_key:
        raise ConfigError(
            f"{key_name} is not set. Copy .env.example to .env and put your {service_name} API key in it."
        )
    if api_key == placeholder_key:
        raise ConfigError(
            f"{key_name} still has the placeholder value. Put your real {service_name} API key in .env."
        )

    rpm_text = _lookup_setting(rpm_name, file_values)
    if not rpm_text:
        rpm = default_rpm
    else:
        try:
            rpm = int(rpm_text)
        except ValueError:
            raise ConfigError(
                f"{rpm_name} must be a whole number, got '{rpm_text}'."
            )
        if rpm < 1 or rpm > 1000:
            raise ConfigError(
                f"{rpm_name} must be between 1 and 1000."
            )

    return cls(api_key=api_key, requests_per_minute=rpm)


def load_settings(env_path: str | Path | None = None) -> Settings:
    """Loads and validates VirusTotal configuration from environment variables and an env file."""
    return _load_service_settings(
        prefix="VT",
        default_rpm=DEFAULT_REQUESTS_PER_MINUTE,
        placeholder_key=PLACEHOLDER_API_KEY,
        cls=Settings,
        env_path=env_path,
    )


def load_abuseipdb_settings(
    env_path: str | Path | None = None,
) -> AbuseIPDBSettings:
    """Loads and validates AbuseIPDB configuration from environment variables and an env file."""
    return _load_service_settings(
        prefix="ABUSEIPDB",
        default_rpm=DEFAULT_ABUSEIPDB_REQUESTS_PER_MINUTE,
        placeholder_key=PLACEHOLDER_ABUSEIPDB_API_KEY,
        cls=AbuseIPDBSettings,
        env_path=env_path,
    )


def get_api_settings_raw(env_path: str | Path | None = None) -> dict[str, Any]:
    """Reads the raw configured API settings without raising ConfigError on missing keys."""
    file_values = _read_env_file(env_path)
    vt_key = _lookup_setting("VT_API_KEY", file_values)
    vt_rpm = _lookup_setting("VT_REQUESTS_PER_MINUTE", file_values)
    abuse_key = _lookup_setting("ABUSEIPDB_API_KEY", file_values)
    abuse_rpm = _lookup_setting("ABUSEIPDB_REQUESTS_PER_MINUTE", file_values)

    vt_rpm_val = DEFAULT_REQUESTS_PER_MINUTE
    if vt_rpm.isdigit():
        vt_rpm_val = int(vt_rpm)

    abuse_rpm_val = DEFAULT_ABUSEIPDB_REQUESTS_PER_MINUTE
    if abuse_rpm.isdigit():
        abuse_rpm_val = int(abuse_rpm)

    return {
        "vt_api_key": vt_key if vt_key != PLACEHOLDER_API_KEY else "",
        "vt_rpm": vt_rpm_val,
        "vt_status": "Ready" if vt_key and vt_key != PLACEHOLDER_API_KEY else "Not configured",
        "abuse_api_key": abuse_key if abuse_key != PLACEHOLDER_ABUSEIPDB_API_KEY else "",
        "abuse_rpm": abuse_rpm_val,
        "abuse_status": "Ready" if abuse_key and abuse_key != PLACEHOLDER_ABUSEIPDB_API_KEY else "Not configured",
    }


def save_api_settings(
    env_path: str | Path | None = None,
    *,
    vt_api_key: Optional[str] = None,
    vt_rpm: Optional[int] = None,
    abuse_api_key: Optional[str] = None,
    abuse_rpm: Optional[int] = None,
) -> Path:
    """Safely saves or updates API settings in the .env file and updates os.environ."""
    target_path = Path(env_path) if env_path is not None else Path.cwd() / ".env"
    target_path.parent.mkdir(parents=True, exist_ok=True)

    existing_lines: list[str] = []
    if target_path.is_file():
        try:
            existing_lines = target_path.read_text(encoding="utf-8-sig").splitlines()
        except OSError:
            existing_lines = []

    updates: dict[str, str] = {}
    if vt_api_key is not None:
        if any(c in vt_api_key for c in ("\r", "\n", "\x00")):
            raise ValueError("VT_API_KEY must not contain newline or null characters.")
        updates["VT_API_KEY"] = vt_api_key.strip()
    if vt_rpm is not None:
        if vt_rpm < 1 or vt_rpm > 1000:
            raise ValueError("VT_REQUESTS_PER_MINUTE must be between 1 and 1000.")
        updates["VT_REQUESTS_PER_MINUTE"] = str(vt_rpm)
    if abuse_api_key is not None:
        if any(c in abuse_api_key for c in ("\r", "\n", "\x00")):
            raise ValueError("ABUSEIPDB_API_KEY must not contain newline or null characters.")
        updates["ABUSEIPDB_API_KEY"] = abuse_api_key.strip()
    if abuse_rpm is not None:
        if abuse_rpm < 1 or abuse_rpm > 1000:
            raise ValueError("ABUSEIPDB_REQUESTS_PER_MINUTE must be between 1 and 1000.")
        updates["ABUSEIPDB_REQUESTS_PER_MINUTE"] = str(abuse_rpm)

    new_lines: list[str] = []
    seen_keys: set[str] = set()

    for line in existing_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in updates:
                new_lines.append(f"{key}={updates[key]}")
                seen_keys.add(key)
                continue
        new_lines.append(line)

    for key, val in updates.items():
        if key not in seen_keys:
            new_lines.append(f"{key}={val}")

    content = "\n".join(new_lines).strip() + "\n"
    tmp = target_path.with_name(f"{target_path.stem}.partial{target_path.suffix}")
    try:
        tmp.write_text(content, encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, target_path)
    finally:
        if tmp.is_file():
            try:
                tmp.unlink()
            except OSError:
                pass

    for key, val in updates.items():
        os.environ[key] = val

    return target_path


def _test_http_connection(
    service_name: str,
    url: str,
    headers: dict[str, str],
    placeholder_key: str,
    api_key: str,
    timeout: float = 8.0,
) -> tuple[bool, str]:
    """Shared HTTP connection tester for API services."""
    if any(c in api_key for c in ("\r", "\n", "\x00")):
        return False, "API key contains invalid control characters."
    key = api_key.strip()
    if not key or key == placeholder_key:
        return False, "API key is empty or placeholder."
    import requests

    try:
        resp = requests.get(url, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            return True, f"Connected successfully! {service_name} key is valid."
        elif resp.status_code in (401, 403):
            return False, f"Authentication failed (HTTP {resp.status_code}). Invalid API key."
        elif resp.status_code == 429:
            return True, "Key is valid, but rate limit or quota exceeded (HTTP 429)."
        return False, f"{service_name} returned HTTP {resp.status_code}."
    except requests.exceptions.Timeout:
        return False, "Connection timed out. Check network connection."
    except Exception as exc:
        return False, f"Network error ({type(exc).__name__})."


def test_vt_api_connection(api_key: str, timeout: float = 8.0) -> tuple[bool, str]:
    """Tests VirusTotal API connection with the provided key."""
    return _test_http_connection(
        service_name="VirusTotal",
        url="https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
        headers={"x-apikey": api_key.strip(), "accept": "application/json"},
        placeholder_key=PLACEHOLDER_API_KEY,
        api_key=api_key,
        timeout=timeout,
    )


def test_abuseipdb_api_connection(api_key: str, timeout: float = 8.0) -> tuple[bool, str]:
    """Tests AbuseIPDB API connection with the provided key."""
    return _test_http_connection(
        service_name="AbuseIPDB",
        url="https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8",
        headers={"Key": api_key.strip(), "Accept": "application/json"},
        placeholder_key=PLACEHOLDER_ABUSEIPDB_API_KEY,
        api_key=api_key,
        timeout=timeout,
    )

