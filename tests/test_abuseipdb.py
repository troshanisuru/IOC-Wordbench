"""Unit tests for AbuseIPDB bulk IP check client, runner, table, CSV, and CLI."""

from __future__ import annotations

import io
from pathlib import Path
from typing import Any
import pytest
import requests

from vt_ioc_checker.__main__ import EXIT_CONFIG, EXIT_FILE, EXIT_LIMIT, EXIT_OK, main
from vt_ioc_checker.abuseipdb import (
    ABUSEIPDB_TABLE_HEADERS,
    STATUS_CHECKED,
    STATUS_ERROR,
    STATUS_INVALID,
    STATUS_NOT_CHECKED,
    AbuseIPDBAuthError,
    AbuseIPDBClient,
    AbuseIPDBQuotaExceededError,
    AbuseIPDBRequestError,
    AbuseIPDBResult,
    build_abuseipdb_check_url,
    format_abuseipdb_table,
    read_abuseipdb_csv,
    run_abuseipdb_bulk,
    run_abuseipdb_bulk_items,
    write_abuseipdb_csv,
)
from vt_ioc_checker.config import ConfigError, load_abuseipdb_settings
from vt_ioc_checker.vt_client import RateLimiter


class FakeResponse:
    """Simulated HTTP response for AbuseIPDB unit tests."""

    def __init__(
        self,
        status_code: int,
        payload: Any = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}

    def json(self) -> Any:
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeSession:
    """Simulated requests.Session returning queued responses."""

    def __init__(self, responses: list[Any]) -> None:
        self._responses = list(responses)
        self.calls: list[tuple[str, dict[str, str], float]] = []

    def get(
        self, url: str, headers: dict[str, str], timeout: float
    ) -> FakeResponse:
        self.calls.append((url, headers, timeout))
        item = self._responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class FakeAbuseClient:
    """Stub AbuseIPDB client for bulk runner and CLI tests."""

    def __init__(self, mapping: dict[str, Any]) -> None:
        self._mapping = mapping
        self.checked: list[tuple[str, int]] = []

    def check_ip(
        self, ip_address: str, max_age_in_days: int = 90
    ) -> AbuseIPDBResult:
        self.checked.append((ip_address, max_age_in_days))
        val = self._mapping.get(ip_address)
        if isinstance(val, Exception):
            raise val
        if isinstance(val, AbuseIPDBResult):
            return val
        return AbuseIPDBResult(
            ip_address=ip_address,
            abuse_score=0,
            country="US",
            domain="example.com",
        )


def test_load_abuseipdb_settings_from_env_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reads ABUSEIPDB_API_KEY and ABUSEIPDB_REQUESTS_PER_MINUTE from .env."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("ABUSEIPDB_REQUESTS_PER_MINUTE", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text(
        "ABUSEIPDB_API_KEY=real_abuse_key_123\nABUSEIPDB_REQUESTS_PER_MINUTE=120\n",
        encoding="utf-8",
    )
    settings = load_abuseipdb_settings(env_file)
    assert settings.api_key == "real_abuse_key_123"
    assert settings.requests_per_minute == 120


def test_load_abuseipdb_settings_rejects_missing_or_placeholder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rejects missing or placeholder ABUSEIPDB_API_KEY."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    env_file = tmp_path / ".env"
    env_file.write_text("", encoding="utf-8")
    with pytest.raises(ConfigError, match="ABUSEIPDB_API_KEY is not set"):
        load_abuseipdb_settings(env_file)

    env_file.write_text(
        "ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here\n", encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="placeholder"):
        load_abuseipdb_settings(env_file)


def test_build_abuseipdb_check_url_valid_and_invalid() -> None:
    """Builds the check URL for IPv4/IPv6 and rejects non-IPs or invalid max_age."""
    url = build_abuseipdb_check_url("118[.]25[.]6[.]39", max_age_in_days=30)
    assert (
        url
        == "https://api.abuseipdb.com/api/v2/check?ipAddress=118.25.6.39&maxAgeInDays=30"
    )

    with pytest.raises(ValueError, match="valid IPv4 or IPv6"):
        build_abuseipdb_check_url("evil.com")

    with pytest.raises(ValueError, match="max_age_in_days"):
        build_abuseipdb_check_url("8.8.8.8", max_age_in_days=400)


def test_abuseipdb_client_check_ip_200_and_null_fields() -> None:
    """Parses AbuseIPDB 200 responses including null country/domain fallback to Unknown."""
    session = FakeSession(
        [
            FakeResponse(
                200,
                {
                    "data": {
                        "ipAddress": "118.25.6.39",
                        "abuseConfidenceScore": 100,
                        "countryCode": "CN",
                        "domain": "tencent.com",
                        "isp": "Tencent Cloud",
                        "usageType": "Data Center/Web Hosting/Transit",
                        "totalReports": 42,
                        "isPublic": True,
                    }
                },
            ),
            FakeResponse(
                200,
                {
                    "data": {
                        "ipAddress": "127.0.0.1",
                        "abuseConfidenceScore": 0,
                        "countryCode": None,
                        "domain": None,
                        "isPublic": False,
                    }
                },
            ),
        ]
    )
    limiter = RateLimiter(60, clock=lambda: 0.0, sleep=lambda s: None)
    client = AbuseIPDBClient(
        "secret_key", limiter, session=session, sleep=lambda s: None
    )

    res1 = client.check_ip("118.25.6.39")
    assert res1.ip_address == "118.25.6.39"
    assert res1.abuse_score == 100
    assert res1.abuse_score_text == "100"
    assert res1.country == "CN"
    assert res1.domain == "tencent.com"
    assert res1.total_reports == 42
    assert res1.to_table_row() == ("118.25.6.39", "100", "CN", "tencent.com")

    res2 = client.check_ip("127.0.0.1")
    assert res2.abuse_score == 0
    assert res2.country == "Unknown"
    assert res2.domain == "Unknown"
    assert res2.to_table_row() == ("127.0.0.1", "0", "Unknown", "Unknown")


def test_abuseipdb_client_error_handling_and_retries() -> None:
    """Handles 401 auth error, 429 daily quota error, and retry on network/500."""
    limiter = RateLimiter(60, clock=lambda: 0.0, sleep=lambda s: None)

    auth_session = FakeSession([FakeResponse(401, {})])
    auth_client = AbuseIPDBClient(
        "bad_key", limiter, session=auth_session, sleep=lambda s: None
    )
    with pytest.raises(AbuseIPDBAuthError):
        auth_client.check_ip("8.8.8.8")

    quota_session = FakeSession(
        [
            FakeResponse(
                429,
                {"errors": [{"detail": "Daily rate limit of 1000 requests exceeded."}]},
            )
        ]
    )
    quota_client = AbuseIPDBClient(
        "key", limiter, session=quota_session, sleep=lambda s: None
    )
    with pytest.raises(AbuseIPDBQuotaExceededError):
        quota_client.check_ip("8.8.8.8")

    retry_session = FakeSession(
        [
            requests.exceptions.ConnectionError("dropped"),
            FakeResponse(502, {}),
            FakeResponse(
                200,
                {
                    "data": {
                        "ipAddress": "8.8.8.8",
                        "abuseConfidenceScore": 0,
                        "countryCode": "US",
                        "domain": "google.com",
                    }
                },
            ),
        ]
    )
    retry_client = AbuseIPDBClient(
        "key", limiter, session=retry_session, sleep=lambda s: None
    )
    res = retry_client.check_ip("8.8.8.8")
    assert res.domain == "google.com"
    assert len(retry_session.calls) == 3


def test_run_abuseipdb_bulk_items_table_and_csv(tmp_path: Path) -> None:
    """Deduplicates IPs, marks non-IPs Invalid, invokes on_result callback, and writes CSV."""
    client = FakeAbuseClient(
        {
            "118.25.6.39": AbuseIPDBResult(
                ip_address="118.25.6.39",
                abuse_score=95,
                country="CN",
                domain="tencent.com",
            ),
            "8.8.8.8": AbuseIPDBResult(
                ip_address="8.8.8.8",
                abuse_score=0,
                country="US",
                domain="google.com",
            ),
            "1.2.3.4": AbuseIPDBRequestError("HTTP 422"),
        }
    )
    seen_callbacks: list[tuple[int, int, str]] = []
    csv_out = tmp_path / "abuse_results.csv"

    summary = run_abuseipdb_bulk_items(
        [
            "118[.]25[.]6[.]39",
            "118.25.6.39",  # duplicate
            "not-an-ip.com",  # non-IP -> Invalid
            "8.8.8.8",
            "1.2.3.4",
        ],
        client,
        csv_output_path=csv_out,
        on_result=lambda pos, total, row: seen_callbacks.append(
            (pos, total, row.ip_address)
        ),
    )

    assert summary.total_unique == 4
    assert summary.duplicates_removed == 1
    assert summary.invalid == 1
    assert summary.checked == 3
    assert summary.errors == 1
    assert summary.csv_path == csv_out
    assert seen_callbacks == [
        (1, 3, "118.25.6.39"),
        (2, 3, "8.8.8.8"),
        (3, 3, "1.2.3.4"),
    ]

    table = format_abuseipdb_table(summary.rows)
    for col in ABUSEIPDB_TABLE_HEADERS:
        assert col in table
    assert "118.25.6.39" in table
    assert "tencent.com" in table
    assert "Invalid" in table

    loaded_csv = read_abuseipdb_csv(csv_out)
    assert [r.to_table_row() for r in loaded_csv] == [
        ("118.25.6.39", "95", "CN", "tencent.com"),
        ("not-an-ip.com", STATUS_INVALID, "Unknown", "Unknown"),
        ("8.8.8.8", "0", "US", "google.com"),
        ("1.2.3.4", STATUS_ERROR, "Unknown", "Unknown"),
    ]


def test_cli_abuseipdb_mode_displays_table_and_exports_csv(
    tmp_path: Path,
) -> None:
    """CLI --abuseipdb prints the ASCII table and exports CSV when requested."""
    env_file = tmp_path / ".env"
    env_file.write_text("ABUSEIPDB_API_KEY=real_key\n", encoding="utf-8")

    input_file = tmp_path / "ips.txt"
    input_file.write_text("118.25.6.39\n8.8.8.8\n", encoding="utf-8")
    csv_file = tmp_path / "out.csv"

    fake_client = FakeAbuseClient(
        {
            "118.25.6.39": AbuseIPDBResult(
                ip_address="118.25.6.39",
                abuse_score=88,
                country="CN",
                domain="tencent.com",
            ),
            "8.8.8.8": AbuseIPDBResult(
                ip_address="8.8.8.8",
                abuse_score=0,
                country="US",
                domain="google.com",
            ),
        }
    )

    out = io.StringIO()
    err = io.StringIO()
    code = main(
        [
            str(input_file),
            "--abuseipdb",
            "--csv",
            str(csv_file),
            "--env-file",
            str(env_file),
        ],
        client_factory=lambda s: fake_client,
        stdout=out,
        stderr=err,
    )

    assert code == EXIT_OK
    assert err.getvalue() == ""
    stdout_text = out.getvalue()
    assert "| IP" in stdout_text
    assert "| Abuse Score |" in stdout_text
    assert "| Country |" in stdout_text
    assert "| Domain" in stdout_text
    assert "118.25.6.39" in stdout_text
    assert "tencent.com" in stdout_text
    assert csv_file.is_file()


def test_cli_abuseipdb_max_lookups_and_missing_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """CLI --abuseipdb returns EXIT_CONFIG on missing key and EXIT_LIMIT on --max-lookups."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    empty_env = tmp_path / ".env"
    empty_env.write_text("", encoding="utf-8")
    input_file = tmp_path / "ips.txt"
    input_file.write_text("1.1.1.1\n8.8.8.8\n", encoding="utf-8")

    out = io.StringIO()
    err = io.StringIO()
    code = main(
        [str(input_file), "--abuseipdb", "--env-file", str(empty_env)],
        stdout=out,
        stderr=err,
    )
    assert code == EXIT_CONFIG
    assert "ABUSEIPDB_API_KEY" in err.getvalue()

    empty_env.write_text("ABUSEIPDB_API_KEY=valid_key\n", encoding="utf-8")
    out2 = io.StringIO()
    err2 = io.StringIO()
    code2 = main(
        [
            str(input_file),
            "--abuseipdb",
            "--max-lookups",
            "1",
            "--env-file",
            str(empty_env),
        ],
        client_factory=lambda s: FakeAbuseClient({}),
        stdout=out2,
        stderr=err2,
    )
    assert code2 == EXIT_LIMIT
    assert STATUS_NOT_CHECKED in out2.getvalue()

