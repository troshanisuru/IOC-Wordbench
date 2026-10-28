"""Unit tests for Phase 11 URL canonicalization and runner refinements."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import zipfile

import pytest

from vt_ioc_checker.ioc_parser import IocType, load_iocs, make_entry
from vt_ioc_checker.report import read_report_info, read_report_rows
from vt_ioc_checker.runner import run_check
from vt_ioc_checker.vt_client import (
    VT_API_BASE,
    RateLimiter,
    VTClient,
    VTResult,
    build_analysis_url,
    build_lookup_url,
    build_reanalyze_url,
)

NOW = datetime(2026, 10, 25, 10, 0, 0, tzinfo=timezone.utc)


class FakeClient:
    """Fake VirusTotal client for testing runner behavior."""

    def __init__(self) -> None:
        """Initialize the fake client."""
        self.calls: list[tuple[IocType, str]] = []

    def lookup(self, ioc_type: IocType, value: str) -> VTResult:
        """Record the lookup and return a not-found result."""
        self.calls.append((ioc_type, value))
        return VTResult(found=False)


@pytest.mark.parametrize(
    ("raw", "expected_value"),
    [
        ("evil.com/path/file.exe", "http://evil.com/path/file.exe"),
        ("1.2.3.4/path", "http://1.2.3.4/path"),
        ("evil.com:8080/x", "http://evil.com:8080/x"),
        ("HTTPS://Evil.com/Path", "https://Evil.com/Path"),
        ("FTP://1.2.3.4/file", "ftp://1.2.3.4/file"),
    ],
)
def test_url_canonicalization_in_make_entry(
    raw: str, expected_value: str
) -> None:
    """Ensure schemeless URLs get http:// and uppercase schemes are lowercased."""
    entry = make_entry(raw)
    assert entry.ioc_type == IocType.URL
    assert entry.value == expected_value


def test_schemeless_and_schemed_url_deduplicated(tmp_path: Path) -> None:
    """Deduplicate schemeless URL against explicit http:// URL in load_iocs."""
    p = tmp_path / "list.txt"
    p.write_text(
        "evil.com/path/a.exe\nhttp://evil.com/path/a.exe\n", encoding="utf-8"
    )
    res = load_iocs(p)
    assert res.total_read == 2
    assert res.duplicates_removed == 1
    assert [e.value for e in res.entries] == ["http://evil.com/path/a.exe"]


def test_build_lookup_url_schemeless_fallback() -> None:
    """Ensure build_lookup_url prepends http:// if passed a schemeless URL."""
    assert build_lookup_url(
        IocType.URL, "www.virustotal.com/"
    ) == build_lookup_url(IocType.URL, "http://www.virustotal.com/")
    assert build_lookup_url(IocType.URL, "www.virustotal.com/") == (
        f"{VT_API_BASE}/urls/aHR0cDovL3d3dy52aXJ1c3RvdGFsLmNvbS8"
    )


def test_vt_client_strips_api_key_whitespace() -> None:
    """Strip surrounding whitespace from api_key when initializing VTClient."""
    limiter = RateLimiter(4, clock=lambda: 0.0, sleep=lambda x: None)
    client = VTClient("  my-key-123  ", limiter)
    assert client._headers["x-apikey"] == "my-key-123"


def test_non_excel_zip_raises_value_error(tmp_path: Path) -> None:
    """Raise ValueError instead of KeyError when an .xlsx is an empty zip."""
    p = tmp_path / "empty.xlsx"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("hello.txt", "not an excel file")
    with pytest.raises(ValueError, match="valid Excel"):
        load_iocs(p)
    with pytest.raises(ValueError, match="not a vt-ioc-checker report"):
        read_report_info(p)
    with pytest.raises(ValueError, match="not a vt-ioc-checker report"):
        read_report_rows(p)


def test_no_duplicate_save_when_max_lookups_equals_save_every(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Avoid writing the report twice when max_lookups is a multiple of save_every."""
    from vt_ioc_checker import runner

    real_write = runner.write_report
    write_count = [0]

    def counting_write(path, rows, meta):
        """Count calls to write_report and delegate."""
        write_count[0] += 1
        return real_write(path, rows, meta)

    monkeypatch.setattr(runner, "write_report", counting_write)
    in_path = tmp_path / "in.txt"
    in_path.write_text("evil.com\n8.8.8.8\nexample.com\n", encoding="utf-8")
    out = tmp_path / "out.xlsx"
    summary = run_check(
        in_path,
        out,
        FakeClient(),
        max_lookups=2,
        save_every=2,
        now=lambda: NOW,
    )
    assert summary.stop_kind == "limit"
    assert summary.looked_up == 2
    assert write_count[0] == 1


class PostCapableFakeResponse:
    """Fake HTTP response for testing POST reanalysis and polling."""

    def __init__(self, status_code: int, json_data: dict) -> None:
        """Initialize the fake response."""
        self.status_code = status_code
        self._json_data = json_data
        self.headers: dict[str, str] = {}

    def json(self) -> dict:
        """Return the JSON dictionary."""
        return self._json_data


class PostCapableFakeSession:
    """Fake session supporting both POST and GET requests."""

    def __init__(self, responses: list[PostCapableFakeResponse]) -> None:
        """Initialize the fake session with queued responses."""
        self.responses = list(responses)
        self.calls: list[tuple[str, str]] = []

    def post(self, url: str, headers=None, timeout=None) -> PostCapableFakeResponse:
        """Record a POST call and return the next response."""
        self.calls.append(("POST", url))
        return self.responses.pop(0)

    def get(self, url: str, headers=None, timeout=None) -> PostCapableFakeResponse:
        """Record a GET call and return the next response."""
        self.calls.append(("GET", url))
        return self.responses.pop(0)


def test_post_reanalyze_polls_until_completed() -> None:
    """Trigger POST /analyse, poll GET /analyses/{id} from queued to completed."""
    md5 = "44d88612fea8a8f36de82e1278abb02f"
    session = PostCapableFakeSession(
        [
            PostCapableFakeResponse(200, {"data": {"id": "analysis-123"}}),
            PostCapableFakeResponse(
                200, {"data": {"attributes": {"status": "queued"}}}
            ),
            PostCapableFakeResponse(
                200,
                {
                    "data": {
                        "attributes": {
                            "status": "completed",
                            "stats": {"malicious": 63, "undetected": 3},
                            "results": {
                                "Sophos": {"category": "malicious"},
                            },
                            "date": 1700000100,
                        }
                    }
                },
            ),
        ]
    )
    limiter = RateLimiter(60, clock=lambda: 0.0, sleep=lambda x: None)
    client = VTClient(
        "key-123", limiter, session=session, sleep=lambda x: None, poll_wait=0.0
    )
    res = client.lookup(IocType.MD5, md5)
    assert res.found is True
    assert res.stats == {"malicious": 63, "undetected": 3}
    assert res.engine_results == {"Sophos": "malicious"}
    assert res.last_analysis_date == 1700000100
    assert session.calls == [
        ("POST", build_reanalyze_url(IocType.MD5, md5)),
        ("GET", build_analysis_url("analysis-123")),
        ("GET", build_analysis_url("analysis-123")),
    ]


def test_post_reanalyze_fallback_to_get_when_still_queued() -> None:
    """Fall back to GET /files/{id} if analysis polling does not complete in time."""
    md5 = "44d88612fea8a8f36de82e1278abb02f"
    session = PostCapableFakeSession(
        [
            PostCapableFakeResponse(200, {"data": {"id": "analysis-999"}}),
            PostCapableFakeResponse(
                200, {"data": {"attributes": {"status": "in-progress"}}}
            ),
            PostCapableFakeResponse(
                200,
                {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "malicious": 63,
                                "undetected": 3,
                            },
                            "last_analysis_results": {
                                "Sophos": {"category": "malicious"},
                            },
                            "last_analysis_date": 1700000200,
                        }
                    }
                },
            ),
        ]
    )
    limiter = RateLimiter(60, clock=lambda: 0.0, sleep=lambda x: None)
    client = VTClient(
        "key-123",
        limiter,
        session=session,
        sleep=lambda x: None,
        max_poll_attempts=1,
        poll_wait=0.0,
    )
    res = client.lookup(IocType.MD5, md5)
    assert res.found is True
    assert res.stats == {"malicious": 63, "undetected": 3}
    assert session.calls == [
        ("POST", build_reanalyze_url(IocType.MD5, md5)),
        ("GET", build_analysis_url("analysis-999")),
        ("GET", build_lookup_url(IocType.MD5, md5)),
    ]

