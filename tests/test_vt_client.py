"""Unit tests for VirusTotal API v3 client."""

from __future__ import annotations

import pytest
import requests

from vt_ioc_checker.ioc_parser import IocType
from vt_ioc_checker.vt_client import (
    VT_API_BASE,
    RateLimiter,
    VTAuthError,
    VTClient,
    VTQuotaExceededError,
    VTRequestError,
    build_lookup_url,
)

API_KEY = "test-key-123456"
DEFAULT_MD5 = "44d88612fea8a8f36de82e1278abb02f"


class FakeResponse:
    """Fake HTTP response for testing."""

    def __init__(
        self,
        status_code: int = 200,
        json_data: dict | None = None,
        headers: dict[str, str] | None = None,
        bad_json: bool = False,
    ) -> None:
        self.status_code = status_code
        self._json_data = json_data
        self.headers = headers if headers is not None else {}
        self.bad_json = bad_json

    def json(self) -> dict:
        if self.bad_json:
            raise ValueError("bad json")
        return self._json_data if self._json_data is not None else {}


class FakeSession:
    """Fake requests.Session queueing responses or exceptions."""

    def __init__(self, responses: list) -> None:
        self.responses = list(responses)
        self.requests: list[tuple[str, dict | None, float | None]] = []

    def get(
        self,
        url: str,
        headers: dict | None = None,
        timeout: float | None = None,
    ) -> FakeResponse:
        self.requests.append((url, headers, timeout))
        resp = self.responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        if isinstance(resp, type) and issubclass(resp, Exception):
            raise resp()
        return resp


class FakeLimiter:
    """Fake RateLimiter tracking wait calls."""

    def __init__(self) -> None:
        self.calls = 0

    def wait(self) -> None:
        self.calls += 1


class FakeClock:
    """Fake clock recording now and sleep durations."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.now += s


FOUND_BODY = {
    "data": {
        "attributes": {
            "last_analysis_stats": {
                "malicious": 2,
                "harmless": 0,
                "undetected": 3,
                "suspicious": 0,
            },
            "last_analysis_results": {
                "Sophos": {"category": "malicious", "result": "Mal/Generic"},
                "Microsoft": {"category": "undetected", "result": None},
            },
            "last_analysis_date": 1700000000,
        }
    }
}


def make_client(responses: list, max_retries: int = 3):
    session = FakeSession(responses)
    limiter = FakeLimiter()
    sleeps: list[float] = []
    client = VTClient(
        API_KEY,
        limiter,
        session=session,
        sleep=sleeps.append,
        max_retries=max_retries,
    )
    return client, session, limiter, sleeps


@pytest.mark.parametrize(
    ("ioc_type", "value", "expected_suffix"),
    [
        (
            IocType.MD5,
            "44d88612fea8a8f36de82e1278abb02f",
            "/files/44d88612fea8a8f36de82e1278abb02f",
        ),
        (
            IocType.SHA1,
            "3395856ce81f2b7382dee72602f798b642f14140",
            "/files/3395856ce81f2b7382dee72602f798b642f14140",
        ),
        (
            IocType.SHA256,
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "/files/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        ),
        (IocType.IP, "8.8.8.8", "/ip_addresses/8.8.8.8"),
        (IocType.IP, "2001:db8::1", "/ip_addresses/2001:db8::1"),
        (IocType.DOMAIN, "example.com", "/domains/example.com"),
        (
            IocType.URL,
            "http://www.virustotal.com/",
            "/urls/aHR0cDovL3d3dy52aXJ1c3RvdGFsLmNvbS8",
        ),
    ],
)
def test_build_lookup_url(
    ioc_type: IocType, value: str, expected_suffix: str
) -> None:
    assert build_lookup_url(ioc_type, value) == VT_API_BASE + expected_suffix


def test_build_lookup_url_invalid() -> None:
    with pytest.raises(ValueError, match="Cannot look up an invalid IOC."):
        build_lookup_url(IocType.INVALID, "anything")


def test_rate_limiter_r1() -> None:
    fake = FakeClock()
    limiter = RateLimiter(4, clock=fake.time, sleep=fake.sleep)
    limiter.wait()
    limiter.wait()
    limiter.wait()
    assert fake.sleeps == pytest.approx([15.0, 15.0])


def test_rate_limiter_r2() -> None:
    fake = FakeClock()
    limiter = RateLimiter(4, clock=fake.time, sleep=fake.sleep)
    limiter.wait()
    fake.now += 20
    limiter.wait()
    assert fake.sleeps == []


def test_rate_limiter_r3() -> None:
    fake = FakeClock()
    limiter = RateLimiter(4, clock=fake.time, sleep=fake.sleep)
    limiter.wait()
    fake.now += 5
    limiter.wait()
    assert fake.sleeps == pytest.approx([10.0])


def test_rate_limiter_r4() -> None:
    fake = FakeClock()
    limiter = RateLimiter(60, clock=fake.time, sleep=fake.sleep)
    limiter.wait()
    limiter.wait()
    assert fake.sleeps == pytest.approx([1.0])


@pytest.mark.parametrize("rpm", [0, -1])
def test_rate_limiter_r5(rpm: int) -> None:
    with pytest.raises(ValueError, match="requests_per_minute must be at least 1."):
        RateLimiter(rpm)


def test_found() -> None:
    client, session, limiter, sleeps = make_client([FakeResponse(200, FOUND_BODY)])
    res = client.lookup(IocType.MD5, DEFAULT_MD5)
    assert res.found is True
    assert res.stats == {
        "malicious": 2,
        "harmless": 0,
        "undetected": 3,
        "suspicious": 0,
    }
    assert res.engine_results == {
        "Sophos": "malicious",
        "Microsoft": "undetected",
    }
    assert res.last_analysis_date == 1700000000
    assert len(session.requests) == 1
    assert session.requests[0][0] == build_lookup_url(IocType.MD5, DEFAULT_MD5)
    assert session.requests[0][1] is not None
    assert session.requests[0][1]["x-apikey"] == API_KEY
    assert session.requests[0][2] == 30.0
    assert limiter.calls == 1
    assert sleeps == []


def test_not_found() -> None:
    client, session, limiter, sleeps = make_client(
        [FakeResponse(404, {"error": {"code": "NotFoundError"}})]
    )
    res = client.lookup(IocType.MD5, DEFAULT_MD5)
    assert res.found is False
    assert res.stats == {}
    assert res.engine_results == {}
    assert res.last_analysis_date is None
    assert len(session.requests) == 1
    assert sleeps == []


def test_found_without_analysis() -> None:
    client, session, limiter, sleeps = make_client(
        [FakeResponse(200, {"data": {"attributes": {}}})]
    )
    res = client.lookup(IocType.MD5, DEFAULT_MD5)
    assert res.found is True
    assert res.stats == {}
    assert res.engine_results == {}
    assert res.last_analysis_date is None


@pytest.mark.parametrize("status_code", [401, 403])
def test_auth_errors(status_code: int) -> None:
    client, session, limiter, sleeps = make_client([FakeResponse(status_code)])
    with pytest.raises(VTAuthError, match="API key") as exc_info:
        client.lookup(IocType.MD5, DEFAULT_MD5)
    assert API_KEY not in str(exc_info.value)
    assert len(session.requests) == 1


def test_quota_exceeded() -> None:
    client, session, limiter, sleeps = make_client(
        [FakeResponse(429, {"error": {"code": "QuotaExceededError"}})]
    )
    with pytest.raises(VTQuotaExceededError, match="quota exceeded"):
        client.lookup(IocType.MD5, DEFAULT_MD5)
    assert len(session.requests) == 1
    assert sleeps == []


@pytest.mark.parametrize(
    ("retry_after_header", "expected_sleep"),
    [
        (None, 60.0),
        ("abc", 60.0),
        ("7", 7.0),
        ("9999", 120.0),
    ],
)
def test_too_many_requests_then_ok(
    retry_after_header: str | None, expected_sleep: float
) -> None:
    headers = (
        {"Retry-After": retry_after_header}
        if retry_after_header is not None
        else {}
    )
    resp1 = FakeResponse(
        429,
        {"error": {"code": "TooManyRequestsError"}},
        headers=headers,
    )
    resp2 = FakeResponse(200, FOUND_BODY)
    client, session, limiter, sleeps = make_client([resp1, resp2])
    res = client.lookup(IocType.MD5, DEFAULT_MD5)
    assert res.found is True
    assert sleeps == pytest.approx([expected_sleep])
    assert len(session.requests) == 2
    assert limiter.calls == 2


def test_too_many_requests_exhausted() -> None:
    responses = [
        FakeResponse(429, {"error": {"code": "TooManyRequestsError"}})
        for _ in range(4)
    ]
    client, session, limiter, sleeps = make_client(responses)
    with pytest.raises(VTQuotaExceededError, match="too many requests"):
        client.lookup(IocType.MD5, DEFAULT_MD5)
    assert len(session.requests) == 4
    assert sleeps == pytest.approx([60.0, 60.0, 60.0])


def test_server_error_then_ok() -> None:
    responses = [
        FakeResponse(503),
        FakeResponse(503),
        FakeResponse(200, FOUND_BODY),
    ]
    client, session, limiter, sleeps = make_client(responses)
    res = client.lookup(IocType.MD5, DEFAULT_MD5)
    assert res.found is True
    assert sleeps == pytest.approx([2.0, 4.0])
    assert len(session.requests) == 3
    assert limiter.calls == 3


def test_server_error_exhausted() -> None:
    responses = [FakeResponse(503) for _ in range(4)]
    client, session, limiter, sleeps = make_client(responses)
    with pytest.raises(
        VTRequestError, match="failed after 4 attempts"
    ) as exc_info:
        client.lookup(IocType.MD5, DEFAULT_MD5)
    assert "HTTP 503" in str(exc_info.value)
    assert len(session.requests) == 4
    assert sleeps == pytest.approx([2.0, 4.0, 8.0])


def test_network_error_then_ok() -> None:
    responses = [
        requests.exceptions.ConnectionError(),
        FakeResponse(200, FOUND_BODY),
    ]
    client, session, limiter, sleeps = make_client(responses)
    res = client.lookup(IocType.MD5, DEFAULT_MD5)
    assert res.found is True
    assert sleeps == pytest.approx([2.0])
    assert len(session.requests) == 2


def test_timeout_exhausted() -> None:
    responses = [requests.exceptions.Timeout() for _ in range(4)]
    client, session, limiter, sleeps = make_client(responses)
    with pytest.raises(
        VTRequestError, match="failed after 4 attempts"
    ) as exc_info:
        client.lookup(IocType.MD5, DEFAULT_MD5)
    assert "Timeout" in str(exc_info.value)
    assert API_KEY not in str(exc_info.value)
    assert len(session.requests) == 4


def test_other_client_error() -> None:
    client, session, limiter, sleeps = make_client(
        [FakeResponse(400, {"error": {"code": "BadRequestError"}})]
    )
    with pytest.raises(VTRequestError, match="HTTP 400") as exc_info:
        client.lookup(IocType.MD5, DEFAULT_MD5)
    assert "BadRequestError" in str(exc_info.value)
    assert len(session.requests) == 1
    assert sleeps == []


def test_bad_json() -> None:
    client, session, limiter, sleeps = make_client(
        [FakeResponse(200, bad_json=True)]
    )
    with pytest.raises(VTRequestError, match="Unexpected response"):
        client.lookup(IocType.MD5, DEFAULT_MD5)


def test_invalid_ioc() -> None:
    client, session, limiter, sleeps = make_client([])
    with pytest.raises(ValueError, match="Cannot look up an invalid IOC."):
        client.lookup(IocType.INVALID, "not an ioc")
    assert len(session.requests) == 0
    assert limiter.calls == 0


def test_empty_api_key() -> None:
    with pytest.raises(ValueError, match="api_key must not be empty."):
        VTClient("   ", FakeLimiter())
