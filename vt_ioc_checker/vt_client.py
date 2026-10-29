"""Talks to the VirusTotal API v3 with rate limiting and retries."""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import math
import time
from typing import Callable, Optional

import requests

from vt_ioc_checker.ioc_parser import IocType

VT_API_BASE = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_RATE_LIMIT_WAIT_SECONDS = 60.0
MAX_RETRY_AFTER_SECONDS = 120.0
BACKOFF_BASE_SECONDS = 2.0
DEFAULT_MAX_POLL_ATTEMPTS = 4
DEFAULT_POLL_WAIT_SECONDS = 5.0


class VTError(Exception):
    """Base exception for VirusTotal API client errors."""


class VTAuthError(VTError):
    """Fatal authentication error indicating an invalid or rejected API key."""


class VTQuotaExceededError(VTError):
    """Fatal quota error indicating VirusTotal quota or rate limit exhaustion."""


class VTRequestError(VTError):
    """Non-fatal request error affecting only the current IOC."""


@dataclass(frozen=True)
class VTResult:
    """Result of looking up an indicator on VirusTotal."""

    found: bool
    stats: dict[str, int] = field(default_factory=dict)
    engine_results: dict[str, str] = field(default_factory=dict)
    last_analysis_date: Optional[int] = None


def build_lookup_url(ioc_type: IocType, value: str) -> str:
    """Constructs the VirusTotal API v3 endpoint URL for an indicator."""
    if ioc_type in (IocType.MD5, IocType.SHA1, IocType.SHA256):
        return f"{VT_API_BASE}/files/{value}"
    if ioc_type == IocType.IP:
        return f"{VT_API_BASE}/ip_addresses/{value}"
    if ioc_type == IocType.DOMAIN:
        return f"{VT_API_BASE}/domains/{value}"
    if ioc_type == IocType.URL:
        if not value.lower().startswith(("http://", "https://", "ftp://")):
            value = "http://" + value
        url_id = (
            base64.urlsafe_b64encode(value.encode("utf-8"))
            .decode("ascii")
            .rstrip("=")
        )
        return f"{VT_API_BASE}/urls/{url_id}"
    raise ValueError("Cannot look up an invalid IOC.")


def build_reanalyze_url(ioc_type: IocType, value: str) -> str:
    """Constructs the VirusTotal API v3 POST re-analysis endpoint URL."""
    return f"{build_lookup_url(ioc_type, value)}/analyse"


def build_analysis_url(analysis_id: str) -> str:
    """Constructs the VirusTotal API v3 analysis status endpoint URL."""
    cleaned = analysis_id.strip()
    if not cleaned or ".." in cleaned or any(c in cleaned for c in ("/", "\\", "?", "#", "\r", "\n", "\x00")):
        raise ValueError("Invalid analysis_id.")
    from urllib.parse import quote

    return f"{VT_API_BASE}/analyses/{quote(cleaned, safe='')}"


class RateLimiter:
    """Enforces requests-per-minute limits using a monotonic clock."""

    def __init__(
        self,
        requests_per_minute: int,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if requests_per_minute < 1:
            raise ValueError("requests_per_minute must be at least 1.")
        self._interval = 60.0 / requests_per_minute
        self._next_allowed: Optional[float] = None
        self._clock = clock
        self._sleep = sleep

    def wait(self) -> None:
        now = self._clock()
        start = now if self._next_allowed is None else max(now, self._next_allowed)
        if start > now:
            self._sleep(start - now)
        self._next_allowed = start + self._interval


def _error_code(resp: requests.Response) -> str:
    try:
        return str(resp.json()["error"]["code"])
    except (ValueError, KeyError, TypeError):
        return ""


def _retry_after_seconds(resp: requests.Response) -> float:
    value = resp.headers.get("Retry-After")
    try:
        sec = float(value)  # type: ignore[arg-type]
        if not math.isfinite(sec):
            return DEFAULT_RATE_LIMIT_WAIT_SECONDS
        return max(1.0, min(sec, MAX_RETRY_AFTER_SECONDS))
    except (TypeError, ValueError):
        return DEFAULT_RATE_LIMIT_WAIT_SECONDS


def _parse_200(resp: requests.Response) -> VTResult:
    try:
        attributes = resp.json()["data"]["attributes"]
    except (ValueError, KeyError, TypeError):
        raise VTRequestError(
            "Unexpected response from VirusTotal (could not read JSON)."
        )
    if not isinstance(attributes, dict):
        raise VTRequestError(
            "Unexpected response from VirusTotal (could not read JSON)."
        )

    raw_stats = attributes.get("last_analysis_stats")
    stats: dict[str, int] = {}
    if isinstance(raw_stats, dict):
        for k, v in raw_stats.items():
            try:
                stats[str(k)] = int(v)
            except (ValueError, TypeError):
                continue

    raw_results = attributes.get("last_analysis_results")
    engine_results: dict[str, str] = {}
    if isinstance(raw_results, dict):
        for engine, info in raw_results.items():
            if isinstance(info, dict):
                engine_results[str(engine)] = str(info.get("category", ""))

    raw_date = attributes.get("last_analysis_date")
    last_analysis_date: Optional[int] = (
        raw_date
        if isinstance(raw_date, int) and not isinstance(raw_date, bool)
        else None
    )

    return VTResult(
        found=True,
        stats=stats,
        engine_results=engine_results,
        last_analysis_date=last_analysis_date,
    )


def _extract_analysis_id(resp: requests.Response) -> Optional[str]:
    """Extracts the analysis job identifier from a POST .../analyse response."""
    try:
        analysis_id = resp.json()["data"]["id"]
    except (ValueError, KeyError, TypeError):
        return None
    if isinstance(analysis_id, str) and analysis_id.strip():
        return analysis_id.strip()
    return None


def _parse_analysis_200(resp: requests.Response) -> Optional[VTResult]:
    """Parses a GET /analyses/{id} response if the analysis is completed."""
    try:
        attributes = resp.json()["data"]["attributes"]
    except (ValueError, KeyError, TypeError):
        return None
    if not isinstance(attributes, dict):
        return None
    if attributes.get("status") != "completed":
        return None

    raw_stats = attributes.get("stats")
    stats: dict[str, int] = {}
    if isinstance(raw_stats, dict):
        for k, v in raw_stats.items():
            try:
                stats[str(k)] = int(v)
            except (ValueError, TypeError):
                continue

    raw_results = attributes.get("results")
    engine_results: dict[str, str] = {}
    if isinstance(raw_results, dict):
        for engine, info in raw_results.items():
            if isinstance(info, dict):
                engine_results[str(engine)] = str(info.get("category", ""))

    if not stats and not engine_results:
        return None

    raw_date = attributes.get("date")
    last_analysis_date: Optional[int] = (
        raw_date
        if isinstance(raw_date, int) and not isinstance(raw_date, bool)
        else None
    )

    return VTResult(
        found=True,
        stats=stats,
        engine_results=engine_results,
        last_analysis_date=last_analysis_date,
    )


class VTClient:
    """Client for VirusTotal API v3 with rate limiting and exponential retries."""

    def __init__(
        self,
        api_key: str,
        limiter: RateLimiter,
        session: Optional[requests.Session] = None,
        sleep: Callable[[float], None] = time.sleep,
        max_retries: int = DEFAULT_MAX_RETRIES,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        reanalyze: bool = True,
        max_poll_attempts: int = DEFAULT_MAX_POLL_ATTEMPTS,
        poll_wait: float = DEFAULT_POLL_WAIT_SECONDS,
    ) -> None:
        if not api_key or not api_key.strip():
            raise ValueError("api_key must not be empty.")
        self._limiter = limiter
        self._session = session if session is not None else requests.Session()
        self._sleep = sleep
        self._max_retries = max_retries
        self._timeout = timeout
        self._reanalyze = reanalyze
        self._max_poll_attempts = max_poll_attempts
        self._poll_wait = poll_wait
        self._headers = {"x-apikey": api_key.strip(), "accept": "application/json"}

    def _send_with_retries(
        self, method: str, url: str
    ) -> requests.Response:
        """Sends an HTTP GET or POST request with rate limiting and retries."""
        attempt = 0
        while True:
            self._limiter.wait()
            try:
                if method == "POST":
                    resp = self._session.post(
                        url, headers=self._headers, timeout=self._timeout
                    )
                else:
                    resp = self._session.get(
                        url, headers=self._headers, timeout=self._timeout
                    )
            except requests.exceptions.RequestException as exc:
                failure = f"network error ({type(exc).__name__})"
                wait_seconds = BACKOFF_BASE_SECONDS * (2 ** attempt)
                rate_limited = False
            else:
                status = resp.status_code
                if status in (200, 404):
                    return resp
                elif status in (401, 403):
                    raise VTAuthError(
                        f"VirusTotal rejected the API key (HTTP {status}). Check VT_API_KEY in .env."
                    )
                elif status == 429:
                    code = _error_code(resp)
                    if code == "QuotaExceededError":
                        raise VTQuotaExceededError(
                            "VirusTotal quota exceeded (daily or monthly limit reached). Stop and try again later."
                        )
                    failure = "HTTP 429"
                    wait_seconds = _retry_after_seconds(resp)
                    rate_limited = True
                elif status >= 500:
                    failure = f"HTTP {status}"
                    wait_seconds = BACKOFF_BASE_SECONDS * (2 ** attempt)
                    rate_limited = False
                else:
                    code = _error_code(resp)
                    raise VTRequestError(
                        f"VirusTotal returned HTTP {status} ({code or 'no error code'})."
                    )

            if attempt >= self._max_retries:
                if rate_limited:
                    raise VTQuotaExceededError(
                        "VirusTotal keeps answering 'too many requests'. Lower VT_REQUESTS_PER_MINUTE or try again later."
                    )
                raise VTRequestError(
                    f"VirusTotal request failed after {attempt + 1} attempts ({failure})."
                )
            self._sleep(wait_seconds)
            attempt += 1

    def lookup(self, ioc_type: IocType, value: str) -> VTResult:
        """Triggers reanalysis (when enabled) and retrieves the VirusTotal verdict."""
        url = build_lookup_url(ioc_type, value)
        if self._reanalyze and hasattr(self._session, "post"):
            reanalyze_url = build_reanalyze_url(ioc_type, value)
            try:
                post_resp = self._send_with_retries("POST", reanalyze_url)
            except VTRequestError:
                post_resp = None

            if post_resp is not None:
                if post_resp.status_code == 404:
                    return VTResult(found=False)
                analysis_id = _extract_analysis_id(post_resp)
                if analysis_id is not None:
                    try:
                        analysis_url = build_analysis_url(analysis_id)
                    except ValueError:
                        analysis_url = None
                    if analysis_url is not None:
                        for _ in range(self._max_poll_attempts):
                            if self._poll_wait > 0:
                                self._sleep(self._poll_wait)
                            try:
                                poll_resp = self._send_with_retries(
                                    "GET", analysis_url
                                )
                            except VTRequestError:
                                break
                            if poll_resp.status_code == 200:
                                parsed = _parse_analysis_200(poll_resp)
                                if parsed is not None:
                                    return parsed

        resp = self._send_with_retries("GET", url)
        if resp.status_code == 404:
            return VTResult(found=False)
        return _parse_200(resp)
