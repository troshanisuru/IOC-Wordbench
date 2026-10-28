"""AbuseIPDB API v2 client, bulk IP runner, table formatter, and CSV exporter."""

from __future__ import annotations

import csv
from dataclasses import dataclass
import math
import os
from pathlib import Path
import re
import time
from typing import Any, Callable, Optional, Sequence
import urllib.parse

import requests

from vt_ioc_checker.ioc_parser import (
    IocEntry,
    IocType,
    make_entry,
    read_raw_values,
)
from vt_ioc_checker.vt_client import (
    BACKOFF_BASE_SECONDS,
    DEFAULT_MAX_RETRIES,
    DEFAULT_RATE_LIMIT_WAIT_SECONDS,
    DEFAULT_TIMEOUT_SECONDS,
    MAX_RETRY_AFTER_SECONDS,
    RateLimiter,
)

ABUSEIPDB_API_BASE = "https://api.abuseipdb.com/api/v2"
DEFAULT_MAX_AGE_DAYS = 90
MIN_MAX_AGE_DAYS = 1
MAX_MAX_AGE_DAYS = 365

STATUS_CHECKED = "Checked"
STATUS_INVALID = "Invalid"
STATUS_ERROR = "Error"
STATUS_NOT_CHECKED = "Not checked"

ABUSEIPDB_TABLE_HEADERS = ("IP", "Abuse Score", "Country", "Domain")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


class AbuseIPDBError(Exception):
    """Base exception for AbuseIPDB API client errors."""


class AbuseIPDBAuthError(AbuseIPDBError):
    """Fatal authentication error indicating an invalid or rejected AbuseIPDB API key."""


class AbuseIPDBQuotaExceededError(AbuseIPDBError):
    """Fatal quota error indicating AbuseIPDB daily quota or rate limit exhaustion."""


class AbuseIPDBRequestError(AbuseIPDBError):
    """Non-fatal request error affecting only the current IP address."""


class AbuseIPDBWriteError(AbuseIPDBError):
    """Raised when the AbuseIPDB CSV export file cannot be written."""


@dataclass(frozen=True)
class AbuseIPDBResult:
    """Represents the AbuseIPDB check result for a single IP indicator."""

    ip_address: str
    abuse_score: Optional[int] = None
    country: str = "Unknown"
    domain: str = "Unknown"
    isp: str = ""
    usage_type: str = ""
    total_reports: Optional[int] = None
    last_reported_at: str = ""
    is_public: Optional[bool] = None
    status: str = STATUS_CHECKED
    error: str = ""

    @property
    def abuse_score_text(self) -> str:
        """Returns the display string for the Abuse Score column."""
        if self.status == STATUS_CHECKED:
            if self.abuse_score is None:
                return "Unknown"
            return str(self.abuse_score)
        return self.status

    def to_table_row(self) -> tuple[str, str, str, str]:
        """Returns the 4-tuple (IP, Abuse Score, Country, Domain) for table/CSV output."""
        if self.status == STATUS_CHECKED:
            country_val = self.country if self.country else "Unknown"
            domain_val = self.domain if self.domain else "Unknown"
        else:
            country_val = self.country if self.country else "Unknown"
            domain_val = self.domain if self.domain else "Unknown"
        return (
            self.ip_address,
            self.abuse_score_text,
            country_val,
            domain_val,
        )


@dataclass(frozen=True)
class AbuseIPDBBulkSummary:
    """Summary metrics and results for an AbuseIPDB bulk check run."""

    rows: list[AbuseIPDBResult]
    total_unique: int
    duplicates_removed: int
    invalid: int
    checked: int
    errors: int
    stop_kind: str
    stop_reason: str
    csv_path: Optional[Path] = None

    @property
    def stopped_early(self) -> bool:
        """Returns True if the bulk check stopped before checking all valid IPs."""
        return self.stop_kind != ""


def build_abuseipdb_check_url(
    ip_address: str, max_age_in_days: int = DEFAULT_MAX_AGE_DAYS
) -> str:
    """Constructs the AbuseIPDB API v2 check endpoint URL with query parameters."""
    entry = make_entry(ip_address)
    if entry.ioc_type != IocType.IP:
        raise ValueError("AbuseIPDB only supports valid IPv4 or IPv6 addresses.")
    if max_age_in_days < MIN_MAX_AGE_DAYS or max_age_in_days > MAX_MAX_AGE_DAYS:
        raise ValueError(
            f"max_age_in_days must be between {MIN_MAX_AGE_DAYS} and {MAX_MAX_AGE_DAYS}."
        )
    query = urllib.parse.urlencode(
        {"ipAddress": entry.value, "maxAgeInDays": str(max_age_in_days)}
    )
    return f"{ABUSEIPDB_API_BASE}/check?{query}"


def _retry_after_seconds(resp: requests.Response) -> float:
    """Extracts and bounds the Retry-After header from an HTTP 429 response."""
    value = resp.headers.get("Retry-After")
    try:
        sec = float(value)  # type: ignore[arg-type]
        if not math.isfinite(sec):
            return DEFAULT_RATE_LIMIT_WAIT_SECONDS
        return max(1.0, min(sec, MAX_RETRY_AFTER_SECONDS))
    except (TypeError, ValueError):
        return DEFAULT_RATE_LIMIT_WAIT_SECONDS


def _error_detail(resp: requests.Response) -> str:
    """Extracts the first error detail string from an AbuseIPDB error response."""
    try:
        errors = resp.json().get("errors")
        if isinstance(errors, list) and errors:
            first = errors[0]
            if isinstance(first, dict) and first.get("detail"):
                return str(first["detail"])
    except (ValueError, KeyError, TypeError, AttributeError):
        pass
    return ""


def _parse_check_200(ip_address: str, resp: requests.Response) -> AbuseIPDBResult:
    """Parses an HTTP 200 response from the AbuseIPDB check endpoint."""
    try:
        data = resp.json()["data"]
    except (ValueError, KeyError, TypeError):
        raise AbuseIPDBRequestError(
            "Unexpected response from AbuseIPDB (could not read JSON)."
        )
    if not isinstance(data, dict):
        raise AbuseIPDBRequestError(
            "Unexpected response from AbuseIPDB (could not read JSON)."
        )

    raw_ip = data.get("ipAddress")
    canonical_ip = (
        str(raw_ip).strip()
        if isinstance(raw_ip, str) and raw_ip.strip()
        else ip_address
    )

    raw_score = data.get("abuseConfidenceScore")
    abuse_score: Optional[int] = None
    if isinstance(raw_score, int) and not isinstance(raw_score, bool):
        abuse_score = raw_score
    elif isinstance(raw_score, (float, str)):
        try:
            abuse_score = int(raw_score)
        except ValueError:
            abuse_score = None

    raw_country = data.get("countryCode")
    country = (
        str(raw_country).strip()
        if isinstance(raw_country, str) and raw_country.strip()
        else "Unknown"
    )

    raw_domain = data.get("domain")
    domain = (
        str(raw_domain).strip()
        if isinstance(raw_domain, str) and raw_domain.strip()
        else "Unknown"
    )

    raw_isp = data.get("isp")
    isp = str(raw_isp).strip() if isinstance(raw_isp, str) else ""

    raw_usage = data.get("usageType")
    usage_type = str(raw_usage).strip() if isinstance(raw_usage, str) else ""

    raw_reports = data.get("totalReports")
    total_reports: Optional[int] = (
        raw_reports
        if isinstance(raw_reports, int) and not isinstance(raw_reports, bool)
        else None
    )

    raw_last = data.get("lastReportedAt")
    last_reported_at = str(raw_last).strip() if isinstance(raw_last, str) else ""

    raw_public = data.get("isPublic")
    is_public: Optional[bool] = (
        raw_public if isinstance(raw_public, bool) else None
    )

    return AbuseIPDBResult(
        ip_address=canonical_ip,
        abuse_score=abuse_score,
        country=country,
        domain=domain,
        isp=isp,
        usage_type=usage_type,
        total_reports=total_reports,
        last_reported_at=last_reported_at,
        is_public=is_public,
        status=STATUS_CHECKED,
    )


class AbuseIPDBClient:
    """Client for AbuseIPDB API v2 with rate limiting and exponential retries."""

    def __init__(
        self,
        api_key: str,
        limiter: RateLimiter,
        session: Optional[requests.Session] = None,
        sleep: Callable[[float], None] = time.sleep,
        max_retries: int = DEFAULT_MAX_RETRIES,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_age_in_days: int = DEFAULT_MAX_AGE_DAYS,
    ) -> None:
        if not api_key or not api_key.strip():
            raise ValueError("api_key must not be empty.")
        if (
            max_age_in_days < MIN_MAX_AGE_DAYS
            or max_age_in_days > MAX_MAX_AGE_DAYS
        ):
            raise ValueError(
                f"max_age_in_days must be between {MIN_MAX_AGE_DAYS} and {MAX_MAX_AGE_DAYS}."
            )
        self._limiter = limiter
        self._session = session if session is not None else requests.Session()
        self._sleep = sleep
        self._max_retries = max_retries
        self._timeout = timeout
        self._max_age_in_days = max_age_in_days
        self._headers = {
            "Key": api_key.strip(),
            "Accept": "application/json",
        }

    def check_ip(
        self,
        ip_address: str,
        max_age_in_days: Optional[int] = None,
    ) -> AbuseIPDBResult:
        """Queries AbuseIPDB for a single IPv4 or IPv6 address."""
        age = (
            max_age_in_days
            if max_age_in_days is not None
            else self._max_age_in_days
        )
        url = build_abuseipdb_check_url(ip_address, age)
        canonical_ip = make_entry(ip_address).value

        attempt = 0
        while True:
            self._limiter.wait()
            try:
                resp = self._session.get(
                    url, headers=self._headers, timeout=self._timeout
                )
            except requests.exceptions.RequestException as exc:
                failure = f"network error ({type(exc).__name__})"
                wait_seconds = BACKOFF_BASE_SECONDS * (2 ** attempt)
                rate_limited = False
            else:
                status = resp.status_code
                if status == 200:
                    return _parse_check_200(canonical_ip, resp)
                elif status in (401, 403):
                    raise AbuseIPDBAuthError(
                        f"AbuseIPDB rejected the API key (HTTP {status}). Check ABUSEIPDB_API_KEY in .env."
                    )
                elif status == 429:
                    detail = _error_detail(resp)
                    if "daily rate limit" in detail.lower():
                        raise AbuseIPDBQuotaExceededError(
                            "AbuseIPDB daily quota exceeded. Stop and try again later."
                        )
                    failure = "HTTP 429"
                    wait_seconds = _retry_after_seconds(resp)
                    rate_limited = True
                elif status >= 500:
                    failure = f"HTTP {status}"
                    wait_seconds = BACKOFF_BASE_SECONDS * (2 ** attempt)
                    rate_limited = False
                else:
                    detail = _error_detail(resp)
                    raise AbuseIPDBRequestError(
                        f"AbuseIPDB returned HTTP {status} ({detail or 'request error'})."
                    )

            if attempt >= self._max_retries:
                if rate_limited:
                    raise AbuseIPDBQuotaExceededError(
                        "AbuseIPDB keeps answering 'too many requests'. Lower ABUSEIPDB_REQUESTS_PER_MINUTE or try again later."
                    )
                raise AbuseIPDBRequestError(
                    f"AbuseIPDB request failed after {attempt + 1} attempts ({failure})."
                )
            self._sleep(wait_seconds)
            attempt += 1


def _clean_csv_cell(text: str) -> str:
    """Strips control characters and guards against spreadsheet formula injection."""
    cleaned = _CONTROL_CHAR_RE.sub("", text)
    if cleaned.startswith(("=", "+", "-", "@", "\t", "\r")):
        return "'" + cleaned
    return cleaned


def format_abuseipdb_table(rows: Sequence[AbuseIPDBResult]) -> str:
    """Formats AbuseIPDB results as an aligned ASCII table (IP, Abuse Score, Country, Domain)."""
    table_rows = [r.to_table_row() for r in rows]
    widths = [len(h) for h in ABUSEIPDB_TABLE_HEADERS]
    for row in table_rows:
        for idx, cell in enumerate(row):
            widths[idx] = max(widths[idx], len(_CONTROL_CHAR_RE.sub("", cell)))

    def _fmt_row(items: Sequence[str]) -> str:
        parts = [
            _CONTROL_CHAR_RE.sub("", item).ljust(widths[i])
            for i, item in enumerate(items)
        ]
        return "| " + " | ".join(parts) + " |"

    separator = "+-" + "-+-".join("-" * w for w in widths) + "-+"
    lines = [
        separator,
        _fmt_row(ABUSEIPDB_TABLE_HEADERS),
        separator,
    ]
    for row in table_rows:
        lines.append(_fmt_row(row))
    lines.append(separator)
    return "\n".join(lines)


def write_abuseipdb_csv(
    path: str | Path, rows: Sequence[AbuseIPDBResult]
) -> Path:
    """Exports AbuseIPDB results to a UTF-8 CSV file with columns IP, Abuse Score, Country, Domain."""
    p = Path(path)
    if p.suffix.lower() != ".csv":
        raise ValueError("CSV output file must end with .csv")

    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f"{p.stem}.partial{p.suffix}")
    try:
        with tmp.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(ABUSEIPDB_TABLE_HEADERS)
            for r in rows:
                ip_val, score_val, country_val, domain_val = r.to_table_row()
                writer.writerow(
                    [
                        _clean_csv_cell(ip_val),
                        _clean_csv_cell(score_val),
                        _clean_csv_cell(country_val),
                        _clean_csv_cell(domain_val),
                    ]
                )
        os.replace(tmp, p)
    except PermissionError:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise AbuseIPDBWriteError(
            f"Cannot write the CSV file. If it is open in another program, close it and run again: {p}"
        ) from None
    except OSError as exc:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise AbuseIPDBWriteError(
            f"Cannot write the CSV file ({type(exc).__name__}): {p}"
        ) from None
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise

    return p


def read_abuseipdb_csv(path: str | Path) -> list[AbuseIPDBResult]:
    """Reads an exported AbuseIPDB CSV file back into AbuseIPDBResult objects."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"CSV file not found: {p}")

    with p.open("r", newline="", encoding="utf-8-sig") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            raise ValueError("File is not an AbuseIPDB CSV report.")
        if tuple(header[:4]) != ABUSEIPDB_TABLE_HEADERS:
            raise ValueError("File is not an AbuseIPDB CSV report.")

        results: list[AbuseIPDBResult] = []
        for row in reader:
            if not row or all(not c.strip() for c in row):
                continue
            while len(row) < 4:
                row.append("")
            ip_val, score_text, country_val, domain_val = (
                row[0],
                row[1],
                row[2],
                row[3],
            )
            score_int: Optional[int] = None
            status = STATUS_CHECKED
            try:
                score_int = int(score_text)
            except ValueError:
                if score_text in (STATUS_INVALID, STATUS_ERROR, STATUS_NOT_CHECKED):
                    status = score_text
                else:
                    status = STATUS_CHECKED
            results.append(
                AbuseIPDBResult(
                    ip_address=ip_val,
                    abuse_score=score_int,
                    country=country_val or "Unknown",
                    domain=domain_val or "Unknown",
                    status=status,
                )
            )
        return results


def run_abuseipdb_bulk_items(
    raw_items: Sequence[str],
    client: Any,
    *,
    max_age_in_days: int = DEFAULT_MAX_AGE_DAYS,
    max_lookups: Optional[int] = None,
    csv_output_path: Optional[str | Path] = None,
    log: Optional[Callable[[str], None]] = None,
    on_result: Optional[Callable[[int, int, AbuseIPDBResult], None]] = None,
) -> AbuseIPDBBulkSummary:
    """Runs an AbuseIPDB bulk IP check over raw indicator strings."""
    if max_lookups is not None and max_lookups < 1:
        raise ValueError("max_lookups must be at least 1.")
    if (
        max_age_in_days < MIN_MAX_AGE_DAYS
        or max_age_in_days > MAX_MAX_AGE_DAYS
    ):
        raise ValueError(
            f"max_age_in_days must be between {MIN_MAX_AGE_DAYS} and {MAX_MAX_AGE_DAYS}."
        )

    seen_values: set[str] = set()
    entries: list[IocEntry] = []
    duplicates_removed = 0

    for raw in raw_items:
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        entry = make_entry(s)
        key = entry.value if entry.ioc_type == IocType.IP else entry.raw
        if key in seen_values:
            duplicates_removed += 1
        else:
            seen_values.add(key)
            entries.append(entry)

    results: list[Optional[AbuseIPDBResult]] = [None] * len(entries)
    for i, entry in enumerate(entries):
        if entry.ioc_type != IocType.IP:
            results[i] = AbuseIPDBResult(
                ip_address=entry.raw,
                abuse_score=None,
                country="Unknown",
                domain="Unknown",
                status=STATUS_INVALID,
                error="Not a valid IP address",
            )

    pending = [i for i, r in enumerate(results) if r is None]
    _log = log if log is not None else (lambda msg: None)

    checked = 0
    errors = 0
    stop_kind = ""
    stop_reason = ""

    try:
        for position, i in enumerate(pending, start=1):
            entry = entries[i]
            if max_lookups is not None and checked >= max_lookups:
                stop_kind = "limit"
                stop_reason = (
                    f"Reached the lookup limit for this run ({max_lookups})."
                )
                _log(f"STOPPED: {stop_reason}")
                break

            checked += 1
            try:
                res = client.check_ip(
                    entry.value, max_age_in_days=max_age_in_days
                )
            except AbuseIPDBRequestError as exc:
                errors += 1
                row = AbuseIPDBResult(
                    ip_address=entry.value,
                    abuse_score=None,
                    country="Unknown",
                    domain="Unknown",
                    status=STATUS_ERROR,
                    error=str(exc),
                )
                results[i] = row
                _log(f"[{position}/{len(pending)}] {entry.value} -> ERROR: {exc}")
                if on_result is not None:
                    on_result(position, len(pending), row)
            except (AbuseIPDBAuthError, AbuseIPDBQuotaExceededError) as exc:
                stop_kind = (
                    "auth" if isinstance(exc, AbuseIPDBAuthError) else "quota"
                )
                stop_reason = str(exc)
                _log(f"STOPPED: {stop_reason}")
                break
            except KeyboardInterrupt:
                stop_kind = "interrupted"
                stop_reason = "Interrupted by user (Ctrl+C)."
                _log(f"STOPPED: {stop_reason}")
                break
            except Exception as exc:
                stop_kind = "error"
                stop_reason = f"Unexpected error ({type(exc).__name__})."
                _log(f"STOPPED: {stop_reason}")
                break
            else:
                results[i] = res
                _log(
                    f"[{position}/{len(pending)}] {res.ip_address} -> score {res.abuse_score_text}, country {res.country}, domain {res.domain}"
                )
                if on_result is not None:
                    on_result(position, len(pending), res)
    except KeyboardInterrupt:
        if stop_kind == "":
            stop_kind = "interrupted"
            stop_reason = "Interrupted by user (Ctrl+C)."
            _log(f"STOPPED: {stop_reason}")

    final_rows: list[AbuseIPDBResult] = []
    for res, entry in zip(results, entries):
        if res is not None:
            final_rows.append(res)
        else:
            final_rows.append(
                AbuseIPDBResult(
                    ip_address=entry.value,
                    abuse_score=None,
                    country="Unknown",
                    domain="Unknown",
                    status=STATUS_NOT_CHECKED,
                    error=stop_reason or "Run stopped before this IP was checked",
                )
            )

    written_csv: Optional[Path] = None
    if csv_output_path is not None:
        written_csv = write_abuseipdb_csv(csv_output_path, final_rows)

    invalid_count = sum(1 for r in final_rows if r.status == STATUS_INVALID)
    return AbuseIPDBBulkSummary(
        rows=final_rows,
        total_unique=len(entries),
        duplicates_removed=duplicates_removed,
        invalid=invalid_count,
        checked=checked,
        errors=errors,
        stop_kind=stop_kind,
        stop_reason=stop_reason,
        csv_path=written_csv,
    )


def run_abuseipdb_bulk(
    input_path: str | Path,
    client: Any,
    *,
    max_age_in_days: int = DEFAULT_MAX_AGE_DAYS,
    max_lookups: Optional[int] = None,
    csv_output_path: Optional[str | Path] = None,
    log: Optional[Callable[[str], None]] = None,
    on_result: Optional[Callable[[int, int, AbuseIPDBResult], None]] = None,
) -> AbuseIPDBBulkSummary:
    """Reads an input file (.txt, .csv, .xlsx) and runs an AbuseIPDB bulk IP check."""
    raw_values = read_raw_values(input_path)
    return run_abuseipdb_bulk_items(
        raw_values,
        client,
        max_age_in_days=max_age_in_days,
        max_lookups=max_lookups,
        csv_output_path=csv_output_path,
        log=log,
        on_result=on_result,
    )

