"""Reads IOC files and detects IOC type (IP, domain, URL, MD5, SHA1, SHA256)."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from enum import Enum
import ipaddress
from pathlib import Path
import re
import urllib.parse

import openpyxl

HEADER_NAMES = {
    "ioc",
    "iocs",
    "indicator",
    "indicators",
    "value",
    "values",
    "hash",
    "hashes",
    "ip",
    "ips",
    "domain",
    "domains",
    "url",
    "urls",
}

MAX_IOC_LENGTH = 8000

_MD5_REGEX = re.compile(r"^[0-9a-fA-F]{32}$")
_SHA1_REGEX = re.compile(r"^[0-9a-fA-F]{40}$")
_SHA256_REGEX = re.compile(r"^[0-9a-fA-F]{64}$")
_DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$",
    re.IGNORECASE,
)


class IocType(str, Enum):
    """Enumeration of supported IOC types and the invalid fallback."""

    IP = "IP"
    DOMAIN = "Domain"
    URL = "URL"
    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    INVALID = "Invalid"


@dataclass(frozen=True)
class IocEntry:
    """Represents an indicator of compromise with original and canonical values."""

    raw: str
    value: str
    ioc_type: IocType


@dataclass
class LoadResult:
    """Result of loading and deduplicating IOC entries from a file."""

    entries: list[IocEntry]
    total_read: int
    duplicates_removed: int

    @property
    def invalid_count(self) -> int:
        """Returns the number of entries with an INVALID type."""
        return sum(1 for e in self.entries if e.ioc_type == IocType.INVALID)


def refang(text: str) -> str:
    """Undoes common defanging patterns in an indicator string."""
    text = re.sub(re.escape("[://]"), "://", text, flags=re.IGNORECASE)
    text = re.sub(re.escape("[:]"), ":", text, flags=re.IGNORECASE)
    for token in ("[.]", "(.)", "{.}", "[dot]", "(dot)"):
        text = re.sub(re.escape(token), ".", text, flags=re.IGNORECASE)
    text = re.sub(
        r"^hxxp(s?)",
        lambda m: "http" + m.group(1).lower(),
        text,
        flags=re.IGNORECASE,
    )
    return text


def _is_valid_domain(candidate: str) -> bool:
    """Returns True if candidate matches the domain specification."""
    if candidate.endswith("."):
        candidate = candidate[:-1]
    return bool(_DOMAIN_REGEX.match(candidate))


def _is_valid_ipv4(candidate: str) -> bool:
    """Returns True if candidate is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(candidate)
        return True
    except ValueError:
        return False


def detect_ioc_type(value: str) -> IocType:
    """Detects the IOC type of a cleaned indicator value."""
    if not value or len(value) > MAX_IOC_LENGTH or any(c.isspace() for c in value):
        return IocType.INVALID

    if _MD5_REGEX.match(value):
        return IocType.MD5
    if _SHA1_REGEX.match(value):
        return IocType.SHA1
    if _SHA256_REGEX.match(value):
        return IocType.SHA256

    try:
        ipaddress.ip_address(value)
        return IocType.IP
    except ValueError:
        pass

    if value.lower().startswith(("http://", "https://", "ftp://")):
        try:
            parts = urllib.parse.urlsplit(value)
            host = parts.hostname
            if not host:
                return IocType.INVALID
            port = parts.port
            if port == 0:
                return IocType.INVALID
            if (
                ".." in host
                or host.startswith((".", "-"))
                or host.endswith((".", "-"))
            ):
                return IocType.INVALID
            return IocType.URL
        except ValueError:
            return IocType.INVALID

    if "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return IocType.INVALID
        except ValueError:
            pass

        host_part = value.split("/", 1)[0]
        port_match = re.search(r":(\d{1,5})$", host_part)
        if port_match:
            port_num = int(port_match.group(1))
            if port_num < 1 or port_num > 65535:
                return IocType.INVALID
            host_part = host_part[: port_match.start()]
        if _is_valid_domain(host_part) or _is_valid_ipv4(host_part):
            return IocType.URL
        return IocType.INVALID

    domain_candidate = value[:-1] if value.endswith(".") else value
    if _DOMAIN_REGEX.match(domain_candidate):
        return IocType.DOMAIN

    return IocType.INVALID


def make_entry(raw: str) -> IocEntry:
    """Normalizes an indicator and returns an IocEntry."""
    raw_clean = raw.strip()
    cleaned = raw_clean
    if len(cleaned) >= 2 and cleaned[0] in ('"', "'") and cleaned[0] == cleaned[-1]:
        cleaned = cleaned[1:-1].strip()
    cleaned = refang(cleaned)
    ioc_type = detect_ioc_type(cleaned)

    if ioc_type in (IocType.MD5, IocType.SHA1, IocType.SHA256):
        canonical = cleaned.lower()
    elif ioc_type == IocType.DOMAIN:
        canonical = cleaned.lower()
        if canonical.endswith("."):
            canonical = canonical[:-1]
    elif ioc_type == IocType.IP:
        canonical = str(ipaddress.ip_address(cleaned))
    elif ioc_type == IocType.URL:
        if cleaned.lower().startswith(("http://", "https://", "ftp://")):
            scheme_end = cleaned.find("://")
            canonical = cleaned[:scheme_end].lower() + cleaned[scheme_end:]
        else:
            canonical = "http://" + cleaned
    else:
        canonical = cleaned

    return IocEntry(raw=raw_clean, value=canonical, ioc_type=ioc_type)


def read_raw_values(path: str | Path) -> list[str]:
    """Reads and filters raw indicator strings from a supported input file."""
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Input file not found: {p}")

    suffix = p.suffix.lower()
    if suffix == ".txt":
        raw_lines = p.read_text(encoding="utf-8-sig").splitlines()
    elif suffix == ".csv":
        raw_lines = []
        try:
            with p.open("r", newline="", encoding="utf-8-sig") as f:
                reader = csv.reader(f)
                for row in reader:
                    if row:
                        raw_lines.append(row[0])
        except csv.Error:
            raise ValueError("The CSV file could not be parsed.") from None
    elif suffix == ".xlsx":
        raw_lines = []
        try:
            wb = openpyxl.load_workbook(p, read_only=True, data_only=True)
        except KeyError:
            raise ValueError(
                "An .xlsx file could not be read (is it a valid Excel file?)."
            ) from None
        try:
            sheet = wb.active
            if sheet is not None:
                for row in sheet.iter_rows(min_col=1, max_col=1, values_only=True):
                    if row and row[0] is not None:
                        raw_lines.append(str(row[0]))
        finally:
            wb.close()
    else:
        raise ValueError(f"Unsupported file type '{suffix}'. Use .txt, .csv or .xlsx")

    processed: list[str] = []
    for item in raw_lines:
        s = item.strip()
        if not s or s.startswith("#"):
            continue
        processed.append(s)

    if processed:
        first = processed[0]
        if len(first) >= 2 and first[0] in ('"', "'") and first[0] == first[-1]:
            first = first[1:-1].strip()
        if first.lower() in HEADER_NAMES:
            processed = processed[1:]

    return processed


def load_iocs(path: str | Path) -> LoadResult:
    """Loads, parses, and deduplicates IOCs from a file."""
    values = read_raw_values(path)
    total_read = len(values)
    seen_values: set[str] = set()
    entries: list[IocEntry] = []
    duplicates_removed = 0

    for raw in values:
        entry = make_entry(raw)
        if entry.value in seen_values:
            duplicates_removed += 1
        else:
            seen_values.add(entry.value)
            entries.append(entry)

    return LoadResult(
        entries=entries,
        total_read=total_read,
        duplicates_removed=duplicates_removed,
    )
