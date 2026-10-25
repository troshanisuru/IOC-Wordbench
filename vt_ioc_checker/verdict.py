"""Extracts the VT score and the Sophos status from a VT response."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from vt_ioc_checker.vt_client import VTResult

DEFAULT_VENDOR = "Sophos"
SCORE_UNKNOWN = "Unknown"
DETECTED_CATEGORIES = frozenset({"malicious", "suspicious"})
CLEAN_CATEGORIES = frozenset({"harmless", "undetected"})
SCORE_COUNTED_KEYS = ("malicious", "suspicious", "harmless", "undetected")


class VendorStatus(str, Enum):
    """Categorized status for a security vendor engine result."""

    DETECTED = "Detected"
    CLEAN = "Clean"
    NOT_IN_VT = "Unknown"
    NO_RESULT = "No result"


@dataclass(frozen=True)
class Verdict:
    """Summary verdict containing VT score, counts, vendor status, and timestamp."""

    score: str
    malicious_count: Optional[int]
    total_engines: Optional[int]
    vendor_status: VendorStatus
    vendor_category: str
    last_analysis: str


def format_unix_utc(timestamp: Optional[int]) -> str:
    """Formats a Unix epoch timestamp as a UTC date-time string."""
    if (
        timestamp is None
        or isinstance(timestamp, bool)
        or not isinstance(timestamp, int)
    ):
        return ""
    try:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return ""


def _vendor_status(
    engine_results: dict[str, str], vendor: str
) -> tuple[VendorStatus, str]:
    """Determines the vendor status and raw category for a specified vendor."""
    wanted = vendor.strip().casefold()
    matches = [
        str(category).strip().lower()
        for name, category in engine_results.items()
        if name.strip().casefold() == wanted
    ]
    for category in matches:
        if category in DETECTED_CATEGORIES:
            return (VendorStatus.DETECTED, category)
    for category in matches:
        if category in CLEAN_CATEGORIES:
            return (VendorStatus.CLEAN, category)
    return (VendorStatus.NO_RESULT, matches[0] if matches else "")


def build_verdict(result: VTResult, vendor: str = DEFAULT_VENDOR) -> Verdict:
    """Builds a Verdict summary from a VTResult and selected vendor."""
    if not vendor.strip():
        raise ValueError("vendor must not be empty.")
    if not result.found:
        return Verdict(SCORE_UNKNOWN, None, None, VendorStatus.NOT_IN_VT, "", "")
    total = sum(result.stats.get(key, 0) for key in SCORE_COUNTED_KEYS)
    if total > 0:
        malicious = result.stats.get("malicious", 0)
        score = f"{malicious}/{total}"
    else:
        malicious = None
        total = None
        score = SCORE_UNKNOWN
    status, category = _vendor_status(result.engine_results, vendor)
    return Verdict(
        score,
        malicious,
        total,
        status,
        category,
        format_unix_utc(result.last_analysis_date),
    )
