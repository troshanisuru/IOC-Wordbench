"""Unit tests for VT verdict and scoring logic."""

from __future__ import annotations

import pytest

from vt_ioc_checker.verdict import (
    VendorStatus,
    Verdict,
    build_verdict,
    format_unix_utc,
)
from vt_ioc_checker.vt_client import VTResult


def make_result(
    stats: dict[str, int] | None = None,
    engines: dict[str, str] | None = None,
    date: int | None = None,
    found: bool = True,
) -> VTResult:
    """Helper to construct a VTResult with default empty dicts."""
    return VTResult(
        found=found,
        stats=stats or {},
        engine_results=engines or {},
        last_analysis_date=date,
    )


def test_not_found() -> None:
    v = build_verdict(VTResult(found=False))
    assert v.score == "Unknown"
    assert v.malicious_count is None
    assert v.total_engines is None
    assert v.vendor_status == VendorStatus.NOT_IN_VT
    assert v.vendor_category == ""
    assert v.last_analysis == ""


def test_sophos_malicious() -> None:
    stats = {
        "malicious": 5,
        "suspicious": 1,
        "harmless": 0,
        "undetected": 60,
        "timeout": 2,
        "type-unsupported": 4,
        "failure": 1,
    }
    engines = {"Sophos": "malicious", "Microsoft": "undetected"}
    v = build_verdict(make_result(stats=stats, engines=engines))
    assert v.score == "5/66"
    assert v.malicious_count == 5
    assert v.total_engines == 66
    assert v.vendor_status == VendorStatus.DETECTED
    assert v.vendor_category == "malicious"


def test_sophos_clean_others_malicious() -> None:
    stats = {"malicious": 40, "suspicious": 0, "harmless": 0, "undetected": 30}
    engines = {"Sophos": "undetected"}
    v = build_verdict(make_result(stats=stats, engines=engines))
    assert v.score == "40/70"
    assert v.vendor_status == VendorStatus.CLEAN
    assert v.vendor_category == "undetected"


def test_sophos_harmless() -> None:
    stats = {"malicious": 0, "harmless": 70, "undetected": 5}
    engines = {"Sophos": "harmless"}
    v = build_verdict(make_result(stats=stats, engines=engines))
    assert v.score == "0/75"
    assert v.vendor_status == VendorStatus.CLEAN
    assert v.vendor_category == "harmless"


def test_sophos_suspicious() -> None:
    engines = {"Sophos": "suspicious"}
    stats = {"suspicious": 1, "undetected": 70}
    v = build_verdict(make_result(stats=stats, engines=engines))
    assert v.vendor_status == VendorStatus.DETECTED
    assert v.vendor_category == "suspicious"
    assert v.score == "0/71"


def test_vendor_missing() -> None:
    stats = {"malicious": 3, "undetected": 60}
    engines = {"Microsoft": "malicious"}
    v = build_verdict(make_result(stats=stats, engines=engines))
    assert v.vendor_status == VendorStatus.NO_RESULT
    assert v.vendor_category == ""
    assert v.score == "3/63"


@pytest.mark.parametrize(
    "category",
    [
        "timeout",
        "type-unsupported",
        "failure",
        "confirmed-timeout",
        "",
        "something-new",
    ],
)
def test_vendor_no_usable_verdict(category: str) -> None:
    stats = {"undetected": 10}
    engines = {"Sophos": category}
    v = build_verdict(make_result(stats=stats, engines=engines))
    assert v.vendor_status == VendorStatus.NO_RESULT
    assert v.vendor_category == category


def test_vendor_name_matching() -> None:
    engines = {" SOPHOS ": "malicious"}
    stats = {"malicious": 1, "undetected": 1}
    v = build_verdict(make_result(stats=stats, engines=engines), vendor="sophos")
    assert v.vendor_status == VendorStatus.DETECTED


def test_other_vendor() -> None:
    engines = {"Sophos": "malicious", "CrowdStrike": "undetected"}
    stats = {"malicious": 1, "undetected": 1}
    v = build_verdict(
        make_result(stats=stats, engines=engines), vendor="CrowdStrike"
    )
    assert v.vendor_status == VendorStatus.CLEAN
    assert v.vendor_category == "undetected"


def test_found_without_analysis() -> None:
    v = build_verdict(VTResult(found=True))
    assert v.score == "Unknown"
    assert v.malicious_count is None
    assert v.total_engines is None
    assert v.vendor_status == VendorStatus.NO_RESULT
    assert v.vendor_category == ""


def test_zero_total_with_engines() -> None:
    stats: dict[str, int] = {}
    engines = {"Sophos": "undetected"}
    v = build_verdict(make_result(stats=stats, engines=engines))
    assert v.score == "Unknown"
    assert v.malicious_count is None
    assert v.vendor_status == VendorStatus.CLEAN


def test_category_case() -> None:
    engines = {"Sophos": "Malicious"}
    stats = {"malicious": 1, "undetected": 1}
    v = build_verdict(make_result(stats=stats, engines=engines))
    assert v.vendor_status == VendorStatus.DETECTED
    assert v.vendor_category == "malicious"


def test_multiple_matching_engines() -> None:
    engines = {"Sophos": "undetected", "sophos": "malicious"}
    stats = {"malicious": 1, "undetected": 1}
    v = build_verdict(make_result(stats=stats, engines=engines))
    assert v.vendor_status == VendorStatus.DETECTED


@pytest.mark.parametrize(
    ("input_val", "expected"),
    [
        (1700000000, "2023-11-14 22:13:20 UTC"),
        (None, ""),
        (True, ""),
        (10**20, ""),
    ],
)
def test_format_unix_utc(input_val: int | None, expected: str) -> None:
    assert format_unix_utc(input_val) == expected


def test_last_analysis_passthrough() -> None:
    v = build_verdict(make_result(date=1700000000))
    assert v.last_analysis == "2023-11-14 22:13:20 UTC"


def test_status_labels() -> None:
    assert VendorStatus.DETECTED.value == "Detected"
    assert VendorStatus.CLEAN.value == "Clean"
    assert VendorStatus.NOT_IN_VT.value == "Unknown"
    assert VendorStatus.NO_RESULT.value == "Unknown"


def test_empty_vendor_raises() -> None:
    with pytest.raises(ValueError):
        build_verdict(make_result(), vendor="  ")
