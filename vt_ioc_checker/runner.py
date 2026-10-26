"""Pipeline runner coordinating IOC lookup, progress saving, and resumption."""

from __future__ import annotations

import collections
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from vt_ioc_checker.ioc_parser import IocType, load_iocs
from vt_ioc_checker.report import (
    STATUS_CLEAN,
    STATUS_DETECTED,
    STATUS_ERROR,
    STATUS_INVALID,
    STATUS_NO_RESULT,
    STATUS_NOT_CHECKED,
    STATUS_ORDER,
    STATUS_UNKNOWN,
    ReportMeta,
    ReportRow,
    ReportWriteError,
    read_report_rows,
    write_report,
)
from vt_ioc_checker.verdict import DEFAULT_VENDOR, build_verdict
from vt_ioc_checker.vt_client import (
    VTAuthError,
    VTQuotaExceededError,
    VTRequestError,
)

DEFAULT_SAVE_EVERY = 25
GENERIC_STOP_NOTE = "Run stopped before this IOC was checked"
INVALID_NOTE = "Not a valid IOC; not looked up"
NOT_FOUND_NOTE = "Not found in VirusTotal"
INTERRUPTED_REASON = "Interrupted by user (Ctrl+C)."
REUSABLE_STATUSES = frozenset(
    {STATUS_DETECTED, STATUS_CLEAN, STATUS_NO_RESULT, STATUS_UNKNOWN}
)


@dataclass(frozen=True)
class RunSummary:
    """Summary metrics and termination status for an IOC check run."""

    total_unique: int
    duplicates_removed: int
    invalid: int
    reused: int
    looked_up: int
    counts: dict[str, int]
    stop_kind: str
    stop_reason: str
    report_path: Path

    @property
    def stopped_early(self) -> bool:
        """Returns True if the run was stopped before finishing all IOCs."""
        return self.stop_kind != ""


def run_check(
    input_path: str | Path,
    output_path: str | Path,
    client: Any,
    vendor: str = DEFAULT_VENDOR,
    *,
    resume: bool = True,
    max_lookups: Optional[int] = None,
    save_every: int = DEFAULT_SAVE_EVERY,
    now: Optional[Callable[[], datetime]] = None,
    log: Optional[Callable[[str], None]] = None,
) -> RunSummary:
    """Runs the IOC verification pipeline against VirusTotal."""
    if not vendor.strip():
        raise ValueError("vendor must not be empty.")
    if max_lookups is not None and max_lookups < 1:
        raise ValueError("max_lookups must be at least 1.")
    if save_every < 1:
        raise ValueError("save_every must be at least 1.")

    loaded = load_iocs(input_path)

    out = Path(output_path)
    previous: dict[str, ReportRow] = {}
    if resume and out.exists():
        for row in read_report_rows(out):
            if row.vendor_status in REUSABLE_STATUSES:
                previous[row.ioc] = row

    entries = loaded.entries
    results: list[Optional[ReportRow]] = [None] * len(entries)
    reused = 0
    for i, entry in enumerate(entries):
        if entry.ioc_type == IocType.INVALID:
            results[i] = ReportRow(
                ioc=entry.raw,
                ioc_type="Invalid",
                vt_score="",
                vt_malicious=None,
                vendor_status=STATUS_INVALID,
                note=INVALID_NOTE,
            )
        elif entry.value in previous:
            results[i] = previous[entry.value]
            reused += 1

    pending = [i for i, r in enumerate(results) if r is None]

    looked_up = 0
    stop_kind = ""
    stop_reason = ""
    stop_index: Optional[int] = None

    get_now = now if now is not None else (lambda: datetime.now(timezone.utc))
    _log = log if log is not None else (lambda msg: None)

    def _time_text() -> str:
        """Formats current timestamp string."""
        return get_now().strftime("%Y-%m-%d %H:%M:%S UTC")

    def _rows() -> list[ReportRow]:
        """Builds all report rows replacing pending slots with stop rows."""
        out_rows: list[ReportRow] = []
        for idx, (res, ent) in enumerate(zip(results, entries)):
            if res is not None:
                out_rows.append(res)
            else:
                if stop_kind in ("limit", "interrupted"):
                    note = stop_reason
                elif stop_kind != "" and idx == stop_index:
                    note = stop_reason
                else:
                    note = GENERIC_STOP_NOTE
                out_rows.append(
                    ReportRow(
                        ioc=ent.value,
                        ioc_type=ent.ioc_type.value,
                        vt_score="",
                        vt_malicious=None,
                        vendor_status=STATUS_NOT_CHECKED,
                        note=note,
                    )
                )
        return out_rows

    def _meta() -> ReportMeta:
        """Builds metadata describing the report."""
        return ReportMeta(
            vendor=vendor.strip(),
            input_name=Path(input_path).name,
            generated_at=_time_text(),
            duplicates_removed=loaded.duplicates_removed,
        )

    for position, i in enumerate(pending, start=1):
        entry = entries[i]
        if max_lookups is not None and looked_up >= max_lookups:
            stop_kind = "limit"
            stop_reason = f"Reached the lookup limit for this run ({max_lookups})."
            stop_index = i
            _log(f"STOPPED: {stop_reason}")
            break

        looked_up += 1
        try:
            result = client.lookup(entry.ioc_type, entry.value)
        except VTRequestError as exc:
            results[i] = ReportRow(
                ioc=entry.value,
                ioc_type=entry.ioc_type.value,
                vt_score="",
                vt_malicious=None,
                vendor_status=STATUS_ERROR,
                checked_at=_time_text(),
                note=str(exc),
            )
            _log(f"[{position}/{len(pending)}] {entry.value[:60]} -> ERROR: {exc}")
        except (VTAuthError, VTQuotaExceededError) as exc:
            stop_kind = "auth" if isinstance(exc, VTAuthError) else "quota"
            stop_reason = str(exc)
            stop_index = i
            _log(f"STOPPED: {stop_reason}")
            break
        except KeyboardInterrupt:
            stop_kind = "interrupted"
            stop_reason = INTERRUPTED_REASON
            stop_index = i
            _log(f"STOPPED: {stop_reason}")
            break
        except Exception as exc:
            stop_kind = "error"
            stop_reason = f"Unexpected error ({type(exc).__name__})."
            stop_index = i
            _log(f"STOPPED: {stop_reason}")
            break
        else:
            verdict = build_verdict(result, vendor)
            if verdict.vendor_status.value == "Unknown":
                note = NOT_FOUND_NOTE
            elif verdict.vendor_status.value == "No result":
                cat_part = (
                    f" ({verdict.vendor_category})"
                    if verdict.vendor_category
                    else ""
                )
                note = f"{vendor.strip()} gave no verdict{cat_part}"
            else:
                note = ""
            results[i] = ReportRow(
                ioc=entry.value,
                ioc_type=entry.ioc_type.value,
                vt_score=verdict.score,
                vt_malicious=verdict.malicious_count,
                vendor_status=verdict.vendor_status.value,
                vt_last_analysis=verdict.last_analysis,
                checked_at=_time_text(),
                note=note,
            )
            _log(
                f"[{position}/{len(pending)}] {entry.value[:60]} -> score {verdict.score}, {vendor.strip()} {verdict.vendor_status.value}"
            )

        if position < len(pending) and looked_up % save_every == 0:
            try:
                write_report(out, _rows(), _meta())
            except ReportWriteError:
                _log(
                    "Could not save progress (close the report if it is open in Excel); will retry."
                )

    write_report(out, _rows(), _meta())

    rows = _rows()
    counts = {
        label: sum(1 for r in rows if r.vendor_status == label)
        for label in STATUS_ORDER
    }
    return RunSummary(
        total_unique=len(entries),
        duplicates_removed=loaded.duplicates_removed,
        invalid=counts[STATUS_INVALID],
        reused=reused,
        looked_up=looked_up,
        counts=counts,
        stop_kind=stop_kind,
        stop_reason=stop_reason,
        report_path=out,
    )
