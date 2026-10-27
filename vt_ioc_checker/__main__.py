"""Command-line interface: connects settings, VirusTotal client, runner and report."""

from __future__ import annotations

import argparse
import re
import sys
import zipfile
from pathlib import Path
from typing import List, Optional

from vt_ioc_checker import __version__
from vt_ioc_checker.config import ConfigError, Settings, load_settings
from vt_ioc_checker.report import STATUS_ORDER, ReportWriteError
from vt_ioc_checker.runner import run_check
from vt_ioc_checker.verdict import DEFAULT_VENDOR
from vt_ioc_checker.vt_client import RateLimiter, VTClient

DEFAULT_OUTPUT_DIR = Path("data") / "output"
EXIT_OK = 0
EXIT_CONFIG = 2
EXIT_FILE = 3
EXIT_AUTH = 4
EXIT_QUOTA = 5
EXIT_LIMIT = 6
EXIT_ERROR = 7
EXIT_INTERRUPTED = 130

STOP_EXIT_CODES = {
    "": EXIT_OK,
    "auth": EXIT_AUTH,
    "quota": EXIT_QUOTA,
    "limit": EXIT_LIMIT,
    "interrupted": EXIT_INTERRUPTED,
    "error": EXIT_ERROR,
}


def _ascii(text: str) -> str:
    """Convert text to plain ASCII using backslash escapes."""
    return text.encode("ascii", "backslashreplace").decode("ascii")


def _slug(vendor: str) -> str:
    """Make a file-name-safe lowercase slug from a vendor name."""
    return re.sub(r"[^a-z0-9]+", "-", vendor.lower()).strip("-") or "vendor"


def _positive_int(text: str) -> int:
    """Argparse type: a whole number that is at least 1."""
    try:
        value = int(text)
    except ValueError:
        raise argparse.ArgumentTypeError("must be a whole number")
    if value < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return value


def _non_blank(text: str) -> str:
    """Argparse type: a non-empty string, stripped."""
    if not text.strip():
        raise argparse.ArgumentTypeError("must not be empty")
    return text.strip()


def default_client_factory(settings: Settings) -> VTClient:
    """Build the real VirusTotal client from settings."""
    return VTClient(settings.api_key, RateLimiter(settings.requests_per_minute))


def _build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="python -m vt_ioc_checker",
        description=(
            "Check IOCs on VirusTotal and report one vendor's verdict "
            "in an Excel file."
        ),
        epilog="Run the same command again to continue an unfinished report.",
    )
    parser.add_argument(
        "input", help="IOC list: .txt, .csv or .xlsx (first column)"
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        help=(
            "Report file (.xlsx). "
            "Default: data/output/<input name>_<vendor>_report.xlsx"
        ),
    )
    parser.add_argument(
        "--vendor",
        type=_non_blank,
        default=DEFAULT_VENDOR,
        help="Vendor whose verdict is reported (default: Sophos)",
    )
    parser.add_argument(
        "--max-lookups",
        type=_positive_int,
        default=None,
        help=(
            "Stop after this many VirusTotal lookups in one run "
            "(free key: about 500 per day)"
        ),
    )
    parser.add_argument(
        "--save-every",
        type=_positive_int,
        default=25,
        help="Save the report after every N lookups (default: 25)",
    )
    parser.add_argument(
        "--no-resume",
        action="store_true",
        help="Do not continue from an existing report (also needs --overwrite)",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow --no-resume to replace an existing report",
    )
    parser.add_argument(
        "--env-file",
        default=None,
        help="Path to the .env file (default: .env in the current folder)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"vt-ioc-checker {__version__}",
    )
    return parser


def main(
    argv: Optional[List[str]] = None,
    *,
    client_factory=None,
    stdout=None,
    stderr=None,
) -> int:
    """Run the command-line program and return the process exit code."""
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    def say(text: str) -> None:
        """Print one ASCII line to standard output."""
        print(_ascii(text), file=out, flush=True)

    def fail(text: str) -> None:
        """Print one ASCII error line to standard error."""
        print(_ascii("ERROR: " + text), file=err, flush=True)

    args = _build_parser().parse_args(argv)

    input_path = Path(args.input)
    if args.output:
        output_path = Path(args.output)
    else:
        output_path = (
            DEFAULT_OUTPUT_DIR
            / f"{input_path.stem}_{_slug(args.vendor)}_report.xlsx"
        )

    if output_path.resolve() == input_path.resolve():
        fail("Output file must be different from the input file.")
        return EXIT_FILE

    if args.no_resume and output_path.exists() and not args.overwrite:
        fail(
            f"Output file already exists: {output_path}. "
            "Add --overwrite to replace it, or remove --no-resume "
            "to continue from it."
        )
        return EXIT_FILE

    try:
        try:
            settings = load_settings(args.env_file)
        except ConfigError as exc:
            fail(str(exc))
            return EXIT_CONFIG

        client = (client_factory or default_client_factory)(settings)

        say(f"Vendor: {args.vendor} | Input: {input_path} | Output: {output_path}")

        try:
            summary = run_check(
                input_path,
                output_path,
                client,
                args.vendor,
                resume=not args.no_resume,
                max_lookups=args.max_lookups,
                save_every=args.save_every,
                log=say,
            )
        except KeyboardInterrupt:
            fail("Interrupted.")
            return EXIT_INTERRUPTED
        except UnicodeDecodeError:
            fail(
                "The input file is not valid UTF-8 text. "
                "Save it as UTF-8 and try again."
            )
            return EXIT_FILE
        except zipfile.BadZipFile:
            fail("An .xlsx file could not be read (is it a valid Excel file?).")
            return EXIT_FILE
        except (OSError, ValueError, ReportWriteError) as exc:
            fail(str(exc))
            return EXIT_FILE

        say(
            f"Unique IOCs: {summary.total_unique} "
            f"(duplicates removed: {summary.duplicates_removed})"
        )
        say(
            f"Looked up: {summary.looked_up} | "
            f"Reused from previous report: {summary.reused}"
        )
        for label in STATUS_ORDER:
            say(f"  {label}: {summary.counts[label]}")
        say(f"Report: {summary.report_path}")

        if summary.report_path != output_path:
            fail(
                f"The report could not be written to {output_path}. "
                f"Results were saved to {summary.report_path} instead."
            )

        if summary.stop_kind != "":
            if summary.stop_kind in ("auth", "quota", "error"):
                fail(f"Stopped early ({summary.stop_kind}): {summary.stop_reason}")
            elif summary.stop_kind in ("limit", "interrupted"):
                say(f"Stopped early ({summary.stop_kind}): {summary.stop_reason}")
            say("Finished IOCs are saved. Run the same command again to continue.")

        exit_code = STOP_EXIT_CODES[summary.stop_kind]
        if summary.report_path != output_path and exit_code == EXIT_OK:
            return EXIT_FILE
        return exit_code
    except Exception as exc:
        fail(f"Unexpected error ({type(exc).__name__}).")
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
