"""Unit tests for the command-line interface."""

from __future__ import annotations

import io
from pathlib import Path

import openpyxl
import pytest

from vt_ioc_checker.__main__ import default_client_factory, main
from vt_ioc_checker.config import Settings
from vt_ioc_checker.ioc_parser import IocType
from vt_ioc_checker.report import ReportWriteError, read_report_rows
from vt_ioc_checker.vt_client import (
    VTAuthError,
    VTClient,
    VTQuotaExceededError,
    VTResult,
)

KEY = "test-key-123456"
MALICIOUS = VTResult(
    True, {"malicious": 5, "undetected": 60}, {"Sophos": "malicious"}, 1700000000
)
CLEAN = VTResult(
    True,
    {"malicious": 40, "undetected": 30},
    {"Sophos": "undetected"},
    1700000000,
)
THREE = ["evil.com", "8.8.8.8", "example.com"]


class FakeClient:
    """Fake VirusTotal client for testing the CLI."""

    def __init__(self, results=None):
        self.results = results or {}
        self.calls = []

    def lookup(self, ioc_type, value):
        self.calls.append((ioc_type, value))
        item = self.results.get(value, VTResult(found=False))
        if isinstance(item, BaseException):
            raise item
        return item


@pytest.fixture(autouse=True)
def _isolate(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Remove settings env vars and work inside tmp_path."""
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("VT_REQUESTS_PER_MINUTE", raising=False)
    monkeypatch.chdir(tmp_path)


def write_list(tmp_path: Path, lines, name: str = "list.txt") -> Path:
    """Write an IOC list file and return its path."""
    path = tmp_path / name
    path.write_bytes(("\n".join(lines) + "\n").encode("utf-8"))
    return path


def make_env(tmp_path: Path) -> str:
    """Write a .env file with a test key and return its path."""
    path = tmp_path / ".env"
    path.write_text("VT_API_KEY=test-key-123456\n", encoding="utf-8")
    return str(path)


def run_cli(args, client=None):
    """Run main() with a fake client and captured streams."""
    out, err = io.StringIO(), io.StringIO()
    code = main(
        args,
        client_factory=lambda settings: client
        if client is not None
        else FakeClient(),
        stdout=out,
        stderr=err,
    )
    return code, out.getvalue(), err.getvalue()


def default_report(tmp_path: Path) -> Path:
    """Return the default report path for list.txt and Sophos."""
    return tmp_path / "data" / "output" / "list_sophos_report.xlsx"


def test_basic_run(tmp_path: Path) -> None:
    src = write_list(tmp_path, ["evil.com", "8.8.8.8", "not an ioc"])
    env = make_env(tmp_path)
    code, out, err = run_cli(
        [str(src), "--env-file", env],
        FakeClient({"evil.com": MALICIOUS, "8.8.8.8": CLEAN}),
    )
    assert code == 0
    assert default_report(tmp_path).exists()
    assert err == ""
    assert "Unique IOCs: 3 (duplicates removed: 0)" in out
    assert "Looked up: 2 | Reused from previous report: 0" in out
    assert "  Detected: 1" in out
    assert "  Clean: 1" in out
    assert "  Invalid: 1" in out
    assert "Report: " in out
    assert "list_sophos_report.xlsx" in out


def test_output_option(tmp_path: Path) -> None:
    src = write_list(tmp_path, THREE)
    env = make_env(tmp_path)
    custom = tmp_path / "custom.xlsx"
    code, out, err = run_cli([str(src), "--env-file", env, "-o", str(custom)])
    assert code == 0
    assert custom.exists()
    assert not (tmp_path / "data" / "output").exists()


def test_vendor_option(tmp_path: Path) -> None:
    src = write_list(tmp_path, THREE)
    env = make_env(tmp_path)
    code, out, err = run_cli(
        [str(src), "--env-file", env, "--vendor", "Microsoft"]
    )
    assert code == 0
    report = tmp_path / "data" / "output" / "list_microsoft_report.xlsx"
    assert report.exists()
    wb = openpyxl.load_workbook(report)
    assert wb["Results"]["B1"].value == "Microsoft Status"
    wb.close()


def test_vendor_slug(tmp_path: Path) -> None:
    src = write_list(tmp_path, THREE)
    env = make_env(tmp_path)
    code, out, err = run_cli(
        [str(src), "--env-file", env, "--vendor", "Trend Micro"]
    )
    assert code == 0
    assert (
        tmp_path / "data" / "output" / "list_trend-micro_report.xlsx"
    ).exists()


def test_missing_config(tmp_path: Path) -> None:
    src = write_list(tmp_path, THREE)

    def factory(settings):
        raise AssertionError("client factory must not be called")

    out, err = io.StringIO(), io.StringIO()
    code = main(
        [str(src), "--env-file", str(tmp_path / "nope.env")],
        client_factory=factory,
        stdout=out,
        stderr=err,
    )
    assert code == 2
    assert "VT_API_KEY is not set" in err.getvalue()
    assert out.getvalue() == ""


def test_api_key_never_printed(tmp_path: Path) -> None:
    src = write_list(tmp_path, THREE)
    env = make_env(tmp_path)
    code1, out1, err1 = run_cli([str(src), "--env-file", env])
    code2, out2, err2 = run_cli(
        [str(src), "--env-file", env, "-o", str(tmp_path / "auth.xlsx")],
        FakeClient({"evil.com": VTAuthError("auth failed")}),
    )
    for text in (out1, err1, out2, err2):
        assert KEY not in text


def test_input_missing(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    code, out, err = run_cli([str(tmp_path / "nope.txt"), "--env-file", env])
    assert code == 3
    assert "Input file not found" in err


def test_unsupported_extension(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    src = tmp_path / "list.pdf"
    src.write_bytes(b"")
    code, out, err = run_cli([str(src), "--env-file", env])
    assert code == 3
    assert "Unsupported file type" in err


def test_non_utf8_input(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    src = tmp_path / "list.txt"
    src.write_bytes(b"\xff\xfeA\x00")
    code, out, err = run_cli([str(src), "--env-file", env])
    assert code == 3
    assert "UTF-8" in err


def test_corrupt_xlsx(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    src = tmp_path / "list.xlsx"
    src.write_bytes(b"this is not a zip")
    code, out, err = run_cli([str(src), "--env-file", env])
    assert code == 3
    assert err.startswith("ERROR:")


def test_output_same_as_input(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    src = write_list(tmp_path, THREE)
    before = src.read_bytes()
    code, out, err = run_cli([str(src), "--env-file", env, "-o", str(src)])
    assert code == 3
    assert "different from the input" in err
    assert src.read_bytes() == before


def test_no_resume_requires_overwrite(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    src = write_list(tmp_path, THREE)
    code1, _, _ = run_cli([str(src), "--env-file", env])
    assert code1 == 0
    client2 = FakeClient()
    code2, out2, err2 = run_cli(
        [str(src), "--env-file", env, "--no-resume"], client2
    )
    assert code2 == 3
    assert "--overwrite" in err2
    assert client2.calls == []
    client3 = FakeClient()
    code3, out3, err3 = run_cli(
        [str(src), "--env-file", env, "--no-resume", "--overwrite"], client3
    )
    assert code3 == 0
    assert len(client3.calls) == 3


def test_resume_and_limit(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    src = write_list(tmp_path, THREE)
    code1, out1, err1 = run_cli(
        [str(src), "--env-file", env, "--max-lookups", "1"],
        FakeClient({"evil.com": MALICIOUS}),
    )
    assert code1 == 6
    assert (
        "Stopped early (limit): Reached the lookup limit for this run (1)."
        in out1
    )
    assert "Run the same command again to continue" in out1
    client2 = FakeClient({"8.8.8.8": CLEAN})
    code2, out2, err2 = run_cli([str(src), "--env-file", env], client2)
    assert code2 == 0
    assert client2.calls == [
        (IocType.IP, "8.8.8.8"),
        (IocType.DOMAIN, "example.com"),
    ]
    assert "Reused from previous report: 1" in out2


def test_quota_exit_code(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    src = write_list(tmp_path, THREE)
    code, out, err = run_cli(
        [str(src), "--env-file", env],
        FakeClient({"evil.com": VTQuotaExceededError("quota hit")}),
    )
    assert code == 5
    assert "Stopped early (quota): quota hit" in err
    assert default_report(tmp_path).exists()


def test_auth_exit_code(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    src = write_list(tmp_path, THREE)
    code, out, err = run_cli(
        [str(src), "--env-file", env],
        FakeClient({"evil.com": VTAuthError("auth failed")}),
    )
    assert code == 4
    assert "auth failed" in err


def test_interrupted_exit_code(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    src = write_list(tmp_path, THREE)
    code, out, err = run_cli(
        [str(src), "--env-file", env],
        FakeClient({"evil.com": MALICIOUS, "8.8.8.8": KeyboardInterrupt()}),
    )
    assert code == 130
    assert default_report(tmp_path).exists()
    assert "Stopped early (interrupted)" in out


def test_unexpected_error_exit_code(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    src = write_list(tmp_path, THREE)
    code, out, err = run_cli(
        [str(src), "--env-file", env],
        FakeClient({"evil.com": RuntimeError("boom")}),
    )
    assert code == 7
    assert "Unexpected error (RuntimeError)" in err
    assert "boom" not in out
    assert "boom" not in err


def test_non_ascii_output_is_safe(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    src = write_list(tmp_path, ["http://evil.com/caf\u00e9"])
    code, out, err = run_cli([str(src), "--env-file", env])
    assert code == 0
    assert out.isascii() is True
    assert r"caf\xe9" in out


@pytest.mark.parametrize(
    "extra",
    [
        ["--max-lookups", "0"],
        ["--max-lookups", "abc"],
        ["--save-every", "0"],
        ["--vendor", "  "],
    ],
)
def test_argument_validation(tmp_path: Path, extra) -> None:
    env = make_env(tmp_path)
    src = write_list(tmp_path, THREE)
    with pytest.raises(SystemExit) as excinfo:
        main([str(src)] + extra + ["--env-file", env])
    assert excinfo.value.code == 2


def test_version(capsys: pytest.CaptureFixture) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "0.1.0" in capsys.readouterr().out


def test_progress_lines_printed(tmp_path: Path) -> None:
    env = make_env(tmp_path)
    src = write_list(tmp_path, ["evil.com", "8.8.8.8"])
    code, out, err = run_cli([str(src), "--env-file", env])
    assert code == 0
    assert "[1/2] evil.com" in out


def test_report_write_error_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = make_env(tmp_path)
    src = write_list(tmp_path, THREE)

    def fail_write(path, rows, meta):
        raise ReportWriteError("locked")

    monkeypatch.setattr("vt_ioc_checker.runner.write_report", fail_write)
    code, out, err = run_cli([str(src), "--env-file", env])
    assert code == 3
    assert "locked" in err


def test_env_var_settings_reach_factory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("VT_API_KEY", "from-env")
    monkeypatch.setenv("VT_REQUESTS_PER_MINUTE", "10")
    src = write_list(tmp_path, THREE)
    seen = []

    def factory(settings):
        seen.append(settings)
        return FakeClient()

    out, err = io.StringIO(), io.StringIO()
    code = main([str(src)], client_factory=factory, stdout=out, stderr=err)
    assert code == 0
    assert len(seen) == 1
    assert isinstance(seen[0], Settings)
    assert seen[0].api_key == "from-env"
    assert seen[0].requests_per_minute == 10


def test_default_client_factory() -> None:
    client = default_client_factory(
        Settings(api_key="k-123", requests_per_minute=4)
    )
    assert isinstance(client, VTClient)


def test_missing_input_without_gui() -> None:
    """Invoking without input and without --gui returns EXIT_CONFIG."""
    out = io.StringIO()
    err = io.StringIO()
    code = main([], stdout=out, stderr=err)
    assert code == 2
    assert "the following arguments are required: input" in err.getvalue()


def test_cli_gui_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    """Invoking with --gui delegates to launch_gui."""
    launched = []
    monkeypatch.setattr("vt_ioc_checker.gui.launch_gui", lambda: launched.append(True))
    code = main(["--gui"])
    assert code == 0
    assert launched == [True]

