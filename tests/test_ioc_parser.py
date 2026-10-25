from __future__ import annotations

from pathlib import Path

import openpyxl
import pytest

from vt_ioc_checker.ioc_parser import (
    IocType,
    detect_ioc_type,
    load_iocs,
    make_entry,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("44d88612fea8a8f36de82e1278abb02f", IocType.MD5),
        ("44D88612FEA8A8F36DE82E1278ABB02F", IocType.MD5),
        ("3395856ce81f2b7382dee72602f798b642f14140", IocType.SHA1),
        (
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            IocType.SHA256,
        ),
        ("8.8.8.8", IocType.IP),
        ("2001:db8::1", IocType.IP),
        ("::1", IocType.IP),
        ("example.com", IocType.DOMAIN),
        ("EXAMPLE.COM", IocType.DOMAIN),
        ("sub.evil-site.co.uk", IocType.DOMAIN),
        ("xn--80ak6aa92e.com", IocType.DOMAIN),
        ("example.com.", IocType.DOMAIN),
        ("http://evil.com/a.exe", IocType.URL),
        ("https://evil.com", IocType.URL),
        ("HTTPS://Evil.com/Path", IocType.URL),
        ("ftp://1.2.3.4/file", IocType.URL),
        ("http://1.2.3.4:8080/x", IocType.URL),
        ("evil.com/path/file.exe", IocType.URL),
        ("1.2.3.4/path", IocType.URL),
        ("evil.com:8080/x", IocType.URL),
        ("", IocType.INVALID),
        ("256.1.1.1", IocType.INVALID),
        ("1.2.3", IocType.INVALID),
        ("localhost", IocType.INVALID),
        ("-bad.com", IocType.INVALID),
        ("a..com", IocType.INVALID),
        ("evil.c", IocType.INVALID),
        ("evil.com is bad", IocType.INVALID),
        ("http://", IocType.INVALID),
        ("http:///x", IocType.INVALID),
        ("javascript:alert(1)", IocType.INVALID),
        ("10.0.0.0/8", IocType.INVALID),
        ("/etc/passwd", IocType.INVALID),
        ("44d88612fea8a8f36de82e1278abb02", IocType.INVALID),
        ("g4d88612fea8a8f36de82e1278abb02f", IocType.INVALID),
    ],
)
def test_detect_ioc_type(value: str, expected: IocType) -> None:
    assert detect_ioc_type(value) == expected


@pytest.mark.parametrize(
    ("raw", "expected_value", "expected_type"),
    [
        ("1.2.3[.]4", "1.2.3.4", IocType.IP),
        ("evil(.)com", "evil.com", IocType.DOMAIN),
        ("evil[dot]com", "evil.com", IocType.DOMAIN),
        ("EVIL{.}COM", "evil.com", IocType.DOMAIN),
        ("hxxps://evil[.]com/x", "https://evil.com/x", IocType.URL),
        ("hXXp://evil[.]com/a", "http://evil.com/a", IocType.URL),
        ("hxxp[:]//evil[.]com", "http://evil.com", IocType.URL),
        ("hxxp[://]evil[.]com/a", "http://evil.com/a", IocType.URL),
        ('"EVIL.com"', "evil.com", IocType.DOMAIN),
        ("'8.8.8.8'", "8.8.8.8", IocType.IP),
        (
            "  44D88612FEA8A8F36DE82E1278ABB02F  ",
            "44d88612fea8a8f36de82e1278abb02f",
            IocType.MD5,
        ),
        ("2001:DB8:0:0:0:0:0:1", "2001:db8::1", IocType.IP),
        ("example.com.", "example.com", IocType.DOMAIN),
        ("http://Evil.com/Path", "http://Evil.com/Path", IocType.URL),
    ],
)
def test_make_entry(raw: str, expected_value: str, expected_type: IocType) -> None:
    entry = make_entry(raw)
    assert entry.value == expected_value
    assert entry.ioc_type == expected_type


def test_make_entry_raw_preservation() -> None:
    assert make_entry("  hxxp://evil[.]com  ").raw == "hxxp://evil[.]com"


def test_load_txt_bom_crlf(tmp_path: Path) -> None:
    text = (
        "\ufeffIOC\r\n# comment\r\n\r\n8.8.8.8\r\nEVIL.com\r\nevil[.]com\r\n"
        "44d88612fea8a8f36de82e1278abb02f\r\nnot an ioc\r\n"
    )
    file_path = tmp_path / "list.txt"
    file_path.write_bytes(text.encode("utf-8"))
    res = load_iocs(file_path)
    assert res.total_read == 5
    assert res.duplicates_removed == 1
    assert len(res.entries) == 4
    assert res.invalid_count == 1
    assert [e.value for e in res.entries] == [
        "8.8.8.8",
        "evil.com",
        "44d88612fea8a8f36de82e1278abb02f",
        "not an ioc",
    ]
    assert res.entries[1].raw == "EVIL.com"
    assert len(res.entries) + res.duplicates_removed == res.total_read


def test_load_csv(tmp_path: Path) -> None:
    csv_text = (
        'ioc,comment\n8.8.8.8,dns\n"http://evil.com/a,b",url with comma\nevil.com,\n,\n'
    )
    file_path = tmp_path / "list.csv"
    file_path.write_text(csv_text, encoding="utf-8")
    res = load_iocs(file_path)
    assert [e.value for e in res.entries] == [
        "8.8.8.8",
        "http://evil.com/a,b",
        "evil.com",
    ]
    assert [e.ioc_type for e in res.entries] == [
        IocType.IP,
        IocType.URL,
        IocType.DOMAIN,
    ]


def test_load_xlsx(tmp_path: Path) -> None:
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.append(["Indicator", "Notes"])
    ws.append(["8.8.8.8", "x"])
    ws.append([None, "blank"])
    ws.append(["evil.com"])
    ws.append(["EVIL.COM"])
    file_path = tmp_path / "list.xlsx"
    wb.save(file_path)
    wb.close()

    res = load_iocs(file_path)
    assert res.total_read == 3
    assert res.duplicates_removed == 1
    assert [e.value for e in res.entries] == ["8.8.8.8", "evil.com"]
    file_path.unlink()


def test_unsupported_extension(tmp_path: Path) -> None:
    for ext in ("list.xls", "list.pdf"):
        p = tmp_path / ext
        p.touch()
        with pytest.raises(ValueError, match="Unsupported"):
            load_iocs(p)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        load_iocs(tmp_path / "nope.txt")


def test_empty_file(tmp_path: Path) -> None:
    p = tmp_path / "list.txt"
    p.touch()
    res = load_iocs(p)
    assert res.entries == []
    assert res.total_read == 0
    assert res.duplicates_removed == 0


def test_uppercase_extension(tmp_path: Path) -> None:
    p = tmp_path / "LIST.TXT"
    p.write_text("8.8.8.8\n", encoding="utf-8")
    res = load_iocs(p)
    assert len(res.entries) == 1
    assert res.entries[0].value == "8.8.8.8"
