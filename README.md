# vt-ioc-checker

`vt-ioc-checker` is a command-line security tool that reads bulk lists of Indicators of Compromise (IP addresses, domains, URLs, and MD5/SHA1/SHA256 file hashes), queries each indicator against the VirusTotal API v3 with rate limiting and automatic retries, evaluates a target security vendor's verdict (default: `Sophos`), and exports a formatted Excel (`.xlsx`) report with safe resumption.

## Features

- **Supported IOC types:** IPv4/IPv6 addresses, domains, URLs (`http`, `https`, `ftp`, and schemeless URLs), and file hashes (`MD5`, `SHA1`, `SHA256`).
- **Automatic normalization & refanging:** Converts defanged indicators (`hxxp://`, `hxxps://`, `[.]`, `(.)`, `{.}`, `[dot]`, `[:]`, `[://]`) and removes duplicates before querying VirusTotal.
- **Input formats:** `.txt` (one IOC per line, `#` comments ignored), `.csv` (first column), and `.xlsx` (first column of the active sheet). Common header rows (`ioc`, `indicator`, `hash`, `ip`, `domain`, `url`, etc.) are skipped automatically.
- **Rate limiting & retries:** Configurable requests-per-minute limit (default: `4` RPM for the VirusTotal public API) with exponential backoff on network/5xx errors and `Retry-After` handling on HTTP 429 responses.
- **Safe resume & progress saving:** Periodically saves progress (default: every 25 lookups) and resumes unfinished runs by reusing completed rows (`Detected`, `Clean`, `No result`, `Unknown`) while re-checking `Error` and `Not checked` rows.
- **Locked-file protection:** Retries the final save if the report is open in Excel and falls back to a timestamped `.unsaved-YYYYMMDD-HHMMSS.xlsx` file so completed lookups are never lost.

## Setup

### Linux / macOS
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
```

### Windows (PowerShell)
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

### Configuration
Copy `.env.example` to `.env` and set your VirusTotal and/or AbuseIPDB API keys (never commit `.env`):

```ini
VT_API_KEY=your_virustotal_api_key_here
VT_REQUESTS_PER_MINUTE=4
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
ABUSEIPDB_REQUESTS_PER_MINUTE=60
```

Environment variables exported in the shell take precedence over `.env`.

## Desktop Application (GUI)

Launch the full native desktop application (clean blue-and-white enterprise user interface):

```bash
python run_desktop_app.py
```
or:
```bash
python -m vt_ioc_checker --gui
```

### Desktop App Features

- **VirusTotal IOC Analyzer:** Bulk analyze hashes, IPs, domains, and URLs with live progress, reanalysis controls, and one-click Excel export.
- **AbuseIPDB Bulk IP Check:** Check IP reputation scores, country, and domain with real-time counters and CSV export.
- **API Settings & Status Tab:** Enter, view, test, and save custom VirusTotal and AbuseIPDB API keys and rate limits directly within the app without editing `.env` manually. Includes instant connection testing and live status indicators.

## Standalone Installers & Executables (macOS, Linux, Windows)

You can package `IOC Workbench` as a standalone desktop application without requiring end users to install Python:

### 1. macOS Installation App (`.app`, `.zip`, & `.dmg` Installer)
Build the native macOS application bundle (`dist/IOC Workbench.app`), create the macOS installer archive (`dist/IOC-Workbench-macOS-Installer.zip` / `.dmg`), and install to `/Applications` (or `~/Applications`):
```bash
./installers/install_macos.sh
```

### 2. Linux Desktop App & Installer (`IOC-Workbench-Linux` & `.desktop`)
Build the standalone Linux binary (`dist/IOC-Workbench-Linux`), create the distributable installer tarball (`dist/IOC-Workbench-Linux-Installer.tar.gz`), and register the desktop launcher:
```bash
./installers/install_linux.sh
```

### 3. Windows Standalone Executable (`IOC-Workbench.exe`)
On Windows, run the batch builder to produce a single-file standalone GUI executable (`dist\IOC-Workbench.exe`):
```bat
installers\build_windows.bat
```

### Automated Multi-OS Builds (GitHub Actions)
The repository includes [`.github/workflows/build-installers.yml`](.github/workflows/build-installers.yml), which automatically builds:
- `IOC-Workbench-macOS-Installer` (`.dmg`)
- `IOC-Workbench-Linux-Installer` (`IOC-Workbench-Linux` + `.tar.gz` installer)
- `IOC-Workbench-Windows-Executable` (`IOC-Workbench.exe`)
on every push to `main` or version tag (`v*`).

## CLI Usage

```bash
python -m vt_ioc_checker <input_file> [options]
```

### Examples

Check an IOC list using the default vendor (`Sophos`) and default output path (`data/output/<input_stem>_<vendor>_report.xlsx`):
```bash
python -m vt_ioc_checker data/input/iocs.txt
```

Check an IOC list for a specific vendor (`Microsoft`) with a daily lookup cap of 200:
```bash
python -m vt_ioc_checker data/input/iocs.csv --vendor "Microsoft" --max-lookups 200 -o data/output/microsoft_report.xlsx
```

Run an **AbuseIPDB Bulk IP Check** (displays the results table with `IP`, `Abuse Score`, `Country`, `Domain` and optionally exports a `.csv` file):
```bash
python -m vt_ioc_checker data/input/ips.txt --abuseipdb --export-csv
```

Export AbuseIPDB results to a custom CSV path:
```bash
python -m vt_ioc_checker data/input/ips.txt --abuseipdb --csv data/output/abuse_results.csv
```

Resume an interrupted or rate-limited VirusTotal run (re-run the exact same command):
```bash
python -m vt_ioc_checker data/input/iocs.txt
```

Start fresh and overwrite an existing VirusTotal report without resuming:
```bash
python -m vt_ioc_checker data/input/iocs.txt --no-resume --overwrite
```

### Command-Line Options

| Option | Description |
| :--- | :--- |
| `input` | Path to the input IOC file (`.txt`, `.csv`, or `.xlsx`). Optional when `--gui` is specified. |
| `--gui` | Launch the desktop graphical user interface (Indicator Workbench). |
| `-o`, `--output` | Output path (`.xlsx` for VirusTotal, or `.csv` for `--abuseipdb`). Default for VT: `data/output/<input_stem>_<vendor>_report.xlsx`. |
| `--vendor` | Security vendor whose verdict is reported on VirusTotal (default: `Sophos`). |
| `--abuseipdb` | Run AbuseIPDB bulk IP check instead of VirusTotal and display the results table (`IP`, `Abuse Score`, `Country`, `Domain`). |
| `--export-csv` | Export AbuseIPDB results to `data/output/<input_stem>_abuseipdb_report.csv`. |
| `--csv` | Custom CSV output path (`.csv`) for AbuseIPDB results. |
| `--max-age` | Maximum report age in days for AbuseIPDB (`1`–`365`, default: `90`). |
| `--max-lookups` | Stop after performing this many API lookups in one run. |
| `--save-every` | Save intermediate progress to the VT Excel report after every `N` lookups (default: `25`). |
| `--no-resume` | Do not reuse results from an existing VT output report (requires `--overwrite` if the file exists). |
| `--overwrite` | Allow `--no-resume` to replace an existing VT output report file. |
| `--env-file` | Path to the `.env` configuration file (default: `.env` in the current directory). |
| `--version` | Print the program version and exit. |

## Report Structure

The generated `.xlsx` workbook contains two sheets:

1. **`Results` sheet (3 columns):**
   - `IOC`: Canonical indicator value (or raw string for `Invalid` entries).
   - `<Vendor> Status`:
     - `Detected`: Vendor categorized the IOC as `malicious` or `suspicious`.
     - `Clean`: Vendor categorized the IOC as `harmless` or `undetected`.
     - `Unknown`: IOC was not found in VirusTotal (HTTP 404) or the selected vendor did not return a verdict.
     - `Invalid`: Input string is not a valid supported IOC; not queried.
     - `Error`: Non-fatal request failure for this IOC (retried on resume).
     - `Not checked`: Run stopped before this IOC was queried (checked on resume).
   - `VT Score`: `<malicious>/<total>` engine count, or `Unknown` if the IOC is not available on VirusTotal.


2. **`Summary` sheet:**
   - Records the checked vendor, input filename, generation timestamp (UTC), total rows in report, duplicates removed, and per-status counts.

## Exit Codes

| Exit Code | Meaning |
| :--- | :--- |
| `0` | All valid IOCs were checked (or reused) and saved to the target report path. |
| `2` | Configuration or command-line argument error (e.g., missing `VT_API_KEY`). |
| `3` | Input/output file error (missing input, unsupported format, vendor/input mismatch on resume, or locked output file saved to `.unsaved-*.xlsx` fallback). |
| `4` | VirusTotal authentication error (HTTP 401/403). |
| `5` | VirusTotal quota or rate-limit exhaustion (HTTP 429). |
| `6` | Stopped early because `--max-lookups` was reached. |
| `7` | Stopped early due to an unexpected internal error. |
| `130` | Interrupted by user (`Ctrl+C`). |

## Testing

Run the test suite with `pytest`:

```bash
.venv/bin/pytest -q
```

