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
Copy `.env.example` to `.env` and set your VirusTotal API key (never commit `.env`):

```ini
VT_API_KEY=your_virustotal_api_key_here
VT_REQUESTS_PER_MINUTE=4
```

Environment variables exported in the shell take precedence over `.env`.

## Usage

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

Resume an interrupted or rate-limited run (re-run the exact same command):
```bash
python -m vt_ioc_checker data/input/iocs.txt
```

Start fresh and overwrite an existing report without resuming:
```bash
python -m vt_ioc_checker data/input/iocs.txt --no-resume --overwrite
```

### Command-Line Options

| Option | Description |
| :--- | :--- |
| `input` | Path to the input IOC file (`.txt`, `.csv`, or `.xlsx`). |
| `-o`, `--output` | Output Excel report path (`.xlsx`). Default: `data/output/<input_stem>_<vendor>_report.xlsx`. |
| `--vendor` | Security vendor whose verdict is reported (default: `Sophos`). |
| `--max-lookups` | Stop after performing this many VirusTotal API lookups in one run. |
| `--save-every` | Save intermediate progress to the report after every `N` lookups (default: `25`). |
| `--no-resume` | Do not reuse results from an existing output report (requires `--overwrite` if the file exists). |
| `--overwrite` | Allow `--no-resume` to replace an existing output report file. |
| `--env-file` | Path to the `.env` configuration file (default: `.env` in the current directory). |
| `--version` | Print the program version and exit. |

## Report Structure

The generated `.xlsx` workbook contains two sheets:

1. **`Results` sheet:**
   - `IOC`: Canonical indicator value (or raw string for `Invalid` entries).
   - `Type`: `IP`, `Domain`, `URL`, `MD5`, `SHA1`, `SHA256`, or `Invalid`.
   - `VT Score`: `<malicious>/<total>` engine count (or `Unknown`).
   - `VT Malicious`: Number of engines flagging the IOC as malicious.
   - `<Vendor> Status`:
     - `Detected`: Vendor categorized the IOC as `malicious` or `suspicious`.
     - `Clean`: Vendor categorized the IOC as `harmless` or `undetected`.
     - `No result`: IOC is in VirusTotal, but the selected vendor did not return a verdict (`timeout`, `type-unsupported`, missing, etc.).
     - `Unknown`: IOC was not found in VirusTotal (HTTP 404).
     - `Invalid`: Input string is not a valid supported IOC; not queried.
     - `Error`: Non-fatal request failure for this IOC (retried on resume).
     - `Not checked`: Run stopped before this IOC was queried (checked on resume).
   - `VT Last Analysis (UTC)`: Timestamp of VirusTotal's last analysis.
   - `Checked At (UTC)`: Timestamp when the tool queried the IOC.
   - `Note`: Additional context (e.g., `Not found in VirusTotal`, `Sophos verdict is suspicious (not malicious)`, or stop/error reason).

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

