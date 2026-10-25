# vt-ioc-checker

vt-ioc-checker is a command-line security tool that reads bulk lists of indicators of compromise including IP addresses, domains, URLs, and file hashes. It queries each indicator against the VirusTotal API v3 while managing rate limits and retry logic. The tool evaluates detection verdicts from security engines including Sophos and exports a consolidated report to an Excel spreadsheet.

Status: under development

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
Copy `.env.example` to `.env` and configure your settings.
The VirusTotal API key goes in a local `.env` file and must never be committed.
