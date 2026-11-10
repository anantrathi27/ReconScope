# ReconScope – Footprinting and Reconnaissance Dashboard

ReconScope is an academic cybersecurity project. Its purpose is:

> To collect, organize, correlate, and visualize reconnaissance information about an authorized target using multiple footprinting techniques.

It is a **reconnaissance** platform. It does not exploit systems, bypass authentication, or claim to find vulnerabilities.

> ⚠ Use this application only on systems you own or have explicit permission to assess.

## Features

| Module | Technique | Type |
|---|---|---|
| WHOIS | RDAP (HTTPS) with WHOIS fallback; registered-domain lookup | PASSIVE |
| DNS | A, AAAA, MX, NS, TXT, CNAME via dnspython (no shell) | PASSIVE |
| Technology | Signature matching on headers, cookies and HTML | PASSIVE* |
| Shodan | Host lookup against Shodan's index | PASSIVE |
| Wayback | Wayback Machine CDX API | PASSIVE |
| Nmap | Fixed TCP connect scan of 25 common ports + version detection | ACTIVE – AUTHORIZATION REQUIRED |

\*Technology profiling makes one normal HTTP GET to the target's homepage, like a browser visit.

Other features: SQLite storage, scan history, module status badges, Chart.js visualizations, action log (audit trail), and HTML / print-to-PDF reports.

## Safety design

- Server-side domain validation (strict regex)
- No shell execution: Nmap runs via `subprocess.run([...], shell=False)` with a fixed argument list
- Nmap scans the resolved, validated IP address, never raw user text
- Active scans require: an allowlisted target, passive recon completed first, and a confirmed authorization checkbox (all checked on the server)
- API key kept in `.env` (git-ignored), never logged or displayed
- Parameterised SQL only
- Rate limiting on recon and Nmap runs
- Every action is timestamped in the action log

## Requirements

- macOS (tested), Linux or Windows
- Python 3.10+
- Nmap (for the active module): https://nmap.org/download.html
- Optional: a Shodan API key

## Setup

```bash
git clone <your-repo-url> ReconScope
cd ReconScope
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env`:

```
SHODAN_API_KEY=your_key_here
SECRET_KEY=change-this-to-a-random-string
ACTIVE_SCAN_ALLOWLIST=scanme.nmap.org
```

`ACTIVE_SCAN_ALLOWLIST` is a comma-separated list of the only domains Nmap may scan. Add only targets you own or have written permission to test.

## Run

```bash
python app.py
```

Open http://127.0.0.1:5001 (port 5001 because macOS AirPlay uses 5000).

## Usage

1. Enter a domain and open the dashboard.
2. Click **Run Passive Recon**.
3. Optionally run the authorized **Nmap** scan (allowlisted target, box ticked).
4. Open **Reports** to view, download as HTML, or print to PDF.

Safe practice target for active scanning: `scanme.nmap.org` (provided by the Nmap project for testing).

## Project structure

```
ReconScope/
├── app.py                 Flask routes and workflow
├── config.py              Configuration from environment
├── db.py                  SQLite schema and queries
├── requirements.txt
├── .env.example
├── modules/
│   ├── common.py          Shared result format
│   ├── whois_module.py
│   ├── dns_module.py
│   ├── technology_module.py
│   ├── shodan_module.py
│   ├── wayback_module.py
│   └── nmap_module.py
├── templates/             base, index, dashboard, history, report, report_list
├── static/css, static/js  styles, dashboard.js, charts.js
├── database/recon.db      created on first run
└── reports/               exported HTML reports
```

## Limitations

See the project report. In short: technology detection is signature-based, Shodan free plans restrict host lookups, Nmap results cover only 25 ports, and observations are not proof of vulnerability.

## Disclaimer

Reconnaissance observations are not, by themselves, evidence of a security vulnerability. Use responsibly and legally.