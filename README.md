<div align="center">

# 🔭 ReconScope

### Footprinting & Reconnaissance Dashboard

A web-based reconnaissance platform that collects, correlates, and visualizes intelligence about an authorized target using multiple OSINT techniques — all from a clean, interactive dashboard.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-lightgrey?style=flat-square&logo=flask)](https://flask.palletsprojects.com)
[![SQLite](https://img.shields.io/badge/Database-SQLite-003B57?style=flat-square&logo=sqlite)](https://sqlite.org)
[![License](https://img.shields.io/badge/License-Academic-green?style=flat-square)]()
[![Ethical](https://img.shields.io/badge/Use-Ethically%20%26%20Legally-red?style=flat-square)]()

</div>

---

> ⚠️ **Authorization Required** — Use ReconScope **only** on systems you own or have explicit written permission to assess. Unauthorized reconnaissance is illegal.

---

## 📖 What is ReconScope?

ReconScope is an **academic cybersecurity project** built for footprinting and passive/active reconnaissance. It aggregates data from multiple intelligence sources into one unified dashboard — giving you WHOIS records, DNS maps, detected technologies, Shodan-indexed services, historical Wayback snapshots, and authorized port scan results, all in one place.

It is **not** an exploitation tool. It does not bypass authentication or claim to find vulnerabilities — it collects and organizes publicly available reconnaissance data.

---

## ✨ Features at a Glance

| Module | What it does | Technique |
|---|---|---|
| 🌐 **WHOIS** | Registrar, registrant, dates, nameservers via RDAP + fallback | `PASSIVE` |
| 🗺️ **DNS** | A, AAAA, MX, NS, TXT, CNAME records via dnspython | `PASSIVE` |
| 🧪 **Technology** | Detects frameworks, servers, CMS from headers & HTML | `PASSIVE*` |
| 🛰️ **Shodan** | Indexed services & open ports from Shodan's database | `PASSIVE` |
| 📸 **Wayback** | Historical snapshots from the Wayback Machine CDX API | `PASSIVE` |
| ⚡ **Nmap** | TCP connect scan of 25 common ports + version detection | `ACTIVE ⚠️` |

> \*Technology profiling makes one normal HTTP GET to the target's homepage — equivalent to a browser visit.

**Additional capabilities:**
- 📊 Interactive **Chart.js** visualizations (DNS record breakdown, tech categories, Wayback status codes)
- 🗄️ **SQLite** persistent storage with full scan history
- 📋 **Audit log** — every action is timestamped and stored
- 📄 **HTML report export** (print-to-PDF ready)
- 🔒 Multi-layer safety controls (see [Safety Design](#-safety-design))

---

## 🖥️ Screenshots

> Dashboard → Run passive recon → View results → Export report

```
 ┌─────────────────────────────────────────────────────┐
 │  🔭 ReconScope              [History] [Reports]      │
 ├─────────────────────────────────────────────────────┤
 │  Target: example.com        IP: 93.184.216.34        │
 │  Status: ✅ Completed       Progress: ████████ 83%   │
 ├──────────┬──────────────────────────────────────────┤
 │  WHOIS ✅ │  DNS ✅ │  Tech ✅ │  Shodan ✅ │ Nmap ⏳ │
 ├──────────┴──────────────────────────────────────────┤
 │  [DNS Chart]   [Tech Chart]   [Wayback Timeline]     │
 └─────────────────────────────────────────────────────┘
```

---

## 🔒 Safety Design

ReconScope is built with strict safety controls at every layer:

| Control | Detail |
|---|---|
| **Domain validation** | Server-side strict regex — rejects IPs, paths, or malformed input |
| **No shell injection** | Nmap runs via `subprocess.run([...], shell=False)` with a fixed argument list |
| **IP-based scanning** | Nmap targets the resolved, validated IP — never raw user input |
| **Allowlist enforcement** | Active scans only run against domains explicitly listed in `ACTIVE_SCAN_ALLOWLIST` |
| **Passive-first workflow** | Active (Nmap) scans are blocked until passive recon is completed |
| **Authorization checkbox** | Server-side validation — the UI checkbox alone is never trusted |
| **Secret management** | API keys stored in `.env` (git-ignored), never logged or displayed |
| **Parameterized SQL** | All database queries use parameterized statements — no SQL injection |
| **Rate limiting** | 10s cooldown on passive recon, 30s on Nmap runs |
| **Audit trail** | Every action is timestamped and stored in the action log |

---

## 🏗️ Project Structure

```
ReconScope/
│
├── app.py                    # Flask routes, workflow orchestration
├── config.py                 # Environment-based configuration
├── db.py                     # SQLite schema, queries, storage helpers
├── requirements.txt          # Python dependencies
├── .env.example              # Environment variable template
│
├── modules/                  # Reconnaissance modules (each is isolated)
│   ├── common.py             #   Shared result format: {status, message, data}
│   ├── whois_module.py       #   RDAP + WHOIS fallback
│   ├── dns_module.py         #   DNS record resolution
│   ├── technology_module.py  #   Header/HTML technology fingerprinting
│   ├── shodan_module.py      #   Shodan host lookup
│   ├── wayback_module.py     #   Wayback Machine CDX API
│   └── nmap_module.py        #   Active TCP port scan (requires authorization)
│
├── templates/                # Jinja2 HTML templates
│   ├── base.html             #   Shared layout & navigation
│   ├── index.html            #   Landing / domain input page
│   ├── dashboard.html        #   Main recon results dashboard
│   ├── history.html          #   Past scans list
│   ├── report.html           #   Printable report view
│   └── report_list.html      #   Report selection page
│
├── static/
│   ├── css/style.css         # Custom styles
│   └── js/
│       ├── dashboard.js      # Dashboard interactivity
│       └── charts.js         # Chart.js visualizations
│
├── database/
│   └── recon.db              # SQLite database (auto-created on first run)
│
└── reports/                  # Exported HTML reports (git-ignored)
```

---

## ⚙️ Requirements

- **Python** 3.10 or higher
- **Nmap** (only required for the active scan module) → [Download here](https://nmap.org/download.html)
- **Shodan API key** (optional — free tier works) → [Get one here](https://account.shodan.io/register)
- macOS, Linux, or Windows

---

## 🚀 Setup & Installation

### 1. Clone the repository
```bash
git clone https://github.com/anantrathi27/ReconScope.git
cd ReconScope
```

### 2. Create a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate       # macOS / Linux
# venv\Scripts\activate        # Windows
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure environment variables
```bash
cp .env.example .env
```

Edit `.env` with your values:
```env
# Optional: get a free key at https://account.shodan.io
SHODAN_API_KEY=your_shodan_key_here

# Change this to any random string for Flask session security
SECRET_KEY=change-this-to-a-random-string

# Comma-separated list of domains you are authorized to actively scan
# Only these domains will be permitted for Nmap scanning
ACTIVE_SCAN_ALLOWLIST=scanme.nmap.org
```

### 5. Run the app
```bash
python app.py
```

Open your browser at **[http://127.0.0.1:5001](http://127.0.0.1:5001)**

> Port 5001 is used because macOS AirPlay Receiver occupies port 5000.

---

## 🧭 How to Use

```
Step 1 → Enter a domain on the home page
Step 2 → Click "Run Passive Recon" on the dashboard
Step 3 → Review results: WHOIS, DNS, Technologies, Shodan, Wayback
Step 4 → (Optional) Run authorized Nmap scan for open ports
Step 5 → Export an HTML report or print to PDF
```

**Safe testing target:** `scanme.nmap.org` — provided by the Nmap project for public testing.

---

## 📊 Workflow Diagram

```
   Enter Domain
       │
       ▼
  Validate Domain ──── ❌ Invalid ──▶ Reject + Flash Error
       │
       ✅ Valid
       │
       ▼
  Create Scan (SQLite)
       │
       ▼
  ┌────────────────────────────────┐
  │       PASSIVE RECON            │
  │  WHOIS → DNS → Tech            │
  │  Shodan → Wayback              │
  │  (modules run in isolation)    │
  └────────────────────────────────┘
       │
       ▼
  Passive Results → Dashboard + Charts
       │
       ▼ (optional, allowlisted targets only)
  ┌────────────────────────────────┐
  │       ACTIVE RECON             │
  │  Authorization checkbox ✅     │
  │  Allowlist check ✅            │
  │  Nmap TCP scan (25 ports)      │
  └────────────────────────────────┘
       │
       ▼
  Export HTML Report / Print to PDF
```

---

## ⚠️ Limitations

- **Technology detection** is signature-based — it may miss custom or obfuscated stacks
- **Shodan free tier** restricts the number of host lookups per month
- **Nmap scan** covers only 25 common ports (not a full port sweep)
- Reconnaissance observations are **not proof of vulnerability** — they are data collection only
- Results depend on what is publicly indexed / accessible at scan time

---

## 📜 Disclaimer

> ReconScope is an academic project for educational purposes in cybersecurity. All reconnaissance observations represent publicly available information and are **not**, by themselves, evidence of a security vulnerability.
>
> **Always obtain explicit written authorization before scanning any system you do not own.**
> Unauthorized use of this tool against systems without permission may be illegal in your jurisdiction.

---

<div align="center">

Made with 🛡️ for ethical cybersecurity education

</div>
