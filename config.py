"""Central configuration. Secrets come from the environment (.env), never from code."""
import os
from pathlib import Path
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-only-change-me")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
    DATABASE_PATH = BASE_DIR / "database" / "recon.db"
    REPORTS_DIR = BASE_DIR / "reports"
    ACTIVE_SCAN_ALLOWLIST = [
        d.strip().lower()
        for d in os.getenv("ACTIVE_SCAN_ALLOWLIST", "scanme.nmap.org").split(",")
        if d.strip()
    ]   

    APP_NAME = "ReconScope"
    APP_TAGLINE = "Footprinting & Reconnaissance Dashboard"