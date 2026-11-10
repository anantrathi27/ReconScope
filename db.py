"""SQLite helper: schema creation, scan records and module result storage."""
import logging
import sqlite3
from contextlib import closing
from datetime import datetime

from config import Config

log = logging.getLogger("reconscope")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    domain    TEXT NOT NULL,
    scan_date TEXT NOT NULL,
    status    TEXT NOT NULL DEFAULT 'created'
);

CREATE TABLE IF NOT EXISTS dns_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL,
    record_type TEXT NOT NULL,
    value       TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS technologies (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL,
    technology TEXT NOT NULL,
    category   TEXT,
    version    TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS services (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id  INTEGER NOT NULL,
    ip       TEXT,
    port     INTEGER,
    protocol TEXT,
    service  TEXT,
    version  TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS wayback_records (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL,
    url         TEXT NOT NULL,
    timestamp   TEXT,
    status_code TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS whois_records (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    field   TEXT NOT NULL,
    value   TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);
"""


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")  # SQLite ignores FKs unless enabled per connection
    return conn


def init_db() -> None:
    Config.DATABASE_PATH.parent.mkdir(exist_ok=True)
    with closing(get_connection()) as conn:
        conn.executescript(SCHEMA)
        conn.commit()
    log.info("Database initialised at %s", Config.DATABASE_PATH)


# ---------------------------------------------------------------- scans

def create_scan(domain: str) -> int:
    """Insert a new scan row and return its id. Uses parameterised SQL only."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_connection()) as conn:
        cur = conn.execute(
            "INSERT INTO scans (domain, scan_date, status) VALUES (?, ?, ?)",
            (domain, now, "created"),
        )
        conn.commit()
        scan_id = cur.lastrowid
    log.info("Scan created id=%s domain=%s", scan_id, domain)
    return scan_id


def get_scan(scan_id: int):
    with closing(get_connection()) as conn:
        return conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()


def list_scans(limit: int = 50):
    with closing(get_connection()) as conn:
        return conn.execute(
            "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()


def update_scan_status(scan_id: int, status: str) -> None:
    with closing(get_connection()) as conn:
        conn.execute("UPDATE scans SET status = ? WHERE id = ?", (status, scan_id))
        conn.commit()
    log.info("Scan %s status -> %s", scan_id, status)


def set_scan_ip(scan_id: int, ip: str) -> None:
    with closing(get_connection()) as conn:
        try:
            conn.execute("ALTER TABLE scans ADD COLUMN ip TEXT")
        except sqlite3.OperationalError:
            pass  # column already exists
        conn.execute("UPDATE scans SET ip = ? WHERE id = ?", (ip, scan_id))
        conn.commit()


# ---------------------------------------------------------------- module status

def save_module_status(scan_id: int, key: str, status: str, message: str) -> None:
    """Keep per-module status so the dashboard can show it after a reload."""
    with closing(get_connection()) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS module_status (
                   scan_id INTEGER NOT NULL,
                   module  TEXT NOT NULL,
                   status  TEXT NOT NULL,
                   message TEXT,
                   PRIMARY KEY (scan_id, module),
                   FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
               )"""
        )
        conn.execute(
            "INSERT OR REPLACE INTO module_status (scan_id, module, status, message) VALUES (?, ?, ?, ?)",
            (scan_id, key, status, message),
        )
        conn.commit()


def get_module_statuses(scan_id: int) -> dict:
    with closing(get_connection()) as conn:
        try:
            rows = conn.execute(
                "SELECT module, status, message FROM module_status WHERE scan_id = ?", (scan_id,)
            ).fetchall()
        except sqlite3.OperationalError:  # table not created yet
            return {}
    return {r["module"]: {"status": r["status"], "message": r["message"]} for r in rows}


# ---------------------------------------------------------------- results storage

def clear_module_data(scan_id: int, table: str) -> None:
    """Remove old rows before re-running a module. Table names come from a fixed whitelist."""
    allowed = {"whois_records", "dns_records", "technologies", "wayback_records"}
    if table not in allowed:
        raise ValueError("Invalid table")
    with closing(get_connection()) as conn:
        conn.execute(f"DELETE FROM {table} WHERE scan_id = ?", (scan_id,))
        conn.commit()


def save_whois(scan_id: int, data: dict) -> None:
    with closing(get_connection()) as conn:
        conn.executemany(
            "INSERT INTO whois_records (scan_id, field, value) VALUES (?, ?, ?)",
            [(scan_id, k, v) for k, v in data.items()],
        )
        conn.commit()


def get_whois(scan_id: int) -> dict:
    with closing(get_connection()) as conn:
        rows = conn.execute(
            "SELECT field, value FROM whois_records WHERE scan_id = ?", (scan_id,)
        ).fetchall()
    return {r["field"]: r["value"] for r in rows}


def save_dns(scan_id: int, data: dict) -> None:
    rows = [(scan_id, rtype, value) for rtype, values in data.items() for value in values]
    with closing(get_connection()) as conn:
        conn.executemany(
            "INSERT INTO dns_records (scan_id, record_type, value) VALUES (?, ?, ?)",
            rows,
        )
        conn.commit()


def get_dns(scan_id: int) -> dict:
    with closing(get_connection()) as conn:
        rows = conn.execute(
            "SELECT record_type, value FROM dns_records WHERE scan_id = ?", (scan_id,)
        ).fetchall()
    out = {}
    for r in rows:
        out.setdefault(r["record_type"], []).append(r["value"])
    return out


def save_technologies(scan_id: int, techs: list) -> None:
    with closing(get_connection()) as conn:
        conn.executemany(
            "INSERT INTO technologies (scan_id, technology, category, version) VALUES (?, ?, ?, ?)",
            [(scan_id, t["technology"], t["category"], t["version"]) for t in techs],
        )
        conn.commit()


def get_technologies(scan_id: int) -> list:
    with closing(get_connection()) as conn:
        rows = conn.execute(
            "SELECT technology, category, version FROM technologies WHERE scan_id = ? ORDER BY category, technology",
            (scan_id,),
        ).fetchall()
    return [dict(r) for r in rows]

def save_wayback(scan_id: int, snapshots: list) -> None:
    with closing(get_connection()) as conn:
        conn.executemany(
            "INSERT INTO wayback_records (scan_id, url, timestamp, status_code) VALUES (?, ?, ?, ?)",
            [(scan_id, s["url"], s["timestamp"], s["status_code"]) for s in snapshots],
        )
        conn.commit()


def get_wayback(scan_id: int) -> list:
    with closing(get_connection()) as conn:
        rows = conn.execute(
            "SELECT url, timestamp, status_code FROM wayback_records WHERE scan_id = ? ORDER BY timestamp DESC",
            (scan_id,),
        ).fetchall()
    return [dict(r) for r in rows]

def _ensure_banner_column(conn) -> None:
    try:
        conn.execute("ALTER TABLE services ADD COLUMN banner TEXT")
    except sqlite3.OperationalError:
        pass  # already exists


def save_services(scan_id: int, services: list, source: str = "shodan") -> None:
    with closing(get_connection()) as conn:
        _ensure_banner_column(conn)
        try:
            conn.execute("ALTER TABLE services ADD COLUMN source TEXT")
        except sqlite3.OperationalError:
            pass
        conn.executemany(
            "INSERT INTO services (scan_id, ip, port, protocol, service, version, banner, source) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (scan_id, s.get("ip"), s.get("port"), s.get("protocol"), s.get("service"),
                 s.get("version"), s.get("banner", ""), source)
                for s in services
            ],
        )
        conn.commit()


def get_services(scan_id: int, source: str = "shodan") -> list:
    with closing(get_connection()) as conn:
        _ensure_banner_column(conn)
        try:
            conn.execute("ALTER TABLE services ADD COLUMN source TEXT")
        except sqlite3.OperationalError:
            pass
        rows = conn.execute(
            "SELECT ip, port, protocol, service, version, banner FROM services "
            "WHERE scan_id = ? AND source = ? ORDER BY port",
            (scan_id, source),
        ).fetchall()
    return [dict(r) for r in rows]


def clear_services(scan_id: int, source: str) -> None:
    with closing(get_connection()) as conn:
        try:
            conn.execute("DELETE FROM services WHERE scan_id = ? AND source = ?", (scan_id, source))
        except sqlite3.OperationalError:
            return  # source column not created yet, so nothing to clear
        conn.commit()


def save_shodan_meta(scan_id: int, meta: dict) -> None:
    """Store org/ISP/country as key-value rows in whois-style table? No: keep a tiny table."""
    with closing(get_connection()) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS shodan_meta (
                   scan_id INTEGER PRIMARY KEY,
                   ip TEXT, org TEXT, isp TEXT, country TEXT,
                   FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
               )"""
        )
        conn.execute(
            "INSERT OR REPLACE INTO shodan_meta (scan_id, ip, org, isp, country) VALUES (?, ?, ?, ?, ?)",
            (scan_id, meta.get("ip", ""), meta.get("org", ""), meta.get("isp", ""), meta.get("country", "")),
        )
        conn.commit()


def get_shodan_meta(scan_id: int) -> dict:
    with closing(get_connection()) as conn:
        try:
            row = conn.execute(
                "SELECT ip, org, isp, country FROM shodan_meta WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        except sqlite3.OperationalError:
            return {}
    return dict(row) if row else {}

def log_action(scan_id: int, action: str) -> None:
    """Persist an audit trail of what was run and when."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with closing(get_connection()) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS action_log (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   scan_id INTEGER NOT NULL,
                   timestamp TEXT NOT NULL,
                   action TEXT NOT NULL,
                   FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
               )"""
        )
        conn.execute(
            "INSERT INTO action_log (scan_id, timestamp, action) VALUES (?, ?, ?)",
            (scan_id, now, action),
        )
        conn.commit()


def get_action_log(scan_id: int) -> list:
    with closing(get_connection()) as conn:
        try:
            rows = conn.execute(
                "SELECT timestamp, action FROM action_log WHERE scan_id = ? ORDER BY id",
                (scan_id,),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
    return [dict(r) for r in rows]