"""Wayback Machine lookup using the public CDX API. Queries archive.org only,
never the target itself."""
import logging
from datetime import datetime

import requests

from modules.common import make_result

log = logging.getLogger("reconscope")

CDX_URL = "https://web.archive.org/cdx/search/cdx"
MAX_RECORDS = 25  # keep the dashboard readable


def _fmt_ts(ts: str) -> str:
    try:
        return datetime.strptime(ts, "%Y%m%d%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ts


def run_wayback(domain: str) -> dict:
    # Most recent snapshots, one per distinct day, HTML pages only.
    params = {
        "url": domain,
        "output": "json",
        "fl": "timestamp,original,statuscode",
        "filter": "mimetype:text/html",
        "collapse": "timestamp:8",
        "limit": -MAX_RECORDS,  # negative limit = newest N results
    }
    try:
        resp = requests.get(
            CDX_URL,
            params=params,
            timeout=20,
            headers={"User-Agent": "ReconScope/1.0 (academic footprinting project)"},
        )
        resp.raise_for_status()
        rows = resp.json()
    except requests.Timeout:
        return make_result("error", "Wayback Machine timed out. Try again later.")
    except requests.RequestException as exc:
        log.warning("Wayback failed for %s: %s", domain, exc)
        return make_result("error", f"Wayback request failed: {exc}")
    except ValueError:
        # Empty or non-JSON body means no captures.
        return make_result("warning", "No archived snapshots found", {"snapshots": [], "count": 0})

    # First row is the header: ["timestamp", "original", "statuscode"]
    records = rows[1:] if rows else []
    if not records:
        return make_result("warning", "No archived snapshots found", {"snapshots": [], "count": 0})

    snapshots = [
        {
            "timestamp": _fmt_ts(ts),
            "url": f"https://web.archive.org/web/{ts}/{orig}",
            "status_code": status if status and status != "-" else "n/a",
        }
        for ts, orig, status in records
    ]
    snapshots.reverse()  # newest first

    return make_result(
        "completed",
        f"{len(snapshots)} most recent snapshots retrieved (archive.org only)",
        {"snapshots": snapshots, "count": len(snapshots)},
    )