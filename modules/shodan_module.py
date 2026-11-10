"""Shodan host lookup. Queries Shodan's index only; never contacts the target.
The API key is read from the environment and never logged or displayed."""
import logging
import socket

import requests

from config import Config
from modules.common import make_result

log = logging.getLogger("reconscope")

API_URL = "https://api.shodan.io/shodan/host/{ip}"


def _resolve_ip(domain: str):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def run_shodan(domain: str) -> dict:
    key = Config.SHODAN_API_KEY
    if not key:
        return make_result("warning", "API key not configured (set SHODAN_API_KEY in .env)",
                           {"services": [], "meta": {}})

    ip = _resolve_ip(domain)
    if not ip:
        return make_result("error", "Could not resolve domain to an IP address")

    try:
        resp = requests.get(API_URL.format(ip=ip), params={"key": key}, timeout=15)
    except requests.Timeout:
        return make_result("error", "Shodan request timed out")
    except requests.RequestException as exc:
        # Do not include the URL: it contains the API key as a query parameter.
        log.warning("Shodan request failed: %s", type(exc).__name__)
        return make_result("error", "Shodan request failed (network error)")

    if resp.status_code == 404:
        return make_result("warning", f"No information indexed by Shodan for {ip}",
                           {"services": [], "meta": {"ip": ip}})
    if resp.status_code == 401:
        return make_result("error", "Shodan rejected the API key (invalid key)")
    if resp.status_code == 403:
        return make_result("warning", "Shodan denied access (free plan may not allow host lookups)")
    if resp.status_code == 429:
        return make_result("warning", "Shodan rate limit reached. Try again shortly")
    if resp.status_code != 200:
        return make_result("error", f"Shodan returned HTTP {resp.status_code}")

    try:
        j = resp.json()
    except ValueError:
        return make_result("error", "Shodan returned an unreadable response")

    services = []
    for item in j.get("data", []):
        banner = (item.get("data") or "").strip().replace("\r", "")
        services.append({
            "ip": item.get("ip_str", ip),
            "port": item.get("port"),
            "protocol": item.get("transport", "tcp"),
            "service": item.get("product") or item.get("_shodan", {}).get("module", "") or "unknown",
            "version": item.get("version") or "",
            "banner": banner[:200],
        })

    meta = {
        "ip": ip,
        "org": j.get("org") or "",
        "isp": j.get("isp") or "",
        "country": j.get("country_name") or "",
    }
    services.sort(key=lambda s: (s["port"] or 0))

    if not services:
        return make_result("warning", f"Shodan knows {ip} but lists no open services",
                           {"services": [], "meta": meta})
    return make_result("completed", f"{len(services)} indexed services for {ip} (Shodan database only)",
                       {"services": services, "meta": meta})