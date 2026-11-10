"""Domain registration lookup. Tries RDAP (HTTPS) first, then classic WHOIS (port 43).
Only domain-level facts are collected; registrant names, emails and phones are never read."""
import logging

import requests
import whois
import tldextract
from modules.common import make_result

log = logging.getLogger("reconscope")

RDAP_URL = "https://rdap.org/domain/{}"  # public RDAP redirector


def _first(value):
    if isinstance(value, (list, tuple)):
        return value[0] if value else None
    return value


def _fmt(value):
    value = _first(value)
    return str(value) if value else None


def _rdap_lookup(domain: str) -> dict:
    resp = requests.get(
        RDAP_URL.format(domain),
        timeout=10,
        headers={"Accept": "application/rdap+json"},
    )
    if resp.status_code == 404:
        return {}
    resp.raise_for_status()
    j = resp.json()

    # Registrar name lives in the entity whose role is "registrar".
    registrar = None
    for ent in j.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in ent.get("vcardArray", [None, []])[1]:
                if item[0] == "fn":
                    registrar = item[3]
                    break
            break

    created = expires = None
    for ev in j.get("events", []):
        if ev.get("eventAction") == "registration":
            created = ev.get("eventDate")
        elif ev.get("eventAction") == "expiration":
            expires = ev.get("eventDate")

    ns = sorted({n.get("ldhName", "").lower() for n in j.get("nameservers", []) if n.get("ldhName")})

    data = {
        "Registrar": registrar,
        "Creation Date": created,
        "Expiration Date": expires,
        "Name Servers": ", ".join(ns) or None,
        "Domain Status": ", ".join(j.get("status", [])) or None,
    }
    return {k: v for k, v in data.items() if v}


def _whois_lookup(domain: str) -> dict:
    w = whois.whois(domain)
    if not w or not w.get("domain_name"):
        return {}
    name_servers = w.get("name_servers") or []
    if isinstance(name_servers, str):
        name_servers = [name_servers]
    data = {
        "Registrar": _fmt(w.get("registrar")),
        "Creation Date": _fmt(w.get("creation_date")),
        "Expiration Date": _fmt(w.get("expiration_date")),
        "Name Servers": ", ".join(sorted({str(n).lower() for n in name_servers})) or None,
        "Domain Status": _fmt(w.get("status")),
    }
    return {k: v for k, v in data.items() if v}


def _registered_domain(domain: str) -> str:
    """scanme.nmap.org -> nmap.org (registration data exists only at this level)."""
    ext = tldextract.extract(domain)
    return ext.registered_domain or domain


def run_whois(domain: str) -> dict:
    errors = []
    original = domain
    domain = _registered_domain(domain)

    try:
        data = _rdap_lookup(domain)
        if data:
            note = f" (registered domain: {domain})" if domain != original else ""
            return make_result("completed", "Retrieved via RDAP (HTTPS)" + note, data)
        errors.append("RDAP returned no data")
    except Exception as exc:
        log.warning("RDAP failed for %s: %s", domain, exc)
        errors.append(f"RDAP failed: {exc}")

    try:
        data = _whois_lookup(domain)
        if data:
            return make_result("completed", "Retrieved via WHOIS (port 43)", data)
        errors.append("WHOIS returned no data")
    except Exception as exc:
        log.warning("WHOIS failed for %s: %s", domain, exc)
        errors.append(f"WHOIS failed: {exc}")

    # If every method failed, say so; if they only returned nothing, it's a warning.
    if any("failed" in e for e in errors) and not any("no data" in e for e in errors):
        return make_result("error", "; ".join(errors))
    return make_result("warning", "No registration data available (" + "; ".join(errors) + ")")