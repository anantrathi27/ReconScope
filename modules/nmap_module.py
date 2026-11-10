"""Authorized active reconnaissance with Nmap.
Fixed scan profile, no shell, no user-supplied arguments. Discovery only: no NSE
scripts, no exploitation."""
import ipaddress
import logging
import os
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

from modules.common import make_result

log = logging.getLogger("reconscope")

FALLBACK_PATHS = ("/usr/local/bin/nmap", "/opt/homebrew/bin/nmap", "/usr/bin/nmap")

# -sT  TCP connect scan (needs no root)     -sV  service/version detection
# -T3  normal timing                        --top-ports 100  the 100 most common ports
# Common service ports, fixed in code (never taken from user input).
COMMON_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8000,8080,8443,9929,31337"

SCAN_FLAGS = ["-sT", "-sV", "-T3", "-p", COMMON_PORTS, "--host-timeout", "120s", "-oX", "-"]


def _find_nmap():
    found = shutil.which("nmap")
    if found:
        return found
    for p in FALLBACK_PATHS:
        if os.path.exists(p):
            return p
    return None


def run_nmap(domain: str) -> dict:
    nmap_path = _find_nmap()
    if not nmap_path:
        return make_result("warning", "Nmap is not installed on this machine")

    try:
        ip = socket.gethostbyname(domain)
        ipaddress.ip_address(ip)  # must be a real IP before it reaches the command
    except (socket.gaierror, ValueError):
        return make_result("error", "Could not resolve the domain to a valid IP address")

    cmd = [nmap_path, *SCAN_FLAGS, ip]
    log.info("Running Nmap profile %s against %s", " ".join(SCAN_FLAGS), ip)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=180,
            shell=False,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        return make_result("error", "Nmap scan timed out after 180 seconds")
    except OSError as exc:
        return make_result("error", f"Could not start Nmap: {exc}")

    if proc.returncode != 0:
        err = (proc.stderr or "").strip().splitlines()
        return make_result("error", "Nmap failed: " + (err[-1][:200] if err else "unknown error"))

    try:
        root = ET.fromstring(proc.stdout)
    except ET.ParseError:
        return make_result("error", "Could not read Nmap output")

    host = root.find("host")
    if host is None:
        return make_result("warning", f"Host {ip} appears to be down or filtered",
                           {"services": [], "meta": {"ip": ip, "state": "down"}})

    state_el = host.find("status")
    state = state_el.get("state") if state_el is not None else "unknown"

    services = []
    for port in host.findall("ports/port"):
        st = port.find("state")
        if st is None or st.get("state") != "open":
            continue
        svc = port.find("service")
        product = (svc.get("product") if svc is not None else "") or ""
        version = (svc.get("version") if svc is not None else "") or ""
        name = (svc.get("name") if svc is not None else "") or "unknown"
        services.append({
            "ip": ip,
            "port": int(port.get("portid")),
            "protocol": port.get("protocol", "tcp"),
            "service": name,
            "version": (product + " " + version).strip(),
            "banner": "",
        })
    services.sort(key=lambda s: s["port"])

    meta = {"ip": ip, "state": state}
    if not services:
        return make_result("warning", f"Host is {state}; no open ports found among the 25 scanned common ports",
                           {"services": [], "meta": meta})
    return make_result("completed", f"Host is {state}; {len(services)} open ports found",
                       {"services": services, "meta": meta})