"""ReconScope - Footprinting and Reconnaissance Dashboard (Phase 10)."""
import logging
import re
import time
from datetime import datetime

from flask import Flask, Response, flash, redirect, render_template, request, url_for

import db
from config import Config
from modules.common import make_result
from modules.dns_module import run_dns
from modules.nmap_module import run_nmap
from modules.shodan_module import run_shodan
from modules.technology_module import run_technology
from modules.wayback_module import run_wayback
from modules.whois_module import run_whois

app = Flask(__name__)
app.config.from_object(Config)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("reconscope")

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:[a-z][a-z0-9-]{1,62})$"
)

MODULES = [
    {"key": "whois",      "name": "WHOIS",      "type": "passive"},
    {"key": "dns",        "name": "DNS",        "type": "passive"},
    {"key": "technology", "name": "Technology", "type": "passive"},
    {"key": "shodan",     "name": "Shodan",     "type": "passive"},
    {"key": "wayback",    "name": "Wayback",    "type": "passive"},
    {"key": "nmap",       "name": "Nmap",       "type": "active"},
]

# Simple in-memory rate limits (seconds between runs, per scan).
_last_run = {}
_last_nmap = {}
RATE_LIMIT_SECONDS = 10
NMAP_RATE_LIMIT_SECONDS = 30


def normalize_domain(raw: str) -> str:
    value = (raw or "").strip().lower()
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)
    value = value.split("/")[0].split("?")[0].split("#")[0]
    value = value.split(":")[0]
    return value.rstrip(".")


def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain))


db.init_db()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    domain = normalize_domain(request.form.get("domain", ""))
    if not is_valid_domain(domain):
        log.warning("Rejected invalid domain input")
        flash("Please enter a valid domain name, e.g. example.com", "danger")
        return redirect(url_for("index"))
    scan_id = db.create_scan(domain)
    db.log_action(scan_id, f"Scan created for {domain}; domain validated")
    return redirect(url_for("dashboard", scan_id=scan_id))


@app.route("/run/<int:scan_id>", methods=["POST"])
def run_recon(scan_id):
    row = db.get_scan(scan_id)
    if row is None:
        flash("Scan not found.", "danger")
        return redirect(url_for("index"))

    now = time.time()
    if now - _last_run.get(scan_id, 0) < RATE_LIMIT_SECONDS:
        flash("Please wait a few seconds before running again.", "warning")
        return redirect(url_for("dashboard", scan_id=scan_id))
    _last_run[scan_id] = now

    domain = row["domain"]
    log.info("Passive recon started scan_id=%s domain=%s", scan_id, domain)
    db.update_scan_status(scan_id, "running")
    db.log_action(scan_id, "Passive reconnaissance started (WHOIS, DNS, Technology, Shodan, Wayback)")

    # Each module is isolated: one failure never stops the others.
    results = {}
    for key, func in (
        ("whois", run_whois),
        ("dns", run_dns),
        ("technology", run_technology),
        ("shodan", run_shodan),
        ("wayback", run_wayback),
    ):
        try:
            results[key] = func(domain)
        except Exception as exc:
            log.exception("Module %s crashed", key)
            results[key] = make_result("error", f"Unexpected error: {exc}")

    # Store WHOIS
    db.clear_module_data(scan_id, "whois_records")
    if results["whois"]["data"]:
        db.save_whois(scan_id, results["whois"]["data"])

    # Store DNS
    db.clear_module_data(scan_id, "dns_records")
    if results["dns"]["data"]:
        db.save_dns(scan_id, results["dns"]["data"])
        a_records = results["dns"]["data"].get("A", [])
        if a_records:
            db.set_scan_ip(scan_id, a_records[0])

    # Store Technology
    db.clear_module_data(scan_id, "technologies")
    tech_list = results["technology"]["data"].get("technologies", [])
    if tech_list:
        db.save_technologies(scan_id, tech_list)

    # Store Wayback
    db.clear_module_data(scan_id, "wayback_records")
    wb = results["wayback"]["data"]
    if wb.get("snapshots"):
        db.save_wayback(scan_id, wb["snapshots"])

    # Store Shodan
    db.clear_services(scan_id, "shodan")
    sh = results["shodan"]["data"]
    if sh.get("services"):
        db.save_services(scan_id, sh["services"], "shodan")
    if sh.get("meta"):
        db.save_shodan_meta(scan_id, sh["meta"])

    for key, res in results.items():
        db.save_module_status(scan_id, key, res["status"], res["message"])
        log.info("Module %s -> %s (%s)", key, res["status"], res["message"])

    db.log_action(scan_id, "Passive reconnaissance finished")
    db.update_scan_status(scan_id, "completed")
    return redirect(url_for("dashboard", scan_id=scan_id))


@app.route("/nmap/<int:scan_id>", methods=["POST"])
def run_nmap_scan(scan_id):
    """ACTIVE reconnaissance. Refuses to run without explicit authorization."""
    row = db.get_scan(scan_id)
    if row is None:
        flash("Scan not found.", "danger")
        return redirect(url_for("index"))

    domain = row["domain"]

    # Scope enforcement: only allowlisted targets may be actively scanned.
    if domain not in Config.ACTIVE_SCAN_ALLOWLIST:
        log.warning("Nmap BLOCKED scan_id=%s: %s is not in the active-scan allowlist", scan_id, domain)
        db.log_action(scan_id, f"ACTIVE scan blocked: {domain} is outside the authorized scope")
        flash("Active scan blocked: this target is not in your authorized scope (ACTIVE_SCAN_ALLOWLIST in .env).", "danger")
        return redirect(url_for("dashboard", scan_id=scan_id))

    # Workflow rule enforced on the server: passive recon must come first.
    saved_status = db.get_module_statuses(scan_id)
    if "dns" not in saved_status:
        flash("Run passive reconnaissance first. Active scanning comes after passive.", "warning")
        return redirect(url_for("dashboard", scan_id=scan_id))

    # Server-side check: the browser checkbox alone is never trusted.
    if request.form.get("confirm_auth") != "yes":
        log.warning("Nmap REFUSED scan_id=%s domain=%s: authorization not confirmed", scan_id, domain)
        flash("Active scan blocked: you must confirm you are authorized to scan this target.", "danger")
        return redirect(url_for("dashboard", scan_id=scan_id))

    now = time.time()
    if now - _last_nmap.get(scan_id, 0) < NMAP_RATE_LIMIT_SECONDS:
        flash("Please wait 30 seconds between active scans.", "warning")
        return redirect(url_for("dashboard", scan_id=scan_id))
    _last_nmap[scan_id] = now

    log.info("ACTIVE SCAN authorization confirmed by user scan_id=%s domain=%s", scan_id, domain)
    db.log_action(scan_id, "ACTIVE scan: user confirmed authorization; Nmap started")

    try:
        result = run_nmap(domain)
    except Exception as exc:
        log.exception("Nmap module crashed")
        result = make_result("error", f"Unexpected error: {exc}")

    db.clear_services(scan_id, "nmap")
    services = result["data"].get("services", [])
    if services:
        db.save_services(scan_id, services, "nmap")

    meta = result["data"].get("meta", {})
    message = result["message"]
    db.save_module_status(scan_id, "nmap", result["status"], message)
    db.log_action(scan_id, f"Nmap finished: {result['status']} ({message})")
    log.info("Nmap -> %s (%s) host_state=%s", result["status"], message, meta.get("state"))
    return redirect(url_for("dashboard", scan_id=scan_id))


@app.route("/dashboard")
def dashboard():
    scan_id = request.args.get("scan_id", type=int)
    row = db.get_scan(scan_id) if scan_id else None
    if row is None:
        flash("Scan not found.", "danger")
        return redirect(url_for("index"))

    keys = row.keys()
    target = {
        "scan_id": row["id"],
        "domain": row["domain"],
        "ip": (row["ip"] if "ip" in keys and row["ip"] else "Not resolved yet"),
        "timestamp": row["scan_date"],
        "status": row["status"].capitalize(),
    }

    saved = db.get_module_statuses(scan_id)
    modules = []
    for m in MODULES:
        s = saved.get(m["key"], {"status": "pending", "message": "Not executed"})
        modules.append({**m, **s})

    done = sum(1 for m in modules if m["status"] != "pending")
    progress = round(done / len(modules) * 100)
    nmap_info = next(m for m in modules if m["key"] == "nmap")

    # Workflow step: 2 = passive next, 3 = active next, 4 = report
    passive_done = "dns" in saved
    nmap_done = "nmap" in saved
    if nmap_done:
        step = 4
    elif passive_done:
        step = 3
    else:
        step = 2

    dns_data = db.get_dns(scan_id)
    tech_data = db.get_technologies(scan_id)
    wayback_data = db.get_wayback(scan_id)

    # Data for the charts (passed to the page as safe JSON)
    chart_data = {
        "dns": {rtype: len(vals) for rtype, vals in dns_data.items() if vals},
        "tech": {},
        "wayback": {},
    }
    for t in tech_data:
        cat = t["category"] or "Other"
        chart_data["tech"][cat] = chart_data["tech"].get(cat, 0) + 1
    for w in wayback_data:
        code = str(w["status_code"])
        chart_data["wayback"][code] = chart_data["wayback"].get(code, 0) + 1

    status_counts = {"completed": 0, "warning": 0, "error": 0, "pending": 0}
    for m in modules:
        status_counts[m["status"]] = status_counts.get(m["status"], 0) + 1

    return render_template(
        "dashboard.html",
        target=target,
        modules=modules,
        progress=progress,
        whois=db.get_whois(scan_id),
        dns=dns_data,
        technologies=tech_data,
        wayback=wayback_data,
        shodan=db.get_services(scan_id, "shodan"),
        shodan_meta=db.get_shodan_meta(scan_id),
        nmap_services=db.get_services(scan_id, "nmap"),
        nmap_info=nmap_info,
        step=step,
        passive_done=passive_done,
        action_log=db.get_action_log(scan_id),
        chart_data=chart_data,
        status_counts=status_counts,
    )


@app.route("/history")
def history():
    return render_template("history.html", scans=db.list_scans())


# ------------------------------------------------------------------ reports

def _build_report_context(scan_id):
    row = db.get_scan(scan_id)
    if row is None:
        return None
    keys = row.keys()
    saved = db.get_module_statuses(scan_id)
    modules = []
    for m in MODULES:
        s = saved.get(m["key"], {"status": "pending", "message": "Not executed"})
        modules.append({**m, **s})

    technologies = db.get_technologies(scan_id)
    wayback = db.get_wayback(scan_id)
    shodan = db.get_services(scan_id, "shodan")
    nmap_services = db.get_services(scan_id, "nmap")
    dns_data = db.get_dns(scan_id)

    observations = []
    a_count = len(dns_data.get("A", []))
    ns_count = len(dns_data.get("NS", []))
    ns_note = (
        f"{ns_count} NS record(s) were returned for this hostname."
        if ns_count
        else "No NS records exist at this hostname (name servers are defined on the parent domain; see WHOIS)."
    )
    observations.append(f"{a_count} IPv4 address record(s) were observed in DNS. {ns_note}")
    if technologies:
        observations.append(
            "Technologies observed from the homepage: " + ", ".join(t["technology"] for t in technologies) + "."
        )
    else:
        observations.append("No technologies were identified from the homepage response.")
    observations.append(f"{len(wayback)} archived snapshot(s) were retrieved from the Wayback Machine.")
    observations.append(
        f"Shodan lists {len(shodan)} indexed service(s) for the target IP "
        "(publicly indexed, not proof of vulnerability)."
    )
    if saved.get("nmap"):
        observations.append(
            f"Authorized active scan observed {len(nmap_services)} open port(s) among the scanned common ports."
        )
    else:
        observations.append("No active (Nmap) scan was run for this target.")

    return {
        "target": {
            "domain": row["domain"],
            "ip": (row["ip"] if "ip" in keys and row["ip"] else "Not resolved"),
            "timestamp": row["scan_date"],
            "generated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
        "modules": modules,
        "whois": db.get_whois(scan_id),
        "dns": dns_data,
        "technologies": technologies,
        "wayback": wayback,
        "shodan": shodan,
        "shodan_meta": db.get_shodan_meta(scan_id),
        "nmap_services": nmap_services,
        "action_log": db.get_action_log(scan_id),
        "observations": observations,
    }


@app.route("/report")
def report_index():
    return render_template("report_list.html", scans=db.list_scans())


@app.route("/report/<int:scan_id>")
def report(scan_id):
    ctx = _build_report_context(scan_id)
    if ctx is None:
        flash("Scan not found.", "danger")
        return redirect(url_for("index"))
    return render_template("report.html", standalone=False, **ctx)


@app.route("/report/<int:scan_id>/download")
def report_download(scan_id):
    ctx = _build_report_context(scan_id)
    if ctx is None:
        flash("Scan not found.", "danger")
        return redirect(url_for("index"))
    html = render_template("report.html", standalone=True, **ctx)
    Config.REPORTS_DIR.mkdir(exist_ok=True)
    filename = f"reconscope_{ctx['target']['domain'].replace('.', '_')}_scan{scan_id}.html"
    (Config.REPORTS_DIR / filename).write_text(html, encoding="utf-8")
    db.log_action(scan_id, f"Report exported: {filename}")
    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001, debug=True)