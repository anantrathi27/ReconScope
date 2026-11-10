"""DNS lookups using dnspython (no shell, no subprocess)."""
import logging

import dns.exception
import dns.resolver

from modules.common import make_result

log = logging.getLogger("reconscope")

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def run_dns(domain: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5  # total seconds per query

    data = {}
    failures = 0
    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            data[rtype] = [r.to_text().strip('"') for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            data[rtype] = []
        except dns.exception.DNSException as exc:  # timeout, no network, etc.
            log.warning("DNS %s lookup failed for %s: %s", rtype, domain, exc)
            data[rtype] = []
            failures += 1

    if failures == len(RECORD_TYPES):
        return make_result("error", "DNS lookup failed (check network connection)")
    if not any(data.values()):
        return make_result("warning", "No DNS records found", data)
    return make_result("completed", "DNS records retrieved", data)