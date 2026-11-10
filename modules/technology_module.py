"""Technology profiling: one normal HTTPS GET, then signature matching on
headers, cookies and HTML. No crawling, no payloads, no exploitation."""
import logging
import re

import requests

from modules.common import make_result

log = logging.getLogger("reconscope")

USER_AGENT = "ReconScope/1.0 (academic footprinting project)"
MAX_BYTES = 1_000_000  # read at most 1 MB of HTML

# (name, category, regex, where) - where: html | header:<name> | cookie
# A group named "v" captures the version when present.
SIGNATURES = [
    # Web servers
    ("Nginx", "Web server", r"nginx(?:/(?P<v>[\d.]+))?", "header:server"),
    ("Apache", "Web server", r"apache(?:/(?P<v>[\d.]+))?", "header:server"),
    ("Microsoft IIS", "Web server", r"microsoft-iis(?:/(?P<v>[\d.]+))?", "header:server"),
    ("LiteSpeed", "Web server", r"litespeed", "header:server"),
    ("Cloudflare Server", "Hosting / CDN", r"cloudflare", "header:server"),
    ("gws (Google Web Server)", "Web server", r"^gws$", "header:server"),
    # Languages / frameworks
    ("PHP", "Language", r"php(?:/(?P<v>[\d.]+))?", "header:x-powered-by"),
    ("ASP.NET", "Framework", r"asp\.net", "header:x-powered-by"),
    ("Express", "Framework", r"express", "header:x-powered-by"),
    ("Django", "Framework", r"csrftoken", "cookie"),
    ("Laravel", "Framework", r"laravel_session", "cookie"),
    ("Ruby on Rails", "Framework", r"_rails|csrf-param", "html"),
    ("Next.js", "Framework", r"/_next/|__NEXT_DATA__", "html"),
    ("Nuxt.js", "Framework", r"/_nuxt/|__NUXT__", "html"),
    # CMS
    ("WordPress", "CMS", r"wp-content|wp-includes|<meta name=\"generator\" content=\"WordPress(?: (?P<v>[\d.]+))?", "html"),
    ("Drupal", "CMS", r"<meta name=\"generator\" content=\"Drupal(?: (?P<v>[\d.]+))?|sites/default/files", "html"),
    ("Joomla", "CMS", r"<meta name=\"generator\" content=\"Joomla", "html"),
    ("Shopify", "CMS", r"cdn\.shopify\.com", "html"),
    ("Wix", "CMS", r"wixstatic\.com|X-Wix", "html"),
    ("Squarespace", "CMS", r"squarespace\.com", "html"),
    # Hosting / CDN
    ("Cloudflare", "Hosting / CDN", r".+", "header:cf-ray"),
    ("Amazon CloudFront", "Hosting / CDN", r"cloudfront", "header:via"),
    ("Akamai", "Hosting / CDN", r"akamai", "header:server"),
    ("Fastly", "Hosting / CDN", r".+", "header:x-served-by"),
    ("Vercel", "Hosting / CDN", r"vercel", "header:server"),
    ("Netlify", "Hosting / CDN", r"netlify", "header:server"),
    ("GitHub Pages", "Hosting / CDN", r"github\.com", "header:server"),
    # Analytics
    ("Google Analytics", "Analytics", r"google-analytics\.com|googletagmanager\.com/gtag|gtag\(", "html"),
    ("Google Tag Manager", "Analytics", r"googletagmanager\.com/gtm\.js", "html"),
    ("Matomo", "Analytics", r"matomo\.js|piwik\.js", "html"),
    ("Hotjar", "Analytics", r"static\.hotjar\.com", "html"),
    ("Facebook Pixel", "Analytics", r"connect\.facebook\.net/.*fbevents\.js", "html"),
    # JavaScript libraries
    ("jQuery", "JavaScript library", r"jquery[-.]?(?P<v>\d+\.\d+(?:\.\d+)?)?(?:\.min)?\.js", "html"),
    ("React", "JavaScript library", r"react(?:-dom)?(?:\.production)?(?:\.min)?\.js|data-reactroot|__REACT", "html"),
    ("Vue.js", "JavaScript library", r"vue(?:\.min)?\.js|data-v-[a-f0-9]{6,}", "html"),
    ("Angular", "JavaScript library", r"ng-version=\"(?P<v>[\d.]+)\"|angular(?:\.min)?\.js", "html"),
    ("Bootstrap", "JavaScript library", r"bootstrap(?:[-@/](?P<v>\d+\.\d+(?:\.\d+)?))?(?:\.min)?\.(?:js|css)", "html"),
    ("Tailwind CSS", "JavaScript library", r"tailwindcss|cdn\.tailwindcss\.com", "html"),
]

COMPILED = [(n, c, re.compile(p, re.I), w) for n, c, p, w in SIGNATURES]


def _fetch(domain: str):
    """Try HTTPS first, then HTTP. Returns a Response or raises."""
    headers = {"User-Agent": USER_AGENT, "Accept": "text/html,*/*"}
    last_exc = None
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{domain}/",
                headers=headers,
                timeout=10,
                allow_redirects=True,
                stream=True,
            )
            body = resp.raw.read(MAX_BYTES, decode_content=True)
            resp.close()
            return resp, body.decode(resp.encoding or "utf-8", errors="replace")
        except requests.RequestException as exc:
            last_exc = exc
    raise last_exc


def run_technology(domain: str) -> dict:
    try:
        resp, html = _fetch(domain)
    except Exception as exc:
        log.warning("Technology fetch failed for %s: %s", domain, exc)
        return make_result("error", f"Could not fetch site: {exc}")

    headers = {k.lower(): v for k, v in resp.headers.items()}
    cookies = " ".join(headers.get("set-cookie", "").split(","))

    found = {}  # name -> (category, version)
    for name, category, pattern, where in COMPILED:
        if where == "html":
            target = html
        elif where == "cookie":
            target = cookies
        else:
            target = headers.get(where.split(":", 1)[1], "")
        if not target:
            continue
        m = pattern.search(target)
        if m:
            version = m.groupdict().get("v") if m.groupdict() else None
            prev = found.get(name)
            if prev is None or (not prev[1] and version):
                found[name] = (category, version)

    techs = [
        {"technology": n, "category": c, "version": v or ""}
        for n, (c, v) in sorted(found.items(), key=lambda kv: (kv[1][0], kv[0]))
    ]

    msg = "Single HTTP GET, like a normal browser visit"
    if not techs:
        return make_result("warning", "No known technologies detected. " + msg, {"technologies": []})
    return make_result("completed", f"{len(techs)} technologies detected. " + msg, {"technologies": techs})