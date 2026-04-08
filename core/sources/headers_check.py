# osint_aggregator/core/sources/headers_check.py
import requests

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cache-Control",
    "Access-Control-Allow-Origin",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
]

INFO_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"
}

def check_headers(domain):
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            res = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)
            raw = dict(res.headers)

            security = {}
            for h in SECURITY_HEADERS:
                val = raw.get(h) or raw.get(h.lower())
                security[h] = val if val else "[MISSING]"

            # Info-disclosing headers — present = potentially bad
            info_disclosure = {}
            for h in INFO_HEADERS:
                val = raw.get(h) or raw.get(h.lower())
                if val:
                    info_disclosure[h] = val

            missing = [h for h, v in security.items() if v == "[MISSING]"]
            score = round((len(SECURITY_HEADERS) - len(missing)) / len(SECURITY_HEADERS) * 100)

            return {
                "url": res.url,
                "status_code": res.status_code,
                "security_score": f"{score}% ({len(SECURITY_HEADERS) - len(missing)}/{len(SECURITY_HEADERS)} headers present)",
                "security_headers": security,
                "info_disclosure": info_disclosure,
                "missing_headers": missing,
            }
        except Exception:
            continue

    return {"url": domain, "error": f"Could not connect to {domain} over HTTPS or HTTP"}
