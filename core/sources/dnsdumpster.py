# osint_aggregator/core/sources/dnsdumpster.py
import requests
from bs4 import BeautifulSoup

BASE_URL = "https://dnsdumpster.com/"
HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={}"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36",
    "Referer": "https://dnsdumpster.com/",
}

def _try_dnsdumpster(domain):
    session = requests.Session()
    try:
        res = session.get(BASE_URL, headers=HEADERS, timeout=12)
        soup = BeautifulSoup(res.text, "html.parser")
        token_input = soup.find("input", {"name": "csrfmiddlewaretoken"})
        if not token_input:
            return None

        csrf = token_input.get("value")
        data = {"csrfmiddlewaretoken": csrf, "targetip": domain, "user": "free"}
        res = session.post(
            BASE_URL,
            headers={**HEADERS, "Origin": "https://dnsdumpster.com"},
            cookies=res.cookies.get_dict(),
            data=data,
            timeout=15,
        )
        soup = BeautifulSoup(res.text, "html.parser")
        results = []
        for table in soup.find_all("table"):
            for row in table.find_all("tr")[1:]:
                cols = row.find_all("td")
                if len(cols) >= 1:
                    entry = " | ".join(c.text.strip() for c in cols if c.text.strip())
                    if entry:
                        results.append(entry)
        return results if results else None
    except Exception:
        return None


def _try_hackertarget(domain):
    try:
        res = requests.get(
            HACKERTARGET_URL.format(domain), headers=HEADERS, timeout=12
        )
        if res.status_code == 200 and "error" not in res.text.lower()[:30]:
            lines = [l.strip() for l in res.text.strip().splitlines() if l.strip()]
            return lines
        return None
    except Exception:
        return None


def get_dns_info(domain):
    results = _try_dnsdumpster(domain)
    if results:
        return results

    # Fallback to HackerTarget passive DNS API
    results = _try_hackertarget(domain)
    if results:
        return ["[i] DNSDumpster unavailable — results via HackerTarget API:"] + results

    return ["[!] Both DNSDumpster and HackerTarget fallback failed."]
