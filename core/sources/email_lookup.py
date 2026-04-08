# osint_aggregator/core/sources/email_lookup.py
import re
import requests
import dns.resolver

# Common disposable/temporary email providers
DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwaway.email", "sharklasers.com", "guerrillamailblock.com", "grr.la",
    "guerrillamail.info", "spam4.me", "yopmail.com", "trashmail.com",
    "dispostable.com", "maildrop.cc", "fakeinbox.com", "mailnull.com",
    "spamgourmet.com", "trashmail.me", "discard.email", "spamhereplease.com",
}

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$")

def _validate_format(email):
    return bool(EMAIL_REGEX.match(email))

def _get_mx_records(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=8)
        return sorted([(r.preference, str(r.exchange).rstrip(".")) for r in answers])
    except Exception:
        return []

def _check_emailrep(email):
    try:
        res = requests.get(
            f"https://emailrep.io/{email}",
            headers={"User-Agent": "osint-aggregator/2.0"},
            timeout=10,
        )
        if res.status_code == 200:
            data = res.json()
            details = data.get("details", {})
            return {
                "reputation": data.get("reputation", "unknown"),
                "suspicious": data.get("suspicious", False),
                "references": data.get("references", 0),
                "blacklisted": details.get("blacklisted", False),
                "malicious_activity": details.get("malicious_activity", False),
                "credentials_leaked": details.get("credentials_leaked", False),
                "data_breach": details.get("data_breach", False),
                "known_profiles": details.get("profiles", []),
                "first_seen": details.get("first_seen", "N/A"),
                "last_seen": details.get("last_seen", "N/A"),
            }
        if res.status_code == 429:
            return {"error": "emailrep.io rate limit hit — try again later"}
        return {"error": f"emailrep.io HTTP {res.status_code}"}
    except Exception as e:
        return {"error": str(e)}

def lookup_email(email):
    if not _validate_format(email):
        return {"email": email, "error": "Invalid email format"}

    domain = email.split("@", 1)[1]
    mx = _get_mx_records(domain)

    return {
        "email": email,
        "domain": domain,
        "valid_format": True,
        "disposable": domain.lower() in DISPOSABLE_DOMAINS,
        "mx_records": [f"{pref} {exch}" for pref, exch in mx],
        "mx_valid": bool(mx),
        "emailrep": _check_emailrep(email),
    }
