# osint_aggregator/core/sources/whois_domain.py
import whois

def _to_str(val):
    if val is None:
        return "N/A"
    if isinstance(val, list):
        return ", ".join(str(v) for v in val)
    return str(val)

def get_domain_whois(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain": domain,
            "registrar": _to_str(w.registrar),
            "creation_date": _to_str(w.creation_date),
            "expiration_date": _to_str(w.expiration_date),
            "updated_date": _to_str(w.updated_date),
            "name_servers": _to_str(w.name_servers),
            "status": _to_str(w.status),
            "emails": _to_str(w.emails),
            "org": _to_str(w.org),
            "country": _to_str(w.country),
            "dnssec": _to_str(getattr(w, "dnssec", None)),
        }
    except Exception as e:
        return {"domain": domain, "error": str(e)}
