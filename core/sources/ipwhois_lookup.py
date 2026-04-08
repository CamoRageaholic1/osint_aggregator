# osint_aggregator/core/sources/ipwhois_lookup.py
from ipwhois import IPWhois

def get_whois(ip):
    try:
        obj = IPWhois(ip)
        results = obj.lookup_rdap(depth=1)

        network = results.get("network") or {}
        org_block = network.get("org") or {}
        # org_block can be a dict (RDAP object) or None
        if isinstance(org_block, dict):
            org_name = org_block.get("name", "N/A")
        else:
            org_name = str(org_block) if org_block else "N/A"

        return {
            "ip": ip,
            "network_name": network.get("name", "N/A"),
            "org": org_name,
            "cidr": network.get("cidr", "N/A"),
            "asn": results.get("asn", "N/A"),
            "asn_description": results.get("asn_description", "N/A"),
            "country": results.get("asn_country_code", "N/A"),
            "abuse_emails": results.get("abuse_emails", "N/A"),
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}
