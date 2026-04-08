# osint_aggregator/core/sources/shodan_lookup.py
# Optional module — requires a Shodan API key.
# Install: pip install shodan
# Set key via: export SHODAN_API_KEY=your_key  OR  pass --shodan-key flag to CLI

import os

def lookup_ip(ip, api_key=None):
    key = api_key or os.environ.get("SHODAN_API_KEY")
    if not key:
        return {
            "error": (
                "Shodan API key required. "
                "Set SHODAN_API_KEY env var or use --shodan-key flag. "
                "Free keys available at https://account.shodan.io"
            )
        }
    try:
        import shodan
    except ImportError:
        return {"error": "shodan package not installed — run: pip install shodan"}

    try:
        api = shodan.Shodan(key)
        host = api.host(ip)
        return {
            "ip": ip,
            "org": host.get("org", "N/A"),
            "isp": host.get("isp", "N/A"),
            "os": host.get("os", "N/A"),
            "country": host.get("country_name", "N/A"),
            "city": host.get("city", "N/A"),
            "hostnames": host.get("hostnames", []),
            "ports": sorted(host.get("ports", [])),
            "vulns": sorted(host.get("vulns", [])),
            "services": [
                {
                    "port": svc.get("port"),
                    "transport": svc.get("transport", "tcp"),
                    "product": svc.get("product", ""),
                    "version": svc.get("version", ""),
                    "banner": svc.get("data", "")[:200],
                }
                for svc in host.get("data", [])
            ],
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)}
