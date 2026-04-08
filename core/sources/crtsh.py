# osint_aggregator/core/sources/crtsh.py
import requests

def get_subdomains(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        res = requests.get(url, timeout=15)
        if res.status_code != 200:
            return [f"[!] crt.sh returned HTTP {res.status_code}"]

        data = res.json()
        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            issuer = entry.get("issuer_ca_id")
            for line in name.split("\n"):
                line = line.strip()
                # Strip leading wildcard (*.example.com -> example.com)
                if line.startswith("*."):
                    line = line[2:]
                if domain in line and line:
                    subdomains.add(line)

        return sorted(subdomains)
    except ValueError:
        return ["[!] crt.sh returned invalid JSON — may be rate limited, try again."]
    except Exception as e:
        return [f"[!] Error querying crt.sh: {e}"]
