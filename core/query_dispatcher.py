# osint_aggregator/core/query_dispatcher.py
import csv
import datetime
import json
import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED

from core.sources import (
    crtsh,
    dnsdumpster,
    dns_lookup,
    email_lookup,
    google_dorks,
    headers_check,
    ipwhois_lookup,
    port_scan,
    username_lookup,
    whois_domain,
)


# ─── Output formatters ────────────────────────────────────────────────────────

def _write_json(report, path):
    with open(path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"  [+] JSON  -> {path}")


def _write_txt(report, path):
    lines = []
    meta = report.get("metadata", {})
    lines += [
        "=" * 70,
        f"  OSINT AGGREGATOR — {meta.get('tool', '')} v{meta.get('version', '')}",
        f"  Scan timestamp : {meta.get('timestamp', '')}",
        f"  Targets        : {meta.get('targets', '')}",
        "=" * 70,
        "",
    ]

    results = report.get("results", {})

    section_order = [
        ("crtsh_subdomains",      "[crt.sh] Subdomain Certificate Transparency"),
        ("dns_records",           "[DNS] Full Record Lookup"),
        ("dnsdumpster",           "[DNSDumpster] Passive DNS / Subdomain Info"),
        ("domain_whois",          "[WHOIS] Domain Registration Data"),
        ("http_headers",          "[HTTP] Security Header Analysis"),
        ("ip_whois",              "[IPWhois] IP Ownership / RDAP"),
        ("port_scan",             "[PortScan] Open Ports"),
        ("shodan",                "[Shodan] Host Intelligence"),
        ("email",                 "[Email] Reputation & MX Lookup"),
        ("username_check",        "[Username] Platform Presence"),
        ("google_dorks_domain",   "[Google Dorks] Domain"),
        ("google_dorks_email",    "[Google Dorks] Email"),
        ("google_dorks_username", "[Google Dorks] Username"),
    ]

    for key, title in section_order:
        if key not in results:
            continue
        data = results[key]
        lines += ["", f"{'─' * 70}", f"  {title}", f"{'─' * 70}"]

        if key == "crtsh_subdomains":
            lines += [f"  {s}" for s in data] or ["  (none found)"]

        elif key == "dns_records":
            for rtype, vals in data.items():
                if vals:
                    lines.append(f"  {rtype}:")
                    lines += [f"    {v}" for v in vals]

        elif key == "dnsdumpster":
            lines += [f"  {e}" for e in data]

        elif key in ("domain_whois", "ip_whois", "shodan", "email"):
            for k, v in data.items():
                if isinstance(v, dict):
                    lines.append(f"  {k}:")
                    for kk, vv in v.items():
                        lines.append(f"    {kk}: {vv}")
                elif isinstance(v, list):
                    lines.append(f"  {k}: {', '.join(str(i) for i in v) or 'N/A'}")
                else:
                    lines.append(f"  {k}: {v}")

        elif key == "http_headers":
            lines.append(f"  URL          : {data.get('url', 'N/A')}")
            lines.append(f"  Status       : {data.get('status_code', 'N/A')}")
            lines.append(f"  Score        : {data.get('security_score', 'N/A')}")
            lines.append(f"  Missing      : {', '.join(data.get('missing_headers', [])) or 'none'}")
            info = data.get("info_disclosure", {})
            if info:
                lines.append("  Info Leakage :")
                for h, v in info.items():
                    lines.append(f"    {h}: {v}")
            lines.append("  Security Headers:")
            for h, v in data.get("security_headers", {}).items():
                lines.append(f"    {h}: {v}")

        elif key == "port_scan":
            open_p = data.get("open", [])
            lines.append(f"  Host: {data.get('host')} — {len(open_p)} open port(s)")
            if open_p:
                for p in open_p:
                    lines.append(f"    {p['port']}/tcp  {p['service']}")
            else:
                lines.append("  No open ports found in common port list.")

        elif key == "username_check":
            found = [r for r in data if r.get("found") is True]
            not_found = [r for r in data if r.get("found") is False]
            unknown = [r for r in data if r.get("found") is None]
            if found:
                lines.append("  FOUND:")
                for r in found:
                    lines.append(f"    [+] {r['platform']:<30} {r['url']}")
            if unknown:
                lines.append("  UNKNOWN (timeout/error):")
                for r in unknown:
                    lines.append(f"    [?] {r['platform']:<30} {r.get('error', '')}")
            if not_found:
                lines.append("  NOT FOUND:")
                for r in not_found:
                    lines.append(f"    [-] {r['platform']}")

        elif key in ("google_dorks_domain", "google_dorks_email", "google_dorks_username"):
            for d in data:
                lines.append(f"  {d['dork']}")
                lines.append(f"    -> {d['search_url']}")

    lines += ["", "=" * 70, "  Scan complete.", "=" * 70]

    with open(path, "w") as f:
        f.write("\n".join(lines))
    print(f"  [+] TXT   -> {path}")


def _write_csv(report, path):
    rows = []
    results = report.get("results", {})
    ts = report.get("metadata", {}).get("timestamp", "")

    def row(section, key, value):
        rows.append({"timestamp": ts, "section": section, "key": key, "value": str(value)})

    # Flatten each section
    for rtype, vals in results.get("dns_records", {}).items():
        for v in vals:
            row("dns_records", rtype, v)

    for s in results.get("crtsh_subdomains", []):
        row("crtsh_subdomains", "subdomain", s)

    for e in results.get("dnsdumpster", []):
        row("dnsdumpster", "entry", e)

    for k, v in results.get("domain_whois", {}).items():
        row("domain_whois", k, v)

    for k, v in results.get("ip_whois", {}).items():
        row("ip_whois", k, v)

    hdr = results.get("http_headers", {})
    for k, v in hdr.get("security_headers", {}).items():
        row("http_headers", k, v)
    for k, v in hdr.get("info_disclosure", {}).items():
        row("http_headers_info_leak", k, v)

    ps = results.get("port_scan", {})
    for p in ps.get("open", []):
        row("port_scan", "open", f"{p['port']}/{p['service']}")
    for p in ps.get("closed", []):
        row("port_scan", "closed", f"{p['port']}/{p['service']}")

    em = results.get("email", {})
    for k, v in em.items():
        row("email", k, v)

    for r in results.get("username_check", []):
        row("username_check", r["platform"], "FOUND" if r.get("found") else ("ERROR" if r.get("found") is None else "NOT_FOUND"))

    for d in results.get("google_dorks_domain", []):
        row("google_dorks_domain", "dork", d["dork"])
    for d in results.get("google_dorks_email", []):
        row("google_dorks_email", "dork", d["dork"])
    for d in results.get("google_dorks_username", []):
        row("google_dorks_username", "dork", d["dork"])

    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["timestamp", "section", "key", "value"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"  [+] CSV   -> {path}")


# ─── Main scanner ─────────────────────────────────────────────────────────────

def run_osint_scan(targets, output_file, output_format="txt", shodan_key=None, enable_ports=None):
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    report = {
        "metadata": {
            "timestamp": timestamp,
            "tool": "OSINT Aggregator",
            "version": "2.0",
            "targets": {k: v for k, v in targets.items() if v},
        },
        "results": {},
    }
    res = report["results"]

    domain  = targets.get("domain")
    ip      = targets.get("ip")
    email   = targets.get("email")
    username = targets.get("username")

    # ── Domain scans (run in parallel) ────────────────────────────────────────
    if domain:
        print(f"\n[*] Domain: {domain}")

        def _crtsh():
            print("    crt.sh ...")
            return "crtsh_subdomains", crtsh.get_subdomains(domain)

        def _dns():
            print("    DNS records ...")
            return "dns_records", dns_lookup.get_dns_records(domain)

        def _dnsdump():
            print("    DNSDumpster ...")
            return "dnsdumpster", dnsdumpster.get_dns_info(domain)

        def _whois_d():
            print("    Domain WHOIS ...")
            return "domain_whois", whois_domain.get_domain_whois(domain)

        def _headers():
            print("    HTTP headers ...")
            return "http_headers", headers_check.check_headers(domain)

        def _dorks_d():
            return "google_dorks_domain", google_dorks.generate_dorks(domain, "domain")

        tasks = [_crtsh, _dns, _dnsdump, _whois_d, _headers, _dorks_d]
        with ThreadPoolExecutor(max_workers=len(tasks)) as ex:
            for future in as_completed([ex.submit(t) for t in tasks]):
                key, val = future.result()
                res[key] = val

        # Port scan domain — only if explicitly requested (not default for domains)
        if enable_ports:
            try:
                resolved_ip = socket.gethostbyname(domain)
                print(f"    Port scan ({resolved_ip}) ...")
                res["port_scan"] = port_scan.scan_ports(resolved_ip)
            except Exception as e:
                res["port_scan"] = {"error": str(e)}

    # ── IP scans ──────────────────────────────────────────────────────────────
    if ip:
        print(f"\n[*] IP: {ip}")

        def _ipwhois():
            print("    IP WHOIS/RDAP ...")
            return "ip_whois", ipwhois_lookup.get_whois(ip)

        def _ports():
            do_scan = enable_ports if enable_ports is not None else True
            if not do_scan:
                return "port_scan", {"skipped": True}
            print("    Port scan ...")
            return "port_scan", port_scan.scan_ports(ip)

        def _shodan():
            key = shodan_key or os.environ.get("SHODAN_API_KEY")
            if not key:
                return "shodan", None
            print("    Shodan ...")
            from core.sources import shodan_lookup
            return "shodan", shodan_lookup.lookup_ip(ip, key)

        tasks = [_ipwhois, _ports, _shodan]
        with ThreadPoolExecutor(max_workers=len(tasks)) as ex:
            for future in as_completed([ex.submit(t) for t in tasks]):
                key, val = future.result()
                if val is not None:
                    res[key] = val

    # ── Email scans ───────────────────────────────────────────────────────────
    if email:
        print(f"\n[*] Email: {email}")
        print("    Email lookup ...")
        res["email"] = email_lookup.lookup_email(email)
        res["google_dorks_email"] = google_dorks.generate_dorks(email, "email")

    # ── Username scans ────────────────────────────────────────────────────────
    if username:
        print(f"\n[*] Username: {username}")
        print("    Platform checks (parallel) ...")
        res["username_check"] = username_lookup.lookup_username(username)
        res["google_dorks_username"] = google_dorks.generate_dorks(username, "username")

    # ── Write output ──────────────────────────────────────────────────────────
    base = output_file.rsplit(".", 1)[0] if "." in os.path.basename(output_file) else output_file
    print(f"\n[*] Writing output ({output_format}) ...")

    if output_format in ("json", "all"):
        _write_json(report, base + ".json")
    if output_format in ("csv", "all"):
        _write_csv(report, base + ".csv")
    if output_format in ("txt", "all"):
        _write_txt(report, base + ".txt")

    print("[+] Done.\n")
    return report
