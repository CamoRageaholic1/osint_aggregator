# osint_aggregator/cli.py
import argparse
import os
import sys
from core.query_dispatcher import run_osint_scan

BANNER = r"""
  ___  ____ ___ _   _ _____     _                        _
 / _ \/ ___|_ _| \ | |_   _|   / \   __ _  __ _ _ __ ___| |_ ___  _ __
| | | \___ \| ||  \| | | |    / _ \ / _` |/ _` | '__/ _ \ __/ _ \| '__|
| |_| |___) | || |\  | | |   / ___ \ (_| | (_| | | |  __/ || (_) | |
 \___/|____/___|_| \_| |_|  /_/   \_\__, |\__, |_|  \___|\__\___/|_|
                                     |___/ |___/
                            v2.0  --  by CamoZeroDay
"""

def parse_args():
    parser = argparse.ArgumentParser(
        prog="osint-aggregator",
        description="One-stop OSINT resource: domain, IP, email, and username reconnaissance.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 cli.py --domain example.com
  python3 cli.py --ip 1.1.1.1
  python3 cli.py --email user@example.com
  python3 cli.py --username johndoe
  python3 cli.py --domain example.com --ip 93.184.216.34 --format all
  python3 cli.py --domain example.com --ports --shodan-key YOUR_KEY
        """,
    )

    # Targets
    targets = parser.add_argument_group("Targets")
    targets.add_argument("--domain",   metavar="DOMAIN",   help="Target domain (crt.sh, DNS, WHOIS, headers, dorks)")
    targets.add_argument("--ip",       metavar="IP",       help="Target IP address (WHOIS/RDAP, port scan, Shodan)")
    targets.add_argument("--email",    metavar="EMAIL",    help="Target email (MX, reputation, breach data, dorks)")
    targets.add_argument("--username", metavar="USERNAME", help="Target username (platform presence check, dorks)")

    # Output
    output_grp = parser.add_argument_group("Output")
    output_grp.add_argument(
        "--format",
        metavar="FMT",
        choices=["txt", "json", "csv", "all"],
        default="txt",
        help="Output format: txt, json, csv, all  (default: txt)",
    )
    output_grp.add_argument(
        "--output",
        metavar="BASENAME",
        default=None,
        help="Base filename for output (no extension). Default: output_<target>",
    )

    # Scan options
    options = parser.add_argument_group("Scan Options")
    options.add_argument(
        "--ports",
        action="store_true",
        default=False,
        help="Enable port scan for domain targets (always on for --ip)",
    )
    options.add_argument(
        "--no-ports",
        dest="no_ports",
        action="store_true",
        default=False,
        help="Disable port scan even when --ip is provided",
    )
    options.add_argument(
        "--shodan-key",
        metavar="KEY",
        default=None,
        help="Shodan API key (or set SHODAN_API_KEY env var)",
    )
    options.add_argument(
        "--passive",
        action="store_true",
        default=False,
        help="Passive mode: skip port scan and HTTP header checks",
    )

    return parser.parse_args()


def build_output_basename(args):
    if args.output:
        return args.output
    identifier = "_".join(filter(None, [args.email, args.ip, args.username, args.domain]))
    safe = (
        identifier.replace("@", "_at_")
                   .replace(".", "_")
                   .replace("/", "_")
                   .replace(":", "_")
    )
    return f"output_{safe}"


def main():
    args = parse_args()

    if not any([args.domain, args.ip, args.email, args.username]):
        print(BANNER)
        print("[!] No target specified. Use --help for usage.")
        sys.exit(1)

    print(BANNER)

    targets = {
        "domain":   args.domain,
        "ip":       args.ip,
        "email":    args.email,
        "username": args.username,
    }

    # Determine port scan behaviour
    if args.passive or args.no_ports:
        enable_ports = False
    elif args.ip:
        enable_ports = True   # on by default when an IP is given
    elif args.ports:
        enable_ports = True   # user explicitly requested for domain
    else:
        enable_ports = False  # off by default for domain-only scans

    basename = build_output_basename(args)
    print(f"[+] Output base: {basename}  |  Format: {args.format}\n")

    run_osint_scan(
        targets=targets,
        output_file=basename,
        output_format=args.format,
        shodan_key=args.shodan_key,
        enable_ports=enable_ports,
    )


if __name__ == "__main__":
    main()
