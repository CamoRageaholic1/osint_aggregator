# osint_aggregator/core/sources/dns_lookup.py
import dns.resolver

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

def get_dns_records(domain):
    records = {}
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 10

    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            if rtype == "MX":
                records[rtype] = sorted(
                    [f"{r.preference} {r.exchange}" for r in answers]
                )
            elif rtype == "SOA":
                r = answers[0]
                records[rtype] = [
                    f"mname={r.mname} rname={r.rname} serial={r.serial} "
                    f"refresh={r.refresh} retry={r.retry} expire={r.expire}"
                ]
            else:
                records[rtype] = [str(r) for r in answers]
        except dns.resolver.NoAnswer:
            records[rtype] = []
        except dns.resolver.NXDOMAIN:
            records[rtype] = ["[!] Domain does not exist (NXDOMAIN)"]
            break
        except Exception as e:
            records[rtype] = [f"[!] {e}"]

    return records
