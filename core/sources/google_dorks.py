# osint_aggregator/core/sources/google_dorks.py
from urllib.parse import quote

def _make(dork):
    return {"dork": dork, "search_url": f"https://www.google.com/search?q={quote(dork)}"}

def generate_dorks(target, target_type="domain"):
    if target_type == "domain":
        dorks = [
            f"site:{target}",
            f"site:{target} filetype:pdf",
            f"site:{target} filetype:xls OR filetype:xlsx",
            f"site:{target} filetype:doc OR filetype:docx",
            f"site:{target} filetype:sql",
            f"site:{target} filetype:log",
            f"site:{target} filetype:bak OR filetype:backup",
            f"site:{target} inurl:admin",
            f"site:{target} inurl:login",
            f"site:{target} inurl:dashboard",
            f"site:{target} inurl:config",
            f"site:{target} inurl:backup",
            f"site:{target} inurl:.git",
            f"site:{target} inurl:.env",
            f"site:{target} inurl:phpinfo",
            f'site:{target} intitle:"index of"',
            f'site:{target} intext:"password"',
            f'site:{target} intext:"api_key" OR intext:"apikey" OR intext:"api key"',
            f'site:{target} intext:"secret_key" OR intext:"secret"',
            f'site:{target} inurl:"wp-admin" OR inurl:"wp-login"',
            f'site:{target} inurl:"wp-content/uploads"',
            f"cache:{target}",
            f"related:{target}",
            f'"{target}" email OR "contact us"',
            f'"{target}" "powered by"',
        ]
    elif target_type == "email":
        dorks = [
            f'"{target}"',
            f'"{target}" filetype:pdf',
            f'"{target}" site:linkedin.com',
            f'"{target}" site:github.com',
            f'"{target}" site:pastebin.com',
            f'"{target}" resume OR cv OR curriculum',
            f'"{target}" intext:password',
            f'"{target}" intext:"api_key"',
        ]
    elif target_type == "username":
        dorks = [
            f'"{target}" site:github.com',
            f'"{target}" site:reddit.com',
            f'"{target}" site:twitter.com',
            f'"{target}" site:linkedin.com',
            f'"{target}" site:pastebin.com',
            f'"{target}" profile OR account',
            f'"{target}" intext:"about me"',
        ]
    else:
        dorks = [f'"{target}"']

    return [_make(d) for d in dorks]
