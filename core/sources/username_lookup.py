# osint_aggregator/core/sources/username_lookup.py
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Platform definitions: check="status" means 200=found, 404=not found.
# check="not_found_text" means look for a string in the body to confirm absence.
# check="not_null" means non-"null" body = found (JSON APIs).
PLATFORMS = [
    {"name": "GitHub",          "url": "https://github.com/{u}",                                    "check": "status"},
    {"name": "GitLab",          "url": "https://gitlab.com/{u}",                                    "check": "status"},
    {"name": "Reddit",          "url": "https://www.reddit.com/user/{u}/about.json",                "check": "status"},
    {"name": "Twitter/X",       "url": "https://twitter.com/{u}",                                   "check": "status"},
    {"name": "Instagram",       "url": "https://www.instagram.com/{u}/",                            "check": "status"},
    {"name": "TikTok",          "url": "https://www.tiktok.com/@{u}",                               "check": "status"},
    {"name": "Pinterest",       "url": "https://www.pinterest.com/{u}/",                            "check": "status"},
    {"name": "Twitch",          "url": "https://www.twitch.tv/{u}",                                 "check": "status"},
    {"name": "YouTube",         "url": "https://www.youtube.com/@{u}",                              "check": "status"},
    {"name": "Keybase",         "url": "https://keybase.io/{u}",                                    "check": "status"},
    {"name": "Medium",          "url": "https://medium.com/@{u}",                                   "check": "status"},
    {"name": "Dev.to",          "url": "https://dev.to/{u}",                                        "check": "status"},
    {"name": "Telegram",        "url": "https://t.me/{u}",                                          "check": "status"},
    {"name": "npm",             "url": "https://www.npmjs.com/~{u}",                                "check": "status"},
    {"name": "PyPI",            "url": "https://pypi.org/user/{u}/",                                "check": "status"},
    {"name": "DockerHub",       "url": "https://hub.docker.com/u/{u}/",                             "check": "status"},
    {"name": "HackerNews",      "url": "https://hacker-news.firebaseio.com/v0/user/{u}.json",       "check": "not_null"},
    {"name": "Steam",           "url": "https://steamcommunity.com/id/{u}",                         "check": "not_found_text", "nft": "The specified profile could not be found."},
    {"name": "Gravatar",        "url": "https://en.gravatar.com/{u}",                               "check": "status"},
    {"name": "About.me",        "url": "https://about.me/{u}",                                      "check": "status"},
    {"name": "Pastebin",        "url": "https://pastebin.com/u/{u}",                                "check": "not_found_text", "nft": "Not Found"},
    {"name": "Replit",          "url": "https://replit.com/@{u}",                                   "check": "status"},
    {"name": "Codepen",         "url": "https://codepen.io/{u}",                                    "check": "status"},
    {"name": "Mastodon (infosec.exchange)", "url": "https://infosec.exchange/@{u}",                  "check": "status"},
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"
}

def _check_platform(platform, username):
    url = platform["url"].format(u=username)
    name = platform["name"]
    try:
        res = requests.get(url, headers=HEADERS, timeout=9, allow_redirects=True)
        check = platform["check"]
        if check == "status":
            found = res.status_code == 200
        elif check == "not_null":
            found = res.text.strip() not in ("null", "")
        elif check == "not_found_text":
            found = platform.get("nft", "") not in res.text
        else:
            found = res.status_code == 200

        return {"platform": name, "url": url, "found": found, "status_code": res.status_code}
    except requests.exceptions.Timeout:
        return {"platform": name, "url": url, "found": None, "error": "timeout"}
    except Exception as e:
        return {"platform": name, "url": url, "found": None, "error": str(e)}

def lookup_username(username):
    results = []
    with ThreadPoolExecutor(max_workers=12) as executor:
        futures = {executor.submit(_check_platform, p, username): p for p in PLATFORMS}
        for future in as_completed(futures):
            results.append(future.result())

    # Sort: found first, then unknown, then not found
    def sort_key(r):
        if r.get("found") is True:
            return 0
        if r.get("found") is None:
            return 1
        return 2

    return sorted(results, key=sort_key)
