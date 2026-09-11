import json
import re
import time

import requests
from bs4 import BeautifulSoup

ONION_V3 = re.compile(r"\b[a-z2-7]{56}\.onion\b")

# Dark.fail verified addresses (Sept 2026) and other known fixtures - fallback when offline.
ONION_DIRECTORY = [
    ("Dread forum", "dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion", "forum"),
    ("Recon vendor search", "recon222tttn4ob7ujdhbn3s4gjre7netvzybuvbq2bcqwltkiqinhad.onion", "search"),
    ("Drughub market", "drughuberjxfrxtlk2cystdz4jvogmc3lsnk5drvwx2nfi63ou2r2kid.onion", "market"),
    ("Torzon market", "torzonoxqu4kibxr6yjxangdondtzupzba5hhdiakjdkczyiqhdmhgad.onion", "market"),
    ("Prime market", "primeazlozdecj746nw7anc7vpcaz3pqltbjm4slxx6y6g4r3tel35qd.onion", "market"),
    ("Black Ops market", "blackopiilza74ekpzlymiyjbkio6mro25ddx5wbjmnl3tbus7c67nad.onion", "market"),
    ("Dark.fail status", "darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion", "directory"),
    ("Ahmia", "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion", "search"),
    ("DuckDuckGo", "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion", "search"),
    ("Torch", "xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion", "search"),
    ("Tor66", "tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion", "search"),
    ("Deepr", "deeprecyrsonacndoosu3udqp7ziofjddoiq6grsfizp3m3mvbiinpad.onion", "directory"),
]


def _get(url, proxies=None, timeout=15, headers=None):
    try:
        return requests.get(url, proxies=proxies, headers=headers or {"User-Agent": "Mozilla/5.0"},
                            timeout=timeout)
    except Exception:
        return None


def collect_ahmia(queries=("market vendor", "dump", "database", "combo list")):
    out = []
    for q in queries:
        r = _get("https://ahmia.fi/api/search/", params={"q": q})
        if not r or r.status_code != 200:
            continue
        try:
            for item in r.json() if isinstance(r.json(), list) else r.json().get("results", []):
                url = item.get("url") or item.get("location", "")
                if ".onion" in url:
                    out.append({"title": item.get("title", "")[:200], "url": url,
                                "category": item.get("description", "")[:200]})
        except Exception:
            pass
        time.sleep(0.5)
    return out


def collect_darkfail():
    out = []
    r = _get("https://dark.fail/")
    if not r or r.status_code != 200:
        return out
    soup = BeautifulSoup(r.text, "html.parser")
    for name in soup.select("h2, h3, a"):
        txt = name.get_text(" ", strip=True)
        if not txt or len(txt) > 64:
            continue
        onion = ONION_V3.findall(r.text)  # page-level; keep simple
    seen = set()
    for m in ONION_V3.finditer(r.text):
        u = m.group(0)
        if u not in seen:
            seen.add(u)
            out.append({"title": "dark.fail listed", "url": "http://" + u, "category": "directory"})
    return out


def collect_ransomware(api_key=""):
    out = []
    h = {"User-Agent": "Mozilla/5.0"}
    if api_key:
        h["X-API-KEY"] = api_key
    r = _get("https://api.ransomware.live/v2/recentvictims", headers=h)
    if not r or r.status_code != 200:
        return out
    for v in r.json()[:50]:
        group = v.get("group", "unknown")
        out.append({
            "title": f"Victim: {v.get('victim', '')} ({group})",
            "url": v.get("leak_site") or v.get("url", ""),
            "category": group,
        })
    return out


def collect_source(name):
    """Returns list of {title,url,category} seeds for a named source."""
    if name == "ahmia":
        return collect_ahmia()
    if name == "darkfail":
        return collect_darkfail()
    if name == "ransomware":
        return collect_ransomware()
    if name == "directory":
        return [{"title": t, "url": "http://" + o, "category": c} for t, o, c in ONION_DIRECTORY]
    return []


if __name__ == "__main__":
    for s in ("directory", "ahmia", "darkfail", "ransomware"):
        seeds = collect_source(s)
        print(f"{s}: {len(seeds)} seeds, sample: {[x['url'] for x in seeds[:3]]}")