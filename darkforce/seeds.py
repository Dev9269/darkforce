import json
import os
import re
import time

import requests
from bs4 import BeautifulSoup

from .categories import classify_site

ONION_V3 = re.compile(r"\b[a-z2-7]{56}\.onion\b")
ONION_ANY = re.compile(r"\b(?:[a-z2-7]{16,56})\.onion\b")

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


def _get(url, params=None, proxies=None, timeout=15, headers=None):
    try:
        return requests.get(url, params=params, proxies=proxies,
                            headers=headers or {"User-Agent": "Mozilla/5.0"}, timeout=timeout)
    except Exception:
        return None


def collect_ahmia(queries=("market vendor", "dump", "database", "combo list")):
    """Ahmia.fi onion discovery.

    Ahmia's clearnet search fixture now requires a Tor-boundary session, so
    clearnet attempts degrade gracefully (return []). When the caller passes a
    Tor proxy (requests `proxies=`) we can still harvest list items.
    """
    out = []
    for q in queries:
        params = {"q": q}
        try:
            seed = _get("https://ahmia.fi/search/", params=params)
        except Exception:
            seed = None
        if not seed or seed.status_code != 200:
            continue
        try:
            soup = BeautifulSoup(seed.text, "html.parser")
            for a in soup.select("li.result a[href], ul#results li a, li a[href*='.onion']"):
                url = a.get("href", "")
                if ".onion" in url:
                    link = ("https://ahmia.fi" + url) if url.startswith("/") else url
                    title = a.get_text(" ", strip=True)[:200] or "ahmia listed"
                    out.append({"title": title, "url": link, "category": "directory",
                                "purpose": classify_site(title, link)})
        except Exception:
            pass
        time.sleep(0.5)
    if out:
        return out
    # Clearnet/Ahmia search is now session-bound; fall back to the public index pages.
    for page in ("/blacklist/", "/about/"):
        r = _get("https://ahmia.fi" + page)
        if not r or ".onion" not in r.text:
            continue
        seen = set()
        for m in ONION_ANY.finditer(r.text.lower()):
            u = m.group(0)
            if u not in seen:
                seen.add(u)
                link = "http://" + u
                out.append({"title": f"ahmia {page.strip('/')} listed", "url": link,
                            "category": "directory", "purpose": classify_site("", link)})
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
            link = "http://" + u
            out.append({"title": "dark.fail listed", "url": link, "category": "directory",
                        "purpose": classify_site("", link)})
    return out


def collect_ransomware(api_key=""):
    """Leak-site candidates from ransomware.live.

    The old clearnet JSON API (`/v2/payloads`, `/v2/groups`) was retired and
    now returns the SPA (404/HTML). We degrade gracefully: try each known
    endpoint, extract .onion addresses we actually see. Requires no key.
    """
    out = []
    h = {"User-Agent": "Mozilla/5.0"}
    if api_key:
        h["X-API-KEY"] = api_key
    candidates = [
        "https://api.ransomware.live/v2/payloads",
        "https://api.ransomware.live/v2/groups",
    ]
    seen = set()
    for url in candidates:
        r = _get(url, headers=h)
        if not r:
            continue
        if r.status_code != 200:
            continue
        for v in ONION_V3.finditer(r.text.lower()):
            u = v.group(0)
            if u not in seen:
                seen.add(u)
                link = "http://" + u
                out.append({"title": "ransomware.live listed", "url": link,
                            "category": "ransom", "purpose": classify_site("", link)})
        if any(".onion" not in x["url"] for x in out):
            break
    return out


def collect_urlhaus(limit=1500, days=1):
    """URLhaus "recent" CSV -> live malware URLs with threat tags.

    abuse.ch is free, no key required. The CSV is ~12k rows/day; each row is
    [id, dateadded, url, url_status, threat, threat category, tags, urlhaus ref, reporter].
    We cap at `limit` so a single pass stays polite, and skip duplicates the
    DB already knows about at ingest time.
    """
    out = []
    if days <= 0:
        days = 1
    csv_url = "https://urlhaus.abuse.ch/downloads/csv_recent/"
    r = _get(csv_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=None)
    if not r or r.status_code != 200:
        return out
    try:
        import csv
        import io

        reader = csv.reader(io.StringIO(r.text))
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if len(row) < 8:
                continue
            url = (row[2] or "").strip()
            if not url or "://" not in url:
                continue
            tags = (row[6] or "").strip()
            out.append({
                "title": f"URLhaus ~ {tags or 'unclassified'}: {url[:60]}",
                "url": url,
                "category": "malware",
                "purpose": classify_site(tags, url),
                "tags": tags,
            })
            if len(out) >= limit:
                break
    except Exception as e:
        print(f"[seeds] urlhaus csv parse error: {e}")
    return out


def collect_onionoo(limit=500, min_running=True):
    """Tor Project Onionoo relay/hidden-service details (free, no key).

    Returns live relay + bridge records keyed by nickname/fingerprint. Hidden
    services aren't in Onionoo, so this populates the relay/infrastructure
    register (bandwidth, flags, AS, country) rather than marketplaces.
    """
    out = []
    params = {"limit": min(limit, 500),
              "fields": "nickname,fingerprint,first_seen,country,as,flags,"
                        "advertised_bandwidth,platform,running,guard,family"}
    if min_running:
        params["running"] = "true"
    r = _get("https://onionoo.torproject.org/details", params=params,
             headers={"User-Agent": "Mozilla/5.0"}, timeout=None)
    if not r or r.status_code != 200:
        return out
    try:
        data = json.loads(r.text)
    except Exception:
        return out
    relays = data.get("relays", [])[:limit]
    for node in relays:
        fingerprint = node.get("fingerprint", "")
        if not fingerprint:
            continue
        node_url = f"https://{node.get('nickname', 'tor-relay')}.onion" if isinstance(node.get("nickname"), str) else ""
        nick = node.get("nickname", "relay")[:60]
        tags = ",".join(node.get("flags", [])[:4])
        out.append({
            "title": f"Tor relay {nick} [{tags}]",
            "url": fingerprint and f"torrelay:{fingerprint}",
            "category": "privacy",
            "purpose": classify_site(nick, "", " ".join(node.get("flags", []))),
            "tags": tags,
        })
    return out


CLEARNET_INDEX = [
    ("Ransomware.live clearnet index", "https://api.ransomware.live/", "ransom"),
    ("Ahmia clearnet index", "https://ahmia.fi/", "search"),
    ("Dark.fail clearnet status", "https://dark.fail/", "directory"),
    ("URLhaus malware feed", "https://urlhaus.abuse.ch/downloads/csv_recent/", "malware"),
    ("Onionoo relay index", "https://onionoo.torproject.org/details", "privacy"),
]


def collect_telegram(channels=None):
    """Ingest public Telegram channels via Telethon (optional).

    Requires:    pip install telethon
    Requires env: TG_API_ID=<api_id>  TG_API_HASH=<api_hash>
    Optional env: TG_SESSION_NAME, TG_CHANNELS (@ch1,@ch2)
    Returns [{title, url, category}] with telegram.me links as seeds. Every
    channel post URL is treated as a lightweight clearnet seed.
    """
    out = []
    channels = channels or os.getenv("TG_CHANNELS", "").strip()
    if not channels:
        return out
    api_id = os.getenv("TG_API_ID", "").strip()
    api_hash = os.getenv("TG_API_HASH", "").strip()
    if not (api_id and api_hash):
        return out
    try:
        import asyncio
        from telethon import TelegramClient
    except ImportError:
        return out
    session = os.getenv("TG_SESSION_NAME", "darkforce")
    channels = [c.strip() if c.strip().startswith("@") else "@" + c.strip()
                for c in channels.split(",") if c.strip()]

    def run():
        return asyncio.run(_telegram_pull(api_id, api_hash, session, channels))

    try:
        out = run()
    except Exception:
        return out
    return out


async def _telegram_pull(api_id, api_hash, session, channels, limit=25):
    from telethon import TelegramClient
    from telethon.tl.functions.messages import GetHistoryRequest
    import io

    out = []
    client = TelegramClient(session, int(api_id), api_hash)
    await client.connect()
    if not await client.is_user_authorized():
        await client.disconnect()
        return out
    for ch in channels:
        try:
            entity = await client.get_entity(ch)
            hist = await client(GetHistoryRequest(
                peer=entity, offset_id=0, offset_date=None,
                add_offset=0, limit=limit, max_id=0, min_id=0, hash=0))
            for m in hist.messages:
                text = (m.message or "").strip()
                if not text:
                    continue
                out.append({"title": text[:200].replace("\n", " "),
                            "url": f"https://t.me/{ch.strip('@')}/{m.id}",
                            "category": "telegram-chat"})
        except Exception:
            continue
    await client.disconnect()
    return out


def collect_source(name):
    """Returns list of {title,url,category} seeds for a named source."""
    if name == "ahmia":
        return collect_ahmia()
    if name == "darkfail":
        return collect_darkfail()
    if name == "ransomware":
        return collect_ransomware()
    if name == "urlhaus":
        return collect_urlhaus()
    if name == "onionoo":
        return collect_onionoo()
    if name == "telegram":
        return collect_telegram()
    if name == "directory":
        return [{"title": t, "url": "http://" + o, "category": c} for t, o, c in ONION_DIRECTORY]
    if name == "clearnet":
        return [{"title": t, "url": u, "category": c} for t, u, c in CLEARNET_INDEX]
    return []


if __name__ == "__main__":
    for s in ("directory", "ahmia", "darkfail", "ransomware"):
        seeds = collect_source(s)
        print(f"{s}: {len(seeds)} seeds, sample: {[x['url'] for x in seeds[:3]]}")