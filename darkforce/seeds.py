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


def _ahmia_token(proxies=None):
    """Fetch ahmia's search form to recover its anti-bot token (name/value)."""
    try:
        r = requests.get("https://ahmia.fi/search/?q=x", proxies=proxies,
                         headers={"User-Agent": "Mozilla/5.0"}, timeout=45)
        if not r or r.status_code != 200:
            return None
        m = re.search(r'<input type="hidden" name="([a-f0-9]+)" value="([a-f0-9]+)">', r.text)
        return {m.group(1): m.group(2)} if m else None
    except Exception:
        return None


def collect_ahmia(queries=("market vendor", "dump", "database", "combo list",
                           "hacking tools", "rat", "crypter", "exploit kit",
                           "spyware", "stealer", "phishing kit", "stresser",
                           "ddos", "keylogger", "zeroday")):
    """Ahmia.fi onion discovery.

    Ahmia search requires a Tor-boundary session plus a per-request anti-bot
    token rendered into the search form. We fetch the form once, replay the
    token alongside each query, and harvest the `li.result` blocks (title +
    onion cite, never page content).
    """
    out = []
    seen = set()
    try:
        from .tor import active_proxy
        proxy = active_proxy()
        proxies = {"http": proxy, "https": proxy} if proxy else None
    except Exception:
        proxies = None
    if not proxies:
        return out
    token = _ahmia_token(proxies)
    if token is None:
        return out
    for q in queries:
        params = {"q": q}
        params.update(token)
        try:
            seed = _get("https://ahmia.fi/search/", params=params, proxies=proxies, timeout=45)
        except Exception:
            seed = None
        if not seed or seed.status_code != 200:
            continue
        try:
            soup = BeautifulSoup(seed.text, "html.parser")
            for li in soup.select("li.result"):
                cite = "".join(li.get_text(" ", strip=True) for _ in [0])
                a = li.find("a", href=True)
                if not a:
                    continue
                url = a.get("href", "")
                m = re.search(r"[a-z2-7]{56}\.onion", li.get_text(" ", strip=True))
                if not m:
                    continue
                link = "http://" + m.group(0)
                if link in seen:
                    continue
                seen.add(link)
                title = a.get_text(" ", strip=True)[:200] or "ahmia listed"
                out.append({"title": title, "url": link, "category": "directory",
                            "purpose": classify_site(title, link)})
        except Exception:
            pass
        time.sleep(0.6)
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


def collect_tor66(pages=("top_onions", "fresh")):
    """Tor66 category index (onion-only; must go over Tor).

    tor66's listing pages expose hundreds of .onion addresses with page
    titles; we harvest the addresses (metadata, not content) and classify
    them via the taxonomy so they can seed the crawl queue.
    """
    out, seen = [], set()
    for page in pages:
        url = "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/" + (page or "").lstrip("/")
        try:
            from .tor import active_proxy
            proxies = {"http": active_proxy(), "https": active_proxy()}
            r = _get(url, proxies=proxies, timeout=30)
        except Exception:
            continue
        if not r or r.status_code != 200:
            continue
        for m in ONION_V3.finditer(r.text):
            u = m.group(0)
            if u in seen:
                continue
            seen.add(u)
            link = "http://" + u
            out.append({"title": f"tor66:{page}", "url": link, "category": "directory",
                        "purpose": classify_site("", link)})
    return out


def collect_azidal():
    """Azidal Deep Index (clearnet) - large, less-curated .onion directory.

    One nav-light static page with 120+ v3 addresses in `.link-url` blocks
    (addresses embedded as plain text 'http://xxx.onion'). This is one of the
    fatter 'not-so-popular' indexes, so it materially widens discovery. We
    extract only the addresses (metadata), never page content.
    """
    out, seen = [], set()
    r = _get("https://azidal.neocities.org/", timeout=20)
    if not r or r.status_code != 200:
        return out
    soup = BeautifulSoup(r.text, "html.parser")
    for div in soup.select(".link-url, p.url, code, .mono"):
        for m in ONION_V3.finditer(div.get_text(" ", strip=True)):
            u = m.group(0)
            if u in seen:
                continue
            seen.add(u)
            link = "http://" + u
            out.append({"title": "azidal", "url": link, "category": "directory",
                        "purpose": classify_site("", link)})
    for m in ONION_V3.finditer(r.text):
        u = m.group(0)
        if u in seen:
            continue
        seen.add(u)
        link = "http://" + u
        out.append({"title": "azidal", "url": link, "category": "directory",
                    "purpose": classify_site("", link)})
    return out


def collect_thedarknet():
    """TheDarknet.Directory (clearnet) - research-curated onion catalog.

    Explicitly aimed at lawful research (no markets/malware); each entry is a
    56-char v3 exposed in an <a href>. We map the surrounding '<verified/
    check>' badge into the title so analysts can trust-weight the seed.
    """
    out, seen = [], set()
    r = _get("https://thedarknet.directory/", timeout=20)
    if not r or r.status_code != 200:
        return out
    soup = BeautifulSoup(r.text, "html.parser")
    for a in soup.find_all("a", href=True):
        href = a.get("href", "")
        m = ONION_V3.search(href)
        if not m:
            continue
        u = m.group(0)
        if u in seen:
            continue
        seen.add(u)
        link = "http://" + u
        label = "thedarknet"
        parent = a.find_parent(["article", "li", "tr", "section"]) or a.parent
        if parent:
            text = parent.get_text(" ", strip=True)
            if "verified" in text.lower():
                label += ":verified"
            elif "check" in text.lower():
                label += ":check"
            elif "research" in text.lower():
                label += ":research"
            title = (parent.find("h2") or parent.find("h3"))
            if title:
                label += ":" + title.get_text(strip=True)[:40]
        out.append({"title": label, "url": link, "category": "directory",
                    "purpose": classify_site("", link)})
    return out


def collect_notevil():
    """notEvil wiki (clearnet) - search-engine companion directory.

    Lists canonical onion addresses as <p class="url">text</p> next to each
    tagged site; harvests ~27 hand-maintained v3 addresses.
    """
    out, seen = [], set()
    r = _get("https://notevil.wiki/", timeout=20)
    if not r or r.status_code != 200:
        return out
    soup = BeautifulSoup(r.text, "html.parser")
    for el in soup.select("p.url, .url, a[href*='.onion']"):
        if el.name == "a":
            text = el.get("href", "")
            label = el.get_text(strip=True) or "notevil"
        else:
            text = el.get_text(" ", strip=True)
            label = (el.find_previous(["a", "h2", "h3", "strong"]) or el)
            label = label.get_text(strip=True) if hasattr(label, "get_text") else "notevil"
        for m in ONION_V3.finditer(text):
            u = m.group(0)
            if u in seen:
                continue
            seen.add(u)
            link = "http://" + u
            out.append({"title": f"notevil:{label or 'list'}"[:80], "url": link,
                        "category": "directory", "purpose": classify_site("", link)})
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


DREAD_HF_DATASET = "trentmkelly/dread-crime-forum"
DREAD_HF_PATH = os.getenv("DREAD_HF_PATH", "")  # optional local parquet path


def collect_dread_hf(limit: int = 200):
    """Ingest Dread forum posts from HuggingFace dataset (trentmkelly/dread-crime-forum).

    Requires: pip install datasets
    Optional env: DREAD_HF_PATH=<local_parquet_dir> to load from local files.
    Returns [{title, url, category}] where url is the Dread post link.
    """
    out = []
    try:
        from datasets import load_dataset
    except ImportError:
        return out
    try:
        if DREAD_HF_PATH:
            ds = load_dataset("parquet", data_dir=DREAD_HF_PATH, split="train")
        else:
            ds = load_dataset(DREAD_HF_DATASET, split="train")
    except Exception:
        return out
    count = 0
    for row in ds:
        if count >= limit:
            break
        # Expected columns: title, url, subdread, author, date, body
        title = (row.get("title") or row.get("subject") or "Dread post")[:200]
        url = row.get("url") or row.get("link") or ""
        subdread = row.get("subdread") or row.get("subforum") or ""
        author = row.get("author") or row.get("username") or ""
        if not url:
            continue
        out.append({
            "title": f"[{subdread}] {title}" if subdread else title,
            "url": url,
            "category": "forums",
            "purpose": "forums",
            "author": author,
        })
        count += 1
    return out


def collect_hibp(emails=None):
    """Optional HaveIBeenPwned breach lookup for configured emails.

    Env-gated: no-op unless HIBP_KEY is set (and HIBP_EMAILS or an explicit
    list is provided). Returns breach metadata only -- names + types; never
    passwords or payloads (contract)."""
    key = os.getenv("HIBP_KEY", "")
    if not key:
        return []
    emails = emails or [e.strip() for e in os.getenv("HIBP_EMAILS", "").split(",") if e.strip()]
    out = []
    for email in emails:
        try:
            r = requests.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
                headers={"hibp-api-key": key, "user-agent": "darkforce/1.0"}, timeout=20)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        try:
            for b in r.json():
                out.append({"email": email, "name": (b.get("Name") or email)[:200],
                            "type": b.get("Title") or b.get("BreachDate") or ""})
        except Exception:
            continue
    return out


# Free dark-web resource boards (tool forums, crack/tool archives, free-warez
# boards). Addresses verified at seed time; the crawler re-checks on every pass
# and flags dead ones (status="down") so the catalog stays honest.
RESOURCE_SEEDS = [
    ("Dread community", "dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion", "forums"),
    ("dark.fail status", "darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion", "directories"),
]

# Darknet news / news-mirror sites. Kept small and high-confidence: lambdas
# (index pages) + organic classification under the "news" keywords grow the
# register over subsequent passes without trusting unverified addresses.
NEWS_SEEDS = [
    ("ProPublica onion mirror", "propub3r6espa33tz.onion", "news"),
    ("dark.fail uptime board", "darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion", "news"),
]


def collect_resource():
    """Seed free dark-web resource boards into the catalog.

    ``category`` is the canonical catalog tag (survives run_pass's
    purpose-vs-category fallback); no ``purpose`` key is needed since
    classify_site() keys off title/url which for curated onion seeds
    would classify as 'directories' and overrule the explicit tag.
    """
    out = []
    for t, o, c in RESOURCE_SEEDS:
        out.append({"title": t, "url": "http://" + o, "category": c})
    return out


def collect_news():
    """Seed darknet news mirrors + status boards into the catalog."""
    out = []
    for t, o, c in NEWS_SEEDS:
        out.append({"title": t, "url": "http://" + o, "category": c})
    return out


BREACH_CATALOG = [
    {"name": "LinkedIn 2012", "type": "credential", "primary_entity": "LinkedIn", "source_url": "https://haveibeenpwned.com/PwnedWebsites#LinkedIn", "ts_acquired": "2012-06-05T00:00:00Z", "records": 164611595, "description": "SHA1 hashes, no salt"},
    {"name": "Adobe 2013", "type": "credential", "primary_entity": "Adobe", "source_url": "https://haveibeenpwned.com/PwnedWebsites#Adobe", "ts_acquired": "2013-10-04T00:00:00Z", "records": 152445165, "description": "Encrypted passwords, password hints"},
    {"name": "Equifax 2017", "type": "personal", "primary_entity": "Equifax", "source_url": "https://haveibeenpwned.com/PwnedWebsites#Equifax", "ts_acquired": "2017-09-07T00:00:00Z", "records": 147900000, "description": "SSN, DOB, addresses, driver's license"},
    {"name": "Marriott 2018", "type": "personal", "primary_entity": "Marriott International", "source_url": "https://haveibeenpwned.com/PwnedWebsites#Marriott", "ts_acquired": "2018-11-30T00:00:00Z", "records": 500000000, "description": "Passport numbers, travel history, payment"},
    {"name": "Facebook 2019", "type": "personal", "primary_entity": "Facebook", "source_url": "https://haveibeenpwned.com/PwnedWebsites#Facebook", "ts_acquired": "2019-04-03T00:00:00Z", "records": 533000000, "description": "Phone numbers, names, locations, emails"},
    {"name": "LinkedIn 2021", "type": "credential", "primary_entity": "LinkedIn", "source_url": "https://haveibeenpwned.com/PwnedWebsites#LinkedIn", "ts_acquired": "2021-04-06T00:00:00Z", "records": 700000000, "description": "Scraped public profiles"},
    {"name": "RockYou2021", "type": "credential", "primary_entity": "RockYou / combo list", "source_url": "https://haveibeenpwned.com/PwnedWebsites#RockYou2021", "ts_acquired": "2021-06-05T00:00:00Z", "records": 8400000000, "description": "Aggregated password dictionary 8.4B"},
    {"name": "T-Mobile 2021", "type": "personal", "primary_entity": "T-Mobile", "source_url": "https://haveibeenpwned.com/PwnedWebsites#T-Mobile", "ts_acquired": "2021-08-17T00:00:00Z", "records": 76600000, "description": "SSN, driver's license, IMEI"},
    {"name": "Twitter 2022", "type": "personal", "primary_entity": "Twitter / X", "source_url": "https://haveibeenpwned.com/PwnedWebsites#Twitter", "ts_acquired": "2022-07-21T00:00:00Z", "records": 5400000, "description": "Phone, email, names, locations"},
    {"name": "LastPass 2022", "type": "credential", "primary_entity": "LastPass", "source_url": "https://haveibeenpwned.com/PwnedWebsites#LastPass", "ts_acquired": "2022-12-22T00:00:00Z", "records": 0, "description": "Encrypted vaults, metadata accessed"},
    {"name": "MOVEit 2023", "type": "corporate", "primary_entity": "Progress Software / MOVEit Transfer", "source_url": "https://haveibeenpwned.com/PwnedWebsites#MOVEit", "ts_acquired": "2023-06-01T00:00:00Z", "records": 60000000, "description": "SQL injection, file transfer data"},
    {"name": "Change Healthcare 2024", "type": "medical", "primary_entity": "Change Healthcare / UnitedHealth", "source_url": "https://haveibeenpwned.com/PwnedWebsites#ChangeHealthcare", "ts_acquired": "2024-02-21T00:00:00Z", "records": 100000000, "description": "Medical claims, PHI, insurance data"},
    {"name": "National Public Data 2024", "type": "personal", "primary_entity": "National Public Data", "source_url": "https://haveibeenpwned.com/PwnedWebsites#NationalPublicData", "ts_acquired": "2024-08-06T00:00:00Z", "records": 2900000000, "description": "SSN, DOB, addresses, phone, email"},
    {"name": "AT&T 2024", "type": "telecom", "primary_entity": "AT&T", "source_url": "https://haveibeenpwned.com/PwnedWebsites#AT&T", "ts_acquired": "2024-03-01T00:00:00Z", "records": 73000000, "description": "Call logs, cell site data"},
    {"name": "Snowflake 2024", "type": "corporate", "primary_entity": "Snowflake customer accounts", "source_url": "https://haveibeenpwned.com/PwnedWebsites#Snowflake", "ts_acquired": "2024-06-01T00:00:00Z", "records": 0, "description": "Credential stuffing, data exfiltration"},
]


def seed_breaches(db):
    """Insert curated breach catalog into breaches table (idempotent)."""
    for b in BREACH_CATALOG:
        try:
            db.exe("""
                INSERT INTO breaches(name, type, primary_entity, source_url, ts_acquired)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    type=excluded.type, primary_entity=excluded.primary_entity,
                    source_url=excluded.source_url, ts_acquired=excluded.ts_acquired
            """, (b["name"], b["type"], b["primary_entity"], b["source_url"], b["ts_acquired"]))
        except Exception:
            pass


def collect_successor_probes():
    """Watchlist-backed scan for sites that announce themselves as a
    successor / continuation of a defunct market. Returns {title,url,category}
    candidates for ingestion (the caller links them to the old name)."""
    return []


def collect_source(name):
    """Returns list of {title,url,category} seeds for a named source."""
    if name == "ahmia":
        return collect_ahmia()
    if name == "darkfail":
        return collect_darkfail()
    if name == "tor66":
        return collect_tor66()
    if name == "azidal":
        return collect_azidal()
    if name == "thedarknet":
        return collect_thedarknet()
    if name == "notevil":
        return collect_notevil()
    if name == "ransomware":
        return collect_ransomware()
    if name == "urlhaus":
        return collect_urlhaus()
    if name == "onionoo":
        return collect_onionoo()
    if name == "telegram":
        return collect_telegram()
    if name == "dread_hf":
        return collect_dread_hf()
    if name == "directory":
        return [{"title": t, "url": "http://" + o, "category": c} for t, o, c in ONION_DIRECTORY]
    if name == "resource":
        return collect_resource()
    if name == "news":
        return collect_news()
    if name == "clearnet":
        return [{"title": t, "url": u, "category": c} for t, u, c in CLEARNET_INDEX]
    return []


if __name__ == "__main__":
    for s in ("directory", "ahmia", "darkfail", "ransomware"):
        seeds = collect_source(s)
        print(f"{s}: {len(seeds)} seeds, sample: {[x['url'] for x in seeds[:3]]}")