import re
import sys
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from . import detect, extract, net
from .db import utcnow

AUTHOR_SELECTORS = [
    "meta[name='author']",
    "[rel='author']",
    "[itemprop='author']",
    "[data-author]",
    ".author",
    ".postauthor",
    ".post-author",
    ".poster",
    ".username",
    ".member",
    ".vendor",
    ".seller",
    ".market-author",
]


def log(msg, *args):
    print("[collect]", msg.format(*args), file=sys.stderr)


def _clean_handle(value):
    v = re.sub(r"^@", "", (value or "").strip())
    v = re.sub(r"\s+", "_", v)
    v = re.sub(r"[^\w.\-]", "", v)
    v = v.strip("._-")
    if len(v) > 40:
        v = v[:40]
    return v


def _host_handle(url):
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return None
    parts = [p for p in host.split(".") if p and p != "www"]
    return parts[0] if parts else host


def _page_title(soup, url):
    og = soup.find("meta", attrs={"property": "og:title"}) or soup.find("meta", attrs={"name": "twitter:title"})
    if og and (og.get("content") or "").strip():
        return (og.get("content") or "").strip()[:200]
    t = soup.title.get_text(" ", strip=True) if soup.title else ""
    if t:
        return t[:200]
    return (urlparse(url).hostname or url)[:200]


def _page_handles(soup, url):
    """Distinct author handles detectable on the page; falls back to hostname prefix."""
    found = []
    seen = set()
    for sel in AUTHOR_SELECTORS:
        for el in soup.select(sel):
            if sel.startswith("meta"):
                v = el.get("content") or ""
            else:
                v = el.get("content") or el.get("data-author") or el.get_text(" ", strip=True)
            v = re.sub(r"^(Author|Posted by|User|Member|Vendor|Seller)\s*[:,]?\s*", "", v, flags=re.I)
            v = v.split("@")[0]
            h = _clean_handle(v)
            if h and len(h) >= 3 and h.lower() not in seen:
                seen.add(h.lower())
                found.append(h)
            if len(found) >= 8:
                break
        if len(found) >= 8:
            break
    if found:
        return found
    h = _host_handle(url)
    return [h] if h else []


def _page_body(soup, max_len=4000):
    txt = soup.get_text(" ", strip=True)
    txt = re.sub(r"\s+", " ", txt)
    return txt[:max_len]


def crawl_and_ingest(db, url, use_tor=False, timeout=20):
    """Fetch one site and ingest actors, handles, identifiers, findings and a post.

    Never raises: every step is guarded so a single bad site cannot kill the
    crawl. Returns a summary dict the caller can print or aggregate.
    """
    res = {"url": url, "error": None, "skipped": None,
           "findings": 0, "identifiers": 0, "posts": 0, "handles": 0}

    try:
        snap = net.fetch_snap(url, use_tor=use_tor, timeout=timeout)
    except Exception as e:
        res["error"] = f"fetch: {e}"
        log("SKIP {} -> {}", url, res["error"])
        return res

    try:
        fp = detect.fingerprint(snap)
        prev_hash = db.site_content_hash(url)
        if prev_hash and prev_hash == fp["content_hash"]:
            db.mark_site_scanned(url, content_hash=prev_hash)
            res["skipped"] = "dedup"
            log("DEDUP {} unchanged bytes hash, last_scan bumped", url)
            return res
        site_id = db.upsert_site(
            url,
            server=fp["server"] or "",
            favicon_hash=fp["favicon_hash"],
            content_hash=fp["content_hash"],
            category="onion" if ".onion" in (urlparse(url).hostname or "") else "clearnet",
            status=str(getattr(snap, "status", "?")),
        )
    except Exception as e:
        res["error"] = f"site: {e}"
        log("FAIL {} site upsert: {}", url, e)
        return res

    wall = (snap.meta or {}).get("wall")
    if wall in ("captcha", "blocked"):
        try:
            db.mark_site_scanned(url, status=f"blocked_{wall}")
        except Exception:
            pass
        res["skipped"] = wall
        log("WALL {} -> {{wall}} (skipped, marked)", url)
        return res

    try:
        findings, fps = detect.scan(snap)
        detect.pipeline_findings(site_id, db, findings, fps)
        res["findings"] = len(findings)
    except Exception as e:
        log("WARN {} scan/findings: {}", url, e)

    # watchlist alerting on new findings
    try:
        for kind, sev, detail, conf in findings:
            try:
                db.evaluate_watchlists(detail, url=url, kind=kind)
            except Exception:
                pass
    except Exception:
        pass

    host = (urlparse(url).hostname or "")
    if host.endswith(".onion"):
        try:
            deep = detect.onionscan(url)
            if deep:
                detect.pipeline_findings(site_id, db, deep, {})
                res["findings"] += len(deep)
                log("ONIONSCAN {} -> {} finding(s)", url, len(deep))
        except Exception as e:
            log("WARN {} onionscan: {}", url, e)

    handles = _page_handles(BeautifulSoup(snap.html, "html.parser"), url)

    for h in handles:
        try:
            aid = db.upsert_actor(h, category="onion" if ".onion" in (urlparse(url).hostname or "") else "clearnet")
            db.upsert_handle(aid, h, site_id, url)
        except Exception as e:
            log("WARN {} handle {}: {}", url, h, e)

    try:
        for ident in extract.extract_identifiers(snap.html):
            db.add_identifier(
                actor_id=None,
                handle=handles[0] if handles else "",
                kind=ident["kind"],
                value=ident["value"],
                detail=ident["detail"],
                site_id=site_id,
                url=url,
            )
            res["identifiers"] += 1
    except Exception as e:
        log("WARN {} identifiers: {}", url, e)

    try:
        soup = BeautifulSoup(snap.html, "html.parser")
        title = _page_title(soup, url)
        body = _page_body(soup)
        if handles:
            db.save_post(handles[0], site_id, url, title, body, ts=utcnow())
            res["posts"] += 1
    except Exception as e:
        log("WARN {} post: {}", url, e)

    res["handles"] = len(handles)
    log("OK {} findings={} identifiers={} posts={} handles={}",
        url, res["findings"], res["identifiers"], res["posts"], res["handles"])
    return res