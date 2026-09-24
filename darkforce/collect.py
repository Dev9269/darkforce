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


def _site_source(db, site_id):
    """The sources.id recorded on a site row (NULL-safe, silent)."""
    try:
        r = db.one("SELECT source_id FROM sites WHERE id=?", (site_id,))
        return r["source_id"] if r else None
    except Exception:
        return None


def import_stealer_log(db, lines, source_name="stealer_log:manual"):
    """Parse a stealer-log / combo-list dump and ingest its METADATA.

    Safety contract: passwords are never stored. We keep the email (as a
    correlation primary-entity) and any btc/xmr wallets, both byte-capped and
    ledgered. Breach -> corpus pivot links let the Analyst graph cross to 'who
    else reused the same wallet'. Idempotent across re-imports."""
    from . import extract

    parsed = {"emails": set(), "btc": set(), "xmr": set(), "lines": 0}
    for ln in lines or []:
        ln = (ln or "").strip()
        if not ln or ln.startswith("#"):
            continue
        parsed["lines"] += 1
        for e in extract.EMAIL.findall(ln):
            parsed["emails"].add(e.lower())
        for w in extract.BTC.findall(ln):
            parsed["btc"].add(w)
        for w in extract.XMR.findall(ln):
            parsed["xmr"].add(w)

    first_email = sorted(parsed["emails"])[0] if parsed["emails"] else ""
    db.upsert_breach(source_name, "stealer_log", primary_entity=first_email)

    n_ids = 0
    for e in parsed["emails"]:
        ch = db.add_observation("stealer:email", "email", e, collector_version=source_name)
        db.add_identifier(None, "", "email", e, detail=f"breach:{source_name}",
                          content_hash=ch, method="stealer:email")
        db.record_breach_pivot(e, source_name, edge="leaked_in")
        n_ids += 1
    for w in parsed["btc"]:
        ch = db.add_observation("stealer:btc", "btc", w, collector_version=source_name)
        db.add_identifier(None, "", "btc", w, detail=f"breach:{source_name}",
                          content_hash=ch, method="stealer:btc")
        db.upsert_wallet(w, "btc", category="stealer_log")
        db.record_breach_pivot(w, source_name, edge="leaked_in")
        n_ids += 1
    for w in parsed["xmr"]:
        ch = db.add_observation("stealer:xmr", "xmr", w, collector_version=source_name)
        db.add_identifier(None, "", "xmr", w, detail=f"breach:{source_name}",
                          content_hash=ch, method="stealer:xmr")
        db.upsert_wallet(w, "xmr", category="stealer_log")
        db.record_breach_pivot(w, source_name, edge="leaked_in")
        n_ids += 1

    db.log_source_health(source_name, ok=True)
    return {"breach": source_name,
            "emails": len(parsed["emails"]), "btc": len(parsed["btc"]),
            "xmr": len(parsed["xmr"]), "lines": parsed["lines"],
            "identifiers": n_ids}


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


def _crawl_classify(snap, url, max_text=1600):
    """Re-tag a fetched page with the analyst taxonomy from its visible content.

    Metadata only: title, url and a text prefix are fed to classify_site; the
    result is the canonical category used for the Resources / Darknet News
    catalog views. Never stores page content itself.
    """
    try:
        from darkforce import categories as _cats
        soup = BeautifulSoup(snap.html, "html.parser")
        title = soup.title.get_text(" ", strip=True) if soup.title else ""
        text = _page_body(soup, max_len=max_text)
        return _cats.classify_site(title, url, text)
    except Exception:
        return ""


def crawl_and_ingest(db, url, use_tor=False, timeout=20, fast=False):
    """Fetch one site and ingest actors, handles, identifiers, findings and a post.

    fast=True uses single-attempt fetches (bulk sweep: dead onions fail quickly).
    Never raises: every step is guarded so a single bad site cannot kill the
    crawl. Returns a summary dict the caller can print or aggregate.
    """
    res = {"url": url, "error": None, "skipped": None,
           "findings": 0, "identifiers": 0, "posts": 0, "handles": 0}

    try:
        snap = net.fetch_snap(url, use_tor=use_tor, timeout=timeout, fast=fast)
    except Exception as e:
        res["error"] = f"fetch: {e}"
        # previously-indexed site no longer resolves -> signal go-dark / pivot
        if db.site_content_hash(url):
            try:
                db.mark_site_scanned(url, status="down")
            except Exception:
                pass
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
        prev_row = db.one("SELECT category FROM sites WHERE url=?", (url,)) or {}
        prev_cat = (prev_row.get("category") or "").strip()
        if prev_cat and prev_cat not in ("onion", "clearnet", "other", ""):
            kw_cat = prev_cat
        else:
            kw_cat = "onion" if ".onion" in (urlparse(url).hostname or "") else "clearnet"
        _tagged = _crawl_classify(snap, url)
        if _tagged and _tagged != "other":
            kw_cat = _tagged
        site_id = db.upsert_site(
            url,
            server=fp["server"] or "",
            favicon_hash=fp["favicon_hash"],
            content_hash=fp["content_hash"],
            category=kw_cat,
            status=str(getattr(snap, "status", "?")),
            cert_sans=fp["cert_sans"] or None,
            tls_issuer=fp["tls_issuer"] or None,
            cert_fp=fp["cert_fp"] or None,
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
        from .clearnet_index import load as _load_clearnet
        idx = _load_clearnet(db)
    except Exception:
        idx = None

    try:
        findings, fps = detect.scan(snap, idx)
        detect.pipeline_findings(site_id, db, findings, fps,
                                 url=url, source_id=_site_source(db, site_id), method="detect:scan")
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
                detect.pipeline_findings(site_id, db, deep, {},
                                         url=url, source_id=_site_source(db, site_id),
                                         method="onionscan")
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
                source_id=_site_source(db, site_id),
                method=f"extract:{ident['kind']}",
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