"""Clearnet fingerprint index: known-clear-web hosts used to correlate a
hidden service to its clearnet twin/mirror.

Read-only OPSEC posture: we only ever fetch the configured seed home pages and
store fingerprint metadata (favicon/content hashes, server banner, analytics id,
title). No page content is retained.
"""
import os
import re
from urllib.parse import urlparse

from . import detect, net

DEFAULT_SEED_DOMAINS = ["www.wikipedia.org", "github.com", "news.ycombinator.com"]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def seed_domains():
    raw = os.environ.get("CLEARNET_SEED_DOMAINS", "").strip()
    if raw:
        return [d.strip().lower() for d in raw.split(",") if d.strip()]
    return list(DEFAULT_SEED_DOMAINS)


def _host_of(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _page_title(html):
    m = _TITLE_RE.search(html or "")
    if not m:
        return ""
    return re.sub(r"<[^>]+>", "", m.group(1)).strip()[:200]


def _analytics_ids(html):
    return sorted(set(detect.UA_ANALYTICS.findall(html or "")))


def import_sites(db):
    """Fold known non-.onion site rows (their stored fingerprints) into the
    clearnet index. Idempotent: upsert keyed on hostname."""
    rows = db.q(
        "SELECT url,title,favicon_hash,content_hash,server FROM sites "
        "WHERE url NOT LIKE '%.onion%' "
        "AND (favicon_hash IS NOT NULL OR content_hash IS NOT NULL "
        "     OR (server IS NOT NULL AND server <> ''))")
    added = 0
    for row in rows:
        r = dict(row)
        host = _host_of(r.get("url") or "")
        if not host or host.endswith(".onion"):
            continue
        db.upsert_clearnet_fp(host, title=r.get("title") or "",
                              favicon_hash=r.get("favicon_hash"),
                              content_hash=r.get("content_hash"),
                              server=r.get("server") or "")
        added += 1
    return added


def crawl_seeds(db, domains=None, timeout=20):
    """Fetch each clearnet seed home page and persist its fingerprints."""
    made = 0
    for host in (domains or seed_domains()):
        try:
            snap = net.fetch_snap(f"https://{host}/", timeout=timeout)
        except Exception:
            continue
        fp = detect.fingerprint(snap)
        ids = _analytics_ids(snap.html)
        db.upsert_clearnet_fp(_host_of(snap.url) or host,
                              title=_page_title(snap.html),
                              favicon_hash=fp["favicon_hash"],
                              content_hash=fp["content_hash"],
                              server=fp["server"] or "",
                              analytics_id=ids[0] if ids else "")
        made += 1
    return made


def load(db, crawl=False):
    """Build the correlation index.

    Reads persisted clearnet_fingerprints; on a cold table folds existing
    clearnet site rows once so the index is usable without a crawl. crawl=True
    additionally fetches the configured seed domains first.
    """
    if crawl or not (db.one("SELECT COUNT(*) AS n FROM clearnet_fingerprints") or {}).get("n"):
        if crawl:
            crawl_seeds(db)
        import_sites(db)
    return ClearnetIndex([dict(r) for r in db.load_clearnet_index()])


class ClearnetIndex:
    """Known clearnet host fingerprints, keyed for O(1) attribute lookup.

    A record is a dict with keys:
        host, title, favicon_hash, content_hash, server, analytics_id
    """

    _LOOKUP_ATTRS = (
        ("favicon_hash", "favicon_match", 0.9),
        ("content_hash", "mirror_match", 0.9),
        ("server", "banner_match", 0.75),
    )

    def __init__(self, records=None):
        self.records = []
        self._by = {}
        for rec in records or []:
            self.add(rec)

    def add(self, rec):
        rec = dict(rec)
        self.records.append(rec)
        for field, _kind, _conf in self._LOOKUP_ATTRS:
            value = rec.get(field)
            if value:
                self._by.setdefault((field, value), []).append(rec)
        value = rec.get("analytics_id")
        if value:
            self._by.setdefault(("analytics_id", value), []).append(rec)

    def lookup(self, fp, analytics=None):
        """Return correlation matches for a snapshot fingerprint dict plus the
        analytics ids (list of strings) found in its html. Each match:
            {kind, host, title, attribute, value, confidence}
        """
        out = []
        for field, kind, conf in self._LOOKUP_ATTRS:
            value = fp.get(field)
            if not value:
                continue
            for rec in self._by.get((field, value), []):
                out.append({"kind": kind, "host": rec["host"],
                            "title": rec.get("title") or "", "attribute": field,
                            "value": value, "confidence": conf})
        for aid in analytics or []:
            for rec in self._by.get(("analytics_id", aid), []):
                out.append({"kind": "analytics_match", "host": rec["host"],
                            "title": rec.get("title") or "",
                            "attribute": "analytics_id", "value": aid,
                            "confidence": 0.85})
        return out