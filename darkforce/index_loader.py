"""Bulk onion-address registration from public indexes + local harvests.

Registers addresses as status='listed' (no bulk crawl). The rolling liveness
sweep (Phase 4) re-checks listed sites in bite-sized batches.

Safety: we register/link metadata only (url/title/purpose). We never bulk-crawl
thousands of paths and never store page content.
"""
import json
import os

import requests

from .categories import classify_site, normalize_category
from .extract import ONION_V3 as ONION_RE

AHMIA_INDEX_URL = "https://ahmia.fi/onions/"


def normalize_onion(raw):
    """Return canonical 'http://<v3>.onion' or None."""
    if not raw:
        return None
    m = ONION_RE.search((raw or "").lower())
    if not m:
        return None
    return "http://" + m.group(0)


def _as_item(url, title="", purpose="", category="directory"):
    url = normalize_onion(url)
    if not url:
        return None
    return {"title": (title or url)[:200], "url": url,
            "category": category,
            "purpose": purpose or classify_site(title, url)}


def load_ahmia_index(fetch=requests.get, base_url=AHMIA_INDEX_URL):
    out, seen = [], set()
    try:
        r = fetch(base_url, headers={"User-Agent": "Mozilla/5.0"}, timeout=45)
    except Exception:
        return out
    if not getattr(r, "status_code", 0) == 200:
        return out
    for m in ONION_RE.finditer(r.text.lower()):
        it = _as_item(m.group(0), title=f"ahmia indexed {m.group(0)[:16]}")
        if it and it["url"] not in seen:
            seen.add(it["url"])
            out.append(it)
    return out


def load_local_catalogs(base_dir="data"):
    """Combine onion_sites.jsonl + harvest_results.jsonl + ahmia_onions.txt."""
    out, seen = [], set()
    for fname in ("onion_sites.jsonl", "harvest_results.jsonl"):
        path = os.path.join(base_dir, fname)
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    d = json.loads(line)
                except Exception:
                    continue
                url = d.get("url") or ""
                it = _as_item(url, title=d.get("title", ""),
                              purpose=d.get("purpose", ""))
                if it and it["url"] not in seen:
                    seen.add(it["url"])
                    out.append(it)
    path = os.path.join(base_dir, "ahmia_onions.txt")
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                it = _as_item(line.strip(), title="ahmia list")
                if it and it["url"] not in seen:
                    seen.add(it["url"])
                    out.append(it)
    return out


def load_extra_dumps(urls, fetch=requests.get):
    """Optional DF_INDEX_URLS dumps: raw text or jsonl of onion addresses."""
    out, seen = [], set()
    for u in urls or []:
        if not u:
            continue
        try:
            r = fetch(u, headers={"User-Agent": "Mozilla/5.0"}, timeout=60)
        except Exception:
            continue
        if not getattr(r, "status_code", 0) == 200:
            continue
        body = r.text
        for m in ONION_RE.finditer(body.lower()):
            it = _as_item(m.group(0), title=f"dump:{u[:40]}")
            if it and it["url"] not in seen:
                seen.add(it["url"])
                out.append(it)
    return out


def import_indexes(db, items, source_id=None):
    """Upsert unique listed sites. Returns {'new': n, 'total': m}."""
    new = total = 0
    seen = set()
    for it in items:
        url = normalize_onion(it.get("url") or "")
        if not url or url in seen:
            continue
        seen.add(url)
        purpose = it.get("purpose") or ""
        cat = normalize_category(purpose) if normalize_category(purpose) != "other" else it.get("category", "directory")
        prev = db.one("SELECT status FROM sites WHERE url=?", (url,))
        if prev:
            total += 1
            continue
        db.upsert_site(url, title=it.get("title") or url, category=cat,
                       status="listed", source_id=source_id, last_scan=None)
        new += 1
        total += 1
    return {"new": new, "total": total}


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(prog="index_loader")
    ap.add_argument("--dir", default="data")
    ap.add_argument("--ahmia", action="store_true")
    ap.add_argument("--local", action="store_true")
    ap.add_argument("--extra", default="", help="comma-separated dump URLs")
    args = ap.parse_args(argv)

    from darkforce.db import DB
    db = DB()
    items = []
    if args.ahmia:
        items += load_ahmia_index()
    if args.local:
        items += load_local_catalogs(args.dir)
    extra = [u for u in args.extra.split(",") if u.strip()]
    if extra:
        items += load_extra_dumps(extra)
    db.upsert_source("index_loader", "index", AHMIA_INDEX_URL)
    src = db.one("SELECT id FROM sources WHERE name='index_loader'")["id"]
    res = import_indexes(db, items, source_id=src)
    print(f"[index] imported {res['new']} new (of {res['total']} unique) -> stats {db.stats()}")


if __name__ == "__main__":
    main()