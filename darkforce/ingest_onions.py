"""Bulk-ingest structured onion-site records (url/title/lang) from the SIH demo dataset.

Reads data/onion_sites.jsonl (and falls back to data/onion_links.txt URLs) and
upserts each site into the active database driver (SQLite or PG via DATABASE_URL),
auto-assigning a category with darkforce.categories.

Usage:
    python -m darkforce.ingest_onions
    $env:DATABASE_URL="postgresql://darkforce@127.0.0.1:5433/darkforce"; python -m darkforce.ingest_onions
"""
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from darkforce.categories import classify_site, normalize_category
from darkforce.db import DB


def _load_structured():
    path = os.path.join(BASE, "data", "onion_sites.jsonl")
    records = []
    if os.path.exists(path):
        import json

        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except Exception:
                continue
    if records:
        return records
    # fallback: bare URLs
    path = os.path.join(BASE, "data", "onion_links.txt")
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if line.startswith("http"):
                records.append({"url": line, "title": "", "lang": ""})
    return records


def main():
    db = DB()
    records = _load_structured()
    ingested = 0
    for rec in records:
        url = (rec.get("url") or "").strip()
        if not url or "://" not in url:
            continue
        title = (rec.get("title") or "").strip()[:200]
        lang = (rec.get("lang") or "").strip().upper()[:8]
        purpose = rec.get("purpose") or classify_site(title, url)
        purpose = normalize_category(purpose)
        try:
            db.upsert_site(url, title=title or None, category=purpose, lang=lang or None)
            ingested += 1
        except Exception as e:
            print(f"  skip {url[:60]}: {e}")
    print(f"ingested/upserted {ingested} sites")
    return ingested


if __name__ == "__main__":
    main()