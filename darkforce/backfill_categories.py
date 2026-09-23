"""One-time backfill: reclassify `sites` with the current taxonomy.

Conservative: never downgrades to 'other' (keeps prior curation when the
classifier is unsure) and normalizes every result to the canonical list.

Usage:
    $env:DATABASE_URL="postgresql://darkforce@127.0.0.1:5433/darkforce"; python -m darkforce.backfill_categories
"""
import re
import sys


def _print(*args, **kw):
    try:
        print(*args, **kw)
    except UnicodeEncodeError:
        print(*(a.encode("ascii", "replace").decode("ascii") if isinstance(a, str) else a for a in args), **kw)

from darkforce.categories import classify_site, normalize_category
from darkforce.db import DB

_URLHAUS = re.compile(r"^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?/i$|^https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?/bin\.sh$")


def main():
    db = DB()
    rows = list(db.q("SELECT id, url, title, category FROM sites"))
    changed = 0
    fixed = 0
    for r in rows:
        old = r["category"] or "other"
        # Source-of-truth repairs for rows the classifier can't see (no text).
        title = r["title"] or ""
        if _URLHAUS.match(r["url"] or "") or title.startswith("URLhaus"):
            new = "malware"
        else:
            # Title-only: a decisive title beats a URL-driven guess (e.g. a
            # generic "dark.fail listed" title whose .onion hosts a wallet).
            new = normalize_category(classify_site(title, ""))
        if new == "other":
            new = old  # never downgrade curated data
        if new != old:
            db.exe("UPDATE sites SET category=? WHERE id=?", (new, r["id"]))
            changed += 1
            if old in ("malware", "financial", "privacy", "forgery", "markets",
                       "financial/carding", "privacy/hosting", "counterfeit",
                       "weapons", "directories"):
                fixed += 1
            _print(f"  {r['id']}: {old} -> {new}  ({title[:60] or r['url'][:60]})")
    _print(f"\nAdjusted {changed} of {len(rows)} sites ({fixed} legacy corrections).")
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())