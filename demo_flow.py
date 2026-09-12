"""One-command demo proof: seeds demo data, runs the collection pipeline,
recomputes stylometry+graphs, exports CSV/JSON/PDF, and reports live numbers.

Usage:
    python run.py --demo --daemon --interval 10   (normal app entry)
    python demo_flow.py                           (this: full pipeline + exports + PDF)
"""
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from demos import seed_demo
from darkforce import link, stylo
from darkforce.collect import crawl_and_ingest
from darkforce.db import DB

backend = "postgres" if os.getenv("DATABASE_URL") else "sqlite"
print(f"[demo] backend: {backend}")
db = DB()
seed_demo.run(db)  # no-op for already-seeded tables via pre-existing keys

for url in ("http://dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/",
            "http://darkfailenbsdla5mal2mxn2uz66od5vtzd5qozslagrfzachha3f3id.onion/"):
    try:
        r = crawl_and_ingest(db, url, use_tor=False, timeout=8)
        print(f"[demo] ingested {url} -> {r.get('status', '?')}")
    except Exception as e:
        print(f"[demo] skip {url}: {e}")

prof, pairs, per = stylo.match_all(db)
merge = link.rebuild_actors(db, stylo_pairs=pairs)
print(f"[demo] merge result: {merge}")

out = [dict(r) for r in db.q("SELECT * FROM actors")]
out += [dict(r) for r in db.q("SELECT * FROM identifiers")]
out += [dict(r) for r in db.q("SELECT i.kind, i.value, s.url site_url, f.kind finding_kind, "
                              "f.severity, f.detail FROM findings f JOIN sites s ON s.id=f.site_id "
                              "LEFT JOIN identifiers i ON 1=0")]
from darkforce.export import report_pdf, to_csv, to_json

open("data/demo_export.csv", "w", encoding="utf-8").write(to_csv(out[:60]))
open("data/demo_export.json", "w", encoding="utf-8").write(to_json(out[:60]))
open("data/demo_report.pdf", "wb").write(report_pdf({
    "title": "Dark Force - demo threat-actor report",
    "subtitle": "Live evidence from the autonomous collection pipeline",
    "classification": "UNCLASSIFIED // DEMO",
    "backend": backend,
    "coverage": f"{db.stats()['actors']} actors, {db.stats()['sites']} sites, "
                f"{db.stats()['identifiers']} identifiers, {db.stats()['findings']} findings",
}, records=out[:40]))
print(f"[demo] wrote data/demo_export.csv, data/demo_export.json, data/demo_report.pdf")

s = db.stats()
print(f"[demo] FINAL: {s['actors']} actors | {s['sites']} sites | "
      f"{s['identifiers']} ids | {s['posts']} posts | {s['findings']} findings | backend={backend}")
print("[demo] DONE")