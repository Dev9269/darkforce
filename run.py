import argparse
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)


def main():
    ap = argparse.ArgumentParser(prog="darkforce",
                                 description="DarkForce - dark web threat actor de-anonymization platform")
    ap.add_argument("--demo", action="store_true", help="seed demo dataset before starting")
    ap.add_argument("--live", action="store_true", help="pull live seeds from clearnet APIs before starting")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--refresh", action="store_true", help="re-run graph/stylometry merge, then exit")
    args = ap.parse_args()

    from darkforce.db import DB

    db = DB()

    if args.refresh:
        from darkforce import link, stylo

        prof, pairs, per = stylo.match_all(db)
        print("stylo pairs:", len(pairs), "-> merging...")
        print(link.rebuild_actors(db, stylo_pairs=pairs))
        print("stats:", db.stats())
        return

    if args.demo:
        from demos import seed_demo

        print(seed_demo.run(db))
        print("demo stats:", db.stats())

    if args.live:
        from darkforce import seeds

        for s in ("directory", "ahmia", "darkfail", "ransomware"):
            items = seeds.collect_source(s)
            n = 0
            for it in items:
                url = it["url"]
                if not url or db.site_id(url):
                    continue
                db.upsert_site(url, title=it.get("title", "")[:200], category=it.get("category", "seed"))
                n += 1
            print(f"[live] {s}: collected {n}")

    from darkforce.api import main as run_api

    os.environ["PORT"] = str(args.port)
    print(f"\nDarkForce dashboard: http://localhost:{args.port}\n")
    run_api()


if __name__ == "__main__":
    main()