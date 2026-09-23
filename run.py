import argparse
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)


def run_pass(db, tor, max_sites=30, verbose=True):
    """One full collection pass: seed -> crawl -> stylometry merge.
    Returns a summary dict. Safe to call repeatedly (dedup skips unchanged pages)."""
    from darkforce import categories as _cats
    from darkforce import link, seeds, stylo
    from darkforce.collect import crawl_and_ingest
    from urllib.parse import urlparse
    import time

    new_urls = []
    totals = {"findings": 0, "identifiers": 0, "posts": 0,
              "handles": 0, "sites": 0, "failed": 0, "skipped": 0}

    if verbose:
        print("[live] seeding...")
    for s in ("directory", "darkfail", "onionoo", "ahmia", "ransomware",
              "tor66", "azidal", "thedarknet", "notevil",
              "telegram", "clearnet", "urlhaus", "resource", "news"):
        try:
            items = seeds.collect_source(s)
            db.log_source_health(s, ok=True)
        except Exception as e:
            db.log_source_health(s, ok=False, detail=str(e))
            print(f"[live] {s}: seed error: {e}")
            continue
        n = 0
        for it in items:
            url = it["url"]
            if not url or db.site_id(url):
                continue
            purpose = it.get("purpose") or ""
            # A collector-level category is provenance ("came from a directory"),
            # not the analyst purpose. Prefer the classified purpose when it
            # resolves to something meaningful; fall back to provenance.
            cat = purpose if _cats.normalize_category(purpose) != "other" else it.get("category", "seed")
            db.upsert_site(url, title=it.get("title", "")[:200], category=cat)
            new_urls.append(url)
            n += 1
            totals["sites"] += 1
            if len(new_urls) >= max_sites:
                break
        if verbose:
            print(f"[live] {s}: collected {n} new sites ({len(new_urls)} total so far)")
        if len(new_urls) >= max_sites:
            if verbose:
                print(f"[live] hit cap of {max_sites} new sites, stopping seed phase")
            break

    crawlable = [u for u in new_urls if tor or ".onion" not in (urlparse(u).hostname or "")]
    if verbose and len(new_urls) - len(crawlable):
        print(f"[live] Tor unavailable - skipping {len(new_urls) - len(crawlable)} .onion seed(s), "
              f"crawling {len(crawlable)} clearnet site(s)")

    if verbose:
        print(f"[live] crawling {len(crawlable)} new site(s)...")
    for i, url in enumerate(crawlable, 1):
        needs_tor = ".onion" in (urlparse(url).hostname or "") and tor
        r = crawl_and_ingest(db, url, use_tor=needs_tor)
        if r.get("skipped"):
            totals["skipped"] += 1
        if r["error"]:
            totals["failed"] += 1
        for k in ("findings", "identifiers", "posts", "handles"):
            totals[k] += r[k]
        if verbose and (r["error"] or r["skipped"] or r["findings"] or r["identifiers"] or r["posts"] or r["handles"]):
            extra = (f"  ({r['error']})" if r["error"] else "") or (f"  (skipped: {r['skipped']})" if r["skipped"] else "")
            print(f"  [{i}/{len(crawlable)}] {url} -> findings={r['findings']} "
                  f"ids={r['identifiers']} posts={r['posts']} handles={r['handles']}{extra}")
        time.sleep(1.5)

    if verbose:
        print("[live] merging handles into actors (stylometry + shared identifiers)...")
    prof, pairs, per = stylo.match_all(db)
    merged = link.rebuild_actors(db, stylo_pairs=pairs)
    totals["stylo_pairs"] = len(pairs)
    if verbose:
        print("[live] stylo pairs:", len(pairs), "->", merged)
        print(f"[live] crawl totals: {totals}")
    return totals


def main():
    ap = argparse.ArgumentParser(prog="darkforce",
                                 description="DarkForce - dark web threat actor de-anonymization platform")
    ap.add_argument("--demo", action="store_true", help="seed demo dataset before starting")
    ap.add_argument("--live", action="store_true", help="pull live seeds from clearnet APIs before starting")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--refresh", action="store_true", help="re-run graph/stylometry merge, then exit")
    ap.add_argument("--daemon", action="store_true",
                    help="run live collection passes on a schedule (requires --live or --demo)")
    ap.add_argument("--interval", type=int, default=15,
                    help="minutes between autonomous collection passes (default 15)")
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

    from darkforce.tor import external_running, start_managed

    if external_running():
        print("Tor detected on 127.0.0.1:9050 - .onion sites will be crawled via existing SOCKS5.")
        tor = True
    elif start_managed():
        print("Bundled Tor started (127.0.0.1:9052) - .onion sites will be crawled via SOCKS5.")
        tor = True
    else:
        print("WARNING: no Tor available (no listener on 9050, bundled Tor failed to bootstrap) - "
              ".onion hostnames will fail to fetch; clearnet seeds will still be ingested.")
        tor = False

    if args.live:
        run_pass(db, tor)
        from darkforce.seeds import seed_breaches
        seed_breaches(db)
        print("Breach catalog seeded.")

    if args.demo:
        from demos import seed_demo

        print(seed_demo.run(db))
        print("demo stats:", db.stats())
        from darkforce.seeds import seed_breaches
        seed_breaches(db)

    if args.daemon:
        try:
            from apscheduler.schedulers.background import BackgroundScheduler
        except ImportError:
            print("--daemon requires APScheduler: pip install apscheduler")
            sys.exit(1)
        import os as _os
        interval_env = _os.environ.get("DF_COLLECT_INTERVAL")
        if interval_env:
            try:
                minutes = max(1, int(interval_env))
            except ValueError:
                minutes = max(1, args.interval)
        else:
            minutes = max(1, args.interval)
        sched = BackgroundScheduler(daemon=True)

        def daemon_pass():
            try:
                totals = run_pass(db, tor, verbose=False)
                from datetime import datetime, timezone
                ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                db.exe("INSERT OR REPLACE INTO meta(key, value) VALUES('last_collection_pass', ?)", (ts,))
                print(f"[daemon] pass complete at {ts}: {totals}")
            except Exception as e:
                print(f"[daemon] pass error: {e}")

        sched.add_job(
            daemon_pass,
            "interval", minutes=minutes, id=f"pass-{minutes}m", max_instances=1,
            coalesce=True, misfire_grace_time=300)
        sched.start()
        print(f"[daemon] autonomous collection every {minutes} min (Tor={'yes' if tor else 'NO'})")

    from darkforce.api import main as run_api

    os.environ["PORT"] = str(args.port)
    print(f"\nDarkForce dashboard: http://localhost:{args.port}\n")
    run_api()


if __name__ == "__main__":
    main()