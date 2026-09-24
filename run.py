import argparse
import os
import sys
import threading
from urllib.parse import urlparse

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

DEFAULT_MAX_SITES = int(os.environ.get("DF_MAX_SITES", "5000"))
DEFAULT_CRAWL_CAP = int(os.environ.get("DF_CRAWL_CAP", "40"))


def run_pass(db, tor, max_sites=None, verbose=True, crawl_cap=None):
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

    max_sites = max_sites or DEFAULT_MAX_SITES

    if verbose:
        print("[live] seeding...")
    for s in ("directory", "darkfail", "onionoo", "ahmia", "ransomware",
              "tor66", "azidal", "thedarknet", "notevil",
              "telegram", "clearnet", "urlhaus", "resource", "news", "successor"):
        try:
            if s == "successor":
                items = seeds.collect_successor_probes(db)
            else:
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

    crawl_cap = crawl_cap if crawl_cap is not None else DEFAULT_CRAWL_CAP
    crawled_this_pass = []
    for u in crawlable:
        if len(crawled_this_pass) >= crawl_cap:
            if verbose:
                print(f"[live] crawl cap {crawl_cap} reached this pass; remaining deferred to next pass")
            break
        try:
            src = db.one("SELECT last_scan FROM sites WHERE url=?", (u,))
            if src and src.get("last_scan"):
                continue
        except Exception:
            pass
        crawled_this_pass.append(u)

    n_crawl = len(crawled_this_pass)
    if verbose:
        print(f"[live] crawling {n_crawl} new site(s) (cap {crawl_cap})...")
    fast = bool(os.environ.get("DF_FAST_CRAWL", "1"))
    if fast and n_crawl > 1:
        from concurrent.futures import ThreadPoolExecutor
        from darkforce.collect import crawl_and_ingest as _cai
        with ThreadPoolExecutor(max_workers=DEFAULT_CRAWL_CAP) as pool:
            futures = {pool.submit(_cai, db, url, use_tor=(tor and ".onion" in (urlparse(url).hostname or "")), timeout=20, fast=True): url for url in crawled_this_pass}
            for i, fut in enumerate(futures, 1):
                url = futures[fut]
                try:
                    r = fut.result()
                except Exception as e:
                    r = {"error": str(e)}
                if r.get("skipped"):
                    totals["skipped"] += 1
                if r["error"]:
                    totals["failed"] += 1
                for k in ("findings", "identifiers", "posts", "handles"):
                    totals[k] += r[k]
                if verbose and (r["error"] or r["skipped"] or r["findings"] or r["identifiers"] or r["posts"] or r["handles"]):
                    extra = (f"  ({r['error']})" if r["error"] else "") or (f"  (skipped: {r['skipped']})" if r["skipped"] else "")
                    print(f"  [{i}/{n_crawl}] {url} -> findings={r['findings']} "
                          f"ids={r['identifiers']} posts={r['posts']} handles={r['handles']}{extra}")
        time.sleep(2)
    else:
        for i, url in enumerate(crawled_this_pass, 1):
            needs_tor = ".onion" in (urlparse(url).hostname or "") and tor
            r = crawl_and_ingest(db, url, use_tor=needs_tor, fast=fast)
            if r.get("skipped"):
                totals["skipped"] += 1
            if r["error"]:
                totals["failed"] += 1
            for k in ("findings", "identifiers", "posts", "handles"):
                totals[k] += r[k]
            if verbose and (r["error"] or r["skipped"] or r["findings"] or r["identifiers"] or r["posts"] or r["handles"]):
                extra = (f"  ({r['error']})" if r["error"] else "") or (f"  (skipped: {r['skipped']})" if r["skipped"] else "")
                print(f"  [{i}/{n_crawl}] {url} -> findings={r['findings']} "
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


def crawl_one(db, url, tor=True, verbose=True):
    """Debug hook: fetch + ingest a single site, print the summary, return it."""
    from darkforce.collect import crawl_and_ingest

    url = url.lower().strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    need_tor = tor and ".onion" in (urlparse(url).hostname or "")
    r = crawl_and_ingest(db, url, use_tor=need_tor, fast=False, timeout=25)
    if verbose:
        print(f"[crawl-one] {url} -> {r}")
    return r


def make_parser():
    ap = argparse.ArgumentParser(prog="darkforce",
                                 description="DarkForce - dark web threat actor de-anonymization platform")
    ap.add_argument("--demo", action="store_true", help="seed demo dataset before starting")
    ap.add_argument("--live", action="store_true", help="pull live seeds from clearnet APIs before starting")
    ap.add_argument("--wipe", action="store_true",
                    help="delete all collected data (sites/actors/posts/findings/alerts) before starting")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--refresh", action="store_true", help="re-run graph/stylometry merge, then exit")
    ap.add_argument("--daemon", action="store_true",
                    help="run live collection passes on a schedule (requires --live or --demo)")
    ap.add_argument("--interval", type=int, default=15,
                    help="minutes between autonomous collection passes (default 15)")
    ap.add_argument("--crawl-one", metavar="URL",
                    help="fetch + ingest a single site, print the summary, then exit (debug)")
    ap.add_argument("--import-index", action="store_true",
                    help="fetch Ahmia index + local harvest catalogs and register as listed (then exit)")
    return ap


def main():
    args = make_parser().parse_args()

    from darkforce.db import DB

    db = DB()

    if args.import_index:
        from darkforce.config import DATA_DIR
        from darkforce.index_loader import import_indexes, load_ahmia_index, load_local_catalogs
        items = load_ahmia_index() + load_local_catalogs(DATA_DIR)
        db.upsert_source("index_loader", "index", "https://ahmia.fi/onions/")
        src = db.one("SELECT id FROM sources WHERE name='index_loader'")["id"]
        print("[index]", import_indexes(db, items, source_id=src))
        print("stats:", db.stats())
        return

    if args.crawl_one:
        from darkforce.tor import external_running, start_managed

        if external_running():
            print("Tor detected on 127.0.0.1:9050 - .onion sites will be crawled via existing SOCKS5.")
            tor = True
        elif start_managed():
            print("Bundled Tor started (127.0.0.1:9052) - .onion sites will be crawled via SOCKS5.")
            tor = True
        else:
            tor = False
            print("WARNING: no Tor available - .onion hostnames will fail to fetch.")
        crawl_one(db, args.crawl_one, tor=tor)
        print("stats:", db.stats())
        return

    if args.wipe:
        print("[wipe] clearing collected data tables...")
        for t in ("links", "findings", "identifiers", "posts", "handles",
                  "actors", "sites", "alerts", "observations", "link_evidence",
                  "collector_health", "sources", "clearnet_fingerprints"):
            try:
                db.exe(f"DELETE FROM {t}")
            except Exception as e:
                print(f"[wipe] {t}: {e}")
        db.exe("DELETE FROM meta WHERE key IN ('last_collection_pass')")
        print("[wipe] data cleared")

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

    if args.demo:
        from demos import seed_demo

        print(seed_demo.run(db))
        print("demo stats:", db.stats())

    if args.live or args.daemon:
        from darkforce.seeds import seed_breaches

        seed_breaches(db)

    _collector_stop = threading.Event()

    def _run_live_pass(tor_available):
        """Blocking collection pass; called from background thread so the API
        stays up while we crawl. Always restores portability via seed_breaches."""
        from darkforce.seeds import seed_breaches
        try:
            try:
                from darkforce.index_loader import import_indexes, load_ahmia_index
                db.upsert_source("index_loader", "index", "https://ahmia.fi/onions/")
                src = db.one("SELECT id FROM sources WHERE name='index_loader'")["id"]
                import_indexes(db, load_ahmia_index(), source_id=src)
            except Exception as e:
                print(f"[collector] index refresh failed: {e}")
            totals = run_pass(db, tor_available, verbose=False)
            seed_breaches(db)
            from datetime import datetime, timezone
            ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            db.exe("INSERT OR REPLACE INTO meta(key, value) VALUES('last_collection_pass', ?)", (ts,))
            return totals
        except Exception as e:
            print(f"[collector] pass error: {e}")
            return {}

    def _latest_actor_count():
        return db.one("SELECT COUNT(*) c FROM actors")["c"]

    def _initial_pass(tor_available):
        before = _latest_actor_count()
        print("[collector] first live pass starting (this populates real .onion sites)...")
        totals = _run_live_pass(tor_available)
        print(f"[collector] first live pass complete: {totals}")
        if _latest_actor_count() > before:
            print(f"[collector] actors now {before} -> {_latest_actor_count()}")

    if args.live or args.daemon:
        t = threading.Thread(target=_initial_pass, args=(tor,), name="collector-initial", daemon=True)
        t.start()

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
                totals = _run_live_pass(tor)
                print(f"[daemon] pass complete at {datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}: {totals}")
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