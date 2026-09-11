# DarkForce — Dark Web Threat Actor De-anonymization

Autonomous OSINT platform for the SIH (NTRO) problem statement #26151: collect footprints of dark web threat actors, detect hidden-service misconfigurations to locate origin infrastructure, link personas across marketplaces into a relationship graph, and attribute rebranded identities via stylometry — behind an analytical dashboard.

## Core capabilities
1. **Hidden-service misconfiguration detection** — server banners, exposed `server-status`/`phpinfo`, `.git`/`.env`, TLS/SSH fingerprints, favicon & content-hash correlation to clearnet hosts (Capability 1).
2. **Entity resolution graph** — merge handles that share PGP keys, BTC/XMR wallets, emails/jabber, onions, reused content; weighted confidence edges (Capability 2).
3. **AI stylometry** — character n-gram authorship profiles + cosine similarity with feature-level explainability to catch rebranded personas (Capability 3).
4. Dashboard (search, graph, timeline, infra findings, exports CSV/JSON/PDF), autonomous seed collection via clearnet APIs (Ahmia, dark.fail, ransomware.live) and Tor-ready crawling.

## Quick start
```bash
pip install -r requirements.txt
python run.py --demo        # seed demo dataset + start dashboard at http://localhost:8000
python run.py --live        # pull live onion seeds from clearnet APIs (+ --demo to combine)
python run.py --refresh     # re-run stylometry + entity merge and exit
```

## Layout
```
darkforce/        core engine (db, extract, detect, link, stylo, seeds, net, api, export)
darkforce/web/    single-file dashboard
demos/            seed_demo.py (synthetic lab: markets, rebranded vendors, planted leaks)
data/             SQLite store + raw snapshots
```

## OPSEC & legal posture
Read-only collection of publicly served pages only. No login, no purchases, no interaction with markets, no network attacks; PII-minimized, per-record source tracking; abuse-category filtering recommended before live onion crawling.

## Live sources used
- Ahmia search API (onion discovery, clearnet)
- dark.fail verified onion directory + status page
- ransomware.live API (group/victim leak-site tracking)
- OnionScan-compatible checks wrapped by the scan endpoint; optional Tor via `socks5://127.0.0.1:9050`
- Bulk/historical training data: Dread forum archive (Hugging Face `trentmkelly/dread-crime-forum`), Gwern DNM archives