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
python run.py --demo           # seed demo dataset + start dashboard at http://localhost:8000
python run.py --live           # pull live onion seeds from clearnet APIs (+ --demo to combine)
python -m darkforce.setup_pg   # provision a project-local PostgreSQL cluster (port 5433)
$env:DATABASE_URL="postgresql://darkforce@127.0.0.1:5433/darkforce"
python run.py --demo --daemon --interval 10   # autonomous collection loop every 10 min
# dashboard: http://localhost:8000  ·  interactive graph: http://localhost:8000/graph?min_conf=0.6
```

## Production patterns (implemented)
- **Database is pluggable** — `DATABASE_URL` unset uses zero-config SQLite (WAL mode); set it to `postgresql://…` to switch the whole app to PostgreSQL. `python -m darkforce.setup_pg` boots a private cluster you own (no admin/password). One-time migration of an existing SQLite store: `python -m darkforce.db.migrate` (via `from darkforce.db import migrate`).
- **Autonomous operation** — `--daemon` runs full collection passes on a schedule (APScheduler). Each pass: seed clearnet APIs → Tor/clearnet crawl → misconfig scan → stylometry → entity merge → graph rebuild. Content-hash dedup skips unchanged pages; circuit rotation (Stem NEWNYM) + per-host rate limiting + exponential backoff + CAPTCHA/block detection keep the crawler polite; optional guarded OnionScan for deep .onion fingerprinting when the binary is present.
- **Real-time signals** — watchlists + alerts API (`/api/watchlist`, `/api/alerts`), live Server-Sent-Events stream at `/api/alerts/stream`, and per-source collector health at `/api/health/collectors` for observability.
- **Interactive entity graph** — `/graph` renders a physics-driven vis.js/pyvis view: node color = entity type, edge thickness = confidence, `?min_conf=` declutters.

## Layout
```
darkforce/        core engine (db sqlite+pg drivers, extract, detect, link, stylo, seeds, net, api, export, setup_pg)
darkforce/web/    React dashboard (search, graph, timeline, infra findings)
demos/            seed_demo.py (synthetic lab: markets, rebranded vendors, planted leaks)
tests/            pytest smoke suite (extraction, findings, stylo, dual-backend DB, exports, watchlists)
data/             SQLite/PG store + raw snapshots
```

## OPSEC & legal posture
Read-only collection of publicly served pages only. No login, no purchases, no interaction with markets, no network attacks; PII-minimized, per-record source tracking; abuse-category filtering recommended before live onion crawling. Automated human-CAPTCHA solving is intentionally out of scope for the read-only posture — gated/proof-of-work surfaces are routed to index-cache refresh or analyst-assisted intake instead of being bypassed.

## Confidence rubric (attribution)
| Confidence | Basis |
|---|---|
| 0.9+ | Reused PGP key or same BTC/XMR wallet across personas, or identical favicon/content hash to a known clearnet host |
| 0.7–0.9 | Shared unique identifiers (jabber/email/ICQ) or stylometric cosine above threshold with shared tokens |
| 0.5–0.7 | Stylometric similarity or shared non-unique handles / server banners |
| <0.5 | Weak (single generic handle, common banner) — not presented as attribution |

## Live sources used
- Ahmia search API (onion discovery, clearnet)
- dark.fail verified onion directory + status page
- ransomware.live API (group/victim leak-site tracking)
- OnionScan-compatible checks wrapped by the scan endpoint; optional Tor via `socks5://127.0.0.1:9050`
- Bulk/historical training data: Dread forum archive (Hugging Face `trentmkelly/dread-crime-forum`), Gwern DNM archives