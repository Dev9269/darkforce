# DarkForce Live-Intel Coverage — NTRO Fulfillment

Date: 2026-09-24
Status: Approved
Author: AI-assisted dev (Jainam H. Maru, dev9269)

## 1. Context & Problem

The NTRO problem statement asks for an end-to-end dark web threat actor
de-anonymization system with three core capabilities:

1. **C1 — Misconfiguration detection in Tor hidden services** (exposed
   server-status pages, SSL certs tied to clearnet domains, default banners,
   descriptor inconsistencies) matched against clearnet infrastructure to
   point at likely origin servers.
2. **C2 — Cross-marketplace actor graph** (handles, PGP keys, wallets, trust
   links across multiple markets).
3. **C3 — AI stylometric / behavioural persona linkage** (rebranded or
   migrated personas linked to known actors).

Expected solution: end-to-end collection, storage, contextualization and
querying (GUI/dashboards); actor profiles, identifiers, hidden-service
infrastructure indicators, persona linkages, attribution confidence,
category, last-scan date, source; CSV/JSON/report export; autonomous mode.

### Reality check on "ALL existing onion sites"

Research (USENIX FOCI 2025 + Tor ecosystem data) shows:
- ~480k unique v3 onion addresses have *ever* been published.
- Only ~15–40k are reachable web services on any given day.
- 50%+ die within days; a quarter+ are non-HTTP (Bitcoin/SSH/IM).
- Onion services are not enumerable by design (blinded descriptors); roughly
  half are never observable from any public vantage point.

**"ALL existing" is physically unattainable.** The attainable target is the
**entire published/listable universe**: Ahmia full index (~10.8k, verified
reachable at `https://ahmia.fi/onions/`), tor66 fresh, dark.fail, thedarknet,
azidal, onionoo-derived relay adjacency (not addresses), plus historical
harvest catalogs on disk and optional GitHub/Bitnodes address dumps. Target:
~30–60k unique registered addresses within a week.

### Critical bug: live pipeline produces zero actors

The live collector registered 43 sites but produced **0 actors, 0 handles,
0 posts** — every working actor in the system came from demo fixtures.
This is the primary reason the system felt "limited": live collection
registers sites but extracts almost nothing from real onion content.

## 2. Goal

1. Register every publicly-listed onion address (target ~30–60k unique).
2. Fix the live-pipeline actor-extraction bug so real crawls yield actors,
   posts, identifiers (handles, PGP, wallets, jabber/telegram/ICQ).
3. Close NTRO gaps: descriptor-inconsistency checks, successor probes,
   wallets on live data, stylometry hardening.
4. Run continuously & autonomously (daemon + rolling liveness sweep).

## 3. Work Order: Phase 2 → 1 → 3 → 4

### Phase 2 — Rebuild live actor extraction (FIRST)

Files: `darkforce/collect.py`, `darkforce/extract.py`, `darkforce/run.py` (+ new `--crawl-one` debug hook).

- Replace selector-only handle detection (`_page_handles` relying on
  `AUTHOR_SELECTORS`) with site-agnostic regex fallbacks over full page text:
  PGP keys, BTC/XMR addresses, `Name_vendor` patterns, `@jabber`,
  Telegram/ICQ handles, `mailto:` addresses.
- Save a post whenever ≥1 handle is found (not only via author selectors).
- Cap distinct handles per page at 8.
- Add `run.py --crawl-one <url>` CLI hook: crawl a single live onion and dump
  the extraction breakdown per step (snap → scan → handles → identifiers →
  post) for debugging.
- **Acceptance:** crawling one known-live onion yields ≥1 actor, ≥1 post,
  ≥1 identifier (handle/PGP/wallet/jabber).

### Phase 1 — Mass onion ingestion (SECOND)

Files: new `darkforce/index_loader.py`, `darkforce/db.py`, `darkforce/run.py`.

- `load_ahmia_index()`: fetch `https://ahmia.fi/onions/`, parse onion URLs
  (verified: 200 OK, ~10.8k onion links).
- `load_historical_catalogs()`: ingest `data/onion_sites.jsonl`,
  `data/harvest_results.jsonl`, `data/ahmia_onions.txt`; optional GitHub /
  Bitnodes address dumps via `DF_INDEX_URLS` env list.
- Dedup by onion base32 hostname `[a-z2-7]{16,56}.onion`.
- Register every URL via `db.upsert_site(..., status="listed")` — do NOT bulk
  crawl in one go; liveness comes from the rolling sweep.
- Wire into the daemon pass so each cycle refreshes the index.

### Phase 3 — Close NTRO gaps (THIRD)

Files: `darkforce/descriptors.py`, `darkforce/seeds.py`, `darkforce/collect.py`,
`darkforce/stylo.py`, `darkforce/api.py`.

- Wire `descriptors.check_onion_descriptor()` descriptor-inconsistency checks
  into the crawl loop (C1) — currently dead code.
- Implement `seeds.successor_probes()` — watchlist-backed scan for markets
  announcing as successors of defunct ones (C2/C1).
- Add wallet extraction (BTC/XMR) to `crawl_and_ingest` so `/api/wallets`
  clustering runs on real data (C2).
- Harden stylometry (C3): add posting-time-distribution + vocabulary
  similarity alongside n-gram cosine; cross-lingual guard.

### Phase 4 — Autonomous operations (FOURTH)

Files: `darkforce/db.py`, `darkforce/run.py`.

- Rolling liveness sweep (`DF_SWEEP_DAYS=7`) — sites whose `last_scan` is
  stale get re-checked in batches; mark `down` on unreachable.
- Daemon refreshes the Ahmia index + fresh feeds each pass.
- Detached run: `run.py --live --daemon --interval 6`.

## 4. Data Model Notes

- `sites.status` currently "listed"/"up"/"down"/"blocked_*" — reuse for
  registry + liveness.
- `sites.source_id` — set via a new `sources` row `name='ahmia_index'`,
  `name='harvest_catalog'` per catalog so provenance is visible in UG.
- `identifiers.kind` gains `jabber` alias handling in fallback extraction
  (already supported in schema value space).

## 5. Acceptance Criteria

- [ ] `--crawl-one` on a live onion yields actor + post + identifier.
- [ ] Full Ahmia index + historical catalogs imported; total sites ≥ 30k.
- [ ] Descriptor checks appear as `/api/misconfigs` findings on real crawls.
- [ ] `successor_probes()` returns structured candidates (non-empty).
- [ ] Wallets table grows from live crawls; `/api/wallets` cluster resolves.
- [ ] Rolling sweep re-checks stale `last_scan`; dead sites marked `down`.
- [ ] `pytest -q` green; `npm run build` green.
- [ ] Server runs detached: `--live --daemon --interval 6`.

## 6. Out of Scope

- Claiming literally "all" onion services (unattainable; §1).
- Crawling the deep/dark web beyond Tor-accessible `.onion` + clearnet feeds
  already in `seeds.py`.
- UI redesign; only minimal frontend additions (per-site source/status) allowed.
- I2P / Freenet support.