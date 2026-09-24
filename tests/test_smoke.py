"""DarkForce smoke tests. Run: python -m pytest tests -q

Covers the critical paths judges will exercise without needing the network:
  - identifier extraction regexes
  - fingerprint / config finding detection
  - stylometry profile + cosine bounds
  - SQLite + PostgreSQL round-trip + stats/graph/search
  - export formats (csv / json / pdf)
  - content-hash dedup marker in collect
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from darkforce import detect, extract, stylo
from darkforce.categories import normalize_category
from darkforce.config import DATABASE_URL
from darkforce.db import DB, PostgresDB, SQLiteDB
from darkforce.export import export


# ---------- fixtures ----------
def _db_path():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return path


@pytest.fixture
def sqlite_db():
    db = SQLiteDB(_db_path())
    yield db


@pytest.fixture
def backend_db():
    """Uses whichever backend is active (sqlite default, or postgres via DATABASE_URL)."""
    db = DB(_db_path())
    yield db
    try:
        db.conn.close()
    except Exception:
        pass


def _seed(db):
    db.upsert_source("test", "onion", "http://test.onion")
    sid = db.upsert_site("http://test.onion", title="Test market", category="onion")
    aid = db.upsert_actor("alice", category="onion")
    db.upsert_handle(aid, "alice", sid, "http://test.onion")
    db.upsert_handle(aid, "shopper", sid)
    for i in range(3):
        db.save_post("alice", sid, "http://test.onion/posts/{}".format(i),
                     "Post about carding markets {}".format(i),
                     "discussing dumps and fullz vendors" * 20, "2026-01-0{}T00:00:00".format(i + 1))
    db.add_identifier(aid, "alice", "btc", "bc1q" + "0" * 38, "wallet")
    db.add_identifier(aid, "alice", "email", "alice@protonmail.com", "")
    db.add_finding(sid, "server_banner", "medium", "Apache header", 0.6)
    db.add_link("handle", "alice", "btc", "bc1q" + "0" * 38, "controls", 0.9, "shared post")
    return sid, aid


# ---------- extraction ----------
def test_extract_btc():
    hits = extract.extract_identifiers(
        "wallet bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh thx")
    assert any(h["kind"] == "btc" and "bc1q" in h["value"] for h in hits)


def test_extract_email():
    assert any(h["kind"] == "email" and "protonmail" in h["value"]
               for h in extract.extract_identifiers("contact alice@protonmail.com now"))


def test_extract_pgp():
    assert any(h["kind"] == "pgp" for h in extract.extract_identifiers(
        "-----BEGIN PGP PUBLIC KEY BLOCK-----" + "\n" + "mQINBF" + "x" * 500
        + "-----END PGP PUBLIC KEY BLOCK-----"))


def test_extract_onion():
    assert any(h["kind"] == "onion"
               for h in extract.extract_identifiers("juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"))


def test_extract_handles():
    assert any(h["kind"] in ("telegram", "handle", "username")
               for h in extract.extract_identifiers("telegram @market_vendor123 join"))


# ---------- fingerprint / findings ----------
def test_fingerprint_content_hash_stable():
    snap = detect.Snap(url="http://a.onion", html="<html>hello world</html>", meta={"hostname": "a.onion"})
    assert snap.meta["hostname"] == "a.onion"
    f1 = detect.fingerprint(snap)
    f2 = detect.fingerprint(snap)
    assert f1["content_hash"] == f2["content_hash"]


def test_fingerprint_via_leak():
    snap = detect.Snap(url="http://a.onion", headers={"Via": "1.1 varnish"}, html="x")
    findings, fp = detect.scan(snap)
    assert any(k == "proxy_leak" for k, *_ in findings)


def test_scan_reports(clearnet_index=None):
    snap = detect.Snap(url="http://a.onion", html="<title>Index of /</title> 10.1.2.3", headers={})
    findings, fp = detect.scan(snap, clearnet_index)
    kinds = {k for k, *_ in findings}
    assert "dir_listing" in kinds


# ---------- stylometry ----------
def test_stylo_cosine_in_range():
    a = stylo.profile(["this is the quick brown fox" * 5])
    b = stylo.profile(["this is the quick brown fox" * 5])
    c = stylo.profile(["completely different vocabulary zeta kappa omega" * 5])
    assert 0 <= stylo.cosine(a, b) <= 1
    assert stylo.cosine(a, b) > stylo.cosine(a, c)


# ---------- db round-trip ----------
def test_sqlite_roundtrip(sqlite_db):
    sid, aid = _seed(sqlite_db)
    s = sqlite_db.stats()
    assert s["actors"] == 1 and s["handles"] == 2 and s["sites"] == 1
    assert s["posts"] == 3 and s["identifiers"] == 2 and s["findings"] == 1
    assert len(sqlite_db.search("alice")["actors"]) == 1
    assert sqlite_db.graph()["nodes"]
    assert sqlite_db.timeline()


def test_dedup_marker():
    from darkforce import net
    db = SQLiteDB(_db_path())
    db.upsert_site("http://stale.onion", content_hash="abc")
    assert db.site_content_hash("http://stale.onion") == "abc"
    db.mark_site_scanned("http://stale.onion", content_hash="abc")
    assert db.site_last_scan("http://stale.onion") is not None


def test_upsert_site_default_last_scan_null(sqlite_db):
    sqlite_db.upsert_site("http://a.onion", title="A", category="onion")
    row = sqlite_db.one("SELECT last_scan, first_seen FROM sites WHERE url='http://a.onion'")
    assert row["first_seen"] is not None
    assert row["last_scan"] is None  # not yet crawled
    sqlite_db.upsert_site("http://a.onion", title="A", category="onion", last_scan="2026-01-01T00:00:00Z")
    row2 = sqlite_db.one("SELECT last_scan FROM sites WHERE url='http://a.onion'")
    assert row2["last_scan"] == "2026-01-01T00:00:00Z"


def test_run_pass_crawls_newly_seeded(monkeypatch):
    """Regression: seeded sites must be crawl-eligible, not skipped as pre-scanned."""
    from darkforce import collect

    db = SQLiteDB(_db_path())
    seen = []

    def fake_cai(_db, url, use_tor=False, timeout=20, fast=False):
        seen.append(url)
        return {"url": url, "error": None, "skipped": None, "findings": 0,
                "identifiers": 0, "posts": 0, "handles": 0}

    monkeypatch.setattr(collect, "crawl_and_ingest", fake_cai)

    import darkforce.seeds as seeds
    def fake_collect(name):
        return [{"title": "x", "url": "http://fresh.onion", "category": "onion"}]
    monkeypatch.setattr(seeds, "collect_source", fake_collect)

    import run as rn
    totals = rn.run_pass(db, tor=True, max_sites=5, crawl_cap=5)
    assert "http://fresh.onion" in seen
    assert totals["sites"] >= 1


def test_extract_page_handles_selector_free():
    from darkforce import extract
    text = (
        "DM us: @HellasVendor and @AlphaBay\n"
        "keybase.io/kingpin\n"
        "ICQ 555123456\n"
        "mail => dexter@riseup.net\n"
    )
    handles = extract.extract_page_handles(text)
    by_kind = {h["kind"]: h["value"] for h in handles}
    tg = sorted({h["value"] for h in handles if h["kind"] == "telegram"})
    assert tg == ["AlphaBay", "HellasVendor"]
    assert by_kind["icq"] == "555123456"
    assert by_kind["keybase"] == "kingpin"


def test_collect_fallback_recovers_handle(sqlite_db, monkeypatch):
    """When page selectors find no author, raw-text handle extraction must recover one."""
    from darkforce import detect, extract, net

    snap = detect.Snap(url="http://hello.onion",
                       headers={},
                       html="<html><body><p>Contact us: @HelloVendor on Telegram.</p></body></html>",
                       favicon=b"",
                       meta={})
    monkeypatch.setattr(net, "fetch_snap", lambda *a, **k: snap)
    monkeypatch.setattr(extract, "extract_identifiers", lambda *a, **k: [])

    from darkforce import collect
    res = collect.crawl_and_ingest(sqlite_db, "http://hello.onion")
    assert res["error"] is None
    rows = sqlite_db.q("SELECT h.handle FROM handles h "
                       "JOIN sites s ON h.site_id=s.id WHERE s.url='http://hello.onion'")
    assert any(r["handle"] == "HelloVendor" for r in rows)


def test_crawl_one_debug_hook(sqlite_db, monkeypatch):
    """--crawl-one must normalize the URL, route to crawl_and_ingest, and return a summary."""
    import run as rn
    from darkforce import detect, extract, net

    snap = detect.Snap(url="http://crawlone.onion", headers={},
                       html="<html><body>one site</body></html>", favicon=b"", meta={})
    monkeypatch.setattr(net, "fetch_snap", lambda *a, **k: snap)
    monkeypatch.setattr(extract, "extract_identifiers", lambda *a, **k: [])

    r = rn.crawl_one(sqlite_db, "crawlone.onion", tor=False)
    assert r["error"] is None
    assert sqlite_db.site_id("http://crawlone.onion")


def test_descriptor_check_wired_into_crawl(sqlite_db, monkeypatch):
    """Crawl must route Onionoo descriptor anomalies into findings for .onion sites."""
    from darkforce import detect, extract, net
    from darkforce import descriptors as desc_mod
    from darkforce.descriptors import DESCRIPTOR_ANOMALY

    snap = detect.Snap(url="http://anon.onion", headers={},
                       html="<html><body>x</body></html>", favicon=b"", meta={})
    monkeypatch.setattr(net, "fetch_snap", lambda *a, **k: snap)
    monkeypatch.setattr(extract, "extract_identifiers", lambda *a, **k: [])
    monkeypatch.setattr(detect, "onionscan", lambda *a, **k: [])

    captured = {}

    def fake_descriptor(address, observed=None, timeout=15):
        captured["address"] = address
        captured["observed"] = observed
        return [(DESCRIPTOR_ANOMALY, "high", f"{address}: port mismatch", 0.7)]

    monkeypatch.setattr(desc_mod, "check_onion_descriptor", fake_descriptor)

    from darkforce import collect as collect_mod
    res = collect_mod.crawl_and_ingest(sqlite_db, "http://anon.onion")
    assert res["error"] is None
    assert captured.get("address") == "anon.onion"
    assert res["findings"] >= 1
    kinds = {r["kind"] for r in sqlite_db.q("SELECT kind FROM findings")}
    assert DESCRIPTOR_ANOMALY in kinds


def test_successor_probes_returns_candidates(sqlite_db):
    from darkforce import seeds
    sqlite_db.add_watchlist("SR successor", "silk road", "market")
    sqlite_db.upsert_site("http://sr3.onion", title="Silk Road 3 - we are back", category="markets")
    sqlite_db.upsert_site("http://other.onion", title="Random blog", category="news")
    cands = seeds.collect_successor_probes(sqlite_db)
    urls = [c["url"] for c in cands]
    assert "http://sr3.onion" in urls


def test_crawl_upserts_wallets(sqlite_db, monkeypatch):
    import darkforce.collect as collect
    from darkforce import detect, extract, net

    class FakeSnap:
        url = "http://w.onion"
        html = ("<html><title>W</title>Vendor: cashman "
                "wallet bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh "
                "xmr 88833y3h0FxBtxvQgQ9Wk1S3EhwJf3t3GYKRJwhW1dHbN3VtJ8BkyFHX1PzC6aL8YoFmbAHW5bTk7XgRkW8xgjM6Wf5P4kQ")
        status = 200
        headers = {}
        favicon = None
        meta = {"hostname": "w.onion", "wall": None}

    monkeypatch.setattr(net, "fetch_snap", lambda *a, **k: FakeSnap())
    monkeypatch.setattr(detect, "onionscan", lambda url: [])
    monkeypatch.setattr(extract, "content_hash", lambda *a, **k: "h2")

    r = collect.crawl_and_ingest(sqlite_db, "http://w.onion")
    assert r["error"] is None
    assert r["identifiers"] >= 1
    rows, total = sqlite_db.list_wallets(q="bc1q")
    assert total >= 1
    assert any(w["kind"] == "btc" for w in rows)


def test_stylo_hour_and_vocab_features_separate_handles(sqlite_db):
    from darkforce import stylo
    sid = sqlite_db.upsert_site("http://m.onion", title="M", category="onion")
    for h, txt in (("night_owl", "buying guns paying in bitcoin only vouch"),
                   ("night_owl", "bitcoin only buying guns vouch paying"),
                   ("morning_duck", "recipes cooking soup pasta rice bread")):
        for i, body in enumerate([txt, txt]):
            sqlite_db.save_post(h, sid, f"http://m.onion/p{i}", "t", body,
                                f"2026-01-0{1 + i}T0{i + 1 if i < 9 else 8}:00:00")
    prof, pairs, per = stylo.match_all(sqlite_db, min_posts=2)
    assert not any("night_owl" in m["handle"] for m in per.get("morning_duck", []))
    assert not any("morning_duck" in m["handle"] for m in per.get("night_owl", []))
    assert not any(("night_owl" in p and "morning_duck" in p)
                   for pair in pairs for p in [pair[0], pair[1]])


def test_stylo_profile_hour_feature_exists():
    from darkforce import stylo
    d = stylo.profile(["buying guns bitcoins vouch"], hours=["2026-01-01T03:00:00",
                                                              "2026-01-02T03:00:00"])
    assert any(k.startswith("h") and v > 0 for k, v in d.items())


def test_run_make_parser_accepts_import_index():
    import run as rn
    ap = rn.make_parser()
    ns = ap.parse_args(["--import-index"])
    assert ns.import_index is True
    assert ns.crawl_one is None


# ---------- export formats ----------
def test_export_csv():
    data, ct, fn = export([{"handle": "alice", "btc": "abc"}], "csv")
    assert b"handle" in data and b"alice" in data


def test_export_json():
    data, ct, fn = export([{"handle": "alice", "btc": "abc"}], "json")
    assert b"alice" in data


def test_export_pdf():
    data, ct, fn = export([{"handle": "alice"}], "pdf")
    assert data.startswith(b"%PDF")


# ---------- watchlists / alerts / health ----------
def test_finding_alerts_fire_and_dedupe(sqlite_db):
    sid = sqlite_db.upsert_site("http://leak.onion", title="Leak index", category="leaked_data")
    url = "http://leak.onion/collection"
    base = sqlite_db.latest_alert_id()
    sqlite_db.add_finding(sid, "ransomware", "critical", "Ransomware leak site", 0.95, url)
    sqlite_db.add_finding(sid, "server_banner", "low", "X-Powered-By", 0.3, url)
    sqlite_db.add_finding(sid, "banner_match", "high", "Matched fingerprint", 0.9, url)
    new = [a for a in sqlite_db.alerts() if a["id"] > base]
    kinds = sorted(a["kind"] for a in new)
    assert kinds == ["finding:banner_match", "finding:ransomware"], kinds
    sqlite_db.add_finding(sid, "ransomware", "critical", "Ransomware leak site", 0.95, url)
    new2 = [a for a in sqlite_db.alerts() if a["id"] > base]
    assert len(new2) == 2, "same finding re-added within 24h must not create a second alert"


def test_watchlist_alerts_and_sqlite(sqlite_db):
    sqlite_db.add_watchlist("Creds", "password", "all")
    sqlite_db.add_watchlist("Disabled", "zzz", "all")
    sqlite_db.exe("UPDATE watchlists SET enabled=0 WHERE name='Disabled'")
    hits = sqlite_db.evaluate_watchlists("leaked password=admin123", url="http://x.onion")
    assert "Creds" in hits and "Disabled" not in hits
    al = sqlite_db.alerts()
    assert al and al[0]["title"] == "Creds"
    assert sqlite_db.latest_alert_id() == al[0]["id"]
    assert sqlite_db.alerts_since(al[0]["id"] - 1)


def test_health_tracking(sqlite_db):
    sqlite_db.log_source_health("ahmia", ok=True)
    sqlite_db.log_source_health("ahmia", ok=True)
    sqlite_db.log_source_health("darkfail", ok=False, detail="conn reset")
    h = {r["source"]: r for r in sqlite_db.collector_health()}
    assert h["ahmia"]["success_count"] == 2
    assert h["darkfail"]["error_count"] == 1
    assert "ahmia" in sqlite_db.healthy_sources() and "darkfail" not in sqlite_db.healthy_sources()


# ---------- evidence provenance ledger ----------
def test_provenance_chain_identifier(sqlite_db):
    sid = sqlite_db.upsert_site("http://ev.onion", title="Evidence", category="onion")
    ch = sqlite_db.add_observation("extract:btc", "btc", "bc1q" + "0" * 38,
                                   url="http://ev.onion", site_id=sid)
    assert ch and len(ch) == 64
    obs = sqlite_db.observation_by_hash(ch)
    assert obs["raw"] == "bc1q" + "0" * 38
    sid2 = sqlite_db.upsert_site("http://ev2.onion", title="Evidence2", category="onion")
    sqlite_db.add_identifier(None, "bob", "btc", "bc1q" + "0" * 38, "wallet",
                      site_id=sid2, url="http://ev2.onion", content_hash=ch, method="extract:btc")
    irow = [r for r in sqlite_db.search("bc1q")["identifiers"]][0]
    chain = sqlite_db.evidence_chain("identifier", irow["id"])
    assert chain["object"]["content_hash"] == ch
    assert chain["observations"] and chain["observations"][0]["method"] == "extract:btc"
    assert chain["observations"][0]["raw"] == "bc1q" + "0" * 38


def test_provenance_chain_finding(sqlite_db):
    sid = sqlite_db.upsert_site("http://p.onion", title="P", category="onion")
    sqlite_db.add_finding(sid, "server_banner", "medium", "Apache header", 0.6,
                          url="http://p.onion", method="detect:scan")
    fid = [r for r in sqlite_db.q("SELECT * FROM findings WHERE site_id=?", (sid,))][0]["id"]
    chain = sqlite_db.evidence_chain("finding", fid)
    assert chain["observations"] and chain["observations"][0]["kind"] == "server_banner"
    assert chain["observations"][0]["raw"] == "Apache header"


def test_provenance_link_and_attribute(sqlite_db):
    sqlite_db.add_link("handle", "alice", "btc", "bc1q" + "0" * 38, "controls", 0.9, "shared post")
    lid = [r for r in sqlite_db.q(
        "SELECT * FROM links WHERE src_value='alice' AND edge='controls'")][0]["id"]
    ev = sqlite_db.q("SELECT * FROM link_evidence WHERE link_id=?", (lid,))
    assert ev and ev[0]["evidence"] == "shared post"
    chain = sqlite_db.evidence_chain("link", lid)
    assert len(chain["observations"]) >= 1
    sqlite_db.add_attribution("link", "alice", chain["observations"][0]["content_hash"],
                              statement="disputes", confidence=0.2, note="another plausible owner")
    stmts = sqlite_db.list_attribution(subject="alice")
    assert stmts and stmts[0]["statement"] == "disputes"
    chain2 = sqlite_db.evidence_chain("link", lid)
    assert chain2["attribution"]


def test_add_link_idempotent_no_bloat(sqlite_db):
    n0 = sqlite_db.one("SELECT COUNT(*) c FROM links")["c"]
    ev0 = sqlite_db.one("SELECT COUNT(*) c FROM link_evidence")["c"]
    for _ in range(50):
        sqlite_db.add_link("handle", "alice", "btc", "bc1q" + "0" * 38, "controls", 0.9, "shared post")
    assert sqlite_db.one("SELECT COUNT(*) c FROM links")["c"] == n0 + 1
    assert sqlite_db.one("SELECT COUNT(*) c FROM link_evidence")["c"] == ev0 + 1


def test_source_trust_roundtrip(sqlite_db):
    sqlite_db.set_source_trust("test", 0.9, notes="verified mirror", analyst="alice")
    rows = sqlite_db.source_trusts()
    assert rows and rows[0]["source"] == "test" and abs(rows[0]["trust"] - 0.9) < 1e-6
    sqlite_db.set_source_trust("test", 0.3, notes="downgraded", analyst="bob")
    rows = sqlite_db.source_trusts()
    assert abs(rows[0]["trust"] - 0.3) < 1e-6 and rows[0]["rated_by"] == "bob"


def test_observation_dedupes_on_hash(sqlite_db):
    before = sqlite_db.one("SELECT COUNT(*) c FROM observations")["c"]
    sqlite_db.add_observation("m", "k", "same raw")
    sqlite_db.add_observation("m", "k", "same raw")
    after = sqlite_db.one("SELECT COUNT(*) c FROM observations")["c"]
    assert after == before + 1


# ---------- wallets / stealer pivots ----------
def test_wallet_cluster_links_handles(sqlite_db):
    sid = sqlite_db.upsert_site("http://mkt.onion", title="Market", category="onion")
    aid1 = sqlite_db.upsert_actor("carol", category="onion")
    aid2 = sqlite_db.upsert_actor("dave", category="onion")
    w = "bc1q" + "0" * 38
    sqlite_db.add_identifier(aid1, "carol", "btc", w, "wallet", site_id=sid, method="extract:btc")
    sqlite_db.add_identifier(aid2, "dave", "btc", w, "wallet", site_id=sid, method="extract:btc")
    sqlite_db.upsert_wallet(w, "btc")
    rows, total = sqlite_db.list_wallets(q=w)
    assert total == 1 and rows[0]["n_identifiers"] == 2
    cl = sqlite_db.wallet_cluster(w)
    assert w in cl["wallets"] and "carol" in cl["handles"] and "dave" in cl["handles"]


def test_stealer_import_pivots(sqlite_db):
    from darkforce import collect
    text = (
        "# sample stealer log\n"
        "alice@protonmail.com:somesecret1x:bc1q" + "0" * 38 + ":1.2.3.4:win10\n"
        "bob@pm.me:otherpass1y:bc1q" + "q" * 38 + ":5.6.7.8:win11\n"
    )
    out = collect.import_stealer_log(sqlite_db, text.splitlines(), "stealer_test")
    assert out["emails"] == 2 and out["btc"] == 2 and out["lines"] == 2
    piv = sqlite_db.breach_pivots("alice@protonmail.com")
    assert piv["query"] == "alice@protonmail.com"
    assert any(b["name"] == "stealer_test" for b in piv["matches"])
    edges = [r for r in sqlite_db.q("SELECT * FROM links WHERE edge='leaked_in'")]
    assert len(edges) >= 2
    # idempotence: re-running adds no duplicate breach record
    collect.import_stealer_log(sqlite_db, text.splitlines(), "stealer_test")
    assert sqlite_db.one("SELECT COUNT(*) c FROM breaches WHERE name='stealer_test'")["c"] == 1


# ---------- case folders + ops detection ----------
def test_case_folder_lifecycle(sqlite_db):
    cid = sqlite_db.create_case("OP Ghost", status="open", owner="alice", notes="follow the wallets")
    assert cid and sqlite_db.create_case("OP Ghost") is None  # name unique
    sid = sqlite_db.upsert_site("http://ghost.onion", title="Ghost", category="onion")
    sqlite_db.case_add_member(cid, "site", sid, label="Market pivot", note="vendor index", tag="poi")
    c = sqlite_db.get_case(cid)
    assert c["n_members"] >= 1 and c["members"][0]["label"] == "Market pivot"
    sqlite_db.update_case_status(cid, "closed")
    rows = sqlite_db.list_cases(status="closed")
    assert rows and rows[0]["id"] == cid and rows[0]["status"] == "closed"
    sqlite_db.case_remove_member(cid, c["members"][0]["id"])
    assert sqlite_db.get_case(cid)["n_members"] == 0


def test_gone_dark_detection(sqlite_db):
    url = "http://gone.onion"
    sqlite_db.upsert_site(url, title="Hidden", category="onion", content_hash="abc123")
    sqlite_db.mark_site_scanned(url, status="down")
    base = sqlite_db.latest_alert_id()
    out = sqlite_db.detect_ops(days=14)
    assert any(g["url"] == url for g in out["gone_dark"])
    fresh = [a for a in sqlite_db.alerts() if a["id"] > base]
    assert any(a["kind"] == "sites_gone_dark" for a in fresh)


def test_successor_detection(sqlite_db):
    sqlite_db.add_watchlist("Silk Road 2 successor", "silk road", "market")
    sqlite_db.upsert_site("http://successor.onion", title="Silk Road 3 - we are back",
                          category="markets")
    urls = sqlite_db.sites_all()
    site = [r for r in urls if r["url"] == "http://successor.onion"][0]
    assert "silk road" in (site["title"] or "").lower()
    base = sqlite_db.latest_alert_id()
    out = sqlite_db.detect_ops(days=14)
    assert out["successor_alerts"] >= 1
    fresh = [a for a in sqlite_db.alerts() if a["id"] > base]
    assert any(a["kind"] == "successor_suspected" for a in fresh)
    # hardening: repeated ops runs must not spam identical successor alerts
    sqlite_db.detect_ops(days=14)
    n = sqlite_db.one(
        "SELECT COUNT(*) c FROM alerts WHERE kind='successor_suspected' AND url='http://successor.onion'")
    assert n["c"] == 1


def test_wallet_cluster_truncates_runaway(sqlite_db):
    w = "bc1q" + "0" * 38
    for i in range(801):
        sqlite_db.add_identifier(None, f"operator{i}", "btc", w, "wallet", method="extract:btc")
    cl = sqlite_db.wallet_cluster(w)
    assert cl["truncated"] is True
    assert len(cl["wallets"]) <= 401


class _O:
    def __init__(self):
        import json
        self.dto = json


# ---------- RBAC + audit ----------
def test_auth_and_audit(sqlite_db):
    from darkforce import auth
    h = auth.hash_password("hunter2")
    assert auth.verify_password("hunter2", h) and not auth.verify_password("wrong", h)
    sqlite_db.ensure_admin("boss", h)
    u = sqlite_db.get_user("boss")
    assert u["role"] == "admin"
    t = auth.issue_token("boss", "admin", ttl=30)
    who = auth.parse_token(t)
    assert who["username"] == "boss" and who["role"] == "admin"
    assert auth.parse_token(t + "x") is None
    sqlite_db.log_audit("boss", "admin", "POST", "/api/refresh", 200)
    rows = sqlite_db.audit_logs()
    assert rows[0]["path"] == "/api/refresh" and rows[0]["username"] == "boss"


# ---------- telegram guard + pdf report ----------
def test_telegram_guard_requires_env(monkeypatch):
    from darkforce.seeds import collect_telegram
    monkeypatch.delenv("TG_API_ID", raising=False)
    monkeypatch.delenv("TG_API_HASH", raising=False)
    monkeypatch.delenv("TG_CHANNELS", raising=False)
    assert collect_telegram(channels="@somechannel") == []  # no TG_API_ID/HASH -> no-op


def test_pdf_report_builds():
    from darkforce.export import report_pdf
    meta = {"title": "Test", "classification": "UNCLASSIFIED",
            "verdict": {"confidence": 0.91, "basis": "shared PGP key"},
            "coverage": "2 actors, 3 sites"}
    data = report_pdf(meta, records=[{"handle": "a", "score": 0.9}, {"handle": "b", "score": 0.2}])
    assert data[:4] == b"%PDF" and len(data) > 800


def test_digest_summary_and_pdf(sqlite_db):
    from darkforce.export import digest_pdf
    sid, aid = _seed(sqlite_db)
    sqlite_db.add_finding(sid, "leaked_data", "critical", "Found dump", 0.98)
    act = sqlite_db.recent_activity(hours=24)
    assert "generated_at" in act and "snapshot" in act
    assert act["new_sites_total"] == 1
    assert act["new_sites_by_category"].get("other") == 1
    assert any(f["severity"] in ("high", "critical") for f in act["high_critical_findings"])
    meta = {"title": "Digest", "date": act["generated_at"], "backend": "sqlite"}
    data = digest_pdf(meta, act)
    assert data[:4] == b"%PDF" and len(data) > 800


# ---------- category taxonomy ----------
def test_collectors_validate_urls(monkeypatch):
    """Directory collectors must return well-formed v3 onion URLs, or degrade
    gracefully (empty) rather than raising when the source is unreachable."""
    from darkforce import seeds

    def fake_get(url, params=None, proxies=None, timeout=15, headers=None):
        v3 = "a" * 56
        class R:
            status_code = 200
            text = (
                f'<div class="link-url">http://{v3}.onion</div>'
                f'<p class="url">http://{v3}.onion</p>'
                f'<a href="http://{v3}.onion">x</a>'
            )
        return R()

    monkeypatch.setattr(seeds, "_get", fake_get)
    for name in ("azidal", "thedarknet", "notevil"):
        items = seeds.collect_source(name)
        assert items, f"{name} returned nothing with a live fixture"
        for it in items:
            assert it["url"].lstrip("http://").endswith(".onion")
            assert len(it["url"].lstrip("http://").split(".")[0]) in (16, 56)
            assert it.get("category") and it.get("title")


def test_normalize_category_maps_to_canonical():
    from darkforce.categories import CANONICAL, normalize_category
    assert normalize_category("financial") == "financial/carding"
    assert normalize_category("privacy") == "privacy/hosting"
    assert normalize_category("market") == "markets"
    assert normalize_category("marketplace") == "markets"
    assert normalize_category("ransom") == "ransomware"
    assert normalize_category("directory") == "directories"
    assert normalize_category("clearnet") == "other"
    assert normalize_category("forum") == "forums"
    assert normalize_category("phishing") == "fraud/scam"
    assert normalize_category("terrorism") == "extremism"
    assert normalize_category("document") == "forgery"
    assert normalize_category("casino") == "gambling"
    assert normalize_category("assassination") == "hitman"
    assert normalize_category("leak") == "leaked data"
    assert normalize_category("") == "other"
    assert normalize_category("free tools") == "free"
    assert normalize_category("free tool") == "free"
    assert normalize_category("free resources") == "free"
    assert normalize_category("free resource") == "free"
    assert normalize_category("free downloads") == "free"
    assert normalize_category("freebies") == "free"
    assert normalize_category("darknet news") == "news"
    assert normalize_category("webzine") == "news"
    assert normalize_category("hacking tools") == "hacking"
    assert "hacking tools" not in CANONICAL
    for c in CANONICAL:
        assert normalize_category(c) == c


def test_classify_site_uses_extended_taxonomy():
    from darkforce.categories import classify_site
    cases = {
        "passport for sale": "forgery",
        "Replica watches knockoff": "counterfeit",
        "phishing kit and spoof": "fraud/scam",
        "jihadist recruitment": "extremism",
        "tor casino and poker": "gambling",
        "dread forum discussion": "forums",
        "Leaked database for sale": "leaked data",
        "Hitman hire": "hitman",
        "clone card shop": "financial",
        "xanax bars": "drugs",
        "free tool dumps for everyone": "free",
        "free downloads for everyone": "free",
        "crackz vault store": "resources",
        "premium cracked software": "resources",
        "daily breaking darknet news": "news",
        "cyber threat daily brief": "news",
    }
    for title, expected in cases.items():
        assert classify_site(title=title) == expected, title


def test_classify_site_scored_not_first_match():
    from darkforce.categories import classify_site
    # A single loose porn token no longer outvotes a real category.
    assert classify_site(title="sex education forum") == "forums"
    assert classify_site(title="sex chat") == "forums"
    # Two scam signals beat one hacking-tools signal.
    assert classify_site(title="phishing kit and spoof") == "fraud/scam"
    # Strong porn token still wins.
    assert classify_site(title="watch porn free videos") == "porn"
    assert classify_site(title="xxx video archive") == "porn"


def test_danger_flags():
    from darkforce.categories import danger_flags
    assert "child" in danger_flags(title="download child porn")
    assert "fraud" in danger_flags(title="phishing kit for sale")
    assert "intoxicants" in danger_flags(title="buy xanax bars online")
    assert "weapons" in danger_flags(title="buy ammo and guns")
    assert "hitman" in danger_flags(title="contract killer hire")
    assert "extremism" in danger_flags(title="jihadist recruitment")
    assert danger_flags(title="hidden wiki") == set()


def test_sites_all_exposes_lang_and_normalized_category(sqlite_db):
    sqlite_db.upsert_site("http://lang-test.onion", title="Kuiper cards",
                          category=normalize_category("financial"), lang="EN")
    rows = sqlite_db.sites_all()
    row = [r for r in rows if r["url"] == "http://lang-test.onion"][0]
    assert row["lang"] == "EN"


def test_resources_and_news_api(monkeypatch):
    import darkforce.api as api
    from fastapi.testclient import TestClient

    db = SQLiteDB(_db_path())
    monkeypatch.setattr(api, "db", db)
    rid = db.upsert_site("http://freetools.onion", title="Free tools hub",
                         category="resources")
    cid = db.upsert_site("http://tools2.onion", title="Crackz vault",
                         category="hacking")
    nid = db.upsert_site("http://propub3r.onion", title="ProPublica mirror",
                         category="news")
    db.save_post("editor", rid, "http://freetools.onion/t", "Grab our free keygen pack",
                 "metadata only index", "2026-02-01T00:00:00")
    db.save_post("editor", nid, "http://propub3r.onion/a", "Leak exposes state secrets",
                 "metadata only index", "2026-02-01T01:00:00")

    client = TestClient(api.app)
    res = client.get("/api/resources")
    assert res.status_code == 200
    rows = res.json()
    urls = [r["url"] for r in rows]
    assert set(urls) == {"http://tools2.onion", "http://freetools.onion"}
    assert any(r["headline"] for r in rows)

    res = client.get("/api/resources?category=hacking")
    assert [r["url"] for r in res.json()] == ["http://tools2.onion"]

    res = client.get("/api/news")
    assert res.status_code == 200
    items = res.json()
    assert items and items[0]["title"] == "Leak exposes state secrets"
    assert "http://propub3r.onion" in items[0]["site_url"]
    assert items[0]["handle"] == "editor"
    db.close()


# ---------- postgres (only when DATABASE_URL is set) ----------
@pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")
def test_postgres_roundtrip():
    pg = DB()
    _seed(pg)
    s = pg.stats()
    assert s["actors"] >= 1 and s["identifiers"] >= 2
    assert pg.graph()["nodes"]
    assert pg.timeline()
    pg.close()


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))