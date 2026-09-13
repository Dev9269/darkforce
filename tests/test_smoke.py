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
    for c in CANONICAL:
        assert normalize_category(c) == c


def test_classify_site_uses_extended_taxonomy():
    from darkforce.categories import classify_site
    cases = {
        "passport for sale": "forgery",
        "Replica watches knockoff": "counterfeit",
        "phishing kit and spoof": "hacking tools",
        "jihadist recruitment": "extremism",
        "tor casino and poker": "gambling",
        "dread forum discussion": "forums",
        "Leaked database for sale": "leaked data",
        "Hitman hire": "hitman",
        "clone card shop": "financial",
        "xanax bars": "drugs",
    }
    for title, expected in cases.items():
        assert classify_site(title=title) == expected, title


def test_sites_all_exposes_lang_and_normalized_category(sqlite_db):
    sqlite_db.upsert_site("http://lang-test.onion", title="Kuiper cards",
                          category=normalize_category("financial"), lang="EN")
    rows = sqlite_db.sites_all()
    row = [r for r in rows if r["url"] == "http://lang-test.onion"][0]
    assert row["lang"] == "EN"


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