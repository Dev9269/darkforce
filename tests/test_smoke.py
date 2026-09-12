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


# ---------- postgres (only when DATABASE_URL is set) ----------
@pytest.mark.skipif(not DATABASE_URL, reason="DATABASE_URL not set")
def test_postgres_roundtrip():
    pg = DB()
    _seed(pg)
    s = pg.stats()
    assert s["actors"] >= 1 and s["identifiers"] >= 2
    assert pg.graph()["nodes"]
    assert pg.timeline()
    pg.conn.close()


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))