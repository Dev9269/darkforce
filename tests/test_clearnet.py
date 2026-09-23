"""Clearnet correlation capability (hidden-service -> clearnet swaps).

Regression suite for Capability 1: detect.scan must correlate a fetched onion
snap against a clearnet fingerprint index and emit favicon/mirror/analytics/
banner matches that survive into findings.
"""
import hashlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from darkforce import detect, net as net_mod

FAVICON = b"\x89PNG\r\n" + b"\x00" * 48
FAVICON_SHA = hashlib.sha1(FAVICON).hexdigest()
ONION_HTML = "<html><body>alpha content</body></html>"
ONION_HTML_SHA = hashlib.sha1(ONION_HTML.encode("utf-8")).hexdigest()


@pytest.fixture
def clearnet_db():
    import tempfile

    from darkforce.db import SQLiteDB

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = SQLiteDB(path)
    yield db
    db.close()


def _cn_snap(host, html, favicon=None, server=""):
    return detect.Snap(url=f"http://{host}", html=html, favicon=favicon,
                       headers={"Server": server} if server else {},
                       meta={"hostname": host})


def _onion_snap(favicon=None, html=ONION_HTML, server=""):
    return detect.Snap(url=f"http://swap{hashlib.md5(html.encode()).hexdigest()[:6]}.onion",
                       html=html, favicon=favicon,
                       headers={"Server": server} if server else {},
                       meta={"hostname": "swap.onion"})


# ---------- db persistence ----------
def test_upsert_and_load_clearnet_fp(clearnet_db):
    clearnet_db.upsert_clearnet_fp(
        "www.example.com", title="Example",
        favicon_hash=FAVICON_SHA, content_hash=ONION_HTML_SHA, server="nginx",
        analytics_id="UA-123456-1")
    clearnet_db.upsert_clearnet_fp("blog.example.net", title="Blog")

    rows = clearnet_db.load_clearnet_index()
    assert len(rows) == 2
    by_host = {r["host"]: r for r in rows}
    assert by_host["www.example.com"]["favicon_hash"] == FAVICON_SHA
    assert by_host["www.example.com"]["content_hash"] == ONION_HTML_SHA
    assert by_host["www.example.com"]["server"] == "nginx"
    assert by_host["www.example.com"]["analytics_id"] == "UA-123456-1"

    clearnet_db.upsert_clearnet_fp("www.example.com", title="Example 2", server="nginx")
    assert len(clearnet_db.load_clearnet_index()) == 2, "upsert by host must not duplicate"


# ---------- index import from sites ----------
def test_index_imports_clearnet_sites_and_skips_onions(clearnet_db):
    from darkforce.clearnet_index import import_sites, load

    clearnet_db.upsert_site("http://clearnet-host.example/page", title="Cn site",
                            favicon_hash=FAVICON_SHA, content_hash="c1", server="nginx",
                            category="clearnet")
    clearnet_db.upsert_site("http://deadbeef.onion", title="Onion only",
                            favicon_hash=FAVICON_SHA, category="onion")

    import_sites(clearnet_db)

    idx = load(clearnet_db)
    hosts = {r["host"] for r in idx.records}
    assert "clearnet-host.example" in hosts
    assert "deadbeef.onion" not in hosts
    rec = [r for r in idx.records if r["host"] == "clearnet-host.example"][0]
    assert rec["favicon_hash"] == FAVICON_SHA
    assert rec["server"] == "nginx"
    assert rec["title"] == "Cn site"


def test_crawl_seeds_persists_fingerprints(clearnet_db, monkeypatch):
    from darkforce.clearnet_index import crawl_seeds

    def fake_fetch(url, use_tor=False, timeout=20):
        html = ('<html><title>Mirror</title><script>gtag("config", "UA-7777-1");</script></html>')
        return detect.Snap(url=url, headers={"Server": "nginx"}, html=html,
                           favicon=FAVICON, meta={"hostname": "mirror.example.com"})

    monkeypatch.setattr(net_mod, "fetch_snap", fake_fetch)

    crawl_seeds(clearnet_db, domains=["mirror.example.com"])

    rows = clearnet_db.load_clearnet_index()
    assert len(rows) == 1
    assert rows[0]["host"] == "mirror.example.com"
    assert rows[0]["favicon_hash"] == FAVICON_SHA
    assert rows[0]["server"] == "nginx"
    assert rows[0]["analytics_id"] == "UA-7777-1"


# ---------- detect.scan against an index ----------
def test_scan_favicon_and_mirror_match_from_two_snaps():
    from darkforce.clearnet_index import ClearnetIndex

    cl1 = detect.fingerprint(_cn_snap("clearnet-a.example", "<html>alpha</html>",
                                      favicon=FAVICON, server="nginx"))
    cl2 = detect.fingerprint(_cn_snap("clearnet-b.example", "<html>beta</html>",
                                      favicon=FAVICON, server="nginx"))
    idx = ClearnetIndex([
        {"host": "clearnet-a.example", "title": "A Mirror",
         "favicon_hash": cl1["favicon_hash"], "content_hash": cl1["content_hash"],
         "server": cl1["server"], "analytics_id": ""},
        {"host": "clearnet-b.example", "title": "B Mirror",
         "favicon_hash": cl2["favicon_hash"], "content_hash": cl2["content_hash"],
         "server": cl2["server"], "analytics_id": ""},
    ])

    onion = _onion_snap(favicon=FAVICON, html="<html>alpha</html>", server="nginx")
    findings, _ = detect.scan(onion, idx)

    by_kind = {}
    for kind, sev, detail, conf in findings:
        by_kind.setdefault(kind, []).append(conf)
    assert len(by_kind.get("favicon_match", [])) >= 1
    assert all(c == 0.9 for c in by_kind["favicon_match"])
    assert len(by_kind.get("mirror_match", [])) >= 1
    assert all(c == 0.9 for c in by_kind["mirror_match"])


def test_scan_analytics_match_from_index():
    from darkforce.clearnet_index import ClearnetIndex

    idx = ClearnetIndex([
        {"host": "track.example", "title": "Tracker", "favicon_hash": None,
         "content_hash": None, "server": "", "analytics_id": "UA-9999-1"},
    ])
    snap = detect.Snap(url="http://x.onion",
                       html='<script>gtag("config", "UA-9999-1");</script>')
    findings, _ = detect.scan(snap, idx)
    assert any(k == "analytics_match" and c == 0.85 for k, s, d, c in findings)


def test_scan_banner_match_from_index():
    from darkforce.clearnet_index import ClearnetIndex

    idx = ClearnetIndex([
        {"host": "banner.example", "title": "Banner", "favicon_hash": None,
         "content_hash": None, "server": "nginx", "analytics_id": ""},
    ])
    snap = detect.Snap(url="http://y.onion", html="<html>z</html>",
                       headers={"Server": "nginx"})
    findings, _ = detect.scan(snap, idx)
    assert any(k == "banner_match" and c == 0.75 for k, s, d, c in findings)


# ---------- crawl_and_ingest wiring ----------
def test_crawl_and_ingest_correlates_against_index(clearnet_db, monkeypatch):
    from darkforce import collect
    from darkforce.clearnet_index import load

    clearnet_db.upsert_clearnet_fp(
        "clearnet-a.example", title="A Mirror",
        favicon_hash=FAVICON_SHA, content_hash=ONION_HTML_SHA, server="nginx")

    def fake_fetch(url, use_tor=False, timeout=20):
        return detect.Snap(url="http://swap.onion", headers={"Server": "nginx"},
                           html=ONION_HTML, favicon=FAVICON,
                           meta={"hostname": "swap.onion"})

    monkeypatch.setattr(net_mod, "fetch_snap", fake_fetch)

    res = collect.crawl_and_ingest(clearnet_db, "http://swap.onion")
    assert res["error"] is None
    assert res["findings"] >= 2

    kinds = {r["kind"] for r in clearnet_db.q("SELECT kind FROM findings")}
    assert "favicon_match" in kinds
    assert "mirror_match" in kinds
    assert load(clearnet_db)  # index loadable after ingest


# ---------- api wiring ----------
def test_api_scan_emits_correlation(monkeypatch):
    import tempfile

    from fastapi.testclient import TestClient

    import darkforce.api as api
    from darkforce import auth
    from darkforce.db import SQLiteDB

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = SQLiteDB(path)
    monkeypatch.setattr(api, "db", db)
    db.upsert_clearnet_fp(
        "clearnet-a.example", title="A Mirror",
        favicon_hash=FAVICON_SHA, content_hash=ONION_HTML_SHA, server="nginx")

    def fake_fetch(url, use_tor=False, timeout=20):
        return detect.Snap(url=url, headers={"Server": "nginx"},
                           html=ONION_HTML, favicon=FAVICON,
                           meta={"hostname": "swap.onion"})

    monkeypatch.setattr(api.net, "fetch_snap", fake_fetch)

    token = auth.issue_token("analyst", "analyst")
    client = TestClient(api.app)
    res = client.post("/api/scan", json={"url": "http://swap.onion", "use_tor": False},
                      headers={"authorization": f"Bearer {token}"})
    assert res.status_code == 200
    body = res.json()
    kinds = {f["kind"] for f in body["findings"]}
    assert "favicon_match" in kinds
    assert "mirror_match" in kinds
    db.close()


def test_correlations_endpoint(monkeypatch):
    import tempfile

    from fastapi.testclient import TestClient

    import darkforce.api as api
    from darkforce import auth
    from darkforce.db import SQLiteDB

    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = SQLiteDB(path)
    monkeypatch.setattr(api, "db", db)
    db.upsert_site("http://swap.onion", title="Swap", server="nginx",
                   favicon_hash=FAVICON_SHA, content_hash=ONION_HTML_SHA, category="onion")
    db.upsert_clearnet_fp(
        "clearnet-a.example", title="A Mirror",
        favicon_hash=FAVICON_SHA, content_hash=ONION_HTML_SHA, server="nginx")

    token = auth.issue_token("analyst", "analyst")
    client = TestClient(api.app)
    res = client.get("/api/infra/correlations",
                     headers={"authorization": f"Bearer {token}"})
    assert res.status_code == 200
    entries = res.json()["correlations"]
    assert entries, "at least one onion site must correlate"
    tops = entries[0]
    assert tops["onion_url"] == "http://swap.onion"
    hosts = {c["host"] for c in tops["candidates"]}
    assert "clearnet-a.example" in hosts
    shared = {(c["attribute"], c["confidence"]) for c in tops["candidates"]}
    assert ("favicon_hash", 0.9) in shared
    assert ("content_hash", 0.9) in shared
    db.close()