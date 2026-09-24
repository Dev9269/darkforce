import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from darkforce import index_loader
from darkforce.db import SQLiteDB


def _db():
    fd, p = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return SQLiteDB(p)


V3 = "a" * 56 + ".onion"


def _fake_get_ahmia(url, *a, **k):
    class R:
        status_code = 200
        text = f"<a href='http://{V3}/shop'>X</a> <td>{V3}</td> <h1>http://b{V3}</h1>"
    return R()


def test_normalize_onion():
    assert index_loader.normalize_onion(f"https://{V3}/Path") == f"http://{V3}"
    assert index_loader.normalize_onion(f"{V3}/") == f"http://{V3}"
    assert index_loader.normalize_onion("admin.site.onion") is None  # not v3
    assert index_loader.normalize_onion("clearnet.example.com") is None


def test_ahmia_index_fetch():
    items = index_loader.load_ahmia_index(fetch=_fake_get_ahmia)
    urls = {i["url"] for i in items}
    assert f"http://{V3}" in urls
    assert all(i["url"].endswith(".onion") for i in items)
    assert all(i.get("category") == "directory" for i in items)


def test_local_catalogs_parse(tmp_path):
    (tmp_path / "onion_sites.jsonl").write_text(
        f'{{"url":"http://{V3}","title":"Shop","lang":"EN"}}\n', encoding="utf-8")
    (tmp_path / "harvest_results.jsonl").write_text(
        f'{{"url":"http://{V3}/","title":"S","purpose":"markets","desc":"d"}}\n', encoding="utf-8")
    (tmp_path / "ahmia_onions.txt").write_text(f"{V3}\n", encoding="utf-8")
    items = index_loader.load_local_catalogs(str(tmp_path))
    assert len({i["url"] for i in items}) == 1  # dedup by host
    assert any(i.get("purpose") == "markets" for i in items)


def test_import_indexes_dedups_and_marks_listed():
    db = _db()
    items = [{"title": "A", "url": f"http://{V3}", "category": "directory", "purpose": ""},
             {"title": "A2", "url": f"http://{V3}/", "category": "directory", "purpose": ""}]
    db.upsert_source("ahmia_index", "index", "https://ahmia.fi/onions/")
    src = db.one("SELECT id FROM sources WHERE name='ahmia_index'")["id"]
    res = index_loader.import_indexes(db, items, source_id=src)
    assert res["new"] == 1
    row = db.one("SELECT * FROM sites WHERE url=?", (f"http://{V3}",))
    assert row and row["status"] == "listed" and row["source_id"] == src
    assert row["last_scan"] is None  # not yet crawled
    res2 = index_loader.import_indexes(db, items, source_id=src)
    assert res2["new"] == 0 and res2["total"] == 1