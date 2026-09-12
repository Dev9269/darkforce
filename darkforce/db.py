import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from .config import DB_PATH


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def iso(dt):
    return dt.isoformat(timespec="seconds")


def days_ago(n):
    return iso(datetime.now(timezone.utc) - timedelta(days=n))


SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE, type TEXT, url TEXT, live INTEGER DEFAULT 1,
  last_scan TEXT, notes TEXT
);
CREATE TABLE IF NOT EXISTS sites (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  url TEXT UNIQUE, title TEXT, server TEXT, tech TEXT,
  favicon_hash TEXT, content_hash TEXT, status TEXT,
  category TEXT, source_id INTEGER, first_seen TEXT, last_scan TEXT
);
CREATE TABLE IF NOT EXISTS actors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  canon TEXT UNIQUE, category TEXT, confidence REAL DEFAULT 0,
  first_seen TEXT, last_seen TEXT, bio TEXT, risk TEXT
);
CREATE TABLE IF NOT EXISTS handles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_id INTEGER, handle TEXT, site_id INTEGER, url TEXT,
  role TEXT, trust_level TEXT, joined TEXT, first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  handle TEXT, site_id INTEGER, url TEXT, title TEXT, body TEXT,
  ts TEXT, lang TEXT, content_hash TEXT
);
CREATE TABLE IF NOT EXISTS identifiers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  actor_id INTEGER, handle TEXT, kind TEXT, value TEXT, detail TEXT,
  site_id INTEGER, url TEXT, first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id INTEGER, kind TEXT, severity TEXT, detail TEXT,
  confidence REAL DEFAULT 0, url TEXT, first_seen TEXT
);
CREATE TABLE IF NOT EXISTS links (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  src_type TEXT, src_value TEXT, tgt_type TEXT, tgt_value TEXT,
  edge TEXT, confidence REAL DEFAULT 0, evidence TEXT, site_id INTEGER
);
CREATE INDEX IF NOT EXISTS ix_ident_value ON identifiers(value);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ident ON identifiers(handle, kind, value);
CREATE INDEX IF NOT EXISTS ix_handles_h ON handles(handle);
CREATE INDEX IF NOT EXISTS ix_posts_h ON posts(handle);
"""


class DB:
    def __init__(self, path=DB_PATH):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def q(self, sql, args=()):
        return self.conn.execute(sql, args).fetchall()

    def one(self, sql, args=()):
        r = self.conn.execute(sql, args).fetchone()
        return dict(r) if r else None

    def exe(self, sql, args=()):
        c = self.conn.execute(sql, args)
        self.conn.commit()
        return c

    # ---------- upserts ----------
    def upsert_source(self, name, type_, url, notes=""):
        self.exe(
            "INSERT INTO sources(name,type,url,last_scan,notes) VALUES(?,?,?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET last_scan=excluded.last_scan, url=excluded.url",
            (name, type_, url, utcnow(), notes),
        )

    def upsert_site(self, url, **kw):
        kw.setdefault("first_seen", utcnow())
        kw.setdefault("last_scan", utcnow())
        cols = list(kw.keys())
        self.exe(
            f"INSERT INTO sites(url,{','.join(cols)}) VALUES(?," + ",".join("?" * len(cols)) + ") "
            "ON CONFLICT(url) DO UPDATE SET last_scan=excluded.last_scan",
            (url,) + tuple(kw[c] for c in cols),
        )
        return self.one("SELECT id FROM sites WHERE url=?", (url,))["id"]

    def site_id(self, url):
        r = self.one("SELECT id FROM sites WHERE url=?", (url,))
        return r["id"] if r else None

    def actor_by_canon(self, canon):
        return self.one("SELECT * FROM actors WHERE canon=?", (canon,))

    def actor_id(self, canon):
        r = self.actor_by_canon(canon)
        return r["id"] if r else None

    def upsert_actor(self, canon, category="unknown", bio="", risk="open"):
        self.exe(
            "INSERT INTO actors(canon,category,confidence,first_seen,last_seen,bio,risk) "
            "VALUES(?,?,?,?,?,?,?) ON CONFLICT(canon) DO UPDATE SET last_seen=excluded.last_seen",
            (canon, category, 0.6, utcnow(), utcnow(), bio, risk),
        )
        return self.actor_id(canon)

    def upsert_handle(self, actor_id, handle, site_id, url="", role="", trust_level="", joined=""):
        self.exe(
            "INSERT INTO handles(actor_id,handle,site_id,url,role,trust_level,joined,first_seen,last_seen) "
            "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
            (actor_id, handle, site_id, url, role, trust_level, joined, utcnow(), utcnow()),
        )

    def save_post(self, handle, site_id, url, title, body, ts, lang="en"):
        import hashlib

        ch = hashlib.sha1((title + body).encode("utf-8", "ignore")).hexdigest()
        self.exe(
            "INSERT INTO posts(handle,site_id,url,title,body,ts,lang,content_hash) VALUES(?,?,?,?,?,?,?,?)",
            (handle, site_id, url, title, body, ts, lang, ch),
        )
        return ch

    def add_identifier(self, actor_id, handle, kind, value, detail="", site_id=None, url=""):
        self.exe(
            "INSERT INTO identifiers(actor_id,handle,kind,value,detail,site_id,url,first_seen,last_seen) "
            "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(handle, kind, value) DO NOTHING",
            (actor_id, handle, kind, value, detail, site_id, url, utcnow(), utcnow()),
        )

    def add_finding(self, site_id, kind, severity, detail, confidence, url=""):
        self.exe(
            "INSERT INTO findings(site_id,kind,severity,detail,confidence,url,first_seen) VALUES(?,?,?,?,?,?,?)",
            (site_id, kind, severity, detail, confidence, url, utcnow()),
        )

    def add_link(self, src_type, src_value, tgt_type, tgt_value, edge, confidence, evidence="", site_id=None):
        self.exe(
            "INSERT INTO links(src_type,src_value,tgt_type,tgt_value,edge,confidence,evidence,site_id) "
            "VALUES(?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
            (src_type, src_value, tgt_type, tgt_value, edge, confidence, evidence, site_id),
        )

    # ---------- queries ----------
    def stats(self):
        sources = [dict(r) for r in self.q("SELECT name, type, url FROM sources ORDER BY name")]
        return {
            "actors": self.one("SELECT COUNT(*) c FROM actors")["c"],
            "handles": self.one("SELECT COUNT(*) c FROM handles")["c"],
            "identifiers": self.one("SELECT COUNT(*) c FROM identifiers")["c"],
            "posts": self.one("SELECT COUNT(*) c FROM posts")["c"],
            "sites": self.one("SELECT COUNT(*) c FROM sites")["c"],
            "findings": self.one("SELECT COUNT(*) c FROM findings")["c"],
            "links": self.one("SELECT COUNT(*) c FROM links")["c"],
            "sources": [s["name"] for s in sources],
            "source_status": "SEEDED" if sources else "EMPTY",
            "source": sources[0]["name"] if sources else "",
        }

    def search(self, q, kind="all", start=None, end=None):
        q = q.strip().lower()
        res = {"actors": [], "identifiers": [], "sites": []}
        if not q:
            return res
        if kind in ("all", "actor"):
            res["actors"] = [dict(r) for r in self.q(
                "SELECT * FROM actors WHERE lower(canon) LIKE ?", (f"%{q}%",))]
        if kind in ("all", "id", "identifier"):
            res["identifiers"] = [dict(r) for r in self.q(
                "SELECT * FROM identifiers WHERE lower(kind||' '||value||' '||COALESCE(detail,'')) LIKE ?",
                (f"%{q}%",))]
        if kind in ("all", "site"):
            res["sites"] = [dict(r) for r in self.q(
                "SELECT * FROM sites WHERE lower(url||' '||COALESCE(title,'')) LIKE ?", (f"%{q}%",))]
        return res

    def identifiers_for_actor(self, actor_id):
        return [dict(r) for r in self.q(
            "SELECT * FROM identifiers WHERE actor_id=? ORDER BY kind", (actor_id,))]

    def handles_for_actor(self, actor_id):
        return [dict(r) for r in self.q(
            "SELECT h.*, s.url site_url, s.category FROM handles h LEFT JOIN sites s ON h.site_id=s.id "
            "WHERE h.actor_id=? ORDER BY h.handle", (actor_id,))]

    def posts_for_handle(self, handle, limit=500):
        return [dict(r) for r in self.q(
            "SELECT * FROM posts WHERE handle=? ORDER BY ts LIMIT ?", (handle, limit))]

    def posts_for_actor(self, actor_id, limit=1000):
        hs = [r["handle"] for r in self.handles_for_actor(actor_id)]
        if not hs:
            return []
        ph = ",".join("?" * len(hs))
        return [dict(r) for r in self.q(
            f"SELECT * FROM posts WHERE handle IN ({ph}) ORDER BY ts LIMIT ?", tuple(hs) + (limit,))]

    def findings_for_site(self, site_id):
        return [dict(r) for r in self.q(
            "SELECT * FROM findings WHERE site_id=? ORDER BY confidence DESC", (site_id,))]

    def all_sites(self):
        return [dict(r) for r in self.q(
            "SELECT s.*, COUNT(f.id) nfindings FROM sites s LEFT JOIN findings f ON f.site_id=s.id "
            "GROUP BY s.id ORDER BY s.first_seen DESC")]

    def timeline(self, start=None, end=None):
        evs = [dict(r) for r in self.q(
            "SELECT ts, handle, title, url, 'post' etype FROM posts WHERE ts>='1900'" )]
        for f in self.q("SELECT first_seen ts, detail title, url, 'finding' etype FROM findings WHERE ts>= '1900'"):
            evs.append(dict(f))
        evs.sort(key=lambda e: e["ts"] or "")
        return evs

    def graph(self, actor_id=None, max_nodes=300):
        nodes, edges, seen = {}, [], set()
        def add_n(i, label, kind, meta=None):
            if i not in seen:
                seen.add(i)
                nodes[i] = {"id": i, "label": label, "kind": kind, "meta": meta or {}}
        if actor_id:
            a = self.one("SELECT * FROM actors WHERE id=?", (actor_id,))
            if not a:
                return {"nodes": [], "edges": []}
            canon = a["canon"]
            add_n(f"actor:{canon}", canon, "actor", {"conf": a["confidence"]})
            for h in self.handles_for_actor(actor_id):
                add_n(f"handle:{h['handle']}", h["handle"], "handle")
                edges.append({"s": f"actor:{canon}", "t": f"handle:{h['handle']}", "e": "has_handle", "w": 0.9})
                if h["site_url"]:
                    add_n(f"site:{h['site_url']}", h["site_url"], "site")
                    edges.append({"s": f"handle:{h['handle']}", "t": f"site:{h['site_url']}", "e": "registered", "w": 0.8})
            for i in self.identifiers_for_actor(actor_id):
                add_n(f"id:{i['kind']}:{i['value'][:18]}", i["value"][:26], i["kind"])
                edges.append({"s": f"actor:{canon}", "t": f"id:{i['kind']}:{i['value'][:18]}", "e": f"uses_{i['kind']}", "w": 0.95})
        else:
            for a in self.q("SELECT * FROM actors LIMIT ?", (max_nodes,)):
                add_n(f"actor:{a['canon']}", a["canon"], "actor", {"conf": a["confidence"]})
            for l in self.q("SELECT * FROM links LIMIT ?", (max_nodes * 2,)):
                sn = f"{l['src_type']}:{l['src_value'][:18]}"
                tn = f"{l['tgt_type']}:{l['tgt_value'][:18]}"
                add_n(sn, l["src_value"][:26], l["src_type"])
                add_n(tn, l["tgt_value"][:26], l["tgt_type"])
                edges.append({"s": sn, "t": tn, "e": l["edge"], "w": l["confidence"]})
        return {"nodes": list(nodes.values()), "edges": edges}

    def actor_summary(self, actor_id):
        a = self.one("SELECT * FROM actors WHERE id=?", (actor_id,))
        if not a:
            return None
        return {
            **a,
            "identifiers": self.identifiers_for_actor(actor_id),
            "handles": self.handles_for_actor(actor_id),
            "n_posts": self.one("SELECT COUNT(*) c FROM posts p JOIN handles h ON h.handle=p.handle WHERE h.actor_id=?", (actor_id,))["c"],
        }


def tz_filter(start, end):
    w = ""
    if start:
        w += " AND ts>=?"
    if end:
        w += " AND ts<=?"
    return w, [x for x in (start, end) if x]