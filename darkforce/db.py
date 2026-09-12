"""
Database layer. Two drivers, one interface:
  - SQLite  (default, zero-config, used for the demo/dogfooding)
  - PostgreSQL (via DATABASE_URL env var, e.g.
       postgresql://darkforce:darkforce_dev@localhost:5432/darkforce)

Both offer the same method surface (q/one/exe + typed upserts/queries) so
the rest of the app never cares which backend is active.
"""
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from .config import DB_PATH, DATABASE_URL


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def iso(dt):
    return dt.isoformat(timespec="seconds")


def days_ago(n):
    return iso(datetime.now(timezone.utc) - timedelta(days=n))


_EXTRA_SCHEMA = """
CREATE TABLE IF NOT EXISTS watchlists (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT, pattern TEXT, kind TEXT, enabled INTEGER DEFAULT 1,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  kind TEXT, title TEXT, detail TEXT, url TEXT,
  confidence REAL DEFAULT 0, created_at TEXT
);
CREATE TABLE IF NOT EXISTS collector_health (
  source TEXT PRIMARY KEY,
  success_count INTEGER DEFAULT 0, error_count INTEGER DEFAULT 0,
  last_success TEXT, last_error TEXT, last_error_detail TEXT
);
"""

PG_EXTRA_SCHEMA = """
CREATE TABLE IF NOT EXISTS watchlists (
  id BIGSERIAL PRIMARY KEY,
  name TEXT, pattern TEXT, kind TEXT, enabled INTEGER DEFAULT 1,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS alerts (
  id BIGSERIAL PRIMARY KEY,
  kind TEXT, title TEXT, detail TEXT, url TEXT,
  confidence REAL DEFAULT 0, created_at TEXT
);
CREATE TABLE IF NOT EXISTS collector_health (
  source TEXT PRIMARY KEY,
  success_count INTEGER DEFAULT 0, error_count INTEGER DEFAULT 0,
  last_success TEXT, last_error TEXT, last_error_detail TEXT
);
"""


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
""" + _EXTRA_SCHEMA

PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
  id BIGSERIAL PRIMARY KEY,
  name TEXT UNIQUE, type TEXT, url TEXT, live INTEGER DEFAULT 1,
  last_scan TEXT, notes TEXT
);
CREATE TABLE IF NOT EXISTS sites (
  id BIGSERIAL PRIMARY KEY,
  url TEXT UNIQUE, title TEXT, server TEXT, tech TEXT,
  favicon_hash TEXT, content_hash TEXT, status TEXT,
  category TEXT, source_id INTEGER, first_seen TEXT, last_scan TEXT
);
CREATE TABLE IF NOT EXISTS actors (
  id BIGSERIAL PRIMARY KEY,
  canon TEXT UNIQUE, category TEXT, confidence REAL DEFAULT 0,
  first_seen TEXT, last_seen TEXT, bio TEXT, risk TEXT
);
CREATE TABLE IF NOT EXISTS handles (
  id BIGSERIAL PRIMARY KEY,
  actor_id INTEGER, handle TEXT, site_id INTEGER, url TEXT,
  role TEXT, trust_level TEXT, joined TEXT, first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS posts (
  id BIGSERIAL PRIMARY KEY,
  handle TEXT, site_id INTEGER, url TEXT, title TEXT, body TEXT,
  ts TEXT, lang TEXT, content_hash TEXT
);
CREATE TABLE IF NOT EXISTS identifiers (
  id BIGSERIAL PRIMARY KEY,
  actor_id INTEGER, handle TEXT, kind TEXT, value TEXT, detail TEXT,
  site_id INTEGER, url TEXT, first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS findings (
  id BIGSERIAL PRIMARY KEY,
  site_id INTEGER, kind TEXT, severity TEXT, detail TEXT,
  confidence REAL DEFAULT 0, url TEXT, first_seen TEXT
);
CREATE TABLE IF NOT EXISTS links (
  id BIGSERIAL PRIMARY KEY,
  src_type TEXT, src_value TEXT, tgt_type TEXT, tgt_value TEXT,
  edge TEXT, confidence REAL DEFAULT 0, evidence TEXT, site_id INTEGER
);
CREATE INDEX IF NOT EXISTS ix_ident_value ON identifiers(value);
CREATE UNIQUE INDEX IF NOT EXISTS ux_ident ON identifiers(handle, kind, value);
CREATE INDEX IF NOT EXISTS ix_handles_h ON handles(handle);
CREATE INDEX IF NOT EXISTS ix_posts_h ON posts(handle);
""" + PG_EXTRA_SCHEMA

try:
    import psycopg2
    import psycopg2.extras
    _HAVE_PG = True
except Exception:
    psycopg2 = None
    _HAVE_PG = False


def _pg_sql(sql):
    """Translate SQLite positional '?' placeholders to psycopg2 '%s'.

    psycopg2 reserves '%' in the query text, so literal percents must be
    doubled ('%%') or they get mistaken for argument slots.
    """
    sql = sql.replace("%", "%%")
    return sql.replace("?", "%s")


class BaseDB:
    """Shared business methods; drivers only implement q/one/exe/backend bits."""

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

    def site_content_hash(self, url):
        r = self.one("SELECT content_hash FROM sites WHERE url=?", (url,))
        return (r["content_hash"] if r else None)

    def site_last_scan(self, url):
        r = self.one("SELECT last_scan FROM sites WHERE url=?", (url,))
        return (r["last_scan"] if r else None)

    def mark_site_scanned(self, url, content_hash=None, status=None):
        parts, args = [], []
        if content_hash is not None:
            parts.append("content_hash=?")
            args.append(content_hash)
        if status is not None:
            parts.append("status=?")
            args.append(status)
        parts.append("last_scan=?")
        args.append(utcnow())
        if not parts:
            return
        args.append(url)
        self.exe(f"UPDATE sites SET {', '.join(parts)} WHERE url=?", args)

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
            "SELECT ts, handle, title, url, 'post' etype FROM posts WHERE ts>='1900'")]
        for f in self.q("SELECT first_seen ts, detail title, url, 'finding' etype FROM findings WHERE first_seen >= '1900'"):
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

    # ---------- watchlists / alerts ----------
    def add_watchlist(self, name, pattern, kind="all"):
        self.exe(
            "INSERT INTO watchlists(name,pattern,kind,enabled,created_at) VALUES(?,?,?,1,?)",
            (name, pattern, kind, utcnow()),
        )

    def list_watchlists(self):
        return [dict(r) for r in self.q(
            "SELECT * FROM watchlists ORDER BY enabled DESC, id")]

    def delete_watchlist(self, wid):
        self.exe("DELETE FROM watchlists WHERE id=?", (wid,))

    def alerts(self, limit=100):
        return [dict(r) for r in self.q(
            "SELECT * FROM alerts ORDER BY created_at DESC LIMIT ?", (limit,))]

    def alerts_since(self, aid):
        return [dict(r) for r in self.q(
            "SELECT * FROM alerts WHERE id>? ORDER BY id", (aid,))]

    def latest_alert_id(self):
        r = self.one("SELECT MAX(id) m FROM alerts")
        return r["m"] or 0

    def evaluate_watchlists(self, text, url="", kind="all"):
        """Match free text against watchlist patterns -> returns + records alerts."""
        import re

        hits, ids = [], self.list_watchlists()
        for w in ids:
            if not w["enabled"]:
                continue
            if kind != "all" and w["kind"] not in ("all", kind):
                continue
            try:
                if re.search(re.escape(w["pattern"]), text, re.I):
                    self.exe(
                        "INSERT INTO alerts(kind,title,detail,url,confidence,created_at) "
                        "VALUES(?,?,?,?,?,?)",
                        (w["kind"], w["name"], text[:300], url, 0.8, utcnow()))
                    hits.append(w["name"])
            except Exception:
                continue
        return hits

    def log_source_health(self, source, ok, detail=""):
        col = "success_count" if ok else "error_count"
        ts = utcnow()
        if ok:
            self.exe(
                "INSERT INTO collector_health(source,success_count,error_count,last_success,last_error,last_error_detail) "
                "VALUES(?,1,0,?,NULL,'') "
                "ON CONFLICT(source) DO UPDATE SET success_count=collector_health.success_count+1, last_success=?",
                (source, ts, ts))
        else:
            self.exe(
                "INSERT INTO collector_health(source,success_count,error_count,last_success,last_error,last_error_detail) "
                "VALUES(?,0,1,NULL,?,?) "
                "ON CONFLICT(source) DO UPDATE SET error_count=collector_health.error_count+1, last_error=?, last_error_detail=?",
                (source, ts, detail, ts, detail))

    def collector_health(self):
        return [dict(r) for r in self.q(
            "SELECT * FROM collector_health ORDER BY source")]

    def healthy_sources(self):
        """Sources whose last fetch succeeded (usable for autonomous polling)."""
        return [r["source"] for r in self.q(
            "SELECT source FROM collector_health WHERE last_success IS NOT NULL")]


class SQLiteDB(BaseDB):
    def __init__(self, path=DB_PATH):
        self.path = path
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
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


class PostgresDB(BaseDB):
    def __init__(self, dsn=None):
        if psycopg2 is None:
            raise RuntimeError("psycopg2 not installed; DATABASE_URL can't be used")
        self.dsn = dsn or DATABASE_URL
        self.conn = psycopg2.connect(self.dsn)
        self.conn.autocommit = False
        with self.conn.cursor() as cur:
            cur.execute(PG_SCHEMA)
        self.conn.commit()

    def q(self, sql, args=()):
        with self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(_pg_sql(sql), list(args))
            return cur.fetchall()

    def one(self, sql, args=()):
        with self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(_pg_sql(sql), list(args))
            r = cur.fetchone()
            return dict(r) if r else None

    def exe(self, sql, args=()):
        with self.conn.cursor() as cur:
            cur.execute(_pg_sql(sql), list(args))
        self.conn.commit()
        return cur


# The driver factory — app code keeps calling DB() with no args.
def DB(path=None):
    if DATABASE_URL:
        if not _HAVE_PG:
            raise RuntimeError(
                "DATABASE_URL is set but psycopg2-binary isn't installed "
                "(pip install psycopg2-binary)")
        return PostgresDB(DATABASE_URL)
    return SQLiteDB(path or DB_PATH)


def migrate(dst_db=None):
    """One-time SQLite -> Postgres copy. dst must be a DB instance (default: DATABASE_URL)."""
    src = SQLiteDB(DB_PATH)
    dst = dst_db or DB()
    tables = ("sources", "sites", "actors", "handles", "posts",
              "identifiers", "findings", "links")
    moved = {}
    for t in tables:
        try:
            rows = [dict(r) for r in src.q(f"SELECT * FROM {t}")]
        except Exception as e:
            print(f"  skip {t}: {e}")
            continue
        for r in rows:
            cols = list(r.keys())
            ph = ",".join("?" * len(cols))
            cols_s = ",".join(cols)
            dst.exe(
                f"INSERT INTO {t} ({cols_s}) VALUES ({ph}) ON CONFLICT DO NOTHING",
                tuple(r[c] for c in cols))
        # advance the identity / serial sequence so new inserts don't collide
        try:
            dst.exe("SELECT setval(pg_get_serial_sequence('" + t + "','id'), "
                    "COALESCE((SELECT MAX(id) FROM " + t + "), 1), true)")
        except Exception:
            pass
        moved[t] = len(rows)
        print(f"  migrated {t}: {len(rows)} rows")
    return moved


def tz_filter(start, end):
    w = ""
    if start:
        w += " AND ts>=?"
    if end:
        w += " AND ts<=?"
    return w, [x for x in (start, end) if x]