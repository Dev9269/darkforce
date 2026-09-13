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
import threading
from datetime import datetime, timedelta, timezone

from .config import DB_PATH, DATABASE_URL
from . import categories


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
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE, password_hash TEXT, role TEXT,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT, role TEXT, method TEXT, path TEXT,
  status INTEGER, ts TEXT
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
CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  username TEXT UNIQUE, password_hash TEXT, role TEXT,
  created_at TEXT
);
CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  username TEXT, role TEXT, method TEXT, path TEXT,
  status INTEGER, ts TEXT
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
  category TEXT, source_id INTEGER, first_seen TEXT, last_scan TEXT,
  lang TEXT
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
  category TEXT, source_id INTEGER, first_seen TEXT, last_scan TEXT,
  lang TEXT
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

    def close(self):
        """Release the current thread's connection(s). Subclasses may override."""
        if getattr(self, "conn", None) is not None:
            try:
                self.conn.close()
            except Exception:
                pass

    # ---------- upserts ----------
    def upsert_source(self, name, type_, url, notes=""):
        self.exe(
            "INSERT INTO sources(name,type,url,last_scan,notes) VALUES(?,?,?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET last_scan=excluded.last_scan, url=excluded.url",
            (name, type_, url, utcnow(), notes),
        )

    def upsert_site(self, url, **kw):
        if kw.get("category"):
            kw["category"] = categories.normalize_category(kw["category"])
        kw.setdefault("first_seen", utcnow())
        kw.setdefault("last_scan", utcnow())
        cols = list(kw.keys())
        updates = ", ".join(
            f"{name}=excluded.{name}" if name not in ("first_seen",) else f"first_seen=excluded.first_seen"
            for name in cols
        )
        self.exe(
            f"INSERT INTO sites(url,{','.join(cols)}) VALUES(?," + ",".join("?" * len(cols)) + ") "
            f"ON CONFLICT(url) DO UPDATE SET {updates}",
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

    def search(self, q, kind="all", start=None, end=None, category=None):
        q = (q or "").strip().lower()
        res = {"actors": [], "identifiers": [], "sites": []}
        cat = None
        if category:
            cat = categories.normalize_category(category)
        if not q:
            if kind in ("all", "actor"):
                res["actors"] = self.all_actors()
            if kind in ("all", "id", "identifier"):
                res["identifiers"] = self.all_identifiers()
            if kind in ("all", "site"):
                if cat:
                    res["sites"] = [dict(r) for r in self.q(
                        "SELECT * FROM sites WHERE category=? "
                        "ORDER BY last_scan DESC, id DESC", (cat,))]
                else:
                    res["sites"] = [dict(r) for r in self.q(
                        "SELECT * FROM sites ORDER BY last_scan DESC, id DESC")]
            return res
        if kind in ("all", "actor"):
            res["actors"] = [dict(r) for r in self.q(
                "SELECT * FROM actors WHERE lower(canon) LIKE ?", (f"%{q}%",))]
        if kind in ("all", "id", "identifier"):
            res["identifiers"] = [dict(r) for r in self.q(
                "SELECT * FROM identifiers WHERE lower(kind||' '||value||' '||COALESCE(detail,'')) LIKE ?",
                (f"%{q}%",))]
        if kind in ("all", "site"):
            if cat:
                res["sites"] = [dict(r) for r in self.q(
                    "SELECT * FROM sites WHERE category=? AND "
                    "lower(url||' '||COALESCE(title,'')) LIKE ?",
                    (cat, f"%{q}%"))]
            else:
                res["sites"] = [dict(r) for r in self.q(
                    "SELECT * FROM sites WHERE lower(url||' '||COALESCE(title,'')) LIKE ?", (f"%{q}%",))]
        return res

    def identifiers_for_actor(self, actor_id):
        return [dict(r) for r in self.q(
            "SELECT * FROM identifiers WHERE actor_id=? ORDER BY kind", (actor_id,))]

    def all_identifiers(self):
        """Every identifier joined to its actor canonical name, newest first."""
        return [dict(r) for r in self.q(
            "SELECT i.*, a.canon actor_canon FROM identifiers i "
            "LEFT JOIN actors a ON a.id=i.actor_id ORDER BY i.last_seen DESC, i.id DESC")]

    def all_actors(self):
        """Every actor with handle count + post count, by confidence."""
        return [dict(r) for r in self.q(
            "SELECT a.*, (SELECT COUNT(*) FROM handles h WHERE h.actor_id=a.id) n_handles, "
            "       (SELECT COUNT(*) FROM posts p JOIN handles h ON h.handle=p.handle AND h.actor_id=a.id) n_posts "
            "FROM actors a ORDER BY a.confidence DESC, a.id DESC")]

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

    def sites_catalog(self, category=None, q="", page=1, per_page=100):
        """Paginated, filterable master registry for the sites catalog page.

        Returns (page_rows, total). Handles both SQLite (?) and Postgres
        (auto-converted) via the existing q() placeholder style.
        """
        page = max(1, int(page))
        per_page = min(max(1, int(per_page or 100)), 500)
        where, args = [], []
        if category:
            where.append("s.category=?")
            args.append(category)
        if q and q.strip():
            like = f"%{q.strip().lower()}%"
            where.append("(lower(s.url) LIKE ? OR lower(COALESCE(s.title,'')) LIKE ?)")
            args += [like, like]
        wsql = (" WHERE " + " AND ".join(where)) if where else ""
        base = ("SELECT s.id, s.url, s.title, s.server, s.status, s.category, "
                "s.lang, s.source_id, s.first_seen, s.last_scan, "
                "COUNT(f.id) nfindings "
                "FROM sites s LEFT JOIN findings f ON f.site_id=s.id" + wsql + " GROUP BY s.id")
        total = self.one("SELECT COUNT(*) n FROM (" + base + ") t", tuple(args))["n"]
        rows = [dict(r) for r in self.q(
            base + " ORDER BY s.last_scan DESC, s.id DESC LIMIT ? OFFSET ?",
            tuple(args) + (per_page, (page - 1) * per_page))]
        return rows, total

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

    def sites_all(self):
        """Every site with its post count and a body-text digest for purpose
        classification. `digest` is truncated; enough for keyword tagging."""
        rows = [dict(r) for r in self.q(
            "SELECT s.id, s.url, s.title, s.category, s.server, s.status, s.first_seen, s.last_scan, s.lang, "
            "       COUNT(p.id) AS post_count "
            "FROM sites s LEFT JOIN posts p ON p.site_id = s.id "
            "GROUP BY s.id ORDER BY s.last_scan DESC, s.id DESC")]
        for r in rows:
            r["digest"] = ""
            texts = [dict(x) for x in self.q(
                "SELECT body FROM posts WHERE site_id = ? ORDER BY id DESC LIMIT 8", (r["id"],))]
            if texts:
                r["digest"] = " ".join((t["body"] or "") for t in texts)[:4000]
        return rows

    # ---------- RBAC: users + audit log ----------
    def get_user(self, username):
        return self.one("SELECT * FROM users WHERE username=?", (username,))

    def add_user(self, username, password_hash, role="analyst"):
        self.exe("INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
                 (username, password_hash, role, self._now()))
        return self.one("SELECT * FROM users WHERE username=?", (username,))

    def list_users(self):
        return [dict(r) for r in self.q("SELECT id, username, role, created_at FROM users ORDER BY id")]

    def delete_user(self, uid):
        self.exe("DELETE FROM users WHERE id=?", (uid,))

    def log_audit(self, username, role, method, path, status):
        try:
            self.exe("INSERT INTO audit_log (username, role, method, path, status, ts) VALUES (?,?,?,?,?,?)",
                     (username or "-", role or "-", method, path, status, self._now()))
        except Exception:
            pass  # auditing must never break the request

    def audit_logs(self, limit=200):
        return [dict(r) for r in self.q(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,))]

    def ensure_admin(self, username, password_hash):
        """Seed the initial admin only when the users table is empty."""
        if not self.one("SELECT id FROM users LIMIT 1"):
            self.add_user(username, password_hash, role="admin")
            return True
        return False

    def _ensure_columns(self, conn=None):
        """Additive schema migrations so existing stores keep working after new columns land."""
        try:
            cols = [r["name"] for r in self.q("PRAGMA table_info(sites)")]
        except Exception:
            try:
                cols = [r["column_name"] for r in self.q(
                    "SELECT column_name FROM information_schema.columns WHERE table_name='sites'")]
            except Exception:
                cols = []
        if "lang" in cols:
            return
        try:
            self.exe("ALTER TABLE sites ADD COLUMN lang TEXT")
            self.q("SELECT lang FROM sites LIMIT 0")  # force PG to plan; harmless on sqlite
        except Exception:
            pass

    def _now(self):
        import datetime
        return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


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
        self._ensure_columns()

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
    """PostgreSQL driver with per-thread connections.

    psycopg2 connections are not thread-safe, and the app runs uvicorn worker
    threads alongside a background collection thread and long-lived SSE streams.
    Instead of one shared `self.conn`, each thread gets its own connection that
    reconnects lazily if the server dropped it (idle timeout / server restart).

    All schema/migration setup happens on the main thread's connection; new
    threads just use that schema.
    """

    def __init__(self, dsn=None):
        if psycopg2 is None:
            raise RuntimeError("psycopg2 not installed; DATABASE_URL can't be used")
        self.dsn = dsn or DATABASE_URL
        self._thread_local = threading.local()
        with self._conn() as conn:
            with conn.cursor() as cur:
                cur.execute(PG_SCHEMA)
            conn.commit()
            self._ensure_columns(conn)

    @property
    def conn(self):
        """Compatibility accessor so callers using `db.conn` / `db.conn.commit()`
        keep working on the PostgreSQL driver (resolves to this thread's connection)."""
        return self._conn()

    def _conn(self):
        """Return this thread's connection, reconnecting if it is gone/broken."""
        tls = self._thread_local
        if getattr(tls, "conn", None) is not None:
            c = tls.conn
            try:
                if c.closed == 0:
                    return c
            except Exception:
                pass
        tls.conn = psycopg2.connect(self.dsn)
        tls.conn.autocommit = True
        return tls.conn

    def q(self, sql, args=()):
        conn = self._conn()
        for attempt in (0, 1):
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(_pg_sql(sql), list(args))
                    return cur.fetchall()
            except psycopg2.OperationalError as e:
                if attempt == 0 and ("closed" in str(e).lower() or "recovery" in str(e).lower()
                                     or "terminated" in str(e).lower()):
                    self._drop_conn()
                    conn = self._conn()
                    continue
                raise

    def one(self, sql, args=()):
        conn = self._conn()
        for attempt in (0, 1):
            try:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    cur.execute(_pg_sql(sql), list(args))
                    r = cur.fetchone()
                    return dict(r) if r else None
            except psycopg2.OperationalError as e:
                if attempt == 0 and ("closed" in str(e).lower() or "recovery" in str(e).lower()
                                     or "terminated" in str(e).lower()):
                    self._drop_conn()
                    conn = self._conn()
                    continue
                raise

    def exe(self, sql, args=()):
        conn = self._conn()
        for attempt in (0, 1):
            try:
                with conn.cursor() as cur:
                    cur.execute(_pg_sql(sql), list(args))
                conn.commit()
                return cur
            except psycopg2.OperationalError as e:
                if attempt == 0 and ("closed" in str(e).lower() or "recovery" in str(e).lower()
                                     or "terminated" in str(e).lower()):
                    self._drop_conn()
                    conn = self._conn()
                    continue
                raise

    def _drop_conn(self):
        try:
            self._thread_local.conn.close()
        except Exception:
            pass
        self._thread_local.conn = None

    def close(self):
        self._drop_conn()


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