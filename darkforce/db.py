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
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT
);
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
CREATE TABLE IF NOT EXISTS observations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT, source_id INTEGER, site_id INTEGER, url TEXT,
  method TEXT, kind TEXT, raw TEXT,
  content_hash TEXT, collector_version TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_obs_hash ON observations(content_hash);
CREATE INDEX IF NOT EXISTS ix_obs_site ON observations(site_id);
CREATE TABLE IF NOT EXISTS link_evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  link_id INTEGER, evidence TEXT, content_hash TEXT,
  source_id INTEGER, ts TEXT
);
CREATE INDEX IF NOT EXISTS ix_link_ev_link ON link_evidence(link_id);
CREATE TABLE IF NOT EXISTS sources_trust (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT UNIQUE, source_id INTEGER,
  trust REAL DEFAULT 0.5, rated_by TEXT, rated_at TEXT, notes TEXT
);
CREATE TABLE IF NOT EXISTS attribution (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  subject_type TEXT, subject TEXT, claim TEXT,
  statement TEXT, confidence REAL DEFAULT 0, note TEXT,
  analyst TEXT, ts TEXT
);
CREATE INDEX IF NOT EXISTS ix_attr_subject ON attribution(subject);
CREATE TABLE IF NOT EXISTS wallets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  address TEXT UNIQUE, kind TEXT, category TEXT,
  first_seen TEXT, last_seen TEXT
);
CREATE INDEX IF NOT EXISTS ix_wallet_kind ON wallets(kind);
CREATE TABLE IF NOT EXISTS breaches (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE, type TEXT, primary_entity TEXT,
  source_url TEXT, ts_acquired TEXT
);
CREATE INDEX IF NOT EXISTS ix_breach_entity ON breaches(primary_entity);
CREATE TABLE IF NOT EXISTS cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE, status TEXT DEFAULT 'open',
  owner TEXT DEFAULT 'analyst', notes TEXT,
  created_at TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS case_members (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id INTEGER, object_type TEXT, object_id INTEGER,
  label TEXT, note TEXT, tag TEXT, added_by TEXT, ts TEXT
);
CREATE INDEX IF NOT EXISTS ix_case_members_case ON case_members(case_id);
DELETE FROM link_evidence WHERE link_id NOT IN (SELECT MIN(id) FROM links GROUP BY src_type, src_value, tgt_type, tgt_value, edge);
DELETE FROM link_evidence WHERE id NOT IN (SELECT MIN(id) FROM link_evidence GROUP BY link_id, content_hash);
DELETE FROM links WHERE id NOT IN (SELECT MIN(id) FROM links GROUP BY src_type, src_value, tgt_type, tgt_value, edge);
CREATE UNIQUE INDEX IF NOT EXISTS ux_links ON links(src_type,src_value,tgt_type,tgt_value,edge);
CREATE UNIQUE INDEX IF NOT EXISTS ux_link_evidence ON link_evidence(link_id,content_hash);
"""

PG_EXTRA_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
  key TEXT PRIMARY KEY,
  value TEXT
);
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
CREATE TABLE IF NOT EXISTS observations (
  id BIGSERIAL PRIMARY KEY,
  ts TEXT, source_id INTEGER, site_id INTEGER, url TEXT,
  method TEXT, kind TEXT, raw TEXT,
  content_hash TEXT, collector_version TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_obs_hash ON observations(content_hash);
CREATE INDEX IF NOT EXISTS ix_obs_site ON observations(site_id);
CREATE TABLE IF NOT EXISTS link_evidence (
  id BIGSERIAL PRIMARY KEY,
  link_id INTEGER, evidence TEXT, content_hash TEXT,
  source_id INTEGER, ts TEXT
);
CREATE INDEX IF NOT EXISTS ix_link_ev_link ON link_evidence(link_id);
CREATE TABLE IF NOT EXISTS sources_trust (
  id BIGSERIAL PRIMARY KEY,
  source TEXT UNIQUE, source_id INTEGER,
  trust REAL DEFAULT 0.5, rated_by TEXT, rated_at TEXT, notes TEXT
);
CREATE TABLE IF NOT EXISTS attribution (
  id BIGSERIAL PRIMARY KEY,
  subject_type TEXT, subject TEXT, claim TEXT,
  statement TEXT, confidence REAL DEFAULT 0, note TEXT,
  analyst TEXT, ts TEXT
);
CREATE INDEX IF NOT EXISTS ix_attr_subject ON attribution(subject);
CREATE TABLE IF NOT EXISTS wallets (
  id BIGSERIAL PRIMARY KEY,
  address TEXT UNIQUE, kind TEXT, category TEXT,
  first_seen TEXT, last_seen TEXT
);
CREATE INDEX IF NOT EXISTS ix_wallet_kind ON wallets(kind);
CREATE TABLE IF NOT EXISTS breaches (
  id BIGSERIAL PRIMARY KEY,
  name TEXT UNIQUE, type TEXT, primary_entity TEXT,
  source_url TEXT, ts_acquired TEXT
);
CREATE INDEX IF NOT EXISTS ix_breach_entity ON breaches(primary_entity);
CREATE TABLE IF NOT EXISTS cases (
  id BIGSERIAL PRIMARY KEY,
  name TEXT UNIQUE, status TEXT DEFAULT 'open',
  owner TEXT DEFAULT 'analyst', notes TEXT,
  created_at TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS case_members (
  id BIGSERIAL PRIMARY KEY,
  case_id INTEGER, object_type TEXT, object_id INTEGER,
  label TEXT, note TEXT, tag TEXT, added_by TEXT, ts TEXT
);
CREATE INDEX IF NOT EXISTS ix_case_members_case ON case_members(case_id);
DELETE FROM link_evidence WHERE link_id NOT IN (SELECT MIN(id) FROM links GROUP BY src_type, src_value, tgt_type, tgt_value, edge);
DELETE FROM link_evidence WHERE id NOT IN (SELECT MIN(id) FROM link_evidence GROUP BY link_id, content_hash);
DELETE FROM links WHERE id NOT IN (SELECT MIN(id) FROM links GROUP BY src_type, src_value, tgt_type, tgt_value, edge);
CREATE UNIQUE INDEX IF NOT EXISTS ux_links ON links(src_type,src_value,tgt_type,tgt_value,edge);
CREATE UNIQUE INDEX IF NOT EXISTS ux_link_evidence ON link_evidence(link_id,content_hash);
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
CREATE TABLE IF NOT EXISTS clearnet_fingerprints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  host TEXT UNIQUE, title TEXT DEFAULT '',
  favicon_hash TEXT, content_hash TEXT, server TEXT DEFAULT '',
  analytics_id TEXT DEFAULT '', last_seen TEXT
);
CREATE INDEX IF NOT EXISTS ix_clearnet_fp_favicon ON clearnet_fingerprints(favicon_hash);
CREATE INDEX IF NOT EXISTS ix_clearnet_fp_content ON clearnet_fingerprints(content_hash);
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
CREATE TABLE IF NOT EXISTS clearnet_fingerprints (
  id BIGSERIAL PRIMARY KEY,
  host TEXT UNIQUE, title TEXT DEFAULT '',
  favicon_hash TEXT, content_hash TEXT, server TEXT DEFAULT '',
  analytics_id TEXT DEFAULT '', last_seen TEXT
);
CREATE INDEX IF NOT EXISTS ix_clearnet_fp_favicon ON clearnet_fingerprints(favicon_hash);
CREATE INDEX IF NOT EXISTS ix_clearnet_fp_content ON clearnet_fingerprints(content_hash);
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

    def sites_by_cert_san(self, domain):
        """Rows whose cert SANs mention a clearnet domain (correlator search)."""
        return self.q(
            "SELECT id,url,cert_sans FROM sites WHERE cert_sans LIKE ?",
            (f"%{domain}%",))

    def upsert_clearnet_fp(self, host, title="", favicon_hash=None, content_hash=None,
                           server="", analytics_id=""):
        self.exe(
            "INSERT INTO clearnet_fingerprints(host,title,favicon_hash,content_hash,"
            "server,analytics_id,last_seen) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(host) DO UPDATE SET title=excluded.title, "
            "favicon_hash=excluded.favicon_hash, content_hash=excluded.content_hash, "
            "server=excluded.server, analytics_id=excluded.analytics_id, "
            "last_seen=excluded.last_seen",
            (host, title, favicon_hash, content_hash, server, analytics_id, utcnow()),
        )

    def load_clearnet_index(self):
        return self.q(
            "SELECT host,title,favicon_hash,content_hash,server,analytics_id "
            "FROM clearnet_fingerprints")

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

    def add_identifier(self, actor_id, handle, kind, value, detail="", site_id=None, url="",
                       source_id=None, content_hash=None, method=""):
        if content_hash is None:
            content_hash = self.add_observation(method or f"extract:{kind}", kind, value,
                                                url=url, site_id=site_id, source_id=source_id)
        self.exe(
            "INSERT INTO identifiers(actor_id,handle,kind,value,detail,site_id,url,"
            "first_seen,last_seen,source_id,content_hash,method) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(handle, kind, value) DO NOTHING",
            (actor_id, handle, kind, value, detail, site_id, url, utcnow(), utcnow(),
             source_id, content_hash, method),
        )

    def add_finding(self, site_id, kind, severity, detail, confidence, url="",
                    source_id=None, content_hash=None, evidence=None, method=""):
        if content_hash is None:
            content_hash = self.add_observation(method or f"detect:{kind}", kind,
                                                (evidence or detail)[:500],
                                                url=url, site_id=site_id, source_id=source_id)
        self.exe(
            "INSERT INTO findings(site_id,kind,severity,detail,confidence,url,first_seen,"
            "source_id,content_hash,evidence) VALUES(?,?,?,?,?,?,?,?,?,?)",
            (site_id, kind, severity, detail, confidence, url, utcnow(),
             source_id, content_hash, evidence or detail),
        )
        self._maybe_alert_from_finding(site_id, kind, severity, detail, confidence, url)

    _ALERT_KINDS = frozenset({
        "hitman", "hitman_for_hire", "leaked_data", "leaked_database", "data_breach",
        "ransomware", "ransomware_leak", "extremism", "terrorism", "weapons",
        "weapon_sale", "malware", "carding", "stolen_cards", "fraud_scam",
    })

    def _maybe_alert_from_finding(self, site_id, kind, severity, detail, confidence, url=""):
        """Derive a LIVE alert from a finding at the sink so the alerts badge /
        SSE actually moves. Alerts fire when a finding is high/critical OR hits
        a danger kind OR is very confident. No alert if this exact finding was
        already alerted in the last 24h (dedupe across rescans)."""
        sev = severity or "low"
        danger = kind in self._ALERT_KINDS
        if not (sev in ("high", "critical") or danger or confidence >= 0.85):
            return
        import datetime as _dt
        cutoff = (_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=1)).isoformat(timespec="seconds")
        dup = self.one(
            "SELECT COUNT(*) n FROM alerts WHERE kind=? AND COALESCE(url,'')=? "
            "AND created_at > ?",
            (f"finding:{kind}", url or "", cutoff),
        )["n"]
        if dup:
            return
        self.exe(
            "INSERT INTO alerts(kind,title,detail,url,confidence,created_at) "
            "VALUES(?,?,?,?,?,?)",
            (
                f"finding:{kind}",
                "Finding: " + (kind or "unknown").replace("_", " ").title(),
                (detail or "")[:400],
                url,
                confidence,
                utcnow(),
            ),
        )

    def add_link(self, src_type, src_value, tgt_type, tgt_value, edge, confidence, evidence="", site_id=None,
                 source_id=None, content_hash=None):
        """Record a typed link between two entities.

        Idempotent per (src_type, src_value, tgt_type, tgt_value, edge): a
        repeat call returns the existing link row without duplicating the
        evidence row, so repeated merges / refreshes stay cheap and the links
        tables cannot bloat."""
        existing = self.one(
            "SELECT id FROM links WHERE src_type=? AND src_value=? AND tgt_type=? AND tgt_value=? AND edge=?",
            (src_type, src_value, tgt_type, tgt_value, edge))
        if existing:
            return existing["id"]
        if content_hash is None:
            content_hash = self.add_observation(f"link:{edge}", edge, (evidence or edge)[:500],
                                                url="", site_id=site_id, source_id=source_id)
        self.exe(
            "INSERT INTO links(src_type,src_value,tgt_type,tgt_value,edge,confidence,evidence,site_id,"
            "source_id,content_hash) VALUES(?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING",
            (src_type, src_value, tgt_type, tgt_value, edge, confidence, evidence, site_id,
             source_id, content_hash),
        )
        link_id = self.one(
            "SELECT id FROM links WHERE src_type=? AND src_value=? AND tgt_type=? AND tgt_value=? AND edge=?",
            (src_type, src_value, tgt_type, tgt_value, edge))["id"]
        self.exe(
            "INSERT INTO link_evidence(link_id,evidence,content_hash,source_id,ts) VALUES(?,?,?,?,?) "
            "ON CONFLICT DO NOTHING",
            (link_id, (evidence or "")[:500], content_hash, source_id, utcnow()),
        )
        return link_id

    # ---------- evidence provenance ledger ----------
    def add_observation(self, method, kind, raw, url="", site_id=None, source_id=None, collector_version=""):
        """Record one observation (the raw, byte-capped fragment that a finding /
        identifier / link derives from) and return its sha256 content-hash.

        The hash is the walkable handle: every consumer row stores it, so any
        claim resolves here for a verifiable chain of custody."""
        import hashlib

        raw = (raw or "")[:500]
        ch = hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()
        self.exe(
            "INSERT INTO observations(ts,source_id,site_id,url,method,kind,raw,content_hash,collector_version) "
            "VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(content_hash) DO NOTHING",
            (utcnow(), source_id, site_id, url, method, kind, raw, ch, collector_version),
        )
        return ch

    def observation_by_hash(self, content_hash):
        r = self.one("SELECT * FROM observations WHERE content_hash=?", (content_hash,))
        if not r:
            return None
        src_info = self.one("SELECT * FROM sources WHERE id=?", (r["source_id"],)) if r["source_id"] else None
        src_name = src_info["name"] if src_info else ""
        trust = None
        if src_name:
            t = self.one("SELECT trust FROM sources_trust WHERE source=?", (src_name,))
            if t:
                trust = t["trust"]
        return {
            **r,
            "source_name": src_name,
            "source_type": src_info["type"] if src_info else "",
            "trust": trust,
        }

    def source_trusts(self):
        rows = [dict(r) for r in self.q(
            "SELECT st.*, COALESCE(s.name, st.source) source_name, s.type source_type "
            "FROM sources_trust st LEFT JOIN sources s ON s.id=st.source_id ORDER BY trust DESC")]
        return rows

    def set_source_trust(self, source, trust, notes="", analyst="analyst"):
        self.exe(
            "INSERT INTO sources_trust(source,trust,rated_by,rated_at,notes) VALUES(?,?,?,?,?) "
            "ON CONFLICT(source) DO UPDATE SET trust=excluded.trust, rated_by=excluded.rated_by, "
            "rated_at=excluded.rated_at, notes=excluded.notes",
            (source, min(max(float(trust), 0.0), 1.0), analyst, utcnow(), notes),
        )
        return {"source": source, "trust": min(max(float(trust), 0.0), 1.0)}

    def evidence_chain(self, objtype, objid):
        """Resolve a stored object (identifier/finding/link/site/actor) back to
        its observation(s), the rated source, and any analyst statements on it."""
        objtype = (objtype or "").lower().rstrip("s")
        out = {"type": objtype, "id": objid, "object": None,
               "observations": [], "attribution": [], "trust": None}
        try:
            if objtype == "identifier":
                out["object"] = self.one("SELECT * FROM identifiers WHERE id=?", (objid,))
            elif objtype == "finding":
                out["object"] = self.one(
                    "SELECT f.*, s.url site_url, s.title FROM findings f LEFT JOIN sites s ON s.id=f.site_id "
                    "WHERE f.id=?", (objid,))
            elif objtype == "link":
                out["object"] = self.one("SELECT * FROM links WHERE id=?", (objid,))
            elif objtype == "site":
                out["object"] = self.one("SELECT * FROM sites WHERE id=?", (objid,))
            elif objtype == "actor":
                out["object"] = self.one("SELECT * FROM actors WHERE id=?", (objid,))
        except Exception:
            pass
        if not out["object"]:
            return out
        ch = out["object"].get("content_hash")
        if ch:
            obs = self.observation_by_hash(ch)
            if obs:
                out["observations"].append(obs)
                out["trust"] = obs.get("trust")
        if objtype == "link":
            for le in self.q("SELECT * FROM link_evidence WHERE link_id=?", (objid,)):
                obs = self.observation_by_hash(le["content_hash"])
                if obs:
                    out["observations"].append({**obs, "evidence": le["evidence"]})
        subj = out["object"].get("url") or out["object"].get("canon") or out["object"].get("value") or ""
        stmts = [dict(r) for r in self.q(
            "SELECT * FROM attribution WHERE subject=? AND subject_type=? ORDER BY id DESC LIMIT 20",
            (subj, objtype))]
        if not stmts and ch:
            stmts = [dict(r) for r in self.q(
                "SELECT * FROM attribution WHERE claim=? ORDER BY id DESC LIMIT 20", (ch,))]
        out["attribution"] = stmts
        return out

    def add_attribution(self, subject_type, subject, claim, statement="asserts",
                        confidence=0.5, note="", analyst="analyst"):
        """Analyst statement about an attribution claim (asserts / denies / disputes)."""
        if statement not in ("asserts", "denies", "disputes"):
            raise ValueError("statement must be asserts|denies|disputes")
        self.exe(
            "INSERT INTO attribution(subject_type,subject,claim,statement,confidence,note,analyst,ts) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (subject_type, subject, claim, statement, confidence, note, analyst, utcnow()),
        )
        return {"subject": subject, "statement": statement, "confidence": confidence}

    def list_attribution(self, subject_type="", subject=""):
        w, args = [], []
        if subject_type:
            w.append("subject_type=?")
            args.append(subject_type)
        if subject:
            w.append("subject LIKE ?")
            args.append(f"%{subject}%")
        wsql = (" WHERE " + " AND ".join(w)) if w else ""
        return [dict(r) for r in self.q(
            "SELECT * FROM attribution" + wsql + " ORDER BY ts DESC, id DESC LIMIT 200", tuple(args))]

    # ---------- wallets / breaches / pivots ----------
    def upsert_wallet(self, address, kind, category="", first_seen=None):
        ts = first_seen or utcnow()
        self.exe(
            "INSERT INTO wallets(address,kind,category,first_seen,last_seen) VALUES(?,?,?,?,?) "
            "ON CONFLICT(address) DO UPDATE SET last_seen=excluded.last_seen",
            (address, kind, category, ts, ts))
        return self.one("SELECT id FROM wallets WHERE address=?", (address,))["id"]

    def list_wallets(self, q="", kind="", page=1, per_page=50):
        page = max(1, int(page))
        per_page = min(max(1, int(per_page or 50)), 500)
        where, args = [], []
        if kind:
            where.append("w.kind=?")
            args.append(kind)
        if q and q.strip():
            where.append("w.address LIKE ?")
            args.append(f"%{q.strip()}%")
        wsql = (" WHERE " + " AND ".join(where)) if where else ""
        base = ("SELECT w.*, (SELECT COUNT(*) FROM identifiers i WHERE i.kind=w.kind AND i.value=w.address) "
                "n_identifiers FROM wallets w" + wsql)
        total = self.one("SELECT COUNT(*) c FROM (" + base + ") t", tuple(args))["c"]
        rows = [dict(r) for r in self.q(
            base + " ORDER BY w.last_seen DESC, w.id DESC LIMIT ? OFFSET ?",
            tuple(args) + (per_page, (page - 1) * per_page))]
        return rows, total

    def wallet_detail(self, address):
        w = self.one("SELECT * FROM wallets WHERE address=?", (address,))
        if not w:
            return None
        # Posts that reference this wallet address
        posts_ref = [dict(r) for r in self.q(
            "SELECT p.id, p.ts, p.title, p.site_id, s.url as site_url "
            "FROM posts p LEFT JOIN sites s ON p.site_id=s.id "
            "WHERE p.raw LIKE ? ORDER BY p.ts DESC LIMIT 20",
            (f"%{address}%",))]
        # Observations that extracted this wallet
        obs_ref = [dict(r) for r in self.q(
            "SELECT o.id, o.ts, o.method, o.kind, o.source_name, o.site_id, s.url as site_url "
            "FROM observations o LEFT JOIN sites s ON o.site_id=s.id "
            "WHERE o.raw LIKE ? ORDER BY o.ts DESC LIMIT 20",
            (f"%{address}%",))]
        return {
            **w,
            "cluster": self.wallet_cluster(address),
            "identifiers": [dict(r) for r in self.q(
                "SELECT * FROM identifiers WHERE (kind='btc' OR kind='xmr') AND value=? ORDER BY id",
                (address,))]
            if w["kind"] in ("btc", "xmr")
            else [dict(r) for r in self.q(
                "SELECT * FROM identifiers WHERE value=? ORDER BY id", (address,))],
            "posts": posts_ref,
            "observations": obs_ref,
        }

    def wallet_cluster(self, address, depth=6):
        """Transitive closure over 'reused wallet' edges: starting from one
        address, collect everything the actors/handles that use it also use.

        Casual offenders reuse wallets across markets, so this is the fastest
        route to a cross-corpus persona."""
        addrs = {address}
        seen_handles, seen_actors = set(), set()
        truncated = False
        for _ in range(depth):
            old = set(addrs)
            for a in list(addrs):
                for r in self.q(
                        "SELECT DISTINCT handle, actor_id FROM identifiers "
                        "WHERE (kind='btc' OR kind='xmr') AND value=?", (a,)):
                    if r["handle"]:
                        seen_handles.add(r["handle"])
                    if r["actor_id"]:
                        seen_actors.add(r["actor_id"])
            if seen_handles:
                ph = ",".join("?" * len(seen_handles))
                for r in self.q(
                        "SELECT DISTINCT value FROM identifiers WHERE (kind='btc' OR kind='xmr') "
                        "AND handle IN (" + ph + ")", tuple(seen_handles)):
                    addrs.add(r["value"])
            if seen_actors:
                ph = ",".join("?" * len(seen_actors))
                for r in self.q(
                        "SELECT DISTINCT value FROM identifiers WHERE (kind='btc' OR kind='xmr') "
                        "AND actor_id IN (" + ph + ")", tuple(seen_actors)):
                    addrs.add(r["value"])
            # Harden the closure: stop expanding a runaway cluster so a single
            # address can never fan out into an oversized IN(...) query.
            if len(addrs) > 400 or len(seen_handles) + len(seen_actors) > 800:
                truncated = True
                break
            if addrs == old:
                break
        return {"seed": address, "wallets": sorted(addrs),
                "handles": sorted(seen_handles), "actors": sorted(seen_actors),
                "truncated": truncated}

    def upsert_breach(self, name, type_, primary_entity="", source_url=""):
        self.exe(
            "INSERT INTO breaches(name,type,primary_entity,source_url,ts_acquired) VALUES(?,?,?,?,?) "
            "ON CONFLICT(name) DO UPDATE SET ts_acquired=excluded.ts_acquired",
            (name, type_, primary_entity, source_url[:500], utcnow()))
        return self.one("SELECT id FROM breaches WHERE name=?", (name,))["id"]

    def list_breaches(self, q="", limit=200):
        if q and q.strip():
            like = f"%{q.strip().lower()}%"
            return [dict(r) for r in self.q(
                "SELECT * FROM breaches WHERE lower(name||' '||COALESCE(primary_entity,'')) LIKE ? "
                "ORDER BY ts_acquired DESC LIMIT ?", (like, limit))]
        return [dict(r) for r in self.q(
            "SELECT * FROM breaches ORDER BY ts_acquired DESC LIMIT ?", (limit,))]

    def breach_pivots(self, value=None):
        """Cross-correlate identifier values against known breach records.
        With a value: exact/similar entity match. Without: every corpus
        identifier that also appears as a breach primary-entity."""
        if value:
            low = value.strip().lower()
            matches = [dict(r) for r in self.q(
                "SELECT * FROM breaches WHERE lower(COALESCE(primary_entity,'')) LIKE ? LIMIT 50",
                (f"%{low}%",))]
            return {"query": value, "matches": matches,
                    "corpus": [dict(r) for r in self.q(
                        "SELECT * FROM identifiers WHERE lower(value)=? LIMIT 20", (low,))]}
        return [dict(r) for r in self.q(
            "SELECT DISTINCT b.name, b.type, b.primary_entity, i.kind, i.value, i.handle, i.site_id "
            "FROM breaches b JOIN identifiers i ON lower(i.value)=lower(b.primary_entity) LIMIT 200")]

    def record_breach_pivot(self, value, breach_name, edge="leaked_in", confidence=0.85):
        self.add_link("identifier", value, "breach", breach_name, edge, confidence,
                      evidence=f"{value} appears in breach corpus '{breach_name}'")

    # ---------- case folders ----------
    def create_case(self, name, status="open", owner="analyst", notes=""):
        try:
            self.exe(
                "INSERT INTO cases(name,status,owner,notes,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                (name, status, owner, notes, utcnow(), utcnow()))
        except Exception:
            return None  # name conflict
        return self.one("SELECT id FROM cases WHERE name=?", (name,))["id"]

    def list_cases(self, status=""):
        w, args = "", ()
        if status:
            w, args = " WHERE status=?", (status,)
        return [dict(r) for r in self.q(
            "SELECT c.*, (SELECT COUNT(*) FROM case_members m WHERE m.case_id=c.id) n_members "
            "FROM cases c" + w + " ORDER BY c.updated_at DESC", args)]

    def get_case(self, case_id):
        c = self.one("SELECT * FROM cases WHERE id=?", (case_id,))
        if not c:
            return None
        members = [dict(r) for r in self.q(
            "SELECT m.*, s.url site_url, s.title site_title FROM case_members m "
            "LEFT JOIN sites s ON s.id=m.object_id AND m.object_type='site' "
            "WHERE m.case_id=? ORDER BY m.id DESC", (case_id,))]
        return {**c, "n_members": len(members), "members": members}

    def update_case_status(self, case_id, status):
        self.exe("UPDATE cases SET status=?, updated_at=? WHERE id=?", (status, utcnow(), case_id))

    def case_add_member(self, case_id, object_type, object_id, label="", note="", tag="", analyst="analyst"):
        self.exe(
            "INSERT INTO case_members(case_id,object_type,object_id,label,note,tag,added_by,ts) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (case_id, object_type, object_id, label[:200], note[:500], tag[:50], analyst, utcnow()))
        self.update_case_status(case_id, self.one("SELECT status FROM cases WHERE id=?", (case_id,))["status"])
        return True

    def case_remove_member(self, case_id, member_id):
        self.exe("DELETE FROM case_members WHERE id=? AND case_id=?", (member_id, case_id))

    # ---------- ops: gone-dark / successor detection ----------
    def sites_gone_dark(self, days=14):
        """Sites that previously resolved (content_hash present) but whose most
        recent fetch FAILED (status='down') - i.e. the operator went dark or
        rotated the address. Returns candidates for analyst review."""
        return [dict(r) for r in self.q(
            "SELECT url, title, category, server, first_seen, last_scan FROM sites "
            "WHERE content_hash IS NOT NULL AND status='down' "
            "AND last_scan >= ? ORDER BY last_scan DESC LIMIT 100", (days_ago(days),))]

    def detect_successors(self, freshness_hours=720):
        """Successor-propaganda detection: new sites whose digest mentions a
        defunct market or matches a watchlist name. Raises successor_suspected
        alerts with the matched market name as evidence."""
        import re

        hits, n = [], 0
        wl = [w for w in self.list_watchlists() if w["enabled"]]
        for row in self.sites_all():
            if row["first_seen"] and row["first_seen"] < days_ago(freshness_hours / 24):
                continue
            text = (row["title"] or "") + " " + (row.get("digest") or "")
            low = text.lower()
            for pat in ("successor", "continuation", "new home of", "we are back",
                        "formerly", "ex-",
                        "restructured", "moved to", "now operating as"):
                if pat in low:
                    hits.append({"url": row["url"], "title": row["title"], "hint": pat})
                    break
            for w in wl:
                if w["pattern"] and w["pattern"].lower() in low:
                    dup = self.one(
                        "SELECT COUNT(*) c FROM alerts WHERE kind='successor_suspected' "
                        "AND COALESCE(url,'')=? AND created_at > ?",
                        (row["url"], days_ago(1)))["c"]
                    if dup:
                        continue
                    self.exe(
                        "INSERT INTO alerts(kind,title,detail,url,confidence,created_at) "
                        "VALUES(?,?,?,?,?,?)",
                        ("successor_suspected", f"Successor candidate: {w['name'] or w['pattern']}",
                         f"{row['url']} mentions '{w['pattern']}'", row["url"], 0.7, utcnow()))
                    n += 1
                    hits.append({"url": row["url"], "title": row["title"],
                                 "hint": f"watchlist {w['pattern']}"})
                    break
        return {"candidates": hits, "alerts": n}

    def detect_ops(self, days=14):
        """Run everywhere-facing operational detection: mark+collect gone-dark
        sites and scan fresh sites for successor propaganda."""
        gone = [dict(r) for r in self.q(
            "SELECT url, title, category, last_scan FROM sites "
            "WHERE content_hash IS NOT NULL AND status='down' AND last_scan>=? LIMIT 50",
            (days_ago(days),))]
        new_alerts = 0
        for g in gone:
            dup = self.one(
                "SELECT COUNT(*) c FROM alerts WHERE kind='sites_gone_dark' AND COALESCE(url,'')=? "
                "AND created_at > ?", (g["url"], days_ago(1)))["c"]
            if dup:
                continue
            self.exe(
                "INSERT INTO alerts(kind,title,detail,url,confidence,created_at) "
                "VALUES(?,?,?,?,?,?)",
                ("sites_gone_dark", "Site went dark: " + (g["title"] or g["url"]),
                 f"previously reachable; last scan {g['last_scan']}", g["url"], 0.8, utcnow()))
            new_alerts += 1
        succ = self.detect_successors()
        return {"gone_dark": gone, "gone_dark_alerts": new_alerts,
                **succ, "successor_alerts": succ["alerts"]}

    # ---------- queries ----------
    def stats(self):
        sources = [dict(r) for r in self.q("SELECT name, type, url FROM sources ORDER BY name")]
        last_pass = self.one("SELECT value FROM meta WHERE key='last_collection_pass'")
        return {
            "actors": self.one("SELECT COUNT(*) c FROM actors")["c"],
            "handles": self.one("SELECT COUNT(*) c FROM handles")["c"],
            "identifiers": self.one("SELECT COUNT(*) c FROM identifiers")["c"],
            "posts": self.one("SELECT COUNT(*) c FROM posts")["c"],
            "sites": self.one("SELECT COUNT(*) c FROM sites")["c"],
            "findings": self.one("SELECT COUNT(*) c FROM findings")["c"],
            "links": self.one("SELECT COUNT(*) c FROM links")["c"],
            "observations": self.one("SELECT COUNT(*) c FROM observations")["c"],
            "attribution": self.one("SELECT COUNT(*) c FROM attribution")["c"],
            "sources": [s["name"] for s in sources],
            "source_status": ("LIVE" if last_pass else ("SEEDED" if sources else "EMPTY")),
            "source": sources[0]["name"] if sources else "",
            "last_collection_pass": last_pass["value"] if last_pass else None,
        }

    def recent_activity(self, hours=24):
        """Nightly-digest summary of the last `hours`: new sites per category,
        new high/critical findings, recent alerts and collector state."""
        cutoff = days_ago(hours)
        new_sites = [dict(r) for r in self.q(
            "SELECT s.url, s.category, s.first_seen FROM sites s WHERE s.first_seen >= ? "
            "ORDER BY s.first_seen DESC", (cutoff,))]
        new_findings = [dict(r) for r in self.q(
            "SELECT f.kind, f.severity, f.detail, f.confidence, f.url, s.url AS site "
            "FROM findings f LEFT JOIN sites s ON s.id = f.site_id "
            "WHERE f.first_seen >= ? ORDER BY f.first_seen DESC "
            "LIMIT 200", (cutoff,))]
        grave = [f for f in new_findings
                 if f["severity"] in ("high", "critical")]
        alerts = [dict(r) for r in self.q(
            "SELECT kind, title, detail, confidence, created_at FROM alerts "
            "WHERE created_at >= ? ORDER BY created_at DESC", (cutoff,))]
        by_category = {}
        for s in new_sites:
            by_category[s["category"] or "unknown"] = by_category.get(s["category"] or "unknown", 0) + 1
        return {
            "window_hours": hours,
            "generated_at": utcnow(),
            "new_sites_total": len(new_sites),
            "new_sites_by_category": by_category,
            "new_findings_total": len(new_findings),
            "high_critical_findings": grave[:50],
            "new_alerts_total": len(alerts),
            "new_alerts": alerts[:50],
            "snapshot": self.stats(),
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
                "SELECT a.*, "
                "       (SELECT COUNT(*) FROM handles h WHERE h.actor_id=a.id) n_handles, "
                "       (SELECT COUNT(*) FROM posts p JOIN handles h ON h.handle=p.handle AND h.actor_id=a.id) n_posts "
                "FROM actors a "
                "WHERE lower(a.canon) LIKE ? "
                "   OR a.id IN (SELECT actor_id FROM handles WHERE lower(handle) LIKE ?) "
                "   OR a.id IN (SELECT actor_id FROM identifiers WHERE lower(value) LIKE ?) "
                "ORDER BY a.confidence DESC, a.id DESC", (f"%{q}%", f"%{q}%", f"%{q}%"))]
        if kind in ("all", "id", "identifier"):
            base = "SELECT * FROM identifiers WHERE lower(kind||' '||value||' '||COALESCE(detail,'')) LIKE ?"
            args = [f"%{q}%"]
            if start:
                base += " AND ts >= ?"
                args.append(start)
            if end:
                base += " AND ts <= ?"
                args.append(end)
            res["identifiers"] = [dict(r) for r in self.q(base, tuple(args))]
        if kind in ("all", "site"):
            if cat:
                base = "SELECT * FROM sites WHERE category=? AND lower(url||' '||COALESCE(title,'')) LIKE ?"
                args = [cat, f"%{q}%"]
            else:
                base = "SELECT * FROM sites WHERE lower(url||' '||COALESCE(title,'')) LIKE ?"
                args = [f"%{q}%"]
            if start:
                base += " AND first_seen >= ?"
                args.append(start)
            if end:
                base += " AND first_seen <= ?"
                args.append(end)
            res["sites"] = [dict(r) for r in self.q(base, tuple(args))]
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

    def graph(self, actor_id=None, max_nodes=300, min_conf=0.0):
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
                if l["confidence"] is not None and l["confidence"] < min_conf:
                    continue
                sn = f"{l['src_type']}:{l['src_value'][:18]}"
                tn = f"{l['tgt_type']}:{l['tgt_value'][:18]}"
                add_n(sn, l["src_value"][:26], l["src_type"])
                add_n(tn, l["tgt_value"][:26], l["tgt_type"])
                edges.append({"s": sn, "t": tn, "e": l["edge"], "w": l["confidence"],
                              "ev": (dict(l).get("content_hash") or "")})
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
        classification. `digest` is truncated; enough for keyword tagging.

        Digests are built from ONE bulk query (newest 8 bodies per site)
        instead of one query per site, which was an N+1 that made the
        sites / categories endpoints crawl at ~2s with large corpora."""
        rows = [dict(r) for r in self.q(
            "SELECT s.id, s.url, s.title, s.category, s.server, s.status, s.first_seen, s.last_scan, s.lang, "
            "       COUNT(p.id) AS post_count "
            "FROM sites s LEFT JOIN posts p ON p.site_id = s.id "
            "GROUP BY s.id ORDER BY s.last_scan DESC, s.id DESC")]
        digests = {}
        for r in self.q("SELECT site_id, body FROM posts ORDER BY site_id, id DESC"):
            sid, body = r["site_id"], (r["body"] or "")
            if sid not in digests:
                digests[sid] = []
            if len(digests[sid]) < 8:
                digests[sid].append(body)
        for r in rows:
            r["digest"] = " ".join(digests.get(r["id"], []))[:4000]
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
        """Additive schema migrations so existing stores keep working after new
        columns land. Idempotent on both SQLite (PRAGMA) and Postgres
        (information_schema); never drops or rewrites data."""
        backend = getattr(self, "backend", "sqlite")

        def cols_for(table):
            try:
                if backend == "postgres":
                    return [r["column_name"] for r in self.q(
                        "SELECT column_name FROM information_schema.columns WHERE table_name=?",
                        (table,))]
                return [r["name"] for r in self.q(f"PRAGMA table_info({table})")]
            except Exception:
                return []

        def ensure(table, col, ddl):
            if col in cols_for(table):
                return
            try:
                self.exe(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
            except Exception:
                # a failed ALTER (e.g. aborted transaction) must not poison the
                # connection for the remaining migrations
                try:
                    self.conn.rollback()
                except Exception:
                    pass  # cleared next boot if the ALTER truly never landed

        ensure("sites", "lang", "TEXT")
        ensure("sites", "cert_sans", "TEXT")
        ensure("sites", "tls_issuer", "TEXT")
        ensure("sites", "cert_fp", "TEXT")
        ensure("identifiers", "source_id", "INTEGER")
        ensure("identifiers", "content_hash", "TEXT")
        ensure("identifiers", "method", "TEXT")
        ensure("findings", "source_id", "INTEGER")
        ensure("findings", "content_hash", "TEXT")
        ensure("findings", "evidence", "TEXT")
        ensure("links", "source_id", "INTEGER")
        ensure("links", "content_hash", "TEXT")
        ensure("observations", "source_id", "INTEGER")
        ensure("observations", "site_id", "INTEGER")

    def _now(self):
        import datetime
        return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


class SQLiteDB(BaseDB):
    def __init__(self, path=DB_PATH):
        self.path = path
        self.backend = "sqlite"
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
        self.backend = "postgres"
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