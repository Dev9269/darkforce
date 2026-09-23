"""Export the active Postgres dataset into a standalone SQLite file.

Intended to produce the self-contained data/darkforce.db used by the portable
USB launcher (which runs in SQLite mode when DATABASE_URL is unset).

Usage (from project root, while the local PG is running):
    python tools/export_pg_to_sqlite.py D:\\darkforce\\data\\darkforce.db
"""
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ["DATABASE_URL"] = "postgresql://darkforce@127.0.0.1:5433/darkforce"

from darkforce import db as dbm

TABLES = [
    "sources", "sites", "actors", "handles", "posts", "identifiers",
    "findings", "links", "watchlists", "alerts", "collector_health",
    "users", "audit_log", "observations", "link_evidence", "sources_trust",
    "attribution", "wallets", "breaches", "cases", "case_members",
]


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(dbm.DATA_DIR, "darkforce.db")
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)

    if os.path.exists(target):
        os.remove(target)

    src = dbm.PostgresDB()
    dst_db = dbm.SQLiteDB(target)
    dst = dst_db.conn
    dst.execute("PRAGMA journal_mode=OFF")
    dst.execute("PRAGMA synchronous=OFF")

    counts = {}
    for table in TABLES:
        rows = src.q(f"SELECT * FROM {table}")
        if not rows:
            dst.commit()
            counts[table] = 0
            continue
        sqlite_cols = {r["name"] for r in dst.execute(f"PRAGMA table_info({table})")}
        cols = [c for c in rows[0].keys() if c in sqlite_cols]
        placeholders = ",".join(["?"] * len(cols))
        dst.executemany(
            f"INSERT INTO {table} ({','.join(cols)}) VALUES ({placeholders})",
            [tuple(r[c] for c in cols) for r in rows],
        )
        dst.commit()
        counts[table] = len(rows)

    for table, n in counts.items():
        print(f"{table:16s} {n:>6d}")
    print("wrote", target, f"{os.path.getsize(target) / 1e6:.1f} MB")


if __name__ == "__main__":
    main()