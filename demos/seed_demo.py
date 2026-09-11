import sys
import os
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from darkforce.db import DB, iso, utcnow
from darkforce import detect, extract, link, stylo
from darkforce.detect import Snap

PKEY_ALPHA = ("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
              "mQINBGVendor1MAAAAFQKAKsBWtWf0/McTBjJ1YjBYe3mQumHh+jBofNlqYvA2cX\n"
              "=shadow\n-----END PGP PUBLIC KEY BLOCK-----")
PKEY_GHOST = ("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"
              "mQINBGVendor2NAAAAFQKAKsBWtWfKKraZVy0ZtsxCTMkFhjxQumHh+jctIUSp9qv\n"
              "=ghost\n-----END PGP PUBLIC KEY BLOCK-----")

BTC_SHARED = "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
BTC_GHOST = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
XMR_GHOST = "8Bsz7X4myiTW8j2ohTyQfS1RZJYAV6xKqhZfPkUzKpZod7CwJxzsZ1nQh3JzB7VjRqB2Mx4uYbQaR6wSmN8qKXp0vM9jTz2wRkYbPqXfD8R2yNmR4kVgHm6CcY"
JB = "shadow_official@jabber.exploit"
EMAIL_MULE = "quietmule@protonmail.com"
JABBER_LINE = f"Jabber for orders: {JB}"

ALPHANEX = "http://alphanex6x2k7hzvab4evqudqnixx.onion"
DARKMART = "http://darkmartkp2vaa4q7tf4gnj7om5n3ca.onion"
CRYPTOBR = "http://cryptobridge7y3p6lsu3tzpxd2mt7we3qq.onion"
DREAD = "dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion"
SECONDARY = "http://shadowcust5xyz7plbm2a4dmu3qpwku2f.onion"
CLEARNET = "https://corporate-dev.example.com"
STATUSPAGE = ALPHANEX + "/server-status"

CLR_HTML = ("<html><head><title>Corporate Dev Portal - CM inventory</title></head>"
            "<body><h1>ACME Cloud Services dev environment</h1><p>Service mesh: k8s-prod-02</p>"
            "</body></html>")
CLR_FAV = b"\x89PNG\r\n\x1a\nclearnet-favicon-bytes"
STATUS_HTML = ("<html><body><h1>Apache Server Status</h1>"
               "<pre>Server uptime: 102 days\nHOST 10.10.0.5  backend-web-01\nHOST 10.10.0.12  db-internal\n"
               "Slaves: 127.0.0.1</pre></body></html>")


def sha(s):
    import hashlib

    if isinstance(s, bytes):
        return hashlib.sha1(s).hexdigest()
    return hashlib.sha1(s.encode("utf-8")).hexdigest()


SHARED_POOL = [
    "full escrow as always, no FE anything, that is how I have always operated, go check my history",
    "stealth pack included with every order, guaranteed across EU, discreet and solid",
    "OPSEC reminder brothers, never reuse passwords, always rotate your PGP, I have been here for years",
    "new batch in, quality is off the charts, the reviews tell you everything you need to know",
    "orders ship every day, next resupply Friday, escrow only, stay safe out there",
]

STYLES = {
    "Shad0wVendor": {
        "head": "Yo fam, it is your guy again. ",
        "tail": "Respect to all the regulars. Stay safe.",
    },
    "Cyph3rKing": {
        "head": "Yo crew, the King is back. ",
        "tail": "Respect to everyone who knows. Stay sharp.",
    },
    "GhostRunner": {
        "parts": [
            "Units available. Discrete shipping. No questions. Do not contact market support.",
            "Inventory: 500g. Escrow via multisig only. Refunds on reship per policy.",
            "Ops note: schedules shifted. Orders pack within 4h. Coordinate via key.",
            "Stock fast-moving. Re-up Fri. Established, trusted, low profile.",
        ],
        "title_pat": "[{i}] inventory update - bulk lots - trusted seller",
    },
    "QuietMule": {
        "parts": [
            "Hello, I buy in bulk for reselling. Looking for stable long term contact, no single-use alts.",
            "Please DM, I want references before dealing. Serious buyers only.",
            "Testing the waters here, heard good things about this forum.",
        ],
        "title_pat": "bulk buyer inquiry #{i}",
    },
}


def _mkposts(handle, n, site_id, url_base, start_day):
    st = STYLES[handle]
    posts = []
    if "head" in st:
        pool = SHARED_POOL
    else:
        pool = None
    for i in range(n):
        if pool is not None:
            body = st["head"] + pool[i % len(pool)] + " " + st["tail"]
            title = f"{i+1}% OFF + restock - verified vendor (escrow)"
        else:
            body = st["parts"][i % len(st["parts"])]
            title = st["title_pat"].format(i=i + 1)
        if handle in ("Shad0wVendor", "Cyph3rKing") and i == 0:
            body += f"\nPGP verify anytime: {handle}_key. BTC: {BTC_SHARED}"
        ts = iso(datetime.now(timezone.utc) - timedelta(days=start_day - i))
        url = f"{url_base}/post/{i}" if url_base.startswith("http") else f"{url_base}/{i}"
        posts.append({"handle": handle, "site_id": site_id, "url": url,
                      "title": title, "body": body, "ts": ts})
    return posts


def ingest(db):
    for t in ("sites", "actors", "handles", "posts", "identifiers", "findings", "links"):
        db.exe(f"DELETE FROM {t}")
    db.conn.commit()

    # seed market/forum sites
    def site(url, title, cat, **kw):
        return db.upsert_site(url, title=title, category=cat, **kw)

    sid_an = site(ALPHANEX, "AlphaNex Market - electronics, dumps", "market", server="nginx/1.18.0 (Ubuntu)")
    sid_dm = site(DARKMART, "DarkMart - vendor marketplace", "market", server="nginx/1.18.0 (Ubuntu)")
    sid_cb = site(CRYPTOBR, "Cryptobridge - multisig market", "market", server="Apache/2.4.41 (Debian)")
    sid_dr = site("http://" + DREAD, "Dread - darknet forum", "forum", server="nginx/1.18.0 (Ubuntu)")
    sid_cl = site(CLEARNET, "Corporate Dev Portal (ACME Cloud Services)", "clearnet", server="Apache/2.4.41 (Debian)")
    sid_ss = site(STATUSPAGE, "AlphaNex hidden status page", "market")
    sid_2nd = site(SECONDARY, "ShadowVendor customer vault", "market")

    # clearnet fingerprint index for mirror/favicon matching
    clr_hash = sha(CLR_HTML)
    clr_fav = sha(CLR_FAV)
    db.exe("UPDATE sites SET content_hash=?, favicon_hash=? WHERE id=?", (clr_hash, clr_fav, sid_cl))
    db.exe("UPDATE sites SET content_hash=?, favicon_hash=? WHERE id=?",
           (sha(STATUS_HTML), sha(STATUS_HTML), sid_ss))

    clr_index = {clr_fav: CLEARNET, clr_hash: CLEARNET}

    # ---- scan the misconfigured hidden status page (real scanner path) ----
    snap_ss = Snap(url=STATUSPAGE, html=STATUS_HTML, meta={"hostname": "alphanex6x2k7hzvab4evqudqnixx.onion"})
    findings, fp = detect.scan(snap_ss, clr_index)
    for kind, sev, detail, conf in findings:
        db.add_finding(sid_ss, kind, sev, detail, conf, STATUSPAGE)

    # ---- AlphaNex homepage shares the clearnet favicon+body (origin-server link) ----
    snap_an = Snap(url=ALPHANEX, headers={"Server": "nginx/1.18.0 (Ubuntu)"},
                   html=CLR_HTML.replace("Corporate Dev Portal", "AlphaNex Market is up"),
                   favicon=CLR_FAV, meta={"hostname": "alphanex6x2k7hzvab4evqudqnixx.onion"})
    f_an, fp_an = detect.scan(snap_an, clr_index)
    for kind, sev, detail, conf in f_an:
        db.add_finding(sid_an, kind, sev, detail, conf, ALPHANEX)
    # EAG: banner matches clearnet host
    db.add_finding(sid_an, "banner_match", "high",
                   "Server banner identical to clearnet host corporate-dev.example.com", 0.75)
    # TLS cert naming clearnet domain
    db.add_finding(sid_an, "tls_cert", "high",
                   "TLS cert CN=cert.dev-cloud.example.com (clearweb domain)", 0.8)

    # ---- actors / handles / identifiers / posts ----
    def vendor(handle, market_sid, market_url, role="vendor", trust="verified", joined="2019-04-12"):
        aid = db.upsert_actor(handle, category="vendor")
        db.upsert_handle(aid, handle, market_sid, market_url + "/vendor/" + handle, role, trust, joined)
        return aid

    posts_all = []
    # Shad0wVendor on AlphaNex
    aid_sv = vendor("Shad0wVendor", sid_an, ALPHANEX)
    posts_all += _mkposts("Shad0wVendor", 6, sid_an, ALPHANEX, start_day=120)
    # Cyph3rKing = rebrand, on DarkMart and Cryptobridge
    aid_ck = vendor("Cyph3rKing", sid_dm, DARKMART, trust="trusted", joined="2025-03-01")
    posts_all += _mkposts("Cyph3rKing", 5, sid_dm, DARKMART, start_day=40)
    db.upsert_handle(aid_ck, "Cyph3rKing", sid_cb, CRYPTOBR + "/vendor/Cyph3rKing", "vendor", "trusted", "2025-03-01")
    posts_all += _mkposts("Cyph3rKing", 3, sid_cb, CRYPTOBR, start_day=25)
    # GhostRunner on AlphaNex + Cryptobridge
    aid_gr = vendor("GhostRunner", sid_an, ALPHANEX, role="vendor", trust="trusted", joined="2021-08-30")
    posts_all += _mkposts("GhostRunner", 4, sid_an, ALPHANEX, start_day=200)
    db.upsert_handle(aid_gr, "GhostRunner", sid_cb, CRYPTOBR + "/vendor/GhostRunner", "vendor", "verified", "2021-08-30")
    posts_all += _mkposts("GhostRunner", 3, sid_cb, CRYPTOBR, start_day=180)
    # QuietMule on forum + Cryptobridge
    aid_qm = vendor("QuietMule", sid_dr, "http://" + DREAD, role="buyer", trust="new", joined="2026-01-15")
    posts_all += _mkposts("QuietMule", 3, sid_dr, "http://" + DREAD, start_day=60)
    db.upsert_handle(aid_qm, "QuietMule", sid_cb, CRYPTOBR + "/u/QuietMule", "buyer", "new", "2026-01-15")

    # identifiers (the planted linking evidence)
    idents = [
        (aid_sv, "Shad0wVendor", "pgp", extract.pgp_meta(PKEY_ALPHA)["fingerprint"], "shadow_official key"),
        (aid_sv, "Shad0wVendor", "pgp_email", "shadow_official@protonmail.com", "UID on PGP key"),
        (aid_sv, "Shad0wVendor", "btc", BTC_SHARED, "donations/withdrawals wallet"),
        (aid_sv, "Shad0wVendor", "jabber", JB, "order contact"),
        (aid_sv, "Shad0wVendor", "onion", SECONDARY, "customer vault service"),
        (aid_ck, "Cyph3rKing", "pgp", extract.pgp_meta(PKEY_ALPHA)["fingerprint"], "shadow_official key"),
        (aid_ck, "Cyph3rKing", "btc", BTC_SHARED, "donations/withdrawals wallet"),
        (aid_ck, "Cyph3rKing", "onion", SECONDARY, "customer vault service"),
        (aid_gr, "GhostRunner", "pgp", extract.pgp_meta(PKEY_GHOST)["fingerprint"], "GHOST-A key"),
        (aid_gr, "GhostRunner", "btc", BTC_GHOST, "withdrawals"),
        (aid_gr, "GhostRunner", "xmr", XMR_GHOST, "primary pay-in"),
        (aid_qm, "QuietMule", "email", EMAIL_MULE, "contact"),
        (aid_qm, "QuietMule", "telegram", "qm_bulk01", "bulk buyer channel"),
    ]
    for a, h, k, v, d in idents:
        db.add_identifier(a, h, k, v, d, None, "")

    # posts + auto-extraction of identifiers from text
    for p in posts_all:
        db.save_post(p["handle"], p["site_id"], p["url"], p["title"], p["body"], p["ts"])
    for p in posts_all:
        aid = db.one("SELECT actor_id FROM handles WHERE handle=?", (p["handle"],))
        if aid:
            for idt in extract.extract_identifiers(p["body"] + " " + p["title"]):
                db.add_identifier(aid["actor_id"], p["handle"], idt["kind"], idt["value"], idt["detail"])

    db.conn.commit()
    return {"clearnet_index": clr_index}


def run(db):
    props = ingest(db)
    prof, pairs, per = stylo.match_all(db, min_posts=3)
    res = link.rebuild_actors(db, stylo_pairs=pairs, stylo_threshold=0.55)
    return {"seeded": True, "graph": res, "stylo_pairs": len(pairs),
            "key_links": [dict(l) for l in db.q("SELECT DISTINCT edge FROM links")]}


if __name__ == "__main__":
    db = DB()
    print(run(db))
    print("Demo data ready:", db.stats())