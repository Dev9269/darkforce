from collections import defaultdict


class UnionFind:
    def __init__(self):
        self.p = {}

    def find(self, x):
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[ra] = rb


KIND_W = {"pgp": 0.98, "pgp_email": 0.9, "btc": 0.95, "xmr": 0.95,
          "email": 0.9, "jabber": 0.85, "telegram": 0.75, "onion": 0.85,
          "icq": 0.8}


def _sites_by_handle(db, handle):
    r = db.one("SELECT s.category cat FROM handles h JOIN sites s ON s.id=h.site_id WHERE h.handle=?",
               (handle,))
    return r["cat"] if r else "unknown"


def rebuild_actors(db, stylo_pairs=None, stylo_threshold=0.7, dry=False):
    """Merge handles sharing identifiers / content / style into one actor each."""
    uf = UnionFind()

    # existing link keys, so repeated merges don't re-insert the same edges
    existing_links = {(r["src_type"], r["src_value"], r["tgt_type"], r["tgt_value"], r["edge"])
                      for r in db.q("SELECT src_type, src_value, tgt_type, tgt_value, edge FROM links")}

    def link_once(src, tgt, edge, conf, evidence):
        key = ("handle", src, "handle", tgt, edge)
        if key not in existing_links:
            existing_links.add(key)
            db.add_link(*key, conf, evidence)

    ident_rows = db.q("SELECT kind, value, handle, detail, actor_id FROM identifiers")
    by_value = defaultdict(list)
    for r in ident_rows:
        by_value[(r["kind"], r["value"])].append(r["handle"])
    for (kind, value), handles in by_value.items():
        if len(handles) > 1:
            for h in handles[1:]:
                uf.union(handles[0], h)
            ev = next((r["detail"] for r in ident_rows if r["kind"] == kind and r["value"] == value), "")
            for h in handles[1:]:
                link_once(handles[0], h, f"shares_{kind}", KIND_W.get(kind, 0.5),
                          f"Common {kind} {value[:20]}" + (f" ({ev})" if ev else ""))

    # identical content reused across handles (stolen boilerplate/listing reuse)
    posts = db.q("SELECT handle, content_hash FROM posts WHERE content_hash IS NOT NULL")
    by_ch = defaultdict(set)
    for p in posts:
        by_ch[p["content_hash"]].add(p["handle"])
    for ch, handles in by_ch.items():
        hs = list(handles)
        if len(hs) > 1:
            for h in hs[1:]:
                uf.union(hs[0], h)
            for h in hs[1:]:
                link_once(hs[0], h, "same_content", 0.7, "Identical content/paste reused")

    # stylometry linkage
    for (a, b, score) in (stylo_pairs or []):
        if score >= stylo_threshold:
            uf.union(a, b)
            w = 0.6 + 0.3 * (score - stylo_threshold) / (1 - stylo_threshold + 1e-9)
            link_once(a, b, "stylo_match", min(w, 0.9), f"Stylometric similarity {score:.0%}")

    handles_all = db.q("SELECT id, actor_id, handle FROM handles")
    handle_actors = {}
    for h in handles_all:
        handle_actors[h["handle"]] = h["actor_id"]
    handle_existing_actor = handle_actors.copy()

    root_handles = set(uf.find(h["handle"]) for h in handles_all)
    members_by_root = defaultdict(list)
    for h in handles_all:
        members_by_root[uf.find(h["handle"])].append(h)
    new_actors = {}
    for root, ms in members_by_root.items():
        root_meta = next((h for h in ms if h["handle"] == root), ms[0])
        existing = root_meta["actor_id"]
        if not existing:
            existing = next((m["actor_id"] for m in ms if m["actor_id"]), None)
        if not existing:
            canon = min(m["handle"] for m in ms)
            n_roots = sum(1 for h in handles_all if h["actor_id"] and uf.find(h["handle"]) == root)
            risk = "merged" if len(ms) > 1 else "open"
            existing = db.upsert_actor(canon, category=_sites_by_handle(db, root), risk=risk)
        new_actors[root] = existing

    actor_by_handle = {h["handle"]: new_actors[uf.find(h["handle"])] for h in handles_all}

    changes = 0
    for h in handles_all:
        new_aid = actor_by_handle[h["handle"]]
        if h["actor_id"] != new_aid:
            db.exe("UPDATE handles SET actor_id=? WHERE id=?", (new_aid, h["id"]))
            db.exe("UPDATE identifiers SET actor_id=?, handle=? WHERE handle=?",
                   (new_aid, h["handle"], h["handle"]))
            changes += 1
    db.conn.commit()

    # refresh actor metadata
    for aid in set(actor_by_handle.values()):
        _refresh_actor(db, aid)

    # finalize: canonical name = earliest-joined persona; drop orphans; mark aliases
    from collections import defaultdict as _dd

    grp = _dd(list)
    for h in db.q("SELECT id, handle, actor_id, joined, first_seen FROM handles"):
        grp[h["actor_id"]].append(h)
    renames = []
    for aid, ms in grp.items():
        h0 = min(ms, key=lambda x: (x["joined"] or "9999", x["first_seen"] or ""))
        a = db.one("SELECT * FROM actors WHERE id=?", (aid,))
        if a and a["canon"] != h0["handle"]:
            renames.append((aid, h0["handle"], h0["first_seen"] or a["first_seen"]))
    orphans = [r["id"] for r in db.q(
        "SELECT a.id FROM actors a LEFT JOIN handles h ON h.actor_id=a.id GROUP BY a.id HAVING COUNT(h.id)=0")]
    ids_keep = {aid for aid, _, _ in renames}
    orphans = [oid for oid in orphans if oid not in ids_keep]
    for oid in orphans:
        db.exe("DELETE FROM actors WHERE id=?", (oid,))
    for aid, canon, fseen in renames:
        db.exe("UPDATE actors SET canon=?, risk=?, first_seen=? WHERE id=?", (canon, "merged_alias", fseen, aid))
    db.conn.commit()
    return {"groups": len(root_handles), "handled": len(handles_all), "reassigned": changes,
            "orphans_removed": len(orphans)}


def _refresh_actor(db, aid):
    a = db.one("SELECT * FROM actors WHERE id=?", (aid,))
    if not a:
        return
    hs = db.handles_for_actor(aid)
    if not hs:
        return
    cats = [h.get("category") for h in hs if h.get("category")]
    cat = max(set(cats), key=cats.count) if cats else a["category"]
    ids = db.identifiers_for_actor(aid)
    idkinds = len(ids)
    n_handles = len(hs)
    conf = 0.6 + 0.06 * min(n_handles, 5) + 0.05 * min(idkinds, 4)
    conf = min(conf, 0.97)
    db.exe("UPDATE actors SET category=?, confidence=?, last_seen=? WHERE id=?",
           (cat, conf, a["last_seen"], aid))