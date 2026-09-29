from collections import defaultdict
import re

from .extract import is_mergeable_identifier

# Weights reflect how strongly sharing an identifier implies a single human.
# These are the single source of truth for the attribution rubric: the README
# table is generated from this dict, so the docs cannot drift from the code.
KIND_W = {"pgp": 0.98, "pgp_email": 0.9, "btc": 0.95, "xmr": 0.95,
          "email": 0.9, "jabber": 0.85, "telegram": 0.75, "onion": 0.85,
          "icq": 0.8, "handle": 0.5, "username": 0.5, "stealer": 0.9,
          "domain": 0.7, "ssh_fp": 0.9, "cert_fp": 0.9}

# A union is only permitted at or above this weight. Anything weaker may still
# be *recorded* as a link (it is evidence), but it must never collapse two
# personas on its own. Set from KIND_W deliberately: telegram (0.75) and
# handle/username (0.5) are below the line precisely because a shared handle
# is ambiguous -- the same vendor name, a support bot, a quoted third party.
MIN_MERGE_CONF = 0.8

# Two independent sub-threshold signals may still justify a merge, because
# corroboration is what distinguishes a real person from a coincidence.
CORROBORATING_THRESHOLD = 0.6
MIN_CORROBORATED_SIGNALS = 2

# Hard ceiling on a single actor cluster. Union-find is transitive, so one
# over-shared identifier can otherwise absorb an entire corpus into one node.
MAX_CLUSTER = 40

# Stylometry is corroborating evidence only. STYLO_MAX sits just under
# MIN_MERGE_CONF by design: a perfect stylistic match still cannot merge two
# personas on its own, because authors who share a template, a translator or a
# vocabulary are routinely near-identical on style alone.
STYLO_W = 0.60
STYLO_MAX = 0.79

# Edge kinds that never justify a merge on their own.
NON_MERGING_EDGES = {"leaked_in", "controls", "mentions", "co_occurs"}


def purge_implausible_handles(db):
    """Delete handle rows that are page furniture rather than identities.

    The crawler's author selectors also match member counts, post numbers and
    ratings. Production data ended up with 1804 handle rows spanning only 396
    distinct strings, the most common being '42', '176' and '182' -- each one a
    spurious actor. Also drops the now-orphaned identifiers and posts.
    """
    from .extract import is_plausible_site_handle

    bad = [r["id"] for r in db.q("SELECT id, handle FROM handles")
           if not is_plausible_site_handle(r["handle"])]
    for hid in bad:
        db.exe("DELETE FROM handles WHERE id=?", (hid,))
    db.exe("DELETE FROM identifiers WHERE handle NOT IN (SELECT handle FROM handles WHERE handle IS NOT NULL)")
    db.exe("DELETE FROM posts WHERE handle NOT IN (SELECT handle FROM handles WHERE handle IS NOT NULL)")
    db.commit()
    return len(bad)


def rederive_handle_provenance(db):
    """Re-establish provenance for @-handles stored before the prose filter.

    Identifier rows carry no stored page text, but `posts` does. For each
    unverified @-handle we check whether the token actually appears as a
    mention in prose authored by that handle; if it does we promote the row to
    TELEGRAM_PROSE, otherwise it stays untrusted. Improvable identifiers are
    deleted outright -- they were page-source artifacts and only ever produced
    false merges.

    Returns counts so the caller can report what changed.
    """
    from .extract import TELEGRAM_MARKUP, TELEGRAM_PROSE, is_plausible_handle

    bodies = defaultdict(str)
    for r in db.q("SELECT handle, body FROM posts WHERE handle IS NOT NULL AND body IS NOT NULL"):
        bodies[r["handle"]] += " " + r["body"]

    promoted = rejected = 0
    rows = db.q("SELECT id, handle, value, method FROM identifiers "
                "WHERE kind IN ('telegram','handle','username')")
    for r in rows:
        val = r["value"]
        if not is_plausible_handle(val):
            db.exe("DELETE FROM identifiers WHERE id=?", (r["id"],))
            rejected += 1
            continue
        if r["method"] == TELEGRAM_PROSE:
            continue
        body = bodies.get(r["handle"] or "", "")
        # A prose mention looks like @token with a non-word boundary after it.
        if re.search(r"@" + re.escape(val) + r"(?![A-Za-z0-9_])", body):
            db.exe("UPDATE identifiers SET method=? WHERE id=?", (TELEGRAM_PROSE, r["id"]))
            promoted += 1
        elif r["method"] != TELEGRAM_MARKUP:
            db.exe("UPDATE identifiers SET method=? WHERE id=?", (TELEGRAM_MARKUP, r["id"]))
    db.commit()
    return {"promoted_to_prose": promoted, "rejected_implausible": rejected,
            "handles_with_text": len(bodies)}


def confidence_band(conf):
    """Map a confidence onto the documented rubric band (kept in step with the README)."""
    if conf >= 0.9:
        return "critical"
    if conf >= 0.7:
        return "high"
    if conf >= 0.5:
        return "medium"
    return "low"


class UnionFind:
    """Union-find that tracks component size so a cluster ceiling can be enforced.

    Plain union-find is why the production graph collapsed: it merges
    transitively with no regard for how weak the connecting evidence was, so a
    single over-shared identifier could absorb the whole corpus.
    """

    def __init__(self):
        self.p = {}
        self.size = {}

    def add(self, x):
        self.p.setdefault(x, x)
        self.size.setdefault(x, 1)

    def find(self, x):
        self.add(x)
        root = x
        while self.p[root] != root:
            root = self.p[root]
        while self.p[x] != root:  # path compression
            self.p[x], x = root, self.p[x]
        return root

    def union(self, a, b, max_size=None):
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return False
        if max_size is not None and (self.size[ra] + self.size[rb]) > max_size:
            return False
        # keep the larger component as the root for stable output
        if self.size[ra] < self.size[rb]:
            ra, rb = rb, ra
        self.p[rb] = ra
        self.size[ra] += self.size[rb]
        return True

    def component_size(self, x):
        return self.size[self.find(x)]


def _sites_by_handle(db, handle):
    r = db.one("SELECT s.category cat FROM handles h JOIN sites s ON s.id=h.site_id WHERE h.handle=?",
               (handle,))
    return r["cat"] if r else "unknown"


def _collect_candidates(db, stylo_pairs=None, stylo_threshold=0.7):
    """Gather every (handle, handle) merge candidate with its evidence.

    Nothing is merged here. This deliberately over-collects: the `links` table
    is the evidence trail and should keep the weak edges too, because an analyst
    needs to see that two personas were *considered* and rejected, not silently
    never considered. Deciding what actually collapses an actor is _apply_merges.
    """
    ident_rows = db.q("SELECT kind, value, handle, detail, method FROM identifiers")
    by_value = defaultdict(list)
    for r in ident_rows:
        # Blank values are not identity claims. Rows written before add_identifier
        # learned to reject them must not be allowed to merge actors either.
        if r["value"] is None or not str(r["value"]).strip():
            continue
        by_value[(r["kind"], r["value"])].append(r)

    candidates = []
    skipped_unmergeable = 0
    for (kind, value), rows in by_value.items():
        if kind in NON_MERGING_EDGES:
            continue
        weight = KIND_W.get(kind, 0.5)
        # Identifiers that cannot speak to identity (CSS/JS @-tokens, markup-only
        # mentions) are kept in the table for search but never reach a merge.
        usable = [r for r in rows if is_mergeable_identifier(kind, value, r["method"] or "")]
        skipped_unmergeable += len(rows) - len(usable)
        if len(usable) < 2:
            continue
        handles = sorted({r["handle"] for r in usable if r["handle"]})
        if len(handles) < 2:
            continue
        ev = next((r["detail"] for r in usable if r["detail"]), "")
        evidence = f"Common {kind} {value[:20]}" + (f" ({ev})" if ev else "")
        hub = handles[0]
        for h in handles[1:]:
            candidates.append({"a": hub, "b": h, "conf": weight,
                               "edge": f"shares_{kind}", "evidence": evidence})

    # identical content reused across handles (stolen boilerplate/listing reuse)
    posts = db.q("SELECT handle, content_hash FROM posts WHERE content_hash IS NOT NULL")
    by_ch = defaultdict(set)
    for p in posts:
        by_ch[p["content_hash"]].add(p["handle"])
    for ch, handles in by_ch.items():
        hs = sorted(h for h in handles if h)
        for h in hs[1:]:
            candidates.append({"a": hs[0], "b": h, "conf": 0.7,
                               "edge": "same_content",
                               "evidence": "Identical content/paste reused"})

    # Stylometry. A stylistic resemblance is never sufficient on its own -- it is
    # corroborating evidence. stylo.match_all has already withheld pairs that
    # failed its permutation and split-half gates, so anything arriving here is a
    # significant resemblance; the weight still tops out below MIN_MERGE_CONF so
    # the generic merge rules continue to demand a second, independent signal.
    # This mirrors the rubric: 0.7-0.9 requires a high cosine *plus* shared
    # tokens, never a high cosine alone.
    for rec in (stylo_pairs or []):
        if isinstance(rec, dict):
            a, b = rec.get("a"), rec.get("b")
            score = float(rec.get("score") or 0.0)
            significant = bool(rec.get("significant"))
        else:  # legacy (a, b, score) tuples
            a, b, score = rec
            significant = True
        if not a or not b or not significant or score < stylo_threshold:
            continue
        span = (1 - stylo_threshold) or 1.0
        w = STYLO_W + (1.0 - STYLO_W) * (score - stylo_threshold) / span
        candidates.append({"a": a, "b": b, "conf": min(w, STYLO_MAX),
                           "edge": "stylo_match",
                           "evidence": f"Stylometric similarity {score:.0%}"})
    return candidates, skipped_unmergeable


def _apply_merges(candidates, max_size=MAX_CLUSTER, min_signals=MIN_CORROBORATED_SIGNALS):
    """Decide which candidates actually collapse an actor.

    Pass 1: any single edge at or above MIN_MERGE_CONF.
    Pass 2: a sub-threshold pair merges only when the two handles *directly*
    share at least `min_signals` different kinds of identifier, each above
    CORROBORATING_THRESHOLD. Corroboration is deliberately non-transitive: two
    personas who each share one weak signal with a third party are not thereby
    the same person. Counting direct shared kinds is also what stops one
    over-shared identifier from dragging in a whole neighbourhood, because a
    long chain of the same signal yields one kind and never corroborates.

    Ordered strongest-first so the ceiling, when it binds, truncates the weakest
    relationships rather than an arbitrary set.
    """
    uf = UnionFind()
    # Direct evidence between a specific pair, by unordered key.
    pair_kinds = defaultdict(set)
    for c in candidates:
        uf.add(c["a"])
        uf.add(c["b"])
        if c["conf"] >= CORROBORATING_THRESHOLD and c["edge"] not in NON_MERGING_EDGES:
            pair_kinds[frozenset((c["a"], c["b"]))].add(c["edge"])

    ordered = sorted(candidates, key=lambda c: -c["conf"])

    merged = []
    for c in ordered:
        if c["edge"] in NON_MERGING_EDGES or c["conf"] < MIN_MERGE_CONF:
            continue
        if uf.union(c["a"], c["b"], max_size=max_size):
            merged.append(c)

    for c in ordered:
        if c["conf"] < CORROBORATING_THRESHOLD or c["conf"] >= MIN_MERGE_CONF:
            continue
        if c["edge"] in NON_MERGING_EDGES:
            continue
        if uf.find(c["a"]) == uf.find(c["b"]):
            continue
        kinds = pair_kinds.get(frozenset((c["a"], c["b"])), set())
        if len(kinds) >= min_signals and uf.union(c["a"], c["b"], max_size=max_size):
            merged.append(c)
    return uf, merged


def rebuild_actors(db, stylo_pairs=None, stylo_threshold=0.7, dry=False,
                   reset=False, max_size=MAX_CLUSTER):
    """Merge handles sharing identifiers / content / style into one actor each.

    reset=True first clears all prior actor assignment and link evidence so a
    changed merge policy can be re-derived from scratch without a re-crawl.
    """
    if reset:
        db.exe("UPDATE handles SET actor_id=NULL")
        db.exe("UPDATE identifiers SET actor_id=NULL")
        db.exe("DELETE FROM links")
        db.exe("DELETE FROM link_evidence")
        db.exe("DELETE FROM actors")
        db.commit()

    candidates, skipped_unmergeable = _collect_candidates(
        db, stylo_pairs=stylo_pairs, stylo_threshold=stylo_threshold)
    if dry:
        return {"candidates": len(candidates), "skipped_unmergeable": skipped_unmergeable}

    uf, merged = _apply_merges(candidates, max_size=max_size)

    # Record every candidate as evidence, including the ones we declined to
    # merge on. The edge table is the audit trail, not just the answer.
    existing_links = {(r["src_type"], r["src_value"], r["tgt_type"], r["tgt_value"], r["edge"])
                      for r in db.q("SELECT src_type, src_value, tgt_type, tgt_value, edge FROM links")}

    def link_once(src, tgt, edge, conf, evidence):
        key = ("handle", src, "handle", tgt, edge)
        if key not in existing_links:
            existing_links.add(key)
            db.add_link(*key, conf, evidence)

    for c in candidates:
        link_once(c["a"], c["b"], c["edge"], c["conf"], c["evidence"])

    handles_all = db.q("SELECT id, actor_id, handle FROM handles")

    root_handles = {uf.find(h["handle"]) for h in handles_all}
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
    db.commit()

    # refresh actor metadata
    for aid in set(actor_by_handle.values()):
        _refresh_actor(db, aid, merged)

    # finalize: canonical name = earliest-joined persona; drop orphans; mark aliases
    grp = defaultdict(list)
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
        db.exe("UPDATE actors SET canon=?, risk=?, first_seen=? WHERE id=?",
               (canon, "merged_alias", fseen, aid))
    db.commit()

    sizes = sorted((uf.component_size(h["handle"]) for h in handles_all), reverse=True)
    return {"groups": len(root_handles), "handled": len(handles_all), "reassigned": changes,
            "orphans_removed": len(orphins) if False else len(orphans),
            "candidates": len(candidates), "merged": len(merged),
            "skipped_unmergeable": skipped_unmergeable,
            "largest_cluster": sizes[0] if sizes else 0,
            "clusters_over_cap": sum(1 for s in sizes if s > max_size),
            "capped_at": max_size}


def actor_confidence(db, actor_id, merged=None):
    """Confidence that the personas in one actor really are one person.

    Derived from the evidence that actually justifies the merge, not from a
    count of rows. The previous formula was 0.6 + 0.06*handles + 0.05*kinds,
    which scored a merge justified by a shared @media token identically to one
    justified by a reused PGP key -- directly contradicting the published
    rubric, and the reason 90 of 105 actors sat at a flat 0.66.
    """
    member_handles = {r["handle"] for r in db.q(
        "SELECT handle FROM handles WHERE actor_id=?", (actor_id,))}
    if merged:
        inside = [c for c in merged
                  if c["a"] in member_handles and c["b"] in member_handles]
        if inside:
            best = max(c["conf"] for c in inside)
            # Corroboration: how many distinct signal kinds support this cluster.
            distinct = {c["edge"] for c in inside}
            return min(round(best + 0.02 * (len(distinct) - 1), 4), 0.99)

    edges = db.q(
        "SELECT edge, MAX(confidence) c FROM links WHERE "
        "(src_type='handle' AND src_value IN (SELECT handle FROM handles WHERE actor_id=?)) "
        "OR (tgt_type='handle' AND tgt_value IN (SELECT handle FROM handles WHERE actor_id=?)) "
        "GROUP BY edge", (actor_id, actor_id))
    usable = [r["c"] for r in edges if r["edge"] not in NON_MERGING_EDGES]
    if not usable:
        # No cross-identity evidence at all. Report a floor rather than 0.0 so
        # the dashboard can distinguish "we found nothing" from "no such actor";
        # 0.2 sits in the rubric's <0.5 band, i.e. explicitly not an attribution.
        return 0.2
    return min(round(max(usable) + 0.02 * (len(usable) - 1), 4), 0.99)


def _refresh_actor(db, aid, merged=None):
    a = db.one("SELECT * FROM actors WHERE id=?", (aid,))
    if not a:
        return
    hs = db.handles_for_actor(aid)
    if not hs:
        return
    cats = [h.get("category") for h in hs if h.get("category")]
    cat = max(set(cats), key=cats.count) if cats else a["category"]
    conf = actor_confidence(db, aid, merged)
    db.exe("UPDATE actors SET category=?, confidence=?, last_seen=? WHERE id=?",
           (cat, conf, a["last_seen"], aid))