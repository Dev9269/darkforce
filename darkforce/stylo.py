import math
import re
from collections import Counter

from .extract import bucket_handles

NGRAMS = (4, 5, 6)


def _grams(text):
    t = re.sub(r"[\s\W_]+", " ", text).lower()
    g = Counter()
    for n in NGRAMS:
        for i in range(len(t) - n + 1):
            g[t[i : i + n]] += 1
    return g


def profile(texts):
    c = Counter()
    for t in texts or []:
        c.update(_grams(t))
    n = math.sqrt(sum(v * v for v in c.values())) or 1
    return {k: v / n for k, v in c.items()}


def cosine(a, b):
    if len(a) < 20 or len(b) < 20:
        return 0.0
    inter = set(a) & set(b)
    dot = sum(a[k] * b[k] for k in inter)
    na = math.sqrt(sum(v * v for v in a.values())) or 1
    nb = math.sqrt(sum(v * v for v in b.values())) or 1
    return dot / (na * nb)


def explain(a, b, k=5):
    keys = sorted(set(a) | set(b), key=lambda g: abs(a.get(g, 0) - b.get(g, 0)), reverse=True)[:k]
    return [{"feature": g, "in_a": round(a.get(g, 0), 4), "in_b": round(b.get(g, 0), 4)} for g in keys]


def corpus_by_handle(db, min_posts=8):
    hs = db.q("SELECT handle, COUNT(*) c FROM posts GROUP BY handle HAVING c>=?", (min_posts,))
    res = {}
    for r in hs:
        posts = db.posts_for_handle(r["handle"])
        res[r["handle"]] = " ".join((p["title"] or "") + " " + (p["body"] or "") for p in posts)
    return res


def match_all(db, min_posts=8, top=10):
    """Return {handle: profile} and all pairwise {a,b,score} and per-handle matches."""
    corpus = corpus_by_handle(db, min_posts)
    prof = {h: profile([corpus[h]]) for h in corpus}
    pairs, per = [], {}
    hs = list(prof)
    for i in range(len(hs)):
        per[hs[i]] = []
        for j in range(i + 1, len(hs)):
            s = cosine(prof[hs[i]], prof[hs[j]])
            if s > 0.5:
                pairs.append((hs[i], hs[j], round(s, 4)))
    for a in hs:
        matches = [(b, cosine(prof[a], prof[b])) for b in hs if b != a]
        matches = [m for m in matches if m[1] > 0.5]
        matches.sort(key=lambda m: -m[1])
        per[a] = [{"handle": b, "score": round(s, 4),
                   "evidence": explain(prof[a], prof[b])} for b, s in matches[:top]]
    return prof, pairs, per


def match_handle(db, handle, top=10, min_posts=8):
    prof, pairs, per = match_all(db, min_posts, top)
    return per.get(handle, [])