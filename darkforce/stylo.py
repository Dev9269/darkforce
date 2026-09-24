import datetime
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


def _hours_of(ts_values):
    buckets = [0] * 24
    for t in ts_values or []:
        try:
            dt = datetime.datetime.fromisoformat(str(t).replace("Z", "+00:00"))
            buckets[dt.hour] += 1
        except (TypeError, ValueError):
            continue
    n = math.sqrt(sum(b * b for b in buckets)) or 1
    return {f"h{i}": b / n for i, b in enumerate(buckets)}


def _vocab_richness(text):
    tokens = re.findall(r"\w+", (text or "").lower())
    if len(tokens) < 5:
        return {}
    return {"vocab_ttr": min(1.0, len(set(tokens)) / float(len(tokens)))}


def profile(texts, hours=None):
    c = Counter()
    for t in texts or []:
        c.update(_grams(t))
    v = _vocab_richness(" ".join(texts or []))
    for k, val in v.items():
        c[k] += val
    if hours:
        c.update(_hours_of(hours))
    n = math.sqrt(sum(x * x for x in c.values())) or 1
    return {k: v / n for k, v in c.items()}


def cosine(a, b):
    if len(a) < 20 or len(b) < 20:
        return 0.0
    inter = set(a) & set(b)
    dot = sum(a[k] * b[k] for k in inter)
    na = math.sqrt(sum(v * v for v in a.values())) or 1
    nb = math.sqrt(sum(v * v for v in b.values())) or 1
    return max(0.0, min(1.0, dot / (na * nb)))


def explain(a, b, k=5):
    keys = sorted(set(a) | set(b), key=lambda g: abs(a.get(g, 0) - b.get(g, 0)), reverse=True)[:k]
    return [{"feature": g, "in_a": round(a.get(g, 0), 4), "in_b": round(b.get(g, 0), 4)} for g in keys]


def corpus_by_handle(db, min_posts=8):
    hs = db.q("SELECT handle, COUNT(*) c FROM posts GROUP BY handle HAVING COUNT(*)>=?", (min_posts,))
    res = {}
    for r in hs:
        posts = db.posts_for_handle(r["handle"])
        hours = [p.get("ts") for p in posts]
        text = " ".join((p["title"] or "") + " " + (p["body"] or "") for p in posts)
        langs = {p.get("lang") for p in posts if p.get("lang")}
        res[r["handle"]] = {"text": text, "hours": hours, "langs": langs,
                            "n": len(posts)}
    return res


def match_all(db, min_posts=8, top=10):
    """Return {handle: profile} and all pairwise {a,b,score} and per-handle matches.

    Blends character n-gram cosine with posting-hour distribution + vocabulary
    richness; a cross-lingual guard caps matches between corpora that share no
    detected language, so two active-but-different-language handles never merge.
    """
    corpus = corpus_by_handle(db, min_posts)
    prof = {h: profile([corpus[h]["text"]], hours=corpus[h]["hours"]) for h in corpus}
    pairs, per = [], {}
    hs = list(prof)
    for i in range(len(hs)):
        per[hs[i]] = []
        for j in range(i + 1, len(hs)):
            s = cosine(prof[hs[i]], prof[hs[j]])
            lang_i = corpus[hs[i]]["langs"]
            lang_j = corpus[hs[j]]["langs"]
            if lang_i and lang_j and not lang_i & lang_j:
                s = min(s, 0.35)
            if s > 0.5:
                pairs.append((hs[i], hs[j], round(s, 4)))
    for a in hs:
        matches = []
        for b in hs:
            if b == a:
                continue
            s = cosine(prof[a], prof[b])
            lang_a = corpus[a]["langs"]
            lang_b = corpus[b]["langs"]
            if lang_a and lang_b and not lang_a & lang_b:
                s = min(s, 0.35)
            if s > 0.5:
                matches.append((b, s))
        matches.sort(key=lambda m: -m[1])
        per[a] = [{"handle": b, "score": round(s, 4),
                   "evidence": explain(prof[a], prof[b])} for b, s in matches[:top]]
    return prof, pairs, per


def match_handle(db, handle, top=10, min_posts=8):
    prof, pairs, per = match_all(db, min_posts, top)
    return per.get(handle, [])