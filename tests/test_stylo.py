"""Stylometry: does the method separate authors, and refuse to when it cannot?

The synthetic corpora here are built to be adversarial in the way real ones are:
every author posts on the same board, so everyone shares the same boilerplate.
A raw cosine over that boilerplate makes all authors look alike. The point of
subtracting the corpus centroid is that a *different* author must then stop
looking like a match, while a *relabelled* author must keep looking like one.
"""
import random

import pytest

from darkforce import stylo

BOILERPLATE = (
    "Welcome to the board. Please read the rules before posting. "
    "Use descriptive titles. No advertising. Escrow required for all trades. "
    "Shipping takes 5 to 7 business days. Contact support with your order number. "
    "We reserve the right to remove any listing at any time. Thanks for your business. "
)

WORD_BANK = """
i think we should really just go ahead and do it again today because honestly
there is no reason not to and it might even help us out later when the other
folks ask about it again like they always do somehow committee noted that no
fewer than three members objected strongly to the proposal submitted tuesday
afternoon concerning the amendment circulated beforehand all relevant
stakeholders for consideration prior to the scheduled review of the matter
itself ship tonight if escrow clears otherwise refund immediately questions
asked we have stock in the warehouse already packed and ready to go out the
door as soon as payment lands in the right account today built this tool over
some time mostly weekends and evenings while working around a day job family
things it started as a small script for my own use and slowly grew into
something other people seem to find useful too payment sent confirm receipt
thanks quick response everything arrived intact good order will recommend
others here whenever needed again regards apologies for delay getting back
send message if you need anything further from me this week thanks again bye
""".split()

# Distinct punctuation habits. Each voice leans on a different set, so the
# punctuation-rate features separate authors the way real writing habits do.
PUNCT_STYLES = [
    (".", ".", ".", "?", "!"),
    (".", ".", ",", ".", ";"),
    ("!", "!", "?", ".", "."),
    (".", " ...", ".", "?", ""),
    (" -- ", ".", ";", "!", "?"),
]
CASE_STYLES = ["normal", "normal", "shout", "lower", "title"]


def _make_voice(idx, n_authors=6):
    """A distinct voice: a disjoint vocabulary slice, punctuation habits, casing.

    The slice is `WORD_BANK[idx::n_authors]`, so the authors' vocabularies are
    disjoint by construction. An earlier generator stepped through the bank by
    5, which wrapped it twice -- every author ended up holding two thirds of the
    vocabulary, punctuation could not carry the signal, and unrelated authors
    scored ~0.78.
    """
    words = WORD_BANK[idx::n_authors]
    return {"words": words, "punct": PUNCT_STYLES[idx % len(PUNCT_STYLES)],
            "case": CASE_STYLES[idx % len(CASE_STYLES)]}


def _shape(s, voice):
    style, punct = voice["case"], voice["punct"]
    if style == "shout":
        s = s.upper()
    elif style == "lower":
        s = s.lower()
    elif style == "title":
        s = s.title()
    if punct[-1]:
        s = s + punct[-1]
    return s


def _author(voice, n_posts, rng):
    """Posts in one voice.

    Each post draws a different slice of the voice's vocabulary in a different
    order and length. That within-author variety is essential: if every post by
    an author is near-identical, a random half of their posts is as similar to
    the other half as the real halves are, and the split-half and replication
    checks have nothing to measure.
    """
    words, punct, case = voice["words"], voice["punct"], voice["case"]
    posts = []
    for _ in range(n_posts):
        w = words[:]
        rng.shuffle(w)
        body, k = [], 0
        for _ in range(rng.randrange(6, 14)):
            n = rng.randrange(6, 20)
            chunk = w[k:k + n]
            if not chunk:
                break
            k += n
            sent = _shape(" ".join(chunk), {"case": case, "punct": punct})
            body.append(rng.choice(punct[:4]) + " " + sent + rng.choice(punct))
        posts.append(_shape(" ".join(body), {"case": case, "punct": punct})
                     + " " + BOILERPLATE)
    return posts


def _corpus(rng, n_posts=16):
    """Seven handles / six authors: 'alice' relabelled as 'alice_v2', five others.

    Each other handle gets its own voice, so alice/alice_v2 is the only genuine
    match. Seven handles is the smallest corpus that can clear the significance
    gate at all: a rank test over N unrelated pairs cannot report a p-value below
    1/(N+1), so 7 handles (20 null pairs, floor p = 1/21) is the minimum for
    MAX_PVALUE = 0.05. Sixteen posts each gives split-half enough material.
    """
    names = ["bob", "carol", "dave", "erin", "frank"]
    handles = {"alice": 0, "alice_v2": 0}
    for i, name in enumerate(names, start=1):
        handles[name] = i
    n_authors = len(names) + 1
    return {h: _author(_make_voice(v, n_authors), n_posts, rng)
            for h, v in handles.items()}


class _Row(dict):
    __getattr__ = dict.get


class StubDB:
    """Minimal stand-in exposing the one query stylo uses."""

    def __init__(self, corpus):
        rows = []
        for handle, texts in corpus.items():
            for t in texts:
                rows.append(_Row(handle=handle, title="", body=t))
        self._rows = rows

    def q(self, _sql):
        return self._rows


@pytest.fixture
def corpus():
    return _corpus(random.Random(7))


@pytest.fixture
def results(corpus):
    return stylo.match_all(StubDB(corpus), min_posts=1)


def _pair(pairs, a, b):
    for p in pairs:
        if {p["a"], p["b"]} == {a, b}:
            return p
    return None


# --- the positive case ------------------------------------------------------

def test_same_author_under_two_handles_is_significant(results):
    _, pairs, _ = results
    p = _pair(pairs, "alice", "alice_v2")
    assert p is not None, "the true match was never even considered"
    assert p["significant"], p
    assert p["score"] >= stylo.MIN_SCORE
    assert p["p_value"] <= stylo.MAX_PVALUE
    assert p["reliability"] >= stylo.MIN_RELIABILITY


# --- the false-positive case the centroid is there to prevent ---------------

def test_shared_boilerplate_does_not_make_different_authors_match(results):
    """The one true match is the only one promoted to a lead."""
    _, pairs, _ = results
    flagged = {(p["a"], p["b"]) for p in pairs if p["significant"]}
    assert flagged <= {("alice", "alice_v2")}, flagged


def test_replication_is_evidence_but_not_a_gate(results):
    """Guards a measured decision, so it cannot be silently reinstated.

    `replication` did not separate true matches from false ones on this data, so
    it is reported but not enforced. This test would fail if that changed.
    """
    _, pairs, _ = results
    true_rep = [p["replication"] for p in pairs
                if {p["a"], p["b"]} == {"alice", "alice_v2"}][0]
    false_rep = [p["replication"] for p in pairs
                 if {p["a"], p["b"]} != {"alice", "alice_v2"}]
    assert true_rep < 0.05, "replication has become informative; reconsider the gate"
    assert all(r < 0.05 for r in false_rep)


def test_raw_cosine_would_have_been_fooled_but_residual_is_not(corpus):
    """The premise: un-corrected similarity really is high across the board."""
    hc = stylo.handle_counts(corpus, min_posts=1)
    vocab, ok = stylo.build_vocab(hc)
    assert ok
    vecs = stylo._vectors(hc, vocab)
    prof = {h: stylo.aggregate(v) for h, v in vecs.items()}
    base = stylo.centroid(prof)
    resid = {h: stylo.residual(prof[h], base) for h in prof}

    raw_bob_carol = stylo.cosine(prof["bob"], prof["carol"])
    res_bob_carol = stylo.cosine(resid["bob"], resid["carol"])
    assert raw_bob_carol > 0.5, "fixture no longer exercises the template effect"
    assert res_bob_carol < raw_bob_carol
    assert res_bob_carol < stylo.MIN_SCORE, (raw_bob_carol, res_bob_carol)


# --- gating -----------------------------------------------------------------

def test_thin_corpora_are_not_analysed():
    """Two short posts is not evidence, and must produce no claim at all."""
    db = StubDB({"x": ["too short to mean anything"], "y": ["also far too short"]})
    prof, pairs, per = stylo.match_all(db, min_posts=1)
    assert pairs == [] and per == {}
    assert prof == {}


def test_single_author_yields_nothing():
    db = StubDB({"solo": _author(_make_voice(0, 2), 9, random.Random(1))})
    _, pairs, per = stylo.match_all(db, min_posts=1)
    assert pairs == [] and per == {}


def test_min_posts_is_respected():
    db = StubDB({"a": _author(_make_voice(0, 2), 2, random.Random(1)),
                 "b": _author(_make_voice(1, 2), 2, random.Random(2))})
    _, pairs, _ = stylo.match_all(db, min_posts=5)
    assert pairs == []


# --- reported evidence ------------------------------------------------------

def test_every_reported_pair_carries_its_evidence(results):
    _, pairs, per = results
    for p in pairs:
        assert set(p) >= {"a", "b", "score", "p_value", "reliability",
                          "replication", "significant", "null_pairs",
                          "posts", "words", "evidence"}
        assert 0.0 <= p["score"] <= 1.0
        assert 0.0 < p["p_value"] <= 1.0
    for handle, recs in per.items():
        assert len(recs) <= 10
        assert all(r["a"] == handle or r["b"] == handle for r in recs)
        scores = [r["score"] for r in recs]
        assert scores == sorted(scores, reverse=True)


def test_evidence_names_real_features(results):
    _, pairs, _ = results
    p = _pair(pairs, "alice", "alice_v2")
    feats = [e["feature"] for e in p["evidence"]]
    assert feats, "a reported match must say what it matched on"
    assert any(f.startswith(("fw:", "p:", "cg:")) for f in feats)


# --- robustness -------------------------------------------------------------

def test_empty_and_blank_input_is_safe():
    db = StubDB({"a": [""], "b": ["   "]})
    prof, pairs, per = stylo.match_all(db, min_posts=1)
    assert pairs == [] and per == {}


def test_repeated_calls_are_deterministic(corpus):
    db = StubDB(corpus)
    a = stylo.match_all(db, min_posts=1)[1]
    b = stylo.match_all(db, min_posts=1)[1]
    assert [p["score"] for p in a] == [p["score"] for p in b]
    assert [p["p_value"] for p in a] == [p["p_value"] for p in b]


def test_p_value_is_never_zero_and_never_exceeds_one(results):
    """(1 + k) / (1 + n) can never be 0, and is a real probability."""
    _, pairs, _ = results
    assert pairs, "fixture produced no pairs to check"
    for p in pairs:
        assert 0.0 < p["p_value"] <= 1.0
