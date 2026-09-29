"""Avatar and screenshot correlation.

What this is for
----------------
The same actor running a forum under three handles will usually reuse one
avatar, and a clearnet mirror of a darknet forum will show the same page. Both
give a perceptual handle worth having, alongside the existing favicon, content
and certificate pivots.

Why it needs its own module, and is treated more carefully than a favicon
--------------------------------------------------------------------------
A favicon is, in practice, unique to a deployment: the operator picks it. An
avatar is not. Forums fall back to a default silhouette, admins paste the same
stock wolf, and pastebin-style sites ship one placeholder to every user. A
perceptual avatar match is therefore very likely to be a *default image* rather
than evidence of a shared operator.

Left unchecked this is the single most damaging false-attribution primitive in
the whole index: link the default avatar of one site to the default avatar of
another and two unrelated actors merge, and because actor merges are
transitive, a chain of a dozen such links fuses an entire unrelated cluster.

So an avatar match is admitted as evidence only when the image is *rare*. The
ubiquity gate below counts how many distinct actors carry the hash and refuses
to correlate anything seen often enough to be a default. It reports those
separately, as a negative result, rather than silently dropping them -- an
analyst needs to see that a match was suppressed and why.

Screenshots do not get that treatment, because a screenshot is of a specific
page and is not a reusable default, but they are held to a much tighter
threshold than a favicon, since they are large, high-entropy and get rescaled
and re-cropped constantly.
"""
import hashlib
import re
from urllib.parse import urljoin, urlparse

from . import imaging

# An avatar seen on more than this many distinct actors is treated as a default
# image and is not admissible as identity evidence. Two is deliberately
# generous: a real operator reusing one avatar across forums is the case we want
# to catch, and by the third holder the "default image" explanation is the
# parsimonious one.
UBIQUITY_LIMIT = 2

# Avatars are tiny and get re-encoded and rescaled constantly, so the same
# image rarely lands on identical bits. Screenshots get a tighter budget
# because they are page renders: same page, different viewport, and most of the
# hash should survive.
AVATAR_THRESHOLD = 10
SCREENSHOT_THRESHOLD = 24

# Both are far below the confidence of an exact match and below the favicon
# perceptual match, because "same picture" is a weaker claim about a person than
# "same certificate" or "same site".
AVATAR_CONFIDENCE = 0.55
SCREENSHOT_CONFIDENCE = 0.60

# Shared by the generic silhouette, the anonymous-user gif and friends. Not
# load-bearing -- the ubiquity gate is what actually prevents the false merge --
# but catching the obvious cases early keeps the index small.
_COMMON_AVATAR_HINTS = ("default", "placeholder", "anonymous", "avatar-blank",
                        "no-avatar", "gravatar", "spacer", "1x1", "blank")

_ATTR = re.compile(r'([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*"([^"]*)"')
_SRC = re.compile(r'<img[^>]+src\s*=\s*"([^"]+)"', re.I)
_META = re.compile(r'<meta[^>]+(?:property|name)\s*=\s*"(og:image|twitter:image)"'
                   r'[^>]+content\s*=\s*"([^"]+)"', re.I)


def _attrs(tag):
    return {k.lower(): v for k, v in _ATTR.findall(tag)}


def _candidate(img_tag, url):
    """An <img> tag's src resolved against the page, if it is not obviously junk."""
    tag = _attrs(img_tag)
    src = tag.get("src", "").strip()
    if not src or src.startswith("data:"):
        # Inline data: URIs are overwhelmingly tracking pixels and spacers, and
        # they would also let one page pin a unique hash per visitor, which
        # poisons the index with single-use images.
        return None
    low = src.lower()
    if any(h in low for h in _COMMON_AVATAR_HINTS):
        return None
    try:
        full = urljoin(url, src)
    except Exception:
        return None
    if not full.startswith(("http://", "https://")):
        return None
    return full


def extract_avatar_urls(html, page_url):
    """Avatar-ish image URLs in page order, de-duplicated, capped.

    Heuristic and deliberately noisy: it looks for class/id/alt naming that
    suggests a profile picture, and otherwise falls back to the first few images,
    which on a forum thread is the poster's avatar. Precision is not the point --
    the ubiquity gate is what decides whether a match means anything.
    """
    if not html:
        return []
    found, seen = [], set()
    for tag in re.findall(r"<img[^>]*>", html, re.I):
        attrs = _attrs(tag)
        blob = " ".join((attrs.get("class", ""), attrs.get("id", ""), attrs.get("alt", ""))).lower()
        strong = any(k in blob for k in ("avatar", "profile", "portrait", "userpic",
                                         "post-author", "author", "member"))
        url = _candidate(tag, page_url)
        if not url or url in seen:
            continue
        if strong or len(found) < 3:
            seen.add(url)
            found.append(url)
        if len(found) >= 12:
            break
    return found


def extract_screenshot_urls(html, page_url):
    """Preview/screenshot image URLs (og:image, twitter:image), de-duplicated."""
    if not html:
        return []
    found, seen = [], set()
    for _prop, src in _META.findall(html):
        if not src or src.lower().startswith("data:"):
            continue
        try:
            full = urljoin(page_url, src)
        except Exception:
            continue
        if full.startswith(("http://", "https://")) and full not in seen:
            seen.add(full)
            found.append(full)
    return found[:6]


def exact_hash(data):
    """Byte-exact digest, the provenance counterpart to the perceptual hash."""
    return hashlib.sha256(data).hexdigest() if data else ""


def describe(image_bytes, kind="avatar"):
    """Both hashes plus the exact digest, ready for storage. Empty phash means
    the image was undecodable, which the caller treats as 'store nothing'."""
    grid = imaging.AVATAR_GRID if kind == "avatar" else imaging.SCREENSHOT_GRID
    phash = imaging.dhash(image_bytes, grid)
    if not phash:
        return {}
    return {"phash": phash, "exact_hash": exact_hash(image_bytes),
            "bytes": len(image_bytes or b"")}


class ImageIndex:
    """Perceptual correlation over stored avatar/screenshot hashes.

    records: dicts with at least {kind, phash, handle, site_url} and optionally
    {actor_id, site_id, exact_hash}.
    """

    THRESHOLDS = {"avatar": AVATAR_THRESHOLD, "screenshot": SCREENSHOT_THRESHOLD}
    CONFIDENCE = {"avatar": AVATAR_CONFIDENCE, "screenshot": SCREENSHOT_CONFIDENCE}

    def __init__(self, records=None):
        self.records = []
        self._by_kind = {"avatar": [], "screenshot": []}
        for rec in records or []:
            self.add(rec)

    def add(self, rec):
        rec = dict(rec)
        self.records.append(rec)
        kind = rec.get("kind", "avatar")
        if rec.get("phash") and kind in self._by_kind:
            self._by_kind[kind].append(rec)
        return rec

    def _distinct_actors(self, kind, phash):
        actors, handles = set(), set()
        for r in self._by_kind.get(kind, []):
            if imaging.hamming(phash, r["phash"]) > 0:
                continue
            if r.get("actor_id") is not None:
                actors.add(r["actor_id"])
            else:
                handles.add(r.get("handle") or r.get("site_url") or "")
        # Prefer actor ids when known; fall back to raw handles, since two handles
        # on one site are not yet known to be the same person.
        return actors if actors else handles

    def ubiquity(self, kind, phash):
        """How many distinct actors carry this image. 0 if unseen."""
        return len(self._distinct_actors(kind, phash))

    def is_generic(self, kind, phash):
        return self.ubiquity(kind, phash) > UBIQUITY_LIMIT

    def lookup(self, fp, require_rare=True):
        """Correlate {kind: image_bytes} (or precomputed {kind: phash}) against the
        index.

        Returns a list of match dicts. Suppressed matches are reported too, with
        admitted=False and a reason, so a suppressed default-avatar match stays
        visible to the analyst instead of looking like a clean miss.
        """
        out = []
        for kind in ("avatar", "screenshot"):
            raw = fp.get(kind)
            if not raw:
                continue
            if isinstance(raw, bytes):
                grid = imaging.AVATAR_GRID if kind == "avatar" else imaging.SCREENSHOT_GRID
                phash = imaging.dhash(raw, grid)
            else:
                phash = raw
            if not phash:
                continue
            threshold = self.THRESHOLDS[kind]
            n = self.ubiquity(kind, phash)
            # The rarity gate is an avatar rule only. It exists because avatars
            # are frequently shared defaults; a screenshot is a render of one
            # specific page, so a page mirrored to several hosts is a real
            # finding and must not be suppressed for being widespread.
            generic = kind == "avatar" and n > UBIQUITY_LIMIT
            if generic and require_rare:
                for rec in self._by_kind.get(kind, []):
                    dist = imaging.hamming(phash, rec["phash"])
                    if 0 <= dist <= threshold:
                        out.append({
                            "kind": f"{kind}_perceptual_match",
                            "host": rec.get("site_url", ""),
                            "handle": rec.get("handle", ""),
                            "attribute": f"{kind}_phash",
                            "value": phash,
                            "distance": dist,
                            "confidence": self.CONFIDENCE[kind],
                            "admitted": False,
                            "reason": f"image seen on {n} distinct actors; "
                                      "consistent with a default/placeholder image, "
                                      "so it is not evidence of a shared operator",
                        })
                continue
            for rec in self._by_kind.get(kind, []):
                # Not a correlation if it is the same page we are looking at.
                # Keyed on site_url *and* handle, both normalised: screenshots
                # are page-level and carry no handle, so a handle-only test would
                # let a page match itself. `add()` copies each record, so object
                # identity is unavailable here and the strings must carry it.
                same_page = (rec.get("site_url") or "") == (fp.get("site_url") or "")
                same_handle = (rec.get("handle") or "") == (fp.get("handle") or "")
                if same_page and same_handle:
                    continue
                dist = imaging.hamming(phash, rec["phash"])
                if 0 <= dist <= threshold:
                    out.append({
                        "kind": f"{kind}_perceptual_match",
                        "host": rec.get("site_url", ""),
                        "handle": rec.get("handle", ""),
                        "attribute": f"{kind}_phash",
                        "value": phash,
                        "distance": dist,
                        "confidence": self.CONFIDENCE[kind],
                        "admitted": True,
                    })
        return out


def host_of(url):
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""
