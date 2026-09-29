"""Clearnet fingerprint index: known-clear-web hosts used to correlate a
hidden service to its clearnet twin/mirror.

Read-only OPSEC posture: we only ever fetch the configured seed home pages and
store fingerprint metadata (favicon/content hashes, server banner, analytics id,
title). No page content is retained.
"""
import collections
import os
import re
from urllib.parse import urlparse

from . import detect, imaging, net

# A perceptual favicon match is weaker evidence than an exact byte match: it
# survives re-encoding, which is what a re-saved icon does and also what a
# different icon cut from the same stock artwork does. Scored below the exact
# match so the two are never conflated in a finding.
PHASH_CONFIDENCE = 0.7

# Certificate pivots, weakest last. These are not interchangeable, and the
# ordering encodes why:
#
#   cert_match  - identical certificate (SHA-256 of the DER). One key, one cert.
#   serial_match- same issuer AND serial. Identifies one certificate even if the
#                 operator re-keys the host, and cannot collide by accident.
#   ssh_match   - identical SSH host key. Same reasoning, port 22.
#
#   window_match is deliberately weak (0.45) and is NOT a general-purpose
#   signal. Public CAs batch issuance: every Let's Encrypt certificate in a
#   given window shares notBefore to the second, so ~millions of unrelated
#   sites match. It is only meaningful for a self-signed or unusual issuer,
#   which is what SELF_SIGNED_HINTS checks.
CERT_MATCH_CONFIDENCE = 0.9
SERIAL_MATCH_CONFIDENCE = 0.85
SSH_MATCH_CONFIDENCE = 0.85
WINDOW_MATCH_CONFIDENCE = 0.45

SELF_SIGNED_HINTS = ("self", "localhost", "c=", "ou=", "r3", "rs=", "st=", "l=")


def _is_self_signedish(issuer):
    """True when the issuer string looks self-signed or hand-issued rather than
    a public CA, which is the only case where a shared validity window means
    anything."""
    s = (issuer or "").lower()
    if not s:
        return False
    if "let's encrypt" in s or "lets encrypt" in s or "zerossl" in s:
        return False
    if "digicert" in s or "globalsign" in s or "comodo" in s or "sectigo" in s:
        return False
    if "buypass" in s or "ssl.com" in s or "goDaddy" in s.lower():
        return False
    return any(h in s for h in SELF_SIGNED_HINTS)

DEFAULT_SEED_DOMAINS = ["www.wikipedia.org", "github.com", "news.ycombinator.com"]

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)

_URL_RE = re.compile(
    r"https?://([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)+)"
    r"(?::(\d{1,6}))?", re.I)

MAX_PORT = 65535


def _url_host(m):
    """Hostname from a _URL_RE match, rejecting out-of-range ports.

    The port is captured rather than swallowed by a non-capturing group so it
    can be checked: a link written as :99999 is junk that should not become a
    pivot, and a regex that silently accepts it puts a malformed reference into
    the index as though it were a real address.
    """
    host, port = m.group(1), m.group(2)
    if port is not None and not (1 <= int(port) <= MAX_PORT):
        return None
    return host

# Hosts that cannot identify an operator because the entire internet uses them.
# Matching a favicon or content hash against one of these yields a
# "correlation" for every site on earth, which is worse than no correlation:
# it looks like evidence and inflates confidence. Exact-subdomain match, so
# `drive.google.com` is excluded while `abc.workers.dev` is not.
GENERIC_HOSTS = frozenset("""
    google.com google.co.uk googleapis.com gstatic.com drive.google.com
    docs.google.com mail.google.com accounts.google.com
    yahoo.com ymail.com bing.com duckduckgo.com
    facebook.com fb.com fbcdn.net instagram.com twitter.com x.com t.co
    linkedin.com reddit.com r.reddit.com wikipedia.org wikimedia.org
    github.com githubusercontent.com codeload.github.com gist.github.com
    gitlab.com bitbucket.org stackoverflow.com stackexchange.com
    youtube.com youtu.be vimeo.com flickr.com imgur.com
    amazon.com aws.amazon.com cloudflare.com cdn.jsdelivr.net unpkg.com
    wordpress.com wp.com blogger.com tumblr.com medium.com
    telegram.me t.me telegram.org pastebin.com ghostbin.com
    protonmail.com proton.me icloud.com apple.com microsoft.com
    mozilla.org apache.org nginx.org letsencrypt.org
    archive.org archive.is 0x0.st file.io anonfiles.com
""".split())


# Public resolvers and anycast endpoints appear in darknet posts as ordinary
# "how to reach us" boilerplate. Treating them as operator infrastructure would
# correlate every site that pasted the same DNS instructions.
PUBLIC_RESOLVERS = frozenset({
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220", "64.6.64.6", "77.88.8.8", "94.140.14.14",
})


def _is_generic_host(host):
    h = (host or "").lower().strip(".")
    if not h or h in PUBLIC_RESOLVERS:
        return True
    parts = h.split(".")
    # Strip one leading label so subdomains of a generic provider are caught,
    # but keep checking: a.b.example.com should still be generic.
    for i in range(min(3, len(parts) - 1)):
        cand = ".".join(parts[i:])
        if cand in GENERIC_HOSTS:
            return True
    return False


def _ip_host(host):
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or ""))


def mine_clearnet_hosts(db, limit=500, include_generic=False):
    """Rank the clearnet hosts this corpus points at, keeping two signals apart.

    Read-only: reads stored post bodies and site rows, fetches nothing.

    The two sources mean very different things and collapsing them would
    overstate the result:

    - `advertised_sites` - a host referenced from inside a darknet page's own
      post body. This is the vendor's clearnet presence (a mirror, an escrow
      contact, a landing page) and is the only one of the two that supports
      attribution.
    - `seed_sites` - a host that merely *is* a row in the seed list. With
      URLhaus-dominated seeds this is mostly malware distribution addresses, so
      breadth here means "many payloads on one box", which is infrastructure
      clustering, not attribution.

    Ranking puts advertised hosts first, then falls back to seed breadth.
    """
    advertised = collections.defaultdict(set)
    seeds = collections.Counter()

    def ok(h):
        if not h:
            return None
        h = h.lower()
        if h.endswith(".onion") or (not include_generic and _is_generic_host(h)):
            return None
        return h

    for r in db.q("SELECT site_id, body FROM posts"):
        for h in {ok(_url_host(m)) for m in _URL_RE.finditer(r["body"] or "")}:
            if h:
                advertised[h].add(r["site_id"])
    for r in db.q("SELECT url FROM sites"):
        m = _URL_RE.match(r["url"] or "")
        h = ok(_url_host(m)) if m else None
        if h:
            seeds[h] += 1

    out = []
    for h in set(advertised) | set(seeds):
        a, s = len(advertised.get(h, ())), seeds.get(h, 0)
        out.append({
            "host": h,
            "advertised_sites": a,
            "seed_sites": s,
            "is_ip": _ip_host(h),
            "kind": ("advertised" if a and s else
                     "advertised" if a else "seed"),
        })
    # Advertised presence first; within each tier, distinct-site breadth.
    out.sort(key=lambda e: (-e["advertised_sites"], -e["seed_sites"], e["host"]))
    return out[:limit]


def seed_domains():
    raw = os.environ.get("CLEARNET_SEED_DOMAINS", "").strip()
    if raw:
        return [d.strip().lower() for d in raw.split(",") if d.strip()]
    return list(DEFAULT_SEED_DOMAINS)


def _host_of(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _page_title(html):
    m = _TITLE_RE.search(html or "")
    if not m:
        return ""
    return re.sub(r"<[^>]+>", "", m.group(1)).strip()[:200]


def _analytics_ids(html):
    return sorted(set(detect.UA_ANALYTICS.findall(html or "")))


def import_sites(db):
    """Fold known non-.onion site rows (their stored fingerprints) into the
    clearnet index. Idempotent: upsert keyed on hostname."""
    rows = db.q(
        "SELECT url,title,favicon_hash,favicon_phash,content_hash,server,"
        "       cert_fp,cert_serial,tls_issuer,cert_valid_from,cert_valid_to,ssh_fp FROM sites "
        "WHERE url NOT LIKE '%.onion%' "
        "AND (favicon_hash IS NOT NULL OR favicon_phash IS NOT NULL "
        "     OR content_hash IS NOT NULL "
        "     OR cert_fp IS NOT NULL OR cert_serial IS NOT NULL "
        "     OR ssh_fp IS NOT NULL "
        "     OR (server IS NOT NULL AND server <> ''))")
    added = 0
    for row in rows:
        r = dict(row)
        host = _host_of(r.get("url") or "")
        if not host or host.endswith(".onion"):
            continue
        db.upsert_clearnet_fp(host, title=r.get("title") or "",
                              favicon_hash=r.get("favicon_hash"),
                              favicon_phash=r.get("favicon_phash") or None,
                              content_hash=r.get("content_hash"),
                              server=r.get("server") or "",
                              cert_fp=r.get("cert_fp") or None,
                              cert_serial=r.get("cert_serial") or None,
                              cert_issuer=r.get("tls_issuer") or None,
                              cert_valid_from=r.get("cert_valid_from") or None,
                              cert_valid_to=r.get("cert_valid_to") or None,
                              ssh_fp=r.get("ssh_fp") or None)
        added += 1
    return added


def pivot_hosts(db, limit=50, include_ips=True, include_generic=False):
    """The hosts worth fingerprinting: vendor-advertised clearnet presence first,
    then the most widely-seeded hosts. Excludes public resolvers."""
    rows = mine_clearnet_hosts(db, limit=limit * 20, include_generic=include_generic)
    # include_ips gates both tiers: an operator-advertised raw address is still
    # an IP, and a caller asking for hostname pivots must not silently get
    # addresses from whichever half of the ranking they happened to be in.
    allowed = [r for r in rows if include_ips or not r["is_ip"]]
    out = [r["host"] for r in allowed if r["advertised_sites"] > 0]
    out += [r["host"] for r in allowed if r["advertised_sites"] == 0]
    seen, uniq = set(), []
    for h in out:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
        if len(uniq) >= limit:
            break
    return uniq


def crawl_seeds(db, domains=None, timeout=20):
    """Fetch each clearnet seed home page and persist its fingerprints."""
    made = 0
    for host in (domains or seed_domains()):
        try:
            snap = net.fetch_snap(f"https://{host}/", timeout=timeout)
        except Exception:
            continue
        fp = detect.fingerprint(snap)
        ids = _analytics_ids(snap.html)
        meta = snap.meta or {}
        db.upsert_clearnet_fp(_host_of(snap.url) or host,
                              title=_page_title(snap.html),
                              favicon_hash=fp["favicon_hash"],
                              favicon_phash=fp.get("favicon_phash") or None,
                              content_hash=fp["content_hash"],
                              server=fp["server"] or "",
                              analytics_id=ids[0] if ids else "",
                              cert_fp=meta.get("cert_fp") or None,
                              cert_serial=meta.get("cert_serial") or None,
                              cert_issuer=meta.get("tls_issuer") or None,
                              cert_valid_from=meta.get("tls_valid_from") or None,
                              cert_valid_to=meta.get("tls_valid_to") or None,
                              ssh_fp=meta.get("ssh_fp") or None)
        made += 1
    return made


def load(db, crawl=False):
    """Build the correlation index.

    Reads persisted clearnet_fingerprints; on a cold table folds existing
    clearnet site rows once so the index is usable without a crawl. crawl=True
    additionally fetches the configured seed domains first.
    """
    if crawl or not (db.one("SELECT COUNT(*) AS n FROM clearnet_fingerprints") or {}).get("n"):
        if crawl:
            crawl_seeds(db)
        import_sites(db)
    return ClearnetIndex([dict(r) for r in db.load_clearnet_index()])


class ClearnetIndex:
    """Known clearnet host fingerprints, keyed for O(1) attribute lookup.

    A record is a dict with keys:
        host, title, favicon_hash, content_hash, server, analytics_id
    """

    _LOOKUP_ATTRS = (
        ("favicon_hash", "favicon_match", 0.9),
        ("content_hash", "mirror_match", 0.9),
        ("server", "banner_match", 0.75),
    )

    def __init__(self, records=None, phash_threshold=imaging.DEFAULT_THRESHOLD):
        self.records = []
        self._by = {}
        self._phash = []
        self.phash_threshold = phash_threshold
        for rec in records or []:
            self.add(rec)

    def add(self, rec):
        rec = dict(rec)
        self.records.append(rec)
        for field, _kind, _conf in self._LOOKUP_ATTRS:
            value = rec.get(field)
            if value:
                self._by.setdefault((field, value), []).append(rec)
        value = rec.get("analytics_id")
        if value:
            self._by.setdefault(("analytics_id", value), []).append(rec)
        value = rec.get("favicon_phash")
        if value:
            self._phash.append((value, rec))
        # Cert/ssh pivots are keyed on a compound so a bare serial that happens
        # to collide across issuers still needs the issuer to match.
        for attr, key in (("cert_fp", "cert"), ("ssh_fp", "ssh")):
            v = rec.get(attr)
            if v:
                self._by.setdefault((key, v), []).append(rec)
        serial, issuer = rec.get("cert_serial"), rec.get("cert_issuer")
        if serial and issuer:
            self._by.setdefault(("serial", f"{issuer}|{serial}".lower()), []).append(rec)
        vfrom = rec.get("cert_valid_from")
        if vfrom and issuer:
            self._by.setdefault(("window", f"{issuer}|{vfrom}".lower()), []).append(rec)

    def lookup(self, fp, analytics=None):
        """Return correlation matches for a snapshot fingerprint dict plus the
        analytics ids (list of strings) found in its html. Each match:
            {kind, host, title, attribute, value, confidence}
        """
        out = []
        for field, kind, conf in self._LOOKUP_ATTRS:
            value = fp.get(field)
            if not value:
                continue
            for rec in self._by.get((field, value), []):
                out.append({"kind": kind, "host": rec["host"],
                            "title": rec.get("title") or "", "attribute": field,
                            "value": value, "confidence": conf})
        # Perceptual favicon match. Reported at a lower confidence than an
        # exact favicon match because it tolerates re-encoding, which is exactly
        # what a copied-and-resaved icon does -- and also what an unrelated icon
        # derived from the same stock artwork does.
        phash = fp.get("favicon_phash")
        if phash:
            for other, rec in self._phash:
                dist = imaging.hamming(phash, other)
                if 0 <= dist <= self.phash_threshold:
                    out.append({"kind": "favicon_perceptual_match", "host": rec["host"],
                                "title": rec.get("title") or "",
                                "attribute": "favicon_phash", "value": phash,
                                "distance": dist, "confidence": PHASH_CONFIDENCE})
        # ---- certificate / host-key pivots ----
        def _pivot(key, kind, conf, value, extra=None):
            for rec in self._by.get((key, value), []):
                hit = {"kind": kind, "host": rec["host"],
                       "title": rec.get("title") or "", "attribute": key,
                       "value": value, "confidence": conf}
                if extra:
                    hit.update(extra)
                out.append(hit)

        v = fp.get("cert_fp")
        if v:
            _pivot("cert", "cert_match", CERT_MATCH_CONFIDENCE, v)

        serial, issuer = fp.get("cert_serial"), (fp.get("cert_issuer") or fp.get("tls_issuer"))
        if serial and issuer:
            _pivot("serial", "cert_serial_match", SERIAL_MATCH_CONFIDENCE,
                   f"{issuer}|{serial}".lower(),
                   {"issuer": issuer, "serial": serial})

        v = fp.get("ssh_fp")
        if v:
            _pivot("ssh", "ssh_key_match", SSH_MATCH_CONFIDENCE, v)

        # Shared validity window, gated on a non-public issuer.
        vfrom = fp.get("cert_valid_from")
        if vfrom and issuer and _is_self_signedish(issuer):
            _pivot("window", "cert_validity_match", WINDOW_MATCH_CONFIDENCE,
                   f"{issuer}|{vfrom}".lower(),
                   {"issuer": issuer, "valid_from": vfrom,
                    "caveat": "self-signed/hand-issued issuer; shared window suggests "
                              "the same issuance event, not the same operator"})

        for aid in analytics or []:
            for rec in self._by.get(("analytics_id", aid), []):
                out.append({"kind": "analytics_match", "host": rec["host"],
                            "title": rec.get("title") or "",
                            "attribute": "analytics_id", "value": aid,
                            "confidence": 0.85})
        return out