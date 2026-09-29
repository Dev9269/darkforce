import base64
import hashlib
import re
import unicodedata

try:  # bs4 is a hard requirement of collect.py, but keep extract.py importable alone
    from bs4 import BeautifulSoup as _Soup, Comment as _Comment
except Exception:  # pragma: no cover - only hit in a stripped-down environment
    _Soup = None
    _Comment = ()

ONION_V3 = re.compile(r"\b[a-z2-7]{56}\.onion\b")
ONION_ALL = re.compile(r"\b[a-z2-7]{16,56}\.onion\b")
BTC = re.compile(r"\b(bc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{20,71}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
XMR = re.compile(r"\b[89][1-9A-HJ-NP-Za-km-z]{93}\b")
EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)+\b")
PGP_BLOCK = re.compile(r"-----BEGIN PGP PUBLIC KEY BLOCK-----\r?\n.*?-----END PGP PUBLIC KEY BLOCK-----", re.S)
JABBER = re.compile(r"\b[\w.+-]+@(?:jabber|exploit|disroot|accessnow)\.\w+\b", re.I)
TELEGRAM = re.compile(r"(?<!\w)@([A-Za-z0-9_]{4,32})(?![A-Za-z0-9_])")
ICQ = re.compile(r"\bICQ[: ]?(\d{5,10})\b", re.I)
IP = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]{1,5})?\b")
CLEARNET_HOST = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|ru|xyz|info|cc|me)\b")
KEYBASE = re.compile(r"(?:keybase\.io|keybase\.com)/\s*([a-zA-Z0-9_]{3,32})")
SESSION_ID = re.compile(r"\b05[a-f0-9]{58,66}\b")
WIRE_HANDLE = re.compile(r"(?i)\bwire\s*(?:id|handle)?[:@]?\s*([a-zA-Z0-9_]{3,32})\b")

# Provenance tags for @-handles. An @-mention found in visible prose is
# evidence about a person; the same token found in a <style>/<script> block is
# a CSS at-rule or a JS global. Both are stored (search still benefits) but only
# the prose form is allowed to merge actors -- see link.py.
TELEGRAM_PROSE = "extract:telegram_prose"
TELEGRAM_MARKUP = "extract:telegram_markup"

# Non-content elements whose text is never a statement about a person.
_INVISIBLE_TAGS = ("script", "style", "noscript", "template", "svg", "iframe", "head")
# Attributes that legitimately carry contact/identity targets. Onion addresses
# and wallet links live almost exclusively in href/src, so dropping attribute
# values wholesale would lose real signal.
_IDENTITY_ATTRS = ("href", "src", "action", "data-url", "data-href", "content", "value")

# Web-development vocabulary that shows up as bare tokens in page source. These
# are the tokens that historically polluted the identifier table (observed in
# production data: @media on 77 handles, @context on 54, @type on 54,
# @graph on 44, @font on 32). Blocking them keeps the merge graph clean even
# when a page is ingested through a path that still sees raw markup.
_WEBDEV_TOKENS = frozenset("""
media supports import charset page namespace layer container property keyframes
font-face font-face-src font-weight font-style font-family font-size font
context type types graph graphs graphname bgcolor background foreground
width height color colours border margin padding flex grid align items justify
content display position absolute relative fixed static sticky hidden visible
block inline table list none auto solid dashed dotted inherit initial unset
revert solid function return const let var class this new delete typeof
instanceof undefined null true false string number boolean object array json
math date regex regexp map set promise symbol proxy reflect global window
document console module export default extends super yield await async static
void enum interface public private protected readonly declare abstract
implements package require records index main args argv stdin stdout params
config options settings util utils helper helpers core base common shared
vendor lib libs dist build bundle chunk assets static public images img css
js fonts icons data meta link script style head body html page site web www
com net org home login register signup search about contact privacy terms
cookie cookies banner nav menu header footer sidebar widget modal popup overlay
button input form field label select option text email user users name first
last full address phone mobile country city state zip code message messages
post posts comment comments reply replies like likes share shared view views
read more next prev previous back forward up down left right yes no ok done
error warning info debug trace fatal notice alert title subtitle description
summary details detail note notes todo task tasks item items list table row
rows column columns cell grid card cards panel panels tab tabs bar toolbar
layout container wrapper inner outer box span div section article main aside
unsupported placeholder sample example template default source target origin
parent child node leaf root branch edge link chain tree graphml
enable enabled disable disabled active inactive current previous next first
last start stop begin end open close show hide visible invisible toggle
switch select deselect reset clear add remove delete update insert append
prepend before after next prior recent latest oldest newest best worst
success failure pass fail error warn info debug trace fatal critical
analytics google tag manager pixel track tracking monitor counter badge
avatar profile account login signup register logout session token cookie
localstorage sessionstorage storage cache clear expired refresh reload
captcha recaptcha challenge verify verified human robot bot spider crawler
""".split())

# Long unbroken alpha runs are keyboard tests / alphabet strings, not handles.
_ALPHA_RUN_RE = re.compile(r"^[A-Za-z]{13,}$")
# Vendor device/hostname tokens that are alpha but machine-generated.
_DEVICE_TOKEN_RE = re.compile(
    r"^(?:Huawei|Android|OnePlus|Xiaomi|Redmi|Realme|Samsung|Sony|LG|Motorola|"
    r"Nokia|Technicolor|HuaweiHomeGateway|Hgw|Device|Ap|Client|User)\w*$", re.I)
_ALPHABET_RE = re.compile(r"^(?:[A-Z][A-Z0-9]*){3,}$")

# Service handles that are never a threat actor. Previously inline here.
_TG_STOPWORDS = frozenset((
    "onionscan", "telegram", "tor", "signal", "proton", "admin", "support",
    "moderator", "mod", "help", "info", "contact", "official", "news",
    "privacy", "abuse", "security", "postmaster", "webmaster", "noreply",
    "no_reply", "root", "system", "bot", "test", "example", "username",
    "someone", "anyone", "everyone", "nobody", "anonymous", "unknown",
))


# Storage/CDN/hosting path fragments. Author selectors match these because they
# appear in link text, and the hostname-prefix fallback returns them wholesale
# (e.g. pub-<hash>.firebaseapp.com). Real personas do not look like this.
_INFRA_TOKENS = frozenset("""
pub firebasestorage firebase googlonion workerstats raw res get drive cdn
static assets media img files data api app www dev stage test s3 storage
bucket blob cache content uploads download dist build src lib vendor public
private share shared link links node npm js css html htm php asp jsp cgi bin
usr tmp var etc opt home root admin panel dashboard portal gateway proxy
""".split())

# A long unbroken hex run is a content hash / object id, never a handle.
_HASHISH_RE = re.compile(r"[0-9a-f]{12,}", re.I)


def is_plausible_site_handle(value):
    """Whether a string is credible as a *site* author handle.

    Site handles are looser than Telegram (no @, may contain . - _) but the
    crawler's author selectors still pick up page furniture: member counts,
    post numbers, ratings, prices, and CDN/storage path segments. Production
    data held 1804 handle rows across only 396 distinct strings, the most
    common being '42', '176' and '182' -- every one of which became a spurious
    "actor".
    """
    v = (value or "").strip()
    if not (3 <= len(v) <= 40):
        return False
    if not any(ch.isalpha() for ch in v):
        return False
    if not re.fullmatch(r"[\w.\-]{3,40}", v, flags=re.UNICODE):
        return False
    if _HASHISH_RE.search(v):
        return False
    # A dotted host is a hostname, not a handle (the crawler sometimes stores
    # the bare host when no author is found).
    if v.count(".") and re.fullmatch(r"[\w.\-]+\.[a-z]{2,}", v, re.I):
        return False
    low = v.lower()
    if low in _WEBDEV_TOKENS or low in _INFRA_TOKENS:
        return False
    # Storage-style compound: <word>-<word>-<word> is a path, not a name.
    if v.count("-") >= 2 and len(v) > 14:
        return False
    return True


def is_plausible_handle(value):
    """Reject @-tokens that are clearly page-source artifacts, not identities.

    Telegram allows 5-32 chars of [A-Za-z0-9_]. That range overlaps heavily
    with CSS property names, JS globals and device tokens, so shape alone is
    not enough. Blocks web-dev vocabulary, alphabet/keyboard-test strings and
    vendor device tokens.
    """
    v = (value or "").strip()
    if not (4 <= len(v) <= 32):
        return False
    if not re.fullmatch(r"[A-Za-z0-9_]{4,32}", v):
        return False
    if v.lower() in _WEBDEV_TOKENS:
        return False
    if _ALPHA_RUN_RE.match(v) and not any(ch.isdigit() for ch in v):
        return False
    if _DEVICE_TOKEN_RE.match(v):
        return False
    # Pure-uppercase with internal digits looks like a serial/asset tag, but a
    # shouted handle is legitimate, so only reject exact alphabet sequences.
    if _ALPHABET_RE.match(v) and re.fullmatch(r"[A-Z]+", v) and len(v) > 8:
        return False
    return True


def _strip_invisible(html):
    """Remove script/style/comment subtrees. Regex fallback when bs4 is absent."""
    if _Soup is not None:
        try:
            soup = _Soup(html, "html.parser")
            for tag in soup(list(_INVISIBLE_TAGS)):
                tag.decompose()
            for c in soup.find_all(string=lambda s: isinstance(s, type(soup.new_string("")))):
                pass
            return soup
        except Exception:
            pass
    out = html
    for tag in _INVISIBLE_TAGS:
        out = re.sub(rf"<{tag}\b.*?</{tag}>", " ", out, flags=re.I | re.S)
        out = re.sub(rf"<{tag}\b[^>]*/?>", " ", out, flags=re.I)
    return re.sub(r"<!--.*?-->", " ", out, flags=re.S)


def visible_text(html, max_len=400_000):
    """Human-visible text plus identity-bearing attribute values.

    This is the correct input for identifier extraction. `detect.py` keeps
    consuming raw HTML on purpose (it is a web-configuration scanner), but
    identifiers describe *people*, and people are not mentioned in CSS.
    """
    if not html:
        return ""
    parts = []
    soup = None
    if _Soup is not None:
        try:
            soup = _Soup(html, "html.parser")
            for tag in soup(list(_INVISIBLE_TAGS)):
                tag.decompose()
            for c in soup.find_all(string=lambda s: isinstance(s, _Comment)):
                c.extract()
            parts.append(soup.get_text(" ", strip=True))
            seen = set()
            for attr in _IDENTITY_ATTRS:
                for el in soup.find_all(attrs={attr: True}):
                    v = el.get(attr)
                    if isinstance(v, list):
                        v = " ".join(v)
                    v = (v or "").strip()
                    if v and v not in seen:
                        seen.add(v)
                        parts.append(v)
        except Exception:
            soup = None
    if soup is None:
        stripped = _strip_invisible(html)
        parts.append(re.sub(r"<[^>]+>", " ", stripped))
        parts.extend(re.findall(
            r"""(?:%s)\s*=\s*["']([^"']{4,})["']""" % "|".join(_IDENTITY_ATTRS),
            stripped, flags=re.I))
    text = re.sub(r"[ \t]+", " ", " ".join(parts))
    return text[:max_len]


def is_mergeable_identifier(kind, value, method=""):
    """Whether an identifier may drive an actor merge.

    Load-bearing control: an @-handle only qualifies when it came from visible
    prose AND survives the plausibility filter. Anything of unknown provenance
    is untrusted by default and must be promoted explicitly -- `rebuild` in
    link.py does that by checking the token against stored post text, so rows
    ingested before this filter existed are neutralised without a re-crawl
    while genuine prose mentions are recovered.
    """
    if kind in ("telegram", "handle", "username"):
        if not is_plausible_handle(value):
            return False
        return method == TELEGRAM_PROSE
    return True



def norm(t):
    t = unicodedata.normalize("NFKC", t or "")
    t = re.sub(r"[^\S\n]+", " ", t)
    return t


_ARMOR_RE = re.compile(
    r"-----BEGIN PGP PUBLIC KEY BLOCK-----(.*?)-----END PGP PUBLIC KEY BLOCK-----", re.S)
_CRC24_INIT = 0xB704CE
_CRC24_POLY = 0x1864CFB


def _crc24(data):
    """RFC 4880 armor checksum. Used to reject corrupted key pastes."""
    crc = _CRC24_INIT
    for byte in data:
        crc ^= byte << 16
        for _ in range(8):
            crc <<= 1
            if crc & 0x1000000:
                crc ^= _CRC24_POLY
    return crc & 0xFFFFFF


def dearmor(block):
    """ASCII-armored public key block -> raw OpenPGP packet bytes, or None.

    Deliberately returns the *binary* payload, not the text. The previous
    implementation hashed the armored text, so re-flowing the base64 or changing
    a line break produced a different "fingerprint" for the identical key --
    trivial to evade and impossible to correlate on.

    Returns (data, checksum_ok). `checksum_ok` is None when the armor carried no
    CRC line to check, and False when a CRC was present but did not match, which
    means the paste was truncated or mangled.
    """
    m = _ARMOR_RE.search(block or "")
    if not m:
        return None, False
    body = m.group(1)
    # Drop armor headers ("Version: x", "Comment: y") up to the first blank line.
    if "\n\n" in body:
        body = body.split("\n\n", 1)[1]
    lines, crc_line = [], None
    for raw in body.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("="):  # CRC24 checksum terminates the payload
            crc_line = line
            break
        if ":" in line and not re.fullmatch(r"[A-Za-z0-9+/=]+", line):
            continue  # an armor header line
        lines.append(line)
    try:
        data = base64.b64decode("".join(lines), validate=False)
    except Exception:
        return None, False
    if crc_line:
        try:
            want = int(crc_line[1:], 16)
        except ValueError:
            return data, None
        return data, (_crc24(data) == want)
    return data, None


def _packet_iter(data):
    """Yield (tag, body) for each OpenPGP packet. RFC 4880 section 4.2.

    Both header formats share the same bit layout -- bit 7 set, bit 6 selects
    the format, bits 5-2 are the tag, bits 1-0 the length type. The formats
    differ only in how length type 3 is interpreted: old format means "the body
    runs to the end of the stream", new format means a 5-octet length.
    """
    i, n = 0, len(data)
    while i < n:
        header = data[i]
        i += 1
        if not header & 0x80:  # bit 7 clear: not a packet header, stop
            return
        new_format = bool(header & 0x40)
        tag = (header >> 2) & 0x0F
        ltype = header & 0x03
        if ltype == 0:
            if i >= n:
                return
            length = data[i]
            i += 1
        elif ltype == 1:
            if i + 2 > n:
                return
            length = int.from_bytes(data[i:i + 2], "big")
            i += 2
        elif ltype == 2:
            if i + 4 > n:
                return
            length = int.from_bytes(data[i:i + 4], "big")
            i += 4
        else:  # length type 3
            if not new_format:
                yield tag, data[i:]
                return
            if i + 5 > n:
                return
            length = int.from_bytes(data[i:i + 5], "big")
            i += 5
        if i + length > n:
            return
        yield tag, data[i:i + length]
        i += length


def _public_key_body(data):
    """First tag-6 (Public-Key) packet body, i.e. the canonical key material."""
    for tag, body in _packet_iter(data):
        if tag == 6 and body:
            return body
    return None


def pgp_fingerprint(key_body):
    """RFC 4880 §12.2 fingerprint of a public-key packet body.

    v4: SHA-1 over 0x99 || len16 || body.  v6: SHA-256 over 0x9B || len32 || body.
    """
    if not key_body:
        return ""
    version = key_body[0]
    if version == 4:
        prefix = b"\x99" + len(key_body).to_bytes(2, "big")
        digest = hashlib.sha1(prefix + key_body).hexdigest().upper()
    elif version == 6:
        prefix = b"\x9b" + len(key_body).to_bytes(4, "big")
        digest = hashlib.sha256(prefix + key_body).hexdigest().upper()
    else:
        return ""
    return " ".join(digest[i:i + 4] for i in range(0, len(digest), 4))


def pgp_meta(block):
    """Identity facts about an armored public key.

    `key_sha` is the correlation identity: a hash of the canonical public-key
    packet bytes. Two personas presenting the same key produce the same
    `key_sha` no matter how the armor was wrapped or retyped, which the old
    text-hash approach could not do. `fingerprint` is the quotable v4/v6
    fingerprint and falls back to `key_sha` when the packet cannot be parsed.
    `corrupt` is True when the armor's CRC24 did not match, i.e. the paste was
    damaged -- the UIDs are still worth recording, but the key is not trusted
    for merging.
    """
    data, crc_ok = dearmor(block)
    key_body = _public_key_body(data) if data else None
    digest = hashlib.sha256(key_body).hexdigest().upper() if key_body else ""
    fingerprint = pgp_fingerprint(key_body) if key_body else ""

    # Real pasted key listings use both "UID" and "uid:", so match either.
    uid_emails = re.findall(r"uid.*?<([^>\s]+@[^>\s]+)>", block or "", re.I)
    algo = re.search(r"pub\s+(\S+)\s+\S+/(\w+)\s+(\d{4}-\d{2}-\d{2})", block or "", re.I)
    return {
        "fingerprint": fingerprint or digest,  # never fall back to the armor text
        "key_sha": digest,
        "key_id": fingerprint.replace(" ", "")[-16:] if fingerprint else "",
        "algo": algo.group(1) if algo else "",
        "bits": algo.group(2) if algo else "",
        "created": algo.group(3) if algo else "",
        "emails": uid_emails,
        "corrupt": crc_ok is False,
    }


def extract_identifiers(text, provenance="prose"):
    """Extract identity identifiers from text.

    `provenance` records whether `text` was visible prose (safe to merge on) or
    unfiltered markup (retained for search, never merged). Callers that hold raw
    HTML should run it through visible_text() and keep the default; only code
    that deliberately mines markup should pass "markup".
    """
    out = []
    seen = set()
    for m in PGP_BLOCK.finditer(text):
        meta = pgp_meta(m.group(0))
        key = ("pgp", meta["fingerprint"])
        if key not in seen:
            seen.add(key)
            out.append({"kind": "pgp", "value": meta["fingerprint"],
                        "detail": "; ".join(meta["emails"]) or meta["algo"],
                        "method": "extract:pgp"})
        for e in meta["emails"]:
            k = ("email", e.lower())
            if k not in seen:
                seen.add(k)
                out.append({"kind": "pgp_email", "value": e.lower(),
                            "detail": meta["fingerprint"], "method": "extract:pgp_email"})
    for lbl, rx, dpol in (("btc", BTC, lambda m: m.group(0)),
                          ("xmr", XMR, lambda m: m.group(0)),
                          ("email", EMAIL, lambda m: m.group(0).lower()),
                          ("jabber", JABBER, lambda m: m.group(0).lower()),
                          ("onion", ONION_ALL, lambda m: m.group(0)),
                          ("icq", ICQ, lambda m: m.group(1))):
        for m in rx.finditer(text):
            v = dpol(m)
            k = (lbl, v)
            if k not in seen and v and not v.endswith(".onion.onion"):
                seen.add(k)
                out.append({"kind": lbl, "value": v, "detail": "",
                            "method": f"extract:{lbl}"})
    # telegram handles from @mentions (post-author excluded outside)
    tg_method = TELEGRAM_PROSE if provenance == "prose" else TELEGRAM_MARKUP
    for m in TELEGRAM.finditer(text):
        v = m.group(1)
        k = ("telegram", v)
        if k in seen or not is_plausible_handle(v):
            continue
        if v.lower() in _TG_STOPWORDS:
            continue
        seen.add(k)
        out.append({"kind": "telegram", "value": v, "detail": "", "method": tg_method})
    return out


def content_hash(text):
    return hashlib.sha1(text.encode("utf-8", "ignore")).hexdigest()


def extract_page_handles(text):
    """Selector-free handle recovery: harvests handles from raw page text
    (telegram @mentions, ICQ, keybase/session/wire) when DOM selectors miss them.

    Returns a list of dicts with ``kind`` (telegram/icq/keybase/session/wire)
    and ``value``; caller decides how to attribute. Never raises."""
    out = []
    seen = set()
    for rx, kind in ((TELEGRAM, "telegram"), (ICQ, "icq"),
                     (KEYBASE, "keybase"), (SESSION_ID, "session"),
                     (WIRE_HANDLE, "wire")):
        for m in rx.finditer(text or ""):
            v = m.group(0) if rx is SESSION_ID else (m.group(1) if m.groups() else m.group(0))
            v = v.strip(" ,.:;")
            if not v or v.lower() in ("onionscan", "telegram", "tor", "signal",
                                      "proton", "wire", "keybase", "session"):
                continue
            if kind == "icq" and v.lower().startswith("icq"):
                v = m.group(1)
            if kind == "session":
                v = v.lower()
            key = (kind, v.lower())
            if key in seen:
                continue
            seen.add(key)
            out.append({"kind": kind, "value": v})
    return out


def bucket_handles(posts):
    hb = {}
    for p in posts:
        hb.setdefault(p.get("handle") or "anon", []).append(p)
    return hb