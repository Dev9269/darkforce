import hashlib
import re
import unicodedata

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


def norm(t):
    t = unicodedata.normalize("NFKC", t or "")
    t = re.sub(r"[^\S\n]+", " ", t)
    return t


def pgp_meta(block):
    fpr = hashlib.sha256(block.encode("utf-8", "ignore")).hexdigest().upper()
    fp = " ".join(fpr[i : i + 4] for i in range(0, 40, 4))
    uid_emails = re.findall(r"UID.*?<([^>]+)>", block)
    algo = re.search(r"pub\s+(\S+)\s+\S+/(\w+)\s+(\d{4}-\d{2}-\d{2})", block, re.I)
    return {
        "fingerprint": fp,
        "algo": algo.group(1) if algo else "",
        "bits": algo.group(2) if algo else "",
        "created": algo.group(3) if algo else "",
        "emails": uid_emails,
    }


def extract_identifiers(text):
    out = []
    seen = set()
    for m in PGP_BLOCK.finditer(text):
        meta = pgp_meta(m.group(0))
        key = ("pgp", meta["fingerprint"])
        if key not in seen:
            seen.add(key)
            out.append({"kind": "pgp", "value": meta["fingerprint"],
                        "detail": "; ".join(meta["emails"]) or meta["algo"]})
        for e in meta["emails"]:
            k = ("email", e.lower())
            if k not in seen:
                seen.add(k)
                out.append({"kind": "pgp_email", "value": e.lower(), "detail": meta["fingerprint"]})
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
                out.append({"kind": lbl, "value": v, "detail": ""})
    # telegram handles from @mentions (post-author excluded outside)
    for m in TELEGRAM.finditer(text):
        v = m.group(1)
        k = ("telegram", v)
        if k not in seen and v.lower() not in ("onionscan", "telegram", "tor", "signal", "proton"):
            seen.add(k)
            out.append({"kind": "telegram", "value": v, "detail": ""})
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