"""Keyword-based site categorization.

Maps a site title/URL/raw text to a threat-ops category using a robust,
order-independent keyword set. Used at ingest time and by the collection
pipeline so every site in the register carries an analyst-readable purpose.
"""
import re

# Canonical threat-ops taxonomy shown in the UI filter. Every raw category
# (classifier output, seed source tags, legacy rows) normalizes to one of these.
CANONICAL = [
    "drugs",
    "hacking",
    "markets",
    "financial/carding",
    "crypto",
    "weapons",
    "privacy/hosting",
    "directories",
    "ransomware",
    "malware",
    "other",
]

_ALIASES = {
    "financial": "financial/carding",
    "privacy": "privacy/hosting",
    "market": "markets",
    "marketplace": "markets",
    "ransom": "ransomware",
    "directory": "directories",
    "search": "directories",
    "onion": "other",
    "clearnet": "other",
    "seed": "other",
    "scanned": "other",
    "telegram-chat": "other",
    "forum": "other",
}


def normalize_category(raw):
    """Map any raw category string onto the canonical taxonomy (defaults to 'other')."""
    if not raw:
        return "other"
    key = str(raw).strip().lower()
    if key in CANONICAL:
        return key
    return _ALIASES.get(key, "other")

# Order matters: first matching group wins.
RULES = [
    "hacking",
    "drugs",
    "weapons",
    "financial",
    "crypto",
    "markets",
    "privacy",
    "ransomware",
    "malware",
    "directories",
    "other",
]

KEYWORDS = {
    "drugs": [
        r"\bketamine\b", r"\bpercocet\b", r"\bxanax\b", r"\balprazolam\b",
        r"\bdesoxyn\b", r"\bcannabis\b", r"\bweed\b", r"\bmarijuana\b",
        r"\bpsychedelic", r"\bmushroom", r"\blsd\b", r"\bmdma\b",
        r"\bopioid", r"\bdrug", r"\bpill", r"\bnarcotic", r"\bovernight.*pill",
        r"\bstero", r"\bpharmaceutical", r"\bvinia\b", r"\bameth\b",
        r"\bbuy .* (powder|pills|pills?|bars)\b",
    ],
    "hacking": [
        r"\bhacker", r"\bhacking", r"\bexploit", r"\bzeroday\b",
        r"\bRAT\b", r"\bFUD\b", r"\bcrypter\b", r"\bbackdoor\b",
        r"\bsurveillance", r"\bmonitor\b", r"\bhack service",
        r"\bprofessional hacker", r"\belite hacking", r"\bblack hat",
    ],
    "weapons": [
        r"\bgun\b", r"\bweapon", r"\bfirearm", r"\bammo", r"\bammunition",
        r"\bsilencer", r"\btrafficking .* gun", r"\bbuy .* (gun|ammo)\b",
    ],
    "financial": [
        r"\bclone card", r"\bbank log", r"\bpaypal", r"\bcashapp\b",
        r"\bvisa\b", r"\bmastercard", r"\bwestern union", r"\bgift card",
        r"\btransfer", r"\bcc\b", r"\bcvv", r"\bdumps", r"\bbank[- ]log",
        r"\bchecking\b", r"\blogs\b", r"\bfinancial", r"\bescrow\b",
        r"\bcarding", r"\bstolen (card|credit)", r"\bprepaid",
    ],
    "crypto": [
        r"\bbitcoin", r"\bbtc\b", r"\bmixer", r"\bwallet",
        r"\bethereum", r"\bcrypto", r"\btumbler", r"\bcoin\b",
        r"\bxmr\b", r"\bmonero",
    ],
    "markets": [
        r"\bmarket", r"\bmarketplace", r"\bshop\b", r"\bstore\b",
        r"\bvendor", r"\bescrow\b", r"\bdarkweb", r"\bmarket link",
        r"\bmarketplace\b", r"\bboutique",
    ],
    "privacy": [
        r"\bvpn\b", r"\bhosting", r"\bkv\s*m\b", r"\bprivacy",
        r"\banonymous", r"\bproxy", r"\bsocks", r"\btor relay",
        r"\bencrypt", r"\bsecure", r"\bno[- ]kyc\b",
    ],
    "ransomware": [
        r"\bransom", r"\bleak", r"\bdox\b", r"\bextortion",
        r"\bransomware",
    ],
    "malware": [
        r"\bmalware", r"\bmirai", r"\bc2\b", r"\bbotnet",
        r"\bstealer", r"\btrojan", r"\bminer", r"\bmonero.*rce",
    ],
    "directories": [
        r"\bonion", r"\bdirectory", r"\bwiki\b", r"\blink list",
        r"\bindex\b", r"\bsearch", r"\brepository", r"\bonion dir",
        r"\bonions", r"\bsearch engine", r"\bwiki\b",
    ],
    "other": [r"(?!)"],  # never matches; explicit fallback below
}

_PATTERNS = None


def _patterns():
    global _PATTERNS
    if _PATTERNS is None:
        _PATTERNS = {group: re.compile("|".join(keys), re.I)
                     for group, keys in KEYWORDS.items()}
    return _PATTERNS


def classify_site(title="", url="", text=""):
    """Return the best-effort category for a site.

    Tries title first (most indicative), then url, then any scraped text.
    Returns "other" when nothing matches so the UI never shows an empty tag.
    """
    blob = " ".join([title or "", url or "", text or ""])
    pats = _patterns()
    for group in RULES:
        if pats[group].search(blob):
            return group
    return "other"