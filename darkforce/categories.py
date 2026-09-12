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
    "forgery",
    "counterfeit",
    "fraud/scam",
    "extremism",
    "gambling",
    "forums",
    "privacy/hosting",
    "directories",
    "ransomware",
    "malware",
    "leaked data",
    "hitman",
    "porn",
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
    "porn": "porn",
    "adult": "porn",
    "leak": "leaked data",
    "leaks": "leaked data",
    "dump": "leaked data",
    "dumps": "leaked data",
    "data": "leaked data",
    "dox": "leaked data",
    "hitman": "hitman",
    "assassination": "hitman",
    "forgery": "forgery",
    "document": "forgery",
    "passport": "forgery",
    "fake id": "forgery",
    "counterfeit": "counterfeit",
    "fraud": "fraud/scam",
    "scam": "fraud/scam",
    "scams": "fraud/scam",
    "phishing": "fraud/scam",
    "sextortion": "fraud/scam",
    "terror": "extremism",
    "terrorism": "extremism",
    "extremist": "extremism",
    "gambling": "gambling",
    "casino": "gambling",
    "betting": "gambling",
    "forum": "forums",
    "discussion": "forums",
    "chat": "forums",
    "social": "forums",
    "onion": "other",
    "clearnet": "other",
    "seed": "other",
    "scanned": "other",
    "telegram-chat": "other",
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
    "hitman",
    "porn",
    "leaked data",
    "forgery",
    "counterfeit",
    "fraud/scam",
    "extremism",
    "gambling",
    "forums",
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
    "hitman": [
        r"\bhitman", r"\bhit man", r"\bcontract killer", r"\bkill for hire",
        r"\bassassin", r"\bassassination", r"\bmurder for hire",
        r"\bhire a killer", r"\bpay.*kill", r"\bcontract killing",
    ],
    "leaked data": [
        r"\bleak(s)?\b", r"\bbreach(ed)?\b", r"\bdatabase dump", r"\bdata dump",
        r"\bdumped", r"\bcombo list", r"\bcredential dump", r"\bexposed",
        r"\bstealer log", r"\bcredential leak", r"\bstolen data",
        r"\bpersonal data", r"\bdatabas.* sale", r"\bsell.*database",
        r"\bhacked database", r"\buser data", r"\bpasswords? list",
        r"\bdata breach", r"\bbreach data", r"\bleaked", r"\bexposed db",
    ],
    "forgery": [
        r"\bpassport", r"\bfake id", r"\bfake documents?", r"\bdrivers? licence",
        r"\bdriver.?s license", r"\bidentity", r"\bbirth certificate",
        r"\bproof of address", r"\bfake diploma", r"\bcounterfeit documents?",
        r"\bforged", r"\bforgery", r"\bids?\b", r"\bid card",
        r"\bssn\b", r"\bsocial security", r"\bdegrees?\b", r"\bcertificates?\b",
    ],
    "counterfeit": [
        r"\bcounterfeit", r"\bprinter", r"\bfake (currency|money|dollars?|euros?|bills?)",
        r"\breplica", r"\bknockoff", r"\bfake (goods|products?|bags?|shoes?|watches?)",
        r"\bsuperfake", r"\breps?\b", r"\bfake rolex", r"\bfake gucci",
    ],
    "fraud/scam": [
        r"\bphishing", r"\bsextortion", r"\bscam", r"\bscams", r"\bfraud",
        r"\bspoof", r"\bclone.?site", r"\badvance.?fee", r"\bransomware asa",
        r"\btax fraud", r"\bchargeback services?", r"\bcarded days",
        r"\bethical.?hacker", r"\bvishing", r"\bsmishing", r"\bloan scam",
        r"\binvestment scam", r"\bponzi", r"\bfake store", r"\bchargeback",
    ],
    "extremism": [
        r"\bjihad", r"\bterror", r"\bterrorism", r"\baez\b", r"\bal.?qaeda",
        r"\bislamic state", r"\bisis\b", r"\bpropaganda", r"\bradicaliz",
        r"\bwhite.?supremac", r"\bskinhead", r"\bneo.?nazi", r"\brecruit",
        r"\bextremism", r"\bfascist", r"\bholocaust denial", r"\bconcentration camp",
    ],
    "gambling": [
        r"\bgambl", r"\bcasino", r"\bbet\b", r"\bbetting", r"\blottery",
        r"\bpoker", r"\bslots?\b", r"\bblackjack", r"\broulette", r"\bwagering",
    ],
    "forums": [
        r"\bforum", r"\bboard\b", r"\bdiscussion", r"\bcommunity",
        r"\bdread\b", r"\bchat\b", r"\bbulletin", r"\breddit-style",
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
    "porn": [
        r"\bporn\b", r"\bxxx\b", r"\badult\b", r"\bescort", r"\bsex\b",
        r"\bnsfw\b", r"\bonlyfans\b", r"\bplayboy\b", r"\bcam girl",
        r"\bcams\b", r"\bnude[sz]?\b", r"\bstripper", r"\bsexting\b",
        r"\bhentai\b", r"\bblower\b", r"\bwebcam\b", r"\bchild", r"\bcp\b",
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