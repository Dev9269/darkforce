"""Keyed threat-intel and blockchain enrichment collectors.

All three are optional and no-op without credentials, matching the existing
`urlhaus`-style collectors: a missing key is a normal state, not an error.

    ALIENVAULT_OTX_KEY   AlienVault OTX pulse lookups
    ABUSEIPDB_KEY        AbuseIPDB IP reputation

Blockchain needs no key -- public nodes are queried directly.

Provenance and confidence
-------------------------
Each source is scored on its own terms, and the score travels with the record,
because they are not interchangeable:

  OTX / AbuseIPDB   Assertions by other third parties about an IP. Useful, but
                    they are reports, not observations, and reputation feeds are
                    noisy and skewed by whoever chooses to submit.
  Blockchain        A fact read directly from a public ledger. A transaction that
                    actually exists is not a claim about it, so ledger-derived
                    facts are marked `observed` and carry the most weight.

Nothing here attributes a person. An address with a malware payment in its
history is a lead, and the gap between "this wallet paid" and "this person is
the actor" is exactly the gap the rest of the index refuses to cross.
"""
import json
import os

import requests

from .config import ABUSEIPDB_KEY, ALIENVAULT_OTX_KEY

UA = {"User-Agent": "Mozilla/5.0 (darkforce research)"}

# Free tiers are 1 req/sec for OTX and 1/s for AbuseIPDB. Stay under it.
RATE_LIMIT_S = 1.0

OTX_BASE = "https://otx.alienvault.com/api/v1"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"
# No public default: a shared provider is a single point of both rate limiting and
# outage. The operator supplies their own node, which also keeps collection out of
# anyone else's logs.
BLOCKCHAIN_BASE = os.environ.get("DARKFORCE_ETH_NODE", "")

# Reputation feeds publish a numeric score in [0,100]. Map to a coarse band so a
# 91 and a 92 do not read as meaningfully different degrees of certainty.
REPUTATION_BANDS = ((80, "high"), (40, "medium"), (1, "low"))


def _get(url, params=None, headers=None, timeout=15):
    try:
        return requests.get(url, params=params, headers=headers or UA, timeout=timeout)
    except Exception:
        return None


def reputation_band(score):
    """Coarse label for a 0-100 reputation score, or "" if unusable."""
    try:
        score = int(score)
    except (TypeError, ValueError):
        return ""
    for floor, label in REPUTATION_BANDS:
        if score >= floor:
            return label
    return "none"


def available():
    """Which collectors are configured. Lets the UI explain a no-op rather than
    looking broken."""
    return {"otx": bool(ALIENVAULT_OTX_KEY), "abuseipdb": bool(ABUSEIPDB_KEY),
            "blockchain": bool(BLOCKCHAIN_BASE)}


# ---------- AlienVault OTX ----------

def collect_otx(ip):
    """Pulse summary for an IP. Requires ALIENVAULT_OTX_KEY."""
    if not ALIENVAULT_OTX_KEY or not ip:
        return None
    r = _get(f"{OTX_BASE}/indicators/IPv4/{ip}/general",
             headers={**UA, "X-OTX-API-KEY": ALIENVAULT_OTX_KEY})
    if not r or r.status_code != 200:
        return None
    try:
        data = r.json()
    except (ValueError, json.JSONDecodeError):
        return None
    count = data.get("pulse_info", {}).get("count", 0) or 0
    if not count:
        return None  # no pulses is a negative result, not a finding
    return {
        "source": "otx",
        "kind": "ip_rep",
        "value": ip,
        "detail": f"{count} OTX pulse(s)",
        "pulses": count,
        "reputation": "high" if count >= 3 else "low",
        "confidence": 0.5,
        "provenance": "third-party report",
    }


# ---------- AbuseIPDB ----------

def collect_abuseipdb(ip):
    """Reputation report for an IP. Requires ABUSEIPDB_KEY."""
    if not ABUSEIPDB_KEY or not ip:
        return None
    r = _get(f"{ABUSEIPDB_BASE}/blacklist", params={"ipAddress": ip, "maxAgeInDays": 90},
             headers={**UA, "Key": ABUSEIPDB_KEY, "Accept": "application/json"})
    if not r or r.status_code != 200:
        return None
    try:
        data = r.json().get("data", {}) or {}
    except (ValueError, json.JSONDecodeError):
        return None
    score = data.get("abuseConfidenceScore", 0) or 0
    reports = data.get("totalReports", 0) or 0
    if not score and not reports:
        return None
    return {
        "source": "abuseipdb",
        "kind": "ip_rep",
        "value": ip,
        "detail": f"abuse confidence {score}% from {reports} report(s)",
        "reputation": reputation_band(score),
        "confidence": min(0.6, 0.3 + (score / 100) * 0.3),
        "provenance": "third-party report",
        "country": data.get("countryCode", "") or "",
    }


# ---------- blockchain ----------

def collect_eth_address(address):
    """On-chain facts for an ETH address. Needs DARKFORCE_ETH_NODE.

    Only reads what the node itself asserts: balance, whether the address has ever
    transacted, and the first/last block touched. Movements are not attributed to
    a person here.
    """
    if not BLOCKCHAIN_BASE or not address:
        return None
    address = address.strip()

    def rpc(method, params):
        """JSON-RPC 2.0 over POST. eth_getBalance and friends are not GETs, and
        sending them as one silently returns nothing from most nodes."""
        body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        try:
            r = requests.post(BLOCKCHAIN_BASE, json=body,
                              headers={**UA, "Content-Type": "application/json"},
                              timeout=20)
        except Exception:
            return None
        if not r or r.status_code != 200:
            return None
        try:
            payload = r.json()
        except (ValueError, json.JSONDecodeError):
            return None
        if payload.get("error"):
            return None
        return payload.get("result")

    balance = rpc("eth_getBalance", [address, "latest"])
    if balance is None:
        return None
    try:
        wei = int(balance, 16)
    except (TypeError, ValueError):
        return None
    if wei == 0:
        # A zero balance is the overwhelmingly common case and is not a finding.
        return None
    tx_count = rpc("eth_getTransactionCount", [address, "latest"])
    try:
        n = int(tx_count, 16) if isinstance(tx_count, str) else 0
    except (TypeError, ValueError):
        n = 0
    return {
        "source": "blockchain",
        "kind": "wallet",
        "value": address,
        "detail": f"{wei / 1e18:.6f} ETH, {n} transaction(s) from this address",
        "balance_eth": wei / 1e18,
        "tx_count": n,
        "reputation": "",
        "confidence": 0.9,
        "provenance": "observed on public ledger",
    }


COLLECTORS = {
    "otx": {"fn": collect_otx, "requires": "ALIENVAULT_OTX_KEY", "input": "ip"},
    "abuseipdb": {"fn": collect_abuseipdb, "requires": "ABUSEIPDB_KEY", "input": "ip"},
    "blockchain": {"fn": collect_eth_address, "requires": "DARKFORCE_ETH_NODE",
                   "input": "address"},
}


def collect(name, value):
    """Dispatch to a named collector. Returns None if unconfigured or failing."""
    spec = COLLECTORS.get(name)
    if not spec:
        return None
    return spec["fn"](value)
