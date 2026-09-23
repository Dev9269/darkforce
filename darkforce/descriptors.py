"""Tor service descriptor consistency checks (Onionoo-backed).

Compares a relay/service's *declared* facts (what a descriptor advertises,
fetched via the same free Onionoo endpoint seeds.collect_onionoo uses) against
what we *observed* locally (ports, Tor version, liveness, first contact) and
flags inconsistencies as ``descriptor_anomaly`` findings.

Onionoo has no hidden-service records, so for real .onion lookups the declared
facts are typically empty and checks return []; the module still carries the
full declared-vs-observed engine, which is exercised against relay records and
is ready to consume any descriptor source.
"""

import datetime
import json
import re

from . import seeds

DESCRIPTOR_ANOMALY = "descriptor_anomaly"
ONIONOO_URL = "https://onionoo.torproject.org/details"
ONIONOO_FIELDS = ("nickname,fingerprint,first_seen,last_seen,running,platform,"
                  "family,country,as,flags,or_addresses,dir_addresses")


def _parse_dt(value):
    if not value:
        return None
    try:
        dt = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt
    except (TypeError, ValueError):
        return None


def _tor_version(value):
    m = re.search(r"Tor\s+([0-9][\w.\-]*)", value or "")
    return m.group(1) if m else ((value or "").strip() or None)


def _declared_from_onionoo(data):
    """First relay/bridge record -> declared-facts dict, or None when absent."""
    for node in (data.get("relays") or []) + (data.get("bridges") or []):
        if not node.get("fingerprint"):
            continue
        ports = []
        for key in ("or_addresses", "dir_addresses"):
            for addr in node.get(key) or []:
                m = re.search(r":(\d+)$", str(addr))
                if m:
                    ports.append(int(m.group(1)))
        family = [f for f in (node.get("family") or []) if isinstance(f, str) and f]
        return {
            "address": (node.get("nickname") or ""),
            "ports": ports,
            "version": _tor_version(node.get("platform")),
            "family": family,
            "first_seen": node.get("first_seen"),
            "last_seen": node.get("last_seen"),
            "running": bool(node.get("running")),
        }
    return None


def check_descriptor(address, declared=None, observed=None):
    """Compare declared vs observed Tor facts.

    declared: {ports:[int], version:str, family:[str], first_seen:iso,
               running:bool}
    observed: {ports:[int], version:str, alive:bool, first_seen:iso}

    Returns [(kind, severity, detail, confidence), ...] with kind
    descriptor_anomaly.
    """
    declared = declared or {}
    observed = observed or {}
    label = address or declared.get("address", "")
    out = []

    dports = set(declared.get("ports") or [])
    oports = set(observed.get("ports") or [])
    if dports and oports and dports != oports:
        bits = []
        extra = sorted(dports - oports)
        missing = sorted(oports - dports)
        if extra:
            bits.append(f"declared {extra} not observed")
        if missing:
            bits.append(f"observed {missing} not declared")
        out.append((DESCRIPTOR_ANOMALY, "high",
                    f"{label}: port mismatch ({'; '.join(bits)})", 0.7))

    dver = _tor_version(declared.get("version"))
    over = (observed.get("version") or "").strip() or None
    if dver and over and dver != over:
        out.append((DESCRIPTOR_ANOMALY, "medium",
                    f"{label}: version mismatch (declared {dver}, observed {over})",
                    0.55))

    family = [f for f in (declared.get("family") or []) if f]
    if family:
        out.append((DESCRIPTOR_ANOMALY, "low",
                    f"{label}: declared family links {len(family)} peer(s): "
                    f"{', '.join(family[:3])}", 0.45))

    d_first = _parse_dt(declared.get("first_seen"))
    o_first = _parse_dt(observed.get("first_seen"))
    if d_first and o_first and d_first > o_first:
        out.append((DESCRIPTOR_ANOMALY, "high",
                    f"{label}: descriptor age inconsistent (declared seen "
                    f"{d_first} after observed {o_first})", 0.85))
    elif d_first and (datetime.datetime.now(datetime.timezone.utc) - d_first).days < 7:
        out.append((DESCRIPTOR_ANOMALY, "low",
                    f"{label}: descriptor recently registered (age < 7 days)",
                    0.4))

    drun = declared.get("running")
    oalive = observed.get("alive")
    if drun is not None and oalive is not None and bool(drun) != bool(oalive):
        out.append((DESCRIPTOR_ANOMALY, "high",
                    f"{label}: descriptor running={bool(drun)} but observed "
                    f"alive={bool(oalive)}", 0.8))

    return out


def fetch_onionoo_search(address, timeout=15):
    """Query Onionoo details search for the address (pattern reused from seeds)."""
    r = seeds._get(
        ONIONOO_URL,
        params={"search": address, "fields": ONIONOO_FIELDS},
        timeout=timeout,
        headers={"User-Agent": "Mozilla/5.0"},
    )
    if not r or r.status_code != 200:
        return {"relays": [], "bridges": []}
    try:
        return json.loads(r.text)
    except Exception:
        return {"relays": [], "bridges": []}


def check_onion_descriptor(address, observed=None, timeout=15):
    """Onionoo-backed descriptor check for a given onion/relay address."""
    data = fetch_onionoo_search(address, timeout=timeout)
    declared = _declared_from_onionoo(data)
    if not declared:
        return []
    return check_descriptor(address, declared=declared, observed=observed)