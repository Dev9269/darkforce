import hashlib
import json
import os
import re
import shutil
import subprocess

from .extract import IP

MOD_STATUS_RE = re.compile(r"Apache(\s+Server\s+Status)?|Server:\s+Apache", re.I)
SERVER_STATUS_IP = re.compile(r"\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.)[\d.]*\b")
UA_ANALYTICS = re.compile(r"\b(UA-\d{4,10}-\d|G-[A-Z0-9]{10,14})\b")

SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}

_MATCH_LABELS = {
    "favicon_match": "Favicon hash matches clearnet host",
    "mirror_match": "Same page content as clearnet host",
    "analytics_match": "Analytics ID shared with clearnet host",
    "banner_match": "Server banner identical to clearnet host",
}
_MATCH_SEVERITY = {"favicon_match": "critical", "mirror_match": "critical",
                   "analytics_match": "high", "banner_match": "high"}


class Snap:
    def __init__(self, url="", headers=None, html="", favicon=None, meta=None):
        self.url = url
        self.headers = headers or {}
        self.html = html or ""
        self.favicon = favicon  # bytes or None
        self.meta = meta or {}  # extra: tls_cn, cert_sans, ssh_fp, hostname


def _hash(b):
    return hashlib.sha1(b).hexdigest() if b else None


def _clearnet_names(*values):
    """Names from CN/SAN values that look like public clearnet domains
    (non-onion, dotted, not loopback) - correlators worth flagging."""
    out = []
    for raw in values:
        for name in re.split(r"[,\s]+", raw or ""):
            name = name.strip().lower().rstrip(".")
            if name and "." in name and not name.endswith(".onion") \
                    and name not in ("localhost", "127.0.0.1"):
                out.append(name)
    return sorted(set(out))


def fingerprint(snap):
    """Stable identifiers that allow cross-site correlation."""
    h = _hash(snap.favicon)
    c = hashlib.sha1(snap.html.encode("utf-8", "ignore")).hexdigest()
    return {
        "favicon_hash": h,
        "content_hash": c,
        "server": (snap.headers.get("Server") or "").strip(),
        "powered": (snap.headers.get("X-Powered-By") or "").strip(),
        "via": (snap.headers.get("Via") or snap.headers.get("X-Forwarded-For") or "").strip(),
        "host": snap.meta.get("hostname", ""),
        "tls_cn": snap.meta.get("tls_cn", ""),
        "cert_sans": snap.meta.get("cert_sans", ""),
        "tls_issuer": snap.meta.get("tls_issuer", ""),
        "cert_fp": snap.meta.get("cert_fp", ""),
        "tls_protocol": snap.meta.get("tls_protocol", ""),
        "tls_cipher": snap.meta.get("tls_cipher", ""),
        "ssh_fp": snap.meta.get("ssh_fp", ""),
    }


def scan(snap, clearnet_index=None):
    """Run misconfiguration checks. clearnet_index: {favicon_hash: desc, content_hash: desc}"""
    out = []
    fp = fingerprint(snap)
    html = snap.html
    url = snap.url

    if fp["server"]:
        out.append(("server_banner", "medium", f"Default server banner exposed: {fp['server']}", 0.6))
    if fp["powered"]:
        out.append(("server_banner", "medium", f"Framework leak: X-Powered-By: {fp['powered']}", 0.6))
    if fp["via"]:
        out.append(("proxy_leak", "high", f"Proxy/Via header echoes backend: {fp['via']}", 0.85))
    cert_names = _clearnet_names(fp["tls_cn"], fp["cert_sans"])
    if cert_names:
        out.append(("tls_cert", "high",
                    f"TLS cert names clearnet domain(s): {', '.join(cert_names)}", 0.8))
    if fp["ssh_fp"]:
        out.append(("ssh_key", "high", f"SSH host key fingerprint exposed (correlatable): {fp['ssh_fp']}", 0.85))

    if re.search(r"/(server-status|server-info)\b", html, re.I) or "Apache Server Status" in html:
        ips = set(SERVER_STATUS_IP.findall(html))
        detail = f"Apache mod_status exposed; backend IPs leaked: {', '.join(sorted(ips)) or 'none parsed'}"
        out.append(("server_status", "critical", detail, 0.95))
    if "phpinfo()" in html or re.search(r"/phpinfo(\.php)?\b", html):
        out.append(("phpinfo", "high", "phpinfo() output reachable", 0.9))
    if "Index of /" in html or re.search(r"<title>Index of /", html, re.I):
        out.append(("dir_listing", "low", "Directory listing enabled", 0.5))
    if re.search(r"\.git/HEAD", html):
        out.append(("git_exposed", "high", ".git metadata reachable", 0.85))
    if re.search(r"(DB_PASSWORD|SECRET_KEY|AWS_SECRET|DATABASE_URL)\s*=", html):
        out.append(("env_exposed", "critical", "Environment variables (.env) leaked", 0.95))

    robots_internal = re.findall(r"[Hh]ost\s*:\s*([\w.-]+)", html)
    if robots_internal:
        out.append(("robots_hosts", "medium",
                    "robots.txt or page leaks internal hostnames: " + ", ".join(robots_internal[:3]), 0.55))

    ips = list(set(m for m in IP.findall(html) if not SERVER_STATUS_IP.search(m) and not m.startswith("172.16") ))[:5]
    ips = [m for m in ips if not re.match(r"^(?:255|0)\.", m)]
    if ips:
        out.append(("embedded_ip", "medium", "IP addresses embedded in page: " + ", ".join(ips), 0.6))

    analytics = list(set(UA_ANALYTICS.findall(html)))
    if analytics:
        out.append(("analytics_id", "medium", "Analytics / tracker IDs (correlator): " + ", ".join(analytics), 0.65))

    if clearnet_index:
        for m in _clearnet_matches(fp, analytics, clearnet_index):
            label = _MATCH_LABELS.get(m["kind"], "Fingerprint matches clearnet host")
            out.append((m["kind"], _MATCH_SEVERITY.get(m["kind"], "high"),
                        f"{label}: {m['host']}", m["confidence"]))

    return out, fp


def _clearnet_matches(fp, analytics, clearnet_index):
    """Resolve clearnet correlation matches from either a ClearnetIndex object
    or a legacy {value: host-label} dict. Each match keeps the shape:
        {kind, host, title, attribute, value, confidence}
    """
    if hasattr(clearnet_index, "lookup"):
        return clearnet_index.lookup(fp, analytics)
    out = []
    for field, kind in (("favicon_hash", "favicon_match"), ("content_hash", "mirror_match")):
        value = fp.get(field)
        if value and value in clearnet_index:
            out.append({"kind": kind, "host": clearnet_index[value], "title": "",
                        "attribute": field, "value": value, "confidence": 0.9})
    return out


def severity_rank(s):
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0)


def pipeline_findings(site_id, db, findings, fps, url="", source_id=None, method="detect"):
    rows = []
    for kind, sev, detail, conf in findings:
        db.add_finding(site_id, kind, sev, detail, conf, url=url,
                       source_id=source_id, method=method)
        rows.append({"kind": kind, "severity": sev, "detail": detail, "confidence": conf})
    return rows


def onionscan(url, exe=None, timeout=120):
    """Optional deep scan via the OnionScan tool (github.com/s-rah/onionscan).

    OnionScan is a Go binary that isn't shipped with DarkForce. If the binary
    isn't installed, this returns an empty list and the pipeline keeps going
    (we never fail a crawl just because an auxiliary tool is missing).
    """
    if not url.endswith(".onion"):
        return []
    exe = exe or os.environ.get("ONIONSCAN") or shutil.which("onionscan")
    if not exe:
        return []
    try:
        r = subprocess.run(
            [exe, "--jsonReport", url],
            capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        return [("onionscan", "low", f"OnionScan run error: {e}", 0.3)]
    if r.returncode != 0 or not r.stdout.strip():
        return []
    try:
        report = json.loads(r.stdout)
    except Exception:
        return [("onionscan", "low", "OnionScan returned non-JSON output", 0.3)]
    out = []
    if report.get("pgpKeysMatched"):
        out.append(("onionscan_pgp", "high", "OnionScan matched PGP keys on the site", 0.8))
    for key in ("relatedServices", "linkedSites"):
        if report.get(key):
            out.append(("onionscan_linked", "medium",
                        f"OnionScan found linked/related service: {', '.join(map(str, report[key][:4]))}", 0.7))
    if report.get("bitcoinAddresses"):
        out.append(("onionscan_btc", "high",
                    f"OnionScan extracted Bitcoin addresses: {', '.join(map(str, report['bitcoinAddresses'][:4]))}", 0.8))
    if report.get("interestingFiles"):
        out.append(("onionscan_files", "medium",
                    "Interesting files exposed: " + ", ".join(map(str, report["interestingFiles"][:4])), 0.7))
    if report.get("serverVersion"):
        out.append(("onionscan_server", "medium",
                    f"Server version: {report['serverVersion']}", 0.6))
    return out