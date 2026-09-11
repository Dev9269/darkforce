import hashlib
import re

from .extract import IP

MOD_STATUS_RE = re.compile(r"Apache(\s+Server\s+Status)?|Server:\s+Apache", re.I)
SERVER_STATUS_IP = re.compile(r"\b(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|127\.)[\d.]*\b")
UA_ANALYTICS = re.compile(r"\b(UA-\d{4,10}-\d|G-[A-Z0-9]{10,14})\b")

SEVERITY_WEIGHT = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}


class Snap:
    def __init__(self, url="", headers=None, html="", favicon=None, meta=None):
        self.url = url
        self.headers = headers or {}
        self.html = html or ""
        self.favicon = favicon  # bytes or None
        self.meta = meta or {}  # extra: tls_cn, cert_sans, ssh_fp, hostname


def _hash(b):
    return hashlib.sha1(b).hexdigest() if b else None


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
    if fp["tls_cn"]:
        out.append(("tls_cert", "high", f"TLS cert CN names clearnet domain: {fp['tls_cn']}", 0.8))
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
        if fp["favicon_hash"] and fp["favicon_hash"] in clearnet_index:
            out.append(("favicon_match", "critical",
                        f"Favicon hash matches clearnet host: {clearnet_index[fp['favicon_hash']]}", 0.9))
        if fp["content_hash"] and fp["content_hash"] in clearnet_index:
            out.append(("mirror_match", "critical",
                        f"Same page content as clearnet host: {clearnet_index[fp['content_hash']]}", 0.9))
        if fp["server"] and fp["server"] in [v.get("server") for v in clearnet_index.values() if isinstance(v, dict)]:
            out.append(("banner_match", "high", "Server banner identical to a clearnet host", 0.75))

    return out, fp


def severity_rank(s):
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(s, 0)


def pipeline_findings(site_id, db, findings, fps):
    rows = []
    for kind, sev, detail, conf in findings:
        db.add_finding(site_id, kind, sev, detail, conf)
        rows.append({"kind": kind, "severity": sev, "detail": detail, "confidence": conf})
    return rows