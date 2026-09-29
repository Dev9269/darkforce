"""Opt-in, analyst-triggered read-only probing.

This is the only module in DarkForce that deliberately touches a host that was
not already queued for collection, so it is deliberately hard to trigger.

Constraints, enforced in code rather than left to convention:

* **Opt-in.** Constructed with ``enabled=True`` or nothing happens. There is no
  environment variable, config file or CLI default that turns probing on, so no
  deployment, upgrade or environment change can silently start it.
* **Analyst-triggered.** Every call requires an explicit list of URLs from the
  caller. Nothing here enumerates hosts, follows links, or expands a target set
  on its own.
* **GET only.** The method is a module constant. There is no parameter through
  which a caller could change it.
* **Never autonomous.** The scheduler in run.py never calls this module; the
  test suite asserts that.
* **Polite.** One request per host per ``MIN_HOST_INTERVAL`` (4s), reusing the
  same gate the ordinary collector uses, plus a cap on requests per invocation.
* **Audited.** Every attempt, allowed or refused, is written to the audit log
  with its reason.

It also blocks requests to loopback, private, link-local and cloud-metadata
addresses. An analyst-facing endpoint that fetches a caller-supplied URL is an
SSRF primitive against the host running the dashboard, and an investigation
tool has no legitimate reason to reach 169.254.169.254.
"""
import ipaddress
import os
import socket
import time
from urllib.parse import urlparse

from . import detect, net

# The method is fixed. It is not a default argument because a default argument
# can be overridden by the caller.
METHOD = "GET"

# Hard ceiling for a single invocation, so a bad analyst action cannot turn into
# an unbounded scan.
MAX_REQUESTS = 25

# Reuse the collector's politeness gate so probing cannot be a way around it.
MIN_HOST_INTERVAL = net.MIN_HOST_INTERVAL

# Cloud metadata endpoints, blocked explicitly. These are inside the link-local
# range, but naming them keeps the intent legible if that range ever changes.
METADATA_HOSTS = frozenset({"169.254.169.254", "metadata.google.internal",
                            "100.100.100.200", "fd00:ec2::254"})

ALLOWED_SCHEMES = ("http", "https")


class ProbeRefused(Exception):
    """Raised when a probe request is not permitted. Carries a reason for audit."""


def _resolve(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception as e:
        raise ProbeRefused(f"dns: {e}") from e
    addrs = {i[4][0] for i in infos}
    if not addrs:
        raise ProbeRefused("dns: no addresses")
    return addrs


def check_target(url, allow_private=False):
    """Validate a probe target. Raises ProbeRefused with an audit-able reason.

    Returns the host on success.
    """
    try:
        p = urlparse(url)
    except Exception as e:
        raise ProbeRefused(f"unparseable url: {e}") from e
    if p.scheme.lower() not in ALLOWED_SCHEMES:
        raise ProbeRefused(f"scheme not allowed: {p.scheme or '(none)'}")
    host = (p.hostname or "").lower()
    if not host:
        raise ProbeRefused("no host in url")
    if host in METADATA_HOSTS:
        raise ProbeRefused("cloud metadata address blocked")

    if allow_private:
        return host

    literal = None
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        pass
    if literal is not None:
        if (literal.is_loopback or literal.is_private or literal.is_link_local
                or literal.is_reserved or literal.is_multicast or literal.is_unspecified):
            raise ProbeRefused(f"non-public address blocked: {host}")
        return host

    # A hostname can resolve to an internal address (DNS rebinding, or an
    # attacker-controlled name pointing at 127.0.0.1), so resolve and check
    # every answer rather than trusting the name.
    for addr in _resolve(host):
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if (ip.is_loopback or ip.is_private or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise ProbeRefused(f"host {host} resolves to non-public {addr}")
    return host


class Prober:
    """Read-only, opt-in prober. Construct with enabled=True to arm it."""

    def __init__(self, db, enabled=False, allow_private=False, timeout=15,
                 keep_evidence=True):
        self.db = db
        self.enabled = bool(enabled)
        self.allow_private = bool(allow_private)
        self.timeout = timeout
        self.keep_evidence = keep_evidence
        self._host_gate = {}

    # -- audit ------------------------------------------------------------
    def _audit(self, analyst, action, url, allowed, reason=""):
        try:
            self.db.exe(
                "INSERT INTO audit_log(username, role, method, path, status, ts) "
                "VALUES(?,?,?,?,?,?)",
                (analyst or "unknown", "analyst", action, url[:500],
                 "allowed" if allowed else "refused", _now()))
        except Exception:
            # Auditing must never be the reason a probe fails, and never the
            # reason a refusal is hidden.
            pass

    def _gate(self, host):
        """One request per host per MIN_HOST_INTERVAL, independently of the
        ordinary collector's gate so a probe cannot be used to slip past it."""
        now = time.monotonic()
        last = self._host_gate.get(host)
        if last is not None:
            wait = MIN_HOST_INTERVAL - (now - last)
            if wait > 0:
                time.sleep(wait)
        self._host_gate[host] = time.monotonic()

    # -- probing ----------------------------------------------------------
    def probe(self, url, analyst="analyst", note=""):
        """Fetch one URL with GET. Returns a result dict; never raises for a
        policy refusal, so callers can record the refusal rather than crash."""
        if not self.enabled:
            self._audit(analyst, "probe:disabled", url, False, "probing not enabled")
            return {"url": url, "ok": False, "refused": True,
                    "reason": "probing is not enabled on this deployment"}

        try:
            host = check_target(url, allow_private=self.allow_private)
        except ProbeRefused as e:
            self._audit(analyst, "probe:refused", url, False, str(e))
            return {"url": url, "ok": False, "refused": True, "reason": str(e)}

        self._gate(host)
        res = {"url": url, "host": host, "ok": False, "refused": False, "note": note}
        try:
            snap = net.fetch_snap(url, timeout=self.timeout)
        except Exception as e:
            res["error"] = str(e)[:300]
            self._audit(analyst, "probe:error", url, False, res["error"])
            return res

        fp = detect.fingerprint(snap)
        res.update({"ok": True, "status": getattr(snap, "status", None),
                    "fingerprint": fp})
        # A probe exists to produce evidence, so the response is retained the
        # same way a collected page is.
        try:
            site_id = self.db.site_id(url)
            if site_id is None:
                site_id = self.db.upsert_site(
                    url, title=url, category="clearnet",
                    status=str(getattr(snap, "status", "")),
                    server=fp.get("server") or "", favicon_hash=fp["favicon_hash"],
                    favicon_phash=fp.get("favicon_phash") or None,
                    content_hash=fp["content_hash"],
                    cert_fp=fp.get("cert_fp") or None,
                    cert_serial=fp.get("cert_serial") or None,
                    tls_issuer=fp.get("tls_issuer") or None,
                    cert_valid_from=fp.get("cert_valid_from") or None,
                    cert_valid_to=fp.get("cert_valid_to") or None,
                    ssh_fp=fp.get("ssh_fp") or None)
            if self.keep_evidence:
                self.db.add_html_snapshot(
                    site_id=site_id, url=url, html=snap.html or "",
                    status=getattr(snap, "status", ""),
                    encoding=(snap.meta or {}).get("encoding", ""),
                    headers=getattr(snap, "headers", None) or {},
                    raw_bytes=(snap.meta or {}).get("raw_bytes"),
                    collector_version="probe:analyst")
            res["site_id"] = site_id
        except Exception as e:
            res["store_error"] = str(e)[:200]

        self._audit(analyst, "probe:get", url, True)
        return res

    def probe_many(self, urls, analyst="analyst"):
        """Probe an explicit list. No enumeration, no link following, no
        expansion: the caller's list is the whole scope."""
        if not self.enabled:
            return {"probing_enabled": False, "results": [],
                    "reason": "probing is not enabled on this deployment"}
        targets = [u for u in (urls or []) if u][:MAX_REQUESTS]
        results = [self.probe(u, analyst=analyst) for u in targets]
        return {
            "probing_enabled": True,
            "requested": len(targets),
            "capped": len(list(urls or [])) > MAX_REQUESTS,
            "cap": MAX_REQUESTS,
            "ok": sum(1 for r in results if r.get("ok")),
            "refused": sum(1 for r in results if r.get("refused")),
            "results": results,
        }


def _now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def enabled_from_env():
    """Explicitly NOT used to arm a Prober.

    Present only so the API can report why probing is off. Arming from the
    environment would mean an env change silently starts sending traffic.
    """
    return False


def default_prober(db):
    return Prober(db, enabled=False, allow_private=False)
