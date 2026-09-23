"""Live infra signals for Capability 1 (TLS + SSH fingerprints, Onionoo descriptors).

Regression suite for:
  - darkforce.tlsfp.fetch_tls_peer_info / ssh_banner
  - net.fetch_snap populating https meta with tls_cn/cert_sans/cert_fp/tls_issuer
  - detect.scan emitting a tls_cert finding <=>= 0.8 when a cert SAN names a
    clearnet domain
  - sites rows storing cert SANs (searchable against clearnet domains)
  - darkforce.descriptors descriptor_anomaly consistency findings
"""
import hashlib
import os
import re
import socket
import sys
import tempfile
import threading
import types
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from darkforce import detect, net as net_mod
from darkforce.db import SQLiteDB


@pytest.fixture
def tmp_db():
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    db = SQLiteDB(path)
    yield db
    db.close()


# --------------------------------------------------------------------------
# self-signed TLS test server (with SANs)
# --------------------------------------------------------------------------

def _make_self_signed_cert():
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "app.example")])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "app-ca.example")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("app.example"), x509.DNSName("www.app.example")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.DER),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        cert.public_bytes(serialization.Encoding.PEM),
    )


class _TLSServer:
    """Background self-signed TLS listener bound to 127.0.0.1."""

    def __init__(self):
        der, key_pem, cert_pem = _make_self_signed_cert()
        self.der = der
        fd, self.cert_path = tempfile.mkstemp(suffix=".crt")
        os.close(fd)
        with open(self.cert_path, "wb") as f:
            f.write(cert_pem)
        fd2, self.key_path = tempfile.mkstemp(suffix=".key")
        os.close(fd2)
        with open(self.key_path, "wb") as f:
            f.write(key_pem)
        self._stop = threading.Event()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        import ssl

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert_path, self.key_path)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    try:
                        tls.recv(1024)
                    except Exception:
                        pass
            except Exception:
                pass

    def stop(self):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        self.thread.join(timeout=2)


@pytest.fixture
def tls_server():
    srv = _TLSServer()
    yield srv
    srv.stop()


# --------------------------------------------------------------------------
# tlsfp: TLS peer info extraction
# --------------------------------------------------------------------------

def test_fetch_tls_peer_info_extracts_cn_sans_and_fingerprints(tls_server):
    from darkforce import tlsfp

    info = tlsfp.fetch_tls_peer_info("127.0.0.1", tls_server.port, timeout=5)

    assert info["tls_cn"] == "app.example"
    assert "app.example" in info["cert_sans"]
    assert "www.app.example" in info["cert_sans"]
    assert info["tls_issuer"] == "app-ca.example"
    assert re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){31}", info["cert_fp"])
    assert re.fullmatch(r"[0-9a-f]{2}(?::[0-9a-f]{2}){19}", info["cert_fp_sha1"])
    assert info["tls_valid_from"] and info["tls_valid_to"]
    assert info["tls_valid_from"] < info["tls_valid_to"]
    assert info["protocol"].startswith("TLSv")
    assert info["cipher"]


def test_san_naming_clearnet_domain_raises_tls_cert_finding(tls_server):
    from darkforce import tlsfp

    info = tlsfp.fetch_tls_peer_info("127.0.0.1", tls_server.port, timeout=5)
    snap = detect.Snap(
        url="http://swap.onion",
        html="<html/>",
        meta={
            "hostname": "swap.onion",
            "tls_cn": info["tls_cn"],
            "cert_sans": ",".join(info["cert_sans"]),
            "cert_fp": info["cert_fp"],
        },
    )

    findings, fp = detect.scan(snap)
    tls = [f for f in findings if f[0] == "tls_cert"]
    assert tls, "expected a tls_cert finding for clearnet SAN"
    assert tls[0][3] >= 0.8
    assert "app.example" in tls[0][2]
    assert fp["cert_sans"] == "app.example,www.app.example"


def test_onion_only_names_do_not_emit_tls_cert():
    snap = detect.Snap(
        url="http://only.onion",
        html="<html/>",
        meta={"hostname": "only.onion", "tls_cn": "only.onion",
              "cert_sans": "only.onion,hidden.abc.onion"},
    )
    findings, _ = detect.scan(snap)
    assert not [f for f in findings if f[0] == "tls_cert"]


# --------------------------------------------------------------------------
# tlsfp: SSH banner
# --------------------------------------------------------------------------

def _serve_banner(banner):
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    got = {}

    def serve():
        conn, _ = srv.accept()
        try:
            conn.sendall(banner)
            try:
                conn.recv(1024)
            except Exception:
                pass
        finally:
            conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return srv, port, t


def test_ssh_banner_raw_socket():
    from darkforce import tlsfp

    srv, port, t = _serve_banner(b"SSH-2.0-OpenSSH_9.0 mock\r\n")
    try:
        info = tlsfp.ssh_banner("127.0.0.1", port, timeout=5)
    finally:
        srv.close()
        t.join(timeout=2)
    assert info["banner"] == "SSH-2.0-OpenSSH_9.0 mock"


def test_ssh_banner_paramiko_fingerprint(monkeypatch):
    from darkforce import tlsfp

    class _FakeKey:
        def asbytes(self):
            return b"\x00\x01keyblob"

        def get_fingerprint(self):
            return hashlib.md5(b"\x00\x01keyblob").digest()

        def get_name(self):
            return "ssh-ed25519"

    class _FakeTransport:
        remote_version = "SSH-2.0-OpenSSH_9.0 paramiko-mock"

        def __init__(self, sock):
            self.sock = sock

        def start_client(self, timeout=None):
            pass

        def get_remote_server_key(self):
            return _FakeKey()

    monkeypatch.setitem(sys.modules, "paramiko",
                        types.SimpleNamespace(Transport=_FakeTransport))

    srv, port, t = _serve_banner(b"SSH-2.0-OpenSSH_9.0 paramiko-mock\r\n")
    try:
        info = tlsfp.ssh_banner("127.0.0.1", port, timeout=5)
    finally:
        srv.close()
        t.join(timeout=2)

    assert info["banner"] == "SSH-2.0-OpenSSH_9.0 paramiko-mock"
    assert info["host_key_fp"].startswith("MD5:")
    assert info["key_type"] == "ssh-ed25519"


# --------------------------------------------------------------------------
# net.fetch_snap https meta population
# --------------------------------------------------------------------------

class _FakeResp:
    def __init__(self, status_code=200, html="<html>ok</html>"):
        self.status_code = status_code
        self.headers = {"Server": "nginx"}
        self.text = html
        self.content = html.encode()


def test_fetch_snap_populates_https_tls_meta(monkeypatch):
    captured = {}

    def fake_get(url, proxies=None, headers=None, timeout=20, verify=True):
        captured["url"] = url
        captured["proxies"] = proxies
        return _FakeResp()

    def fake_tls(host, port=443, socks_proxy=None, timeout=15):
        captured["tls"] = (host, port)
        return {
            "host": host,
            "port": 443,
            "tls_cn": "clearnet-swap.example",
            "cert_sans": ["clearnet-swap.example", "www.clearnet-swap.example"],
            "cert_fp": "aa:11:22:33",
            "tls_issuer": "swapca",
            "tls_valid_from": "2026-01-01T00:00:00",
            "tls_valid_to": "2026-12-31T00:00:00",
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
        }

    monkeypatch.setattr(net_mod, "requests", types.SimpleNamespace(get=fake_get))
    monkeypatch.setattr(net_mod, "_polite_wait", lambda url: None)
    monkeypatch.setattr(net_mod.tlsfp, "fetch_tls_peer_info", fake_tls)

    snap = net_mod.fetch_snap("https://clearnet-swap.example/page", timeout=15)

    m = snap.meta
    assert m["tls_cn"] == "clearnet-swap.example"
    assert m["cert_sans"] == "clearnet-swap.example,www.clearnet-swap.example"
    assert m["cert_fp"] == "aa:11:22:33"
    assert m["tls_issuer"] == "swapca"
    assert m["tls_protocol"] == "TLSv1.3"
    assert "ssh_fp" in m
    assert captured["tls"] == ("clearnet-swap.example", 443)

    fp = detect.fingerprint(snap)
    assert fp["cert_sans"] == "clearnet-swap.example,www.clearnet-swap.example"
    assert fp["tls_issuer"] == "swapca"
    assert fp["cert_fp"] == "aa:11:22:33"


def test_fetch_snap_tls_failure_keeps_meta_keys(monkeypatch):
    def fake_get(url, proxies=None, headers=None, timeout=20, verify=True):
        return _FakeResp()

    def fake_tls(host, port=443, socks_proxy=None, timeout=15):
        return {}

    monkeypatch.setattr(net_mod, "requests", types.SimpleNamespace(get=fake_get))
    monkeypatch.setattr(net_mod, "_polite_wait", lambda url: None)
    monkeypatch.setattr(net_mod.tlsfp, "fetch_tls_peer_info", fake_tls)

    snap = net_mod.fetch_snap("https://dead.example/", timeout=5)
    assert snap.meta["tls_cn"] == ""
    assert snap.meta["cert_sans"] == ""
    assert snap.meta["ssh_fp"] == ""


# --------------------------------------------------------------------------
# sites row: cert SAN storage + clearnet search
# --------------------------------------------------------------------------

def test_site_stores_cert_sans_and_is_searchable(tmp_db):
    sid = tmp_db.upsert_site(
        "http://swap.onion",
        cert_sans="app.example,www.app.example",
        tls_issuer="app-ca.example",
        cert_fp="aa:11:22:33",
    )
    row = tmp_db.one(
        "SELECT id,url,cert_sans,tls_issuer,cert_fp FROM sites WHERE id=?", (sid,))
    assert row["cert_sans"] == "app.example,www.app.example"
    assert row["tls_issuer"] == "app-ca.example"
    assert row["cert_fp"] == "aa:11:22:33"

    hits = tmp_db.sites_by_cert_san("app.example")
    assert any(r["id"] == sid for r in hits)
    assert not tmp_db.sites_by_cert_san("unrelated.example")


# --------------------------------------------------------------------------
# descriptors: Onionoo-backed descriptor_anomaly findings
# --------------------------------------------------------------------------

def test_descriptor_port_and_version_anomalies():
    from darkforce import descriptors

    declared = {
        "ports": [80, 443],
        "version": "Tor 0.4.8.1",
        "family": ["AAAA", "BBBB"],
        "first_seen": "2026-09-01 00:00:00",
        "running": True,
    }
    observed = {
        "ports": [443],
        "version": "0.4.6.5",
        "alive": True,
        "first_seen": "2026-08-01 00:00:00",
    }
    findings = descriptors.check_descriptor("x.onion", declared=declared, observed=observed)

    with_ports = [f for f in findings if f[0] == "descriptor_anomaly" and "port" in f[2].lower()]
    with_version = [f for f in findings if f[0] == "descriptor_anomaly" and "version" in f[2].lower()]
    with_family = [f for f in findings if f[0] == "descriptor_anomaly" and "family" in f[2].lower()]
    assert with_ports and with_ports[0][3] >= 0.7
    assert with_version
    assert with_family


def test_descriptor_age_anomaly():
    from darkforce import descriptors

    declared = {"first_seen": "2026-09-23 00:00:00", "running": True}
    observed = {"alive": True, "first_seen": "2026-08-01 00:00:00"}
    findings = descriptors.check_descriptor("x.onion", declared=declared, observed=observed)
    age = [f for f in findings if f[0] == "descriptor_anomaly" and "age" in f[2].lower()]
    assert age and age[0][3] >= 0.8


def test_descriptor_running_mismatch():
    from darkforce import descriptors

    declared = {"running": True, "first_seen": "2026-01-01 00:00:00"}
    observed = {"alive": False, "first_seen": "2026-01-01 00:00:00"}
    findings = descriptors.check_descriptor("x.onion", declared=declared, observed=observed)
    assert any(f[0] == "descriptor_anomaly" and "running" in f[2].lower()
               for f in findings)


def test_check_onion_descriptor_from_onionoo(monkeypatch):
    import json

    from darkforce import descriptors, seeds

    class _Resp:
        status_code = 200
        text = json.dumps({
            "relays": [{
                "nickname": "myservice",
                "fingerprint": "ABCDEF",
                "first_seen": "2026-09-01 00:00:00",
                "last_seen": "2026-09-22 00:00:00",
                "running": True,
                "platform": "Tor 0.4.8.1 on Linux",
                "country": "US",
                "as": "AS123",
                "flags": ["Fast", "Stable", "HSDir"],
                "family": ["FACC", "DEAD"],
            }],
            "bridges": [],
        })

    calls = {}

    def fake_get(url, params=None, proxies=None, timeout=15, headers=None):
        calls["params"] = params
        return _Resp()

    monkeypatch.setattr(seeds, "_get", fake_get)

    observed = {"ports": [443], "version": "0.4.6.5", "alive": True,
                "first_seen": "2026-08-01 00:00:00"}
    findings = descriptors.check_onion_descriptor("myservice.onion", observed=observed,
                                                  timeout=10)
    assert calls["params"]["search"] == "myservice.onion"
    assert any(f[0] == "descriptor_anomaly" for f in findings)


def test_check_onion_descriptor_no_record_is_graceful(monkeypatch):
    import json

    from darkforce import descriptors, seeds

    class _Resp:
        status_code = 200
        text = json.dumps({"relays": [], "bridges": []})

    def fake_get(url, params=None, proxies=None, timeout=15, headers=None):
        return _Resp()

    monkeypatch.setattr(seeds, "_get", fake_get)
    assert descriptors.check_onion_descriptor("ghost.onion", observed={}, timeout=10) == []