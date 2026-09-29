"""Live TLS + SSH infrastructure fingerprints.

Fetches the peer TLS certificate (CN, SANs, issuer, validity, hashes) and SSH
banner / host-key fingerprint for a host so detections can correlate onion
services with their clearnet infrastructure.

Everything is proxy / Tor aware: pass an optional SOCKS5 URL (e.g.
``socks5h://127.0.0.1:9050``) and the probes route through it.
"""

import hashlib
import socket
import ssl
from urllib.parse import urlparse


def _socks_connect(host, port, socks_proxy=None, timeout=15):
    """Return a connected socket, optionally routed through a SOCKS5 proxy."""
    if socks_proxy:
        import socks  # PySocks (pip install pysocks)

        p = urlparse(socks_proxy)
        proxy_host = p.hostname or "127.0.0.1"
        proxy_port = p.port or 9050
        s = socks.socksocket(socket.AF_INET, socket.SOCK_STREAM)
        s.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
        s.settimeout(timeout)
        s.connect((host, port))
        return s
    return socket.create_connection((host, port), timeout=timeout)


def _x509_from_der(der):
    """Parse a DER cert into {tls_cn, cert_sans, tls_issuer, valid_from, valid_to}.

    Uses `cryptography` when available, otherwise falls back to CPython's
    internal DER decoder (present until Python 3.13).
    """
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID

        cert = x509.load_der_x509_certificate(der)
        subj = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        iss = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        sans = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = [str(v.value) for v in ext.value
                    if isinstance(v, (x509.DNSName, x509.IPAddress))]
        except x509.ExtensionNotFound:
            pass
        nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        return {
            "tls_cn": subj[0].value if subj else "",
            "cert_sans": sans,
            "tls_issuer": iss[0].value if iss else "",
            "tls_valid_from": nb.isoformat(),
            "tls_valid_to": na.isoformat(),
            # Serial + issuer together identify one certificate uniquely, which
            # makes it a usable pivot even when the private key differs from
            # every other site the operator runs.
            "cert_serial": format(cert.serial_number, "x"),
        }
    except ImportError:
        pass
    decode = getattr(ssl._ssl, "_test_decode_cert", None)
    if decode is None:
        return {}
    return _x509_from_dict(decode(der))


def _x509_from_dict(parsed):
    """Convert the CPython decoded-cert dict into our key shape."""
    def cn_of(entries):
        for name in entries or []:
            for key, value in name:
                if key == "commonName":
                    return value
        return ""

    sans = [v for _, v in (parsed.get("subjectAltName") or [])]
    out = {
        "tls_cn": cn_of(parsed.get("subject")),
        "cert_sans": sans,
        "tls_issuer": cn_of(parsed.get("issuer")),
        "tls_valid_from": parsed.get("notBefore", ""),
        "tls_valid_to": parsed.get("notAfter", ""),
    }
    # The stdlib fallback exposes no serial field, so recover it from the
    # TBSCertificate SEQUENCE that ssl decoded for us.
    der = parsed.get("_der")
    if der:
        try:
            out["cert_serial"] = _serial_from_der(der)
        except Exception:
            pass
    return out


def _serial_from_der(der):
    """Minimal DER walk to reach tbsCertificate.serialNumber.

    Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
    TBSCertificate ::= SEQUENCE { [0] version, serialNumber INTEGER, ... }
    """
    i = 0

    def read_tlv(buf, pos):
        tag = buf[pos]
        pos += 1
        n = buf[pos]
        pos += 1
        if n & 0x80:
            k = n & 0x7F
            n = int.from_bytes(buf[pos:pos + k], "big")
            pos += k
        return tag, buf[pos:pos + n], pos + n

    _, cert_body, _ = read_tlv(der, i)
    _, tbs, _ = read_tlv(cert_body, i)
    tag, first, nxt = read_tlv(tbs, i)
    if tag == 0xA0:            # explicit [0] version, skip it
        _, serial_bytes, _ = read_tlv(tbs, nxt)
    else:
        serial_bytes = first
    v = int.from_bytes(serial_bytes, "big") if serial_bytes else 0
    return format(v, "x")


def _fmt_fp(digest, sep=":"):
    return sep.join(f"{b:02x}" for b in digest)


def fetch_tls_peer_info(host, port=443, socks_proxy=None, timeout=15):
    """Open a TLS connection and extract peer-certificate infra signals.

    Self-signed certs are tolerated (verification disabled) - onion services
    almost always present one. Returns a dict with tls_cn, cert_sans, issuer,
    validity, sha1/sha256 fingerprints, negotiated protocol and cipher, or {}
    when the peer cannot be reached.
    """
    try:
        s = _socks_connect(host, port, socks_proxy, timeout)
    except Exception:
        return {}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with ctx.wrap_socket(s, server_hostname=host) as tls:
            info = {
                "host": host,
                "port": port,
                "protocol": tls.version() or "",
            }
            cipher = tls.cipher()
            if cipher:
                info["cipher"] = cipher[0]
            der = tls.getpeercert(binary_form=True)
            if not der:
                return info
            parsed = _x509_from_der(der)
            info.update(parsed)
            info["cert_fp"] = _fmt_fp(hashlib.sha256(der).digest())
            info["cert_fp_sha1"] = _fmt_fp(hashlib.sha1(der).digest())
            return info
    except Exception:
        return {}


def ssh_banner(host, port=22, socks_proxy=None, timeout=10):
    """Grab the SSH banner; when paramiko is installed also negotiate key exchange
    to capture the remote host-key fingerprint. Returns {banner, host_key_fp,
    key_type} (tails omitted without paramiko), or {} on failure.
    """
    try:
        s = _socks_connect(host, port, socks_proxy, timeout)
        s.settimeout(timeout)
    except Exception:
        return {}
    try:
        try:
            import paramiko  # optional
        except ImportError:
            paramiko = None

        if paramiko is not None:
            tr = paramiko.Transport(s)
            tr.start_client(timeout=float(timeout))
            key = tr.get_remote_server_key()
            md5 = "MD5:" + _fmt_fp(key.get_fingerprint())
            return {
                "banner": tr.remote_version,
                "host_key_fp": md5,
                "key_type": key.get_name(),
            }
        banner = s.recv(255).decode("utf-8", "replace").strip()
        return {"banner": banner}
    except Exception:
        return {}
    finally:
        try:
            s.close()
        except Exception:
            pass