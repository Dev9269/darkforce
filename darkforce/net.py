import random
import re
import threading
import time
from collections import defaultdict

import requests

from .config import UAS
from .detect import Snap

# --- per-host politeness gate -----------------------------------------------
MIN_HOST_INTERVAL = 4.0          # minimum seconds between requests to same host
_last_request = {}
_rate_lock = threading.Lock()


def _host(url):
    try:
        from urllib.parse import urlparse

        return urlparse(url).hostname or url
    except Exception:
        return url


def _polite_wait(url):
    """Sleep so we never hit the same host more often than MIN_HOST_INTERVAL."""
    host = _host(url)
    with _rate_lock:
        now = time.time()
        wait = MIN_HOST_INTERVAL - (now - _last_request.get(host, 0.0))
        if wait > 0:
            time.sleep(wait)
        _last_request[host] = time.time()


# --- circuit rotation (Stem, graceful when Tor control is unavailable) -------
_circuit_lock = threading.Lock()
_last_rotation = 0.0
MIN_ROTATION_GAP = 30.0

CAPTCHA_RE = re.compile(
    r"(captcha|recaptcha|cf-challenge|cf-chl-|are you (a )?human|proof[- ]of[- ]work|x-vercel-captch|"
    r"challenge-p|lone-wolf-captcha|hcaptcha|cloudflare[^\n]{0,40}(challenge|verified))",
    re.I,
)
_BOT_RE = re.compile(
    r"(access denied|accessdenied|too many requests|you have been blocked|cf-error-code|"
    r"request blocked|g-recaptcha|challenge-platform|verifying you are human)",
    re.I,
)


def rotate_circuit(min_gap=MIN_ROTATION_GAP):
    """Ask Tor for a fresh circuit (NEWNYM). Never raises - logs and continues."""
    global _last_rotation
    with _circuit_lock:
        now = time.time()
        if now - _last_rotation < min_gap:
            return False
        try:
            from stem import Signal
            from stem.control import Controller

            from .tor import MANAGED_CONTROL_PORT, managed_control_cookie

            attempts = []
            cookie = managed_control_cookie()
            if cookie:
                attempts.append((MANAGED_CONTROL_PORT, cookie))
            attempts.append((9051, None))  # conventional external Tor control port
            err = None
            for port, ck in attempts:
                try:
                    c = Controller.from_port(port=port)
                    if ck:
                        c.authenticate(cookie_path=ck)
                    else:
                        c.authenticate()
                    c.signal(Signal.NEWNYM)
                    c.close()
                    _last_rotation = time.time()
                    time.sleep(2)  # let Tor settle the new circuit
                    return True
                except Exception as e:
                    err = e
            print(f"[tor] circuit rotation unavailable: {err}")
            return False
        except Exception as e:
            print(f"[tor] no Stem/control port for circuit rotation: {e}")
            return False


def _tor_proxy():
    """Best available SOCKS proxy for .onion fetches, or raise a clear error."""
    from .tor import active_proxy

    p = active_proxy()
    if not p:
        raise RuntimeError("Tor unavailable (no external Tor on 9050 and bundled Tor failed to bootstrap)")
    return {"http": p, "https": p}


def classify(html, status):
    """Return a hint for CAPTCHA/bot walls so the crawler can skip & mark them."""
    if status in (403, 429):
        return "blocked"
    if not html:
        return None
    if CAPTCHA_RE.search(html):
        return "captcha"
    if _BOT_RE.search(html):
        return "blocked"
    return None


def fetch_snap(url, use_tor=False, timeout=20):
    """Fetch a URL and return a Snap (headers + html + favicon).

    Tor-aware: per-host rate limiting, exponential backoff + circuit rotation on
    403/429/timeouts, retries, and self-signed-cert tolerance for .onion hosts.
    """
    prox = _tor_proxy() if use_tor else None
    h = {"User-Agent": random.choice(UAS)}
    # .onion services almost always use self-signed certs; Tor already gives us
    # transport anonymity, so skip CA verification for onion hosts only.
    verify = not use_tor
    if use_tor:
        import warnings

        import urllib3

        warnings.filterwarnings("ignore", module="urllib3")
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    _polite_wait(url)
    backoff = 5.0
    r = None
    for attempt in range(4):
        try:
            r = requests.get(url, proxies=prox, headers=h, timeout=timeout, verify=verify)
            if r.status_code in (403, 429):
                print(f"[net] {_host(url)} -> {r.status_code}; backoff {backoff:.0f}s + rotate")
                rotate_circuit()
                time.sleep(backoff)
                backoff = min(backoff * 2, 120)
                continue
            break
        except requests.exceptions.SSLError:
            verify = False  # self-signed cert: retry once without verification
        except requests.exceptions.RequestException:
            if use_tor and attempt < 3:
                print(f"[net] {_host(url)} transient error (attempt {attempt + 1}/4); "
                      f"backoff {backoff:.0f}s + rotate")
                rotate_circuit()
                time.sleep(backoff)
                backoff = min(backoff * 2, 120)
            else:
                raise
    if r is None:
        raise RuntimeError(f"fetch failed after retries: {url}")
    html = r.text
    favicon = None
    try:
        m = re.search(r'<link[^>]+rel="[^"]*icon[^"]*"[^>]+href="([^"]+)"', html)
        or_ = re.search(r'<link[^>]+href="([^"]+)"[^>]+rel="[^"]*icon[^"]*"', html)
        src = (m or or_)
        if src:
            furl = src.group(1)
            if not furl.startswith("http"):
                from urllib.parse import urljoin

                furl = urljoin(url, furl)
            f = requests.get(furl, proxies=prox, headers=h, timeout=10, verify=verify)
            if f.status_code == 200:
                favicon = f.content
    except Exception:
        pass
    host = _host(url)
    hint = classify(html, r.status_code)
    snap = Snap(url=url, headers=dict(r.headers), html=html, favicon=favicon,
                meta={"hostname": host, "wall": hint})
    snap.status = r.status_code
    return snap