import random
import time

import requests

from .config import UAS
from .detect import Snap


def _tor_proxy():
    """Best available SOCKS proxy for .onion fetches, or raise a clear error."""
    from .tor import active_proxy

    p = active_proxy()
    if not p:
        raise RuntimeError("Tor unavailable (no external Tor on 9050 and bundled Tor failed to bootstrap)")
    return {"http": p, "https": p}


def fetch_snap(url, use_tor=False, timeout=20):
    """Fetch a URL and return a Snap (headers + html + favicon)."""
    prox = _tor_proxy() if use_tor else None
    h = {"User-Agent": random.choice(UAS)}
    # .onion services almost always use self-signed certs; Tor already gives us
    # transport anonymity, so skip CA verification for onion hosts only.
    verify = not use_tor
    if use_tor:
        import warnings

        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
    for attempt in range(3):
        try:
            r = requests.get(url, proxies=prox, headers=h, timeout=timeout, verify=verify)
            break
        except requests.exceptions.SSLError:
            verify = False  # self-signed cert: retry once without verification
        except requests.exceptions.RequestException:
            if use_tor and attempt < 2:
                time.sleep(2)  # transient onion circuit drop: retry once
    else:
        raise RuntimeError(f"fetch failed after retries: {url}")
    html = r.text
    favicon = None
    try:
        import re

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
    host = None
    try:
        from urllib.parse import urlparse

        host = urlparse(url).hostname
    except Exception:
        pass
    snap = Snap(url=url, headers=dict(r.headers), html=html, favicon=favicon,
                meta={"hostname": host})
    snap.status = r.status_code
    return snap