import random
import time

import requests

from .config import TOR_PROXY, UAS
from .detect import Snap


def fetch_snap(url, use_tor=False, timeout=20):
    """Fetch a URL and return a Snap (headers + html + favicon)."""
    prox = {"http": TOR_PROXY, "https": TOR_PROXY} if use_tor else None
    h = {"User-Agent": random.choice(UAS)}
    r = requests.get(url, proxies=prox, headers=h, timeout=timeout, verify=True)
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
            f = requests.get(furl, proxies=prox, headers=h, timeout=10)
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