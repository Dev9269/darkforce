import os
import socket
import subprocess
import time

import requests

from .config import BASE_DIR, DATA_DIR

EXT_PORT = 9050
MANAGED_PORT = 9052
MANAGED_CONTROL_PORT = 9053
MANAGED_HOST = "127.0.0.1"
TOR_EXE = os.path.join(BASE_DIR, "vendor", "tor", "tor", "tor.exe")
MANAGED_DATA = os.path.join(DATA_DIR, "tor-managed")
MANAGED_LOG = os.path.join(DATA_DIR, "tor-managed.log")
BOOTSTRAP_TIMEOUT = 90

_managed = None
_last_proxy = None


def managed_control_cookie():
    """Path to the control auth cookie of the managed Tor, or None before spawn."""
    if not managed_running():
        return None
    ck = os.path.join(MANAGED_DATA, "control_auth_cookie")
    return ck if os.path.exists(ck) else None


def listener(host=MANAGED_HOST, port=EXT_PORT, timeout=1.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def external_running():
    return listener(port=EXT_PORT)


def managed_running():
    return listener(port=MANAGED_PORT)


def _spawn():
    global _managed
    os.makedirs(MANAGED_DATA, exist_ok=True)
    if not os.path.exists(TOR_EXE):
        raise RuntimeError(
            "bundled Tor missing - expected vendor/tor/tor/tor.exe (download the official "
            "expert bundle from https://dist.torproject.org and extract it)"
        )
    cmd = [
        TOR_EXE,
        "--SocksPort", f"{MANAGED_HOST}:{MANAGED_PORT}",
        "--ControlPort", f"{MANAGED_HOST}:{MANAGED_CONTROL_PORT}",
        "--CookieAuthentication", "1",
        "--DataDirectory", MANAGED_DATA,
        "--SafeLogging", "1",
        "--Log", "notice stdout",
    ]
    logf = open(MANAGED_LOG, "wb")
    _managed = subprocess.Popen(cmd, stdout=logf, stderr=subprocess.STDOUT)
    return _managed


def _bootstrap_ok():
    if not listener(port=MANAGED_PORT):
        return False
    proxy = {"http": f"socks5h://{MANAGED_HOST}:{MANAGED_PORT}",
             "https": f"socks5h://{MANAGED_HOST}:{MANAGED_PORT}"}
    try:
        r = requests.get("https://check.torproject.org/api/ip", proxies=proxy, timeout=15)
        return r.status_code == 200 and r.json().get("IsTor") is True
    except Exception:
        return False


def start_managed():
    """Spawn the bundled Tor and wait for a working circuit. Returns proxy URL or None."""
    global _last_proxy
    if managed_running():
        _last_proxy = f"socks5h://{MANAGED_HOST}:{MANAGED_PORT}"
        return _last_proxy
    _spawn()
    deadline = time.time() + BOOTSTRAP_TIMEOUT
    while time.time() < deadline:
        if _bootstrap_ok():
            _last_proxy = f"socks5h://{MANAGED_HOST}:{MANAGED_PORT}"
            return _last_proxy
        time.sleep(2)
    stop_managed()
    return None


def active_proxy(auto=True):
    """Return the best available SOCKS proxy URL, or None.

    Uses an already-running external Tor (port 9050) when present, otherwise the
    managed bundle. With auto=True, spawns the managed instance if nothing is up.
    """
    global _last_proxy
    if external_running():
        _last_proxy = f"socks5h://127.0.0.1:{EXT_PORT}"
        return _last_proxy
    if managed_running():
        _last_proxy = f"socks5h://{MANAGED_HOST}:{MANAGED_PORT}"
        return _last_proxy
    if auto:
        return start_managed()
    _last_proxy = None
    return None


def stop_managed():
    global _managed, _last_proxy
    if _managed is not None and _managed.poll() is None:
        try:
            _managed.terminate()
            _managed.wait(timeout=10)
        except Exception:
            pass
    _managed = None
    if _last_proxy and ":" in str(_last_proxy) and MANAGED_PORT in str(_last_proxy):
        _last_proxy = None