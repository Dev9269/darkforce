import os
import socket


def _load_env():
    """Minimal stdlib .env loader (KEY=VALUE lines). No external dep needed;
    real process env always wins over the file."""
    envf = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if not os.path.exists(envf):
        return
    for line in open(envf, encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        k, v = k.strip(), v.strip().strip("\"'")
        if k and k not in os.environ:
            os.environ[k] = v


_load_env()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "darkforce.db")
RAW_DIR = os.path.join(DATA_DIR, "raw")
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(RAW_DIR, exist_ok=True)

# Leave DATABASE_URL unset to use SQLite (zero-config demo). Set it to a
# postgres URL to switch the whole app to PostgreSQL, e.g.:
#   postgresql://darkforce:darkforce_dev@localhost:5432/darkforce
DATABASE_URL = os.getenv("DATABASE_URL", "")

# Tor endpoint. In a Docker compose deployment Tor runs as a sidecar container
# reachable as socks5h://tor:9050; locally the app spawns (or uses) 127.0.0.1.
TOR_PROXY = os.getenv("TOR_EXTERNAL", "socks5h://127.0.0.1:9050")
TOR_HOST = os.getenv("TOR_HOST", "127.0.0.1")
TOR_PORT = int(os.getenv("TOR_PORT", "9050"))

# RBAC / sessions. SECRET_KEY signs the bearer tokens issued at /api/login.
SECRET_KEY = os.getenv("SECRET_KEY", "darkforce-dev-secret-change-me")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "darkforce-admin")


def tor_available(host="127.0.0.1", port=9050, timeout=2.0):
    """Probe the local Tor SOCKS port. True only if a listener actually answers."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
]