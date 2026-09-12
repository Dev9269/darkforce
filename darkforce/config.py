import os
import socket

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

TOR_PROXY = "socks5h://127.0.0.1:9050"


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