import os
import secrets
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

# RBAC / sessions.
#
# SECRET_KEY signs the bearer tokens issued at /api/login. It previously
# defaulted to a literal constant that is published in this repository, which
# meant anyone who read the source could mint a valid admin token with one line
# of Python and every role check in the app was decorative. It now has no
# usable default: if the operator has not supplied one, a random key is
# generated and persisted to a 0600 file outside version control.
_SECRET_KEY_FILE = os.path.join(DATA_DIR, ".secret_key")
_SECRET_PLACEHOLDERS = {
    "darkforce-dev-secret-change-me",
    "change-me",
    "changeme",
    "secret",
}


def _load_secret_key():
    env = (os.getenv("SECRET_KEY") or "").strip()
    if env and env not in _SECRET_PLACEHOLDERS:
        return env, "environment"
    if env in _SECRET_PLACEHOLDERS:
        print(
            "[auth] WARNING: SECRET_KEY is set to a well-known placeholder. "
            "Anybody who has read this repository can forge admin tokens. "
            "Replacing it with a random value now.")
    # Reuse an existing generated key so sessions survive a restart.
    try:
        if os.path.exists(_SECRET_KEY_FILE):
            with open(_SECRET_KEY_FILE, encoding="utf-8") as fh:
                stored = fh.read().strip()
            if stored and stored not in _SECRET_PLACEHOLDERS:
                return stored, f"persisted ({_SECRET_KEY_FILE})"
    except OSError:
        pass
    key = secrets.token_urlsafe(48)
    try:
        fd = os.open(_SECRET_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(key)
        os.chmod(_SECRET_KEY_FILE, 0o600)
        where = f"generated, persisted to {_SECRET_KEY_FILE}"
    except OSError:
        # Read-only filesystem: still fine for this run, but sessions will not
        # survive a restart, so say so rather than failing silently.
        where = "generated for this process only (could not persist; sessions reset on restart)"
    print(f"[auth] SECRET_KEY {where}. Set SECRET_KEY to pin it explicitly.")
    return key, where


SECRET_KEY, SECRET_KEY_SOURCE = _load_secret_key()

ADMIN_USER = os.getenv("ADMIN_USER") or "admin"

# No default password. A shipped default means every deployment shares one, and
# for an investigation tool the admin account is the one holding the corpus.
# When the operator has not supplied one, generate it once and persist it to a
# 0600 file, so the password stays stable across restarts and never has to be
# printed a second time. (An earlier version generated one per process and
# printed it every boot; from the second boot onward the printed password was
# simply wrong, because the account had already been seeded with the first.)
_ADMIN_PASSWORD_FILE = os.path.join(DATA_DIR, ".admin_password")


def _load_admin_password():
    env = (os.getenv("ADMIN_PASSWORD") or "").strip()
    if env:
        return env, "environment", False
    try:
        if os.path.exists(_ADMIN_PASSWORD_FILE):
            with open(_ADMIN_PASSWORD_FILE, encoding="utf-8") as fh:
                stored = fh.read().strip()
            if stored:
                return stored, f"persisted ({_ADMIN_PASSWORD_FILE})", False
    except OSError:
        pass
    pw = secrets.token_urlsafe(24)
    try:
        fd = os.open(_ADMIN_PASSWORD_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(pw)
        os.chmod(_ADMIN_PASSWORD_FILE, 0o600)
    except OSError:
        pass
    return pw, "generated", True


ADMIN_PASSWORD, ADMIN_PASSWORD_SOURCE, ADMIN_PASSWORD_IS_NEW = _load_admin_password()


def announce_admin_password():
    """Print the generated password, but only when it is actually being used to
    seed a fresh account. Calling this on a database that already has users
    would print a password that does not work."""
    if ADMIN_PASSWORD_SOURCE == "environment" or not ADMIN_PASSWORD_IS_NEW:
        return
    print(
        "\n[auth] ADMIN_PASSWORD was not set. Generated and stored one for the "
        f"'{ADMIN_USER}' account:\n\n    {ADMIN_PASSWORD}\n\n"
        f"Also written to {_ADMIN_PASSWORD_FILE} (mode 0600). Set ADMIN_PASSWORD in "
        ".env to choose your own, or log in and change it.\n")

# Optional threat-intel feed API keys (free tiers; collectors no-op without them).
ALIENVAULT_OTX_KEY = os.getenv("ALIENVAULT_OTX_KEY", "")
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")


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