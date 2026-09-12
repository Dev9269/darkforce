"""RBAC + stateless bearer tokens for the dashboard API.

Password storage: salted PBKDF2-HMAC-SHA256 (stdlib only, no bcrypt needed).
Sessions: HMAC-signed tokens (stateless, no server-side store).
Roles: admin > analyst > viewer.

API usage:
  POST /api/login  {"username","password"}  -> {"token": "...", "role": "..."}
  GET  /api/audit  (admin only)             -> recent audit log rows
"""
import base64
import hashlib
import hmac
import os
import secrets
import time

from fastapi import Depends, Header, HTTPException

from .config import ADMIN_PASSWORD, ADMIN_USER, SECRET_KEY

ITERATIONS = 130_000  # OWASP-ish pbkdf2 count; fast enough in pure python here

ROLES = ("viewer", "analyst", "admin")
ROLE_INDEX = {r: i for i, r in enumerate(ROLES)}

_B64_ALPHABET = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

_session_version = None  # discarded; kept for potential future revocation lists
_dependencies = {}


# ---------- password hashing ----------

def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2${ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt, hashv = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 base64.b64decode(salt), int(iters))
        return hmac.compare_digest(base64.b64encode(dk).decode(), hashv)
    except Exception:
        return False


# ---------- tokens ----------

def issue_token(username: str, role: str, ttl: int = 12 * 3600) -> str:
    exp = int(time.time()) + ttl
    msg = f"{username}|{role}|{exp}"
    sig = hmac.new(SECRET_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{msg}|{sig}".encode()).decode()


def parse_token(token: str):
    try:
        token = token.strip().rstrip("=")
        if not token or not all(c in _B64_ALPHABET for c in token):
            return None
        token += "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(token.encode()).decode()
        username, role, exp, sig = raw.split("|")
        msg = f"{username}|{role}|{exp}"
        expect = hmac.new(SECRET_KEY.encode(), msg.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expect):
            return None
        if int(exp) < time.time():
            return None
        return {"username": username, "role": role}
    except Exception:
        return None


# ---------- FastAPI guards ----------

def current_user(authorization: str = Header(default="")) -> dict:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "missing bearer token (POST /api/login first)")
    who = parse_token(authorization[7:].strip())
    if not who:
        raise HTTPException(401, "invalid or expired token")
    return who


def require_role(min_role: str = "viewer"):
    """Dependency factory. Guard endpoints with `deps=[Depends(require_role("admin"))]`."""

    def dep(who: dict = Depends(current_user)) -> dict:
        if ROLE_INDEX.get(who["role"], -1) < ROLE_INDEX[min_role]:
            raise HTTPException(403, f"requires role >= {min_role}")
        return who

    return dep


def try_username(authorization: str = Header(default="")) -> str:
    """Best-effort identity for audit middleware when auth is optional."""
    if authorization.lower().startswith("bearer "):
        who = parse_token(authorization[7:].strip())
        if who:
            return who["username"]
    return "-"