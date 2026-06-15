"""Primitivi de nivel jos folositi de toate submodulele CAPTCHA."""
import base64
import hashlib
import hmac
import os
import secrets
import time
from typing import Any

from .constants import GRID_DIR

def _now() -> int:
    return int(time.time())

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")

def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))

def _hmac_sha256(secret: str, msg: bytes) -> bytes:
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()

def _sign(secret: str, payload: bytes) -> str:
    return _b64url_encode(_hmac_sha256(secret, payload))

def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default

def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default

def make_session_id() -> str:
    return secrets.token_urlsafe(32)

def make_nonce() -> str:
    return secrets.token_urlsafe(24)

def ensure_dirs() -> None:
    os.makedirs(GRID_DIR, exist_ok=True)
