"""
HMAC-signed pass token issued after a successful CAPTCHA flow.

Format: ``base64url(json_payload).base64url(HMAC-SHA256(payload))``.
The payload binds the session id (``sid``), policy version (``pv``),
expiry (``exp``), and an optional User-Agent / Host context so the
token cannot be replayed from another browser or vhost.
"""
import hmac
import json
from typing import Any, Dict, Optional, Tuple

from .helpers import (
    _b64url_decode,
    _b64url_encode,
    _now,
    _safe_int,
    _sign,
)


def make_pass_token(
    secret: str,
    sid: str,
    ttl_seconds: int,
    policy_version: str,
    context: Optional[Dict[str, str]] = None,
) -> str:
    exp = _now() + int(ttl_seconds)
    ctx = context or {}
    body = {
        "sid": sid,
        "pv": str(policy_version),
        "exp": exp,
        "ua": str(ctx.get("ua", ""))[:120],
        "host": str(ctx.get("host", ""))[:120],
    }
    payload = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = _sign(secret, payload)
    return f"{_b64url_encode(payload)}.{sig}"


def verify_pass_token(
    secret: str,
    token: str,
    sid: str,
    policy_version: str,
    context: Optional[Dict[str, str]] = None,
) -> Tuple[bool, Optional[int]]:
    try:
        if not token or "." not in token:
            return False, None

        b64, sig = token.split(".", 1)
        payload = _b64url_decode(b64)
        expected = _sign(secret, payload)
        if not hmac.compare_digest(sig, expected):
            return False, None

        body = json.loads(payload.decode("utf-8"))
        if body.get("sid") != sid:
            return False, None

        if str(body.get("pv")) != str(policy_version):
            return False, None

        exp = _safe_int(body.get("exp"), 0)
        if _now() > exp:
            return False, None

        ctx = context or {}
        tok_ua = str(body.get("ua", ""))
        tok_host = str(body.get("host", ""))

        if tok_ua and tok_ua != str(ctx.get("ua", ""))[:120]:
            return False, None
        if tok_host and tok_host != str(ctx.get("host", ""))[:120]:
            return False, None

        return True, exp
    except Exception:
        return False, None
