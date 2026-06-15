"""Helper-i fara stare folositi de rutele web."""
import functools
import hashlib
import time

from flask import Response, request

from captcha import (
    CAPTCHA_COOKIE,
    SESSION_COOKIE,
    make_session_id,
    verify_pass_token,
)
from config import (
    ADMIN_PASSWORD,
    ADMIN_USER,
    CAPTCHA_SECRET,
    COOKIE_SAMESITE,
    COOKIE_SECURE,
    POLICY_VERSION,
    REDIS_ADMIN_PW,
    r,
)

def _now() -> int:
    return int(time.time())

def _hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def get_client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

def ua_hash() -> str:
    ua = request.headers.get("User-Agent", "")[:250]
    return hashlib.sha256(ua.encode()).hexdigest()

def host_header() -> str:
    return (request.host or "")[:200]

def get_or_set_sid(resp=None) -> str:
    sid = request.cookies.get(SESSION_COOKIE, "")
    if sid and len(sid) > 10:
        return sid

    sid = make_session_id()
    if resp:
        resp.set_cookie(
            SESSION_COOKIE, sid,
            max_age=604800, httponly=True,
            samesite=COOKIE_SAMESITE, secure=COOKIE_SECURE,
        )
    return sid

def safe_state(state):
    """Curata campurile interne inainte de a trimite starea catre client."""
    current = state.get("current", {}) or {}
    public = {
        "kind": current.get("kind", "checkbox"),
        "attempt_index": current.get("attempt_index", 0),
    }
    if current.get("kind") == "grid":
        public["task_type"] = current.get("task_type", "")
        public["prompt"] = current.get("prompt", "")
        public["expect_count"] = current.get("expect_count", 0)
        public["tiles"] = current.get("tiles", [])
    return public

def verify_pass() -> bool:
    sid = request.cookies.get(SESSION_COOKIE, "")
    tok = request.cookies.get(CAPTCHA_COOKIE, "")
    if not sid or not tok:
        return False
    ok, _ = verify_pass_token(
        CAPTCHA_SECRET, tok,
        sid=sid,
        policy_version=POLICY_VERSION,
        context={"ua": ua_hash(), "host": host_header()},
    )
    return ok

def _check_admin_auth() -> bool:
    auth = request.authorization
    if not auth:
        return False
    if auth.username != ADMIN_USER:
        return False
    stored_hash = r.get(REDIS_ADMIN_PW)
    if stored_hash:
        return _hash_password(auth.password) == stored_hash
    return auth.password == ADMIN_PASSWORD

def require_admin(f):
    """Decorator: cere HTTP Basic Auth pentru rutele admin."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not _check_admin_auth():
            return Response(
                "Admin login required", 401,
                {"WWW-Authenticate": 'Basic realm="Admin Dashboard"'},
            )
        return f(*args, **kwargs)
    return decorated
