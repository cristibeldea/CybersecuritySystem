"""Publica evenimente HTTP pe Redis si scrie istoricul pentru panoul de administrare."""
import json
import logging

from flask import abort, redirect, request

from config import (
    BAN_SECONDS_HONEYPOT,
    REDIS_BAN_HISTORY,
    REDIS_NEAR_MISSES,
    r,
)
from helpers import _now, get_client_ip, verify_pass
from request_checker import build_entry, is_banned, log_and_publish

log = logging.getLogger("web")

def log_ban_event(ip: str, reason: str, duration: int) -> None:
    """Inregistreaza un eveniment de ban in Redis pentru istoricul admin."""
    event = json.dumps(
        {"ts": _now(), "ip": ip, "reason": reason, "duration": duration},
        separators=(",", ":"),
    )
    pipe = r.pipeline()
    pipe.lpush(REDIS_BAN_HISTORY, event)
    pipe.ltrim(REDIS_BAN_HISTORY, 0, 499)
    pipe.execute()

def log_near_miss(ip: str, module: str, score, threshold, details: str = "") -> None:
    """Inregistreaza un eveniment near-threshold pentru panoul admin."""
    event = json.dumps(
        {
            "ts": _now(),
            "ip": ip,
            "module": module,
            "score": round(float(score), 4) if score is not None else 0,
            "threshold": round(float(threshold), 4) if threshold is not None else 0,
            "details": details,
        },
        separators=(",", ":"),
    )
    pipe = r.pipeline()
    pipe.lpush(REDIS_NEAR_MISSES, event)
    pipe.ltrim(REDIS_NEAR_MISSES, 0, 199)
    pipe.execute()

def register_security_gate(app) -> None:
    """Conecteaza hook-ul global @before_request pentru securitate si logare."""
    from ban_manager import ban_ip_with_history
    from routes.honeypot_routes import TRAP_FIELD_NAMES, TRAP_PATH_PREFIXES

    @app.before_request
    def security_gate_and_logging():
        ip = get_client_ip()
        ip_banned = is_banned(r, ip)

        is_trap_path     = any(request.path.startswith(p) for p in TRAP_PATH_PREFIXES)
        is_trap_endpoint = request.path in ("/hp-trap", "/hp-form")

        if (ip_banned
                and not request.path.startswith(("/captcha", "/admin"))
                and not is_trap_endpoint
                and not is_trap_path):
            abort(403)

        if request.path.startswith(("/captcha", "/static", "/admin")):
            return

        entry = build_entry(
            ip=ip, username="anonymous",
            path=request.path, method=request.method,
            headers=request.headers,
        )
        log_and_publish(r, entry)

        if is_trap_endpoint or is_trap_path:
            return

        if request.method == "POST" and request.form:
            submitted_fields = set(request.form.keys())
            trap_hits = submitted_fields & TRAP_FIELD_NAMES
            if trap_hits:
                log.warning("HONEYPOT FIELD-TRAP ip=%s fields=%s", ip, list(trap_hits))
                ban_ip_with_history(
                    ip, BAN_SECONDS_HONEYPOT,
                    reason=f"honeypot:trap_fields:{','.join(trap_hits)}",
                )
                abort(403)

        if not verify_pass():
            return redirect("/captcha")
