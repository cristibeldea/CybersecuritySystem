"""Scara de ban progresiv si contor de infractiuni per IP."""
import logging

from request_checker import ban_ip

from config import (
    BAN_LADDER,
    BAN_OFFENSE_PREFIX,
    OFFENSE_WINDOW_SECONDS,
    REDIS_SETTINGS,
    REDIS_THRESHOLDS,
    r,
)
from event_publisher import log_ban_event

log = logging.getLogger("web")

def progressive_ban_duration(offense_count: int) -> int:
    """Returneaza durata banului in secunde pentru un nivel de infractiune dat."""
    if offense_count <= 0:
        return BAN_LADDER[0]
    if offense_count > len(BAN_LADDER):
        return BAN_LADDER[-1]
    return BAN_LADDER[offense_count - 1]

def get_offense_count(ip: str) -> int:
    """Returneaza contorul curent de infractiuni pentru un IP (0 daca nu a fost banat)."""
    try:
        val = r.get(f"{BAN_OFFENSE_PREFIX}{ip}")
        return int(val) if val else 0
    except Exception:
        return 0

def increment_offense_count(ip: str) -> int:
    """Incrementeaza contorul de infractiuni, reseteaza TTL si returneaza noua valoare."""
    key = f"{BAN_OFFENSE_PREFIX}{ip}"
    try:
        new_val = r.incr(key)
        r.expire(key, OFFENSE_WINDOW_SECONDS)
        return int(new_val)
    except Exception:
        return 1

def reset_offense_count(ip: str) -> None:
    """Reseteaza contorul de infractiuni pentru un IP (folosit la reset admin)."""
    try:
        r.delete(f"{BAN_OFFENSE_PREFIX}{ip}")
    except Exception:
        pass

def ban_ip_with_history(ip: str, duration: int = 0, reason: str = "",
                        progressive: bool = True) -> int:
    """Baneaza un IP si logheaza evenimentul pentru istoricul admin."""
    if progressive:
        offense = increment_offense_count(ip)
        applied = progressive_ban_duration(offense)
        full_reason = f"{reason} | level={offense} duration={applied}s"
    else:
        applied = max(1, int(duration))
        full_reason = reason

    ban_ip(r, ip, applied, reason=full_reason)
    log_ban_event(ip, full_reason, applied)
    return applied

def get_admin_threshold(key: str, default):
    """Returneaza valoarea unui prag (override admin din Redis sau default)."""
    val = r.hget(REDIS_THRESHOLDS, key)
    if val is not None:
        try:
            return type(default)(float(val))
        except (ValueError, TypeError):
            pass
    return default

def get_ban_mode() -> str:
    """Returneaza modul curent de ban: 'ip' sau 'ip_fingerprint'."""
    mode = r.hget(REDIS_SETTINGS, "ban_mode")
    return mode if mode in ("ip", "ip_fingerprint") else "ip"
