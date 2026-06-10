"""
Progressive ban ladder + per-IP offense counter + ``ban_ip_with_history``.

Each new ban for the same IP escalates the duration via ``BAN_LADDER``.
The offense counter lives in Redis with a 7-day TTL — if the IP stays
clean during that window the counter resets and the next ban starts at
level 1.

``ban_ip_with_history`` is the single entry point used by every other
module that needs to ban an IP; it both writes the ban to Redis (via
``request_checker.ban_ip``) and records an admin-history event (via
``event_publisher.log_ban_event``).
"""
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


# ---------------------------------------------------------------------
# Progressive ladder
# ---------------------------------------------------------------------
def progressive_ban_duration(offense_count: int) -> int:
    """Return ban duration in seconds for a given offense count (1-based)."""
    if offense_count <= 0:
        return BAN_LADDER[0]
    if offense_count > len(BAN_LADDER):
        return BAN_LADDER[-1]
    return BAN_LADDER[offense_count - 1]


def get_offense_count(ip: str) -> int:
    """Return the current offense count for an IP (0 if never banned)."""
    try:
        val = r.get(f"{BAN_OFFENSE_PREFIX}{ip}")
        return int(val) if val else 0
    except Exception:
        return 0


def increment_offense_count(ip: str) -> int:
    """Increment the offense counter for an IP, reset TTL, return new value."""
    key = f"{BAN_OFFENSE_PREFIX}{ip}"
    try:
        new_val = r.incr(key)
        r.expire(key, OFFENSE_WINDOW_SECONDS)
        return int(new_val)
    except Exception:
        return 1


def reset_offense_count(ip: str) -> None:
    """Clear the offense counter for an IP (used by admin reset)."""
    try:
        r.delete(f"{BAN_OFFENSE_PREFIX}{ip}")
    except Exception:
        pass


# ---------------------------------------------------------------------
# Public ban entry point
# ---------------------------------------------------------------------
def ban_ip_with_history(ip: str, duration: int = 0, reason: str = "",
                        progressive: bool = True) -> int:
    """Ban an IP and log the event for admin history.

    When ``progressive=True`` (default), the duration is computed from
    the offense ladder using the per-IP counter, ignoring the passed
    duration. Pass ``progressive=False`` to apply a fixed duration (used
    by manual admin bans).

    Returns the duration that was actually applied.
    """
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


# ---------------------------------------------------------------------
# Admin overrides
# ---------------------------------------------------------------------
def get_admin_threshold(key: str, default):
    """Resolve a threshold value: admin override from Redis or default."""
    val = r.hget(REDIS_THRESHOLDS, key)
    if val is not None:
        try:
            return type(default)(float(val))
        except (ValueError, TypeError):
            pass
    return default


def get_ban_mode() -> str:
    """Get the current ban mode: 'ip' or 'ip_fingerprint'."""
    mode = r.hget(REDIS_SETTINGS, "ban_mode")
    return mode if mode in ("ip", "ip_fingerprint") else "ip"
