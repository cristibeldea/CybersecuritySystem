"""
Admin dashboard + JSON API for inspecting bans, history, near-misses,
thresholds and settings.

All routes are protected by HTTP Basic Auth via ``require_admin``.
"""
import json
import logging

from flask import Blueprint, jsonify, render_template, request

from ban_manager import (
    ban_ip_with_history,
    get_ban_mode,
    get_offense_count,
    progressive_ban_duration,
    reset_offense_count,
)
from config import (
    BAN_LADDER,
    BAN_SECONDS_BEHAVIOR,
    BAN_SECONDS_CAPTCHA,
    BAN_SECONDS_HONEYPOT,
    BEHAVIOR_RISK_THRESHOLD,
    REDIS_ADMIN_PW,
    REDIS_BAN_HISTORY,
    REDIS_NEAR_MISSES,
    REDIS_SETTINGS,
    REDIS_THRESHOLDS,
    r,
)
from event_publisher import log_ban_event
from helpers import _hash_password, require_admin
from request_checker import BANNED_PREFIX


log = logging.getLogger("web")
bp = Blueprint("admin_routes", __name__)


# ---------------------------------------------------------------------
# Dashboard page
# ---------------------------------------------------------------------
@bp.get("/admin")
@require_admin
def admin_page():
    return render_template("admin.html")


# ---------------------------------------------------------------------
# Ban inspection + manual ban / unban
# ---------------------------------------------------------------------
@bp.get("/admin/api/bans")
@require_admin
def admin_get_bans():
    """List all currently active bans with TTL and reason."""
    keys = r.keys(f"{BANNED_PREFIX}*")
    bans = []
    for key in sorted(keys):
        ip = key[len(BANNED_PREFIX):]
        ttl = r.ttl(key)
        # Find the most recent matching reason from the history list
        reason = ""
        raw_history = r.lrange(REDIS_BAN_HISTORY, 0, 99)
        for raw in raw_history:
            try:
                evt = json.loads(raw)
                if evt.get("ip") == ip:
                    reason = evt.get("reason", "")
                    break
            except Exception:
                pass
        bans.append({"ip": ip, "ttl": max(0, ttl), "reason": reason})
    return jsonify({"bans": bans})


@bp.post("/admin/api/unban")
@require_admin
def admin_unban():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    r.delete(f"{BANNED_PREFIX}{ip}")
    log.info("ADMIN UNBAN ip=%s", ip)
    log_ban_event(ip, "manual:unban:admin", 0)
    return jsonify({"status": "ok"})


@bp.post("/admin/api/ban")
@require_admin
def admin_manual_ban():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    duration = int(data.get("duration", 600))
    reason = data.get("reason", "manual:admin")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    ban_ip_with_history(ip, duration, reason=reason, progressive=False)
    log.info("ADMIN BAN ip=%s duration=%d reason=%s", ip, duration, reason)
    return jsonify({"status": "ok"})


@bp.post("/admin/api/unban-keep-counter")
@require_admin
def admin_unban_keep_counter():
    """Clear active ban but preserve offense counter — used by escalation
    demo to advance through ban levels without waiting for natural expiry."""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    r.delete(f"{BANNED_PREFIX}{ip}")
    log.info("ADMIN UNBAN(keep-counter) ip=%s", ip)
    log_ban_event(ip, "manual:unban:demo-skip", 0)
    return jsonify({"status": "ok", "offense_count": get_offense_count(ip)})


@bp.post("/admin/api/reset-offense")
@require_admin
def admin_reset_offense():
    """Reset the offense counter for an IP (cleanup between demo runs)."""
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    reset_offense_count(ip)
    r.delete(f"{BANNED_PREFIX}{ip}")
    log.info("ADMIN RESET OFFENSE ip=%s", ip)
    return jsonify({"status": "ok"})


@bp.get("/admin/api/offense-count")
@require_admin
def admin_offense_count():
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    count = get_offense_count(ip)
    duration_next = progressive_ban_duration(count + 1)
    return jsonify({
        "ip": ip,
        "offense_count": count,
        "next_ban_duration": duration_next,
        "ladder": BAN_LADDER,
    })


# ---------------------------------------------------------------------
# History + recent logs
# ---------------------------------------------------------------------
@bp.get("/admin/api/ban-history")
@require_admin
def admin_ban_history():
    raw = r.lrange(REDIS_BAN_HISTORY, 0, 199)
    history = []
    for item in raw:
        try:
            history.append(json.loads(item))
        except Exception:
            pass
    return jsonify({"history": history})


@bp.get("/admin/api/near-misses")
@require_admin
def admin_near_misses():
    raw = r.lrange(REDIS_NEAR_MISSES, 0, 199)
    events = []
    for item in raw:
        try:
            events.append(json.loads(item))
        except Exception:
            pass
    return jsonify({"events": events})


@bp.get("/admin/api/logs")
@require_admin
def admin_logs():
    raw = r.lrange("recent_requests", 0, 99)
    logs = []
    for item in raw:
        try:
            logs.append(json.loads(item))
        except Exception:
            pass
    return jsonify({"logs": logs})


# ---------------------------------------------------------------------
# Thresholds + settings + password
# ---------------------------------------------------------------------
@bp.get("/admin/api/thresholds")
@require_admin
def admin_get_thresholds():
    """Return current threshold values (overrides + defaults)."""
    defaults = {
        "max_req": 20,
        "window_seconds": 10,
        "ban_seconds": 600,
        "freq_cv_threshold": 0.10,
        "freq_min_requests": 6,
        "freq_ban_seconds": 120,
        "seq_transition_threshold": 0.90,
        "seq_min_repeats": 3,
        "seq_ban_seconds": 180,
        "fp_max_ips_per_print": 3,
        "fp_ban_seconds": 300,
        "funnel_cv_threshold": 0.08,
        "funnel_min_sessions": 3,
        "funnel_ban_seconds": 240,
        "bot_subnet_threshold": 4,
        "bot_onboard_threshold": 5,
        "bot_ban_seconds": 600,
        "behavior_risk_threshold": BEHAVIOR_RISK_THRESHOLD,
        "behavior_ban_seconds": BAN_SECONDS_BEHAVIOR,
        "honeypot_ban_seconds": BAN_SECONDS_HONEYPOT,
        "captcha_ban_seconds": BAN_SECONDS_CAPTCHA,
    }
    overrides = r.hgetall(REDIS_THRESHOLDS) or {}
    for key, val in overrides.items():
        try:
            defaults[key] = float(val)
        except (ValueError, TypeError):
            pass
    return jsonify(defaults)


@bp.post("/admin/api/thresholds")
@require_admin
def admin_set_thresholds():
    data = request.get_json(silent=True) or {}
    for key, val in data.items():
        r.hset(REDIS_THRESHOLDS, key, str(val))
    log.info("ADMIN thresholds updated: %s", list(data.keys()))
    return jsonify({"status": "ok"})


@bp.get("/admin/api/settings")
@require_admin
def admin_get_settings():
    return jsonify({"ban_mode": get_ban_mode()})


@bp.post("/admin/api/settings")
@require_admin
def admin_set_settings():
    data = request.get_json(silent=True) or {}
    if "ban_mode" in data:
        mode = data["ban_mode"]
        if mode in ("ip", "ip_fingerprint"):
            r.hset(REDIS_SETTINGS, "ban_mode", mode)
            log.info("ADMIN ban_mode changed to: %s", mode)
    return jsonify({"status": "ok"})


@bp.post("/admin/api/password")
@require_admin
def admin_change_password():
    data = request.get_json(silent=True) or {}
    pw = data.get("password", "")
    if len(pw) < 4:
        return jsonify({"error": "Password too short"}), 400
    r.set(REDIS_ADMIN_PW, _hash_password(pw))
    log.info("ADMIN password changed")
    return jsonify({"status": "ok"})
