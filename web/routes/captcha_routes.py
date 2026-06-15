"""Rutele pentru CAPTCHA si telemetria comportamentala."""
import io
import json
import logging

from flask import (
    Blueprint, abort, jsonify, make_response,
    render_template, request, send_file,
)
from PIL import Image

from captcha import (
    CAPTCHA_COOKIE,
    SESSION_COOKIE,
    build_asset_response_data,
    compute_behavior_risk,
    create_or_reset_session,
    ensure_state,
    extract_features,
    is_banned as captcha_is_banned,
    make_pass_token,
    record_failure_and_advance,
    verify_checkbox,
    verify_grid_answer,
)
from config import (
    BAN_SECONDS_BEHAVIOR,
    BAN_SECONDS_CAPTCHA,
    BAN_SECONDS_HONEYPOT,
    BEHAVIOR_RISK_THRESHOLD,
    CAPTCHA_SECRET,
    COOKIE_SAMESITE,
    COOKIE_SECURE,
    PASS_TTL_SECONDS,
    POLICY_VERSION,
    r,
)
from ban_manager import ban_ip_with_history
from event_publisher import log_near_miss
from helpers import (
    _now,
    get_client_ip,
    get_or_set_sid,
    host_header,
    safe_state,
    ua_hash,
)
from request_checker import BANNED_PREFIX, is_banned

log = logging.getLogger("web")
bp = Blueprint("captcha_routes", __name__)

@bp.get("/captcha")
def captcha_page():
    sid = get_or_set_sid()
    state = ensure_state(sid)

    banned, ban_until = captcha_is_banned(state)

    if banned:
        ip = get_client_ip()
        if not is_banned(r, ip):
            state["ban_until"] = 0
            state["fail_count"] = 0
            state["kind"] = "checkbox"
            state["current"] = {"kind": "checkbox", "attempt_index": 0}
            banned = False
            ban_until = 0
        else:
            ttl = r.ttl(f"{BANNED_PREFIX}{ip}")
            if ttl and ttl > 0:
                ban_until = _now() + ttl
                state["ban_until"] = ban_until

    if not banned:
        ip = get_client_ip()
        if is_banned(r, ip):
            ttl = r.ttl(f"{BANNED_PREFIX}{ip}")
            if ttl and ttl > 0:
                banned = True
                ban_until = _now() + ttl

    resp = make_response(
        render_template(
            "captcha.html",
            config={
                "nonce": state["nonce"],
                "state": safe_state(state),
                "ban_until": ban_until if banned else 0,
                "redirect_to": "/",
            },
        )
    )
    resp.set_cookie(
        SESSION_COOKIE, sid,
        httponly=True, samesite=COOKIE_SAMESITE, secure=COOKIE_SECURE,
    )
    return resp

@bp.post("/captcha/verify")
def captcha_verify():
    sid = request.cookies.get(SESSION_COOKIE, "")
    if not sid:
        abort(403)

    state = ensure_state(sid)
    payload = request.get_json(silent=True) or {}

    if payload.get("hp"):
        ip = get_client_ip()
        ban_ip_with_history(ip, BAN_SECONDS_HONEYPOT,
                            reason="honeypot:decoy_button_interaction")
        log.warning("HONEYPOT triggered ip=%s sid=%s", ip, sid)
        ban_until = _now() + BAN_SECONDS_HONEYPOT
        state["ban_until"] = ban_until
        state["kind"] = "banned"
        state["current"] = {"kind": "banned", "attempt_index": 0}
        return jsonify({"action": "banned", "ban_until": ban_until}), 429

    banned, ban_until = captcha_is_banned(state)

    if banned:
        ip = get_client_ip()
        if not is_banned(r, ip):
            state["ban_until"] = 0
            state["fail_count"] = 0
            state["kind"] = "checkbox"
            state["current"] = {"kind": "checkbox", "attempt_index": 0}
            banned = False
            ban_until = 0
        else:
            ttl = r.ttl(f"{BANNED_PREFIX}{ip}")
            if ttl and ttl > 0:
                ban_until = _now() + ttl
                state["ban_until"] = ban_until

    if not banned:
        ip = get_client_ip()
        if is_banned(r, ip):
            ttl = r.ttl(f"{BANNED_PREFIX}{ip}")
            if ttl and ttl > 0:
                banned = True
                ban_until = _now() + ttl

    if banned:
        ip = get_client_ip()
        applied = ban_ip_with_history(
            ip, BAN_SECONDS_CAPTCHA,
            reason=f"captcha:fail_count>={state.get('fail_count', 0)}",
        )
        ban_until = _now() + applied
        state["ban_until"] = ban_until
        return jsonify({"action": "banned", "ban_until": ban_until}), 429

    current_kind = state["current"]["kind"]

    if current_kind == "checkbox":
        ok, msg = verify_checkbox(CAPTCHA_SECRET, state, payload)

        banned, ban_until = captcha_is_banned(state)
        if banned:
            ip = get_client_ip()
            applied = ban_ip_with_history(
                ip, BAN_SECONDS_CAPTCHA,
                reason=f"captcha:checkbox_fail_count>={state.get('checkbox_fail_count', 0)}",
            )
            ban_until = _now() + applied
            state["ban_until"] = ban_until
            return jsonify({"action": "banned", "ban_until": ban_until}), 429

        if not ok:
            return jsonify({
                "action": "retry",
                "message": msg.get("message", "Încearcați din nou."),
                "nonce": state["nonce"],
                "state": safe_state(state),
            })

        return jsonify({
            "action": "next",
            "nonce": state["nonce"],
            "state": safe_state(state),
        })

    if current_kind == "grid":
        ok, _debug = verify_grid_answer(state, payload)

        if ok:
            token = make_pass_token(
                CAPTCHA_SECRET, sid=sid,
                ttl_seconds=PASS_TTL_SECONDS,
                policy_version=POLICY_VERSION,
                context={"ua": ua_hash(), "host": host_header()},
            )
            create_or_reset_session(sid)
            resp = make_response(jsonify({"action": "pass", "redirect": "/"}))
            resp.set_cookie(
                CAPTCHA_COOKIE, token,
                max_age=PASS_TTL_SECONDS, httponly=True,
                samesite=COOKIE_SAMESITE, secure=COOKIE_SECURE,
            )
            return resp

        record_failure_and_advance(CAPTCHA_SECRET, state)

        banned, ban_until = captcha_is_banned(state)
        if banned:
            ip = get_client_ip()
            applied = ban_ip_with_history(
                ip, BAN_SECONDS_CAPTCHA,
                reason=f"captcha:fail_count>={state.get('fail_count', 0)}",
            )
            ban_until = _now() + applied
            state["ban_until"] = ban_until
            return jsonify({"action": "banned", "ban_until": ban_until}), 429

        return jsonify({
            "action": "next",
            "nonce": state["nonce"],
            "state": safe_state(state),
        })

    abort(400)

@bp.post("/captcha/reset")
def captcha_reset():
    sid = request.cookies.get(SESSION_COOKIE, "")
    if not sid:
        abort(403)

    state = create_or_reset_session(sid)
    return jsonify({
        "nonce": state["nonce"],
        "state": safe_state(state),
        "ban_until": 0,
    })

@bp.get("/captcha/asset/<nonce>/<token>")
def captcha_asset(nonce, token):
    sid = request.cookies.get(SESSION_COOKIE, "")

    result = build_asset_response_data(CAPTCHA_SECRET, sid, nonce, token)
    if not result:
        abort(404)

    path, mimetype, cx, cy = result

    img = Image.open(path)
    w, h = img.size
    crop_w = int(w * 0.9)
    crop_h = int(h * 0.9)

    center_x = int(cx * w)
    center_y = int(cy * h)
    left = max(0, min(center_x - crop_w // 2, w - crop_w))
    top  = max(0, min(center_y - crop_h // 2, h - crop_h))

    cropped = img.crop((left, top, left + crop_w, top + crop_h))

    buf = io.BytesIO()
    fmt = "PNG" if mimetype == "image/png" else "JPEG"
    cropped.save(buf, format=fmt)
    buf.seek(0)
    return send_file(buf, mimetype=mimetype)

@bp.post("/behavior/check")
def behavior_check():
    """Primeste telemetrie comportamentala de la site, o scoreaza si returneaza decizia."""
    ip = get_client_ip()
    payload = request.get_json(silent=True) or {}

    features = extract_features(payload)
    risk, reasons = compute_behavior_risk(features)

    log.info("behavior_check ip=%s risk=%d reasons=%s",
             ip, risk, json.dumps(reasons, default=str))

    near_miss_floor = int(BEHAVIOR_RISK_THRESHOLD * 0.80)
    if near_miss_floor <= risk < BEHAVIOR_RISK_THRESHOLD:
        log_near_miss(ip, "behavior", risk, BEHAVIOR_RISK_THRESHOLD,
                      json.dumps(reasons, default=str))

    if risk >= BEHAVIOR_RISK_THRESHOLD:
        ban_ip_with_history(ip, BAN_SECONDS_BEHAVIOR,
                            reason=f"behavior:risk={risk}")
        log.warning("BEHAVIOR BAN ip=%s risk=%d", ip, risk)
        return jsonify({"status": "banned", "risk": risk}), 429

    return jsonify({"status": "ok", "risk": risk})
