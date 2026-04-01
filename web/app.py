import json
import os
import time
import logging
import hashlib
from typing import Any, Dict, Optional

import io

import redis
from flask import Flask, request, render_template, abort, redirect, make_response, jsonify, send_file
from PIL import Image

from request_checker import is_banned, ban_ip, build_entry, log_and_publish, BANNED_PREFIX

from captcha import (
    CAPTCHA_COOKIE,
    SESSION_COOKIE,
    make_session_id,
    make_nonce,
    extract_features,
    compute_behavior_risk,
    make_pass_token,
    verify_pass_token,
    create_or_reset_session,
    ensure_state,
    next_challenge,
    verify_checkbox,
    verify_grid_answer,
    record_failure_and_advance,
    is_banned as captcha_is_banned,
    build_asset_response_data,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [web] %(message)s")
log = logging.getLogger("web")

# -------------------------
# Config
# -------------------------
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

CAPTCHA_SECRET = os.getenv("CAPTCHA_SECRET", "change-this")
POLICY_VERSION = os.getenv("POLICY_VERSION", "1")

PASS_TTL_SECONDS = 1800
BAN_SECONDS_CAPTCHA = 60        # 1 minute — failed captcha attempts
BAN_SECONDS_HONEYPOT = 2 * 60   # 2 minutes — honeypot trap (bot confirmed)
BAN_SECONDS_BEHAVIOR = 90       # 1.5 minutes — behavioral analysis on website
BEHAVIOR_RISK_THRESHOLD = 78    # same as captcha checkbox threshold
COOKIE_SECURE = False
COOKIE_SAMESITE = "Lax"

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
app = Flask(__name__)

# -------------------------
# Helpers
# -------------------------
def _now():
    return int(time.time())

def get_client_ip():
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"

def ua_hash():
    ua = request.headers.get("User-Agent", "")[:250]
    return hashlib.sha256(ua.encode()).hexdigest()

def host_header():
    return (request.host or "")[:200]

def get_or_set_sid(resp=None):
    sid = request.cookies.get(SESSION_COOKIE, "")
    if sid and len(sid) > 10:
        return sid

    sid = make_session_id()

    if resp:
        resp.set_cookie(
            SESSION_COOKIE,
            sid,
            max_age=604800,
            httponly=True,
            samesite=COOKIE_SAMESITE,
            secure=COOKIE_SECURE,
        )

    return sid

def safe_state(state):
    """Strip server-only fields before sending state to the client."""
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

# -------------------------
# Pass verification
# -------------------------
def verify_pass():
    sid = request.cookies.get(SESSION_COOKIE, "")
    tok = request.cookies.get(CAPTCHA_COOKIE, "")

    if not sid or not tok:
        return False

    ok, _ = verify_pass_token(
        CAPTCHA_SECRET,
        tok,
        sid=sid,
        policy_version=POLICY_VERSION,
        context={"ua": ua_hash(), "host": host_header()},
    )

    return ok

# -------------------------
# Gate + logging
# -------------------------
@app.before_request
def security_gate_and_logging():

    ip = get_client_ip()
    ip_banned = is_banned(r, ip)

    # Let captcha pages through even when banned — the captcha UI
    # shows the ban countdown instead of a raw 403
    if ip_banned and not request.path.startswith("/captcha"):
        abort(403)

    entry = build_entry(
        ip=ip,
        username="anonymous",
        path=request.path,
        method=request.method,
        headers=request.headers,
    )

    log_and_publish(r, entry)

    if request.path.startswith("/captcha") or request.path.startswith("/static"):
        return

    if request.path == "/behavior/check":
        return

    if not verify_pass():
        return redirect("/captcha")

# -------------------------
# CAPTCHA PAGE
# -------------------------
@app.get("/captcha")
def captcha_page():

    sid = get_or_set_sid()
    state = ensure_state(sid)

    # Check both in-memory and Redis ban
    banned, ban_until = captcha_is_banned(state)

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
        SESSION_COOKIE,
        sid,
        httponly=True,
        samesite=COOKIE_SAMESITE,
        secure=COOKIE_SECURE,
    )

    return resp

# -------------------------
# CAPTCHA VERIFY
# -------------------------
@app.post("/captcha/verify")
def captcha_verify():

    sid = request.cookies.get(SESSION_COOKIE, "")

    if not sid:
        abort(403)

    state = ensure_state(sid)

    payload = request.get_json(silent=True) or {}

    # Honeypot trap — instant ban, separate from captcha failure logic
    if payload.get("hp"):
        ip = get_client_ip()
        ban_ip(r, ip, BAN_SECONDS_HONEYPOT, reason="honeypot:decoy_button_interaction")
        log.warning("HONEYPOT triggered ip=%s sid=%s", ip, sid)
        ban_until = _now() + BAN_SECONDS_HONEYPOT
        state["ban_until"] = ban_until
        state["kind"] = "banned"
        state["current"] = {"kind": "banned", "attempt_index": 0}
        return jsonify({
            "action": "banned",
            "ban_until": ban_until
        }), 429

    banned, ban_until = captcha_is_banned(state)

    # Also check Redis ban (survives restarts / cookie clears)
    if not banned:
        ip = get_client_ip()
        if is_banned(r, ip):
            ttl = r.ttl(f"{BANNED_PREFIX}{ip}")
            if ttl and ttl > 0:
                banned = True
                ban_until = _now() + ttl

    if banned:
        ip = get_client_ip()
        ban_ip(r, ip, BAN_SECONDS_CAPTCHA, reason=f"captcha:fail_count>={state.get('fail_count', 0)}")
        return jsonify({
            "action": "banned",
            "ban_until": ban_until
        }), 429

    current_kind = state["current"]["kind"]

    # -----------------
    # CHECKBOX
    # -----------------
    if current_kind == "checkbox":

        ok, _ = verify_checkbox(CAPTCHA_SECRET, state, payload)

        # verify_checkbox already calls next_challenge or record_failure_and_advance
        banned, ban_until = captcha_is_banned(state)
        if banned:
            ip = get_client_ip()
            ban_ip(r, ip, BAN_SECONDS_CAPTCHA, reason=f"captcha:checkbox_fail_count>={state.get('fail_count', 0)}")
            return jsonify({
                "action": "banned",
                "ban_until": ban_until
            }), 429

        return jsonify({
            "action": "next",
            "nonce": state["nonce"],
            "state": safe_state(state)
        })

    # -----------------
    # GRID CAPTCHA
    # -----------------
    if current_kind == "grid":

        ok, debug = verify_grid_answer(state, payload)

        if ok:

            token = make_pass_token(
                CAPTCHA_SECRET,
                sid=sid,
                ttl_seconds=PASS_TTL_SECONDS,
                policy_version=POLICY_VERSION,
                context={"ua": ua_hash(), "host": host_header()},
            )

            create_or_reset_session(sid)

            resp = make_response(jsonify({
                "action": "pass",
                "redirect": "/"
            }))

            resp.set_cookie(
                CAPTCHA_COOKIE,
                token,
                max_age=PASS_TTL_SECONDS,
                httponly=True,
                samesite=COOKIE_SAMESITE,
                secure=COOKIE_SECURE,
            )

            return resp

        record_failure_and_advance(CAPTCHA_SECRET, state)

        banned, ban_until = captcha_is_banned(state)

        if banned:
            ip = get_client_ip()
            ban_ip(r, ip, BAN_SECONDS_CAPTCHA, reason=f"captcha:fail_count>={state.get('fail_count', 0)}")
            return jsonify({
                "action": "banned",
                "ban_until": ban_until
            }), 429

        return jsonify({
            "action": "next",
            "nonce": state["nonce"],
            "state": safe_state(state)
        })

    abort(400)

# -------------------------
# CAPTCHA RESET
# -------------------------
@app.post("/captcha/reset")
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

# -------------------------
# CAPTCHA ASSET (images)
# -------------------------
@app.get("/captcha/asset/<nonce>/<token>")
def captcha_asset(nonce, token):

    sid = request.cookies.get(SESSION_COOKIE, "")

    result = build_asset_response_data(
        CAPTCHA_SECRET,
        sid,
        nonce,
        token
    )

    if not result:
        abort(404)

    path, mimetype, cx, cy = result

    # Crop an 80% window centered at (cx, cy) fractions of the image
    img = Image.open(path)
    w, h = img.size
    crop_w = int(w * 0.8)
    crop_h = int(h * 0.8)

    # Convert center fractions to pixel coords, clamped so crop stays in bounds
    center_x = int(cx * w)
    center_y = int(cy * h)
    left = max(0, min(center_x - crop_w // 2, w - crop_w))
    top = max(0, min(center_y - crop_h // 2, h - crop_h))

    cropped = img.crop((left, top, left + crop_w, top + crop_h))

    buf = io.BytesIO()
    fmt = "PNG" if mimetype == "image/png" else "JPEG"
    cropped.save(buf, format=fmt)
    buf.seek(0)

    return send_file(buf, mimetype=mimetype)

# -------------------------
# BEHAVIORAL ANALYSIS (website)
# -------------------------
@app.post("/behavior/check")
def behavior_check():
    """Receive behavioral telemetry from the main website,
    score it with the same pipeline used by the captcha,
    and ban the IP if the risk is too high."""

    ip = get_client_ip()

    payload = request.get_json(silent=True) or {}

    features = extract_features(payload)
    risk, reasons = compute_behavior_risk(features)

    log.info("behavior_check ip=%s risk=%d reasons=%s", ip, risk, json.dumps(reasons, default=str))

    if risk >= BEHAVIOR_RISK_THRESHOLD:
        ban_ip(r, ip, BAN_SECONDS_BEHAVIOR, reason=f"behavior:risk={risk}")
        log.warning("BEHAVIOR BAN ip=%s risk=%d", ip, risk)
        return jsonify({"status": "banned", "risk": risk}), 429

    return jsonify({"status": "ok", "risk": risk})


# -------------------------
# App routes
# -------------------------
NEWS = [
    {"id": 1, "title": "Local Cat Elected Mayor"},
    {"id": 2, "title": "Coffee Improves Debugging"},
]

@app.get("/")
def index():
    return render_template("index.html", news=NEWS)

@app.get("/health")
def health():
    return {"ok": True}

@app.route("/debug-ip")
def debug_ip():
    return {"ip": request.headers.get("X-Forwarded-For", request.remote_addr)}

# -------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)