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

from request_checker import is_banned, ban_ip, build_entry, log_and_publish

from captcha import (
    CAPTCHA_COOKIE,
    SESSION_COOKIE,
    make_session_id,
    make_nonce,
    extract_features,
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

    if is_banned(r, ip):
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

    if not verify_pass():
        return redirect("/captcha")

# -------------------------
# CAPTCHA PAGE
# -------------------------
@app.get("/captcha")
def captcha_page():

    sid = get_or_set_sid()

    state = ensure_state(sid)

    banned, ban_until = captcha_is_banned(state)

    resp = make_response(
        render_template(
            "captcha.html",
            config={
                "nonce": state["nonce"],
                "state": state["current"],
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

    banned, ban_until = captcha_is_banned(state)

    if banned:
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
        return jsonify({
            "action": "next",
            "nonce": state["nonce"],
            "state": state["current"]
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
            return jsonify({
                "action": "banned",
                "ban_until": ban_until
            }), 429

        return jsonify({
            "action": "next",
            "nonce": state["nonce"],
            "state": state["current"]
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
        "state": state["current"],
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