import json
import os
import time
import logging

import redis
from flask import Flask, request, render_template, abort, redirect, make_response, jsonify

from request_checker import is_banned, build_entry, log_and_publish
from captcha import (
    CAPTCHA_COOKIE,
    make_captcha_cookie,
    verify_captcha_cookie,
    compute_behavior_score,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s [web] %(message)s")
log = logging.getLogger("web")

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

CAPTCHA_SECRET = os.getenv("CAPTCHA_SECRET", "change-this-to-a-random-long-string")
CAPTCHA_TTL_SECONDS = int(os.getenv("CAPTCHA_TTL_SECONDS", "30"))

KEEP_LAST_REQUESTS = int(os.getenv("KEEP_LAST_REQUESTS", "200"))
CAPTCHA_MIN_SCORE = int(os.getenv("CAPTCHA_MIN_SCORE", "5"))

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
app = Flask(__name__)


def get_client_ip() -> str:
    # For local simulation you accept X-Forwarded-For.
    # In production you should only trust XFF from your reverse proxy.
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def get_username() -> str:
    return (request.args.get("user") or request.headers.get("X-User") or "anonymous").strip()


@app.before_request
def security_gate_and_logging():
    ip = get_client_ip()
    path = request.path

    # 1) CAPTCHA gate (allow captcha endpoints themselves + static)
    if path not in ("/captcha", "/captcha/verify") and not path.startswith("/static/"):
        token = request.cookies.get(CAPTCHA_COOKIE, "")
        if not token or not verify_captcha_cookie(CAPTCHA_SECRET, token, ip):
            if path == "/health":
                return
            return redirect("/captcha")

    # 2) Ban check
    if is_banned(r, ip):
        abort(403, description="Your IP is temporarily banned.")

    # 3) Log + publish request
    entry = build_entry(
        ip=ip,
        username=get_username(),
        path=path,
        method=request.method,
        headers=request.headers,
    )
    log_and_publish(r, entry, keep_last=KEEP_LAST_REQUESTS)


NEWS = [
    {"id": 1, "title": "Local Cat Elected Mayor", "body": "The cat promised more naps for all."},
    {"id": 2, "title": "Coffee Improves Debugging", "body": "A new study finds a strong correlation with fewer bugs."},
    {"id": 3, "title": "Redis Announces New LIST Feature", "body": "It still pushes to the left. People are thrilled."},
]


@app.get("/captcha")
def captcha_page():
    # If already verified, never show captcha again
    ip = get_client_ip()
    token = request.cookies.get(CAPTCHA_COOKIE, "")
    if token and verify_captcha_cookie(CAPTCHA_SECRET, token, ip):
        return redirect("/")

    resp = make_response(render_template("captcha.html"))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp


@app.post("/captcha/verify")
def captcha_verify():
    ip = get_client_ip()
    data = request.get_json(silent=True) or {}

    points = data.get("points") or []
    clicks = data.get("clicks") or []
    started = float(data.get("started_at_ms") or 0.0)
    ended = float(data.get("ended_at_ms") or 0.0)
    duration_ms = max(0.0, ended - started)

    # sanitize points
    clean_points = []
    for p in points:
        try:
            clean_points.append({"t": float(p["t"]), "x": float(p["x"]), "y": float(p["y"])})
        except Exception:
            continue

    clean_clicks = []
    for c in clicks:
        try:
            clean_clicks.append(float(c))
        except Exception:
            continue

    score, details = compute_behavior_score(clean_points, clean_clicks, duration_ms)

    if score < CAPTCHA_MIN_SCORE:
        log.warning("CAPTCHA failed ip=%s score=%s details=%s", ip, score, details)
        return (f"score_too_low details={details}", 403)

    resp = make_response(jsonify({"ok": True, "redirect": "/"}))
    resp.headers["Cache-Control"] = "no-store"

    token = make_captcha_cookie(CAPTCHA_SECRET, ip, CAPTCHA_TTL_SECONDS)
    resp.set_cookie(
        CAPTCHA_COOKIE,
        token,
        max_age=CAPTCHA_TTL_SECONDS,  # TTL scurt, cum ai acum
        httponly=True,
        samesite="Lax",
        secure=False,  # True în production cu HTTPS
    )
    return resp


@app.get("/")
def index():
    return render_template("index.html", news=NEWS)


@app.get("/article/<int:article_id>")
def article(article_id: int):
    for item in NEWS:
        if item["id"] == article_id:
            return render_template("article.html", item=item)
    abort(404)


@app.get("/health")
def health():
    return {"ok": True}

@app.route("/debug-ip")
def debug_ip():
    return {"ip": request.headers.get("X-Forwarded-For", request.remote_addr)}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)