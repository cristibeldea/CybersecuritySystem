import base64
import functools
import json
import os
import random
import string
import time
import logging
import hashlib
from typing import Any, Dict, Optional

import io

import redis
from flask import Flask, request, render_template, abort, redirect, make_response, jsonify, send_file, Response
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

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")

# Redis keys for admin state
REDIS_BAN_HISTORY = "admin:ban_history"       # list of JSON ban events
REDIS_NEAR_MISSES = "admin:near_misses"       # list of JSON near-miss events
REDIS_THRESHOLDS = "admin:thresholds"         # hash of threshold overrides
REDIS_SETTINGS = "admin:settings"             # hash of admin settings
REDIS_ADMIN_PW = "admin:password_hash"        # stored bcrypt/sha256 hash

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
app = Flask(__name__)

# -------------------------
# Helpers
# -------------------------
def _now():
    return int(time.time())


def _hash_password(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()


def _check_admin_auth():
    """Verify HTTP Basic Auth for admin endpoints."""
    auth = request.authorization
    if not auth:
        return False
    user = auth.username
    pw = auth.password
    if user != ADMIN_USER:
        return False
    # Check Redis for custom password, fall back to env var
    stored_hash = r.get(REDIS_ADMIN_PW)
    if stored_hash:
        return _hash_password(pw) == stored_hash
    return pw == ADMIN_PASSWORD


def _require_admin(f):
    """Decorator: require HTTP Basic Auth for admin routes."""
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        if not _check_admin_auth():
            return Response(
                "Admin login required", 401,
                {"WWW-Authenticate": 'Basic realm="Admin Dashboard"'}
            )
        return f(*args, **kwargs)
    return decorated


def log_ban_event(ip: str, reason: str, duration: int):
    """Record a ban event in Redis for the admin history view."""
    event = json.dumps({
        "ts": _now(), "ip": ip, "reason": reason, "duration": duration
    }, separators=(",", ":"))
    pipe = r.pipeline()
    pipe.lpush(REDIS_BAN_HISTORY, event)
    pipe.ltrim(REDIS_BAN_HISTORY, 0, 499)
    pipe.execute()


def log_near_miss(ip: str, module: str, score, threshold, details: str = ""):
    """Record a near-threshold event for the admin dashboard."""
    event = json.dumps({
        "ts": _now(), "ip": ip, "module": module,
        "score": round(float(score), 4) if score is not None else 0,
        "threshold": round(float(threshold), 4) if threshold is not None else 0,
        "details": details,
    }, separators=(",", ":"))
    pipe = r.pipeline()
    pipe.lpush(REDIS_NEAR_MISSES, event)
    pipe.ltrim(REDIS_NEAR_MISSES, 0, 199)
    pipe.execute()


def get_admin_threshold(key: str, default):
    """Get a threshold value: admin override from Redis, or default."""
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


def ban_ip_with_history(ip: str, duration: int, reason: str = ""):
    """Ban an IP and log the event for admin history."""
    ban_ip(r, ip, duration, reason=reason)
    log_ban_event(ip, reason, duration)

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
# Honeypot system
# -------------------------

# Dynamic trap path prefixes — combined with a random token per page load
# to create unique, unpredictable trap URLs.
TRAP_PATH_PREFIXES = [
    "/user/", "/account/", "/api/v2/", "/settings/",
    "/admin/", "/profile/", "/download/", "/export/",
    "/internal/", "/config/", "/session/", "/auth/",
]

# Trap form field names — no real form uses these.  Any submission = bot.
TRAP_FIELD_NAMES = {
    "newsletter", "terms_agree", "remember_me",
    "opt_out", "confirm_age", "website_url",
    "fax_number", "middle_name",
}


def _rand_id(n=8):
    """Random CSS-safe id like 'a3f8c1d2'."""
    return random.choice(string.ascii_lowercase) + "".join(
        random.choices(string.ascii_lowercase + string.digits, k=n - 1)
    )


def _rand_token(n=10):
    """Random URL-safe token like 'a3f8c1d2e9'."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def _generate_trap_paths(count=4):
    """Generate unique dynamic trap paths for this page load."""
    prefixes = random.sample(TRAP_PATH_PREFIXES, min(count, len(TRAP_PATH_PREFIXES)))
    return [prefix + _rand_token() for prefix in prefixes]


def _build_honeypot_html() -> str:
    """Generate randomised invisible honeypot elements + JS detection script.

    Four layers:
      1. Traditional hidden elements (opacity:0, off-screen, clip-rect)
      2. Hidden form with trap field names
      3. 1px transparent pixel-links placed in non-interactive page areas
      4. All trap links use dynamic paths backed by server-side catch-all routes
    """
    cls_zero = _rand_id()
    cls_off  = _rand_id()
    cls_clip = _rand_id()
    cls_pixel = _rand_id()   # 1px transparent pixel trap
    trap_attr = _rand_id()

    trap_paths = _generate_trap_paths(random.randint(3, 5))
    chosen_fields = random.sample(list(TRAP_FIELD_NAMES), random.randint(2, 3))

    field_labels = {
        "newsletter": "Subscribe to newsletter",
        "terms_agree": "I agree to the terms",
        "remember_me": "Remember me",
        "opt_out": "Opt out of tracking",
        "confirm_age": "I am over 18",
        "website_url": "Your website",
        "fax_number": "Fax number",
        "middle_name": "Middle name",
    }

    # --- Styles ---
    # Traditional hiding
    style = f"""<style>
.{cls_zero}{{opacity:0;position:absolute;z-index:-1;height:0;width:0;overflow:hidden;padding:0;margin:0;border:0;pointer-events:auto}}
.{cls_off}{{position:fixed;left:-9999px;top:-9999px;pointer-events:auto}}
.{cls_clip}{{position:absolute;clip:rect(0,0,0,0);height:1px;width:1px;overflow:hidden;white-space:nowrap;pointer-events:auto}}
.{cls_pixel}{{display:inline-block;width:1px;height:1px;overflow:hidden;color:transparent;background:transparent;border:0;padding:0;margin:0;font-size:0;line-height:0;text-decoration:none;pointer-events:auto;position:relative;z-index:0}}
</style>"""

    traps = []

    # Layer 1: traditional hidden links (2 paths)
    for href in trap_paths[:2]:
        cls = random.choice([cls_zero, cls_off, cls_clip])
        tid = _rand_id()
        traps.append(
            f'<a href="{href}" class="{cls}" id="{tid}" '
            f'data-{trap_attr}="1" tabindex="-1" aria-hidden="true">link</a>'
        )

    # Layer 2: hidden form with trap fields
    form_id = _rand_id()
    form_parts = [f'<form action="/hp-form" method="POST" class="{cls_off}" '
                  f'id="{form_id}" aria-hidden="true">']
    for name in chosen_fields:
        tid = _rand_id()
        label = field_labels.get(name, name.replace("_", " ").title())
        form_parts.append(
            f'<label for="{tid}">{label}</label>'
            f'<input type="checkbox" id="{tid}" name="{name}" '
            f'data-{trap_attr}="1" tabindex="-1">'
        )
    form_parts.append(f'<button type="submit" tabindex="-1" data-{trap_attr}="1">Submit</button>')
    form_parts.append('</form>')
    traps.append("\n".join(form_parts))

    # Layer 3: 1px transparent pixel-links (remaining paths)
    # These look like normal tracking pixels to getComputedStyle() —
    # fully visible, not hidden, not off-screen, just 1x1 transparent.
    for href in trap_paths[2:]:
        tid = _rand_id()
        traps.append(
            f'<a href="{href}" class="{cls_pixel}" id="{tid}" '
            f'data-{trap_attr}="1" tabindex="-1">&nbsp;</a>'
        )

    random.shuffle(traps)

    # Layer 4: JS detection — bonus for headless browsers
    script = f"""<script>
(function(){{
var ts=document.querySelectorAll('[data-{trap_attr}]');
ts.forEach(function(el){{
["click","mousedown","touchstart","focus","change","pointerdown"].forEach(function(ev){{
el.addEventListener(ev,function(){{
fetch("/hp-trap",{{method:"POST",headers:{{"Content-Type":"application/json"}},
body:JSON.stringify({{t:Date.now(),tag:el.tagName,id:el.id}}),credentials:"same-origin"}});
}},{{passive:true,once:true}});
}});
}});
}})();
</script>"""

    return style + "\n".join(traps) + script


@app.after_request
def inject_honeypots(response):
    """Inject invisible honeypot traps into post-captcha HTML pages."""
    if response.content_type and "text/html" not in response.content_type:
        return response
    if request.path.startswith(("/captcha", "/static", "/behavior", "/hp-trap", "/hp-form", "/admin")):
        return response

    try:
        html = response.get_data(as_text=True)
    except Exception:
        return response

    honeypot = _build_honeypot_html()

    if "</body>" in html:
        html = html.replace("</body>", honeypot + "\n</body>", 1)
    elif "</html>" in html:
        html = html.replace("</html>", honeypot + "\n</html>", 1)
    else:
        html += honeypot

    response.set_data(html)
    response.headers["Content-Length"] = len(response.get_data())
    return response


# --- Server-side trap endpoints ---

@app.post("/hp-trap")
def honeypot_trap_js():
    """JS-reported interaction with a hidden element."""
    ip = get_client_ip()
    log.warning("HONEYPOT JS-TRAP ip=%s", ip)
    ban_ip_with_history(ip, BAN_SECONDS_HONEYPOT, reason="honeypot:js_trap")
    return "", 204


@app.post("/hp-form")
def honeypot_form_trap():
    """A bot submitted the hidden honeypot form."""
    ip = get_client_ip()
    log.warning("HONEYPOT FORM-TRAP ip=%s fields=%s", ip, list(request.form.keys()))
    ban_ip_with_history(ip, BAN_SECONDS_HONEYPOT, reason="honeypot:form_submit")
    return "", 204


# Catch-all routes for dynamic trap paths.
# Any request to /user/<token>, /account/<token>, etc. = bot.
def _register_trap_prefix_routes():
    def _make_prefix_handler(prefix):
        def handler(token):
            ip = get_client_ip()
            log.warning("HONEYPOT LINK-TRAP ip=%s path=%s%s", ip, prefix, token)
            ban_ip_with_history(ip, BAN_SECONDS_HONEYPOT,
                   reason=f"honeypot:trap_link:{prefix}{token}")
            return "<html><body><h1>Page not available</h1></body></html>", 200
        return handler

    for prefix in TRAP_PATH_PREFIXES:
        endpoint = f"trap_prefix_{prefix.strip('/').replace('/', '_')}"
        rule = prefix + "<path:token>"
        app.add_url_rule(rule, endpoint=endpoint,
                         view_func=_make_prefix_handler(prefix),
                         methods=["GET", "POST"])

_register_trap_prefix_routes()


# -------------------------
# Gate + logging
# -------------------------
@app.before_request
def security_gate_and_logging():

    ip = get_client_ip()
    ip_banned = is_banned(r, ip)

    # Check if this request hits a honeypot trap prefix
    is_trap_path = any(request.path.startswith(p) for p in TRAP_PATH_PREFIXES)
    is_trap_endpoint = request.path in ("/hp-trap", "/hp-form")

    # Let captcha pages through even when banned — the captcha UI
    # shows the ban countdown instead of a raw 403.
    # Also let trap paths through so the trap handler can ban the bot.
    if ip_banned and not request.path.startswith(("/captcha", "/admin")) \
       and not is_trap_endpoint and not is_trap_path:
        abort(403)

    # Skip logging for internal/admin/static routes — these are not
    # user-browsing requests and should not be analysed by the inspector.
    if request.path.startswith(("/captcha", "/static", "/admin")):
        return

    entry = build_entry(
        ip=ip,
        username="anonymous",
        path=request.path,
        method=request.method,
        headers=request.headers,
    )

    log_and_publish(r, entry)

    # Let honeypot endpoints and trap paths through without captcha check
    if is_trap_endpoint or is_trap_path:
        return

    # Check for honeypot form fields in any POST body
    if request.method == "POST" and request.form:
        submitted_fields = set(request.form.keys())
        trap_hits = submitted_fields & TRAP_FIELD_NAMES
        if trap_hits:
            log.warning("HONEYPOT FIELD-TRAP ip=%s fields=%s", ip, list(trap_hits))
            ban_ip_with_history(ip, BAN_SECONDS_HONEYPOT,
                   reason=f"honeypot:trap_fields:{','.join(trap_hits)}")
            abort(403)

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

    if banned:
        # If in-memory says banned but Redis ban was cleared (admin unban),
        # reset the in-memory state so the user can retry.
        ip = get_client_ip()
        if not is_banned(r, ip):
            state["ban_until"] = 0
            state["fail_count"] = 0
            state["kind"] = "checkbox"
            state["current"] = {"kind": "checkbox", "attempt_index": 0}
            banned = False
            ban_until = 0

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
        ban_ip_with_history(ip, BAN_SECONDS_HONEYPOT, reason="honeypot:decoy_button_interaction")
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

    # If in-memory says banned but Redis ban was cleared (admin unban),
    # reset the in-memory state so the user can retry.
    if banned:
        ip = get_client_ip()
        if not is_banned(r, ip):
            state["ban_until"] = 0
            state["fail_count"] = 0
            state["kind"] = "checkbox"
            state["current"] = {"kind": "checkbox", "attempt_index": 0}
            banned = False
            ban_until = 0

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
        ban_ip_with_history(ip, BAN_SECONDS_CAPTCHA, reason=f"captcha:fail_count>={state.get('fail_count', 0)}")
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
            ban_ip_with_history(ip, BAN_SECONDS_CAPTCHA, reason=f"captcha:checkbox_fail_count>={state.get('fail_count', 0)}")
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
            ban_ip_with_history(ip, BAN_SECONDS_CAPTCHA, reason=f"captcha:fail_count>={state.get('fail_count', 0)}")
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

    # Crop a 90% window centered at (cx, cy) fractions of the image
    img = Image.open(path)
    w, h = img.size
    crop_w = int(w * 0.9)
    crop_h = int(h * 0.9)

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

    # Near-miss: within 80-100% of threshold
    near_miss_floor = int(BEHAVIOR_RISK_THRESHOLD * 0.80)
    if near_miss_floor <= risk < BEHAVIOR_RISK_THRESHOLD:
        log_near_miss(ip, "behavior", risk, BEHAVIOR_RISK_THRESHOLD,
                      json.dumps(reasons, default=str))

    if risk >= BEHAVIOR_RISK_THRESHOLD:
        ban_ip_with_history(ip, BAN_SECONDS_BEHAVIOR, reason=f"behavior:risk={risk}")
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
# ADMIN DASHBOARD
# -------------------------
@app.get("/admin")
@_require_admin
def admin_page():
    return render_template("admin.html")


@app.get("/admin/api/bans")
@_require_admin
def admin_get_bans():
    """List all currently active bans with TTL and reason."""
    keys = r.keys(f"{BANNED_PREFIX}*")
    bans = []
    for key in sorted(keys):
        ip = key[len(BANNED_PREFIX):]
        ttl = r.ttl(key)
        # Try to find reason from recent ban history
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


@app.post("/admin/api/unban")
@_require_admin
def admin_unban():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    r.delete(f"{BANNED_PREFIX}{ip}")
    log.info("ADMIN UNBAN ip=%s", ip)
    log_ban_event(ip, "manual:unban:admin", 0)
    return jsonify({"status": "ok"})


@app.post("/admin/api/ban")
@_require_admin
def admin_manual_ban():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "").strip()
    duration = int(data.get("duration", 600))
    reason = data.get("reason", "manual:admin")
    if not ip:
        return jsonify({"error": "ip required"}), 400
    ban_ip_with_history(ip, duration, reason=reason)
    log.info("ADMIN BAN ip=%s duration=%d reason=%s", ip, duration, reason)
    return jsonify({"status": "ok"})


@app.get("/admin/api/ban-history")
@_require_admin
def admin_ban_history():
    raw = r.lrange(REDIS_BAN_HISTORY, 0, 199)
    history = []
    for item in raw:
        try:
            history.append(json.loads(item))
        except Exception:
            pass
    return jsonify({"history": history})


@app.get("/admin/api/near-misses")
@_require_admin
def admin_near_misses():
    raw = r.lrange(REDIS_NEAR_MISSES, 0, 199)
    events = []
    for item in raw:
        try:
            events.append(json.loads(item))
        except Exception:
            pass
    return jsonify({"events": events})


@app.get("/admin/api/logs")
@_require_admin
def admin_logs():
    raw = r.lrange("recent_requests", 0, 99)
    logs = []
    for item in raw:
        try:
            logs.append(json.loads(item))
        except Exception:
            pass
    return jsonify({"logs": logs})


@app.get("/admin/api/thresholds")
@_require_admin
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
    # Overlay Redis overrides
    overrides = r.hgetall(REDIS_THRESHOLDS) or {}
    for key, val in overrides.items():
        try:
            defaults[key] = float(val)
        except (ValueError, TypeError):
            pass
    return jsonify(defaults)


@app.post("/admin/api/thresholds")
@_require_admin
def admin_set_thresholds():
    data = request.get_json(silent=True) or {}
    for key, val in data.items():
        r.hset(REDIS_THRESHOLDS, key, str(val))
    log.info("ADMIN thresholds updated: %s", list(data.keys()))
    return jsonify({"status": "ok"})


@app.get("/admin/api/settings")
@_require_admin
def admin_get_settings():
    ban_mode = get_ban_mode()
    return jsonify({"ban_mode": ban_mode})


@app.post("/admin/api/settings")
@_require_admin
def admin_set_settings():
    data = request.get_json(silent=True) or {}
    if "ban_mode" in data:
        mode = data["ban_mode"]
        if mode in ("ip", "ip_fingerprint"):
            r.hset(REDIS_SETTINGS, "ban_mode", mode)
            log.info("ADMIN ban_mode changed to: %s", mode)
    return jsonify({"status": "ok"})


@app.post("/admin/api/password")
@_require_admin
def admin_change_password():
    data = request.get_json(silent=True) or {}
    pw = data.get("password", "")
    if len(pw) < 4:
        return jsonify({"error": "Password too short"}), 400
    r.set(REDIS_ADMIN_PW, _hash_password(pw))
    log.info("ADMIN password changed")
    return jsonify({"status": "ok"})


# -------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)