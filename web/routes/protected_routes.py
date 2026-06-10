"""
Public routes that sit behind the CAPTCHA pass gate.

    /          — landing page (news feed)
    /health    — liveness probe
    /debug-ip  — echo the client IP (debugging only)

The captcha check is enforced globally by the ``@before_request`` hook
registered from ``event_publisher.register_security_gate``; these
routes do not need to verify the pass themselves.
"""
from flask import Blueprint, render_template, request


bp = Blueprint("protected_routes", __name__)


NEWS = [
    {"id": 1, "title": "Local Cat Elected Mayor"},
    {"id": 2, "title": "Coffee Improves Debugging"},
]


@bp.get("/")
def index():
    return render_template("index.html", news=NEWS)


@bp.get("/health")
def health():
    return {"ok": True}


@bp.route("/debug-ip")
def debug_ip():
    return {"ip": request.headers.get("X-Forwarded-For", request.remote_addr)}
