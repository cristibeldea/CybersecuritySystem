"""Rutele publice care stau in spatele portii CAPTCHA."""
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
