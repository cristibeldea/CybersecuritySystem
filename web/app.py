import json
import os
import time
from flask import Flask, request, render_template, abort
import redis

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
BAN_SECONDS = int(os.getenv("BAN_SECONDS", "600"))

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

app = Flask(__name__)

RECENT_LIST_KEY = "recent_requests"        # list of last 100 requests (human/audit)
PUBSUB_CHANNEL = "requests_channel"        # realtime feed to inspector
BANNED_PREFIX = "ban:"                     # ban:1.2.3.4 => "1" with TTL


def get_client_ip() -> str:
    """
    In Docker (no reverse proxy), request.remote_addr is fine.
    If you later add a proxy (nginx/traefik), use X-Forwarded-For properly.
    """
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        # Take left-most IP (original client) if present
        return xff.split(",")[0].strip()
    return request.remote_addr or "unknown"


def get_username() -> str:
    # Minimal: accept ?user=alice or X-User: alice
    return (request.args.get("user") or request.headers.get("X-User") or "anonymous").strip()


@app.before_request
def ban_check_and_log():
    ip = get_client_ip()
    if ip != "unknown":
        if r.exists(f"{BANNED_PREFIX}{ip}"):
            abort(403, description="Your IP is temporarily banned.")

    username = get_username()
    ts = int(time.time())
    entry = {
        "ip": ip,
        "ts": ts,
        "username": username,
        "path": request.path,
        "method": request.method,
    }
    payload = json.dumps(entry, separators=(",", ":"))

    # 1) Keep last 100 in a Redis list
    pipe = r.pipeline()
    pipe.lpush(RECENT_LIST_KEY, payload)
    pipe.ltrim(RECENT_LIST_KEY, 0, 99)
    pipe.execute()

    # 2) Publish realtime event for inspector
    r.publish(PUBSUB_CHANNEL, payload)


NEWS = [
    {"id": 1, "title": "Local Cat Elected Mayor", "body": "In a shocking turn of events... the cat promised more naps."},
    {"id": 2, "title": "Scientists Confirm Coffee Improves Debugging", "body": "Peer-reviewed results show +42% productivity per mug."},
    {"id": 3, "title": "New Redis-Based Telepathy Protocol Rumored", "body": "Experts remain skeptical, but LISTs and STREAMs are excited."},
]


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


if __name__ == "__main__":
    # Flask dev server is fine for a mock.
    # In real deployments, switch to gunicorn/uvicorn + a proxy.
    app.run(host="0.0.0.0", port=8080)