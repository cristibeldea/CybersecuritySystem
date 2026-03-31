import json
import time
from typing import Dict, Any

RECENT_LIST_KEY = "recent_requests"
PUBSUB_CHANNEL = "requests_channel"
BANNED_PREFIX = "ban:"


def classify_request(path: str) -> str:
    # Ignore noisy endpoints
    if path in ("/health", "/favicon.ico", "/robots.txt", "/sitemap.xml"):
        return "noise"
    # "page" requests we care about (kept same as your current behavior)
    if path == "/" or path.startswith("/article/") or path.startswith("/captcha"):
        return "page"
    return "other"

def ban_ip(redis_client, ip: str, ban_seconds: int, reason: str = "") -> None:
    """
    Shared ban primitive for the web app.
    Uses the same Redis key contract as inspector.py:
      key = ban:<ip>, value = "1", TTL = ban_seconds
    """
    if not ip or ip == "unknown":
        return
    key = f"{BANNED_PREFIX}{ip}"
    redis_client.set(key, "1", ex=int(ban_seconds))

def is_banned(redis_client, ip: str) -> bool:
    if not ip or ip == "unknown":
        return False
    return bool(redis_client.exists(f"{BANNED_PREFIX}{ip}"))


def build_entry(ip: str, username: str, path: str, method: str, headers) -> Dict[str, Any]:
    kind = classify_request(path)
    return {
        "ip": ip,
        "ts": int(time.time()),
        "username": username,
        "path": path,
        "method": method,
        "kind": kind,
        "ua": headers.get("User-Agent", ""),
        "al": headers.get("Accept-Language", ""),
    }


def log_and_publish(redis_client, entry: Dict[str, Any], keep_last: int = 200) -> None:
    # Skip noise entirely
    if entry.get("kind") == "noise":
        return

    payload = json.dumps(entry, separators=(",", ":"))

    pipe = redis_client.pipeline()
    pipe.lpush(RECENT_LIST_KEY, payload)
    pipe.ltrim(RECENT_LIST_KEY, 0, keep_last - 1)
    pipe.execute()

    redis_client.publish(PUBSUB_CHANNEL, payload)