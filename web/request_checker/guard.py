import hashlib
import json
import time
from typing import Dict, Any, List

RECENT_LIST_KEY = "recent_requests"
PUBSUB_CHANNEL = "requests_channel"
BANNED_PREFIX = "ban:"

def classify_request(path: str) -> str:
    if path in ("/health", "/favicon.ico", "/robots.txt", "/sitemap.xml"):
        return "noise"
    if path.startswith("/captcha/asset/"):
        return "noise"
    if path == "/behavior/check":
        return "noise"
    if path in ("/captcha/verify", "/captcha/reset"):
        return "captcha"
    if path == "/" or path.startswith("/article/") or path.startswith("/captcha"):
        return "page"
    return "other"

def _header_order_hash(headers) -> str:
    """Hash al ordinii antetelor pentru amprenta clientului HTTP."""
    names: List[str] = []
    for name, _ in headers:
        lowered = name.lower()
        if lowered in ("cookie", "content-length", "content-type", "host"):
            continue
        names.append(lowered)
    raw = "|".join(names)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]

def ban_ip(redis_client, ip: str, ban_seconds: int, reason: str = "") -> None:
    """Primitiva de ban partajata pentru aplicatia web."""
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
        "ae": headers.get("Accept-Encoding", ""),
        "acc": headers.get("Accept", ""),
        "ref": headers.get("Referer", ""),
        "conn": headers.get("Connection", ""),
        "cookie_present": bool(headers.get("Cookie", "")),
        "hdr_order": _header_order_hash(headers),
    }

def log_and_publish(redis_client, entry: Dict[str, Any], keep_last: int = 200) -> None:
    if entry.get("kind") == "noise":
        return

    payload = json.dumps(entry, separators=(",", ":"))

    pipe = redis_client.pipeline()
    pipe.lpush(RECENT_LIST_KEY, payload)
    pipe.ltrim(RECENT_LIST_KEY, 0, keep_last - 1)
    pipe.execute()

    redis_client.publish(PUBSUB_CHANNEL, payload)