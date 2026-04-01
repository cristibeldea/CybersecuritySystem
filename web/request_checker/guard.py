import hashlib
import json
import time
from typing import Dict, Any, List

RECENT_LIST_KEY = "recent_requests"
PUBSUB_CHANNEL = "requests_channel"
BANNED_PREFIX = "ban:"


def classify_request(path: str) -> str:
    # Truly silent endpoints — never published
    if path in ("/health", "/favicon.ico", "/robots.txt", "/sitemap.xml"):
        return "noise"
    # Captcha asset loads are high-volume and not useful for analysis
    if path.startswith("/captcha/asset/"):
        return "noise"
    if path == "/behavior/check":
        return "noise"
    # Captcha actions — published for funnel timing (Module 5) but
    # excluded from volume counting (Module 1)
    if path in ("/captcha/verify", "/captcha/reset"):
        return "captcha"
    # "page" requests we care about
    if path == "/" or path.startswith("/article/") or path.startswith("/captcha"):
        return "page"
    return "other"


def _header_order_hash(headers) -> str:
    """Hash the order of header names to fingerprint the HTTP client.
    Different libraries/browsers send headers in different orders."""
    names: List[str] = []
    for name, _ in headers:
        lowered = name.lower()
        # Skip headers that vary per-request (cookies change, content-length varies)
        if lowered in ("cookie", "content-length", "content-type", "host"):
            continue
        names.append(lowered)
    raw = "|".join(names)
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


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
        # --- Headers for fingerprinting (Module 4) ---
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
    # Skip noise entirely — captcha/page/other all get published
    if entry.get("kind") == "noise":
        return

    payload = json.dumps(entry, separators=(",", ":"))

    pipe = redis_client.pipeline()
    pipe.lpush(RECENT_LIST_KEY, payload)
    pipe.ltrim(RECENT_LIST_KEY, 0, keep_last - 1)
    pipe.execute()

    redis_client.publish(PUBSUB_CHANNEL, payload)