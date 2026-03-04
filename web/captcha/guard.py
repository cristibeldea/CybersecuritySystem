import base64
import hashlib
import hmac
import time
from typing import List, Dict, Tuple, Any


CAPTCHA_COOKIE = "captcha_pass"


def _sign(secret: str, payload: str) -> str:
    sig = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")


def make_captcha_cookie(secret: str, ip: str, ttl_seconds: int) -> str:
    exp = int(time.time()) + ttl_seconds
    payload = f"{ip}|{exp}"
    return f"{payload}|{_sign(secret, payload)}"


def verify_captcha_cookie(secret: str, token: str, ip: str) -> bool:
    try:
        parts = token.split("|")
        if len(parts) != 3:
            return False
        token_ip, exp_s, sig = parts
        if token_ip != ip:
            return False
        exp = int(exp_s)
        if time.time() > exp:
            return False
        payload = f"{token_ip}|{exp}"
        return hmac.compare_digest(sig, _sign(secret, payload))
    except Exception:
        return False


def compute_behavior_score(points: List[Dict[str, Any]], clicks: List[float], duration_ms: float) -> Tuple[int, Dict[str, Any]]:
    """
    Same scoring logic you had, moved here.
    """
    details = {
        "duration_ms": duration_ms,
        "n_points": len(points),
        "n_clicks": len(clicks),
    }

    if duration_ms < 500:
        return 0, {**details, "fail": "too_fast_duration"}
    if len(points) < 20:
        return 0, {**details, "fail": "too_few_points"}

    dist = 0.0
    speeds = []
    pauses = 0
    direction_changes = 0

    last_dx, last_dy = None, None
    for i in range(1, len(points)):
        p0 = points[i - 1]
        p1 = points[i]
        dt = max(1.0, (p1["t"] - p0["t"]))  # ms
        dx = (p1["x"] - p0["x"])
        dy = (p1["y"] - p0["y"])
        step = (dx * dx + dy * dy) ** 0.5
        dist += step
        speed = step / dt
        speeds.append(speed)

        if dt > 200:
            pauses += 1

        if last_dx is not None:
            dot = dx * last_dx + dy * last_dy
            if dot < 0:
                direction_changes += 1

        last_dx, last_dy = dx, dy

    avg_speed = sum(speeds) / max(1, len(speeds))
    aad = sum(abs(s - avg_speed) for s in speeds) / max(1, len(speeds))

    details.update({
        "dist_px": round(dist, 2),
        "avg_speed_px_per_ms": round(avg_speed, 4),
        "speed_aad": round(aad, 4),
        "pauses": pauses,
        "direction_changes": direction_changes,
    })

    score = 0

    if dist > 300:
        score += 2
    if dist > 900:
        score += 1

    if avg_speed < 2.5:
        score += 2
    else:
        score -= 2

    if aad > 0.05:
        score += 2
    else:
        score -= 1

    if pauses >= 1:
        score += 1

    if direction_changes >= 1:
        score += 1

    if len(clicks) >= 1:
        score += 1

    details["score"] = score
    return score, details