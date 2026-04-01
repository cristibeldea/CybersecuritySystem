import base64
import hashlib
import hmac
import json
import math
import mimetypes
import os
import random
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

CAPTCHA_COOKIE = "captcha_pass"
SESSION_COOKIE = "captcha_sid"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CAPTCHA_PHOTOS_DIR = os.path.join(BASE_DIR, "CAPTCHA_photos")
GRID_DIR = os.path.join(CAPTCHA_PHOTOS_DIR, "grid")

PASS_TTL_SECONDS = 20 * 60
BAN_SECONDS = 60   # 1 minute
MAX_FAILS_TOTAL = 5

# in-memory store; replace with Redis/database in production
CAPTCHA_STATE: Dict[str, Dict[str, Any]] = {}


# ----------------------------
# Helpers
# ----------------------------
def _now() -> int:
    return int(time.time())


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _hmac_sha256(secret: str, msg: bytes) -> bytes:
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest()


def _sign(secret: str, payload: bytes) -> str:
    return _b64url_encode(_hmac_sha256(secret, payload))


def _safe_int(x: Any, default: int = 0) -> int:
    try:
        return int(x)
    except Exception:
        return default


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except Exception:
        return default


def make_session_id() -> str:
    return secrets.token_urlsafe(32)


def make_nonce() -> str:
    return secrets.token_urlsafe(24)


def ensure_dirs() -> None:
    os.makedirs(GRID_DIR, exist_ok=True)


# ----------------------------
# Behavioral analysis
# ----------------------------

def _std_dev(values: List[float]) -> float:
    """Population standard deviation."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return math.sqrt(sum((v - mean) ** 2 for v in values) / n)


def _cross_2d(ax: float, ay: float, bx: float, by: float) -> float:
    """2D cross product magnitude (used for curvature)."""
    return abs(ax * by - ay * bx)


def extract_features(payload: Dict[str, Any]) -> Dict[str, Any]:
    duration_ms = _safe_float(payload.get("duration_ms"), 0.0)
    points = payload.get("points") or []
    clicks = payload.get("clicks") or []
    focus = payload.get("focus") or []
    tile_hovers = payload.get("tile_hovers") or {}
    had_pointer = bool(payload.get("had_pointer", False))

    n_points = len(points) if isinstance(points, list) else 0
    n_clicks = len(clicks) if isinstance(clicks, list) else 0

    # --------------------------------------------------
    # Trajectory analysis from mouse/touch sample points
    # --------------------------------------------------
    velocities: List[float] = []
    segment_distances: List[float] = []
    total_path_dist = 0.0
    direction_reversals = 0
    curvature_angles: List[float] = []
    overshoot_corrections = 0

    prev_dx: Optional[float] = None
    prev_dy: Optional[float] = None

    if n_points >= 2:
        for i in range(1, n_points):
            p0 = points[i - 1]
            p1 = points[i]

            t0 = _safe_float(p0.get("t"), 0.0)
            t1 = _safe_float(p1.get("t"), 0.0)
            dt = max(1.0, t1 - t0)

            dx = _safe_float(p1.get("x"), 0.0) - _safe_float(p0.get("x"), 0.0)
            dy = _safe_float(p1.get("y"), 0.0) - _safe_float(p0.get("y"), 0.0)

            step = math.hypot(dx, dy)
            total_path_dist += step
            segment_distances.append(step)

            velocity = step / dt  # px/ms
            velocities.append(velocity)

            # Direction reversal: dot product < 0 means > 90 degree turn
            if prev_dx is not None:
                dot = dx * prev_dx + dy * prev_dy
                if dot < 0:
                    direction_reversals += 1

                # Curvature via cross product — angle between consecutive segments
                cross = _cross_2d(prev_dx, prev_dy, dx, dy)
                prev_mag = math.hypot(prev_dx, prev_dy)
                curr_mag = math.hypot(dx, dy)
                denom = prev_mag * curr_mag
                if denom > 0.01:
                    sin_angle = min(1.0, cross / denom)
                    curvature_angles.append(sin_angle)

                # Overshoot + correction: velocity spike followed by reversal
                if dot < 0 and len(velocities) >= 2 and velocities[-2] > 0:
                    speed_ratio = velocities[-1] / max(0.001, velocities[-2])
                    if speed_ratio < 0.5:
                        overshoot_corrections += 1

            prev_dx, prev_dy = dx, dy

    # Straight-line distance (first point to last point)
    straight_line_dist = 0.0
    if n_points >= 2:
        p_first = points[0]
        p_last = points[-1]
        straight_line_dist = math.hypot(
            _safe_float(p_last.get("x"), 0.0) - _safe_float(p_first.get("x"), 0.0),
            _safe_float(p_last.get("y"), 0.0) - _safe_float(p_first.get("y"), 0.0),
        )

    # === HIGH VALUE: Velocity standard deviation ===
    velocity_std = _std_dev(velocities)
    velocity_mean = sum(velocities) / max(1, len(velocities))

    # === HIGH VALUE: Path curvature index ===
    # Average sin(angle) between consecutive segments; 0 = perfectly straight
    curvature_index = (sum(curvature_angles) / max(1, len(curvature_angles))) if curvature_angles else 0.0

    # === HIGH VALUE: Inter-click intervals and variance ===
    click_intervals: List[float] = []
    if isinstance(clicks, list) and n_clicks >= 2:
        click_times = sorted(_safe_float(c.get("t") if isinstance(c, dict) else c, 0.0) for c in clicks)
        for i in range(1, len(click_times)):
            click_intervals.append(click_times[i] - click_times[i - 1])

    click_interval_std = _std_dev(click_intervals)
    click_interval_mean = sum(click_intervals) / max(1, len(click_intervals))

    # === HIGH VALUE: Per-tile hover times ===
    hover_times: List[float] = []
    if isinstance(tile_hovers, dict):
        for tid, info in tile_hovers.items():
            if isinstance(info, dict):
                hover_times.append(_safe_float(info.get("total_ms"), 0.0))

    hover_time_std = _std_dev(hover_times)
    hover_time_mean = sum(hover_times) / max(1, len(hover_times))
    n_tiles_hovered = len(hover_times)

    # === MEDIUM VALUE: Distance/straight-line ratio (detour ratio) ===
    detour_ratio = (total_path_dist / max(1.0, straight_line_dist)) if straight_line_dist > 1.0 else 0.0

    # === Blur count (supporting signal) ===
    blur_count = 0
    if isinstance(focus, list):
        for ev in focus:
            if str(ev.get("type", "")).lower() == "blur":
                blur_count += 1

    return {
        # High value
        "velocity_std": round(velocity_std, 4),
        "velocity_mean": round(velocity_mean, 4),
        "curvature_index": round(curvature_index, 4),
        "click_interval_std": round(click_interval_std, 2),
        "click_interval_mean": round(click_interval_mean, 2),
        "hover_time_std": round(hover_time_std, 2),
        "hover_time_mean": round(hover_time_mean, 2),
        "n_tiles_hovered": n_tiles_hovered,
        "overshoot_corrections": overshoot_corrections,
        # Medium value
        "duration_ms": round(duration_ms, 1),
        "direction_reversals": direction_reversals,
        "detour_ratio": round(detour_ratio, 3),
        "total_path_dist": round(total_path_dist, 1),
        # Supporting
        "had_pointer": had_pointer,
        "n_points": n_points,
        "n_clicks": n_clicks,
        "blur_count": blur_count,
    }


def compute_behavior_risk(features: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Score 0-100 where higher = more likely bot.

    Signal tiers:
      HIGH   (up to ±20 each): velocity_std, hover patterns, curvature,
             inter-click variance, overshoot corrections
      MEDIUM (up to ±8 each):  duration, direction reversals, detour ratio
      LOW    (supporting, ±4): blur, pointer presence
    """
    reasons: Dict[str, Any] = {}

    # --- unpack features ---
    vel_std      = float(features.get("velocity_std", 0.0))
    vel_mean     = float(features.get("velocity_mean", 0.0))
    curvature    = float(features.get("curvature_index", 0.0))
    ci_std       = float(features.get("click_interval_std", 0.0))
    ci_mean      = float(features.get("click_interval_mean", 0.0))
    hover_std    = float(features.get("hover_time_std", 0.0))
    hover_mean   = float(features.get("hover_time_mean", 0.0))
    n_hovered    = int(features.get("n_tiles_hovered", 0))
    overshoots   = int(features.get("overshoot_corrections", 0))

    duration     = float(features.get("duration_ms", 0.0))
    dir_rev      = int(features.get("direction_reversals", 0))
    detour       = float(features.get("detour_ratio", 0.0))
    path_dist    = float(features.get("total_path_dist", 0.0))

    had_pointer  = bool(features.get("had_pointer", False))
    n_points     = int(features.get("n_points", 0))
    n_clicks     = int(features.get("n_clicks", 0))
    blur_count   = int(features.get("blur_count", 0))
    # Start neutral
    risk = 50

    # =============================================
    # HIGH VALUE SIGNALS  (each ±15-20)
    # =============================================

    # 1. Cursor velocity variance
    #    Bots tend to have very uniform speed (low std) or zero movement.
    #    Humans show natural jitter and acceleration/deceleration.
    if n_points >= 5:
        if vel_std < 0.005:
            risk += 18
            reasons["velocity_too_uniform"] = vel_std
        elif vel_std < 0.02:
            risk += 10
            reasons["velocity_low_variance"] = vel_std
        elif vel_std > 0.05:
            risk -= 8
            reasons["velocity_natural_variance"] = vel_std
    else:
        risk += 12
        reasons["insufficient_movement_data"] = n_points

    # 2. Per-tile hover time distribution
    #    Humans deliberate differently over each image; bots tend to
    #    either not hover or hover uniformly.
    if n_hovered >= 3:
        if hover_std < 20:
            risk += 15
            reasons["hover_too_uniform"] = {"std": hover_std, "mean": hover_mean}
        elif hover_std > 100:
            risk -= 6
            reasons["hover_natural_deliberation"] = hover_std
        if hover_mean < 50:
            risk += 10
            reasons["hover_too_brief"] = hover_mean
        elif hover_mean > 200:
            risk -= 4
    elif n_hovered == 0 and n_clicks > 0:
        risk += 12
        reasons["no_hover_before_clicks"] = True

    # 3. Path curvature index
    #    Perfectly straight paths (curvature ≈ 0) signal programmatic movement.
    #    Humans produce gently curved, imprecise paths.
    if n_points >= 10:
        if curvature < 0.01:
            risk += 15
            reasons["path_too_straight"] = curvature
        elif curvature < 0.03:
            risk += 8
            reasons["path_low_curvature"] = curvature
        elif curvature > 0.08:
            risk -= 6
            reasons["path_natural_curvature"] = curvature

    # 4. Inter-click interval variance
    #    Bots click at metronomic intervals; humans are irregular.
    if n_clicks >= 3:
        if ci_std < 15:
            risk += 15
            reasons["click_intervals_metronomic"] = {"std": ci_std, "mean": ci_mean}
        elif ci_std < 40:
            risk += 6
            reasons["click_intervals_low_variance"] = ci_std
        elif ci_std > 100:
            risk -= 6
            reasons["click_intervals_natural"] = ci_std

    # 5. Overshoot + correction events
    #    Humans overshoot click targets and correct; bots go straight to target.
    #    Presence of overshoots is strong evidence of a real hand.
    if overshoots >= 2:
        risk -= 10
        reasons["overshoot_corrections_present"] = overshoots
    elif overshoots == 0 and n_clicks >= 3:
        risk += 8
        reasons["no_overshoot_corrections"] = True

    # =============================================
    # MEDIUM VALUE SIGNALS  (each ±6-8)
    # =============================================

    # 6. Duration (too fast = bot, but don't rely on this alone)
    if duration < 400:
        risk += 8
        reasons["too_fast"] = duration
    elif duration < 800:
        risk += 4
        reasons["fast"] = duration

    # 7. Direction reversals
    #    Smooth, unidirectional paths are suspicious.
    if n_points >= 15:
        reversal_rate = dir_rev / max(1, n_points)
        if reversal_rate < 0.02:
            risk += 7
            reasons["low_direction_reversals"] = {"count": dir_rev, "rate": round(reversal_rate, 4)}
        elif reversal_rate > 0.08:
            risk -= 4
            reasons["natural_direction_reversals"] = round(reversal_rate, 4)

    # 8. Detour ratio (actual distance / straight-line distance)
    #    Bots take efficient paths (ratio ≈ 1); humans wander.
    if path_dist > 50:
        if detour < 1.2:
            risk += 7
            reasons["path_too_direct"] = detour
        elif detour > 2.5:
            risk -= 4
            reasons["path_natural_wandering"] = detour

    # =============================================
    # SUPPORTING SIGNALS  (each ±3-4)
    # =============================================

    if not had_pointer:
        risk += 4
        reasons["no_pointer_events"] = True

    if blur_count >= 3:
        risk += 4
        reasons["excessive_blur"] = blur_count

    risk = max(0, min(100, int(risk)))
    reasons["risk"] = risk
    return risk, reasons


def checkbox_behavior_ok(payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    features = extract_features(payload)
    risk, reasons = compute_behavior_risk(features)
    return risk < 78, {"features": features, "reasons": reasons}


def grid_behavior_ok(payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """Behavioral check during grid interaction — slightly more lenient since
    the user is actively clicking tiles and producing richer signals."""
    features = extract_features(payload)
    risk, reasons = compute_behavior_risk(features)
    return risk < 85, {"features": features, "reasons": reasons}


# ----------------------------
# Pass token
# ----------------------------
def make_pass_token(
    secret: str,
    sid: str,
    ttl_seconds: int,
    policy_version: str,
    context: Optional[Dict[str, str]] = None,
) -> str:
    exp = _now() + int(ttl_seconds)
    ctx = context or {}
    body = {
        "sid": sid,
        "pv": str(policy_version),
        "exp": exp,
        "ua": str(ctx.get("ua", ""))[:120],
        "host": str(ctx.get("host", ""))[:120],
    }
    payload = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sig = _sign(secret, payload)
    return f"{_b64url_encode(payload)}.{sig}"


def verify_pass_token(
    secret: str,
    token: str,
    sid: str,
    policy_version: str,
    context: Optional[Dict[str, str]] = None,
) -> Tuple[bool, Optional[int]]:
    try:
        if not token or "." not in token:
            return False, None

        b64, sig = token.split(".", 1)
        payload = _b64url_decode(b64)
        expected = _sign(secret, payload)
        if not hmac.compare_digest(sig, expected):
            return False, None

        body = json.loads(payload.decode("utf-8"))
        if body.get("sid") != sid:
            return False, None

        if str(body.get("pv")) != str(policy_version):
            return False, None

        exp = _safe_int(body.get("exp"), 0)
        if _now() > exp:
            return False, None

        ctx = context or {}
        tok_ua = str(body.get("ua", ""))
        tok_host = str(body.get("host", ""))

        if tok_ua and tok_ua != str(ctx.get("ua", ""))[:120]:
            return False, None
        if tok_host and tok_host != str(ctx.get("host", ""))[:120]:
            return False, None

        return True, exp
    except Exception:
        return False, None


# ----------------------------
# File scanning
# ----------------------------
def _is_image_file(name: str) -> bool:
    ext = os.path.splitext(name)[1].lower()
    return ext in {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"}


def list_grid_categories() -> List[str]:
    ensure_dirs()
    out: List[str] = []
    for name in os.listdir(GRID_DIR):
        if name == "fake":
            continue  # skip stray fake dir at top level
        full = os.path.join(GRID_DIR, name)
        if os.path.isdir(full):
            # Only count real images (direct children), not fake subfolder
            imgs = [x for x in os.listdir(full) if _is_image_file(x)]
            if imgs:
                out.append(name)
    out.sort()
    return out


def list_images_in_category(category: str) -> List[str]:
    """Return real (non-fake) image paths for a category."""
    folder = os.path.join(GRID_DIR, category)
    if not os.path.isdir(folder):
        return []
    return [
        os.path.join(folder, name)
        for name in os.listdir(folder)
        if _is_image_file(name)  # only files in the category root, not subdirs
    ]


def list_fake_images_in_category(category: str) -> List[str]:
    """Return fake image paths from the category's 'fake' subfolder."""
    folder = os.path.join(GRID_DIR, category, "fake")
    if not os.path.isdir(folder):
        return []
    return [
        os.path.join(folder, name)
        for name in os.listdir(folder)
        if _is_image_file(name)
    ]


def guess_mimetype(path: str) -> str:
    mt, _ = mimetypes.guess_type(path)
    return mt or "application/octet-stream"


# ----------------------------
# Semantic category groups
# ----------------------------
CATEGORY_GROUPS: Dict[str, List[str]] = {
    "vehicles":   ["cars", "buses", "trucks", "motorcycles", "bicycles", "airplanes", "boats"],
    "animals":    ["cats", "dogs", "birds", "horses"],
    "nature":     ["trees", "flowers", "mountains", "lakes"],
    "structures": ["bridges", "stairs", "chimneys", "doors", "windows", "fences"],
    "furniture":  ["benches", "chairs"],
    "traffic":    ["semaphores", "traffic_lights", "stop_signs", "crosswalks", "fire_hydrants"],
    "misc":       ["clocks", "umbrellas"],
}

# Reverse lookup: category -> group name
_CAT_TO_GROUP: Dict[str, str] = {}
for _grp, _cats in CATEGORY_GROUPS.items():
    for _c in _cats:
        _CAT_TO_GROUP[_c] = _grp


def _available_groups() -> Dict[str, List[str]]:
    """Return only groups whose categories actually have images on disk."""
    live_cats = set(list_grid_categories())
    out: Dict[str, List[str]] = {}
    for grp, cats in CATEGORY_GROUPS.items():
        alive = [c for c in cats if c in live_cats]
        if alive:
            out[grp] = alive
    return out


def _pick_images_from_group(group_cats: List[str], n: int,
                            exclude_cats: Optional[List[str]] = None) -> List[Tuple[str, str]]:
    """Pick n random (path, category) pairs from categories in a group."""
    pool: List[Tuple[str, str]] = []
    for cat in group_cats:
        if exclude_cats and cat in exclude_cats:
            continue
        for p in list_images_in_category(cat):
            pool.append((p, cat))
    if len(pool) < n:
        raise RuntimeError(f"Not enough images in group (need {n}, have {len(pool)})")
    return random.sample(pool, n)


def _pick_images_from_category(category: str, n: int) -> List[Tuple[str, str]]:
    """Pick n random (path, category) pairs from a single category."""
    imgs = list_images_in_category(category)
    if len(imgs) < n:
        raise RuntimeError(f"Category '{category}' needs at least {n} images, has {len(imgs)}")
    return [(p, category) for p in random.sample(imgs, n)]


# ----------------------------
# Challenge builders
# ----------------------------
TASK_TYPES = ["odd_one_out", "two_outliers", "matching_pair"]


def _make_asset_token(secret: str, nonce: str, payload: Dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    sig = _sign(secret, nonce.encode("utf-8") + b"." + raw)
    return f"{_b64url_encode(raw)}.{sig}"


def _verify_asset_token(secret: str, nonce: str, token: str) -> Optional[Dict[str, Any]]:
    try:
        if "." not in token:
            return None
        b64, sig = token.split(".", 1)
        raw = _b64url_decode(b64)
        expected = _sign(secret, nonce.encode("utf-8") + b"." + raw)
        if not hmac.compare_digest(sig, expected):
            return None
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def _build_tiles(secret: str, nonce: str,
                 items: List[Tuple[str, str, bool]]) -> Tuple[List[Dict], List[str]]:
    """Build tile dicts and answer list from [(path, category, is_answer), ...]."""
    random.shuffle(items)
    tiles: List[Dict[str, Any]] = []
    answers: List[str] = []

    for idx, (path, cat, is_answer) in enumerate(items):
        cx = random.uniform(0.4, 0.6)
        cy = random.uniform(0.4, 0.6)
        token = _make_asset_token(secret, nonce, {
            "kind": "grid", "path": path, "idx": idx,
            "cx": round(cx, 4), "cy": round(cy, 4),
        })
        tile_id = str(idx)
        tiles.append({"id": tile_id, "url": f"/captcha/asset/{nonce}/{token}"})
        if is_answer:
            answers.append(tile_id)

    return tiles, sorted(answers)


def _build_odd_one_out(secret: str, nonce: str,
                       used_groups: List[str]) -> Dict[str, Any]:
    """8 real images from one category + 1 fake image from the same category.
    Task: 'Select the image that does not belong with the others.'"""
    # Pick a category that has >=8 real images AND >=1 fake image
    all_cats = list_grid_categories()
    eligible = [c for c in all_cats
                if len(list_images_in_category(c)) >= 8
                and len(list_fake_images_in_category(c)) >= 1]
    if not eligible:
        # Fallback: relax to any category with enough real images
        eligible = [c for c in all_cats if len(list_images_in_category(c)) >= 8]

    cat = random.choice(eligible)
    real_images = _pick_images_from_category(cat, 8)

    # Pick 1 fake from the same category
    fakes = list_fake_images_in_category(cat)
    if fakes:
        fake_path = random.choice(fakes)
        outlier = [(fake_path, cat)]
    else:
        # Fallback: pick from a different group if no fakes available
        groups = _available_groups()
        cat_group = _CAT_TO_GROUP.get(cat, "")
        other_groups = [g for g in groups if g != cat_group]
        outlier_group = random.choice(other_groups)
        outlier = _pick_images_from_group(groups[outlier_group], 1)

    items = [(p, c, False) for p, c in real_images] + \
            [(p, c, True) for p, c in outlier]

    tiles, answers = _build_tiles(secret, nonce, items)

    return {
        "kind": "grid",
        "task_type": "odd_one_out",
        "prompt": "Select the image that does not belong with the others.",
        "expect_count": 1,
        "tiles": tiles,
        "correct_ids": answers,
        "_category": cat,
    }


def _build_two_outliers(secret: str, nonce: str,
                        used_groups: List[str]) -> Dict[str, Any]:
    """7 real images from one category + 2 fake images from the same category.
    Task: 'Select the two images that don't belong with the others.'"""
    # Pick a category that has >=7 real images AND >=2 fake images
    all_cats = list_grid_categories()
    eligible = [c for c in all_cats
                if len(list_images_in_category(c)) >= 7
                and len(list_fake_images_in_category(c)) >= 2]
    if not eligible:
        eligible = [c for c in all_cats if len(list_images_in_category(c)) >= 7]

    cat = random.choice(eligible)
    real_images = _pick_images_from_category(cat, 7)

    # Pick 2 fakes from the same category
    fakes = list_fake_images_in_category(cat)
    if len(fakes) >= 2:
        fake_paths = random.sample(fakes, 2)
        outliers = [(p, cat) for p in fake_paths]
    else:
        # Fallback: use whatever fakes exist + fill from different group
        groups = _available_groups()
        cat_group = _CAT_TO_GROUP.get(cat, "")
        other_groups = [g for g in groups if g != cat_group and len(groups[g]) >= 1]
        outliers = [(p, cat) for p in fakes]
        needed = 2 - len(outliers)
        if other_groups:
            outlier_group = random.choice(other_groups)
            outliers += _pick_images_from_group(groups[outlier_group], needed)

    items = [(p, c, False) for p, c in real_images] + \
            [(p, c, True) for p, c in outliers]

    tiles, answers = _build_tiles(secret, nonce, items)

    return {
        "kind": "grid",
        "task_type": "two_outliers",
        "prompt": "Select the two images that don't belong with the others.",
        "expect_count": 2,
        "tiles": tiles,
        "correct_ids": answers,
        "_category": cat,
    }


def _build_matching_pair(secret: str, nonce: str,
                         used_categories: List[str]) -> Dict[str, Any]:
    """9 images each from a different category, except exactly 2 share the
    same category. Task: 'Select the two images that belong to the same category.'"""
    all_cats = list_grid_categories()
    available = [c for c in all_cats if c not in used_categories and
                 len(list_images_in_category(c)) >= 2]
    if not available:
        available = [c for c in all_cats if len(list_images_in_category(c)) >= 2]

    # The "pair" category: need at least 2 images
    pair_cat = random.choice(available)
    pair_images = _pick_images_from_category(pair_cat, 2)

    # 7 singleton images, each from a different category
    singleton_cats = [c for c in all_cats if c != pair_cat]
    random.shuffle(singleton_cats)
    singleton_cats = singleton_cats[:7]

    singleton_images: List[Tuple[str, str]] = []
    for cat in singleton_cats:
        imgs = list_images_in_category(cat)
        if imgs:
            singleton_images.append((random.choice(imgs), cat))

    # Pad if we couldn't fill 7 unique categories
    while len(singleton_images) < 7:
        fallback_cats = [c for c in all_cats if c != pair_cat and
                         c not in [s[1] for s in singleton_images]]
        if not fallback_cats:
            break
        cat = random.choice(fallback_cats)
        imgs = list_images_in_category(cat)
        if imgs:
            singleton_images.append((random.choice(imgs), cat))

    items = [(p, c, True) for p, c in pair_images] + \
            [(p, c, False) for p, c in singleton_images]

    tiles, answers = _build_tiles(secret, nonce, items)

    return {
        "kind": "grid",
        "task_type": "matching_pair",
        "prompt": "Select the two images that belong to the same category.",
        "expect_count": 2,
        "tiles": tiles,
        "correct_ids": answers,
        "_pair_category": pair_cat,
    }


def build_grid_challenge(secret: str, nonce: str,
                         used_categories: List[str],
                         attempt_index: int = 1) -> Dict[str, Any]:
    """Build a random relational challenge. Rotates between task types."""
    task_type = random.choice(TASK_TYPES)

    if task_type == "odd_one_out":
        ch = _build_odd_one_out(secret, nonce, used_categories)
    elif task_type == "two_outliers":
        ch = _build_two_outliers(secret, nonce, used_categories)
    else:
        ch = _build_matching_pair(secret, nonce, used_categories)

    ch["attempt_index"] = attempt_index
    return ch


# ----------------------------
# State machine
# ----------------------------
def _empty_state(nonce: str) -> Dict[str, Any]:
    return {
        "nonce": nonce,
        "kind": "checkbox",
        "fail_count": 0,
        "used_categories": [],
        "ban_until": 0,
        "created_at": _now(),
        "updated_at": _now(),
        "current": {"kind": "checkbox", "attempt_index": 0},
        "behavior_log": [],
    }


def _public_state(state: Dict[str, Any]) -> Dict[str, Any]:
    current = state.get("current", {}) or {}
    public: Dict[str, Any] = {
        "kind": current.get("kind", "checkbox"),
        "attempt_index": current.get("attempt_index", 0),
    }

    if current.get("kind") == "grid":
        public.update({
            "task_type": current.get("task_type", ""),
            "prompt": current.get("prompt", ""),
            "expect_count": current.get("expect_count", 0),
            "tiles": current.get("tiles", []),
        })

    return public


def create_or_reset_session(sid: str) -> Dict[str, Any]:
    nonce = make_nonce()
    state = _empty_state(nonce)
    CAPTCHA_STATE[sid] = state
    return state


def get_state(sid: str) -> Optional[Dict[str, Any]]:
    return CAPTCHA_STATE.get(sid)


def ensure_state(sid: str) -> Dict[str, Any]:
    st = get_state(sid)
    if st is None:
        st = create_or_reset_session(sid)
    return st


def next_challenge(secret: str, state: Dict[str, Any]) -> Dict[str, Any]:
    fail_count = int(state.get("fail_count", 0))

    if fail_count < MAX_FAILS_TOTAL:
        attempt_index = fail_count + 1
        ch = build_grid_challenge(secret, state["nonce"], state["used_categories"],
                                  attempt_index=attempt_index)
        # Track used groups/categories to avoid repeats
        if ch.get("_main_group"):
            state["used_categories"].append(ch["_main_group"])
        if ch.get("_pair_category"):
            state["used_categories"].append(ch["_pair_category"])
        state["kind"] = "grid"
        state["current"] = ch
        state["updated_at"] = _now()
        return state

    state["ban_until"] = _now() + BAN_SECONDS
    state["kind"] = "banned"
    state["current"] = {
        "kind": "banned",
        "attempt_index": fail_count + 1,
    }
    state["updated_at"] = _now()
    return state


def record_failure_and_advance(secret: str, state: Dict[str, Any]) -> Dict[str, Any]:
    state["fail_count"] = int(state.get("fail_count", 0)) + 1
    state["updated_at"] = _now()

    if int(state["fail_count"]) >= MAX_FAILS_TOTAL:
        state["ban_until"] = _now() + BAN_SECONDS
        state["kind"] = "banned"
        state["current"] = {"kind": "banned", "attempt_index": 6}
        return state

    return next_challenge(secret, state)


def verify_checkbox(secret: str, state: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    ok, debug = checkbox_behavior_ok(payload)
    state["behavior_log"].append({
        "ts": _now(),
        "ok": ok,
        "debug": debug,
    })
    state["updated_at"] = _now()

    if ok:
        next_challenge(secret, state)
        return True, {"message": "Proceed to the visual challenge."}

    record_failure_and_advance(secret, state)
    return False, {"message": "Behavioral check failed."}


def verify_grid_answer(state: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """Verify both the grid selection AND behavioral signals during grid interaction."""
    current = state.get("current", {}) or {}
    if current.get("kind") != "grid":
        return False, {"reason": "wrong_stage"}

    # --- correctness check ---
    submitted = payload.get("selected_ids") or []
    if not isinstance(submitted, list):
        return False, {"reason": "invalid_selection"}

    submitted_norm = sorted(str(x) for x in submitted)
    correct = sorted(str(x) for x in (current.get("correct_ids") or []))
    selection_ok = submitted_norm == correct

    # --- behavioral check ---
    behavior_ok, behavior_debug = grid_behavior_ok(payload)

    state["behavior_log"].append({
        "ts": _now(),
        "stage": "grid",
        "selection_ok": selection_ok,
        "behavior_ok": behavior_ok,
        "debug": behavior_debug,
    })
    state["updated_at"] = _now()

    # both must pass
    passed = selection_ok and behavior_ok
    return passed, {
        "selection_ok": selection_ok,
        "behavior_ok": behavior_ok,
        "behavior_debug": behavior_debug,
    }


def is_banned(state: Dict[str, Any]) -> Tuple[bool, int]:
    ban_until = _safe_int(state.get("ban_until"), 0)
    return (_now() < ban_until, ban_until)


def cleanup_expired_states(max_age_seconds: int = 3600) -> None:
    now = _now()
    to_delete = []
    for sid, state in CAPTCHA_STATE.items():
        updated_at = _safe_int(state.get("updated_at"), 0)
        if now - updated_at > max_age_seconds:
            to_delete.append(sid)
    for sid in to_delete:
        CAPTCHA_STATE.pop(sid, None)


# ----------------------------
# Asset serving
# ----------------------------
def build_asset_response_data(secret: str, sid: str, nonce: str, token: str) -> Optional[Tuple[str, str, float, float]]:
    """Returns (path, mimetype, cx, cy) or None. cx/cy are crop center fractions."""
    state = get_state(sid)
    if not state:
        return None

    if state.get("nonce") != nonce:
        return None

    decoded = _verify_asset_token(secret, nonce, token)
    if not decoded:
        return None

    path = decoded.get("path")
    if not path or not isinstance(path, str):
        return None

    path_abs = os.path.abspath(path)
    allowed_roots = [os.path.abspath(GRID_DIR)]

    if not any(path_abs.startswith(root + os.sep) or path_abs == root for root in allowed_roots):
        return None

    if not os.path.isfile(path_abs):
        return None

    cx = _safe_float(decoded.get("cx"), 0.5)
    cy = _safe_float(decoded.get("cy"), 0.5)

    return path_abs, guess_mimetype(path_abs), cx, cy