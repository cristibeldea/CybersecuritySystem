"""Extragerea caracteristicilor din telemetria comportamentala bruta."""
import math
from typing import Any, Dict, List, Optional

from .helpers import _safe_float

def _std_dev(values: List[float]) -> float:
    """Deviatia standard de populatie."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return math.sqrt(sum((v - mean) ** 2 for v in values) / n)

def _cross_2d(ax: float, ay: float, bx: float, by: float) -> float:
    """Magnitudinea produsului vectorial 2D, folosita pentru curbura."""
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

            velocity = step / dt
            velocities.append(velocity)

            if prev_dx is not None:
                dot = dx * prev_dx + dy * prev_dy
                if dot < 0:
                    direction_reversals += 1

                cross = _cross_2d(prev_dx, prev_dy, dx, dy)
                prev_mag = math.hypot(prev_dx, prev_dy)
                curr_mag = math.hypot(dx, dy)
                denom = prev_mag * curr_mag
                if denom > 0.01:
                    sin_angle = min(1.0, cross / denom)
                    curvature_angles.append(sin_angle)

                if (dot < 0
                        and prev_mag >= 4.0
                        and curr_mag >= 4.0
                        and len(velocities) >= 2
                        and velocities[-2] > 0
                        and i >= int(0.7 * n_points)):
                    speed_ratio = velocities[-1] / max(0.001, velocities[-2])
                    if speed_ratio < 0.5:
                        overshoot_corrections += 1

            prev_dx, prev_dy = dx, dy

    straight_line_dist = 0.0
    if n_points >= 2:
        p_first = points[0]
        p_last = points[-1]
        straight_line_dist = math.hypot(
            _safe_float(p_last.get("x"), 0.0) - _safe_float(p_first.get("x"), 0.0),
            _safe_float(p_last.get("y"), 0.0) - _safe_float(p_first.get("y"), 0.0),
        )

    velocity_std = _std_dev(velocities)
    velocity_mean = sum(velocities) / max(1, len(velocities))

    curvature_index = (sum(curvature_angles) / max(1, len(curvature_angles))) if curvature_angles else 0.0

    click_intervals: List[float] = []
    if isinstance(clicks, list) and n_clicks >= 2:
        click_times = sorted(_safe_float(c.get("t") if isinstance(c, dict) else c, 0.0) for c in clicks)
        for i in range(1, len(click_times)):
            click_intervals.append(click_times[i] - click_times[i - 1])

    click_interval_std = _std_dev(click_intervals)
    click_interval_mean = sum(click_intervals) / max(1, len(click_intervals))

    hover_times: List[float] = []
    if isinstance(tile_hovers, dict):
        for tid, info in tile_hovers.items():
            if isinstance(info, dict):
                hover_times.append(_safe_float(info.get("total_ms"), 0.0))

    hover_time_std = _std_dev(hover_times)
    hover_time_mean = sum(hover_times) / max(1, len(hover_times))
    n_tiles_hovered = len(hover_times)

    detour_ratio = (total_path_dist / max(1.0, straight_line_dist)) if straight_line_dist > 1.0 else 0.0

    velocity_bell_ratio = 0.0
    velocity_skew       = 0.0
    n_vel = len(velocities)
    if n_vel >= 15:
        third = n_vel // 3
        v_first  = sum(velocities[:third])             / max(1, third)
        v_middle = sum(velocities[third:2*third])      / max(1, third)
        v_last   = sum(velocities[2*third:])           / max(1, n_vel - 2*third)
        edge_avg = (v_first + v_last) / 2.0
        if edge_avg > 0.0001:
            velocity_bell_ratio = v_middle / edge_avg
        v_mean = sum(velocities) / n_vel
        v_var  = sum((v - v_mean) ** 2 for v in velocities) / n_vel
        if v_var > 1e-8:
            v_sd = math.sqrt(v_var)
            velocity_skew = sum((v - v_mean) ** 3 for v in velocities) / (n_vel * v_sd ** 3)

    blur_count = 0
    if isinstance(focus, list):
        for ev in focus:
            if str(ev.get("type", "")).lower() == "blur":
                blur_count += 1

    return {
        "velocity_std": round(velocity_std, 4),
        "velocity_bell_ratio": round(velocity_bell_ratio, 3),
        "velocity_skew": round(velocity_skew, 3),
        "velocity_mean": round(velocity_mean, 4),
        "curvature_index": round(curvature_index, 4),
        "click_interval_std": round(click_interval_std, 2),
        "click_interval_mean": round(click_interval_mean, 2),
        "hover_time_std": round(hover_time_std, 2),
        "hover_time_mean": round(hover_time_mean, 2),
        "n_tiles_hovered": n_tiles_hovered,
        "overshoot_corrections": overshoot_corrections,
        "duration_ms": round(duration_ms, 1),
        "direction_reversals": direction_reversals,
        "detour_ratio": round(detour_ratio, 3),
        "total_path_dist": round(total_path_dist, 1),
        "had_pointer": had_pointer,
        "n_points": n_points,
        "n_clicks": n_clicks,
        "blur_count": blur_count,
    }
