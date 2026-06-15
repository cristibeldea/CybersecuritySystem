"""Calculul scorului de risc comportamental (0-100) din caracteristicile extrase."""
from typing import Any, Dict, Tuple

from .behavior_features import extract_features

def compute_behavior_risk(features: Dict[str, Any]) -> Tuple[int, Dict[str, Any]]:
    """Returneaza un scor 0-100 unde valoarea mare inseamna probabilitate mare de bot."""
    reasons: Dict[str, Any] = {}

    vel_std      = float(features.get("velocity_std", 0.0))
    vel_mean     = float(features.get("velocity_mean", 0.0))
    vel_bell     = float(features.get("velocity_bell_ratio", 0.0))
    vel_skew     = float(features.get("velocity_skew", 0.0))
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
    risk = 50

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

    if n_points >= 20:
        if vel_bell > 1.3:
            risk -= 8
            reasons["velocity_bell_curve"] = vel_bell
        elif vel_bell > 1.1:
            risk -= 4
            reasons["velocity_moderate_bell"] = vel_bell
        elif vel_bell < 1.02 and vel_bell > 0:
            risk += 12
            reasons["velocity_uniform_profile"] = vel_bell

    if n_points >= 20 and vel_std > 0.001:
        if vel_skew > 0.6:
            risk -= 6
            reasons["velocity_lognormal_skew"] = vel_skew
        elif abs(vel_skew) < 0.15:
            risk += 8
            reasons["velocity_symmetric_distribution"] = vel_skew

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

    if overshoots >= 2:
        risk -= 10
        reasons["overshoot_corrections_present"] = overshoots
    elif overshoots == 0 and n_clicks >= 3:
        risk += 8
        reasons["no_overshoot_corrections"] = True

    if duration < 400:
        risk += 8
        reasons["too_fast"] = duration
    elif duration < 800:
        risk += 4
        reasons["fast"] = duration

    if n_points >= 15:
        reversal_rate = dir_rev / max(1, n_points)
        if reversal_rate < 0.02:
            risk += 7
            reasons["low_direction_reversals"] = {"count": dir_rev, "rate": round(reversal_rate, 4)}
        elif reversal_rate > 0.08:
            risk -= 4
            reasons["natural_direction_reversals"] = round(reversal_rate, 4)

    if path_dist > 50:
        if detour < 1.2:
            risk += 7
            reasons["path_too_direct"] = detour
        elif detour > 2.5:
            risk -= 4
            reasons["path_natural_wandering"] = detour

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
    return risk < 50, {"features": features, "reasons": reasons}

def grid_behavior_ok(payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """Verificare comportamentala pe etapa grilei, putin mai indulgenta."""
    features = extract_features(payload)
    risk, reasons = compute_behavior_risk(features)
    return risk < 60, {"features": features, "reasons": reasons}
