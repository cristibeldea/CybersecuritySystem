"""
``captcha`` — behavioral + visual CAPTCHA subsystem for the web service.

The original monolithic ``captcha/guard.py`` (~950 lines) was split into
single-responsibility submodules:

    constants.py          — cookie names, paths, TTLs, ban thresholds
    helpers.py            — base64, HMAC, time, type-coercion primitives
    behavior_features.py  — extract_features (≈19 trajectory features)
    behavior_scoring.py   — compute_behavior_risk (R = 50 + ΣΔᵢ)
    token_pass.py         — make_pass_token / verify_pass_token
    challenge_builder.py  — file scanning + grid challenge builders
    session_state.py      — CAPTCHA_STATE store + state-machine transitions
    verify_flows.py       — verify_checkbox / verify_grid_answer
    asset_serving.py      — build_asset_response_data
    distort/              — 11-stage adversarial image distortion pipeline

This ``__init__`` re-exports the original public names so callers that
previously used ``from captcha import X`` (or ``from captcha.guard
import X``) continue to work unchanged.
"""
from .constants import (
    BAN_SECONDS,
    BASE_DIR,
    CAPTCHA_COOKIE,
    CAPTCHA_PHOTOS_DIR,
    GRID_DIR,
    MAX_CHECKBOX_FAILS,
    MAX_FAILS_TOTAL,
    PASS_TTL_SECONDS,
    SESSION_COOKIE,
)
from .helpers import (
    ensure_dirs,
    make_nonce,
    make_session_id,
)
from .behavior_features import extract_features
from .behavior_scoring import (
    checkbox_behavior_ok,
    compute_behavior_risk,
    grid_behavior_ok,
)
from .token_pass import (
    make_pass_token,
    verify_pass_token,
)
from .challenge_builder import (
    CATEGORY_DISPLAY,
    build_grid_challenge,
    guess_mimetype,
    list_fake_images_in_category,
    list_grid_categories,
    list_images_in_category,
)
from .session_state import (
    CAPTCHA_STATE,
    cleanup_expired_states,
    create_or_reset_session,
    ensure_state,
    get_state,
    is_banned,
    next_challenge,
    record_failure_and_advance,
)
from .verify_flows import (
    verify_checkbox,
    verify_grid_answer,
)
from .asset_serving import build_asset_response_data


__all__ = [
    "BAN_SECONDS", "BASE_DIR", "CAPTCHA_COOKIE", "CAPTCHA_PHOTOS_DIR",
    "GRID_DIR", "MAX_CHECKBOX_FAILS", "MAX_FAILS_TOTAL",
    "PASS_TTL_SECONDS", "SESSION_COOKIE",
    "ensure_dirs", "make_nonce", "make_session_id",
    "extract_features", "compute_behavior_risk",
    "checkbox_behavior_ok", "grid_behavior_ok",
    "make_pass_token", "verify_pass_token",
    "CATEGORY_DISPLAY", "build_grid_challenge", "guess_mimetype",
    "list_fake_images_in_category", "list_grid_categories",
    "list_images_in_category",
    "CAPTCHA_STATE", "cleanup_expired_states", "create_or_reset_session",
    "ensure_state", "get_state", "is_banned",
    "next_challenge", "record_failure_and_advance",
    "verify_checkbox", "verify_grid_answer",
    "build_asset_response_data",
]
