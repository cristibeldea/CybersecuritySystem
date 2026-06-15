"""Subsistemul CAPTCHA: validare comportamentala plus provocari vizuale."""
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
