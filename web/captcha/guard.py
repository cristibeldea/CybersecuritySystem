"""
Backward-compatibility shim for the pre-refactor ``captcha.guard`` module.

The original ~950-line ``guard.py`` was split into single-responsibility
submodules (see ``captcha/__init__.py`` for the full mapping). All
public names previously importable as ``from captcha.guard import X``
are re-exported here so existing call sites — including the demo
scripts and the legacy test suite — keep working unchanged.

New code should import directly from the focused submodules
(``captcha.behavior_features``, ``captcha.token_pass``, etc.) or from
the top-level ``captcha`` package.
"""
from .constants import (  # noqa: F401
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
from .helpers import (  # noqa: F401
    _b64url_decode,
    _b64url_encode,
    _hmac_sha256,
    _now,
    _safe_float,
    _safe_int,
    _sign,
    ensure_dirs,
    make_nonce,
    make_session_id,
)
from .behavior_features import (  # noqa: F401
    _cross_2d,
    _std_dev,
    extract_features,
)
from .behavior_scoring import (  # noqa: F401
    checkbox_behavior_ok,
    compute_behavior_risk,
    grid_behavior_ok,
)
from .token_pass import (  # noqa: F401
    make_pass_token,
    verify_pass_token,
)
from .challenge_builder import (  # noqa: F401
    CATEGORY_DISPLAY,
    _build_select_not_containing,
    _build_tiles,
    _is_image_file,
    _make_asset_token,
    _verify_asset_token,
    build_grid_challenge,
    guess_mimetype,
    list_fake_images_in_category,
    list_grid_categories,
    list_images_in_category,
)
from .session_state import (  # noqa: F401
    CAPTCHA_STATE,
    _empty_state,
    _public_state,
    cleanup_expired_states,
    create_or_reset_session,
    ensure_state,
    get_state,
    is_banned,
    next_challenge,
    record_failure_and_advance,
)
from .verify_flows import (  # noqa: F401
    verify_checkbox,
    verify_grid_answer,
)
from .asset_serving import build_asset_response_data  # noqa: F401
