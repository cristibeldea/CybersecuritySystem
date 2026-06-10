"""
Serve tile images for the grid CAPTCHA.

Given a session id, the per-session nonce and a per-asset HMAC token,
``build_asset_response_data`` validates everything and returns the
on-disk path plus the crop center fractions (``cx``, ``cy``) used by
the Flask route to render the tile.  Returns ``None`` for any
validation failure so the route can answer 404 without leaking detail.
"""
import os
from typing import Optional, Tuple

from .challenge_builder import _verify_asset_token, guess_mimetype
from .constants import GRID_DIR
from .helpers import _safe_float
from .session_state import get_state


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
