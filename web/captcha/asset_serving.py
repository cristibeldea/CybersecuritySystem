"""Serveste imaginile pentru grila CAPTCHA pe baza tokenului HMAC per asset."""
import os
from typing import Optional, Tuple

from .challenge_builder import _verify_asset_token, guess_mimetype
from .constants import GRID_DIR
from .helpers import _safe_float
from .session_state import get_state

def build_asset_response_data(secret: str, sid: str, nonce: str, token: str) -> Optional[Tuple[str, str, float, float]]:
    """Returneaza (path, mimetype, cx, cy) sau None pentru un asset autentificat."""
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
