"""Stare in-memory a sesiunilor CAPTCHA pe baza cookie-ului captcha_sid."""
from typing import Any, Dict, Optional, Tuple

from .challenge_builder import build_grid_challenge
from .constants import BAN_SECONDS, MAX_FAILS_TOTAL
from .helpers import _now, _safe_int, make_nonce

CAPTCHA_STATE: Dict[str, Dict[str, Any]] = {}

def _empty_state(nonce: str) -> Dict[str, Any]:
    return {
        "nonce": nonce,
        "kind": "checkbox",
        "checkbox_fail_count": 0,
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
        if ch.get("_category"):
            state["used_categories"].append(ch["_category"])
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
