"""Fluxuri de verificare end-to-end care leaga scoringul comportamental de tranzitiile de stare."""
from typing import Any, Dict, Tuple

from .behavior_scoring import checkbox_behavior_ok, grid_behavior_ok
from .constants import BAN_SECONDS, MAX_CHECKBOX_FAILS
from .helpers import _now
from .session_state import next_challenge

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

    state["checkbox_fail_count"] = int(state.get("checkbox_fail_count", 0)) + 1

    if int(state["checkbox_fail_count"]) >= MAX_CHECKBOX_FAILS:
        state["ban_until"] = _now() + BAN_SECONDS
        state["kind"] = "banned"
        state["current"] = {"kind": "banned", "attempt_index": state["checkbox_fail_count"]}
        return False, {"message": "Acces blocat temporar.", "ban": True}

    return False, {"message": "Încearcați din nou.", "retry": True}

def verify_grid_answer(state: Dict[str, Any], payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
    """Verifica selectia de pe grila si semnalele comportamentale din timpul ei."""
    current = state.get("current", {}) or {}
    if current.get("kind") != "grid":
        return False, {"reason": "wrong_stage"}

    submitted = payload.get("selected_ids") or []
    if not isinstance(submitted, list):
        return False, {"reason": "invalid_selection"}

    submitted_norm = sorted(str(x) for x in submitted)
    correct = sorted(str(x) for x in (current.get("correct_ids") or []))
    selection_ok = submitted_norm == correct

    behavior_ok, behavior_debug = grid_behavior_ok(payload)

    state["behavior_log"].append({
        "ts": _now(),
        "stage": "grid",
        "selection_ok": selection_ok,
        "behavior_ok": behavior_ok,
        "debug": behavior_debug,
    })
    state["updated_at"] = _now()

    passed = selection_ok and behavior_ok
    return passed, {
        "selection_ok": selection_ok,
        "behavior_ok": behavior_ok,
        "behavior_debug": behavior_debug,
    }
