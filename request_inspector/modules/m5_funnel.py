"""Modulul 5: timpii dintre pasii palniei comportamentale per IP."""
from typing import List, Optional

from ban import ban_ip
from config import (
    FUNNEL_BAN_SECONDS,
    FUNNEL_CV_THRESHOLD,
    FUNNEL_MIN_PAGE_TO_ACTION,
    FUNNEL_MIN_SESSIONS,
    FUNNEL_SESSION_GAP,
    FUNNEL_WINDOW,
)
from state import _now, _std_dev, ip_history

_FUNNEL_STEPS = {
    "/captcha":        "captcha_load",
    "/captcha/verify": "captcha_action",
    "/captcha/reset":  "captcha_action",
    "/":               "page_access",
}

def _classify_funnel_step(path: str) -> Optional[str]:
    """Mapeaza un path al cererii la un pas al palniei."""
    if path in _FUNNEL_STEPS:
        return _FUNNEL_STEPS[path]
    if path.startswith("/article/"):
        return "page_access"
    return None

def _extract_funnel_sessions(entries: List[dict], gap: int) -> List[List[dict]]:
    """Imparte lista sortata de intrari in sesiuni pe baza pauzelor temporale."""
    if not entries:
        return []

    sessions: List[List[dict]] = [[entries[0]]]
    for e in entries[1:]:
        if e["ts"] - sessions[-1][-1]["ts"] >= gap:
            sessions.append([e])
        else:
            sessions[-1].append(e)
    return sessions

def check_funnel_timing(ip: str) -> bool:
    """Returneaza True daca IP-ul arata tipare de timing al palniei de tip bot."""
    hist = ip_history.get(ip, [])
    cutoff = _now() - FUNNEL_WINDOW
    recent = [e for e in hist if e["ts"] >= cutoff]

    if len(recent) < 4:
        return False

    funnel_entries = []
    for e in recent:
        step = _classify_funnel_step(e["path"])
        if step:
            funnel_entries.append({"ts": e["ts"], "step": step, "path": e["path"]})

    if len(funnel_entries) < 3:
        return False

    sessions = _extract_funnel_sessions(funnel_entries, FUNNEL_SESSION_GAP)
    reasons = []

    fast_sessions = 0
    for session in sessions:
        steps = [e["step"] for e in session]
        if "captcha_load" in steps and "captcha_action" in steps:
            load_ts = None
            action_ts = None
            for e in session:
                if e["step"] == "captcha_load" and load_ts is None:
                    load_ts = e["ts"]
                elif e["step"] == "captcha_action" and load_ts is not None and action_ts is None:
                    action_ts = e["ts"]
                    break
            if load_ts is not None and action_ts is not None:
                delta = action_ts - load_ts
                if delta < FUNNEL_MIN_PAGE_TO_ACTION:
                    fast_sessions += 1

    if fast_sessions >= 2:
        reasons.append(f"fast_page_to_action x{fast_sessions} (< {FUNNEL_MIN_PAGE_TO_ACTION}s)")

    session_durations = []
    for session in sessions:
        if len(session) >= 2:
            duration = session[-1]["ts"] - session[0]["ts"]
            if duration > 0:
                session_durations.append(duration)

    if len(session_durations) >= FUNNEL_MIN_SESSIONS:
        std = _std_dev(session_durations)
        mean = sum(session_durations) / len(session_durations)
        if mean > 0:
            cv = std / mean
            if cv < FUNNEL_CV_THRESHOLD:
                reasons.append(
                    f"funnel_duration_cv={cv:.4f}<{FUNNEL_CV_THRESHOLD} "
                    f"(n={len(session_durations)}, mean={mean:.1f}s, std={std:.1f}s)"
                )

    step_timing_signatures = []
    for session in sessions:
        if len(session) >= 3:
            intervals = []
            for i in range(1, len(session)):
                intervals.append(round(session[i]["ts"] - session[i - 1]["ts"], 1))
            step_timing_signatures.append(tuple(intervals))

    if len(step_timing_signatures) >= FUNNEL_MIN_SESSIONS:
        identical_pairs = 0
        total_pairs = 0
        for i in range(len(step_timing_signatures)):
            for j in range(i + 1, len(step_timing_signatures)):
                total_pairs += 1
                a, b = step_timing_signatures[i], step_timing_signatures[j]
                if len(a) == len(b) and len(a) >= 2:
                    max_diff = max(abs(x - y) for x, y in zip(a, b))
                    if max_diff < 0.5:
                        identical_pairs += 1

        if total_pairs > 0 and identical_pairs / total_pairs >= 0.80:
            reasons.append(
                f"identical_step_timing ({identical_pairs}/{total_pairs} pairs match)"
            )

    if reasons:
        detail = ", ".join(reasons)
        ban_ip(ip, FUNNEL_BAN_SECONDS,
               reason=f"funnel_timing ({detail})")
        return True

    return False
