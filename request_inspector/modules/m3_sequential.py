"""
Module 3 — Sequential pattern detection.

Treats each request's path as a symbol and looks at the per-IP sequence
of URLs within ``SEQ_WINDOW``.  Two complementary checks are applied:

  1. Repeated subsequences (sliding-window substring matching).
     Finds the longest subsequence of length ≥ ``SEQ_MIN_PATTERN_LEN``
     that repeats ≥ ``SEQ_MIN_REPEATS`` times — a structured scraper
     cycling through a list of articles.

  2. First-order Markov transition dominance.
     Builds a P(next | current) matrix and flags any source URL that
     has a successor with probability ≥ ``SEQ_TRANSITION_THRESHOLD``
     (≥3 observations from that source).  Catches scrapers that follow
     a deterministic navigation graph rather than a simple cycle.

Either check fires a ban of ``SEQ_BAN_SECONDS``.
"""
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from ban import ban_ip
from config import (
    SEQ_BAN_SECONDS,
    SEQ_MIN_PATTERN_LEN,
    SEQ_MIN_REPEATS,
    SEQ_MIN_REQUESTS,
    SEQ_TRANSITION_THRESHOLD,
    SEQ_WINDOW,
)
from state import _now, ip_history


def _find_repeated_subsequences(sequence: List[str],
                                min_len: int,
                                min_repeats: int) -> Optional[Tuple[List[str], int]]:
    """Find the longest subsequence of length ≥ min_len that repeats ≥ min_repeats times.
    Returns (pattern, count) or None."""
    n = len(sequence)
    if n < min_len * min_repeats:
        return None

    best: Optional[Tuple[List[str], int]] = None

    # Check pattern lengths from min_len up to n//min_repeats
    for plen in range(min_len, n // min_repeats + 1):
        # Slide through all possible patterns of this length
        seen: Dict[str, int] = defaultdict(int)
        for start in range(n - plen + 1):
            key = "|".join(sequence[start:start + plen])
            seen[key] += 1

        for key, count in seen.items():
            if count >= min_repeats:
                pattern = key.split("|")
                if best is None or len(pattern) > len(best[0]) or count > best[1]:
                    best = (pattern, count)

    return best


def _check_transition_dominance(sequence: List[str],
                                threshold: float) -> Optional[Tuple[str, str, float]]:
    """Build a first-order Markov transition matrix and check if any
    state has a dominant successor (probability ≥ threshold).
    Returns (from_state, to_state, probability) or None."""
    if len(sequence) < 4:
        return None

    transitions: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for i in range(len(sequence) - 1):
        transitions[sequence[i]][sequence[i + 1]] += 1

    for src, dests in transitions.items():
        total = sum(dests.values())
        if total < 3:  # need at least 3 observations from this state
            continue
        for dst, cnt in dests.items():
            prob = cnt / total
            if prob >= threshold:
                return (src, dst, prob)

    return None


def check_sequential_pattern(ip: str) -> bool:
    """Returns True if IP shows bot-like request sequence patterns."""
    hist = ip_history.get(ip, [])
    cutoff = _now() - SEQ_WINDOW
    recent = [e for e in hist if e["ts"] >= cutoff]

    if len(recent) < SEQ_MIN_REQUESTS:
        return False

    paths = [e["path"] for e in recent]
    reasons = []

    # Check 1: Repeated subsequences
    repeated = _find_repeated_subsequences(paths, SEQ_MIN_PATTERN_LEN, SEQ_MIN_REPEATS)
    if repeated:
        pattern, count = repeated
        reasons.append(f"repeated_seq={'->'.join(pattern)} x{count}")

    # Check 2: Transition matrix dominance
    dominant = _check_transition_dominance(paths, SEQ_TRANSITION_THRESHOLD)
    if dominant:
        src, dst, prob = dominant
        reasons.append(f"transition_dominance {src}->{dst} p={prob:.2f}")

    if reasons:
        detail = ", ".join(reasons)
        ban_ip(ip, SEQ_BAN_SECONDS,
               reason=f"seq_pattern ({detail}, n={len(paths)})")
        return True

    return False
