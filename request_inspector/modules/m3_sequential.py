"""Modulul 3: detectia tiparelor secventiale prin entropia tranzitiilor intre rute."""
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
    """Gaseste cea mai lunga subsecventa care se repeta de cel putin un numar dat de ori."""
    n = len(sequence)
    if n < min_len * min_repeats:
        return None

    best: Optional[Tuple[List[str], int]] = None

    for plen in range(min_len, n // min_repeats + 1):
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
    """Construieste matricea de tranzitii Markov si verifica daca o tranzitie domina."""
    if len(sequence) < 4:
        return None

    transitions: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for i in range(len(sequence) - 1):
        transitions[sequence[i]][sequence[i + 1]] += 1

    for src, dests in transitions.items():
        total = sum(dests.values())
        if total < 3:
            continue
        for dst, cnt in dests.items():
            prob = cnt / total
            if prob >= threshold:
                return (src, dst, prob)

    return None

def check_sequential_pattern(ip: str) -> bool:
    """Returneaza True daca IP-ul arata tipare secventiale de tip bot."""
    hist = ip_history.get(ip, [])
    cutoff = _now() - SEQ_WINDOW
    recent = [e for e in hist if e["ts"] >= cutoff]

    if len(recent) < SEQ_MIN_REQUESTS:
        return False

    paths = [e["path"] for e in recent]
    reasons = []

    repeated = _find_repeated_subsequences(paths, SEQ_MIN_PATTERN_LEN, SEQ_MIN_REPEATS)
    if repeated:
        pattern, count = repeated
        reasons.append(f"repeated_seq={'->'.join(pattern)} x{count}")

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
