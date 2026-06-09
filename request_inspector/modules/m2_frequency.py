"""
Module 2 — Frequency regularity.

Computes inter-request intervals for an IP within ``FREQ_WINDOW`` and
applies two complementary checks:

  1. Coefficient of variation (CV = std / mean) of the intervals.
     Humans produce CVs typically between 0.4 and 1.5; bots driven by
     ``time.sleep(constant)`` produce CVs near zero.

  2. Integer-multiple detection (sleep-loop signature).  If at least
     80% of the intervals are integer multiples of the smallest one
     (within an 8% tolerance), the script is using a parameterised
     ``sleep(random.choice([B, 2B, 3B, ...]))`` loop.

Either check fires a ban of ``FREQ_BAN_SECONDS``.
"""
from typing import List, Optional

from ban import ban_ip
from config import (
    FREQ_BAN_SECONDS,
    FREQ_CV_THRESHOLD,
    FREQ_MIN_REQUESTS,
    FREQ_WINDOW,
)
from state import _now, _std_dev, ip_history


def _compute_intervals(timestamps: List[float]) -> List[float]:
    """Return sorted inter-request intervals in milliseconds."""
    if len(timestamps) < 2:
        return []
    ts_sorted = sorted(timestamps)
    return [round((ts_sorted[i] - ts_sorted[i - 1]) * 1000, 1)
            for i in range(1, len(ts_sorted))]


def _detect_base_multiple(intervals: List[float], tolerance_pct: float = 0.08) -> Optional[float]:
    """Check if all intervals are integer multiples of a base unit.
    Returns the base unit if detected, else None."""
    if not intervals:
        return None
    # Candidate base = smallest non-zero interval
    positives = [iv for iv in intervals if iv > 50]  # ignore sub-50ms noise
    if len(positives) < 2:
        return None
    base = min(positives)
    if base < 10:
        return None

    matches = 0
    for iv in positives:
        ratio = iv / base
        nearest_int = round(ratio)
        if nearest_int < 1:
            continue
        deviation = abs(ratio - nearest_int) / nearest_int
        if deviation <= tolerance_pct:
            matches += 1

    # If ≥80% of intervals are integer multiples of the base
    if matches / len(positives) >= 0.80:
        return base
    return None


def check_frequency_regularity(ip: str) -> bool:
    """Returns True if IP shows bot-like interval regularity."""
    hist = ip_history.get(ip, [])
    cutoff = _now() - FREQ_WINDOW
    timestamps = [e["ts"] for e in hist if e["ts"] >= cutoff]

    if len(timestamps) < FREQ_MIN_REQUESTS:
        return False

    intervals = _compute_intervals(timestamps)
    if not intervals:
        return False

    std = _std_dev(intervals)
    mean = sum(intervals) / len(intervals)

    if mean <= 0:
        return False

    cv = std / mean  # coefficient of variation

    reasons = []

    # Check 1: CV below threshold — metronomic requests
    if cv < FREQ_CV_THRESHOLD:
        reasons.append(f"cv={cv:.4f}<{FREQ_CV_THRESHOLD}")

    # Check 2: Integer-multiple pattern (sleep loop)
    base = _detect_base_multiple(intervals)
    if base is not None:
        reasons.append(f"base_multiple={base:.0f}ms")

    if reasons:
        detail = ", ".join(reasons)
        ban_ip(ip, FREQ_BAN_SECONDS,
               reason=f"freq_regularity ({detail}, n={len(timestamps)}, "
                      f"mean={mean:.0f}ms, std={std:.0f}ms)")
        return True

    return False
