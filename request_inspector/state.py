"""
Shared in-memory state and low-level helpers for the inspector.

  - ``r`` — the Redis client used by every module (single shared connection)
  - per-IP history (used by M2, M3, M5)
  - fingerprint <-> IP mapping (M4)
  - per-IP header anomaly history (M4)
  - first-seen IP map (M6)
  - global event timeline (M6)
  - per-IP interval signature cache (M6)
  - ``_now()`` — float wall-clock seconds
  - ``_prune_history(ip, cutoff)`` — drop stale per-IP entries
  - ``_std_dev(values)`` — population standard deviation used by M2 and M5
"""
import math
import time
from collections import defaultdict
from typing import Dict, List

import redis

from config import REDIS_HOST, REDIS_PORT


# ---------------------------------------------------------------------------
# Redis connection (single shared instance)
# ---------------------------------------------------------------------------
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


# ---------------------------------------------------------------------------
# In-memory per-IP history for modules 2, 3 & 5.
# Each entry mirrors the published event dict.
# Pruned on every event to keep only the last HISTORY_TTL seconds.
# ---------------------------------------------------------------------------
ip_history: Dict[str, List[dict]] = defaultdict(list)


# ---------------------------------------------------------------------------
# Module 4: fingerprint -> set of (ip, last_seen_ts)
# ---------------------------------------------------------------------------
fp_to_ips: Dict[str, Dict[str, float]] = defaultdict(dict)   # fp_hash -> {ip: last_ts}
ip_header_stats: Dict[str, List[dict]] = defaultdict(list)    # ip -> [{ts, flags...}]


# ---------------------------------------------------------------------------
# Module 6: distributed botnet detection
# ---------------------------------------------------------------------------
ip_first_seen: Dict[str, float] = {}                    # ip -> first seen timestamp
global_timeline: List[dict] = []                         # [{ts, ip, path}, ...] all IPs
# Per-IP interval signature for cross-IP timing comparison: ip -> [interval_ms, ...]
ip_interval_sig: Dict[str, List[float]] = defaultdict(list)


# ---------------------------------------------------------------------------
# Small numeric helpers
# ---------------------------------------------------------------------------
def _now() -> float:
    """Wall-clock seconds as a float."""
    return time.time()


def _prune_history(ip: str, cutoff: float) -> None:
    """Drop entries older than ``cutoff`` from this IP's history.
    Removes the IP entirely if it has no entries left."""
    hist = ip_history[ip]
    while hist and hist[0]["ts"] < cutoff:
        hist.pop(0)
    if not hist:
        ip_history.pop(ip, None)


def _std_dev(values: List[float]) -> float:
    """Population standard deviation.  Used by M2 (interval CV) and M5
    (session-duration CV).  Returns 0 for fewer than 2 samples."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return math.sqrt(sum((v - mean) ** 2 for v in values) / n)
