"""Stare comuna in memorie si helper-i de nivel jos folositi de toate modulele."""
import math
import time
from collections import defaultdict
from typing import Dict, List

import redis

from config import REDIS_HOST, REDIS_PORT

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

ip_history: Dict[str, List[dict]] = defaultdict(list)

fp_to_ips: Dict[str, Dict[str, float]] = defaultdict(dict)
ip_header_stats: Dict[str, List[dict]] = defaultdict(list)

ip_first_seen: Dict[str, float] = {}
global_timeline: List[dict] = []
ip_interval_sig: Dict[str, List[float]] = defaultdict(list)

def _now() -> float:
    """Returneaza secundele curente ca float."""
    return time.time()

def _prune_history(ip: str, cutoff: float) -> None:
    """Elimina intrarile mai vechi decat cutoff din istoricul unui IP."""
    hist = ip_history[ip]
    while hist and hist[0]["ts"] < cutoff:
        hist.pop(0)
    if not hist:
        ip_history.pop(ip, None)

def _std_dev(values: List[float]) -> float:
    """Deviatia standard de populatie, folosita de M2 si M5."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return math.sqrt(sum((v - mean) ** 2 for v in values) / n)
