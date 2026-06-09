"""
Module 1 — Volume threshold (sliding window).

Counts how many HTTP events an IP has produced within the last
``WINDOW_SECONDS`` seconds.  Uses a Redis sorted set keyed by IP, with
timestamps as scores: each new request is added, then everything older
than the window edge is evicted in the same pipeline.

A continuously sliding window like this prevents the classic "bucket
boundary" attack where a script straddles two adjacent fixed windows
to fit ``2 * MAX_REQ`` requests inside the real window length.
"""
import time

from ban import ban_ip
from config import (
    BAN_SECONDS,
    MAX_REQ,
    RATE_ZSET_PREFIX,
    WINDOW_SECONDS,
)
from state import r


def check_volume(ip: str, ts: int) -> bool:
    """Returns True if IP should be banned for exceeding the volume threshold."""
    zkey = f"{RATE_ZSET_PREFIX}{ip}"
    window_start = ts - WINDOW_SECONDS
    member = f"{ts}-{time.time_ns()}"

    pipe = r.pipeline()
    pipe.zadd(zkey, {member: ts})
    pipe.zremrangebyscore(zkey, 0, window_start)
    pipe.zcard(zkey)
    pipe.expire(zkey, WINDOW_SECONDS * 2)
    _, _, count, _ = pipe.execute()

    if count > MAX_REQ:
        ban_ip(ip, BAN_SECONDS, reason=f"rate>{MAX_REQ}/{WINDOW_SECONDS}s (count={count})")
        return True
    return False
