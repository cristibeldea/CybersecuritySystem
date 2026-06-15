"""Modulul 1: prag de volum pe fereastra glisanta per IP."""
import uuid

from ban import ban_ip
from config import (
    BAN_SECONDS,
    MAX_REQ,
    RATE_ZSET_PREFIX,
    WINDOW_SECONDS,
)
from state import r

def check_volume(ip: str, ts: int) -> bool:
    """Returneaza True daca IP-ul trebuie banat pentru depasirea pragului de volum."""
    zkey = f"{RATE_ZSET_PREFIX}{ip}"
    window_start = ts - WINDOW_SECONDS
    member = f"{ts}-{uuid.uuid4().hex}"

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
