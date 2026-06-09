"""
Single point of truth for applying an IP ban.

Writes ``ban:<ip>`` = "1" with TTL = ``seconds`` into the shared Redis
instance, then prints a short audit line.  Every module that decides to
ban an IP imports this function — there is no other path through which
the inspector writes ban keys.
"""
from config import BANNED_PREFIX
from state import r


def ban_ip(ip: str, seconds: int, reason: str) -> None:
    """Apply a Redis-backed IP ban with the given TTL and log the reason."""
    key = f"{BANNED_PREFIX}{ip}"
    r.set(key, "1", ex=seconds)
    print(f"[BAN] ip={ip} seconds={seconds} reason={reason}")
