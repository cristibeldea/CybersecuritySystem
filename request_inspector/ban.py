"""Punct unic pentru aplicarea ban-ului pe IP in Redis."""
from config import BANNED_PREFIX
from state import r

def ban_ip(ip: str, seconds: int, reason: str) -> None:
    """Aplica un ban pe IP in Redis cu TTL specificat si logheaza motivul."""
    key = f"{BANNED_PREFIX}{ip}"
    r.set(key, "1", ex=seconds)
    print(f"[BAN] ip={ip} seconds={seconds} reason={reason}")
