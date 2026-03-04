import json
import os
import time
import redis

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "10"))
MAX_REQ = int(os.getenv("MAX_REQ", "20"))
BAN_SECONDS = int(os.getenv("BAN_SECONDS", "60"))

PUBSUB_CHANNEL = "requests_channel"
BANNED_PREFIX = "ban:"                 # ban:<ip> = "1" with TTL
RATE_ZSET_PREFIX = "rate:"             # rate:<ip> sorted set of timestamps


r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


def ban_ip(ip: str, reason: str):
    key = f"{BANNED_PREFIX}{ip}"
    # set ban with TTL
    r.set(key, "1", ex=BAN_SECONDS)
    print(f"[BAN] ip={ip} seconds={BAN_SECONDS} reason={reason}")


def handle_event(evt: dict):
    ip = evt.get("ip", "unknown")
    ts = int(evt.get("ts", time.time()))

    if not ip or ip == "unknown":
        return

    # If already banned, ignore further work
    if r.exists(f"{BANNED_PREFIX}{ip}"):
        return

    # Minimal rate logic using a per-IP sorted set:
    # - add timestamp
    # - remove entries older than window
    # - count remaining
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
        ban_ip(ip, reason=f"rate>{MAX_REQ}/{WINDOW_SECONDS}s (count={count})")


def main():
    pubsub = r.pubsub(ignore_subscribe_messages=True)
    pubsub.subscribe(PUBSUB_CHANNEL)
    print(f"[INSPECTOR] subscribed to {PUBSUB_CHANNEL}. Rule: >{MAX_REQ} in {WINDOW_SECONDS}s => ban {BAN_SECONDS}s")

    for msg in pubsub.listen():
        # msg example: {"type":"message","channel":"...","data":"{...json...}"}
        data = msg.get("data")
        if not data:
            continue
        try:
            evt = json.loads(data)
        except json.JSONDecodeError:
            continue
        handle_event(evt)


if __name__ == "__main__":
    main()