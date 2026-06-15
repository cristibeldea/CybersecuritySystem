"""Constante de configurare si client Redis partajat pentru serviciul web."""
import os

import redis

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

CAPTCHA_SECRET   = os.getenv("CAPTCHA_SECRET", "change-this")
POLICY_VERSION   = os.getenv("POLICY_VERSION", "1")
PASS_TTL_SECONDS = 1800

BAN_SECONDS_CAPTCHA     = 60
BAN_SECONDS_HONEYPOT    = 2 * 60
BAN_SECONDS_BEHAVIOR    = 90
BEHAVIOR_RISK_THRESHOLD = 78

COOKIE_SECURE   = False
COOKIE_SAMESITE = "Lax"

ADMIN_USER     = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")

REDIS_BAN_HISTORY = "admin:ban_history"
REDIS_NEAR_MISSES = "admin:near_misses"
REDIS_THRESHOLDS  = "admin:thresholds"
REDIS_SETTINGS    = "admin:settings"
REDIS_ADMIN_PW    = "admin:password_hash"

BAN_OFFENSE_PREFIX     = "ban:offense_count:"
OFFENSE_WINDOW_SECONDS = 7 * 24 * 3600

BAN_LADDER = [
    60,
    300,
    1800,
    86400,
    604800,
]
