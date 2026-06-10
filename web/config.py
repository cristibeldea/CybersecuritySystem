"""
Configuration constants and the shared Redis client for the web service.

All env-driven settings, ban-ladder values, cookie attributes and Redis
key names live here so the rest of the package can import them from a
single authoritative location, and so a deployment can override every
knob by setting the corresponding environment variable.
"""
import os

import redis


# --- Redis client (used by every other module) ----------------------
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


# --- CAPTCHA / pass token --------------------------------------------
CAPTCHA_SECRET   = os.getenv("CAPTCHA_SECRET", "change-this")
POLICY_VERSION   = os.getenv("POLICY_VERSION", "1")
PASS_TTL_SECONDS = 1800


# --- Ban durations and behavioural risk threshold --------------------
BAN_SECONDS_CAPTCHA     = 60        # failed captcha attempts
BAN_SECONDS_HONEYPOT    = 2 * 60    # honeypot trap (bot confirmed)
BAN_SECONDS_BEHAVIOR    = 90        # behavioural analysis on website
BEHAVIOR_RISK_THRESHOLD = 78        # same as captcha checkbox threshold


# --- Cookie attributes -----------------------------------------------
COOKIE_SECURE   = False
COOKIE_SAMESITE = "Lax"


# --- Admin credentials -----------------------------------------------
ADMIN_USER     = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin")


# --- Redis keys used by the admin dashboard --------------------------
REDIS_BAN_HISTORY = "admin:ban_history"       # list of JSON ban events
REDIS_NEAR_MISSES = "admin:near_misses"       # list of JSON near-miss events
REDIS_THRESHOLDS  = "admin:thresholds"        # hash of threshold overrides
REDIS_SETTINGS    = "admin:settings"          # hash of admin settings
REDIS_ADMIN_PW    = "admin:password_hash"     # stored sha256 password hash


# --- Progressive ban ladder ------------------------------------------
# Each new ban for the same IP escalates the duration. The offense
# counter lives in Redis under ``<BAN_OFFENSE_PREFIX><ip>`` with a TTL
# of OFFENSE_WINDOW_SECONDS — if the IP stays clean during that window
# the counter resets and the next ban starts at level 1.
BAN_OFFENSE_PREFIX     = "ban:offense_count:"
OFFENSE_WINDOW_SECONDS = 7 * 24 * 3600   # 7 days

BAN_LADDER = [
    60,        # level 1: 1 min
    300,       # level 2: 5 min
    1800,      # level 3: 30 min
    86400,     # level 4: 24 h
    604800,    # level 5+: 7 days
]
