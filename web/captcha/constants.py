"""
Constants for the CAPTCHA subsystem.

Holds cookie names, filesystem paths, time-to-live values and ban
thresholds.  Kept dependency-free so every other submodule can import
from here without risking a cycle.
"""
import os

# --- Cookie names -----------------------------------------------------
CAPTCHA_COOKIE = "captcha_pass"
SESSION_COOKIE = "captcha_sid"

# --- Filesystem paths -------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CAPTCHA_PHOTOS_DIR = os.path.join(BASE_DIR, "CAPTCHA_photos")
GRID_DIR = os.path.join(CAPTCHA_PHOTOS_DIR, "grid")

# --- TTLs and ban thresholds -----------------------------------------
PASS_TTL_SECONDS = 20 * 60
BAN_SECONDS = 60          # 1 minute
MAX_CHECKBOX_FAILS = 3    # behavioral failures on hold-to-verify → ban
MAX_FAILS_TOTAL    = 5    # wrong answers on grid CAPTCHA → ban
