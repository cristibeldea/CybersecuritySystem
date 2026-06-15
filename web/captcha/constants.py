"""Constante pentru subsistemul CAPTCHA: cookie-uri, cai, TTL-uri si parametri de ban."""
import os

CAPTCHA_COOKIE = "captcha_pass"
SESSION_COOKIE = "captcha_sid"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CAPTCHA_PHOTOS_DIR = os.path.join(BASE_DIR, "CAPTCHA_photos")
GRID_DIR = os.path.join(CAPTCHA_PHOTOS_DIR, "grid")

PASS_TTL_SECONDS = 20 * 60
BAN_SECONDS = 60
MAX_CHECKBOX_FAILS = 3
MAX_FAILS_TOTAL    = 5
