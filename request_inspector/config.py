"""
Centralised configuration for the request inspector.

Every threshold, window and ban duration used by any of the six detection
modules is collected here, sourced from environment variables with safe
defaults.  Constants are grouped by module for easy auditing from the
admin panel and for clear correspondence with the descriptions in
Chapter 3 of the thesis.
"""
import os


# ---------------------------------------------------------------------------
# Redis connection + channel/key prefixes
# ---------------------------------------------------------------------------
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

PUBSUB_CHANNEL = "requests_channel"
BANNED_PREFIX = "ban:"
RATE_ZSET_PREFIX = "rate:"


# ---------------------------------------------------------------------------
# Module 1 — Volume threshold
# ---------------------------------------------------------------------------
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "10"))
MAX_REQ = int(os.getenv("MAX_REQ", "20"))
BAN_SECONDS = int(os.getenv("BAN_SECONDS", "60"))


# ---------------------------------------------------------------------------
# Module 2 — Frequency regularity
# ---------------------------------------------------------------------------
FREQ_WINDOW = int(os.getenv("FREQ_WINDOW", "60"))                       # analyse last N seconds
FREQ_MIN_REQUESTS = int(os.getenv("FREQ_MIN_REQUESTS", "6"))            # need at least this many
FREQ_CV_THRESHOLD = float(os.getenv("FREQ_CV_THRESHOLD", "0.10"))       # CV below this = bot
FREQ_BAN_SECONDS = int(os.getenv("FREQ_BAN_SECONDS", "120"))


# ---------------------------------------------------------------------------
# Module 3 — Sequential pattern detection
# ---------------------------------------------------------------------------
SEQ_WINDOW = int(os.getenv("SEQ_WINDOW", "120"))                        # analyse last N seconds
SEQ_MIN_REQUESTS = int(os.getenv("SEQ_MIN_REQUESTS", "8"))
SEQ_MIN_PATTERN_LEN = int(os.getenv("SEQ_MIN_PATTERN_LEN", "3"))        # shortest repeated subsequence
SEQ_MIN_REPEATS = int(os.getenv("SEQ_MIN_REPEATS", "3"))                # must repeat this many times
SEQ_TRANSITION_THRESHOLD = float(os.getenv("SEQ_TRANSITION_THRESHOLD", "0.90"))
SEQ_BAN_SECONDS = int(os.getenv("SEQ_BAN_SECONDS", "180"))


# ---------------------------------------------------------------------------
# Module 4 — Fingerprint consistency
# ---------------------------------------------------------------------------
FP_WINDOW = int(os.getenv("FP_WINDOW", "300"))                          # 5 min window
FP_MAX_IPS_PER_PRINT = int(os.getenv("FP_MAX_IPS_PER_PRINT", "3"))      # same fingerprint on N+ IPs = botnet
FP_BAN_SECONDS = int(os.getenv("FP_BAN_SECONDS", "300"))
FP_MIN_REQUESTS = int(os.getenv("FP_MIN_REQUESTS", "3"))                # per-IP: need this many before flagging header anomalies


# ---------------------------------------------------------------------------
# Module 5 — Behavioural funnel timing
# ---------------------------------------------------------------------------
FUNNEL_WINDOW = int(os.getenv("FUNNEL_WINDOW", "300"))                          # 5 min window
FUNNEL_MIN_SESSIONS = int(os.getenv("FUNNEL_MIN_SESSIONS", "3"))                # need this many completed sessions
FUNNEL_SESSION_GAP = int(os.getenv("FUNNEL_SESSION_GAP", "30"))                 # seconds of silence = new session
FUNNEL_CV_THRESHOLD = float(os.getenv("FUNNEL_CV_THRESHOLD", "0.08"))           # near-zero variance across sessions
FUNNEL_MIN_PAGE_TO_ACTION = float(os.getenv("FUNNEL_MIN_PAGE_TO_ACTION", "0.8"))# seconds — faster = bot
FUNNEL_BAN_SECONDS = int(os.getenv("FUNNEL_BAN_SECONDS", "240"))


# ---------------------------------------------------------------------------
# Module 6 — Distributed botnet detection
# ---------------------------------------------------------------------------
BOT_WINDOW = int(os.getenv("BOT_WINDOW", "120"))                                  # analysis window in seconds
BOT_ONBOARD_WINDOW = int(os.getenv("BOT_ONBOARD_WINDOW", "10"))                   # mass onboarding: N new IPs in this many seconds
BOT_ONBOARD_THRESHOLD = int(os.getenv("BOT_ONBOARD_THRESHOLD", "5"))               # new IPs in onboard window to trigger
BOT_SUBNET_THRESHOLD = int(os.getenv("BOT_SUBNET_THRESHOLD", "4"))                 # IPs from same /24 subnet
BOT_BURST_WINDOW_MS = int(os.getenv("BOT_BURST_WINDOW_MS", "500"))                 # synchronized burst: events within this ms window
BOT_BURST_MIN_IPS = int(os.getenv("BOT_BURST_MIN_IPS", "4"))                       # distinct IPs in a burst
BOT_BURST_MIN_OCCURRENCES = int(os.getenv("BOT_BURST_MIN_OCCURRENCES", "3"))       # bursts must repeat this many times
BOT_TIMING_MIN_IPS = int(os.getenv("BOT_TIMING_MIN_IPS", "3"))                     # IPs with identical interval signatures
BOT_TIMING_TOLERANCE_MS = float(os.getenv("BOT_TIMING_TOLERANCE_MS", "200"))       # max diff to consider intervals identical
BOT_SEQUENTIAL_THRESHOLD = int(os.getenv("BOT_SEQUENTIAL_THRESHOLD", "4"))         # sequential IP addresses to trigger
BOT_BAN_SECONDS = int(os.getenv("BOT_BAN_SECONDS", "600"))


# ---------------------------------------------------------------------------
# Aggregated history horizon — kept as the maximum window across modules
# so any single in-memory pruning pass is enough for M2, M3 and M5.
# ---------------------------------------------------------------------------
HISTORY_TTL = max(FREQ_WINDOW, SEQ_WINDOW, FUNNEL_WINDOW)
