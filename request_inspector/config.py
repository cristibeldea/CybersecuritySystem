"""Configurare centralizata: praguri, ferestre si durate de ban pentru toate modulele de detectie."""
import os

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

PUBSUB_CHANNEL = "requests_channel"
BANNED_PREFIX = "ban:"
RATE_ZSET_PREFIX = "rate:"

WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "10"))
MAX_REQ = int(os.getenv("MAX_REQ", "20"))
BAN_SECONDS = int(os.getenv("BAN_SECONDS", "60"))

FREQ_WINDOW = int(os.getenv("FREQ_WINDOW", "60"))
FREQ_MIN_REQUESTS = int(os.getenv("FREQ_MIN_REQUESTS", "6"))
FREQ_CV_THRESHOLD = float(os.getenv("FREQ_CV_THRESHOLD", "0.10"))
FREQ_BAN_SECONDS = int(os.getenv("FREQ_BAN_SECONDS", "120"))

SEQ_WINDOW = int(os.getenv("SEQ_WINDOW", "120"))
SEQ_MIN_REQUESTS = int(os.getenv("SEQ_MIN_REQUESTS", "8"))
SEQ_MIN_PATTERN_LEN = int(os.getenv("SEQ_MIN_PATTERN_LEN", "3"))
SEQ_MIN_REPEATS = int(os.getenv("SEQ_MIN_REPEATS", "3"))
SEQ_TRANSITION_THRESHOLD = float(os.getenv("SEQ_TRANSITION_THRESHOLD", "0.90"))
SEQ_BAN_SECONDS = int(os.getenv("SEQ_BAN_SECONDS", "180"))

FP_WINDOW = int(os.getenv("FP_WINDOW", "300"))
FP_MAX_IPS_PER_PRINT = int(os.getenv("FP_MAX_IPS_PER_PRINT", "3"))
FP_BAN_SECONDS = int(os.getenv("FP_BAN_SECONDS", "300"))
FP_MIN_REQUESTS = int(os.getenv("FP_MIN_REQUESTS", "3"))

FUNNEL_WINDOW = int(os.getenv("FUNNEL_WINDOW", "300"))
FUNNEL_MIN_SESSIONS = int(os.getenv("FUNNEL_MIN_SESSIONS", "3"))
FUNNEL_SESSION_GAP = int(os.getenv("FUNNEL_SESSION_GAP", "30"))
FUNNEL_CV_THRESHOLD = float(os.getenv("FUNNEL_CV_THRESHOLD", "0.08"))
FUNNEL_MIN_PAGE_TO_ACTION = float(os.getenv("FUNNEL_MIN_PAGE_TO_ACTION", "0.8"))
FUNNEL_BAN_SECONDS = int(os.getenv("FUNNEL_BAN_SECONDS", "240"))

BOT_WINDOW = int(os.getenv("BOT_WINDOW", "120"))
BOT_ONBOARD_WINDOW = int(os.getenv("BOT_ONBOARD_WINDOW", "10"))
BOT_ONBOARD_THRESHOLD = int(os.getenv("BOT_ONBOARD_THRESHOLD", "5"))
BOT_SUBNET_THRESHOLD = int(os.getenv("BOT_SUBNET_THRESHOLD", "4"))
BOT_BURST_WINDOW_MS = int(os.getenv("BOT_BURST_WINDOW_MS", "500"))
BOT_BURST_MIN_IPS = int(os.getenv("BOT_BURST_MIN_IPS", "4"))
BOT_BURST_MIN_OCCURRENCES = int(os.getenv("BOT_BURST_MIN_OCCURRENCES", "3"))
BOT_TIMING_MIN_IPS = int(os.getenv("BOT_TIMING_MIN_IPS", "3"))
BOT_TIMING_TOLERANCE_MS = float(os.getenv("BOT_TIMING_TOLERANCE_MS", "200"))
BOT_SEQUENTIAL_THRESHOLD = int(os.getenv("BOT_SEQUENTIAL_THRESHOLD", "4"))
BOT_BAN_SECONDS = int(os.getenv("BOT_BAN_SECONDS", "600"))

BOT_W_SUBNET     = int(os.getenv("BOT_W_SUBNET", "20"))
BOT_W_ONBOARD    = int(os.getenv("BOT_W_ONBOARD", "25"))
BOT_W_SEQUENTIAL = int(os.getenv("BOT_W_SEQUENTIAL", "40"))
BOT_W_BURSTS     = int(os.getenv("BOT_W_BURSTS", "60"))
BOT_W_TIMING     = int(os.getenv("BOT_W_TIMING", "65"))
BOT_RISK_THRESHOLD = int(os.getenv("BOT_RISK_THRESHOLD", "55"))

HISTORY_TTL = max(FREQ_WINDOW, SEQ_WINDOW, FUNNEL_WINDOW)
