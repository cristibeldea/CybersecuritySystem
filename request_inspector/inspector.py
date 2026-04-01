import hashlib
import json
import math
import os
import time
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

import redis

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

# --- Module 1: Volume threshold ---
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "10"))
MAX_REQ = int(os.getenv("MAX_REQ", "20"))
BAN_SECONDS = int(os.getenv("BAN_SECONDS", "60"))

# --- Module 2: Frequency regularity ---
FREQ_WINDOW = int(os.getenv("FREQ_WINDOW", "60"))        # analyse last N seconds
FREQ_MIN_REQUESTS = int(os.getenv("FREQ_MIN_REQUESTS", "6"))  # need at least this many
FREQ_CV_THRESHOLD = float(os.getenv("FREQ_CV_THRESHOLD", "0.10"))  # CV below this = bot
FREQ_BAN_SECONDS = int(os.getenv("FREQ_BAN_SECONDS", "120"))

# --- Module 3: Sequential pattern ---
SEQ_WINDOW = int(os.getenv("SEQ_WINDOW", "120"))          # analyse last N seconds
SEQ_MIN_REQUESTS = int(os.getenv("SEQ_MIN_REQUESTS", "8"))
SEQ_MIN_PATTERN_LEN = int(os.getenv("SEQ_MIN_PATTERN_LEN", "3"))  # shortest repeated subsequence
SEQ_MIN_REPEATS = int(os.getenv("SEQ_MIN_REPEATS", "3"))          # must repeat this many times
SEQ_TRANSITION_THRESHOLD = float(os.getenv("SEQ_TRANSITION_THRESHOLD", "0.90"))
SEQ_BAN_SECONDS = int(os.getenv("SEQ_BAN_SECONDS", "180"))

# --- Module 4: Fingerprint consistency ---
FP_WINDOW = int(os.getenv("FP_WINDOW", "300"))            # 5 min window
FP_MAX_IPS_PER_PRINT = int(os.getenv("FP_MAX_IPS_PER_PRINT", "3"))  # same fingerprint on N+ IPs = botnet
FP_BAN_SECONDS = int(os.getenv("FP_BAN_SECONDS", "300"))
FP_MIN_REQUESTS = int(os.getenv("FP_MIN_REQUESTS", "3"))  # per-IP: need this many before flagging header anomalies

# --- Module 5: Funnel timing ---
FUNNEL_WINDOW = int(os.getenv("FUNNEL_WINDOW", "300"))              # 5 min window
FUNNEL_MIN_SESSIONS = int(os.getenv("FUNNEL_MIN_SESSIONS", "3"))    # need this many completed sessions
FUNNEL_SESSION_GAP = int(os.getenv("FUNNEL_SESSION_GAP", "30"))     # seconds of silence = new session
FUNNEL_CV_THRESHOLD = float(os.getenv("FUNNEL_CV_THRESHOLD", "0.08"))  # near-zero variance across sessions
FUNNEL_MIN_PAGE_TO_ACTION = float(os.getenv("FUNNEL_MIN_PAGE_TO_ACTION", "0.8"))  # seconds — faster = bot
FUNNEL_BAN_SECONDS = int(os.getenv("FUNNEL_BAN_SECONDS", "240"))

# --- Module 6: Distributed botnet detection ---
BOT_WINDOW = int(os.getenv("BOT_WINDOW", "120"))                      # analysis window in seconds
BOT_ONBOARD_WINDOW = int(os.getenv("BOT_ONBOARD_WINDOW", "10"))       # mass onboarding: N new IPs in this many seconds
BOT_ONBOARD_THRESHOLD = int(os.getenv("BOT_ONBOARD_THRESHOLD", "5"))   # new IPs in onboard window to trigger
BOT_SUBNET_THRESHOLD = int(os.getenv("BOT_SUBNET_THRESHOLD", "4"))     # IPs from same /24 subnet
BOT_BURST_WINDOW_MS = int(os.getenv("BOT_BURST_WINDOW_MS", "500"))     # synchronized burst: events within this ms window
BOT_BURST_MIN_IPS = int(os.getenv("BOT_BURST_MIN_IPS", "4"))           # distinct IPs in a burst
BOT_BURST_MIN_OCCURRENCES = int(os.getenv("BOT_BURST_MIN_OCCURRENCES", "3"))  # bursts must repeat this many times
BOT_TIMING_MIN_IPS = int(os.getenv("BOT_TIMING_MIN_IPS", "3"))         # IPs with identical interval signatures
BOT_TIMING_TOLERANCE_MS = float(os.getenv("BOT_TIMING_TOLERANCE_MS", "200"))  # max diff to consider intervals identical
BOT_SEQUENTIAL_THRESHOLD = int(os.getenv("BOT_SEQUENTIAL_THRESHOLD", "4"))  # sequential IP addresses to trigger
BOT_BAN_SECONDS = int(os.getenv("BOT_BAN_SECONDS", "600"))

PUBSUB_CHANNEL = "requests_channel"
BANNED_PREFIX = "ban:"
RATE_ZSET_PREFIX = "rate:"

r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

# ---------------------------------------------------------------------------
# In-memory per-IP history for modules 2, 3 & 5.
# Each entry mirrors the published event dict.
# Pruned on every event to keep only the last HISTORY_TTL seconds.
# ---------------------------------------------------------------------------
HISTORY_TTL = max(FREQ_WINDOW, SEQ_WINDOW, FUNNEL_WINDOW)
ip_history: Dict[str, List[dict]] = defaultdict(list)

# ---------------------------------------------------------------------------
# Module 4: fingerprint -> set of (ip, last_seen_ts)
# ---------------------------------------------------------------------------
fp_to_ips: Dict[str, Dict[str, float]] = defaultdict(dict)  # fp_hash -> {ip: last_ts}
ip_header_stats: Dict[str, List[dict]] = defaultdict(list)   # ip -> [{ts, flags...}]

# ---------------------------------------------------------------------------
# Module 6: distributed botnet detection
# ---------------------------------------------------------------------------
ip_first_seen: Dict[str, float] = {}                    # ip -> first seen timestamp
global_timeline: List[dict] = []                         # [{ts, ip, path}, ...] all IPs
# Per-IP interval signature for cross-IP timing comparison: ip -> [interval_ms, ...]
ip_interval_sig: Dict[str, List[float]] = defaultdict(list)


# ===========================================================================
# Helpers
# ===========================================================================

def _now() -> float:
    return time.time()


def _prune_history(ip: str, cutoff: float) -> None:
    """Drop entries older than cutoff."""
    hist = ip_history[ip]
    while hist and hist[0]["ts"] < cutoff:
        hist.pop(0)
    if not hist:
        ip_history.pop(ip, None)


def _std_dev(values: List[float]) -> float:
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return math.sqrt(sum((v - mean) ** 2 for v in values) / n)


def ban_ip(ip: str, seconds: int, reason: str) -> None:
    key = f"{BANNED_PREFIX}{ip}"
    r.set(key, "1", ex=seconds)
    print(f"[BAN] ip={ip} seconds={seconds} reason={reason}")


# ===========================================================================
# Module 1 — Volume threshold (sliding window)
# ===========================================================================

def check_volume(ip: str, ts: int) -> bool:
    """Returns True if IP should be banned for exceeding volume threshold."""
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
        ban_ip(ip, BAN_SECONDS, reason=f"rate>{MAX_REQ}/{WINDOW_SECONDS}s (count={count})")
        return True
    return False


# ===========================================================================
# Module 2 — Frequency regularity
#
# Computes inter-request intervals for an IP and checks:
#   1. Standard deviation of intervals — bots have very low std dev
#   2. Coefficient of variation (CV = std/mean) — CV < threshold = bot
#   3. Integer-multiple detection — intervals that are multiples of a
#      base unit suggest a sleep() loop
# ===========================================================================

def _compute_intervals(timestamps: List[float]) -> List[float]:
    """Return sorted inter-request intervals in milliseconds."""
    if len(timestamps) < 2:
        return []
    ts_sorted = sorted(timestamps)
    return [round((ts_sorted[i] - ts_sorted[i - 1]) * 1000, 1)
            for i in range(1, len(ts_sorted))]


def _detect_base_multiple(intervals: List[float], tolerance_pct: float = 0.08) -> Optional[float]:
    """Check if all intervals are integer multiples of a base unit.
    Returns the base unit if detected, else None."""
    if not intervals:
        return None
    # Candidate base = smallest non-zero interval
    positives = [iv for iv in intervals if iv > 50]  # ignore sub-50ms noise
    if len(positives) < 2:
        return None
    base = min(positives)
    if base < 10:
        return None

    matches = 0
    for iv in positives:
        ratio = iv / base
        nearest_int = round(ratio)
        if nearest_int < 1:
            continue
        deviation = abs(ratio - nearest_int) / nearest_int
        if deviation <= tolerance_pct:
            matches += 1

    # If ≥80% of intervals are integer multiples of the base
    if matches / len(positives) >= 0.80:
        return base
    return None


def check_frequency_regularity(ip: str) -> bool:
    """Returns True if IP shows bot-like interval regularity."""
    hist = ip_history.get(ip, [])
    cutoff = _now() - FREQ_WINDOW
    timestamps = [e["ts"] for e in hist if e["ts"] >= cutoff]

    if len(timestamps) < FREQ_MIN_REQUESTS:
        return False

    intervals = _compute_intervals(timestamps)
    if not intervals:
        return False

    std = _std_dev(intervals)
    mean = sum(intervals) / len(intervals)

    if mean <= 0:
        return False

    cv = std / mean  # coefficient of variation

    reasons = []

    # Check 1: CV below threshold — metronomic requests
    if cv < FREQ_CV_THRESHOLD:
        reasons.append(f"cv={cv:.4f}<{FREQ_CV_THRESHOLD}")

    # Check 2: Integer-multiple pattern (sleep loop)
    base = _detect_base_multiple(intervals)
    if base is not None:
        reasons.append(f"base_multiple={base:.0f}ms")

    if reasons:
        detail = ", ".join(reasons)
        ban_ip(ip, FREQ_BAN_SECONDS,
               reason=f"freq_regularity ({detail}, n={len(timestamps)}, "
                      f"mean={mean:.0f}ms, std={std:.0f}ms)")
        return True

    return False


# ===========================================================================
# Module 3 — Sequential pattern detection
#
# Treats each request's path as a symbol and looks for:
#   1. Repeated subsequences (sliding window substring matching)
#   2. Transition matrix dominance (one next-state always follows a state)
# ===========================================================================

def _find_repeated_subsequences(sequence: List[str],
                                min_len: int,
                                min_repeats: int) -> Optional[Tuple[List[str], int]]:
    """Find the longest subsequence of length ≥ min_len that repeats ≥ min_repeats times.
    Returns (pattern, count) or None."""
    n = len(sequence)
    if n < min_len * min_repeats:
        return None

    best: Optional[Tuple[List[str], int]] = None

    # Check pattern lengths from min_len up to n//min_repeats
    for plen in range(min_len, n // min_repeats + 1):
        # Slide through all possible patterns of this length
        seen: Dict[str, int] = defaultdict(int)
        for start in range(n - plen + 1):
            key = "|".join(sequence[start:start + plen])
            seen[key] += 1

        for key, count in seen.items():
            if count >= min_repeats:
                pattern = key.split("|")
                if best is None or len(pattern) > len(best[0]) or count > best[1]:
                    best = (pattern, count)

    return best


def _check_transition_dominance(sequence: List[str],
                                threshold: float) -> Optional[Tuple[str, str, float]]:
    """Build a first-order Markov transition matrix and check if any
    state has a dominant successor (probability ≥ threshold).
    Returns (from_state, to_state, probability) or None."""
    if len(sequence) < 4:
        return None

    transitions: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for i in range(len(sequence) - 1):
        transitions[sequence[i]][sequence[i + 1]] += 1

    for src, dests in transitions.items():
        total = sum(dests.values())
        if total < 3:  # need at least 3 observations from this state
            continue
        for dst, cnt in dests.items():
            prob = cnt / total
            if prob >= threshold:
                return (src, dst, prob)

    return None


def check_sequential_pattern(ip: str) -> bool:
    """Returns True if IP shows bot-like request sequence patterns."""
    hist = ip_history.get(ip, [])
    cutoff = _now() - SEQ_WINDOW
    recent = [e for e in hist if e["ts"] >= cutoff]

    if len(recent) < SEQ_MIN_REQUESTS:
        return False

    paths = [e["path"] for e in recent]
    reasons = []

    # Check 1: Repeated subsequences
    repeated = _find_repeated_subsequences(paths, SEQ_MIN_PATTERN_LEN, SEQ_MIN_REPEATS)
    if repeated:
        pattern, count = repeated
        reasons.append(f"repeated_seq={'->'.join(pattern)} x{count}")

    # Check 2: Transition matrix dominance
    dominant = _check_transition_dominance(paths, SEQ_TRANSITION_THRESHOLD)
    if dominant:
        src, dst, prob = dominant
        reasons.append(f"transition_dominance {src}->{dst} p={prob:.2f}")

    if reasons:
        detail = ", ".join(reasons)
        ban_ip(ip, SEQ_BAN_SECONDS,
               reason=f"seq_pattern ({detail}, n={len(paths)})")
        return True

    return False


# ===========================================================================
# Module 4 — Fingerprint consistency
#
# Builds a fingerprint from stable client signals (UA, Accept-Language,
# Accept-Encoding, header order) and checks:
#   1. Same fingerprint appearing from N+ different IPs → coordinated botnet
#   2. Per-IP header anomalies: missing browser-expected headers, no cookies
#      on repeat visits, no Referer on internal navigation
# ===========================================================================

# Known browser Accept-Encoding patterns (all real browsers send gzip at minimum)
_BROWSER_AE_FRAGMENTS = ("gzip", "br", "deflate", "zstd")

# User-Agent substrings that indicate a browser (vs. a script/bot library)
_BROWSER_UA_MARKERS = ("mozilla", "chrome", "safari", "firefox", "edge", "opera")


def _build_fingerprint(evt: dict) -> str:
    """Compute a fingerprint hash from stable per-client signals."""
    ua = evt.get("ua", "")
    al = evt.get("al", "")
    ae = evt.get("ae", "")
    hdr_order = evt.get("hdr_order", "")

    raw = f"{ua}|{al}|{ae}|{hdr_order}"
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def _prune_fp_map(cutoff: float) -> None:
    """Remove stale entries from the fingerprint-to-IP map."""
    to_delete = []
    for fp, ip_map in fp_to_ips.items():
        expired = [ip for ip, ts in ip_map.items() if ts < cutoff]
        for ip in expired:
            del ip_map[ip]
        if not ip_map:
            to_delete.append(fp)
    for fp in to_delete:
        del fp_to_ips[fp]


def _prune_header_stats(ip: str, cutoff: float) -> None:
    hist = ip_header_stats.get(ip)
    if not hist:
        return
    while hist and hist[0]["ts"] < cutoff:
        hist.pop(0)
    if not hist:
        ip_header_stats.pop(ip, None)


def _detect_header_anomalies(evt: dict) -> List[str]:
    """Check a single request for suspicious header patterns."""
    flags: List[str] = []
    ua = (evt.get("ua") or "").lower()
    al = evt.get("al") or ""
    ae = evt.get("ae") or ""
    acc = evt.get("acc") or ""
    ref = evt.get("ref") or ""
    cookie_present = evt.get("cookie_present", False)
    path = evt.get("path", "")

    claims_browser = any(m in ua for m in _BROWSER_UA_MARKERS)

    if claims_browser:
        # Real browsers always send Accept-Language
        if not al:
            flags.append("browser_no_accept_language")

        # Real browsers always send Accept-Encoding with at least gzip
        if not ae or not any(f in ae.lower() for f in _BROWSER_AE_FRAGMENTS):
            flags.append("browser_no_accept_encoding")

        # Real browsers send a generic Accept header
        if not acc:
            flags.append("browser_no_accept")

    # Internal navigation should carry a Referer from the same site
    # (clicking from / to /article/X, or from /captcha to /captcha/verify)
    if path.startswith("/article/") and not ref:
        flags.append("internal_nav_no_referer")

    return flags


def check_fingerprint(ip: str, evt: dict) -> bool:
    """Returns True if IP should be banned based on fingerprint analysis."""
    now = _now()
    fp = _build_fingerprint(evt)
    cutoff = now - FP_WINDOW

    # --- Cross-IP: same fingerprint on multiple IPs ---
    _prune_fp_map(cutoff)
    fp_to_ips[fp][ip] = now
    distinct_ips = set(fp_to_ips[fp].keys())

    if len(distinct_ips) >= FP_MAX_IPS_PER_PRINT:
        ip_list = ", ".join(sorted(distinct_ips))
        # Ban all IPs sharing this fingerprint
        for shared_ip in distinct_ips:
            ban_ip(shared_ip, FP_BAN_SECONDS,
                   reason=f"fp_shared ({len(distinct_ips)} IPs: {ip_list}, fp={fp[:10]})")
        return True

    # --- Per-IP: header anomaly accumulation ---
    anomalies = _detect_header_anomalies(evt)
    if anomalies:
        ip_header_stats[ip].append({"ts": now, "flags": anomalies})

    _prune_header_stats(ip, cutoff)
    recent = ip_header_stats.get(ip, [])

    if len(recent) >= FP_MIN_REQUESTS:
        # Count how many of the recent requests had anomalies
        total = len(recent)
        flag_counts: Dict[str, int] = defaultdict(int)
        for entry in recent:
            for f in entry.get("flags", []):
                flag_counts[f] += 1

        # If ≥80% of requests from this IP show the same anomaly → ban
        for flag, cnt in flag_counts.items():
            ratio = cnt / total
            if ratio >= 0.80 and total >= FP_MIN_REQUESTS:
                ban_ip(ip, FP_BAN_SECONDS,
                       reason=f"fp_anomaly ({flag} in {cnt}/{total} requests, fp={fp[:10]})")
                return True

    return False


# ===========================================================================
# Module 5 — Behavioral funnel timing
#
# Tracks the timing between sequential steps in the user funnel:
#   captcha page load → captcha verify → main page access
#
# Checks:
#   1. Per-session: page-to-first-action time is inhumanly fast
#   2. Cross-session: funnel completion times have near-zero variance
#      across multiple sessions from the same IP (identical replay)
# ===========================================================================

# Funnel steps in expected order.  Each request is mapped to a step name.
_FUNNEL_STEPS = {
    "/captcha":        "captcha_load",
    "/captcha/verify": "captcha_action",
    "/captcha/reset":  "captcha_action",
    "/":               "page_access",
}


def _classify_funnel_step(path: str) -> Optional[str]:
    """Map a request path to a funnel step name."""
    if path in _FUNNEL_STEPS:
        return _FUNNEL_STEPS[path]
    if path.startswith("/article/"):
        return "page_access"
    return None


def _extract_funnel_sessions(entries: List[dict], gap: int) -> List[List[dict]]:
    """Split a sorted list of entries into sessions based on time gaps.
    A gap of `gap` seconds or more starts a new session."""
    if not entries:
        return []

    sessions: List[List[dict]] = [[entries[0]]]
    for e in entries[1:]:
        if e["ts"] - sessions[-1][-1]["ts"] >= gap:
            sessions.append([e])
        else:
            sessions[-1].append(e)
    return sessions


def check_funnel_timing(ip: str) -> bool:
    """Returns True if IP shows bot-like funnel timing patterns."""
    hist = ip_history.get(ip, [])
    cutoff = _now() - FUNNEL_WINDOW
    recent = [e for e in hist if e["ts"] >= cutoff]

    if len(recent) < 4:
        return False

    # Tag each entry with its funnel step
    funnel_entries = []
    for e in recent:
        step = _classify_funnel_step(e["path"])
        if step:
            funnel_entries.append({"ts": e["ts"], "step": step, "path": e["path"]})

    if len(funnel_entries) < 3:
        return False

    sessions = _extract_funnel_sessions(funnel_entries, FUNNEL_SESSION_GAP)
    reasons = []

    # ---- Check 1: Per-session — page load to first action too fast ----
    fast_sessions = 0
    for session in sessions:
        steps = [e["step"] for e in session]
        if "captcha_load" in steps and "captcha_action" in steps:
            load_ts = None
            action_ts = None
            for e in session:
                if e["step"] == "captcha_load" and load_ts is None:
                    load_ts = e["ts"]
                elif e["step"] == "captcha_action" and load_ts is not None and action_ts is None:
                    action_ts = e["ts"]
                    break
            if load_ts is not None and action_ts is not None:
                delta = action_ts - load_ts
                if delta < FUNNEL_MIN_PAGE_TO_ACTION:
                    fast_sessions += 1

    # If multiple sessions show inhuman speed → ban
    if fast_sessions >= 2:
        reasons.append(f"fast_page_to_action x{fast_sessions} (< {FUNNEL_MIN_PAGE_TO_ACTION}s)")

    # ---- Check 2: Cross-session — funnel duration variance ----
    session_durations = []
    for session in sessions:
        if len(session) >= 2:
            duration = session[-1]["ts"] - session[0]["ts"]
            if duration > 0:
                session_durations.append(duration)

    if len(session_durations) >= FUNNEL_MIN_SESSIONS:
        std = _std_dev(session_durations)
        mean = sum(session_durations) / len(session_durations)
        if mean > 0:
            cv = std / mean
            if cv < FUNNEL_CV_THRESHOLD:
                reasons.append(
                    f"funnel_duration_cv={cv:.4f}<{FUNNEL_CV_THRESHOLD} "
                    f"(n={len(session_durations)}, mean={mean:.1f}s, std={std:.1f}s)"
                )

    # ---- Check 3: Cross-session — step timing fingerprint ----
    # For each session, build a tuple of inter-step intervals.
    # If all sessions produce near-identical interval tuples → scripted replay.
    step_timing_signatures = []
    for session in sessions:
        if len(session) >= 3:
            intervals = []
            for i in range(1, len(session)):
                intervals.append(round(session[i]["ts"] - session[i - 1]["ts"], 1))
            step_timing_signatures.append(tuple(intervals))

    if len(step_timing_signatures) >= FUNNEL_MIN_SESSIONS:
        # Compare all pairs: what fraction are nearly identical?
        identical_pairs = 0
        total_pairs = 0
        for i in range(len(step_timing_signatures)):
            for j in range(i + 1, len(step_timing_signatures)):
                total_pairs += 1
                a, b = step_timing_signatures[i], step_timing_signatures[j]
                if len(a) == len(b) and len(a) >= 2:
                    max_diff = max(abs(x - y) for x, y in zip(a, b))
                    if max_diff < 0.5:  # within 500ms across all steps
                        identical_pairs += 1

        if total_pairs > 0 and identical_pairs / total_pairs >= 0.80:
            reasons.append(
                f"identical_step_timing ({identical_pairs}/{total_pairs} pairs match)"
            )

    if reasons:
        detail = ", ".join(reasons)
        ban_ip(ip, FUNNEL_BAN_SECONDS,
               reason=f"funnel_timing ({detail})")
        return True

    return False


# ===========================================================================
# Module 6 — Distributed botnet detection
#
# Detects coordination across multiple IPs that bypasses per-IP checks:
#   1. Mass onboarding: many never-before-seen IPs appear in a short window
#   2. Subnet concentration: many IPs from the same /24 subnet
#   3. Sequential IP addresses: numerically adjacent IPs (e.g. .10, .11, .12)
#   4. Synchronized bursts: different IPs sending requests within tight
#      time windows, repeatedly
#   5. Cross-IP timing similarity: different IPs showing identical
#      inter-request interval patterns
# ===========================================================================

def _ip_to_int(ip: str) -> Optional[int]:
    """Convert an IPv4 address to an integer for sequential analysis."""
    parts = ip.split(".")
    if len(parts) != 4:
        return None
    try:
        octets = [int(p) for p in parts]
        if all(0 <= o <= 255 for o in octets):
            return (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
    except ValueError:
        pass
    return None


def _ip_subnet_24(ip: str) -> Optional[str]:
    """Return the /24 subnet prefix (first 3 octets) or None."""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    return None


def _prune_global_timeline(cutoff: float) -> None:
    while global_timeline and global_timeline[0]["ts"] < cutoff:
        global_timeline.pop(0)


def _prune_first_seen(cutoff: float) -> None:
    """Remove first-seen entries older than the botnet window so memory stays bounded."""
    expired = [ip for ip, ts in ip_first_seen.items() if ts < cutoff]
    for ip in expired:
        del ip_first_seen[ip]


def _check_mass_onboarding(now: float) -> Optional[Set[str]]:
    """Detect a burst of never-before-seen IPs in a short window.
    Returns the set of new IPs to ban, or None."""
    cutoff = now - BOT_ONBOARD_WINDOW
    new_ips = [ip for ip, ts in ip_first_seen.items() if ts >= cutoff]
    if len(new_ips) >= BOT_ONBOARD_THRESHOLD:
        return set(new_ips)
    return None


def _check_subnet_concentration(now: float) -> Optional[Tuple[str, Set[str]]]:
    """Detect many active IPs from the same /24 subnet.
    Returns (subnet, set_of_ips) or None."""
    cutoff = now - BOT_WINDOW
    # Collect active IPs (those with recent history)
    active_ips: Set[str] = set()
    for ip, hist in ip_history.items():
        if hist and hist[-1]["ts"] >= cutoff:
            active_ips.add(ip)

    # Group by /24 subnet
    subnet_ips: Dict[str, Set[str]] = defaultdict(set)
    for ip in active_ips:
        subnet = _ip_subnet_24(ip)
        if subnet:
            subnet_ips[subnet].add(ip)

    for subnet, ips in subnet_ips.items():
        if len(ips) >= BOT_SUBNET_THRESHOLD:
            return (subnet, ips)

    return None


def _check_sequential_ips(now: float) -> Optional[Set[str]]:
    """Detect numerically sequential IP addresses (e.g. .10, .11, .12, .13).
    Returns the set of sequential IPs to ban, or None."""
    cutoff = now - BOT_WINDOW
    active_ips: List[str] = []
    for ip, hist in ip_history.items():
        if hist and hist[-1]["ts"] >= cutoff:
            active_ips.append(ip)

    if len(active_ips) < BOT_SEQUENTIAL_THRESHOLD:
        return None

    # Convert to integers and sort
    ip_ints: List[Tuple[int, str]] = []
    for ip in active_ips:
        val = _ip_to_int(ip)
        if val is not None:
            ip_ints.append((val, ip))
    ip_ints.sort()

    # Sliding window: find runs of consecutive IPs
    if len(ip_ints) < BOT_SEQUENTIAL_THRESHOLD:
        return None

    best_run: List[str] = [ip_ints[0][1]]
    current_run: List[str] = [ip_ints[0][1]]

    for i in range(1, len(ip_ints)):
        if ip_ints[i][0] - ip_ints[i - 1][0] <= 2:  # allow gap of 1 (skipped IP)
            current_run.append(ip_ints[i][1])
        else:
            if len(current_run) > len(best_run):
                best_run = current_run
            current_run = [ip_ints[i][1]]

    if len(current_run) > len(best_run):
        best_run = current_run

    if len(best_run) >= BOT_SEQUENTIAL_THRESHOLD:
        return set(best_run)

    return None


def _check_synchronized_bursts(now: float) -> Optional[Set[str]]:
    """Detect repeated synchronized request bursts across different IPs.
    A burst = N+ distinct IPs sending requests within BURST_WINDOW_MS of each other.
    Returns the set of coordinated IPs if bursts repeat, or None."""
    cutoff = now - BOT_WINDOW
    _prune_global_timeline(cutoff)

    if len(global_timeline) < BOT_BURST_MIN_IPS:
        return None

    # Find burst windows: slide through timeline, group events within BURST_WINDOW_MS
    burst_window_s = BOT_BURST_WINDOW_MS / 1000.0
    bursts: List[Set[str]] = []
    i = 0

    while i < len(global_timeline):
        window_end = global_timeline[i]["ts"] + burst_window_s
        ips_in_window: Set[str] = set()
        j = i
        while j < len(global_timeline) and global_timeline[j]["ts"] <= window_end:
            ips_in_window.add(global_timeline[j]["ip"])
            j += 1

        if len(ips_in_window) >= BOT_BURST_MIN_IPS:
            bursts.append(ips_in_window)
            i = j  # skip past this burst
        else:
            i += 1

    if len(bursts) < BOT_BURST_MIN_OCCURRENCES:
        return None

    # Find IPs that appear in multiple bursts — these are coordinated
    ip_burst_count: Dict[str, int] = defaultdict(int)
    for burst in bursts:
        for ip in burst:
            ip_burst_count[ip] += 1

    coordinated = {ip for ip, cnt in ip_burst_count.items()
                   if cnt >= BOT_BURST_MIN_OCCURRENCES}

    if len(coordinated) >= BOT_BURST_MIN_IPS:
        return coordinated

    return None


def _check_cross_ip_timing(now: float) -> Optional[Set[str]]:
    """Detect different IPs with near-identical inter-request interval patterns.
    Even if fingerprints differ, identical timing = same automation script.
    Returns the set of IPs to ban, or None."""
    cutoff = now - BOT_WINDOW

    # Build interval signatures for all active IPs
    signatures: Dict[str, Tuple[float, ...]] = {}
    for ip, hist in ip_history.items():
        recent = [e for e in hist if e["ts"] >= cutoff]
        if len(recent) < 4:
            continue
        timestamps = [e["ts"] for e in recent]
        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append(round((timestamps[i] - timestamps[i - 1]) * 1000, 0))
        if len(intervals) >= 3:
            signatures[ip] = tuple(intervals)

    if len(signatures) < BOT_TIMING_MIN_IPS:
        return None

    # Compare all pairs of IPs for similar interval signatures
    ips = list(signatures.keys())
    # Build clusters of IPs with matching signatures
    matched: Dict[str, Set[str]] = defaultdict(set)

    for i in range(len(ips)):
        for j in range(i + 1, len(ips)):
            sig_a = signatures[ips[i]]
            sig_b = signatures[ips[j]]

            if len(sig_a) != len(sig_b):
                continue
            if len(sig_a) < 3:
                continue

            max_diff = max(abs(a - b) for a, b in zip(sig_a, sig_b))
            if max_diff <= BOT_TIMING_TOLERANCE_MS:
                matched[ips[i]].add(ips[j])
                matched[ips[j]].add(ips[i])

    # Find clusters of N+ IPs
    visited: Set[str] = set()
    for ip in matched:
        if ip in visited:
            continue
        # BFS to find the full cluster
        cluster: Set[str] = set()
        queue = [ip]
        while queue:
            node = queue.pop(0)
            if node in cluster:
                continue
            cluster.add(node)
            for neighbor in matched.get(node, set()):
                if neighbor not in cluster:
                    queue.append(neighbor)
        visited |= cluster

        if len(cluster) >= BOT_TIMING_MIN_IPS:
            return cluster

    return None


def check_distributed_botnet(ip: str, evt: dict) -> bool:
    """Run all distributed botnet detection checks.
    Returns True if the current IP (or a group including it) was banned."""
    now = _now()

    # --- Record in global timeline ---
    global_timeline.append({"ts": evt["ts"], "ip": ip, "path": evt.get("path", "/")})
    _prune_global_timeline(now - BOT_WINDOW)

    # --- Track first-seen ---
    if ip not in ip_first_seen:
        ip_first_seen[ip] = now
    _prune_first_seen(now - BOT_WINDOW)

    banned_any = False

    # Check 1: Mass onboarding
    onboard_ips = _check_mass_onboarding(now)
    if onboard_ips and ip in onboard_ips:
        for oip in onboard_ips:
            ban_ip(oip, BOT_BAN_SECONDS,
                   reason=f"botnet:mass_onboarding ({len(onboard_ips)} new IPs "
                          f"in {BOT_ONBOARD_WINDOW}s)")
        return True

    # Check 2: Subnet concentration
    subnet_result = _check_subnet_concentration(now)
    if subnet_result:
        subnet, subnet_ips = subnet_result
        if ip in subnet_ips:
            for sip in subnet_ips:
                ban_ip(sip, BOT_BAN_SECONDS,
                       reason=f"botnet:subnet_concentration ({len(subnet_ips)} IPs "
                              f"in {subnet}.0/24)")
            return True

    # Check 3: Sequential IP addresses
    seq_ips = _check_sequential_ips(now)
    if seq_ips and ip in seq_ips:
        for sip in seq_ips:
            ban_ip(sip, BOT_BAN_SECONDS,
                   reason=f"botnet:sequential_ips ({len(seq_ips)} consecutive IPs)")
        return True

    # Check 4: Synchronized bursts
    burst_ips = _check_synchronized_bursts(now)
    if burst_ips and ip in burst_ips:
        for bip in burst_ips:
            ban_ip(bip, BOT_BAN_SECONDS,
                   reason=f"botnet:sync_bursts ({len(burst_ips)} IPs in "
                          f"{BOT_BURST_MIN_OCCURRENCES}+ bursts of {BOT_BURST_WINDOW_MS}ms)")
        return True

    # Check 5: Cross-IP timing similarity
    timing_ips = _check_cross_ip_timing(now)
    if timing_ips and ip in timing_ips:
        for tip in timing_ips:
            ban_ip(tip, BOT_BAN_SECONDS,
                   reason=f"botnet:identical_timing ({len(timing_ips)} IPs with matching "
                          f"interval signatures, tolerance={BOT_TIMING_TOLERANCE_MS}ms)")
        return True

    return False


# ===========================================================================
# Main event handler
# ===========================================================================

def handle_event(evt: dict) -> None:
    ip = evt.get("ip", "unknown")
    ts = int(evt.get("ts", time.time()))
    path = evt.get("path", "/")
    kind = evt.get("kind", "other")

    if not ip or ip == "unknown":
        return

    # If already banned, skip
    if r.exists(f"{BANNED_PREFIX}{ip}"):
        return

    # --- Record in history for modules 2, 3, 5 ---
    ip_history[ip].append(evt)
    _prune_history(ip, _now() - HISTORY_TTL)

    # --- Module 1: Volume threshold (skip captcha-kind requests) ---
    if kind != "captcha":
        if check_volume(ip, ts):
            return

    # --- Module 2: Frequency regularity ---
    if check_frequency_regularity(ip):
        return

    # --- Module 3: Sequential pattern ---
    if check_sequential_pattern(ip):
        return

    # --- Module 4: Fingerprint consistency ---
    if check_fingerprint(ip, evt):
        return

    # --- Module 5: Funnel timing ---
    if check_funnel_timing(ip):
        return

    # --- Module 6: Distributed botnet ---
    check_distributed_botnet(ip, evt)


def main():
    pubsub = r.pubsub(ignore_subscribe_messages=True)
    pubsub.subscribe(PUBSUB_CHANNEL)
    print(f"[INSPECTOR] subscribed to {PUBSUB_CHANNEL}")
    print(f"  Module 1: >{MAX_REQ} in {WINDOW_SECONDS}s => ban {BAN_SECONDS}s")
    print(f"  Module 2: CV<{FREQ_CV_THRESHOLD} in {FREQ_WINDOW}s window => ban {FREQ_BAN_SECONDS}s")
    print(f"  Module 3: repeated seq (len>={SEQ_MIN_PATTERN_LEN}, x{SEQ_MIN_REPEATS}) "
          f"or transition p>={SEQ_TRANSITION_THRESHOLD} in {SEQ_WINDOW}s => ban {SEQ_BAN_SECONDS}s")
    print(f"  Module 4: same fp on >={FP_MAX_IPS_PER_PRINT} IPs => ban {FP_BAN_SECONDS}s, "
          f"header anomaly >=80% in {FP_MIN_REQUESTS}+ reqs => ban {FP_BAN_SECONDS}s")
    print(f"  Module 5: page-to-action <{FUNNEL_MIN_PAGE_TO_ACTION}s or "
          f"session CV<{FUNNEL_CV_THRESHOLD} across {FUNNEL_MIN_SESSIONS}+ sessions => ban {FUNNEL_BAN_SECONDS}s")
    print(f"  Module 6: onboard>={BOT_ONBOARD_THRESHOLD}/{BOT_ONBOARD_WINDOW}s, "
          f"subnet>={BOT_SUBNET_THRESHOLD}/24, seq>={BOT_SEQUENTIAL_THRESHOLD}, "
          f"burst>={BOT_BURST_MIN_IPS}IPs/{BOT_BURST_WINDOW_MS}ms, "
          f"timing>={BOT_TIMING_MIN_IPS}IPs => ban {BOT_BAN_SECONDS}s")

    for msg in pubsub.listen():
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