"""
Request inspector main loop.

Subscribes to the Redis Pub/Sub channel published by the Flask web
service and applies the six detection modules sequentially per event,
in increasing order of computational cost.  The first module that
decides to ban the source IP halts the chain for that event.

This file is the consequence of refactoring the original 980-line
``inspector.py`` into a package: configuration lives in ``config.py``,
shared state and helpers in ``state.py``, the ban primitive in
``ban.py``, and the six detection algorithms each in their own file
under ``modules/``.

Module ordering rationale (also discussed in Chapter 3 of the thesis):
    M1 — cheapest (Redis ZSET cardinality, microseconds)
    M2 — interval CV statistics on per-IP history
    M3 — sequential substring + first-order Markov on URL paths
    M4 — SHA-256 fingerprint + header coherence rules
    M5 — funnel-step extraction + cross-session timing analysis
    M6 — costliest (cross-IP global aggregation + BFS clustering)
"""
import json
import time

from config import (
    BAN_SECONDS,
    BANNED_PREFIX,
    BOT_BAN_SECONDS,
    BOT_BURST_MIN_IPS,
    BOT_BURST_WINDOW_MS,
    BOT_ONBOARD_THRESHOLD,
    BOT_ONBOARD_WINDOW,
    BOT_SEQUENTIAL_THRESHOLD,
    BOT_SUBNET_THRESHOLD,
    BOT_TIMING_MIN_IPS,
    FP_BAN_SECONDS,
    FP_MAX_IPS_PER_PRINT,
    FP_MIN_REQUESTS,
    FREQ_BAN_SECONDS,
    FREQ_CV_THRESHOLD,
    FREQ_WINDOW,
    FUNNEL_BAN_SECONDS,
    FUNNEL_CV_THRESHOLD,
    FUNNEL_MIN_PAGE_TO_ACTION,
    FUNNEL_MIN_SESSIONS,
    HISTORY_TTL,
    MAX_REQ,
    PUBSUB_CHANNEL,
    SEQ_BAN_SECONDS,
    SEQ_MIN_PATTERN_LEN,
    SEQ_MIN_REPEATS,
    SEQ_TRANSITION_THRESHOLD,
    SEQ_WINDOW,
    WINDOW_SECONDS,
)
from modules import (
    check_distributed_botnet,
    check_fingerprint,
    check_frequency_regularity,
    check_sequential_pattern,
    check_volume,
    check_funnel_timing,
)
# Re-export the internal helpers of Module 6 so the legacy test suite,
# which historically reached into ``inspector._check_*`` directly,
# keeps working unchanged after the package refactor.
from modules.m6_botnet import (
    _check_cross_ip_timing,
    _check_mass_onboarding,
    _check_sequential_ips,
    _check_subnet_concentration,
    _check_synchronized_bursts,
    _ip_subnet_24,
    _ip_to_int,
    _prune_first_seen,
    _prune_global_timeline,
)
from state import (
    _now,
    _prune_history,
    _std_dev,
    fp_to_ips,
    global_timeline,
    ip_first_seen,
    ip_header_stats,
    ip_history,
    ip_interval_sig,
    r,
)


def handle_event(evt: dict) -> None:
    """Apply the six detection modules to a single inspected event."""
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


def main() -> None:
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
