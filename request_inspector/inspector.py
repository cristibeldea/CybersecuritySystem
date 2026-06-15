"""Bucla principala a inspectorului: consuma evenimente de pe canalul Redis Pub/Sub."""
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
    """Aplica cele sase module de detectie pe un singur eveniment."""
    ip = evt.get("ip", "unknown")
    ts = int(evt.get("ts", time.time()))
    path = evt.get("path", "/")
    kind = evt.get("kind", "other")

    if not ip or ip == "unknown":
        return

    if r.exists(f"{BANNED_PREFIX}{ip}"):
        return

    ip_history[ip].append(evt)
    _prune_history(ip, _now() - HISTORY_TTL)

    if kind != "captcha":
        if check_volume(ip, ts):
            return

    if check_frequency_regularity(ip):
        return

    if check_sequential_pattern(ip):
        return

    if check_fingerprint(ip, evt):
        return

    if check_funnel_timing(ip):
        return

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
