"""
Module 6 — Distributed botnet detection.

Detects coordination across multiple IPs that bypasses every per-IP
check.  Five complementary checks are applied in order; the first one
that fires bans the matching group:

  1. Mass onboarding — many never-before-seen IPs appear in
     ``BOT_ONBOARD_WINDOW`` seconds (≥ ``BOT_ONBOARD_THRESHOLD``).

  2. Subnet concentration — many active IPs share the same /24
     prefix (≥ ``BOT_SUBNET_THRESHOLD``).

  3. Sequential IP addresses — ≥ ``BOT_SEQUENTIAL_THRESHOLD`` active
     IPs whose 32-bit values are numerically consecutive (gap of 1
     allowed).

  4. Synchronized bursts — ≥ ``BOT_BURST_MIN_IPS`` distinct IPs send
     requests inside the same ``BOT_BURST_WINDOW_MS`` window, repeating
     ≥ ``BOT_BURST_MIN_OCCURRENCES`` times.

  5. Cross-IP timing similarity — ≥ ``BOT_TIMING_MIN_IPS`` IPs share an
     inter-request interval signature within ``BOT_TIMING_TOLERANCE_MS``
     of each other on every interval — same script run in parallel
     across machines.

Any of the five fires a ban of ``BOT_BAN_SECONDS`` on the whole group.
"""
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from ban import ban_ip
from config import (
    BOT_BAN_SECONDS,
    BOT_BURST_MIN_IPS,
    BOT_BURST_MIN_OCCURRENCES,
    BOT_BURST_WINDOW_MS,
    BOT_ONBOARD_THRESHOLD,
    BOT_ONBOARD_WINDOW,
    BOT_SEQUENTIAL_THRESHOLD,
    BOT_SUBNET_THRESHOLD,
    BOT_TIMING_MIN_IPS,
    BOT_TIMING_TOLERANCE_MS,
    BOT_WINDOW,
)
from state import (
    _now,
    global_timeline,
    ip_first_seen,
    ip_history,
)


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
