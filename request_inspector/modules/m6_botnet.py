"""Modulul 6: detectia coordonarii intre mai multe IP-uri prin agregare de scor."""
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
    BOT_RISK_THRESHOLD,
    BOT_SEQUENTIAL_THRESHOLD,
    BOT_SUBNET_THRESHOLD,
    BOT_TIMING_MIN_IPS,
    BOT_TIMING_TOLERANCE_MS,
    BOT_WINDOW,
    BOT_W_BURSTS,
    BOT_W_ONBOARD,
    BOT_W_SEQUENTIAL,
    BOT_W_SUBNET,
    BOT_W_TIMING,
)
from state import (
    _now,
    global_timeline,
    ip_first_seen,
    ip_history,
)

def _ip_to_int(ip: str) -> Optional[int]:
    """Converteste o adresa IPv4 la intreg pentru analiza secventiala."""
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
    """Returneaza prefixul subretelei /24 sau None."""
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}"
    return None

def _prune_global_timeline(cutoff: float) -> None:
    while global_timeline and global_timeline[0]["ts"] < cutoff:
        global_timeline.pop(0)

def _prune_first_seen(cutoff: float) -> None:
    """Elimina intrarile first-seen mai vechi decat fereastra botnet."""
    expired = [ip for ip, ts in ip_first_seen.items() if ts < cutoff]
    for ip in expired:
        del ip_first_seen[ip]

def _check_mass_onboarding(now: float) -> Optional[Set[str]]:
    """Detecteaza o rafala de IP-uri noi intr-o fereastra scurta."""
    cutoff = now - BOT_ONBOARD_WINDOW
    new_ips = [ip for ip, ts in ip_first_seen.items() if ts >= cutoff]
    if len(new_ips) >= BOT_ONBOARD_THRESHOLD:
        return set(new_ips)
    return None

def _check_subnet_concentration(now: float) -> Optional[Tuple[str, Set[str]]]:
    """Detecteaza multe IP-uri active din aceeasi subretea /24."""
    cutoff = now - BOT_WINDOW
    active_ips: Set[str] = set()
    for ip, hist in ip_history.items():
        if hist and hist[-1]["ts"] >= cutoff:
            active_ips.add(ip)

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
    """Detecteaza adrese IP secventiale numeric."""
    cutoff = now - BOT_WINDOW
    active_ips: List[str] = []
    for ip, hist in ip_history.items():
        if hist and hist[-1]["ts"] >= cutoff:
            active_ips.append(ip)

    if len(active_ips) < BOT_SEQUENTIAL_THRESHOLD:
        return None

    ip_ints: List[Tuple[int, str]] = []
    for ip in active_ips:
        val = _ip_to_int(ip)
        if val is not None:
            ip_ints.append((val, ip))
    ip_ints.sort()

    if len(ip_ints) < BOT_SEQUENTIAL_THRESHOLD:
        return None

    best_run: List[str] = [ip_ints[0][1]]
    current_run: List[str] = [ip_ints[0][1]]

    for i in range(1, len(ip_ints)):
        if ip_ints[i][0] - ip_ints[i - 1][0] <= 2:
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
    """Detecteaza rafale de cereri sincronizate intre IP-uri diferite."""
    cutoff = now - BOT_WINDOW
    _prune_global_timeline(cutoff)

    if len(global_timeline) < BOT_BURST_MIN_IPS:
        return None

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
            i = j
        else:
            i += 1

    if len(bursts) < BOT_BURST_MIN_OCCURRENCES:
        return None

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
    """Detecteaza IP-uri diferite cu tipare de interval aproape identice."""
    cutoff = now - BOT_WINDOW

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

    ips = list(signatures.keys())
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

    visited: Set[str] = set()
    for ip in matched:
        if ip in visited:
            continue
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

def _aggregate_risk(now: float) -> Tuple[Dict[str, int], Dict[str, List[str]]]:
    """Ruleaza toate cele 5 sub-verificari si acumuleaza greutati de risc per IP."""
    scores: Dict[str, int] = defaultdict(int)
    contributions: Dict[str, List[str]] = defaultdict(list)

    def _add(ips: Optional[Set[str]], weight: int, label: str) -> None:
        if not ips:
            return
        tag = f"{label}:{weight}"
        for x in ips:
            scores[x] += weight
            contributions[x].append(tag)

    _add(_check_mass_onboarding(now), BOT_W_ONBOARD, "onboard")

    subnet_result = _check_subnet_concentration(now)
    if subnet_result is not None:
        _add(subnet_result[1], BOT_W_SUBNET, f"subnet[{subnet_result[0]}.0/24]")

    _add(_check_sequential_ips(now), BOT_W_SEQUENTIAL, "sequential")

    _add(_check_synchronized_bursts(now), BOT_W_BURSTS, "sync_bursts")

    _add(_check_cross_ip_timing(now), BOT_W_TIMING, "timing")

    return scores, contributions

def check_distributed_botnet(ip: str, evt: dict) -> bool:
    """Ruleaza toate sub-verificarile distribuite si agrega rezultatele."""
    now = _now()

    global_timeline.append({"ts": evt["ts"], "ip": ip, "path": evt.get("path", "/")})
    _prune_global_timeline(now - BOT_WINDOW)

    if ip not in ip_first_seen:
        ip_first_seen[ip] = now
    _prune_first_seen(now - BOT_WINDOW)

    scores, contributions = _aggregate_risk(now)
    if not scores:
        return False

    to_ban = {x for x, s in scores.items() if s >= BOT_RISK_THRESHOLD}
    if not to_ban:
        return False

    for bip in to_ban:
        evidence = "+".join(contributions[bip])
        ban_ip(
            bip, BOT_BAN_SECONDS,
            reason=f"botnet:score={scores[bip]} ({evidence})",
        )

    return ip in to_ban
