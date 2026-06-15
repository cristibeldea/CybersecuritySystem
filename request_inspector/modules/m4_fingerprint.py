"""Modulul 4: detectia IP-urilor care partajeaza aceeasi amprenta HTTP."""
import hashlib
from collections import defaultdict
from typing import Dict, List, Set

from ban import ban_ip
from config import (
    FP_BAN_SECONDS,
    FP_MAX_IPS_PER_PRINT,
    FP_MIN_REQUESTS,
    FP_WINDOW,
)
from state import _now, fp_to_ips, ip_header_stats

_BROWSER_AE_FRAGMENTS = ("gzip", "br", "deflate", "zstd")

_BROWSER_UA_MARKERS = ("mozilla", "chrome", "safari", "firefox", "edge", "opera")

def _build_fingerprint(evt: dict) -> str:
    """Calculeaza hash-ul amprentei din semnale stabile per client."""
    ua = evt.get("ua", "")
    al = evt.get("al", "")
    ae = evt.get("ae", "")
    hdr_order = evt.get("hdr_order", "")

    raw = f"{ua}|{al}|{ae}|{hdr_order}"
    return hashlib.sha256(raw.encode()).hexdigest()[:20]

def _prune_fp_map(cutoff: float) -> None:
    """Elimina intrarile vechi din maparea amprenta-IP."""
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
    """Verifica o cerere pentru tipare suspecte de antete."""
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
        if not al:
            flags.append("browser_no_accept_language")

        if not ae or not any(f in ae.lower() for f in _BROWSER_AE_FRAGMENTS):
            flags.append("browser_no_accept_encoding")

        if not acc:
            flags.append("browser_no_accept")

    if path.startswith("/article/") and not ref:
        flags.append("internal_nav_no_referer")

    return flags

def check_fingerprint(ip: str, evt: dict) -> bool:
    """Returneaza True daca IP-ul trebuie banat pe baza analizei de amprenta."""
    now = _now()
    fp = _build_fingerprint(evt)
    cutoff = now - FP_WINDOW

    _prune_fp_map(cutoff)
    fp_to_ips[fp][ip] = now
    distinct_ips = set(fp_to_ips[fp].keys())

    if len(distinct_ips) >= FP_MAX_IPS_PER_PRINT:
        ip_list = ", ".join(sorted(distinct_ips))
        for shared_ip in distinct_ips:
            ban_ip(shared_ip, FP_BAN_SECONDS,
                   reason=f"fp_shared ({len(distinct_ips)} IPs: {ip_list}, fp={fp[:10]})")
        return True

    anomalies = _detect_header_anomalies(evt)
    if anomalies:
        ip_header_stats[ip].append({"ts": now, "flags": anomalies})

    _prune_header_stats(ip, cutoff)
    recent = ip_header_stats.get(ip, [])

    if len(recent) >= FP_MIN_REQUESTS:
        total = len(recent)
        flag_counts: Dict[str, int] = defaultdict(int)
        for entry in recent:
            for f in entry.get("flags", []):
                flag_counts[f] += 1

        for flag, cnt in flag_counts.items():
            ratio = cnt / total
            if ratio >= 0.80 and total >= FP_MIN_REQUESTS:
                ban_ip(ip, FP_BAN_SECONDS,
                       reason=f"fp_anomaly ({flag} in {cnt}/{total} requests, fp={fp[:10]})")
                return True

    return False
