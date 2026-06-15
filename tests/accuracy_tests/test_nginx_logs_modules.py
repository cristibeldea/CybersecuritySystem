"""Test de acuratete al modulelor M1-M4 pe log-uri nginx reale (Zanbil.ir)."""
import os
import sys
import io
import re
import json
import csv
import time
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple, Optional

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

PROJECT_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
INSPECTOR_DIR = os.path.join(PROJECT_ROOT, "request_inspector")
if INSPECTOR_DIR not in sys.path:
    sys.path.insert(0, INSPECTOR_DIR)

import inspector  # noqa: E402
import ban as ban_module  # noqa: E402
from modules import (  # noqa: E402
    m1_volume, m2_frequency, m3_sequential, m4_fingerprint,
    m5_funnel, m6_botnet,
)

LOG_PATH = os.path.join(
    PROJECT_ROOT, "tests", "resources",
    "requests_traffic_kaggle_dataset", "access.log",
)
HOSTNAME_CSV = os.path.join(
    PROJECT_ROOT, "tests", "resources",
    "requests_traffic_kaggle_dataset", "client_hostname.csv",
)
OUT_JSON = os.path.join(
    os.path.dirname(__file__), "data", "nginx_modules_results.json"
)

MAX_LINES = int(os.environ.get("MAX_LINES", "200000"))

MIN_REQUESTS_PER_IP = int(os.environ.get("MIN_REQUESTS", "10"))

BOT_UA_MARKERS = [
    "googlebot", "bingbot", "ahrefsbot", "applebot", "yandexbot",
    "baiduspider", "duckduckbot", "slurp", "crawler", "spider",
    "barkrowler", "petalbot", "semrushbot", "mj12bot", "dotbot",
    "googlebot-image", "googlebot-mobile", "googlebot-video",
    "facebookexternalhit", "twitterbot", "linkedinbot", "telegrambot",
    "whatsapp", "msnbot", "exabot", "facebot", "torob",
]

BOT_HOSTNAME_MARKERS = [
    ".googlebot.com", ".google.com", ".bing.com", ".search.msn.com",
    ".ahrefs.com", ".applebot.apple.com", ".yandex.com", ".yandex.ru",
    ".crawl.baidu.com", ".duckduckgo.com",
]

BROWSER_MARKERS = ["mozilla", "chrome", "safari", "firefox", "edge", "opera"]

def label_ip(ua: str, hostname: Optional[str]) -> str:
    """Returneaza 'bot_known', 'human' sau 'unknown' pe baza UA si hostname."""
    ua_lower = (ua or "").lower()

    for marker in BOT_UA_MARKERS:
        if marker in ua_lower:
            return "bot_known"

    if hostname:
        h_lower = hostname.lower()
        for marker in BOT_HOSTNAME_MARKERS:
            if marker in h_lower:
                return "bot_known"

    has_browser = any(m in ua_lower for m in BROWSER_MARKERS)
    if has_browser and "bot" not in ua_lower and "crawler" not in ua_lower:
        return "human"

    return "unknown"

NGINX_LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>[^"]*) (?P<protocol>HTTP/[\d.]+)" '
    r'(?P<status>\d+) (?P<size>\S+) '
    r'"(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

def parse_line(line: str) -> Optional[Dict]:
    m = NGINX_LINE_RE.match(line)
    if not m:
        return None
    try:
        ts_str = m.group("ts")
        dt_part, tz_part = ts_str.rsplit(" ", 1)
        dt = datetime.strptime(dt_part, "%d/%b/%Y:%H:%M:%S")
        tz_h = int(tz_part[:3])
        tz_m = int(tz_part[0] + tz_part[3:])
        offset_sec = tz_h * 3600 + tz_m * 60
        ts_epoch = int(dt.timestamp()) - offset_sec
    except Exception:
        return None
    return {
        "ip": m.group("ip"),
        "ts": ts_epoch,
        "method": m.group("method"),
        "path": m.group("path"),
        "status": int(m.group("status")),
        "referer": m.group("referer") if m.group("referer") != "-" else "",
        "ua": m.group("ua"),
    }

def load_hostnames(csv_path: str) -> Dict[str, str]:
    """Returneaza dict IP catre hostname."""
    print(f"[*] Incarcare client_hostname.csv ({os.path.basename(csv_path)})...")
    mapping = {}
    with open(csv_path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for row in reader:
            ip = row.get("client", "").strip()
            host = row.get("hostname", "").strip()
            if ip and host and host != ip and not host.startswith("[Errno"):
                mapping[ip] = host
    print(f"    {len(mapping):,} IP-uri cu hostname resolved")
    return mapping

def build_event(parsed: Dict) -> Dict:
    """Construieste un dict in formatul asteptat de handle_event."""
    ua = parsed["ua"]
    path = parsed["path"]
    kind = "captcha" if path.startswith("/captcha") else "page"
    return {
        "ip": parsed["ip"],
        "ts": parsed["ts"],
        "path": path,
        "method": parsed["method"],
        "kind": kind,
        "ua": ua,
        "al": "en-US",
        "ae": "gzip, deflate, br",
        "acc": "text/html",
        "ref": parsed["referer"],
        "hdr_order": "ua,al,ae,acc",
        "cookie_present": False,
        "username": "anonymous",
    }

def reset_state():
    inspector.ip_history.clear()
    inspector.fp_to_ips.clear()
    inspector.ip_header_stats.clear()
    inspector.ip_first_seen.clear()
    inspector.global_timeline.clear()
    inspector.ip_interval_sig.clear()

def clear_redis_bans(ips):
    """Sterge cheile ban si rate pentru o lista de IP-uri."""
    try:
        pipe = inspector.r.pipeline()
        for ip in ips:
            pipe.delete(f"ban:{ip}")
            pipe.delete(f"rate:{ip}")
            pipe.delete(f"ban:offense_count:{ip}")
        pipe.execute()
    except Exception as e:
        print(f"[!] Eroare cleanup Redis: {e}")

def main():
    print("=" * 78)
    print("  TEST ACURATETE MODULE INSPECTOR PE TRAFIC REAL (Zanbil.ir nginx)")
    print("=" * 78)
    print(f"  Sursa:     {os.path.basename(LOG_PATH)}")
    print(f"  Max linii: {MAX_LINES:,}")
    print(f"  Min cereri per IP: {MIN_REQUESTS_PER_IP}")
    print("=" * 78)

    if not os.path.exists(LOG_PATH):
        print(f"[x] Nu gasesc access.log la {LOG_PATH}")
        sys.exit(1)

    hostnames = load_hostnames(HOSTNAME_CSV)

    print(f"\n[*] Parsare log (primele {MAX_LINES:,} linii)...")
    events_by_ip: Dict[str, List[Dict]] = defaultdict(list)
    ua_by_ip: Dict[str, str] = {}
    parsed_count = 0
    skipped = 0
    t_start = time.perf_counter()
    with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            if i >= MAX_LINES:
                break
            parsed = parse_line(line)
            if parsed is None:
                skipped += 1
                continue
            ip = parsed["ip"]
            events_by_ip[ip].append(parsed)
            if ip not in ua_by_ip:
                ua_by_ip[ip] = parsed["ua"]
            parsed_count += 1
    t_parse = time.perf_counter() - t_start
    print(f"    {parsed_count:,} linii parsate, {skipped:,} skip-uite "
          f"({t_parse:.1f}s)")
    print(f"    {len(events_by_ip):,} IP-uri unice")

    eligible_ips = {ip: evs for ip, evs in events_by_ip.items()
                    if len(evs) >= MIN_REQUESTS_PER_IP}
    print(f"    {len(eligible_ips):,} IP-uri cu >= {MIN_REQUESTS_PER_IP} cereri")

    print(f"\n[*] Etichetare IP-uri pe baza UA + hostname...")
    labels: Dict[str, str] = {}
    for ip in eligible_ips:
        labels[ip] = label_ip(ua_by_ip[ip], hostnames.get(ip))
    label_counts = defaultdict(int)
    for lab in labels.values():
        label_counts[lab] += 1
    print(f"    bot_known: {label_counts['bot_known']:,}")
    print(f"    human:     {label_counts['human']:,}")
    print(f"    unknown:   {label_counts['unknown']:,}")

    print(f"\n[*] Reset state inspector + Redis...")
    reset_state()
    clear_redis_bans(list(eligible_ips.keys()))

    print(f"\n[*] Alimentare modulelor (ordine cronologica)...")
    all_events = []
    for ip, evs in eligible_ips.items():
        all_events.extend(evs)
    all_events.sort(key=lambda e: e["ts"])

    bans_by_module: Dict[str, set] = defaultdict(set)

    original_ban = ban_module.ban_ip

    def captured_ban(ip, seconds, reason=""):
        module = "unknown"
        if reason.startswith("rate>"):
            module = "M1_volume"
        elif reason.startswith("freq"):
            module = "M2_frequency"
        elif reason.startswith("seq") or "Markov" in reason:
            module = "M3_sequential"
        elif reason.startswith("fp_") or "fingerprint" in reason or "header" in reason:
            module = "M4_fingerprint"
        elif "funnel" in reason:
            module = "M5_funnel"
        elif reason.startswith("botnet:"):
            module = "M6_botnet"
        bans_by_module[module].add(ip)
        return original_ban(ip, seconds, reason=reason)

    ban_module.ban_ip = captured_ban
    m1_volume.ban_ip = captured_ban
    m2_frequency.ban_ip = captured_ban
    m3_sequential.ban_ip = captured_ban
    m4_fingerprint.ban_ip = captured_ban
    m5_funnel.ban_ip = captured_ban
    m6_botnet.ban_ip = captured_ban

    import modules.m4_fingerprint as m4_mod
    original_check_fp = m4_mod.check_fingerprint
    m4_mod.check_fingerprint = lambda ip, evt: False
    import modules
    if hasattr(modules, "check_fingerprint"):
        modules.check_fingerprint = lambda ip, evt: False
    if hasattr(inspector, "check_fingerprint"):
        inspector.check_fingerprint = lambda ip, evt: False

    t_start = time.perf_counter()
    processed = 0
    for evt in all_events:
        try:
            inspector.handle_event(evt)
            processed += 1
        except Exception:
            pass
    t_total = time.perf_counter() - t_start

    m4_mod.check_fingerprint = original_check_fp
    if hasattr(modules, "check_fingerprint"):
        modules.check_fingerprint = original_check_fp
    if hasattr(inspector, "check_fingerprint"):
        inspector.check_fingerprint = original_check_fp

    ban_module.ban_ip = original_ban
    m1_volume.ban_ip = original_ban
    m2_frequency.ban_ip = original_ban
    m3_sequential.ban_ip = original_ban
    m4_fingerprint.ban_ip = original_ban
    m5_funnel.ban_ip = original_ban
    m6_botnet.ban_ip = original_ban

    print(f"    {processed:,} evenimente procesate in {t_total:.1f}s "
          f"({processed/t_total:,.0f} evt/s)")

    print(f"\n[*] Calcul metrici per modul...")
    results = {}
    for module in ["M1_volume", "M2_frequency", "M3_sequential",
                   "M4_fingerprint", "M5_funnel", "M6_botnet"]:
        banned = bans_by_module.get(module, set())
        banned_eligible = banned & set(eligible_ips.keys())

        tp = sum(1 for ip in banned_eligible if labels.get(ip) == "bot_known")
        fp = sum(1 for ip in banned_eligible if labels.get(ip) == "human")
        fn = sum(1 for ip, lab in labels.items()
                 if lab == "bot_known" and ip not in banned_eligible)
        tn = sum(1 for ip, lab in labels.items()
                 if lab == "human" and ip not in banned_eligible)
        unknown_banned = sum(1 for ip in banned_eligible
                             if labels.get(ip) == "unknown")

        total_bots = label_counts["bot_known"]
        total_humans = label_counts["human"]
        detection_pct = (tp / total_bots * 100) if total_bots > 0 else 0
        fp_pct = (fp / total_humans * 100) if total_humans > 0 else 0
        precision_pct = (tp / (tp + fp) * 100) if (tp + fp) > 0 else 0

        results[module] = {
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "unknown_banned": unknown_banned,
            "detection_pct": round(detection_pct, 2),
            "false_positive_pct": round(fp_pct, 2),
            "precision_pct": round(precision_pct, 2),
            "total_banned": len(banned_eligible),
        }

    print()
    print("=" * 96)
    print(f"  {'MODUL':<16} {'TP':>5} {'FP':>5} {'FN':>5} {'?BAN':>6} "
          f"{'DETECT%':>9} {'FP%':>7} {'PREC%':>8}")
    print("-" * 96)
    for module, m in results.items():
        print(f"  {module:<16} {m['tp']:>5} {m['fp']:>5} {m['fn']:>5} "
              f"{m['unknown_banned']:>6} {m['detection_pct']:>8.2f}% "
              f"{m['false_positive_pct']:>6.2f}% {m['precision_pct']:>7.2f}%")
    print("=" * 96)

    all_banned = set()
    for s in bans_by_module.values():
        all_banned |= s
    all_banned_eligible = all_banned & set(eligible_ips.keys())
    global_tp = sum(1 for ip in all_banned_eligible if labels.get(ip) == "bot_known")
    global_fp = sum(1 for ip in all_banned_eligible if labels.get(ip) == "human")
    global_unknown = sum(1 for ip in all_banned_eligible if labels.get(ip) == "unknown")
    global_detection = (global_tp / label_counts["bot_known"] * 100) \
        if label_counts["bot_known"] > 0 else 0
    global_fp_pct = (global_fp / label_counts["human"] * 100) \
        if label_counts["human"] > 0 else 0

    print(f"\nGLOBAL (cel putin un modul):")
    print(f"  Detectie totala: {global_tp}/{label_counts['bot_known']} "
          f"= {global_detection:.2f}%")
    print(f"  Fals-pozitive:   {global_fp}/{label_counts['human']} "
          f"= {global_fp_pct:.2f}%")
    print(f"  Unknown banati:  {global_unknown}")

    os.makedirs(os.path.dirname(OUT_JSON), exist_ok=True)
    out = {
        "config": {
            "max_lines": MAX_LINES,
            "min_requests_per_ip": MIN_REQUESTS_PER_IP,
            "log_path": LOG_PATH,
            "parsed_lines": parsed_count,
        },
        "summary": {
            "total_eligible_ips": len(eligible_ips),
            "label_counts": dict(label_counts),
            "processing_time_s": round(t_total, 2),
            "events_per_sec": round(processed/t_total, 1) if t_total > 0 else 0,
        },
        "per_module": results,
        "global": {
            "tp": global_tp,
            "fp": global_fp,
            "unknown_banned": global_unknown,
            "detection_pct": round(global_detection, 2),
            "false_positive_pct": round(global_fp_pct, 2),
        },
    }
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\n[+] Rezultate complete: {OUT_JSON}")

if __name__ == "__main__":
    main()
