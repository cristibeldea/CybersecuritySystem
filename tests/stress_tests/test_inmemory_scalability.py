"""Test de scalabilitate a structurilor in-memory ale inspectorului."""
import os
import sys
import io
import json
import time
import tracemalloc

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

PROJECT_ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", ".."))
INSPECTOR_DIR = os.path.join(PROJECT_ROOT, "request_inspector")
sys.path.insert(0, INSPECTOR_DIR)

import inspector  # noqa: E402

LOAD_LEVELS = [
    (1000, 10),
    (5000, 50),
    (10000, 100),
    (25000, 250),
]

OUT_FILE = os.path.join(os.path.dirname(__file__), "data", "inmemory_scalability.json")

def reset_inspector_state():
    """Sterge toate structurile in-memory ale inspectorului."""
    inspector.ip_history.clear()
    inspector.fp_to_ips.clear()
    inspector.ip_header_stats.clear()
    inspector.ip_first_seen.clear()
    inspector.global_timeline.clear()
    inspector.ip_interval_sig.clear()

def clear_redis_state(ips: list):
    """Sterge ban-urile si seturile rate pentru IP-urile testate."""
    try:
        for ip in ips:
            inspector.r.delete(f"ban:{ip}")
            inspector.r.delete(f"rate:{ip}")
            inspector.r.delete(f"ban:offense_count:{ip}")
    except Exception as e:
        print(f"[!] Eroare la cleanup Redis: {e}")

def make_event(ip: str, ts: int, seq: int) -> dict:
    """Construieste un eveniment sintetic."""
    paths = ["/", "/article/1", "/article/2", "/about", "/contact"]
    last_octet = ip.rsplit(".", 1)[-1]
    ua_variant = f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.{last_octet}"
    al_variants = ["en-US,en;q=0.9", "en-GB,en;q=0.9", "ro-RO,ro;q=0.9"]
    al = al_variants[int(last_octet) % len(al_variants)]
    return {
        "ip": ip,
        "ts": ts,
        "path": paths[seq % len(paths)],
        "method": "GET",
        "kind": "page",
        "ua": ua_variant,
        "al": al,
        "ae": "gzip, deflate, br",
        "acc": "text/html",
        "ref": "",
        "hdr_order": "ua,al,ae,acc",
        "cookie_present": True,
        "username": "anonymous",
    }

def run_level(num_events: int, num_ips: int) -> dict:
    """Ruleaza num_events evenimente distribuite peste num_ips si masoara."""
    print(f"\n[*] Nivel: {num_events:,} evenimente, {num_ips} IP-uri unice")

    ips = [f"10.150.{(i // 254) + 1}.{(i % 254) + 1}" for i in range(num_ips)]

    reset_inspector_state()
    clear_redis_state(ips)

    base_ts = int(time.time())
    events = []
    for i in range(num_events):
        ip = ips[i % num_ips]
        ip_seq = i // num_ips
        ts = base_ts + ip_seq // 2
        events.append(make_event(ip, ts, i))

    tracemalloc.start()
    t_start = time.perf_counter()
    for evt in events:
        try:
            inspector.handle_event(evt)
        except Exception as e:
            print(f"[!] Eroare la handle_event: {e}")
            continue
    t_total = time.perf_counter() - t_start
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    sizes = {
        "ip_history_keys": len(inspector.ip_history),
        "ip_history_total_entries": sum(len(v) for v in inspector.ip_history.values()),
        "fp_to_ips_keys": len(inspector.fp_to_ips),
        "ip_first_seen_keys": len(inspector.ip_first_seen),
        "global_timeline_size": len(inspector.global_timeline),
        "ip_header_stats_keys": len(inspector.ip_header_stats),
    }

    avg_us_per_event = (t_total / num_events) * 1_000_000
    throughput = num_events / t_total

    print(f"    Timp total:       {t_total*1000:,.1f} ms")
    print(f"    Per eveniment:    {avg_us_per_event:,.1f} us")
    print(f"    Throughput:       {throughput:,.0f} evenimente/s")
    print(f"    Memorie peak:     {peak/1024/1024:.2f} MB")
    print(f"    ip_history:       {sizes['ip_history_keys']} chei, "
          f"{sizes['ip_history_total_entries']} intrari")
    print(f"    global_timeline:  {sizes['global_timeline_size']} intrari")
    print(f"    fp_to_ips:        {sizes['fp_to_ips_keys']} amprente")

    clear_redis_state(ips)

    return {
        "num_events": num_events,
        "num_ips": num_ips,
        "total_time_s": round(t_total, 4),
        "total_time_ms": round(t_total * 1000, 2),
        "avg_us_per_event": round(avg_us_per_event, 2),
        "throughput_events_per_sec": round(throughput, 1),
        "memory_peak_bytes": peak,
        "memory_peak_mb": round(peak / 1024 / 1024, 3),
        "memory_current_bytes": current,
        "structure_sizes": sizes,
    }

def main():
    print("=" * 72)
    print("  TEST SCALABILITATE STRUCTURI IN-MEMORY")
    print("=" * 72)
    print(f"  Niveluri: {LOAD_LEVELS}")
    print("=" * 72)

    results = []
    for num_events, num_ips in LOAD_LEVELS:
        results.append(run_level(num_events, num_ips))

    print()
    print("=" * 100)
    print(f"  {'EVTS':>7} {'IPs':>5} {'TIMP(ms)':>10} {'us/ev':>8} "
          f"{'evts/s':>10} {'MEM(MB)':>10} {'TIMELINE':>10}")
    print("-" * 100)
    for r in results:
        print(f"  {r['num_events']:>7,} {r['num_ips']:>5} "
              f"{r['total_time_ms']:>9,.0f} "
              f"{r['avg_us_per_event']:>7,.0f} "
              f"{r['throughput_events_per_sec']:>9,.0f} "
              f"{r['memory_peak_mb']:>9.2f} "
              f"{r['structure_sizes']['global_timeline_size']:>9}")
    print("=" * 100)

    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    out = {
        "load_levels": LOAD_LEVELS,
        "results": results,
    }
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\n[+] Rezultate complete: {OUT_FILE}")

if __name__ == "__main__":
    main()
