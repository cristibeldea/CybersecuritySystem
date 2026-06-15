"""Test de throughput: cate evenimente proceseaza inspectorul inainte sa piarda mesaje."""
import os
import sys
import io
import json
import time
import redis

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", "6379"))
PUBSUB_CHANNEL = "requests_channel"
BAN_PREFIX = "ban:"
RATE_PREFIX = "rate:"

LOAD_LEVELS = [
    (10, 25),
    (50, 25),
    (100, 25),
    (200, 25),
]

SETTLE_SECONDS = 3.0

OUT_FILE = os.path.join(os.path.dirname(__file__), "data", "inspector_throughput.json")

def make_event(ip: str, ts: int, seq: int) -> str:
    """Construieste un eveniment in formatul asteptat de inspector."""
    evt = {
        "ip": ip,
        "ts": ts,
        "path": f"/article/{seq}",
        "method": "GET",
        "kind": "page",
        "ua": "Mozilla/5.0 stress-test",
        "al": "en-US",
        "ae": "gzip, deflate",
        "acc": "text/html",
        "ref": "",
        "hdr_order": "ua,al,ae,acc",
        "cookie_present": False,
        "username": "anonymous",
    }
    return json.dumps(evt, separators=(",", ":"))

def cleanup_state(r: redis.Redis, ips: list):
    """Sterge ban-urile si seturile ZSET pentru IP-urile testate."""
    pipe = r.pipeline()
    for ip in ips:
        pipe.delete(f"{BAN_PREFIX}{ip}")
        pipe.delete(f"{RATE_PREFIX}{ip}")
        pipe.delete(f"ban:offense_count:{ip}")
    pipe.execute()

def run_level(r: redis.Redis, num_ips: int, events_per_ip: int) -> dict:
    """Trimite num_ips * events_per_ip evenimente pe canal si verifica procesarea."""
    total = num_ips * events_per_ip
    print(f"\n[*] Nivel: {num_ips} IP-uri x {events_per_ip} evenimente "
          f"= {total} mesaje")

    ips = []
    for i in range(num_ips):
        octet3 = (i // 254) + 1
        octet4 = (i % 254) + 1
        ips.append(f"10.200.{octet3}.{octet4}")

    cleanup_state(r, ips)
    time.sleep(0.2)

    ts = int(time.time())
    pipe = r.pipeline(transaction=False)
    t_pub_start = time.perf_counter()
    for ip in ips:
        for seq in range(events_per_ip):
            evt = make_event(ip, ts, seq)
            pipe.publish(PUBSUB_CHANNEL, evt)
    pipe.execute()
    t_pub_total = time.perf_counter() - t_pub_start

    pub_rate = total / t_pub_total

    print(f"    Publicare: {total} mesaje in {t_pub_total*1000:.1f} ms "
          f"({pub_rate:,.0f} msg/s)")

    time.sleep(SETTLE_SECONDS)

    banned_count = 0
    for ip in ips:
        if r.exists(f"{BAN_PREFIX}{ip}"):
            banned_count += 1

    ban_rate_pct = 100 * banned_count / num_ips
    print(f"    Procesare: {banned_count}/{num_ips} IP-uri banate "
          f"({ban_rate_pct:.1f}%)")

    cleanup_state(r, ips)

    return {
        "num_ips": num_ips,
        "events_per_ip": events_per_ip,
        "total_events": total,
        "publish_time_ms": round(t_pub_total * 1000, 2),
        "publish_rate_msgps": round(pub_rate, 1),
        "ips_banned": banned_count,
        "ban_completion_pct": round(ban_rate_pct, 1),
        "settle_seconds": SETTLE_SECONDS,
    }

def main():
    print("=" * 72)
    print("  TEST THROUGHPUT INSPECTOR")
    print("=" * 72)
    print(f"  Redis:            {REDIS_HOST}:{REDIS_PORT}")
    print(f"  Canal:            {PUBSUB_CHANNEL}")
    print(f"  Niveluri:         {LOAD_LEVELS}")
    print(f"  Asteptare/nivel:  {SETTLE_SECONDS}s")
    print("=" * 72)

    try:
        r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
        r.ping()
    except Exception as e:
        print(f"[x] Nu pot conecta la Redis: {e}")
        sys.exit(1)

    subs = r.pubsub_numsub(PUBSUB_CHANNEL)
    if subs and subs[0][1] == 0:
        print(f"[!] Niciun abonat pe canalul {PUBSUB_CHANNEL}. "
              f"Asigura-te ca inspectorul ruleaza.")
        sys.exit(1)
    else:
        print(f"[+] Abonati pe canal: {subs[0][1] if subs else 'unknown'}")

    results = []
    for num_ips, events_per_ip in LOAD_LEVELS:
        results.append(run_level(r, num_ips, events_per_ip))

    print()
    print("=" * 100)
    print(f"  {'IPs':>5} {'EVS/IP':>7} {'TOTAL':>6} "
          f"{'PUB(ms)':>10} {'PUB(msg/s)':>12} {'BANATI':>10} {'PROCESAT%':>12}")
    print("-" * 100)
    for r_ in results:
        print(f"  {r_['num_ips']:>5} {r_['events_per_ip']:>7} "
              f"{r_['total_events']:>6} {r_['publish_time_ms']:>9.1f} "
              f"{r_['publish_rate_msgps']:>11,.0f} "
              f"{r_['ips_banned']:>9}/{r_['num_ips']} "
              f"{r_['ban_completion_pct']:>10.1f}%")
    print("=" * 100)

    print()
    print("[+] VERDICT:")
    for r_ in results:
        if r_["ban_completion_pct"] >= 95.0:
            print(f"  {r_['num_ips']} IP-uri: inspectorul a tinut pasul "
                  f"({r_['ban_completion_pct']:.1f}% procesate)")
        elif r_["ban_completion_pct"] >= 50.0:
            print(f"  {r_['num_ips']} IP-uri: degradare partiala "
                  f"({r_['ban_completion_pct']:.1f}% procesate)")
        else:
            print(f"  {r_['num_ips']} IP-uri: pierderi semnificative "
                  f"({r_['ban_completion_pct']:.1f}% procesate)")

    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    out = {
        "redis_host": REDIS_HOST,
        "redis_port": REDIS_PORT,
        "channel": PUBSUB_CHANNEL,
        "settle_seconds": SETTLE_SECONDS,
        "results": results,
    }
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\n[+] Rezultate complete: {OUT_FILE}")

if __name__ == "__main__":
    main()
