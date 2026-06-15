"""Test de latenta sub trafic concurent: degradarea sub mai multi clienti simultani."""
import os
import sys
import io
import json
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from statistics import mean

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

BASE_URL = os.environ.get("BASE_URL", "http://localhost:8080")
N_REQUESTS_PER_LEVEL = int(os.environ.get("N_REQUESTS", "200"))
CONCURRENCY_LEVELS = [1, 4, 16, 64]
WARMUP = 20

OUT_FILE = os.path.join(os.path.dirname(__file__), "data", "latency_concurrent.json")

def percentile(data, p):
    s = sorted(data)
    if not s:
        return 0.0
    k = (len(s) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)

def time_request(ip_synthetic: str) -> tuple:
    """Trimite GET / cu X-Forwarded-For sintetic si returneaza (latenta_ms, status)."""
    req = urllib.request.Request(
        f"{BASE_URL}/",
        headers={"X-Forwarded-For": ip_synthetic, "User-Agent": "stress-test/1.0"},
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            resp.read()
            return (time.perf_counter() - t0) * 1000, resp.status
    except urllib.error.HTTPError as e:
        try:
            e.read()
        except Exception:
            pass
        return (time.perf_counter() - t0) * 1000, e.code
    except Exception:
        return (time.perf_counter() - t0) * 1000, -1

def warmup():
    """Cateva cereri pentru a incalzi conexiunile."""
    print(f"[*] Warmup: {WARMUP} cereri...")
    for i in range(WARMUP):
        time_request(f"10.99.0.{i % 254 + 1}")

def run_level(concurrency: int, total_requests: int) -> dict:
    """Ruleaza N cereri folosind un pool de thread-uri."""
    print(f"\n[*] Nivel concurenta: {concurrency} (total cereri: {total_requests})")

    latencies = []
    statuses = []
    ip_counter = 0

    t_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = []
        for i in range(total_requests):
            ip_counter += 1
            octet3 = (ip_counter // 254) + 1
            octet4 = (ip_counter % 254) + 1
            ip = f"10.100.{octet3}.{octet4}"
            futures.append(executor.submit(time_request, ip))

        for f in as_completed(futures):
            elapsed, status = f.result()
            latencies.append(elapsed)
            statuses.append(status)
    t_total = time.perf_counter() - t_start

    if not latencies:
        return {"concurrency": concurrency, "n": 0}

    return {
        "concurrency": concurrency,
        "n": len(latencies),
        "mean_ms": round(mean(latencies), 2),
        "p50_ms": round(percentile(latencies, 50), 2),
        "p95_ms": round(percentile(latencies, 95), 2),
        "p99_ms": round(percentile(latencies, 99), 2),
        "min_ms": round(min(latencies), 2),
        "max_ms": round(max(latencies), 2),
        "total_time_s": round(t_total, 3),
        "throughput_rps": round(len(latencies) / t_total, 1),
        "status_distribution": dict(
            (s, statuses.count(s)) for s in set(statuses)
        ),
    }

def main():
    print("=" * 72)
    print("  TEST LATENTA SUB TRAFIC CONCURENT")
    print("=" * 72)
    print(f"  Server:           {BASE_URL}")
    print(f"  Cereri / nivel:   {N_REQUESTS_PER_LEVEL}")
    print(f"  Niveluri:         {CONCURRENCY_LEVELS}")
    print("=" * 72)

    try:
        with urllib.request.urlopen(f"{BASE_URL}/", timeout=3) as r:
            r.read()
    except Exception as e:
        print(f"[x] Serverul nu raspunde la {BASE_URL}: {e}")
        sys.exit(1)

    warmup()

    results = []
    for c in CONCURRENCY_LEVELS:
        results.append(run_level(c, N_REQUESTS_PER_LEVEL))

    print()
    print("=" * 96)
    print(f"  {'CONC':>5} {'N':>5} {'MEAN':>10} {'P50':>10} {'P95':>10} "
          f"{'P99':>10} {'MAX':>10} {'RPS':>10}")
    print("-" * 96)
    for r in results:
        if r.get("n", 0) == 0:
            continue
        print(f"  {r['concurrency']:>5} {r['n']:>5} "
              f"{r['mean_ms']:>9.2f}ms {r['p50_ms']:>9.2f}ms "
              f"{r['p95_ms']:>9.2f}ms {r['p99_ms']:>9.2f}ms "
              f"{r['max_ms']:>9.2f}ms {r['throughput_rps']:>9.1f}")
    print("=" * 96)

    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)
    out = {
        "base_url": BASE_URL,
        "n_requests_per_level": N_REQUESTS_PER_LEVEL,
        "concurrency_levels": CONCURRENCY_LEVELS,
        "results": results,
    }
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    print(f"\n[+] Rezultate complete: {OUT_FILE}")

if __name__ == "__main__":
    main()
