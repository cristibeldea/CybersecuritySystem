"""
Test de latenta pe traseul critic al sistemului WebToxin.

Cerinta din lucrare (sectiunea 3.1, cerinte nefunctionale):
  > Latenta redusa: decizia de blocare sau autorizare sa se ia
  > intr-un interval care nu degradeaza experienta utilizatorilor
  > legitimi (sub 100 ms per cerere pe traseul critic).

Testul masoara end-to-end (client) timpul de raspuns pentru fiecare
dintre cele patru scenarii reprezentative ale traseului critic, raporteaza
distributia (mean, p50, p95, p99, max) si verifica pragul.

Scenarii:
  S1. GET /captcha pe IP nou
      - cazul cel mai costisitor: rendering template + creare sesiune CAPTCHA
      - trebuie sa stea sub 100 ms

  S2. POST /captcha/verify cu payload de tip "hold-to-verify"
      - cazul cu logica intensa: parsare JSON, calcul scor risc, scriere stare
      - trebuie sa stea sub 100 ms

  S3. GET / pe IP banat
      - traseul scurt-circuit: verificare BANNED_PREFIX in Redis si returnare 429
      - trebuie sa stea CONSIDERABIL sub 100 ms (target informal: < 20 ms)

  S4. GET / pe IP normal (nebanat, fara token CAPTCHA)
      - cazul baseline: verificare ban + redirect catre /captcha
      - trebuie sa stea sub 100 ms

Iesire:
  - tabel sumar in consola
  - JSON cu rezultatele complete in demos/data/latency_critical_path.json
"""
import asyncio, sys, io, os, json, base64, time, math
import urllib.request, urllib.parse, urllib.error
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

BASE_URL    = os.environ.get("BASE_URL", "http://localhost:8080")
ADMIN_USER  = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS  = os.environ.get("ADMIN_PASS", "admin")
N_SAMPLES   = int(os.environ.get("N_SAMPLES", "200"))
WARMUP      = int(os.environ.get("WARMUP", "20"))
TARGET_MS   = float(os.environ.get("TARGET_MS", "100"))

OUT_FILE    = os.path.join(os.path.dirname(__file__), "data", "latency_critical_path.json")

# IP-uri sintetice pentru cele 4 scenarii (X-Forwarded-For)
IP_S1 = "10.55.0.1"   # IP nou pentru S1
IP_S2 = "10.55.0.2"   # IP pentru flow CAPTCHA (S2)
IP_S3 = "10.55.0.3"   # IP banat pentru S3
IP_S4 = "10.55.0.4"   # IP nebanat pentru S4

# -- colors --
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[96m"
W = "\033[97m"; M = "\033[95m"; BD = "\033[1m"; RS = "\033[0m"


def hdr(t):  print(f"\n{B}{BD}{'='*72}{RS}\n{B}{BD}  {t}{RS}\n{B}{BD}{'='*72}{RS}")
def sep():   print(f"{B}{BD}{'-'*72}{RS}")
def ok(t):   print(f"{G}{BD}[+]{RS} {t}")
def err(t):  print(f"{R}{BD}[x]{RS} {t}")
def info(t): print(f"{B}{BD}[~]{RS} {t}")
def step(t): print(f"{W}{BD}[->]{RS} {t}")
def warn(t): print(f"{Y}{BD}[!]{RS} {t}")


# ---------- admin helpers ----------
def _basic_auth() -> str:
    raw = f"{ADMIN_USER}:{ADMIN_PASS}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")


def admin_post(path: str, payload: dict) -> dict:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{BASE_URL}{path}", data=data, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": _basic_auth()})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return {"error": f"HTTP {e.code}: {body[:200]}"}
    except Exception as e:
        return {"error": str(e)}


def admin_ban(ip: str, duration: int = 600):
    return admin_post("/admin/api/ban", {"ip": ip, "duration": duration,
                                          "reason": "latency-test-setup"})

def admin_unban(ip: str):
    return admin_post("/admin/api/unban", {"ip": ip})

def admin_reset_offense(ip: str):
    return admin_post("/admin/api/reset-offense", {"ip": ip})


# ---------- timing helper ----------
def time_request(method: str, path: str, *,
                 ip: str, body: dict = None,
                 cookies: dict = None) -> tuple:
    """Returns (elapsed_ms, status_code). Times only the request itself."""
    headers = {"X-Forwarded-For": ip}
    if cookies:
        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(f"{BASE_URL}{path}", data=data,
                                  method=method, headers=headers)
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            _ = resp.read()
            elapsed_ms = (time.perf_counter() - t0) * 1000
            return elapsed_ms, resp.status
    except urllib.error.HTTPError as e:
        elapsed_ms = (time.perf_counter() - t0) * 1000
        try: e.read()
        except Exception: pass
        return elapsed_ms, e.code


# ---------- statistics ----------
def percentile(data, p):
    s = sorted(data)
    if not s: return 0.0
    k = (len(s) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def fmt_ms(v: float) -> str:
    return f"{v:6.2f}ms"


def color_for(value: float, target: float) -> str:
    if value < target * 0.5:
        return G   # confortabil sub prag
    if value < target * 0.85:
        return Y   # apropiere
    return R       # in zona de risc sau peste


def summarize(name: str, samples: list, target: float) -> dict:
    if not samples:
        return {"name": name, "n": 0}
    samples_sorted = sorted(samples)
    mean = sum(samples) / len(samples)
    p50  = percentile(samples, 50)
    p95  = percentile(samples, 95)
    p99  = percentile(samples, 99)
    mn   = samples_sorted[0]
    mx   = samples_sorted[-1]
    over_target = sum(1 for x in samples if x >= target)
    pct_over    = 100 * over_target / len(samples)
    return {
        "name": name, "n": len(samples), "target_ms": target,
        "mean_ms": round(mean, 3), "median_ms": round(p50, 3),
        "p95_ms": round(p95, 3),   "p99_ms": round(p99, 3),
        "min_ms": round(mn, 3),    "max_ms": round(mx, 3),
        "over_target_n": over_target, "over_target_pct": round(pct_over, 2),
    }


# ---------- scenario runners ----------
def run_scenario_S1():
    """S1 — GET /captcha pe IP nou (rendering + creare sesiune)."""
    info(f"S1: GET /captcha pe IP={IP_S1}  (N={N_SAMPLES}, warmup={WARMUP})")
    admin_unban(IP_S1)
    # Warmup
    for _ in range(WARMUP):
        time_request("GET", "/captcha", ip=IP_S1)
    # Masurare
    samples = []
    statuses = []
    for _ in range(N_SAMPLES):
        elapsed, status = time_request("GET", "/captcha", ip=IP_S1)
        if status in (200, 302):
            samples.append(elapsed)
        statuses.append(status)
    ok(f"   {len(samples)}/{N_SAMPLES} cereri inregistrate (statusuri: {set(statuses)})")
    return samples


def run_scenario_S2():
    """S2 — POST /captcha/verify cu payload de tip 'hold-to-verify'."""
    info(f"S2: POST /captcha/verify pe IP={IP_S2}  (N={N_SAMPLES}, warmup={WARMUP})")
    admin_unban(IP_S2)
    admin_reset_offense(IP_S2)

    # Obtinem un sid valid prin GET /captcha (cookie captcha_sid)
    try:
        req = urllib.request.Request(f"{BASE_URL}/captcha",
                                      headers={"X-Forwarded-For": IP_S2})
        with urllib.request.urlopen(req, timeout=5) as resp:
            set_cookie = resp.headers.get_all("Set-Cookie") or []
        sid = None
        for c in set_cookie:
            if c.startswith("captcha_sid="):
                sid = c.split(";", 1)[0].split("=", 1)[1]
                break
        if not sid:
            err("   nu am putut obtine captcha_sid; sar peste S2")
            return []
    except Exception as e:
        err(f"   eroare obtinere sid: {e}")
        return []

    # Payload reprezentativ pentru hold-to-verify (esuat — ramane pe checkbox)
    payload = {
        "duration_ms": 1100,
        "had_pointer": True,
        "points": [{"t": i * 12, "x": 100 + i * 4, "y": 200} for i in range(100)],
        "clicks": [{"t": 1080, "x": 500, "y": 200}],
        "keydowns": [],
        "focus": [],
        "tile_hovers": {},
        "hp": False,
        "env": {"ua": "test"},
    }
    cookies = {"captcha_sid": sid}

    # Warmup
    for _ in range(WARMUP):
        time_request("POST", "/captcha/verify", ip=IP_S2,
                     body=payload, cookies=cookies)
    # Masurare
    samples = []
    statuses = []
    for _ in range(N_SAMPLES):
        elapsed, status = time_request("POST", "/captcha/verify", ip=IP_S2,
                                        body=payload, cookies=cookies)
        if status in (200, 429):
            samples.append(elapsed)
        statuses.append(status)
        # In caz ca s-a aplicat un ban progresiv dupa cateva esecuri,
        # resetam ca sa continuam masuratoarea.
        if status == 429:
            admin_unban(IP_S2)
            admin_reset_offense(IP_S2)
    ok(f"   {len(samples)}/{N_SAMPLES} cereri inregistrate (statusuri: {set(statuses)})")
    return samples


def run_scenario_S3():
    """S3 — GET / pe IP banat (scurt-circuit, traseul cel mai rapid)."""
    info(f"S3: GET / pe IP BANAT={IP_S3}  (N={N_SAMPLES}, warmup={WARMUP})")
    # Asiguram ca IP-ul e banat
    admin_reset_offense(IP_S3)
    admin_ban(IP_S3, duration=600)
    # Warmup
    for _ in range(WARMUP):
        time_request("GET", "/", ip=IP_S3)
    # Masurare
    samples = []
    statuses = []
    for _ in range(N_SAMPLES):
        elapsed, status = time_request("GET", "/", ip=IP_S3)
        # 429 = ban return, 403 = honeypot trap — ambele sunt scurt-circuit valid
        if status in (429, 403):
            samples.append(elapsed)
        statuses.append(status)
    ok(f"   {len(samples)}/{N_SAMPLES} cereri inregistrate (statusuri: {set(statuses)})")
    return samples


def run_scenario_S4():
    """S4 — GET / pe IP normal (nebanat, fara token CAPTCHA → redirect)."""
    info(f"S4: GET / pe IP NORMAL={IP_S4}  (N={N_SAMPLES}, warmup={WARMUP})")
    admin_unban(IP_S4)
    # Warmup
    for _ in range(WARMUP):
        time_request("GET", "/", ip=IP_S4)
    # Masurare
    samples = []
    statuses = []
    for _ in range(N_SAMPLES):
        elapsed, status = time_request("GET", "/", ip=IP_S4)
        # 200/302/403 = toate sunt raspunsuri valide ale traseului critic
        if status in (200, 302, 403):
            samples.append(elapsed)
        statuses.append(status)
    ok(f"   {len(samples)}/{N_SAMPLES} cereri inregistrate (statusuri: {set(statuses)})")
    return samples


# ---------- main ----------
def main():
    hdr(f"TEST LATENTA — TRASEU CRITIC  (target: < {TARGET_MS:.0f} ms)")
    info(f"Server: {BD}{BASE_URL}{RS}")
    info(f"Iesire: {BD}{OUT_FILE}{RS}\n")

    # Sanity check
    try:
        with urllib.request.urlopen(f"{BASE_URL}/", timeout=3) as r:
            pass
    except Exception as e:
        err(f"Serverul nu raspunde la {BASE_URL}: {e}")
        sys.exit(1)

    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)

    results = {}
    samples_by_scenario = {}

    sep()
    samples_by_scenario["S1"] = run_scenario_S1()
    sep()
    samples_by_scenario["S2"] = run_scenario_S2()
    sep()
    samples_by_scenario["S3"] = run_scenario_S3()
    sep()
    samples_by_scenario["S4"] = run_scenario_S4()
    sep()

    # Sumar
    results["S1"] = summarize("GET /captcha (IP nou)",       samples_by_scenario["S1"], TARGET_MS)
    results["S2"] = summarize("POST /captcha/verify",         samples_by_scenario["S2"], TARGET_MS)
    results["S3"] = summarize("GET / (IP banat, 403/429)",    samples_by_scenario["S3"], TARGET_MS / 2)  # 50ms — strict, dar realist
    results["S4"] = summarize("GET / (IP normal, redirect)",  samples_by_scenario["S4"], TARGET_MS)

    # Print tabel
    print(f"\n{BD}{'SCENARIU':<32} {'N':>4} {'MEAN':>10} {'p50':>10} "
          f"{'p95':>10} {'p99':>10} {'MAX':>10} {'>= tinta':>10}{RS}")
    print("-" * 100)
    for k in ("S1", "S2", "S3", "S4"):
        r = results[k]
        if r.get("n", 0) == 0:
            print(f"{k} {r['name']:<29} (date insuficiente)")
            continue
        c = color_for(r["p95_ms"], r["target_ms"])
        print(f"{c}{k} {r['name']:<29} {r['n']:>4} "
              f"{fmt_ms(r['mean_ms']):>10} {fmt_ms(r['median_ms']):>10} "
              f"{fmt_ms(r['p95_ms']):>10} {fmt_ms(r['p99_ms']):>10} "
              f"{fmt_ms(r['max_ms']):>10} {r['over_target_pct']:>9.1f}%{RS}")
    print("-" * 100)

    # Verdict
    print()
    info(f"{BD}VERDICT:{RS}")
    all_pass = True
    for k in ("S1", "S2", "S3", "S4"):
        r = results[k]
        if r.get("n", 0) == 0:
            warn(f"  {k}: date insuficiente")
            all_pass = False
            continue
        target = r["target_ms"]
        if r["p95_ms"] < target and r["over_target_pct"] < 1.0:
            ok(f"  {k}: p95 = {r['p95_ms']:.2f}ms < {target:.0f}ms tinta "
               f"|  {r['over_target_pct']:.1f}% cereri peste tinta  →  {G}TRECUT{RS}")
        elif r["p95_ms"] < target:
            warn(f"  {k}: p95 = {r['p95_ms']:.2f}ms sub tinta, dar "
                 f"{r['over_target_pct']:.1f}% cereri ocazionale peste  →  {Y}MARGINAL{RS}")
            all_pass = False
        else:
            err(f"  {k}: p95 = {r['p95_ms']:.2f}ms >= tinta {target:.0f}ms  →  {R}ESEC{RS}")
            all_pass = False

    print()
    if all_pass:
        ok(f"{BD}Toate scenariile respecta cerinta de latenta sub {TARGET_MS:.0f} ms"
           f" (p95).{RS}")
    else:
        warn(f"{BD}Cel putin un scenariu nu satisface cerinta integral."
             f" Vezi tabelul.{RS}")

    # Save JSON
    full = {
        "target_ms": TARGET_MS, "n_samples": N_SAMPLES, "warmup": WARMUP,
        "base_url": BASE_URL, "scenarios": results,
        "raw_samples": samples_by_scenario,
    }
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        json.dump(full, f, ensure_ascii=False, indent=2)
    ok(f"\nRezultatele complete salvate in: {OUT_FILE}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{R}[!] Intrerupt de utilizator.{RS}")
