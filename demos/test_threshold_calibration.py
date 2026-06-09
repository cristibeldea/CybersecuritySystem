"""
Test de calibrare a pragului R >= 78 pentru etapa hold-to-verify.

Genereaza traiectorii sintetice la 5 niveluri de sofisticare crescatoare,
calculeaza scorul de risc local (direct cu algoritmul din guard.py) si
raporteaza:
  - statistici per nivel (mean, std, min, max)
  - rata de detectie (% R >= 78)
  - recomandare de ajustare a pragului in caz de calibrare proasta.

Niveluri:
  L1. Perfect liniar             — bot naiv (mouse.move(x1,y1)->mouse.move(x2,y2))
  L2. Liniar + zgomot pozitional — bot cu jitter aleatoriu pe pozitie
  L3. Bezier curat (fara jitter) — bot mediu cu curba precalculata
  L4. Bezier + jitter            — bot sofisticat: curba + jitter pozitional + temporal
  L5. Cvasi-uman                 — Bezier multi-segment + overshoot + viteza variabila
"""
import sys, os, io, math, random, statistics
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

# Permite import-ul direct al guard.py
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "web"))
from captcha.guard import extract_features, compute_behavior_risk

# -- colors --
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[96m"
W = "\033[97m"; M = "\033[95m"; BD = "\033[1m"; RS = "\033[0m"

THRESHOLD     = 50   # ajustat dupa adaugarea Sigma-Lognormal + fix overshoot
N_SAMPLES     = 50        # cate traiectorii generam per nivel
TARGET_X      = 640       # pozitia tinta (butonul hold-to-verify)
TARGET_Y      = 360
START_X_BASE  = 340       # pozitia de start (~300px stanga de buton)
START_Y_BASE  = 360
N_POINTS      = 120       # numar de puncte de traiectorie
DURATION_MS   = 1500      # durata totala simulata


# ---------------------------------------------------------------------------
# Generatoare de traiectorii
# ---------------------------------------------------------------------------

def trajectory_linear(seed: int):
    """L1. Linie perfect dreapta. Curbura = 0, viteza constanta."""
    rng = random.Random(seed)
    sy = START_Y_BASE + rng.uniform(-2, 2)
    ey = TARGET_Y    + rng.uniform(-2, 2)
    pts = []
    for i in range(N_POINTS):
        t = i * DURATION_MS / (N_POINTS - 1)
        u = i / (N_POINTS - 1)
        x = START_X_BASE + (TARGET_X - START_X_BASE) * u
        y = sy + (ey - sy) * u
        pts.append({"t": t, "x": x, "y": y})
    return pts


def trajectory_linear_jitter(seed: int):
    """L2. Linie + zgomot pozitional uniform (+/-1.5 px)."""
    rng = random.Random(seed)
    base = trajectory_linear(seed)
    for p in base:
        p["x"] += rng.uniform(-1.5, 1.5)
        p["y"] += rng.uniform(-1.5, 1.5)
    return base


def _quadratic_bezier(p0, p1, p2, t):
    u = 1 - t
    return (u*u*p0[0] + 2*u*t*p1[0] + t*t*p2[0],
            u*u*p0[1] + 2*u*t*p1[1] + t*t*p2[1])


def trajectory_bezier_clean(seed: int):
    """L3. Bezier patratic cu un singur punct de control. Fara jitter."""
    rng = random.Random(seed)
    p0 = (START_X_BASE, START_Y_BASE)
    p2 = (TARGET_X, TARGET_Y)
    # Punct de control deasupra/sub mijloc, deviatie moderata
    midx = (p0[0] + p2[0]) / 2
    midy = (p0[1] + p2[1]) / 2
    p1 = (midx + rng.uniform(-30, 30), midy + rng.uniform(-80, 80))

    pts = []
    for i in range(N_POINTS):
        t = i * DURATION_MS / (N_POINTS - 1)
        u = i / (N_POINTS - 1)
        x, y = _quadratic_bezier(p0, p1, p2, u)
        pts.append({"t": t, "x": x, "y": y})
    return pts


def trajectory_bezier_jitter(seed: int):
    """L4. Bezier + jitter pozitional (+/-2 px) + jitter temporal (+/-3 ms).
    Reprezinta un bot relativ sofisticat care incearca sa para natural."""
    rng = random.Random(seed)
    base = trajectory_bezier_clean(seed)
    for p in base:
        p["x"] += rng.uniform(-2, 2)
        p["y"] += rng.uniform(-2, 2)
        p["t"] += rng.uniform(-3, 3)
    return base


def trajectory_human_like(seed: int):
    """L5. Traiectorie cvasi-umana:
    - Bezier in doua segmente (drum cu mici devieri)
    - Overshoot la sfarsit + revenire la tinta
    - Variatie de viteza prin sampling neuniform al parametrului t
    - Cateva mici reveniri ('tremur')
    """
    rng = random.Random(seed)
    p0 = (START_X_BASE + rng.uniform(-30, 30), START_Y_BASE + rng.uniform(-30, 30))
    pmid = (
        (p0[0] + TARGET_X) / 2 + rng.uniform(-40, 40),
        (p0[1] + TARGET_Y) / 2 + rng.uniform(-100, 100),
    )
    # Overshoot: trece de tinta cu 12-25 px, apoi revine
    overshoot_dx = rng.uniform(12, 25)
    overshoot_dy = rng.uniform(-10, 10)
    p_over = (TARGET_X + overshoot_dx, TARGET_Y + overshoot_dy)

    # Faza 1: Bezier de la p0 prin pmid pana la p_over (80% din puncte)
    n_phase1 = int(N_POINTS * 0.80)
    # Faza 2: revenire mica de la p_over la tinta exacta (20% din puncte)
    n_phase2 = N_POINTS - n_phase1

    pts = []
    accumulated_t = 0.0
    # Faza 1 — sampling neuniform (accelerare la inceput, decelerare la final)
    for i in range(n_phase1):
        u = i / (n_phase1 - 1)
        # Ease-in-out: u -> 3u^2 - 2u^3
        ue = 3 * u * u - 2 * u * u * u
        x, y = _quadratic_bezier(p0, pmid, p_over, ue)
        # Adauga mici reveniri (tremur)
        x += rng.uniform(-1.5, 1.5)
        y += rng.uniform(-1.5, 1.5)
        # Interval temporal variabil (5-18 ms intre puncte)
        accumulated_t += rng.uniform(5, 18)
        pts.append({"t": accumulated_t, "x": x, "y": y})

    # Faza 2 — revenire la tinta, mai lenta (overshoot correction)
    for i in range(n_phase2):
        u = (i + 1) / n_phase2
        x = p_over[0] + (TARGET_X - p_over[0]) * u
        y = p_over[1] + (TARGET_Y - p_over[1]) * u
        x += rng.uniform(-1, 1)
        y += rng.uniform(-1, 1)
        # Decelerare clara (intervale mai mari)
        accumulated_t += rng.uniform(15, 25)
        pts.append({"t": accumulated_t, "x": x, "y": y})

    return pts


# ---------------------------------------------------------------------------
# Payload + scor
# ---------------------------------------------------------------------------

def make_payload(points):
    """Construieste un payload identic ca format cu cel trimis de JS-ul paginii."""
    duration = points[-1]["t"] - points[0]["t"]
    return {
        "nonce": "test",
        "started_at_ms": points[0]["t"],
        "ended_at_ms":   points[-1]["t"],
        "duration_ms":   duration,
        "had_pointer":   True,
        "points":        points,
        "clicks":        [{"t": points[-1]["t"], "x": points[-1]["x"], "y": points[-1]["y"]}],
        "keydowns":      [],
        "focus":         [],
        "tile_hovers":   {},
        "hp":            False,
        "env":           {},
    }


def score_trajectory(points):
    payload = make_payload(points)
    features = extract_features(payload)
    risk, reasons = compute_behavior_risk(features)
    return risk, reasons


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

LEVELS = [
    ("L1. Liniar perfect            ", trajectory_linear,         "bot naiv (linie dreapta)"),
    ("L2. Liniar + zgomot           ", trajectory_linear_jitter,  "bot cu jitter pozitional"),
    ("L3. Bezier curat              ", trajectory_bezier_clean,   "bot mediu (curba fara jitter)"),
    ("L4. Bezier + jitter           ", trajectory_bezier_jitter,  "bot sofisticat"),
    ("L5. Cvasi-uman (overshoot)    ", trajectory_human_like,     "om real (referinta)"),
]


def percentile(data, p):
    s = sorted(data)
    k = (len(s) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def run():
    print(f"\n{R}{BD}{'='*78}{RS}")
    print(f"{R}{BD}  CALIBRARE PRAG R >= {THRESHOLD}  ({N_SAMPLES} traiectorii / nivel){RS}")
    print(f"{R}{BD}{'='*78}{RS}\n")

    # Verbose: print signals fired for one sample per level
    print(f"{M}{BD}SEMNALE DECLANSATE (un esantion per nivel, seed=0):{RS}")
    for label, gen, _ in LEVELS:
        pts = gen(0)
        risk, reasons = score_trajectory(pts)
        signals = [k for k in reasons.keys() if k != "risk"]
        print(f"\n  {BD}{label.strip()}{RS}  R={risk}")
        for k in signals:
            v = reasons[k]
            sign = "+" if any(kw in k for kw in ("uniform","too","insufficient","low","brief","direct","metronomic","no_","excessive","fast")) else "-"
            print(f"    {sign} {k}: {v}")
    print()

    results = []
    for label, gen, descr in LEVELS:
        scores = []
        for seed in range(N_SAMPLES):
            pts = gen(seed)
            risk, _ = score_trajectory(pts)
            scores.append(risk)

        mean   = statistics.mean(scores)
        stdev  = statistics.pstdev(scores)
        mn, mx = min(scores), max(scores)
        n_ban  = sum(1 for s in scores if s >= THRESHOLD)
        pct    = 100 * n_ban / len(scores)
        results.append((label, descr, mean, stdev, mn, mx, pct))

    # Print results table
    print(f"{BD}{'NIVEL':<32} {'mean':>6} {'std':>6} {'min':>5} {'max':>5} {'%>=78':>7}{RS}")
    print(f"{'-' * 78}")
    for label, descr, mean, stdev, mn, mx, pct in results:
        color = G if pct >= 95 else (Y if pct >= 50 else (W if pct < 5 else R))
        print(f"{color}{label}{RS} {mean:6.1f} {stdev:6.2f} {mn:5.0f} {mx:5.0f} {pct:6.1f}%")
    print(f"{'-' * 78}\n")

    # Interpretation
    print(f"{B}{BD}INTERPRETARE:{RS}\n")
    l1, l2, l3, l4, l5 = results

    def verdict(label, pct, expected_ban, descr):
        if expected_ban:
            if pct >= 95:
                print(f"  {G}[OK]{RS}  {label.strip():<30} detectat in {pct:.0f}% — bine.")
            elif pct >= 50:
                print(f"  {Y}[~]{RS}  {label.strip():<30} detectat doar in {pct:.0f}% — marginal.")
            else:
                print(f"  {R}[!!]{RS} {label.strip():<30} detectat doar in {pct:.0f}% — bot SCAPA.")
        else:
            if pct < 5:
                print(f"  {G}[OK]{RS}  {label.strip():<30} fals pozitiv in {pct:.0f}% — bine.")
            elif pct < 20:
                print(f"  {Y}[~]{RS}  {label.strip():<30} fals pozitiv {pct:.0f}% — marginal.")
            else:
                print(f"  {R}[!!]{RS} {label.strip():<30} fals pozitiv {pct:.0f}% — om penalizat!")

    verdict(l1[0], l1[6], True,  "trebuie sa fie banat")
    verdict(l2[0], l2[6], True,  "trebuie sa fie banat")
    verdict(l3[0], l3[6], True,  "trebuie sa fie banat")
    verdict(l4[0], l4[6], True,  "trebuie sa fie banat")
    verdict(l5[0], l5[6], False, "NU trebuie sa fie banat")

    # Threshold recommendation
    print(f"\n{B}{BD}RECOMANDARE PRAG:{RS}\n")

    # Determine an optimal threshold:
    # We want the threshold to be ABOVE the max of L5 (human max)
    # and BELOW some quantile of the bot scores (L1-L4)
    human_scores = []
    bot_scores   = []
    for seed in range(N_SAMPLES):
        human_scores.append(score_trajectory(trajectory_human_like(seed))[0])
    for gen in [trajectory_linear, trajectory_linear_jitter,
                trajectory_bezier_clean, trajectory_bezier_jitter]:
        for seed in range(N_SAMPLES):
            bot_scores.append(score_trajectory(gen(seed))[0])

    human_p95 = percentile(human_scores, 95)
    human_p99 = percentile(human_scores, 99)
    bot_p05   = percentile(bot_scores, 5)
    bot_p10   = percentile(bot_scores, 10)

    print(f"  Scor uman p95 (zona de risc): {human_p95:.1f}")
    print(f"  Scor uman p99 (extrem):       {human_p99:.1f}")
    print(f"  Scor bot   p05 (cel mai mic): {bot_p05:.1f}")
    print(f"  Scor bot   p10:               {bot_p10:.1f}\n")

    if human_p99 < bot_p05:
        midpoint = (human_p99 + bot_p05) / 2
        print(f"  {G}Separare completa intre om si bot. Prag optim sugerat: {midpoint:.0f}.{RS}")
        if abs(THRESHOLD - midpoint) > 5:
            print(f"  Pragul actual ({THRESHOLD}) ar putea fi ajustat la {midpoint:.0f}.")
        else:
            print(f"  {G}Pragul actual ({THRESHOLD}) este bun.{RS}")
    elif human_p95 < THRESHOLD < bot_p10:
        print(f"  {G}Pragul {THRESHOLD} este bine plasat (om p95 < {THRESHOLD} < bot p10).{RS}")
    elif human_p95 >= THRESHOLD:
        print(f"  {Y}Pragul {THRESHOLD} risca fals pozitive (oameni cu scor >= {THRESHOLD}).{RS}")
        print(f"  Recomandare: creste pragul la {math.ceil(human_p99) + 2}.")
    elif bot_p10 <= THRESHOLD:
        print(f"  {R}Pragul {THRESHOLD} lasa boti sa scape. {RS}")
        print(f"  Recomandare: scade pragul la {math.floor(bot_p05) - 2}.")
    else:
        print(f"  {Y}Suprapunere intre distributii — separare imperfecta.{RS}")

    print()


if __name__ == "__main__":
    run()
