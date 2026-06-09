"""
DEMO 2 — Ban progresiv escaladat (varianta rapida)

Pentru fiecare nivel:
  - 3 esecuri comportamentale instantanee (fara animatie cursor)
  - se confirma prin admin API ca s-a aplicat durata corecta din ladder
  - bypass automat al ban-ului, contorul ramane

Ladder:
    abatere 1 -> 60s     (1 min)
    abatere 2 -> 300s    (5 min)
    abatere 3 -> 1800s   (30 min)
    abatere 4 -> 86400s  (24 h)
    abatere 5+ -> 604800s (7 zile)

La final reincarca pagina o singura data sa se vada TTL-ul ultimului ban.
"""
import asyncio, sys, io, os, json, base64
import urllib.request, urllib.parse, urllib.error
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from playwright.async_api import async_playwright

BASE_URL   = "http://localhost:8080"
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "admin")
FAKE_IP    = "10.99.0.42"

NUM_LEVELS_TO_DEMO = 5
ATTEMPTS_PER_BAN   = 3
FINAL_VIEW_SECONDS = 8   # cat sta deschis ban-ul final pe ecran

# -- colors --
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[96m"
W = "\033[97m"; M = "\033[95m"; BD = "\033[1m"; RS = "\033[0m"
def hdr(t):  print(f"\n{R}{BD}{'='*64}{RS}\n{R}{BD}  {t}{RS}\n{R}{BD}{'='*64}{RS}")
def sep():   print(f"{R}{BD}{'-'*64}{RS}")
def ok(t):   print(f"{G}{BD}[+]{RS} {t}")
def err(t):  print(f"{R}{BD}[x]{RS} {t}")
def info(t): print(f"{B}{BD}[~]{RS} {t}")
def step(t): print(f"{W}{BD}[->]{RS} {t}")


# ---------- admin helpers ----------
def _basic_auth() -> str:
    raw = f"{ADMIN_USER}:{ADMIN_PASS}".encode("utf-8")
    return "Basic " + base64.b64encode(raw).decode("ascii")

def admin_post(path: str, payload: dict) -> dict:
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(f"{BASE_URL}{path}", data=data, method="POST",
            headers={"Content-Type": "application/json", "Authorization": _basic_auth()})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode('utf-8','replace')[:160]}"}
    except Exception as e:
        return {"error": str(e)}

def admin_get(path: str, params: dict) -> dict:
    try:
        qs = urllib.parse.urlencode(params)
        req = urllib.request.Request(f"{BASE_URL}{path}?{qs}", method="GET",
            headers={"Authorization": _basic_auth()})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"error": f"HTTP {e.code}: {e.read().decode('utf-8','replace')[:160]}"}
    except Exception as e:
        return {"error": str(e)}

def unban_keep_counter(ip): return admin_post("/admin/api/unban-keep-counter", {"ip": ip})
def reset_offense(ip):      return admin_post("/admin/api/reset-offense", {"ip": ip})
def offense_count(ip):      return admin_get("/admin/api/offense-count", {"ip": ip})


# ---------- robotic injection (no animation, no cursor SVG) ----------
INJECT_POINTS_JS = """
([startX, endX, y, nSteps, intervalMs]) => {
    if (typeof points !== 'undefined') points.length = 0;
    if (typeof clicks !== 'undefined') clicks.length = 0;
    const t0 = performance.now() - (nSteps * intervalMs);
    for (let i = 0; i < nSteps; i++) {
        const x = startX + (endX - startX) * (i / (nSteps - 1));
        points.push({ t: t0 + i * intervalMs, x: x, y: y });
    }
    if (typeof startT !== 'undefined') startT = t0;
    if (typeof hadPointer !== 'undefined') hadPointer = true;
    return points.length;
}
"""

CHECK_BAN_JS = """
() => {
    const banBox = document.getElementById('bannedBox');
    return banBox && !banBox.classList.contains('hidden');
}
"""

RESET_BUTTON_JS = """
() => {
    const btn = document.querySelector('#checkboxStage .hold-btn');
    const fill = btn && btn.querySelector('.hold-fill');
    const lbl = btn && btn.querySelector('.hold-label');
    if (btn) btn.classList.remove('done');
    if (fill) fill.style.width = '0%';
    if (lbl) lbl.textContent = 'Hold to verify';
}
"""

async def fast_robotic_attempt(page):
    """One robotic Hold-to-Verify attempt, as fast as possible."""
    btn = await page.query_selector("#checkboxStage .hold-btn")
    if not btn:
        return False
    box = await btn.bounding_box()
    if not box:
        return False
    tx = box["x"] + box["width"] / 2
    ty = box["y"] + box["height"] / 2

    # Inject 120 perfectly linear points directly (no real mouse move)
    await page.evaluate(INJECT_POINTS_JS, [tx - 350, tx, ty, 120, 15])
    # Move mouse once and trigger hold
    await page.mouse.move(tx, ty, steps=1)
    await page.mouse.down()
    await asyncio.sleep(1.15)   # required by the hold-to-verify duration
    await page.mouse.up()
    await asyncio.sleep(1.2)    # let server process + state update


def fmt_duration(s: int) -> str:
    if s < 60: return f"{s}s"
    if s < 3600: return f"{s//60}m{s%60:02d}s"
    if s < 86400: return f"{s//3600}h{(s%3600)//60:02d}m"
    return f"{s//86400}z{(s%86400)//3600:02d}h"


async def main():
    hdr("DEMO 2 — Ban Progresiv Escaladat (varianta rapida)")
    info(f"IP fals: {BD}{FAKE_IP}{RS}")
    info(f"Niveluri escaladate: {NUM_LEVELS_TO_DEMO}\n")

    # Sanity check: confirm new endpoints exist
    pre = offense_count(FAKE_IP)
    if "error" in pre:
        err(f"Endpoint nou indisponibil → containerul ruleaza cod vechi!")
        err(f"   Detaliu: {pre['error']}")
        err(f"   Ruleaza: docker compose build web && docker compose restart web")
        return
    if "ladder" not in pre:
        err("Raspuns admin API neasteptat — verifica rebuild-ul containerului.")
        return
    ok(f"Endpoint nou activ. Ladder: {pre['ladder']}\n")

    # Cleanup
    step("Reset contor abateri...")
    reset_offense(FAKE_IP)
    ok("Contor resetat.\n")

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False,
            args=["--window-size=1280,820"])
        context = await browser.new_context(
            viewport={"width": 1280, "height": 820},
            extra_http_headers={"X-Forwarded-For": FAKE_IP},
        )
        page = await context.new_page()
        await page.goto(f"{BASE_URL}/captcha", wait_until="networkidle")

        applied_durations = []

        for level in range(1, NUM_LEVELS_TO_DEMO + 1):
            sep()
            print(f"{M}{BD}  NIVELUL {level}/{NUM_LEVELS_TO_DEMO}{RS}")

            # Trigger 3 robotic failures (= 1 ban)
            banned = False
            for attempt in range(1, ATTEMPTS_PER_BAN + 1):
                await fast_robotic_attempt(page)
                if await page.evaluate(CHECK_BAN_JS):
                    banned = True
                    break
                await page.evaluate(RESET_BUTTON_JS)
                await asyncio.sleep(0.3)

            # Read what actually got applied
            cnt = offense_count(FAKE_IP)
            current_level = cnt.get("offense_count", 0)
            expected_dur = [60, 300, 1800, 86400, 604800][min(current_level - 1, 4)] if current_level > 0 else 0
            applied_durations.append(expected_dur)

            if banned and current_level == level:
                ok(f"Ban aplicat. Nivel={current_level} → durata={fmt_duration(expected_dur)}")
            elif current_level == level:
                ok(f"Ban aplicat (banner nu inca vizibil). Nivel={current_level} → {fmt_duration(expected_dur)}")
            else:
                err(f"Asteptam nivel {level}, primit {current_level}. Ban-ul nu s-a escaladat corect.")
                break

            # Bypass (last level: skip bypass so we can see the ban screen)
            if level < NUM_LEVELS_TO_DEMO:
                unban_keep_counter(FAKE_IP)
                await asyncio.sleep(0.3)
                # Reload page to clear ban banner before next round
                await page.goto(f"{BASE_URL}/captcha", wait_until="networkidle")
                await asyncio.sleep(0.3)

        sep()
        ok(f"Demo incheiat. Escaladare: {' -> '.join(fmt_duration(d) for d in applied_durations)}")

        # Show the final ban page with countdown
        final = offense_count(FAKE_IP)
        info(f"Contor final: {BD}{final.get('offense_count','?')}{RS} abateri")
        info(f"Reincarc pagina ca sa se vada TTL-ul ultimului ban...")
        await page.reload(wait_until="networkidle")
        await asyncio.sleep(FINAL_VIEW_SECONDS)
        await browser.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[interrupted]")
