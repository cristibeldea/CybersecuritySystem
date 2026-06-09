"""
Colector de telemetrie umana reala.

Deschide pagina /captcha intr-un browser vizibil. Utilizatorul (TU) face
operatia de hold-to-verify de N ori, miscand cursorul natural si apasand
butonul ca de obicei. Scriptul intercepteaza fiecare cerere POST catre
/captcha/verify, salveaza payload-ul (traiectorie, evenimente, timing) si
raspunde cu un mesaj de tip 'retry' ca pagina sa ramana pe aceeasi etapa.

Intre capturi, telemetria din pagina este resetata automat (puncte, click-uri,
markeri temporali), astfel incat fiecare mostra capturata sa fie independenta
de cele anterioare.

Iesire: demos/data/human_telemetry.json
"""
import asyncio, sys, io, os, json
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from playwright.async_api import async_playwright

TARGET_SAMPLES = int(os.environ.get("TARGET_SAMPLES", "15"))
BASE_URL       = os.environ.get("BASE_URL", "http://localhost:8080")
OUT_FILE       = os.path.join(os.path.dirname(__file__), "data", "human_telemetry.json")

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[96m"
W = "\033[97m"; M = "\033[95m"; BD = "\033[1m"; RS = "\033[0m"

def hdr(t):  print(f"\n{B}{BD}{'='*64}{RS}\n{B}{BD}  {t}{RS}\n{B}{BD}{'='*64}{RS}")
def ok(t):   print(f"{G}{BD}[+]{RS} {t}")
def info(t): print(f"{B}{BD}[~]{RS} {t}")
def step(t): print(f"{W}{BD}[->]{RS} {t}")
def warn(t): print(f"{Y}{BD}[!]{RS} {t}")
def err(t):  print(f"{R}{BD}[x]{RS} {t}")


captured_payloads = []


OVERLAY_JS = """
() => {
    const existing = document.getElementById('__collector_overlay');
    if (existing) existing.remove();
    const div = document.createElement('div');
    div.id = '__collector_overlay';
    div.style.cssText = [
        'position:fixed', 'top:10px', 'right:10px',
        'background:rgba(20,20,40,0.92)', 'color:white',
        'padding:14px 18px', 'border-radius:8px',
        'font-family:monospace', 'z-index:99999',
        'font-size:13px', 'box-shadow:0 4px 14px rgba(0,0,0,0.4)',
        'line-height:1.5', 'border:1px solid #555'
    ].join(';');
    div.innerHTML =
        '<b>Colector telemetrie umana</b><br>' +
        '<span id="__collector_count">Capturat 0/__TARGET__</span><br>' +
        '<span style="font-size:10px;opacity:0.7">Tine apasat butonul ' +
        '~1 secunda. Apoi repeta natural.</span>';
    document.body.appendChild(div);

    window.__updateProgress = (n, total) => {
        const el = document.getElementById('__collector_count');
        if (!el) return;
        if (n >= total) {
            el.innerHTML = '<b style="color:#5f5">GATA! ' + n + '/' + total + '</b>';
            div.style.background = 'rgba(20,80,20,0.95)';
        } else {
            el.textContent = 'Capturat ' + n + '/' + total;
        }
    };
}
"""

RESET_TELEMETRY_JS = """
() => {
    if (typeof points         !== 'undefined') points.length = 0;
    if (typeof clicks         !== 'undefined') clicks.length = 0;
    if (typeof keydowns       !== 'undefined') keydowns.length = 0;
    if (typeof focusEvents    !== 'undefined') focusEvents.length = 0;
    if (typeof tileHovers     !== 'undefined') {
        for (const k in tileHovers) delete tileHovers[k];
    }
    if (typeof startT         !== 'undefined') startT = performance.now();
    if (typeof lastSample     !== 'undefined') lastSample = 0;
    if (typeof hadPointer     !== 'undefined') hadPointer = false;
}
"""


async def main():
    hdr("COLECTOR TELEMETRIE UMANA REALA")
    info(f"Tinta: {BD}{TARGET_SAMPLES}{RS} mostre")
    info(f"Server: {BD}{BASE_URL}{RS}")
    info(f"Iesire: {BD}{OUT_FILE}{RS}\n")

    os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=False,
            args=["--window-size=1280,820"],
        )
        context = await browser.new_context(viewport={"width": 1280, "height": 820})
        page = await context.new_page()

        async def handle_route(route, request):
            if request.method == "POST" and "/captcha/verify" in request.url:
                try:
                    body = json.loads(request.post_data or "{}")
                    captured_payloads.append(body)
                    n = len(captured_payloads)
                    pts   = len(body.get("points", []))
                    dur   = body.get("duration_ms", 0)
                    print(f"  {G}{BD}[+]{RS} Capturat #{n:2d}/{TARGET_SAMPLES}  "
                          f"({pts} puncte, {dur:.0f} ms)")

                    if n >= TARGET_SAMPLES:
                        msg = f"GATA — {n}/{TARGET_SAMPLES} mostre colectate."
                    else:
                        msg = (f"Mostra {n}/{TARGET_SAMPLES} capturata. "
                               f"Misca cursorul si tine apasat din nou.")

                    await route.fulfill(
                        status=200,
                        content_type="application/json",
                        body=json.dumps({
                            "action":  "retry",
                            "message": msg,
                            "nonce":   "collector",
                            "state":   {"kind": "checkbox", "attempt_index": n},
                        }),
                    )
                except Exception as e:
                    err(f"Eroare la captura: {e}")
                    await route.continue_()
            else:
                await route.continue_()

        await page.route("**/*", handle_route)
        step("Deschid pagina /captcha...")
        await page.goto(f"{BASE_URL}/captcha", wait_until="networkidle")
        await page.evaluate(OVERLAY_JS.replace("__TARGET__", str(TARGET_SAMPLES)))

        print()
        info(f"{Y}Browser deschis. Tine apasat butonul de hold-to-verify "
             f"de {TARGET_SAMPLES} ori, miscand cursorul natural.{RS}\n")

        # Poll: reseteaza telemetria intre capturi si actualizeaza overlay-ul
        last_count = 0
        while len(captured_payloads) < TARGET_SAMPLES:
            await asyncio.sleep(0.25)
            n = len(captured_payloads)
            if n > last_count:
                last_count = n
                try:
                    await page.evaluate(f"window.__updateProgress({n}, {TARGET_SAMPLES})")
                    # Mic delay ca pagina sa-si reseteze UI-ul, apoi sterg
                    # array-urile de puncte/click-uri ca fiecare mostra
                    # urmatoare sa fie complet independenta de cea trecuta.
                    await asyncio.sleep(0.15)
                    await page.evaluate(RESET_TELEMETRY_JS)
                except Exception:
                    pass

        print()
        ok(f"Total: {len(captured_payloads)} mostre.")

        # Salvare
        with open(OUT_FILE, "w", encoding="utf-8") as f:
            json.dump(captured_payloads, f, ensure_ascii=False, indent=2)
        ok(f"Salvat: {OUT_FILE}")

        await page.evaluate(f"window.__updateProgress({TARGET_SAMPLES}, {TARGET_SAMPLES})")
        info("Inchid browserul in 4 secunde...")
        await asyncio.sleep(4)
        await browser.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        if captured_payloads:
            with open(OUT_FILE, "w", encoding="utf-8") as f:
                json.dump(captured_payloads, f, ensure_ascii=False, indent=2)
            print(f"\n{G}[!] Intrerupt. Salvat {len(captured_payloads)} mostre in {OUT_FILE}{RS}")
        else:
            print(f"\n{R}[!] Intrerupt, fara mostre salvate.{RS}")
