"""
DEMO 1 — Dumb Bot: detectat la Hold to Verify
==============================================
- Cursor rosu vizibil, miscare in linie dreapta perfecta
- Hold to Verify robotic (viteza constanta, zero curbura)
- Sistemul afiseaza "Incercati din nou" de 2 ori
- La al 3-lea esec: BAN, pagina afiseaza countdown
"""

import asyncio
import base64
import io
import sys
import urllib.request

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

from playwright.async_api import async_playwright

APP_URL = "http://localhost:8080"
FAKE_IP = "10.99.0.1"

R  = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C  = "\033[96m"; W = "\033[97m"; B = "\033[1m";  RS = "\033[0m"

def info(msg):  print(f"{C}{B}[~]{RS} {msg}")
def warn(msg):  print(f"{Y}{B}[!]{RS} {msg}")
def ok(msg):    print(f"{G}{B}[+]{RS} {msg}")
def err(msg):   print(f"{R}{B}[x]{RS} {msg}")
def step(msg):  print(f"{W}{B}[->]{RS} {msg}")
def sep():      print(f"{R}{B}{'─'*60}{RS}")


def unban_ip(ip: str):
    """Sterge orice ban anterior pe IP-ul fals via admin API."""
    try:
        req = urllib.request.Request(
            f"{APP_URL}/admin/api/unban",
            data=f'{{"ip":"{ip}"}}'.encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": "Basic " + base64.b64encode(b"admin:admin").decode(),
            },
            method="POST",
        )
        urllib.request.urlopen(req, timeout=3)
        step(f"Ban anterior sters pentru {ip}")
    except Exception:
        pass


CURSOR_JS = """
(function() {
    if (document.getElementById('__demo_cursor')) return;
    const el = document.createElementNS('http://www.w3.org/2000/svg','svg');
    el.id = '__demo_cursor';
    el.setAttribute('width','28'); el.setAttribute('height','28');
    el.style.cssText = [
        'position:fixed','top:0','left:0',
        'pointer-events:none','z-index:2147483647',
        'filter:drop-shadow(0 0 6px rgba(229,52,53,1))',
        'transition:none'
    ].join(';');
    el.innerHTML = '<polygon points="3,2 3,22 8,16 12,24 15,22 11,15 18,15"' +
        ' fill="#e53435" stroke="#fff" stroke-width="1.5" stroke-linejoin="round"/>';
    document.body.appendChild(el);
    window.__botMoveCursor = (x, y) => {
        el.style.left = (x - 3) + 'px';
        el.style.top  = (y - 3) + 'px';
    };
})();
"""

# Injecteaza puncte robotice in arrays-urile paginii INAINTE de holdDown
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

CHECK_PAGE_STATE_JS = """
() => {
    const body = document.body ? document.body.innerText.toLowerCase() : '';
    const banStage = document.getElementById('banStage');
    const banVisible = banStage && !banStage.classList.contains('hidden');
    const statusEl = document.getElementById('captchaStatus') ||
                     document.querySelector('.status');
    const statusText = statusEl ? statusEl.innerText : '';
    return {
        banned: banVisible || body.includes('ban') && body.includes('second'),
        statusText: statusText,
        bodySnippet: body.slice(0, 200)
    };
}
"""


async def animate_cursor(page, start_x, btn_x, btn_y, n_steps=90):
    """Misca cursorul SVG in linie dreapta spre buton."""
    await page.evaluate(f"window.__botMoveCursor({start_x}, {btn_y})")
    await page.mouse.move(start_x, btn_y)
    await asyncio.sleep(0.4)

    for i in range(n_steps + 1):
        t  = i / n_steps
        px = start_x + (btn_x - start_x) * t
        await page.evaluate(f"window.__botMoveCursor({px}, {btn_y})")
        if i % 12 == 0:
            await page.mouse.move(px, btn_y)
        await asyncio.sleep(0.016)


async def run_demo():
    print()
    print(f"{R}{B}{'='*60}{RS}")
    print(f"{R}{B}  DEMO 1 — Dumb Bot: Hold to Verify  {RS}")
    print(f"{R}{B}{'='*60}{RS}")
    print()
    info(f"IP fals: {B}{FAKE_IP}{RS}  (X-Forwarded-For)")
    info("Comportament: linie dreapta, viteza constanta, zero curbura")
    info("Sistem: 'Incercati din nou' x2  |  al 3-lea esec = BAN")
    print()

    unban_ip(FAKE_IP)

    async with async_playwright() as p:
        browser = await p.chromium.launch(
            headless=False,
            slow_mo=0,
            args=["--window-size=1280,800", "--window-position=80,30",
                  "--disable-blink-features=AutomationControlled"],
        )
        context = await browser.new_context(viewport={"width": 1280, "height": 800})
        page = await context.new_page()

        async def spoof_ip(route, request):
            headers = dict(request.headers)
            headers["X-Forwarded-For"] = FAKE_IP
            await route.continue_(headers=headers)
        await page.route("**/*", spoof_ip)

        step("Deschid pagina CAPTCHA...")
        await page.goto(f"{APP_URL}/captcha", wait_until="networkidle")
        await asyncio.sleep(1.2)
        await page.evaluate(CURSOR_JS)

        try:
            await page.wait_for_selector(
                "#checkboxStage:not(.hidden)", timeout=8000, state="visible"
            )
        except Exception:
            pass
        await asyncio.sleep(0.6)

        hold_btn = page.locator("#checkboxStage .hold-btn").first
        box = await hold_btn.bounding_box()
        if not box:
            err("Butonul Hold nu a fost gasit.")
            await browser.close()
            return

        btn_x = box["x"] + box["width"] / 2
        btn_y = box["y"] + box["height"] / 2

        for attempt in range(1, 4):
            print()
            warn(f"Tentativa {attempt}/3 — miscare robotica spre buton...")

            # 1. Animeaza cursorul
            await animate_cursor(page, 60.0, btn_x, btn_y)

            # 2. Injecteaza punctele robotice in arrays-urile paginii
            n_pts = await page.evaluate(
                INJECT_POINTS_JS, [60.0, btn_x, btn_y, 120, 15.0]
            )
            step(f"{n_pts} puncte injectate (15ms fix, y={btn_y:.0f} constant)")

            # 3. Hold buton: pagina detecteaza holdDown → holdTick →
            #    dupa HOLD_DURATION_MS (1000ms) → verifyCheckbox() automat
            await page.mouse.move(btn_x, btn_y)
            await asyncio.sleep(0.1)
            await page.mouse.down()
            await asyncio.sleep(1.15)   # asteapta sa se umple bara
            await page.mouse.up()

            step("Butonul eliberat — astept raspunsul serverului...")
            await asyncio.sleep(2.0)

            # 4. Citeste starea paginii
            state_info = await page.evaluate(CHECK_PAGE_STATE_JS)
            status_text = state_info.get("statusText", "")
            is_banned   = state_info.get("banned", False)

            banned_keywords = ("ban", "block", "blocat", "temporar")
            is_banned_kw = any(kw in status_text.lower() for kw in banned_keywords)

            if is_banned or is_banned_kw:
                print()
                sep()
                err(f"IP {B}{FAKE_IP}{RS}{R}{B} — BANAT de WebToxin!")
                err(f"Motiv: {attempt} esecuri comportamentale la Hold to Verify")
                err("Ban activ: 60 secunde")
                sep()
                await asyncio.sleep(1.0)
                await page.reload(wait_until="networkidle")
                await asyncio.sleep(1.5)
                break

            elif "ncerca" in status_text or "retry" in status_text.lower() or "again" in status_text.lower():
                ok(f"Server -> '{status_text.strip()}'  (checkbox_fail_count={attempt})")
            else:
                ok(f"Server -> esec detectat  (status: '{status_text.strip()}')")

            await asyncio.sleep(1.2)

            # 5. Reseteaza butonul vizual pentru urmatoarea tentativa
            await page.evaluate("""
                () => {
                    const btn  = document.querySelector('#checkboxStage .hold-btn');
                    const fill = btn && btn.querySelector('.hold-fill');
                    const lbl  = btn && btn.querySelector('.hold-label');
                    if (btn)  { btn.classList.remove('done'); }
                    if (fill) { fill.style.width = '0%'; }
                    if (lbl)  { lbl.textContent = 'Hold to verify'; }
                    if (typeof holdDone !== 'undefined') holdDone = false;
                    if (typeof holdActive !== 'undefined') holdActive = false;
                }
            """)
            await page.evaluate(f"window.__botMoveCursor(60, {btn_y})")
            await asyncio.sleep(0.8)

        print()
        info("Fereastra ramane deschisa 12 secunde...")
        await asyncio.sleep(12)
        await browser.close()

    print()
    info("Demo incheiat.")


if __name__ == "__main__":
    try:
        asyncio.run(run_demo())
    except KeyboardInterrupt:
        print(f"\n{Y}Demo intrerupt.{RS}")
        sys.exit(0)
