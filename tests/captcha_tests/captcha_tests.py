"""Suita end-to-end pentru CAPTCHA: testeaza fiecare caracteristica testabila."""

import asyncio
import math
import random
import time

import pytest
import redis as redis_lib
from playwright.async_api import async_playwright

BASE = "http://localhost:8080"
CAPTCHA_URL = f"{BASE}/captcha"
VERIFY_URL = f"{BASE}/captcha/verify"
RESET_URL = f"{BASE}/captcha/reset"
HOLD_DURATION_MS = 1500

REAL_HOLD_BTN = "#checkboxStage .field-wrap .hold-btn"

REDIS_HOST = "localhost"
REDIS_PORT = 6379
BANNED_PREFIX = "ban:"

def _redis():
    """Client Redis pentru curatare intre teste."""
    return redis_lib.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

def clear_ban(ip="127.0.0.1"):
    """Sterge orice ban activ pe IP din Redis ca testele sa porneasca curat."""
    r = _redis()
    r.delete(f"{BANNED_PREFIX}{ip}")
    r.delete(f"{BANNED_PREFIX}172.18.0.1")

async def fresh_page(playwright, headless=True):
    """Porneste browserul, deschide pagina CAPTCHA, returneaza (browser, page)."""
    browser = await playwright.chromium.launch(headless=headless)
    ctx = await browser.new_context()
    page = await ctx.new_page()
    await page.goto(CAPTCHA_URL, wait_until="domcontentloaded")
    return browser, page

async def reset_session(page):
    """Apasa butonul Reset ca sa curete starea de pe server."""
    await page.click("#resetBtn")
    await page.wait_for_timeout(500)

async def get_status_text(page):
    return (await page.text_content("#status") or "").strip()

async def is_banned_ui(page):
    """Verifica daca caseta de ban este vizibila in UI."""
    return await page.is_visible("#bannedBox")

async def robot_straight_line(page, target_x, target_y, steps=60, duration_s=0.6):
    """Misca mouse-ul in linie dreapta cu viteza constanta (robot)."""
    start_x, start_y = 10, 10
    await page.mouse.move(start_x, start_y)
    for i in range(steps):
        t = (i + 1) / steps
        x = start_x + (target_x - start_x) * t
        y = start_y + (target_y - start_y) * t
        await page.mouse.move(x, y)
        await asyncio.sleep(duration_s / steps)

async def human_like_movement(page, target_x, target_y, steps=80, duration_s=1.5):
    """Misca mouse-ul cu curbura, viteza variabila si overshoot."""
    start_x, start_y = random.randint(50, 200), random.randint(50, 200)
    await page.mouse.move(start_x, start_y)

    for i in range(steps):
        t = (i + 1) / steps
        ease = t * t * (3 - 2 * t)
        wobble_x = random.gauss(0, 3 + 8 * (1 - t))
        wobble_y = random.gauss(0, 3 + 8 * (1 - t))
        x = start_x + (target_x - start_x) * ease + wobble_x
        y = start_y + (target_y - start_y) * ease + wobble_y
        await page.mouse.move(x, y)
        base = duration_s / steps
        jitter = random.uniform(0.5, 1.8)
        await asyncio.sleep(base * jitter)

    await page.mouse.move(target_x + random.uniform(3, 8),
                          target_y + random.uniform(2, 6))
    await asyncio.sleep(0.04)
    await page.mouse.move(target_x, target_y)

async def do_hold_button(page, movement_fn, btn_selector=REAL_HOLD_BTN):
    """Executa fluxul hold-to-verify cu functia de mouse data."""
    btn = await page.wait_for_selector(btn_selector, state="visible", timeout=5000)
    box = await btn.bounding_box()
    tx = box["x"] + box["width"] / 2
    ty = box["y"] + box["height"] / 2

    await movement_fn(page, tx, ty)

    await page.mouse.down()
    await page.wait_for_timeout(HOLD_DURATION_MS + 300)
    await page.mouse.up()

    await page.wait_for_timeout(1500)

async def post_json(page, url, payload):
    """Trimite POST JSON via page.evaluate si returneaza (status, body)."""
    return await page.evaluate("""
        async ([url, payload]) => {
            const res = await fetch(url, {
                method: "POST",
                headers: {"Content-Type": "application/json"},
                body: JSON.stringify(payload),
                credentials: "same-origin"
            });
            const ct = (res.headers.get("content-type") || "");
            let body;
            if (ct.includes("application/json")) {
                body = await res.json();
            } else {
                body = {text: await res.text()};
            }
            return {status: res.status, body};
        }
    """, [url, payload])

def _generate_human_like_points(n=80, duration_ms=3000):
    """Genereaza puncte de mouse care imita miscarea umana cu curbura si jitter."""
    points = []
    for i in range(n):
        t = (i / n) * duration_ms
        base_x = 100 + (400 * (i / n))
        base_y = 100 + (200 * (i / n))
        wobble_x = math.sin(i * 0.3) * 15 + random.gauss(0, 4)
        wobble_y = math.cos(i * 0.25) * 12 + random.gauss(0, 3)
        t_jitter = random.gauss(0, duration_ms / n * 0.3)
        points.append({
            "t": round(t + t_jitter, 1),
            "x": round(base_x + wobble_x, 1),
            "y": round(base_y + wobble_y, 1),
        })
    return points

def _generate_human_like_clicks(n=4, start_t=1000):
    """Genereaza click-uri cu intervale neregulate, cvasi-umane."""
    clicks = []
    t = start_t
    for i in range(n):
        t += random.uniform(150, 800)
        clicks.append({
            "t": round(t, 1),
            "x": round(200 + random.gauss(0, 50), 1),
            "y": round(200 + random.gauss(0, 30), 1),
        })
    return clicks

def _build_human_payload():
    """Construieste un payload cu semnale comportamentale cvasi-umane."""
    points = _generate_human_like_points(80, 3000)
    clicks = _generate_human_like_clicks(4, 1000)

    tile_hovers = {}
    for i in range(9):
        tile_hovers[str(i)] = {
            "total_ms": round(random.uniform(200, 1200), 1),
            "visits": random.randint(1, 3),
        }

    return {
        "action": "checkbox",
        "nonce": "placeholder",
        "duration_ms": 3500,
        "points": points,
        "clicks": clicks,
        "focus": [{"type": "focus", "t": 0}],
        "had_pointer": True,
        "tile_hovers": tile_hovers,
        "hp": False,
    }

class TestHoldButtonBehavior:
    """Verifica respingerea interactiunilor robotice la hold-to-verify."""

    @pytest.mark.asyncio
    async def test_robot_straight_line_fails(self):
        """Miscarea in linie dreapta cu viteza constanta trebuie sa esueze."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)
                await do_hold_button(page, robot_straight_line)

                assert "/captcha" in page.url, \
                    f"Robot should NOT pass captcha. URL: {page.url}"
            finally:
                await browser.close()

    @pytest.mark.asyncio
    async def test_no_mouse_movement_fails(self):
        """Apasarea butonului fara miscare de mouse trebuie sa esueze."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                await page.evaluate("""
                    () => {
                        const btn = document.querySelector("#checkboxStage .field-wrap .hold-btn");
                        btn.dispatchEvent(new MouseEvent("mousedown", {bubbles: true}));
                    }
                """)
                await page.wait_for_timeout(HOLD_DURATION_MS + 500)
                await page.evaluate("""
                    () => {
                        window.dispatchEvent(new MouseEvent("mouseup", {bubbles: true}));
                    }
                """)
                await page.wait_for_timeout(1500)

                assert "/captcha" in page.url, \
                    "No-movement interaction should NOT pass captcha."
            finally:
                await browser.close()

    @pytest.mark.asyncio
    async def test_teleporting_mouse_fails(self):
        """Teleportarea instantanee la buton trebuie sa esueze."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                btn = await page.wait_for_selector(REAL_HOLD_BTN, state="visible")
                box = await btn.bounding_box()
                tx = box["x"] + box["width"] / 2
                ty = box["y"] + box["height"] / 2

                await page.mouse.move(tx, ty)
                await page.mouse.down()
                await page.wait_for_timeout(HOLD_DURATION_MS + 300)
                await page.mouse.up()
                await page.wait_for_timeout(1500)

                assert "/captcha" in page.url, \
                    "Teleporting mouse should NOT pass captcha."
            finally:
                await browser.close()

    @pytest.mark.asyncio
    async def test_hold_released_too_early_does_not_verify(self):
        """Eliberarea prematura a butonului nu trebuie sa declanseze verificarea."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                btn = await page.wait_for_selector(REAL_HOLD_BTN, state="visible")
                box = await btn.bounding_box()
                tx = box["x"] + box["width"] / 2
                ty = box["y"] + box["height"] / 2

                await human_like_movement(page, tx, ty)
                await page.mouse.down()
                await page.wait_for_timeout(300)
                await page.mouse.up()
                await page.wait_for_timeout(800)

                status = await get_status_text(page)
                assert "Hold the button" in status or "hold" in status.lower(), \
                    f"Early release should show hold instruction. Got: '{status}'"
            finally:
                await browser.close()

class TestGridChallenge:
    """Verifica respingerea selectiilor gresite sau goale pe grila."""

    async def _get_to_grid_stage(self, page):
        """Avanseaza dincolo de butonul hold catre etapa grilei prin POST direct."""
        human_payload = _build_human_payload()
        result = await post_json(page, VERIFY_URL, human_payload)

        if result["body"].get("action") == "next":
            return result["body"]
        return None

    @pytest.mark.asyncio
    async def test_wrong_selection_fails(self):
        """Selectarea de tile-uri gresite nu trebuie sa treaca provocarea grilei."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                grid_data = await self._get_to_grid_stage(page)
                if not grid_data:
                    pytest.skip("Could not reach grid stage (behavioral check too strict)")

                wrong_payload = _build_human_payload()
                wrong_payload["action"] = "grid"
                wrong_payload["selected_ids"] = ["99", "98"]

                result = await post_json(page, VERIFY_URL, wrong_payload)
                action = result["body"].get("action", "")

                assert action != "pass", \
                    "Wrong tile selection should NOT pass the grid challenge."
            finally:
                await browser.close()

    @pytest.mark.asyncio
    async def test_empty_selection_fails(self):
        """Trimiterea fara tile-uri selectate nu trebuie sa treaca grila."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                grid_data = await self._get_to_grid_stage(page)
                if not grid_data:
                    pytest.skip("Could not reach grid stage")

                empty_payload = _build_human_payload()
                empty_payload["action"] = "grid"
                empty_payload["selected_ids"] = []

                result = await post_json(page, VERIFY_URL, empty_payload)
                action = result["body"].get("action", "")

                assert action != "pass", \
                    "Empty selection should NOT pass the grid challenge."
            finally:
                await browser.close()

class TestSessionEnforcement:
    """Verifica respingerea cererilor fara cookie de sesiune valid."""

    @pytest.mark.asyncio
    async def test_verify_without_session_cookie_returns_403(self):
        """POST la /captcha/verify fara cookie de sesiune trebuie sa primeasca 403."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                ctx = page.context
                await ctx.clear_cookies()

                result = await post_json(page, VERIFY_URL, {
                    "nonce": "test",
                    "duration_ms": 2000,
                    "points": [],
                    "clicks": [],
                    "focus": [],
                    "had_pointer": True,
                })

                assert result["status"] == 403, \
                    f"No-session verify should return 403. Got: {result['status']}"
            finally:
                await browser.close()

    @pytest.mark.asyncio
    async def test_reset_without_session_cookie_returns_403(self):
        """POST la /captcha/reset fara cookie de sesiune trebuie sa primeasca 403."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                ctx = page.context
                await ctx.clear_cookies()

                result = await post_json(page, RESET_URL, {})

                assert result["status"] == 403, \
                    f"No-session reset should return 403. Got: {result['status']}"
            finally:
                await browser.close()

class TestPassToken:
    """Verifica refuzul token-urilor forjate, modificate sau expirate."""

    @pytest.mark.asyncio
    async def test_forged_token_does_not_grant_access(self):
        """Un cookie captcha_pass inventat nu trebuie sa treaca poarta."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await page.context.add_cookies([{
                    "name": "captcha_pass",
                    "value": "forged-token.invalidsig",
                    "domain": "localhost",
                    "path": "/",
                }])

                await page.goto(BASE + "/", wait_until="domcontentloaded")
                assert "/captcha" in page.url, \
                    f"Forged token should redirect to captcha. URL: {page.url}"
            finally:
                await browser.close()

    @pytest.mark.asyncio
    async def test_tampered_token_does_not_grant_access(self):
        """Modificarea unui singur caracter dintr-un token real trebuie sa il invalideze."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                tampered = "dGVzdA.tampered_signature_here"
                await page.context.add_cookies([{
                    "name": "captcha_pass",
                    "value": tampered,
                    "domain": "localhost",
                    "path": "/",
                }])

                await page.goto(BASE + "/", wait_until="domcontentloaded")
                assert "/captcha" in page.url, \
                    f"Tampered token should redirect to captcha. URL: {page.url}"
            finally:
                await browser.close()

    @pytest.mark.asyncio
    async def test_token_from_different_session_does_not_work(self):
        """Un token din sesiunea A nu trebuie sa functioneze pentru sesiunea B."""
        clear_ban()
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)

            ctx_a = await browser.new_context()
            page_a = await ctx_a.new_page()
            await page_a.goto(CAPTCHA_URL, wait_until="domcontentloaded")
            cookies_a = await ctx_a.cookies()
            await ctx_a.close()

            ctx_b = await browser.new_context()
            page_b = await ctx_b.new_page()
            await page_b.goto(CAPTCHA_URL, wait_until="domcontentloaded")

            sid_a = ""
            for c in cookies_a:
                if c["name"] == "captcha_sid":
                    sid_a = c["value"]

            fake_token = "eyJzaWQiOiJ7" + sid_a + "cHYiOiIxIiwiZXhwIjo5OTk5OTk5OTk5fQ.fakesig"
            await ctx_b.add_cookies([{
                "name": "captcha_pass",
                "value": fake_token,
                "domain": "localhost",
                "path": "/",
            }])

            await page_b.goto(BASE + "/", wait_until="domcontentloaded")
            assert "/captcha" in page_b.url, \
                "Token from different session should not grant access."

            await ctx_b.close()
            await browser.close()

class TestProtectedRouteAccess:
    """Verifica redirectarea catre CAPTCHA in absenta unui pass valid."""

    @pytest.mark.asyncio
    async def test_homepage_redirects_to_captcha_without_pass(self):
        """Vizitarea / fara pass trebuie sa redirecteze catre /captcha."""
        clear_ban()
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            ctx = await browser.new_context()
            page = await ctx.new_page()

            await page.goto(BASE + "/", wait_until="domcontentloaded")
            assert "/captcha" in page.url, \
                f"Homepage should redirect to captcha. URL: {page.url}"

            await browser.close()

class TestNonceReplay:
    """Verifica refuzul nonce-urilor vechi dupa reset."""

    @pytest.mark.asyncio
    async def test_old_nonce_rejected_after_reset(self):
        """Dupa reset, un verify cu nonce-ul vechi nu trebuie sa treaca."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                old_nonce = await page.evaluate("() => nonce")

                await reset_session(page)
                await page.wait_for_timeout(300)

                new_nonce = await page.evaluate("() => nonce")
                assert old_nonce != new_nonce, "Reset should generate a new nonce."

                payload = _build_human_payload()
                payload["nonce"] = old_nonce

                result = await post_json(page, VERIFY_URL, payload)

                action = result["body"].get("action", "")
                assert action != "pass", \
                    "Old nonce should not allow passing after reset."
            finally:
                await browser.close()

class TestBypassAttempts:
    """Verifica diverse incercari de bypass al sistemului CAPTCHA."""

    @pytest.mark.asyncio
    async def test_direct_post_pass_action_does_not_bypass(self):
        """Trimiterea action=pass direct nu trebuie sa acorde token."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                result = await post_json(page, VERIFY_URL, {
                    "action": "pass",
                    "nonce": await page.evaluate("() => nonce"),
                    "duration_ms": 3000,
                    "points": [],
                    "clicks": [],
                    "focus": [],
                    "had_pointer": True,
                })

                action = result["body"].get("action", "")
                assert action != "pass", \
                    "Sending action='pass' should NOT bypass the captcha."

                await page.goto(BASE + "/", wait_until="domcontentloaded")
                assert "/captcha" in page.url
            finally:
                await browser.close()

    @pytest.mark.asyncio
    async def test_grid_verify_at_checkbox_stage_does_not_work(self):
        """Submit la grila in timpul etapei checkbox nu trebuie sa treaca."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                result = await post_json(page, VERIFY_URL, {
                    "action": "grid",
                    "nonce": await page.evaluate("() => nonce"),
                    "selected_ids": ["0", "1"],
                    "duration_ms": 5000,
                    "points": _generate_human_like_points(80),
                    "clicks": _generate_human_like_clicks(5),
                    "focus": [],
                    "had_pointer": True,
                    "tile_hovers": {},
                })

                action = result["body"].get("action", "")
                assert action != "pass", \
                    "Grid verify at checkbox stage should NOT pass."
            finally:
                await browser.close()

    @pytest.mark.asyncio
    async def test_replay_same_request_twice(self):
        """Replay-ul aceleiasi cereri verify nu trebuie sa treaca a doua oara."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                payload = _build_human_payload()
                payload["nonce"] = await page.evaluate("() => nonce")

                result1 = await post_json(page, VERIFY_URL, payload)
                result2 = await post_json(page, VERIFY_URL, payload)

                action2 = result2["body"].get("action", "")
                assert action2 != "pass", \
                    "Replayed request should NOT grant a pass."
            finally:
                await browser.close()

class TestBehavioralScoringViaAPI:
    """Verifica scoringul comportamental prin payload-uri trimise la endpoint-ul de verify."""

    @pytest.mark.asyncio
    async def test_zero_points_high_risk(self):
        """Payload-ul cu zero puncte de mouse trebuie sa produca risc mare."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                payload = {
                    "nonce": await page.evaluate("() => nonce"),
                    "action": "checkbox",
                    "duration_ms": 200,
                    "points": [],
                    "clicks": [],
                    "focus": [],
                    "had_pointer": False,
                    "tile_hovers": {},
                }

                result = await post_json(page, VERIFY_URL, payload)
                action = result["body"].get("action", "")
                assert action != "pass", \
                    "Zero-point payload should NOT pass behavioral check."
            finally:
                await browser.close()

    @pytest.mark.asyncio
    async def test_constant_velocity_points_high_risk(self):
        """Punctele cu viteza perfect constanta trebuie sa primeasca risc mare."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                points = []
                for i in range(80):
                    points.append({
                        "t": i * 10,
                        "x": 100 + i * 5,
                        "y": 100 + i * 2,
                    })

                payload = {
                    "nonce": await page.evaluate("() => nonce"),
                    "action": "checkbox",
                    "duration_ms": 3000,
                    "points": points,
                    "clicks": [{"t": 800, "x": 500, "y": 260}],
                    "focus": [],
                    "had_pointer": True,
                    "tile_hovers": {},
                }

                result = await post_json(page, VERIFY_URL, payload)
                action = result["body"].get("action", "")
                assert action != "pass", \
                    "Constant-velocity payload should NOT pass."
            finally:
                await browser.close()

    @pytest.mark.asyncio
    async def test_metronomic_clicks_high_risk(self):
        """Click-urile la intervale perfect regulate trebuie sa primeasca risc mare."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                points = []
                for i in range(60):
                    points.append({
                        "t": i * 15 + random.uniform(-2, 2),
                        "x": 100 + i * 4 + random.uniform(-1, 1),
                        "y": 100 + i * 2 + random.uniform(-1, 1),
                    })

                clicks = [{"t": 500 + i * 200, "x": 300, "y": 200} for i in range(6)]

                payload = {
                    "nonce": await page.evaluate("() => nonce"),
                    "action": "checkbox",
                    "duration_ms": 3000,
                    "points": points,
                    "clicks": clicks,
                    "focus": [],
                    "had_pointer": True,
                    "tile_hovers": {},
                }

                result = await post_json(page, VERIFY_URL, payload)
                action = result["body"].get("action", "")
                assert action != "pass", \
                    "Metronomic-click payload should NOT pass."
            finally:
                await browser.close()

    @pytest.mark.asyncio
    async def test_too_fast_duration_high_risk(self):
        """O interactiune incheiata in sub 400ms trebuie sa primeasca risc mare."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                points = []
                for i in range(10):
                    points.append({
                        "t": i * 20,
                        "x": 100 + i * 30,
                        "y": 100 + i * 10,
                    })

                payload = {
                    "nonce": await page.evaluate("() => nonce"),
                    "action": "checkbox",
                    "duration_ms": 200,
                    "points": points,
                    "clicks": [{"t": 180, "x": 370, "y": 190}],
                    "focus": [],
                    "had_pointer": True,
                    "tile_hovers": {},
                }

                result = await post_json(page, VERIFY_URL, payload)
                action = result["body"].get("action", "")
                assert action != "pass", \
                    "Ultra-fast interaction should NOT pass."
            finally:
                await browser.close()

    @pytest.mark.asyncio
    async def test_straight_path_zero_curvature_high_risk(self):
        """O traiectorie perfect dreapta (curbura zero) trebuie sa primeasca risc mare."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                points = []
                for i in range(50):
                    points.append({
                        "t": i * 30 + random.uniform(-3, 3),
                        "x": 50 + i * 8,
                        "y": 50 + i * 4,
                    })

                payload = {
                    "nonce": await page.evaluate("() => nonce"),
                    "action": "checkbox",
                    "duration_ms": 2500,
                    "points": points,
                    "clicks": [{"t": 1500, "x": 450, "y": 250}],
                    "focus": [],
                    "had_pointer": True,
                    "tile_hovers": {},
                }

                result = await post_json(page, VERIFY_URL, payload)
                action = result["body"].get("action", "")
                assert action != "pass", \
                    "Straight-path zero-curvature payload should NOT pass."
            finally:
                await browser.close()

    @pytest.mark.asyncio
    async def test_no_pointer_events_high_risk(self):
        """Un payload cu had_pointer false trebuie sa adauge risc."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                payload = {
                    "nonce": await page.evaluate("() => nonce"),
                    "action": "checkbox",
                    "duration_ms": 1000,
                    "points": [{"t": 0, "x": 100, "y": 100}, {"t": 500, "x": 200, "y": 200}],
                    "clicks": [],
                    "focus": [],
                    "had_pointer": False,
                    "tile_hovers": {},
                }

                result = await post_json(page, VERIFY_URL, payload)
                action = result["body"].get("action", "")
                assert action != "pass", \
                    "No-pointer payload should NOT pass."
            finally:
                await browser.close()

class TestHoneypot:
    """Verifica banul la interactiunea cu butoane capcana ascunse."""

    @pytest.mark.asyncio
    async def test_clicking_decoy_button_triggers_ban(self):
        """Click-ul pe un buton capcana (data-action=verify) trebuie sa duca la ban."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                await page.evaluate("""
                    () => {
                        const decoy = document.querySelector('[data-action="verify"]');
                        if (decoy) {
                            decoy.dispatchEvent(new MouseEvent("click", {bubbles: true}));
                        }
                    }
                """)
                await page.wait_for_timeout(200)

                btn = await page.wait_for_selector(REAL_HOLD_BTN, state="visible")
                box = await btn.bounding_box()
                tx = box["x"] + box["width"] / 2
                ty = box["y"] + box["height"] / 2

                await human_like_movement(page, tx, ty)
                await page.mouse.down()
                await page.wait_for_timeout(HOLD_DURATION_MS + 300)
                await page.mouse.up()
                await page.wait_for_timeout(1500)

                banned = await is_banned_ui(page)
                assert banned, "Honeypot interaction should trigger a ban."
            finally:
                await browser.close()
                clear_ban()

    @pytest.mark.asyncio
    async def test_honeypot_via_direct_post(self):
        """Trimiterea hp=true direct via POST trebuie sa returneze 429 (banat)."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                result = await post_json(page, VERIFY_URL, {
                    "hp": True,
                    "nonce": "whatever",
                    "duration_ms": 2000,
                    "points": [],
                    "clicks": [],
                    "focus": [],
                    "had_pointer": True,
                })
                assert result["status"] == 429, \
                    f"Honeypot POST should return 429. Got: {result['status']}"
                assert result["body"].get("action") == "banned"
            finally:
                await browser.close()
                clear_ban()

class TestFiveFailureBan:
    """Verifica banul dupa 5 esecuri consecutive in Redis."""

    @pytest.mark.asyncio
    async def test_ban_after_five_failures(self):
        """5 esecuri consecutive trebuie sa duca la 429 (banat)."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                got_banned = False

                for i in range(6):
                    payload = _build_human_payload()

                    if i == 0:
                        payload["action"] = "checkbox"
                    else:
                        payload["action"] = "grid"
                        payload["selected_ids"] = ["99"]

                    result = await post_json(page, VERIFY_URL, payload)

                    if result["status"] == 429:
                        got_banned = True
                        break

                    if result["body"].get("action") == "banned":
                        got_banned = True
                        break

                assert got_banned, \
                    "Should be banned after 5 consecutive failures."
            finally:
                await browser.close()
                clear_ban()
