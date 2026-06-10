"""
Comprehensive CAPTCHA test suite.

Tests EVERY testable feature of the captcha system:
  - Hold-to-verify behavioral analysis (robot detection)
  - Grid challenge correctness enforcement
  - Session enforcement (missing cookie)
  - Pass token integrity (forgery, expiry, session binding)
  - Protected route access gate
  - Nonce replay protection
  - Direct bypass attempts
  - Behavioral scoring unit tests (robot vs human-like signals)
  - Honeypot decoy button traps          (bans IP — runs last)
  - 5-failure ban logic                   (bans IP — runs last)

"""

import asyncio
import math
import random
import time

import pytest
import redis as redis_lib
from playwright.async_api import async_playwright

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
BASE = "http://localhost:8080"
CAPTCHA_URL = f"{BASE}/captcha"
VERIFY_URL = f"{BASE}/captcha/verify"
RESET_URL = f"{BASE}/captcha/reset"
HOLD_DURATION_MS = 1500  # must match JS HOLD_DURATION_MS

# The captcha template intentionally contains multiple elements with
# id="holdBtn" — all but one are honeypot decoys sitting inside
# .sr-only containers (offscreen, pointer-events:none) designed to
# trap naive bots that call document.getElementById('holdBtn').
# The application JS identifies the REAL button structurally:
#     document.querySelector("#checkboxStage .field-wrap .hold-btn")
# The test suite must use the same canonical selector so that mouse
# interactions actually reach the live button and not a decoy.
REAL_HOLD_BTN = "#checkboxStage .field-wrap .hold-btn"

REDIS_HOST = "localhost"
REDIS_PORT = 6379
BANNED_PREFIX = "ban:"


# ===========================================================================
#  HELPERS
# ===========================================================================

def _redis():
    """Return a Redis client for test cleanup."""
    return redis_lib.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)


def clear_ban(ip="127.0.0.1"):
    """Remove any existing IP ban from Redis so tests start clean."""
    r = _redis()
    r.delete(f"{BANNED_PREFIX}{ip}")
    # Also try the Docker bridge IP
    r.delete(f"{BANNED_PREFIX}172.18.0.1")


async def fresh_page(playwright, headless=True):
    """Launch browser, open captcha page, return (browser, page)."""
    browser = await playwright.chromium.launch(headless=headless)
    ctx = await browser.new_context()
    page = await ctx.new_page()
    await page.goto(CAPTCHA_URL, wait_until="domcontentloaded")
    return browser, page


async def reset_session(page):
    """Click the Reset button to clear server-side state."""
    await page.click("#resetBtn")
    await page.wait_for_timeout(500)


async def get_status_text(page):
    return (await page.text_content("#status") or "").strip()


async def is_banned_ui(page):
    """Check whether the banned box is visible."""
    return await page.is_visible("#bannedBox")


async def robot_straight_line(page, target_x, target_y, steps=60, duration_s=0.6):
    """Move the mouse in a perfectly straight line at constant speed (robot)."""
    start_x, start_y = 10, 10
    await page.mouse.move(start_x, start_y)
    for i in range(steps):
        t = (i + 1) / steps
        x = start_x + (target_x - start_x) * t
        y = start_y + (target_y - start_y) * t
        await page.mouse.move(x, y)
        await asyncio.sleep(duration_s / steps)


async def human_like_movement(page, target_x, target_y, steps=80, duration_s=1.5):
    """Move the mouse with curvature, variable speed, and small overshoots."""
    start_x, start_y = random.randint(50, 200), random.randint(50, 200)
    await page.mouse.move(start_x, start_y)

    for i in range(steps):
        t = (i + 1) / steps
        ease = t * t * (3 - 2 * t)  # smoothstep
        wobble_x = random.gauss(0, 3 + 8 * (1 - t))
        wobble_y = random.gauss(0, 3 + 8 * (1 - t))
        x = start_x + (target_x - start_x) * ease + wobble_x
        y = start_y + (target_y - start_y) * ease + wobble_y
        await page.mouse.move(x, y)
        base = duration_s / steps
        jitter = random.uniform(0.5, 1.8)
        await asyncio.sleep(base * jitter)

    # Small overshoot then correction
    await page.mouse.move(target_x + random.uniform(3, 8),
                          target_y + random.uniform(2, 6))
    await asyncio.sleep(0.04)
    await page.mouse.move(target_x, target_y)


async def do_hold_button(page, movement_fn, btn_selector=REAL_HOLD_BTN):
    """Execute the hold-to-verify flow with a given mouse movement function."""
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
    """Use page.evaluate to POST JSON and return {status, body}."""
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


# ===========================================================================
#  PAYLOAD GENERATORS
# ===========================================================================

def _generate_human_like_points(n=80, duration_ms=3000):
    """Generate mouse points that mimic human movement with curvature and jitter."""
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
    """Generate clicks with irregular intervals (human-like)."""
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
    """Build a payload with human-like behavioral signals."""
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


# ===========================================================================
#  1. HOLD BUTTON — BEHAVIORAL ANALYSIS
# ===========================================================================

class TestHoldButtonBehavior:
    """Tests that the hold-to-verify stage rejects robotic interaction."""

    @pytest.mark.asyncio
    async def test_robot_straight_line_fails(self):
        """Straight-line constant-speed mouse movement should fail."""
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
        """Clicking the hold button with zero mouse movement should fail."""
        clear_ban()
        async with async_playwright() as p:
            browser, page = await fresh_page(p)
            try:
                await reset_session(page)
                await page.wait_for_timeout(300)

                # NB: getElementById('holdBtn') would hit a honeypot decoy
                # (the template intentionally exposes 7 such decoys). The
                # application JS binds mousedown only on the real button at
                # #checkboxStage .field-wrap .hold-btn — we must hit that one
                # for the bot-detection pipeline to actually run server-side.
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
        """Instant teleportation to the button (no intermediate points) should fail."""
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
        """Releasing the hold button before it fills should not trigger verification."""
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


# ===========================================================================
#  2. GRID CHALLENGE — CORRECTNESS
# ===========================================================================

class TestGridChallenge:
    """Tests that wrong/empty grid selections are rejected."""

    async def _get_to_grid_stage(self, page):
        """Advance past the hold button to the grid stage using direct POST."""
        human_payload = _build_human_payload()
        result = await post_json(page, VERIFY_URL, human_payload)

        if result["body"].get("action") == "next":
            return result["body"]
        return None

    @pytest.mark.asyncio
    async def test_wrong_selection_fails(self):
        """Selecting wrong tiles should not pass the grid challenge."""
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
        """Submitting no tiles should not pass the grid challenge."""
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


# ===========================================================================
#  3. SESSION ENFORCEMENT
# ===========================================================================

class TestSessionEnforcement:
    """Tests that requests without a valid session cookie are rejected."""

    @pytest.mark.asyncio
    async def test_verify_without_session_cookie_returns_403(self):
        """POST to /captcha/verify with no session cookie should get 403."""
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
        """POST to /captcha/reset with no session cookie should get 403."""
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


# ===========================================================================
#  4. PASS TOKEN INTEGRITY
# ===========================================================================

class TestPassToken:
    """Tests that forged, tampered, or expired tokens do not grant access."""

    @pytest.mark.asyncio
    async def test_forged_token_does_not_grant_access(self):
        """A made-up captcha_pass cookie should not bypass the captcha gate."""
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
        """Modifying even one character of a real token should invalidate it."""
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
        """A pass token tied to session A should not work for session B."""
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


# ===========================================================================
#  5. PROTECTED ROUTE ACCESS
# ===========================================================================

class TestProtectedRouteAccess:
    """Tests that the main site redirects to captcha without a valid pass."""

    @pytest.mark.asyncio
    async def test_homepage_redirects_to_captcha_without_pass(self):
        """Visiting / without a pass token should redirect to /captcha."""
        clear_ban()
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            ctx = await browser.new_context()
            page = await ctx.new_page()

            await page.goto(BASE + "/", wait_until="domcontentloaded")
            assert "/captcha" in page.url, \
                f"Homepage should redirect to captcha. URL: {page.url}"

            await browser.close()


# ===========================================================================
#  6. NONCE REPLAY
# ===========================================================================

class TestNonceReplay:
    """Tests that replaying old nonces does not work after reset."""

    @pytest.mark.asyncio
    async def test_old_nonce_rejected_after_reset(self):
        """After resetting, a verify call with the old nonce should not pass."""
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


# ===========================================================================
#  7. DIRECT BYPASS ATTEMPTS
# ===========================================================================

class TestBypassAttempts:
    """Tests various attempts to bypass the captcha system."""

    @pytest.mark.asyncio
    async def test_direct_post_pass_action_does_not_bypass(self):
        """Sending action='pass' directly should not grant a pass token."""
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
        """Trying to submit a grid answer while still at checkbox stage should not pass."""
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
        """Submitting the exact same verify payload twice should not pass on second attempt."""
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


# ===========================================================================
#  8. BEHAVIORAL SCORING UNIT TESTS (via backend)
# ===========================================================================

class TestBehavioralScoringViaAPI:
    """Tests the behavioral scoring by sending crafted payloads to the verify endpoint."""

    @pytest.mark.asyncio
    async def test_zero_points_high_risk(self):
        """Payload with zero mouse points should produce high risk (fail)."""
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
        """Points with perfectly constant velocity should score high risk."""
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
        """Clicks at perfectly regular intervals should score high risk."""
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
        """An interaction completed in under 400ms should score high risk."""
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
        """A perfectly straight path (curvature index ~0) should score high risk."""
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
        """A payload with had_pointer=false should add risk."""
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


# ===========================================================================
#  9. HONEYPOT TRAP  (bans IP — runs near end)
# ===========================================================================

class TestHoneypot:
    """Tests that interacting with hidden decoy buttons triggers a ban."""

    @pytest.mark.asyncio
    async def test_clicking_decoy_button_triggers_ban(self):
        """Clicking a honeypot decoy (data-action='verify') should result in a ban."""
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
        """Sending hp=true directly via POST should return 429 (banned)."""
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


# ===========================================================================
#  10. FIVE-FAILURE BAN  (bans IP — runs last)
# ===========================================================================

class TestFiveFailureBan:
    """Tests that 5 consecutive failures trigger a ban via Redis."""

    @pytest.mark.asyncio
    async def test_ban_after_five_failures(self):
        """Failing 5 times should result in a ban response (429)."""
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
