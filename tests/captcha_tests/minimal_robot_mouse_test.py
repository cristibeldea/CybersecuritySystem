import asyncio
import pytest
from playwright.async_api import async_playwright

URL = "http://localhost:8080/captcha"

STEPS = 60
MOVE_DURATION = 0.6  # constant speed => robot-like

@pytest.mark.asyncio
async def test_robot_straight_line_should_fail():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()

        await page.goto(URL, wait_until="domcontentloaded")

        checkbox = await page.wait_for_selector("#cb")
        box = await checkbox.bounding_box()

        target_x = box["x"] + box["width"] / 2
        target_y = box["y"] + box["height"] / 2

        start_x, start_y = 10, 10
        await page.mouse.move(start_x, start_y)

        for i in range(STEPS):
            t = (i + 1) / STEPS
            x = start_x + (target_x - start_x) * t
            y = start_y + (target_y - start_y) * t
            await page.mouse.move(x, y)
            await asyncio.sleep(MOVE_DURATION / STEPS)

        await page.mouse.click(target_x, target_y)

        # Your captcha page writes status text on failure:
        # setStatus("Verification failed. " + text)
        # We'll assert that the user is NOT redirected to "/"
        # (Redirect happens only on success)
        await page.wait_for_timeout(1200)

        assert "/captcha" in page.url, f"Robot should NOT pass captcha. Current URL: {page.url}"

        # Optional: assert UI shows "Verification failed"
        status = await page.text_content("#status")
        assert status is not None and "Verification failed" in status

        await browser.close()