import asyncio
from playwright.async_api import async_playwright

URL = "http://localhost:8080/captcha"

# Movement parameters (robot-like)
STEPS = 60
MOVE_DURATION = 0.6  # seconds total (constant speed)


async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False)
        page = await browser.new_page()

        await page.goto(URL)

        # Wait for checkbox to appear
        checkbox = await page.wait_for_selector("#cb")

        # Get checkbox position
        box = await checkbox.bounding_box()
        target_x = box["x"] + box["width"] / 2
        target_y = box["y"] + box["height"] / 2

        # Start from top-left corner of viewport
        start_x = 10
        start_y = 10

        await page.mouse.move(start_x, start_y)

        # Perfect straight line movement with constant speed
        for i in range(STEPS):
            t = (i + 1) / STEPS
            x = start_x + (target_x - start_x) * t
            y = start_y + (target_y - start_y) * t
            await page.mouse.move(x, y)
            await asyncio.sleep(MOVE_DURATION / STEPS)

        # Click checkbox
        await page.mouse.click(target_x, target_y)

        # Wait to observe result
        await page.wait_for_timeout(4000)

        await browser.close()


asyncio.run(run())