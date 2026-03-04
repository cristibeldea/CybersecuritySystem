import asyncio
import pytest
from playwright.async_api import async_playwright

# Hit /captcha so we don't need to solve captcha to make requests,
# but we still pass through the ban check in app.before_request.
URL = "http://localhost:8080/captcha"

# Use a fixed IP so all requests aggregate into one rate bucket.
TEST_IP = "172.18.0.1"

# Defaults in inspector.py are WINDOW_SECONDS=10, MAX_REQ=20.
# So >20 requests quickly should trigger a ban.
BURST_REQUESTS = 35

# Give the inspector a moment to process pubsub + ban key write
POLL_SECONDS = 8
POLL_INTERVAL = 0.4


@pytest.mark.asyncio
async def test_request_inspector_should_ban_after_too_many_requests():
    async with async_playwright() as p:
        # Use Playwright's APIRequestContext (no browser UI needed)
        ctx = await p.request.new_context()

        headers = {"X-Forwarded-For": TEST_IP}

        async def one_request():
            r = await ctx.get(URL, headers=headers)
            await r.body()  # consume body to avoid connection buildup
            return r.status

        # Fire a burst of requests as fast as possible
        statuses = await asyncio.gather(*(one_request() for _ in range(BURST_REQUESTS)))

        # It's okay if early ones are 200; ban usually happens after inspector processes the burst.
        # Now poll until we see 403 (banned) or we time out.
        banned = False
        last_status = None

        attempts = int(POLL_SECONDS / POLL_INTERVAL)
        for _ in range(attempts):
            r = await ctx.get(URL, headers=headers)
            last_status = r.status
            await r.body()

            if r.status == 403:
                banned = True
                break

            await asyncio.sleep(POLL_INTERVAL)

        await ctx.dispose()

        assert banned, (
            f"Expected IP to be banned (HTTP 403) after spamming requests. "
            f"Last status={last_status}, initial burst statuses sample={statuses[:10]}"
        )