"""Tests for Asynchronous Rate Limiter and Concurrency Controls."""

import asyncio
import time
import pytest
from vulnforge.core.rate_limiter import RateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_timing():
    """Verify that RateLimiter paces requests to respect rate limits."""
    rate = 10.0  # 10 req/s -> 0.1s interval
    limiter = RateLimiter(rate=rate, concurrency=5)

    start = time.monotonic()
    for _ in range(4):
        async with limiter:
            pass
    elapsed = time.monotonic() - start

    # 4 requests at 10 req/s should take at least ~0.3 seconds
    assert elapsed >= 0.25


@pytest.mark.asyncio
async def test_concurrency_limit():
    """Verify that concurrency does not exceed specified limit."""
    concurrency = 2
    limiter = RateLimiter(rate=None, concurrency=concurrency)

    active_tasks = 0
    max_active_tasks = 0

    async def worker():
        nonlocal active_tasks, max_active_tasks
        async with limiter:
            active_tasks += 1
            max_active_tasks = max(max_active_tasks, active_tasks)
            await asyncio.sleep(0.05)
            active_tasks -= 1

    tasks = [asyncio.create_task(worker()) for _ in range(6)]
    await asyncio.gather(*tasks)

    assert max_active_tasks <= concurrency
