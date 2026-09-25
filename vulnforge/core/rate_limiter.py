"""Asynchronous Rate Limiter and Concurrency Controller."""

import asyncio
import time
from typing import Optional


class RateLimiter:
    """Controls request throughput (requests/sec) and maximum concurrency."""

    def __init__(self, rate: Optional[float] = 5.0, concurrency: int = 5):
        """Initialize RateLimiter.

        Args:
            rate: Maximum requests per second (e.g. 5.0). If None or <= 0, no rate limit is applied.
            concurrency: Maximum number of concurrent in-flight requests (e.g. 5).
        """
        self.rate: Optional[float] = rate if (rate is not None and rate > 0) else None
        self.concurrency: int = max(1, concurrency)
        self._semaphore: asyncio.Semaphore = asyncio.Semaphore(self.concurrency)
        self._lock: asyncio.Lock = asyncio.Lock()
        self._interval: float = (1.0 / self.rate) if self.rate else 0.0
        self._last_request_time: float = 0.0

    async def acquire(self) -> None:
        """Acquire a slot according to rate and concurrency limits."""
        await self._semaphore.acquire()

        if self.rate:
            async with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_request_time
                wait_time = self._interval - elapsed

                if wait_time > 0:
                    await asyncio.sleep(wait_time)

                self._last_request_time = time.monotonic()

    def release(self) -> None:
        """Release the concurrency semaphore slot."""
        self._semaphore.release()

    async def __aenter__(self) -> "RateLimiter":
        """Async context manager entry."""
        await self.acquire()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        self.release()
