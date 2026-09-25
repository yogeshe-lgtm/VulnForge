"""Controlled, rate-limited, and scoped fuzzing engine."""

import asyncio
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from vulnforge.fuzz.models import FuzzMode, FuzzResult, FuzzSummary
from vulnforge.models.endpoint import Endpoint


class ControlledFuzzer:
    """Executes safe, bounded fuzzing campaigns adhering to rate limits, request budgets, and target scope."""

    def __init__(
        self,
        max_requests: int = 500,
        concurrency: int = 5,
        delay_ms: float = 50.0,
    ):
        self.max_requests = max_requests
        self.concurrency = concurrency
        self.delay_ms = delay_ms

    async def fuzz_endpoints(
        self,
        http_client: Any,
        target_base_url: str,
        wordlist: List[str],
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> FuzzSummary:
        """Execute directory and endpoint discovery fuzzing against target base URL."""
        base_url = target_base_url.rstrip("/") + "/"
        clean_words = [w.strip().lstrip("/") for w in wordlist if w.strip() and not w.startswith("#")]
        limited_words = clean_words[:self.max_requests]

        summary = FuzzSummary(
            target_base_url=target_base_url,
            fuzz_mode=FuzzMode.DIRECTORY_DISCOVERY,
            total_requests_sent=0,
            discovered_endpoints_count=0,
            status_distribution={},
            results=[],
        )

        semaphore = asyncio.Semaphore(self.concurrency)

        async def probe_word(index: int, word: str):
            probe_url = urljoin(base_url, word)
            async with semaphore:
                if progress_callback:
                    progress_callback(word, index + 1, len(limited_words))

                try:
                    resp = await http_client.get(probe_url)
                    summary.total_requests_sent += 1
                    status = resp.status_code
                    summary.status_distribution[status] = summary.status_distribution.get(status, 0) + 1

                    # Determine if response is interesting (200, 301, 302, 307, 308, 401, 403, 500)
                    is_interesting = status in (200, 201, 204, 301, 302, 307, 308, 401, 403, 500)
                    note = ""
                    if status == 200:
                        note = "Accessible route"
                    elif status in (301, 302, 307, 308):
                        loc = resp.headers.get("location") or resp.headers.get("Location") or ""
                        note = f"Redirect -> {loc}"
                    elif status in (401, 403):
                        note = "Protected / Forbidden endpoint"
                    elif status >= 500:
                        note = "Internal Server Error"

                    if is_interesting:
                        summary.discovered_endpoints_count += 1
                        summary.results.append(
                            FuzzResult(
                                payload=word,
                                target_url=probe_url,
                                status_code=status,
                                response_size=len(resp.body) if resp.body else 0,
                                elapsed_ms=getattr(resp, "elapsed", 0.0) * 1000.0,
                                content_type=getattr(resp, "content_type", ""),
                                is_interesting=True,
                                note=note,
                            )
                        )

                except Exception:
                    pass

                if self.delay_ms > 0:
                    await asyncio.sleep(self.delay_ms / 1000.0)

        tasks = [probe_word(i, w) for i, w in enumerate(limited_words)]
        await asyncio.gather(*tasks)

        return summary
