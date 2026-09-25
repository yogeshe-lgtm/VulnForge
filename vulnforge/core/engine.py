"""Centralized Async HTTP Engine with Scope Enforcement and Rate Limiting."""

import asyncio
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin
import httpx

from vulnforge.core.context import ScanContext
from vulnforge.core.exceptions import (
    ConnectionFailedError,
    HttpEngineError,
    RequestTimeoutError,
    ScopeViolationError,
)
from vulnforge.core.rate_limiter import RateLimiter
from vulnforge.core.scope import ScopeEngine
from vulnforge.core.session import create_async_client
from vulnforge.models.request import HttpRequest
from vulnforge.models.response import HttpResponse


class HttpEngine:
    """Central HTTP Execution Engine.

    All outbound requests pass through this engine to guarantee:
    1. Scope validation (including all redirect hops)
    2. Rate limiting and concurrency controls
    3. Metrics & statistics tracking
    4. Structured error capture
    """

    def __init__(
        self,
        context: Optional[ScanContext] = None,
        client: Optional[httpx.AsyncClient] = None,
        scope: Optional[ScopeEngine] = None,
        rate_limiter: Optional[RateLimiter] = None,
        default_timeout: float = 10.0,
        user_agent: Optional[str] = None,
        verify_tls: bool = True,
        proxy: Optional[str] = None,
    ):
        """Initialize HttpEngine.

        Args:
            context: Optional ScanContext. If provided, engine hooks into its scope, rate limiter, and stats.
            client: Optional pre-configured httpx.AsyncClient.
            scope: Optional standalone ScopeEngine (if context not provided).
            rate_limiter: Optional standalone RateLimiter (if context not provided).
            default_timeout: Request timeout in seconds.
            user_agent: Default User-Agent header string.
            verify_tls: Whether to verify TLS certificates.
            proxy: Optional HTTP/SOCKS proxy URL.
        """
        self.context: Optional[ScanContext] = context
        self.scope: ScopeEngine = (
            context.scope if context else (scope or ScopeEngine())
        )
        self.rate_limiter: RateLimiter = (
            context.rate_limiter
            if context
            else (rate_limiter or RateLimiter(rate=5.0, concurrency=5))
        )
        self.default_timeout: float = (
            context.config.default_timeout if context else default_timeout
        )
        self.user_agent: Optional[str] = (
            context.config.default_user_agent if context else user_agent
        )
        self.verify_tls: bool = (
            context.config.verify_tls if context else verify_tls
        )
        self.proxy: Optional[str] = proxy

        self._client: Optional[httpx.AsyncClient] = client
        self._owns_client: bool = client is None

        if self.context:
            self.context.http_engine = self

    async def get_client(self) -> httpx.AsyncClient:
        """Get or initialize the underlying httpx.AsyncClient."""
        if self._client is None or self._client.is_closed:
            self._client = create_async_client(
                config=self.context.config if self.context else None,
                user_agent=self.user_agent,
                timeout=self.default_timeout,
                verify_tls=self.verify_tls,
                proxy=self.proxy,
            )
            self._owns_client = True
        return self._client

    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        json: Optional[Any] = None,
        cookies: Optional[Dict[str, str]] = None,
        timeout: Optional[float] = None,
        follow_redirects: bool = True,
        max_redirects: int = 10,
        raise_on_scope_violation: bool = True,
    ) -> HttpResponse:
        """Send an HTTP request with strict scope enforcement and rate limiting.

        Args:
            method: HTTP method (e.g. GET, POST, HEAD, OPTIONS).
            url: Destination URL.
            headers: Optional request headers.
            params: Optional query parameters.
            data: Optional form/raw data body.
            json: Optional JSON payload.
            cookies: Optional per-request cookies.
            timeout: Optional per-request timeout in seconds.
            follow_redirects: Whether to follow in-scope redirects.
            max_redirects: Maximum number of redirects to follow.
            raise_on_scope_violation: If True, raises ScopeViolationError on out-of-scope targets.

        Returns:
            HttpResponse object.

        Raises:
            ScopeViolationError: If URL is outside authorized scope.
            RequestTimeoutError: If request times out.
            ConnectionFailedError: If connection fails.
            HttpEngineError: For general transport errors.
        """
        # 1. Scope Enforcement on initial destination
        scope_check = self.scope.check_url(url)
        if not scope_check.allowed:
            if self.context:
                self.context.stats.record_blocked()
            if raise_on_scope_violation:
                raise ScopeViolationError(url=url, reason=scope_check.reason)
            return HttpResponse(
                status_code=403,
                url=url,
                headers={"X-VulnForge-Blocked": "Scope Violation"},
                body=f"[SCOPE BLOCKED] {scope_check.reason}: {url}",
                raw_bytes=f"[SCOPE BLOCKED] {scope_check.reason}: {url}".encode("utf-8"),
                elapsed=0.0,
                request_method=method.upper(),
                request_url=url,
                request_headers=headers or {},
                history=[],
            )

        client = await self.get_client()
        req_timeout = timeout if timeout is not None else self.default_timeout

        current_method = method.upper()
        current_url = url
        current_headers = dict(headers) if headers else {}
        current_data = data
        current_json = json
        current_params = params

        history: List[str] = []
        redirect_count = 0
        total_elapsed = 0.0

        if self.context:
            self.context.start()

        while True:
            # 2. Acquire Rate Limiter slot
            async with self.rate_limiter:
                if self.context:
                    self.context.stats.record_request_sent()

                start_time = time.monotonic()
                try:
                    raw_resp = await client.request(
                        method=current_method,
                        url=current_url,
                        headers=current_headers,
                        params=current_params,
                        data=current_data,
                        json=current_json,
                        cookies=cookies,
                        timeout=req_timeout,
                    )
                    req_duration = time.monotonic() - start_time
                    total_elapsed += req_duration

                except httpx.TimeoutException:
                    if self.context:
                        self.context.stats.record_timeout()
                    raise RequestTimeoutError(url=current_url, timeout=req_timeout)

                except (httpx.ConnectError, httpx.ConnectTimeout) as e:
                    if self.context:
                        self.context.stats.record_failed()
                    raise ConnectionFailedError(url=current_url, reason=str(e))

                except httpx.HTTPError as e:
                    if self.context:
                        self.context.stats.record_failed()
                    raise HttpEngineError(f"HTTP transport error for {current_url}: {e}")

            # Read response content
            status_code = raw_resp.status_code
            resp_headers = dict(raw_resp.headers)
            body_bytes = raw_resp.content
            body_text = raw_resp.text

            # 3. Handle Redirects with Strict Scope Validation
            is_redirect_code = status_code in (301, 302, 303, 307, 308)
            location = resp_headers.get("location") or resp_headers.get("Location")

            if follow_redirects and is_redirect_code and location and redirect_count < max_redirects:
                if self.context:
                    self.context.stats.record_redirect()

                history.append(current_url)
                next_url = urljoin(current_url, location)
                redirect_count += 1

                # Check scope of redirect target!
                redirect_scope_check = self.scope.check_url(next_url)
                if not redirect_scope_check.allowed:
                    # Redirect destination is OUT OF SCOPE!
                    if self.context:
                        self.context.stats.record_blocked()

                    # Stop redirect chain safely and return the 3xx response with warning header
                    resp_headers["X-VulnForge-Redirect-Blocked"] = (
                        f"Out of scope: {next_url} ({redirect_scope_check.reason})"
                    )
                    return HttpResponse(
                        status_code=status_code,
                        url=current_url,
                        headers=resp_headers,
                        body=body_text,
                        raw_bytes=body_bytes,
                        elapsed=total_elapsed,
                        request_method=method.upper(),
                        request_url=url,
                        request_headers=headers or {},
                        history=history,
                    )

                # Redirect is within scope: update state for next hop
                current_url = next_url
                current_params = None  # Already in URL query if any

                # Adjust method according to RFC specs
                if status_code == 303 or (status_code in (301, 302) and current_method == "POST"):
                    current_method = "GET"
                    current_data = None
                    current_json = None

                continue

            # Terminal response reached
            if self.context:
                if 200 <= status_code < 300:
                    self.context.stats.record_success()
                elif status_code >= 400:
                    self.context.stats.record_http_error()

            return HttpResponse(
                status_code=status_code,
                url=current_url,
                headers=resp_headers,
                body=body_text,
                raw_bytes=body_bytes,
                elapsed=total_elapsed,
                request_method=method.upper(),
                request_url=url,
                request_headers=headers or {},
                history=history,
            )

    async def get(self, url: str, **kwargs: Any) -> HttpResponse:
        """Issue an HTTP GET request."""
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> HttpResponse:
        """Issue an HTTP POST request."""
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> HttpResponse:
        """Issue an HTTP PUT request."""
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> HttpResponse:
        """Issue an HTTP DELETE request."""
        return await self.request("DELETE", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> HttpResponse:
        """Issue an HTTP HEAD request."""
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs: Any) -> HttpResponse:
        """Issue an HTTP OPTIONS request."""
        return await self.request("OPTIONS", url, **kwargs)

    async def close(self) -> None:
        """Close the underlying HTTP client session."""
        if self._client and not self._client.is_closed and self._owns_client:
            await self._client.aclose()

    async def __aenter__(self) -> "HttpEngine":
        """Async context manager entry."""
        await self.get_client()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()
