"""Tests for the Centralized HTTP Engine."""

import httpx
import pytest
from vulnforge.core.context import ScanContext
from vulnforge.core.engine import HttpEngine
from vulnforge.core.exceptions import (
    ConnectionFailedError,
    RequestTimeoutError,
    ScopeViolationError,
)
from vulnforge.core.rate_limiter import RateLimiter
from vulnforge.core.scope import ScopeEngine
from vulnforge.models.target import Target


@pytest.mark.asyncio
async def test_http_engine_blocks_out_of_scope():
    """Verify HTTP Engine blocks out-of-scope requests before dispatching."""
    scope = ScopeEngine(allowed_domains=["example.com"])
    rate_limiter = RateLimiter(rate=None, concurrency=5)
    engine = HttpEngine(scope=scope, rate_limiter=rate_limiter)

    with pytest.raises(ScopeViolationError):
        await engine.get("https://attacker.com/evil")


@pytest.mark.asyncio
async def test_http_engine_successful_request():
    """Verify HTTP Engine executes in-scope requests and captures response metadata."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=200,
            headers={"Content-Type": "application/json", "X-Custom": "Test"},
            content=b'{"status": "ok"}',
        )

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    scope = ScopeEngine(allowed_domains=["example.com"])
    engine = HttpEngine(client=mock_client, scope=scope)

    resp = await engine.get("https://example.com/api")

    assert resp.status_code == 200
    assert resp.is_success is True
    assert resp.body == '{"status": "ok"}'
    assert resp.headers.get("x-custom") == "Test"
    assert resp.url == "https://example.com/api"


@pytest.mark.asyncio
async def test_http_engine_timeout_handling():
    """Verify HTTP Engine converts timeouts into structured RequestTimeoutError."""
    def slow_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("Read timed out")

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(slow_handler))
    scope = ScopeEngine(allowed_domains=["example.com"])
    engine = HttpEngine(client=mock_client, scope=scope, default_timeout=2.0)

    with pytest.raises(RequestTimeoutError) as exc_info:
        await engine.get("https://example.com/slow")

    assert "https://example.com/slow" in str(exc_info.value)


@pytest.mark.asyncio
async def test_http_engine_in_scope_redirect():
    """Verify HTTP Engine follows in-scope redirects."""
    def redirect_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/start":
            return httpx.Response(
                status_code=302,
                headers={"Location": "https://example.com/destination"},
            )
        return httpx.Response(status_code=200, content=b"Final destination")

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(redirect_handler))
    scope = ScopeEngine(allowed_domains=["example.com"])
    engine = HttpEngine(client=mock_client, scope=scope)

    resp = await engine.get("https://example.com/start", follow_redirects=True)

    assert resp.status_code == 200
    assert resp.url == "https://example.com/destination"
    assert resp.history == ["https://example.com/start"]
    assert resp.body == "Final destination"


@pytest.mark.asyncio
async def test_http_engine_blocks_out_of_scope_redirect():
    """Verify HTTP Engine detects and halts redirects pointing outside authorized scope."""
    def malicious_redirect_handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/redirect":
            return httpx.Response(
                status_code=302,
                headers={"Location": "https://attacker.com/exfiltrate"},
            )
        return httpx.Response(status_code=200, content=b"Should not reach here")

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(malicious_redirect_handler))
    scope = ScopeEngine(allowed_domains=["example.com"])  # attacker.com is NOT allowed
    target = Target.from_url("https://example.com")
    context = ScanContext(target=target, scope=scope)
    engine = HttpEngine(client=mock_client, context=context)

    resp = await engine.get("https://example.com/redirect", follow_redirects=True)

    # Must halt at the 302 redirect response and mark blocked header
    assert resp.status_code == 302
    assert "X-VulnForge-Redirect-Blocked" in resp.headers
    assert "attacker.com" in resp.headers["X-VulnForge-Redirect-Blocked"]
    assert context.stats.requests_blocked >= 1
