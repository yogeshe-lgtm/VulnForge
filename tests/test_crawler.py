"""Tests for the Asynchronous Web Crawler."""

import httpx
import pytest
from vulnforge.core.context import ScanContext
from vulnforge.core.engine import HttpEngine
from vulnforge.core.rate_limiter import RateLimiter
from vulnforge.core.scope import ScopeEngine
from vulnforge.crawler.crawler import WebCrawler
from vulnforge.models.target import Target


@pytest.mark.asyncio
async def test_crawler_depth_restriction():
    """Verify crawler strictly respects max_depth limit."""
    pages = {
        "https://example.com/": """
            <html><body>
                <a href="/page1">Page 1 (Depth 1)</a>
                <a href="/page1">Duplicate Page 1 Link</a>
                <a href="https://external.com/out">External</a>
            </body></html>
        """,
        "https://example.com/page1": """
            <html><body>
                <a href="/page2">Page 2 (Depth 2)</a>
            </body></html>
        """,
        "https://example.com/page2": """
            <html><body>
                <a href="/page3">Page 3 (Depth 3)</a>
            </body></html>
        """,
        "https://example.com/page3": """
            <html><body>
                <a href="/page4">Page 4 (Depth 4)</a>
            </body></html>
        """,
    }

    def transport_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        content = pages.get(url, "<html><body>404 Not Found</body></html>")
        return httpx.Response(
            status_code=200 if url in pages else 404,
            headers={"Content-Type": "text/html"},
            content=content.encode("utf-8"),
        )

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(transport_handler))
    target = Target.from_url("https://example.com/")
    scope = ScopeEngine(allowed_domains=["example.com"])
    rate_limiter = RateLimiter(rate=None, concurrency=5)
    context = ScanContext(target=target, scope=scope, rate_limiter=rate_limiter)
    engine = HttpEngine(client=mock_client, context=context)

    # Crawl with max_depth = 2
    crawler = WebCrawler(context=context, max_depth=2)
    result = await crawler.crawl()

    # Root (0), /page1 (1), /page2 (2) should be visited
    assert "https://example.com/" in result.visited_urls
    assert "https://example.com/page1" in result.visited_urls
    assert "https://example.com/page2" in result.visited_urls

    # /page3 is depth 3 -> should NOT be visited
    assert "https://example.com/page3" not in result.visited_urls

    # https://external.com/out is out of scope -> should be registered in out_of_scope_urls
    assert "https://external.com/out" in result.out_of_scope_urls
    assert "https://external.com/out" not in result.visited_urls


@pytest.mark.asyncio
async def test_crawler_form_and_parameter_extraction():
    """Verify crawler discovers forms and query parameters."""
    site = {
        "https://example.com/": """
            <html><body>
                <a href="/items?category=books&page=1">Books</a>
                <form action="/login" method="POST">
                    <input type="text" name="username" />
                    <input type="password" name="password" />
                </form>
            </body></html>
        """,
        "https://example.com/items?category=books&page=1": """
            <html><body><h1>Books list</h1></body></html>
        """,
        "https://example.com/login": """
            <html><body>Login Page</body></html>
        """,
    }

    def transport_handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        content = site.get(url, "<html><body>404</body></html>")
        return httpx.Response(
            status_code=200,
            headers={"Content-Type": "text/html"},
            content=content.encode("utf-8"),
        )

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(transport_handler))
    target = Target.from_url("https://example.com/")
    scope = ScopeEngine(allowed_domains=["example.com"])
    rate_limiter = RateLimiter(rate=None, concurrency=5)
    context = ScanContext(target=target, scope=scope, rate_limiter=rate_limiter)
    engine = HttpEngine(client=mock_client, context=context)

    crawler = WebCrawler(context=context, max_depth=2)
    result = await crawler.crawl()

    # Form should be discovered
    assert len(result.forms) == 1
    assert result.forms[0].action == "https://example.com/login"

    # Parameters should include category, page, username, password
    param_names = {p.name for p in result.parameters}
    assert "category" in param_names
    assert "page" in param_names
    assert "username" in param_names
    assert "password" in param_names
