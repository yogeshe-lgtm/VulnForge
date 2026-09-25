"""Asynchronous Web Crawler with Scope Enforcement and Depth Tracking."""

import asyncio
from collections import deque
from dataclasses import dataclass, field
from typing import Callable, Deque, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlparse

from vulnforge.core.context import ScanContext
from vulnforge.core.engine import HttpEngine
from vulnforge.core.exceptions import (
    ConnectionFailedError,
    RequestTimeoutError,
    ScopeViolationError,
)
from vulnforge.crawler.forms import DiscoveredForm
from vulnforge.crawler.links import DiscoveredLink
from vulnforge.crawler.parser import PageParseResult, parse_html_page
from vulnforge.crawler.sitemap import parse_robots_txt, parse_sitemap_xml
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter, ParameterLocation
from vulnforge.utils.normalization import normalize_url


@dataclass
class CrawlResult:
    """Aggregated outcome of a web crawl execution."""

    visited_urls: Set[str] = field(default_factory=set)
    failed_urls: Dict[str, str] = field(default_factory=dict)
    out_of_scope_urls: Set[str] = field(default_factory=set)
    endpoints: List[Endpoint] = field(default_factory=list)
    parameters: List[Parameter] = field(default_factory=list)
    forms: List[DiscoveredForm] = field(default_factory=list)
    scripts: Set[str] = field(default_factory=set)
    page_results: Dict[str, PageParseResult] = field(default_factory=dict)


class WebCrawler:
    """High-performance async web crawler respecting scope, rate-limiting, and depth limits."""

    def __init__(
        self,
        context: ScanContext,
        max_depth: int = 3,
        max_pages: int = 250,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ):
        """Initialize WebCrawler.

        Args:
            context: Active scan context containing HttpEngine, ScopeEngine, and stats.
            max_depth: Maximum crawl recursion depth (default 3).
            max_pages: Upper bound on total pages crawled to prevent runaway jobs.
            progress_callback: Optional callable(url, current_depth, total_visited).
        """
        self.context: ScanContext = context
        self.http_engine: HttpEngine = context.http_engine or HttpEngine(context=context)
        self.max_depth: int = max_depth
        self.max_pages: int = max_pages
        self.progress_callback: Optional[Callable[[str, int, int], None]] = progress_callback

        self.queue: Deque[Tuple[str, int, str]] = deque()  # (url, depth, source)
        self.seen_urls: Set[str] = set()
        self.result: CrawlResult = CrawlResult()
        self._endpoints_map: Dict[Tuple[str, str], Endpoint] = {}
        self._params_map: Dict[str, Parameter] = {}

    def _add_endpoint(self, endpoint: Endpoint) -> None:
        """Add or update an endpoint in deduplicated inventory."""
        key = (endpoint.url, endpoint.method)
        if key not in self._endpoints_map:
            self._endpoints_map[key] = endpoint
            self.result.endpoints.append(endpoint)
        else:
            # Merge parameters
            existing = self._endpoints_map[key]
            for param in endpoint.parameters:
                existing.add_parameter(param)

    def _add_parameter(self, param: Parameter) -> None:
        """Add a parameter to global inventory."""
        if param.identifier not in self._params_map:
            self._params_map[param.identifier] = param
            self.result.parameters.append(param)

    def _extract_query_params(self, url: str) -> List[Parameter]:
        """Extract query string parameters from a URL."""
        parsed = urlparse(url)
        if not parsed.query:
            return []
        params = []
        base_endpoint_url = normalize_url(url.split("?")[0])
        for key, val in parse_qsl(parsed.query, keep_blank_values=True):
            param = Parameter(
                name=key,
                location=ParameterLocation.QUERY,
                param_type="string",
                sample_value=val,
                endpoint_url=base_endpoint_url,
                source="HTML",
            )
            params.append(param)
            self._add_parameter(param)
        return params

    def enqueue(self, url: str, depth: int = 0, source: str = "HTML") -> bool:
        """Validate and enqueue a URL for crawling.

        Returns:
            True if URL was newly queued, False if skipped (already seen, out of scope, etc.).
        """
        if not url or depth > self.max_depth or len(self.seen_urls) >= self.max_pages:
            return False

        norm_url = normalize_url(url)
        if not norm_url:
            return False

        # Scope Check
        if not self.context.scope.is_allowed(norm_url):
            self.result.out_of_scope_urls.add(norm_url)
            return False

        if norm_url in self.seen_urls:
            return False

        self.seen_urls.add(norm_url)
        self.queue.append((norm_url, depth, source))
        return True

    async def _crawl_robots_and_sitemap(self, root_url: str) -> None:
        """Check /robots.txt and /sitemap.xml for target routes."""
        parsed = urlparse(root_url)
        base_root = f"{parsed.scheme}://{parsed.netloc}"

        # 1. Fetch robots.txt
        robots_url = f"{base_root}/robots.txt"
        if self.context.scope.is_allowed(robots_url):
            try:
                resp = await self.http_engine.get(robots_url, follow_redirects=True)
                if resp.is_success and "text" in resp.content_type.lower():
                    robots_data = parse_robots_txt(resp.body, base_root)
                    for disc_url in robots_data.discovered_urls:
                        self.enqueue(disc_url, depth=1, source="ROBOTS")
                    for sitemap_url in robots_data.sitemaps:
                        if self.context.scope.is_allowed(sitemap_url):
                            try:
                                s_resp = await self.http_engine.get(sitemap_url)
                                if s_resp.is_success:
                                    sitemap_urls = parse_sitemap_xml(s_resp.body, base_root)
                                    for s_url in sitemap_urls:
                                        self.enqueue(s_url, depth=1, source="SITEMAP")
                            except Exception:
                                pass
            except Exception:
                pass

        # 2. Check /sitemap.xml directly if not already found
        sitemap_direct = f"{base_root}/sitemap.xml"
        if self.context.scope.is_allowed(sitemap_direct) and sitemap_direct not in self.seen_urls:
            try:
                s_resp = await self.http_engine.get(sitemap_direct)
                if s_resp.is_success:
                    sitemap_urls = parse_sitemap_xml(s_resp.body, base_root)
                    for s_url in sitemap_urls:
                        self.enqueue(s_url, depth=1, source="SITEMAP")
            except Exception:
                pass

    async def crawl(self, seed_url: Optional[str] = None) -> CrawlResult:
        """Execute the asynchronous crawl lifecycle.

        Args:
            seed_url: Starting URL. Defaults to target normalized URL in context.

        Returns:
            CrawlResult containing all discovered endpoints, parameters, forms, and pages.
        """
        start_url = seed_url or self.context.target.normalized_url

        # Initial enqueue
        self.enqueue(start_url, depth=0, source="USER")

        # Check robots.txt and sitemaps early
        await self._crawl_robots_and_sitemap(start_url)

        while self.queue and not self.context.is_cancelled:
            if len(self.result.visited_urls) >= self.max_pages:
                break

            current_url, depth, source = self.queue.popleft()

            if current_url in self.result.visited_urls:
                continue

            self.result.visited_urls.add(current_url)

            if self.progress_callback:
                self.progress_callback(current_url, depth, len(self.result.visited_urls))

            # Fetch page
            try:
                resp = await self.http_engine.get(current_url, follow_redirects=True)
            except ScopeViolationError:
                self.result.out_of_scope_urls.add(current_url)
                continue
            except (RequestTimeoutError, ConnectionFailedError) as e:
                self.result.failed_urls[current_url] = str(e)
                continue
            except Exception as e:
                self.result.failed_urls[current_url] = f"Error: {e}"
                continue

            # Extract Query Parameters
            query_params = self._extract_query_params(current_url)

            # Record Endpoint
            endpoint = Endpoint.from_url(
                url=current_url,
                method="GET",
                source=source,
                status_code=resp.status_code,
                content_type=resp.content_type,
                response_size=len(resp.raw_bytes),
                parameters=query_params,
            )
            self._add_endpoint(endpoint)

            # Process HTML content
            content_type = resp.content_type.lower() if resp.content_type else ""
            is_html = "text/html" in content_type or (not content_type and "<html" in resp.body.lower())

            if is_html and resp.body:
                page_parse = parse_html_page(resp.body, resp.url)
                self.result.page_results[current_url] = page_parse

                # 1. Process discovered forms
                for form in page_parse.forms:
                    self.result.forms.append(form)
                    form_params = form.to_parameters()
                    for fp in form_params:
                        self._add_parameter(fp)

                    form_endpoint = Endpoint.from_url(
                        url=form.action,
                        method=form.method,
                        source="FORM",
                        parameters=form_params,
                    )
                    self._add_endpoint(form_endpoint)

                    # Enqueue form action for crawling if GET
                    if form.method == "GET" and depth + 1 <= self.max_depth:
                        self.enqueue(form.action, depth=depth + 1, source="FORM")

                # 2. Process discovered scripts
                for script_url in page_parse.scripts:
                    self.result.scripts.add(script_url)

                # 3. Enqueue page links if within depth limit
                if depth + 1 <= self.max_depth:
                    for link in page_parse.links:
                        if link.link_type == "page":
                            self.enqueue(link.url, depth=depth + 1, source="HTML")

        return self.result
