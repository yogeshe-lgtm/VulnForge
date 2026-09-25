"""HTTP client session factory and lifecycle management."""

from typing import Dict, Optional
import httpx

from vulnforge.core.config import VulnForgeConfig


def create_async_client(
    config: Optional[VulnForgeConfig] = None,
    user_agent: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    cookies: Optional[Dict[str, str]] = None,
    proxy: Optional[str] = None,
    timeout: Optional[float] = None,
    verify_tls: Optional[bool] = None,
    max_connections: int = 100,
    max_keepalive_connections: int = 20,
) -> httpx.AsyncClient:
    """Create a configured httpx.AsyncClient with connection pooling and security defaults.

    Args:
        config: Base VulnForge configuration.
        user_agent: Custom User-Agent header string.
        headers: Additional default headers.
        cookies: Default cookies.
        proxy: Proxy URL (e.g. http://127.0.0.1:8080).
        timeout: Request timeout in seconds.
        verify_tls: Whether to verify SSL/TLS certificates.
        max_connections: Maximum total connections in pool.
        max_keepalive_connections: Maximum idle keepalive connections.

    Returns:
        Configured httpx.AsyncClient instance.
    """
    cfg = config or VulnForgeConfig()

    ua = user_agent or cfg.default_user_agent
    req_headers = {"User-Agent": ua, "Accept": "*/*"}
    if headers:
        req_headers.update(headers)

    req_timeout = timeout if timeout is not None else cfg.default_timeout
    req_verify = verify_tls if verify_tls is not None else cfg.verify_tls

    limits = httpx.Limits(
        max_connections=max_connections,
        max_keepalive_connections=max_keepalive_connections,
        keepalive_expiry=30.0,
    )

    client_kwargs: Dict[str, object] = {
        "headers": req_headers,
        "timeout": httpx.Timeout(req_timeout),
        "verify": req_verify,
        "limits": limits,
        "follow_redirects": False,  # Manual redirect loop in HttpEngine enforces scope
    }

    if cookies:
        client_kwargs["cookies"] = cookies

    if proxy:
        client_kwargs["proxy"] = proxy

    return httpx.AsyncClient(**client_kwargs)
