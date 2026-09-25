"""Strict Scope Validation Engine for VulnForge."""

from dataclasses import dataclass, field
import fnmatch
import posixpath
import re
from typing import List, Optional, Set
from urllib.parse import urlparse

from vulnforge.core.exceptions import ScopeViolationError
from vulnforge.utils.normalization import normalize_domain, normalize_url


@dataclass(frozen=True)
class ScopeResult:
    """Result of a scope check."""

    allowed: bool
    url: str
    reason: str


class ScopeEngine:
    """Enforces strict target scope boundaries on all URLs, requests, and redirects."""

    def __init__(
        self,
        allowed_domains: Optional[List[str]] = None,
        excluded_domains: Optional[List[str]] = None,
        excluded_paths: Optional[List[str]] = None,
        allow_subdomains: bool = True,
        strict_ports: bool = False,
        allowed_ports: Optional[List[int]] = None,
    ):
        """Initialize ScopeEngine with allowed and excluded boundaries.

        Args:
            allowed_domains: Domains or wildcard patterns (e.g. ['example.com', '*.example.com']).
            excluded_domains: Domains or patterns strictly forbidden.
            excluded_paths: Path prefixes or patterns forbidden (e.g. ['/logout', '/api/v1/delete*']).
            allow_subdomains: If True, exact domain definitions can automatically permit subdomains if wildcarded.
            strict_ports: If True, requests are restricted to allowed_ports.
            allowed_ports: Explicit list of allowed ports (e.g. [80, 443, 8080]).
        """
        self.allowed_domains: List[str] = [
            d.strip().lower() for d in (allowed_domains or []) if d.strip()
        ]
        self.excluded_domains: List[str] = [
            d.strip().lower() for d in (excluded_domains or []) if d.strip()
        ]
        self.excluded_paths: List[str] = [
            p.strip() for p in (excluded_paths or []) if p.strip()
        ]
        self.allow_subdomains: bool = allow_subdomains
        self.strict_ports: bool = strict_ports
        self.allowed_ports: Set[int] = set(allowed_ports or [80, 443])

    def add_allowed_domain(self, domain: str) -> None:
        """Add a domain or wildcard pattern to the allowed list."""
        dom = domain.strip().lower()
        if dom and dom not in self.allowed_domains:
            self.allowed_domains.append(dom)

    def add_excluded_domain(self, domain: str) -> None:
        """Add a domain or wildcard pattern to the excluded list."""
        dom = domain.strip().lower()
        if dom and dom not in self.excluded_domains:
            self.excluded_domains.append(dom)

    def add_excluded_path(self, path: str) -> None:
        """Add a path prefix/pattern to the excluded list."""
        p = path.strip()
        if p and p not in self.excluded_paths:
            self.excluded_paths.append(p)

    def _match_domain_pattern(self, hostname: str, pattern: str) -> bool:
        """Check if hostname matches a domain pattern (exact or wildcard)."""
        hostname = normalize_domain(hostname)
        pattern = normalize_domain(pattern)

        if not pattern or not hostname:
            return False

        # Exact match
        if hostname == pattern:
            return True

        # Wildcard match (e.g. *.example.com)
        if pattern.startswith("*."):
            base_domain = pattern[2:]
            if hostname == base_domain:
                return True
            if hostname.endswith("." + base_domain):
                return True
            return fnmatch.fnmatch(hostname, pattern)

        # Standard wildcard glob
        if "*" in pattern:
            return fnmatch.fnmatch(hostname, pattern)

        return False

    def check_url(self, url: str) -> ScopeResult:
        """Check if a URL falls strictly within the authorized scope.

        Returns:
            ScopeResult indicating whether the URL is permitted and the rationale.
        """
        if not url:
            return ScopeResult(allowed=False, url=url, reason="Empty URL")

        # Parse URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            return ScopeResult(allowed=False, url=url, reason=f"Malformed URL: {e}")

        scheme = parsed.scheme.lower() if parsed.scheme else "http"
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or "/"

        if not hostname:
            return ScopeResult(allowed=False, url=url, reason="Missing hostname in URL")

        # Check port if strict
        default_port = 443 if scheme == "https" else 80
        port = parsed.port if parsed.port is not None else default_port
        if self.strict_ports and port not in self.allowed_ports:
            return ScopeResult(
                allowed=False,
                url=url,
                reason=f"Port {port} is not in allowed ports {list(self.allowed_ports)}",
            )

        # 1. Check excluded domains (highest precedence)
        for excluded_pattern in self.excluded_domains:
            if self._match_domain_pattern(hostname, excluded_pattern):
                return ScopeResult(
                    allowed=False,
                    url=url,
                    reason=f"Domain '{hostname}' matches excluded rule '{excluded_pattern}'",
                )

        # 2. Check excluded paths
        norm_path = posixpath.normpath(path)
        for excluded_path in self.excluded_paths:
            # Check prefix match
            clean_ex_path = excluded_path.rstrip("/")
            if norm_path == clean_ex_path or norm_path.startswith(clean_ex_path + "/"):
                return ScopeResult(
                    allowed=False,
                    url=url,
                    reason=f"Path '{path}' matches excluded path rule '{excluded_path}'",
                )
            if fnmatch.fnmatch(norm_path, excluded_path) or fnmatch.fnmatch(path, excluded_path):
                return ScopeResult(
                    allowed=False,
                    url=url,
                    reason=f"Path '{path}' matches excluded path pattern '{excluded_path}'",
                )

        # 3. Check allowed domains
        if not self.allowed_domains:
            # If no allowed domains defined, default deny
            return ScopeResult(
                allowed=False, url=url, reason="No allowed domains configured in scope"
            )

        is_domain_allowed = False
        matching_rule = ""
        for allowed_pattern in self.allowed_domains:
            if self._match_domain_pattern(hostname, allowed_pattern):
                is_domain_allowed = True
                matching_rule = allowed_pattern
                break

        if not is_domain_allowed:
            return ScopeResult(
                allowed=False,
                url=url,
                reason=f"Domain '{hostname}' does not match any authorized scope rules: {self.allowed_domains}",
            )

        return ScopeResult(
            allowed=True, url=url, reason=f"Matched authorized scope rule '{matching_rule}'"
        )

    def is_allowed(self, url: str) -> bool:
        """Convenience method returning boolean True/False for URL scope check."""
        return self.check_url(url).allowed

    def enforce(self, url: str) -> None:
        """Enforce scope for a URL, raising ScopeViolationError if out-of-scope.

        Args:
            url: Target or redirect URL.

        Raises:
            ScopeViolationError: If destination is outside authorized scope.
        """
        result = self.check_url(url)
        if not result.allowed:
            raise ScopeViolationError(url=url, reason=result.reason)
