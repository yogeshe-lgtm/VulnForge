"""Tests for the Scope Validation Engine."""

import pytest
from vulnforge.core.exceptions import ScopeViolationError
from vulnforge.core.scope import ScopeEngine, ScopeResult


def test_exact_domain_scope():
    """Verify that exact domain scope only allows the specified domain."""
    scope = ScopeEngine(allowed_domains=["example.com"])

    assert scope.is_allowed("http://example.com") is True
    assert scope.is_allowed("https://example.com/api/v1") is True
    assert scope.is_allowed("http://example.com:8080/test") is True

    # Subdomains should not be allowed for exact domain rule
    assert scope.is_allowed("http://api.example.com") is False
    assert scope.is_allowed("http://evil.com") is False
    assert scope.is_allowed("http://example.org") is False


def test_wildcard_subdomain_scope():
    """Verify wildcard subdomain matching rules."""
    scope = ScopeEngine(allowed_domains=["*.example.com"])

    assert scope.is_allowed("https://example.com") is True
    assert scope.is_allowed("https://api.example.com") is True
    assert scope.is_allowed("https://auth.sub.example.com/login") is True
    assert scope.is_allowed("https://notexample.com") is False
    assert scope.is_allowed("https://example.com.attacker.com") is False


def test_excluded_domain_precedence():
    """Verify that excluded domains override allowed patterns."""
    scope = ScopeEngine(
        allowed_domains=["*.example.com"],
        excluded_domains=["internal.example.com", "logout.example.com"],
    )

    assert scope.is_allowed("https://api.example.com") is True
    assert scope.is_allowed("https://app.example.com") is True
    assert scope.is_allowed("https://internal.example.com") is False
    assert scope.is_allowed("https://logout.example.com") is False


def test_excluded_paths():
    """Verify that excluded path patterns block matching requests."""
    scope = ScopeEngine(
        allowed_domains=["example.com"],
        excluded_paths=["/logout", "/api/v1/delete*", "/admin/*"],
    )

    assert scope.is_allowed("https://example.com/profile") is True
    assert scope.is_allowed("https://example.com/api/v1/users") is True
    assert scope.is_allowed("https://example.com/logout") is False
    assert scope.is_allowed("https://example.com/logout/") is False
    assert scope.is_allowed("https://example.com/api/v1/delete-account") is False
    assert scope.is_allowed("https://example.com/admin/settings") is False


def test_enforce_raises_scope_violation():
    """Verify that enforce() raises ScopeViolationError on out-of-scope targets."""
    scope = ScopeEngine(allowed_domains=["example.com"])

    # In-scope should not raise
    scope.enforce("https://example.com/login")

    # Out-of-scope must raise
    with pytest.raises(ScopeViolationError) as exc_info:
        scope.enforce("https://attacker.com/evil")
    assert "attacker.com" in str(exc_info.value)


def test_empty_scope_default_denies():
    """Verify that an empty scope configuration blocks all requests."""
    scope = ScopeEngine(allowed_domains=[])
    assert scope.is_allowed("https://example.com") is False
