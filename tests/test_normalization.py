"""Tests for URL and Domain Normalization."""

from vulnforge.utils.normalization import normalize_domain, normalize_url


def test_default_port_stripping():
    """Verify default ports :80 and :443 are stripped based on scheme."""
    assert normalize_url("http://example.com:80/path") == "http://example.com/path"
    assert normalize_url("https://example.com:443/path") == "https://example.com/path"

    # Non-standard ports should be preserved
    assert normalize_url("http://example.com:8080/path") == "http://example.com:8080/path"
    assert normalize_url("https://example.com:8443/path") == "https://example.com:8443/path"


def test_scheme_and_hostname_lowercasing():
    """Verify scheme and netloc are lowercased."""
    assert normalize_url("HTTP://EXAMPLE.COM/Path") == "http://example.com/Path"
    assert normalize_url("HTTPS://Sub.Example.Com:443/") == "https://sub.example.com/"


def test_fragment_stripping():
    """Verify URL fragments are stripped."""
    assert normalize_url("https://example.com/page#section1") == "https://example.com/page"


def test_path_normalization():
    """Verify relative path segments are properly resolved."""
    assert normalize_url("https://example.com/a/b/../c") == "https://example.com/a/c"
    assert normalize_url("https://example.com/a/./b/") == "https://example.com/a/b/"


def test_query_parameter_sorting():
    """Verify query parameters are canonically sorted."""
    assert normalize_url("https://example.com/?b=2&a=1") == "https://example.com/?a=1&b=2"
    assert normalize_url("https://example.com/?z=9&m=5&a=1") == "https://example.com/?a=1&m=5&z=9"


def test_domain_normalization():
    """Verify normalize_domain cleans hostnames and trailing dots."""
    assert normalize_domain("EXAMPLE.COM.") == "example.com"
    assert normalize_domain("api.example.com:8080") == "api.example.com"
    assert normalize_domain("http://sub.domain.com/path") == "sub.domain.com"
