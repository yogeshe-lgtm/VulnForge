"""Tests for URL and target validation."""

import pytest
from vulnforge.core.exceptions import TargetValidationError
from vulnforge.models.target import Target
from vulnforge.utils.validators import (
    is_private_ip,
    is_valid_hostname,
    validate_port,
    validate_url,
)


def test_validate_valid_urls():
    """Verify valid HTTP/HTTPS URLs pass validation."""
    valid, err = validate_url("https://example.com")
    assert valid is True
    assert err is None

    valid, err = validate_url("http://api.example.com:8080/v1?test=1")
    assert valid is True
    assert err is None


def test_validate_invalid_schemes():
    """Verify non-HTTP schemes are rejected."""
    valid, err = validate_url("ftp://example.com")
    assert valid is False
    assert "Unsupported scheme" in err

    valid, err = validate_url("javascript:alert(1)")
    assert valid is False


def test_validate_invalid_ports():
    """Verify out-of-range ports are rejected."""
    assert validate_port(80) is True
    assert validate_port(443) is True
    assert validate_port(65535) is True
    assert validate_port(0) is False
    assert validate_port(70000) is False

    valid, err = validate_url("https://example.com:70000")
    assert valid is False
    assert "out of range" in (err or "").lower()


def test_private_ip_detection():
    """Verify private/loopback IP identification."""
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("localhost") is True
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.5") is True
    assert is_private_ip("93.184.216.34") is False
    assert is_private_ip("example.com") is False


def test_target_model_creation():
    """Verify Target.from_url creates normalized Target object."""
    target = Target.from_url("https://EXAMPLE.com:443/test/../api/?b=2&a=1")
    assert target.hostname == "example.com"
    assert target.scheme == "https"
    assert target.port == 443
    assert target.normalized_url == "https://example.com/api/?a=1&b=2"
    assert "example.com" in target.scope


def test_target_model_invalid_raises():
    """Verify Target.from_url raises TargetValidationError on invalid URL."""
    with pytest.raises(TargetValidationError):
        Target.from_url("not_a_valid_url")
