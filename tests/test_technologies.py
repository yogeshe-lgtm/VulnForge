"""Tests for passive technology fingerprinting."""

from vulnforge.discovery.technologies import TechnologyFingerprinter
from vulnforge.models.response import HttpResponse


def test_detect_technologies_from_headers():
    """Verify detecting Nginx, PHP, and Cloudflare from response headers."""
    fingerprinter = TechnologyFingerprinter()
    response = HttpResponse(
        status_code=200,
        url="https://example.com",
        headers={
            "Server": "nginx/1.24.0",
            "X-Powered-By": "PHP/8.2.10",
            "CF-Ray": "89abc1234def",
        },
        body="<html><body>Hello</body></html>",
        request_method="GET",
        request_url="https://example.com",
    )

    detections = fingerprinter.analyze_response(response)
    names = {d.name: d for d in detections}

    assert "Nginx" in names
    assert names["Nginx"].version == "1.24.0"
    assert names["Nginx"].confidence >= 90

    assert "PHP" in names
    assert names["PHP"].version == "8.2.10"

    assert "Cloudflare" in names


def test_detect_frameworks_from_dom_and_meta():
    """Verify detecting Next.js, React, and WordPress from HTML/meta/DOM markers."""
    fingerprinter = TechnologyFingerprinter()
    response = HttpResponse(
        status_code=200,
        url="https://example.com",
        headers={},
        body='<html><head><meta name="generator" content="WordPress 6.4.2" /></head><div id="__next"><div data-reactroot="">Content</div></div></html>',
        request_method="GET",
        request_url="https://example.com",
    )

    detections = fingerprinter.analyze_response(
        response,
        meta_tags={"generator": "WordPress 6.4.2"},
    )
    names = {d.name: d for d in detections}

    assert "WordPress" in names
    assert names["WordPress"].version == "6.4.2"
    assert "React" in names
    assert "Next.js" in names


def test_detect_from_cookies():
    """Verify detecting Laravel from session cookie."""
    fingerprinter = TechnologyFingerprinter()
    response = HttpResponse(
        status_code=200,
        url="https://example.com",
        headers={"Set-Cookie": "laravel_session=eyJpdiI6...; path=/"},
        body="<html></html>",
        request_method="GET",
        request_url="https://example.com",
    )
    detections = fingerprinter.analyze_response(response)
    names = {d.name for d in detections}
    assert "Laravel" in names
    assert "PHP" in names
