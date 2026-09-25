"""Tests for static JavaScript analysis and endpoint discovery."""

from vulnforge.discovery.javascript import extract_endpoints_from_js


def test_extract_endpoints_from_js_code():
    """Verify extracting API endpoints, paths, and fetch calls from JS."""
    js_code = """
    // API routes
    const API_URL = "/api/v1/users";
    const AUTH_ENDPOINT = "/auth/login?redirect=/dashboard";
    const GRAPHQL_PATH = "/graphql";

    async function getUserData(id) {
        const res = await fetch("/api/v2/profile?user_id=" + id);
        return res.json();
    }

    function sendBeacon() {
        axios.post("/analytics/track", { event: "click" });
        $.get("/search?q=test");
    }
    """
    res = extract_endpoints_from_js(
        js_content=js_code,
        script_url="https://example.com/static/app.js",
        base_target_url="https://example.com",
    )

    discovered_urls = {ep.url for ep in res.discovered_endpoints}

    assert "https://example.com/api/v1/users" in discovered_urls
    assert "https://example.com/graphql" in discovered_urls
    assert (
        "https://example.com/auth/login?redirect=%2Fdashboard" in discovered_urls
        or "https://example.com/auth/login?redirect=/dashboard" in discovered_urls
    )
    assert any("api/v2/profile" in u for u in discovered_urls)
    assert "https://example.com/analytics/track" in discovered_urls
    assert "https://example.com/search?q=test" in discovered_urls

    # Check extracted parameters
    param_names = {p.name for p in res.discovered_parameters}
    assert "redirect" in param_names
    assert "q" in param_names


def test_ignore_false_positive_js_tokens():
    """Verify non-route tokens are ignored."""
    js_code = 'const mime = "text/javascript"; const strict = "use strict"; const img = "logo.png";'
    res = extract_endpoints_from_js(js_code, "https://example.com/app.js", "https://example.com")
    discovered_urls = {ep.url for ep in res.discovered_endpoints}
    assert "https://example.com/text/javascript" not in discovered_urls
