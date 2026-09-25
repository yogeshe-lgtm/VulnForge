"""Tests for robots.txt and sitemap.xml parsing."""

from vulnforge.crawler.sitemap import parse_robots_txt, parse_sitemap_xml


def test_parse_robots_txt():
    """Verify parsing robots.txt rules and sitemaps."""
    robots_content = """
    User-agent: *
    Disallow: /admin/
    Disallow: /private/secret.php
    Allow: /public/
    Sitemap: https://example.com/sitemap_index.xml
    """
    res = parse_robots_txt(robots_content, "https://example.com")

    assert "/admin/" in res.disallowed_paths
    assert "/private/secret.php" in res.disallowed_paths
    assert "/public/" in res.allowed_paths
    assert "https://example.com/sitemap_index.xml" in res.sitemaps

    assert "https://example.com/admin/" in res.discovered_urls
    assert "https://example.com/private/secret.php" in res.discovered_urls
    assert "https://example.com/public/" in res.discovered_urls


def test_parse_sitemap_xml():
    """Verify parsing sitemap XML with namespaces."""
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
    <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
        <url>
            <loc>https://example.com/page1</loc>
            <lastmod>2026-01-01</lastmod>
        </url>
        <url>
            <loc>https://example.com/page2</loc>
            <lastmod>2026-01-02</lastmod>
        </url>
        <url>
            <loc>/relative-page</loc>
        </url>
    </urlset>
    """
    urls = parse_sitemap_xml(xml_content, "https://example.com")
    assert len(urls) == 3
    assert "https://example.com/page1" in urls
    assert "https://example.com/page2" in urls
    assert "https://example.com/relative-page" in urls
