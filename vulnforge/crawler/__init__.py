"""VulnForge Web Crawler and HTML/Asset parser package."""

from vulnforge.crawler.crawler import CrawlResult, WebCrawler
from vulnforge.crawler.forms import DiscoveredForm, FormField, extract_forms_from_html
from vulnforge.crawler.links import DiscoveredLink, extract_links_from_html, resolve_link
from vulnforge.crawler.parser import PageParseResult, parse_html_page
from vulnforge.crawler.sitemap import RobotsResult, parse_robots_txt, parse_sitemap_xml

__all__ = [
    "WebCrawler",
    "CrawlResult",
    "DiscoveredLink",
    "extract_links_from_html",
    "resolve_link",
    "DiscoveredForm",
    "FormField",
    "extract_forms_from_html",
    "PageParseResult",
    "parse_html_page",
    "RobotsResult",
    "parse_robots_txt",
    "parse_sitemap_xml",
]
