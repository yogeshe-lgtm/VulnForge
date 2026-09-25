"""Page parsing orchestrator for HTML responses."""

from dataclasses import dataclass, field
from typing import Dict, List
from bs4 import BeautifulSoup

from vulnforge.crawler.forms import DiscoveredForm, extract_forms_from_html
from vulnforge.crawler.links import DiscoveredLink, extract_links_from_html


@dataclass
class PageParseResult:
    """Consolidated assets, forms, links, and metadata extracted from an HTML response."""

    url: str
    title: str = ""
    links: List[DiscoveredLink] = field(default_factory=list)
    forms: List[DiscoveredForm] = field(default_factory=list)
    scripts: List[str] = field(default_factory=list)
    stylesheets: List[str] = field(default_factory=list)
    meta_tags: Dict[str, str] = field(default_factory=dict)
    raw_html: str = ""


def parse_html_page(html_content: str, current_url: str) -> PageParseResult:
    """Parse HTML body and extract links, forms, scripts, stylesheets, and meta tags.

    Args:
        html_content: Raw response HTML string.
        current_url: URL of the response.

    Returns:
        PageParseResult object.
    """
    result = PageParseResult(url=current_url, raw_html=html_content or "")
    if not html_content or not isinstance(html_content, str):
        return result

    # 1. Extract Links
    result.links = extract_links_from_html(html_content, current_url)

    # 2. Extract Forms
    result.forms = extract_forms_from_html(html_content, current_url)

    # 3. Categorize Scripts and Stylesheets
    for link in result.links:
        if link.link_type == "script" and link.url not in result.scripts:
            result.scripts.append(link.url)
        elif link.link_type == "stylesheet" and link.url not in result.stylesheets:
            result.stylesheets.append(link.url)

    # 4. Meta Tags & Title extraction
    try:
        soup = BeautifulSoup(html_content, "html.parser")
        if soup.title and soup.title.string:
            result.title = soup.title.string.strip()

        for meta in soup.find_all("meta"):
            name = meta.get("name") or meta.get("property") or meta.get("http-equiv")
            content = meta.get("content")
            if name and content:
                result.meta_tags[name.lower()] = content.strip()
    except Exception:
        pass

    return result
