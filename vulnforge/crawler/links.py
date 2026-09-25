"""Link extraction, resolution, and categorization utilities."""

from dataclasses import dataclass
from typing import List, Optional, Set
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from vulnforge.utils.normalization import normalize_url


@dataclass(frozen=True)
class DiscoveredLink:
    """Represents a hyperlink or asset discovered in HTML/DOM."""

    url: str
    tag: str
    attribute: str
    link_type: str  # page, script, stylesheet, image, iframe, canonical
    source_url: str


NON_HTTP_SCHEMES = {"mailto", "tel", "javascript", "data", "blob", "whatsapp", "file", "ftp"}


def is_crawlable_scheme(url: str) -> bool:
    """Check if URL uses http or https scheme."""
    if not url:
        return False
    parsed = urlparse(url)
    if parsed.scheme and parsed.scheme.lower() in NON_HTTP_SCHEMES:
        return False
    return True


def resolve_link(base_url: str, raw_link: str) -> Optional[str]:
    """Convert relative link to normalized absolute HTTP/HTTPS URL, stripping fragments."""
    if not raw_link or not isinstance(raw_link, str):
        return None

    raw_link = raw_link.strip()
    if not raw_link or raw_link.startswith("#"):
        return None

    if not is_crawlable_scheme(raw_link):
        return None

    try:
        abs_url = urljoin(base_url, raw_link)
        parsed = urlparse(abs_url)
        if parsed.scheme.lower() not in ("http", "https"):
            return None
        return normalize_url(abs_url)
    except Exception:
        return None


def extract_links_from_html(html_content: str, base_url: str) -> List[DiscoveredLink]:
    """Parse HTML and extract all discoverable hyperlinks and asset URLs.

    Args:
        html_content: Raw HTML text body.
        base_url: Current page URL to resolve relative paths against.

    Returns:
        List of unique DiscoveredLink objects.
    """
    if not html_content or not isinstance(html_content, str):
        return []

    try:
        soup = BeautifulSoup(html_content, "html.parser")
    except Exception:
        return []

    # Check for <base href="...">
    base_tag = soup.find("base", href=True)
    if base_tag and base_tag.get("href"):
        effective_base = urljoin(base_url, base_tag.get("href"))
    else:
        effective_base = base_url

    results: List[DiscoveredLink] = []
    seen_urls: Set[str] = set()

    def add_link(raw_val: str, tag_name: str, attr_name: str, link_type: str) -> None:
        resolved = resolve_link(effective_base, raw_val)
        if resolved and resolved not in seen_urls:
            seen_urls.add(resolved)
            results.append(
                DiscoveredLink(
                    url=resolved,
                    tag=tag_name,
                    attribute=attr_name,
                    link_type=link_type,
                    source_url=base_url,
                )
            )

    # 1. <a> href
    for tag in soup.find_all("a", href=True):
        add_link(tag["href"], "a", "href", "page")

    # 2. <link> href (stylesheets, canonical, alternate)
    for tag in soup.find_all("link", href=True):
        rel = [r.lower() for r in tag.get("rel", [])]
        if "canonical" in rel:
            add_link(tag["href"], "link", "href", "canonical")
        elif "stylesheet" in rel:
            add_link(tag["href"], "link", "href", "stylesheet")
        else:
            add_link(tag["href"], "link", "href", "link")

    # 3. <script> src
    for tag in soup.find_all("script", src=True):
        add_link(tag["src"], "script", "src", "script")

    # 4. <iframe> src
    for tag in soup.find_all("iframe", src=True):
        add_link(tag["src"], "iframe", "src", "iframe")

    # 5. <img> src / data-src
    for tag in soup.find_all("img"):
        if tag.get("src"):
            add_link(tag["src"], "img", "src", "image")
        if tag.get("data-src"):
            add_link(tag["data-src"], "img", "data-src", "image")

    # 6. <area> href
    for tag in soup.find_all("area", href=True):
        add_link(tag["href"], "area", "href", "page")

    return results
