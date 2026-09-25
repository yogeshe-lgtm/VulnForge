"""Robots.txt and Sitemap.xml parser for discovery."""

from dataclasses import dataclass, field
import re
from typing import List, Set
from urllib.parse import urljoin
import xml.etree.ElementTree as ET

from vulnforge.utils.normalization import normalize_url


@dataclass
class RobotsResult:
    """Discovered paths and sitemaps from robots.txt."""

    disallowed_paths: List[str] = field(default_factory=list)
    allowed_paths: List[str] = field(default_factory=list)
    sitemaps: List[str] = field(default_factory=list)
    discovered_urls: List[str] = field(default_factory=list)


def parse_robots_txt(content: str, base_url: str) -> RobotsResult:
    """Parse robots.txt content to extract disallowed/allowed routes and sitemap pointers.

    Args:
        content: Text content of /robots.txt.
        base_url: Target base URL (e.g. https://example.com).

    Returns:
        RobotsResult containing parsed rules and full target URLs.
    """
    result = RobotsResult()
    if not content or not isinstance(content, str):
        return result

    seen_urls: Set[str] = set()

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if ":" not in line:
            continue

        directive, val = line.split(":", 1)
        directive = directive.strip().lower()
        val = val.strip()

        if not val:
            continue

        if directive == "disallow":
            result.disallowed_paths.append(val)
            full_url = normalize_url(urljoin(base_url, val))
            if full_url and full_url not in seen_urls:
                seen_urls.add(full_url)
                result.discovered_urls.append(full_url)

        elif directive == "allow":
            result.allowed_paths.append(val)
            full_url = normalize_url(urljoin(base_url, val))
            if full_url and full_url not in seen_urls:
                seen_urls.add(full_url)
                result.discovered_urls.append(full_url)

        elif directive == "sitemap":
            sitemap_url = normalize_url(urljoin(base_url, val))
            if sitemap_url and sitemap_url not in result.sitemaps:
                result.sitemaps.append(sitemap_url)

    return result


def parse_sitemap_xml(xml_content: str, base_url: str) -> List[str]:
    """Parse sitemap.xml to extract all <loc> URL nodes.

    Handles XML namespaces automatically.

    Args:
        xml_content: Sitemap XML text content.
        base_url: Target base URL for resolving relative entries if any.

    Returns:
        List of normalized canonical URLs extracted from sitemap.
    """
    if not xml_content or not isinstance(xml_content, str):
        return []

    discovered: List[str] = []
    seen: Set[str] = set()

    # Clean potential XML declaration whitespace
    xml_content = xml_content.strip()

    try:
        root = ET.fromstring(xml_content)
        # Match any <loc> tag regardless of XML namespace
        for elem in root.iter():
            tag_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if tag_name.lower() == "loc" and elem.text:
                loc_text = elem.text.strip()
                if loc_text:
                    resolved = normalize_url(urljoin(base_url, loc_text))
                    if resolved and resolved not in seen:
                        seen.add(resolved)
                        discovered.append(resolved)
    except Exception:
        # Fallback to regex if XML is malformed
        loc_matches = re.findall(r"<loc>(.*?)</loc>", xml_content, re.IGNORECASE)
        for loc in loc_matches:
            loc = loc.strip()
            if loc:
                resolved = normalize_url(urljoin(base_url, loc))
                if resolved and resolved not in seen:
                    seen.add(resolved)
                    discovered.append(resolved)

    return discovered
