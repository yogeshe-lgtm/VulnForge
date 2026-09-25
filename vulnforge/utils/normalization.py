"""URL and Domain normalization utilities."""

import posixpath
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def normalize_domain(domain: str) -> str:
    """Normalize a domain or hostname: lowercases, strips port if present, strips trailing dot.

    Args:
        domain: Domain or hostname string (e.g. 'Example.COM:8080.', 'api.sub.domain.com')

    Returns:
        Clean, lowercased hostname (e.g. 'example.com', 'api.sub.domain.com')
    """
    if not domain:
        return ""

    domain = domain.strip().lower()

    # If domain has scheme prefix by accident, strip it
    if "://" in domain:
        domain = urlparse(domain).netloc

    # Strip trailing dots (DNS root notation)
    domain = domain.rstrip(".")

    # Remove port if present
    if ":" in domain:
        # Check if it's an IPv6 address
        if domain.startswith("[") and "]" in domain:
            # IPv6 format [::1]:8080
            closing_idx = domain.find("]")
            domain = domain[1:closing_idx]
        elif domain.count(":") == 1:
            # IPv4 or domain with port
            domain = domain.split(":", 1)[0]

    return domain


def normalize_url(url: str, sort_params: bool = True) -> str:
    """Normalize a URL to its canonical form for consistent comparison and deduplication.

    Transformations:
    - Strips leading/trailing whitespace
    - Lowercases scheme and netloc (hostname + port)
    - Removes standard default ports (:80 for http, :443 for https)
    - Resolves relative path segments ('.' and '..')
    - Preserves trailing slash semantics on path
    - Normalizes and optionally sorts query parameters
    - Strips fragment identifiers

    Args:
        url: Raw URL string.
        sort_params: Whether to sort query string parameters alphabetically.

    Returns:
        Normalized canonical URL string.
    """
    if not url:
        return ""

    url = url.strip()

    # If missing scheme, default to http:// for parsing
    has_scheme = "://" in url
    if not has_scheme:
        url = "http://" + url

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    # Extract hostname and port
    hostname = parsed.hostname.lower() if parsed.hostname else ""
    port = parsed.port

    # Remove standard default ports
    if port:
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            netloc = hostname
        else:
            if ":" in hostname and not hostname.startswith("["):
                # IPv6
                netloc = f"[{hostname}]:{port}"
            else:
                netloc = f"{hostname}:{port}"
    else:
        netloc = hostname

    # Path normalization
    path = parsed.path or "/"
    had_trailing_slash = path.endswith("/") and path != "/"

    # Normalize dot segments in path
    segments = path.split("/")
    norm_segments = []
    for seg in segments:
        if seg == "." or seg == "":
            continue
        elif seg == "..":
            if norm_segments:
                norm_segments.pop()
        else:
            norm_segments.append(seg)

    norm_path = "/" + "/".join(norm_segments)
    if had_trailing_slash and not norm_path.endswith("/"):
        norm_path += "/"

    # Query normalization
    query = ""
    if parsed.query:
        query_tuples = parse_qsl(parsed.query, keep_blank_values=True)
        if sort_params:
            query_tuples.sort(key=lambda item: item[0])
        query = urlencode(query_tuples)

    # Reconstruct without fragment
    normalized = urlunparse((scheme, netloc, norm_path, "", query, ""))
    return normalized
