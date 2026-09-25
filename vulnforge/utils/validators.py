"""URL and Hostname validation utilities."""

import ipaddress
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

# RFC 1123 / RFC 952 hostname regex
HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)

ALLOWED_SCHEMES = {"http", "https"}


def is_valid_hostname(host: str) -> bool:
    """Check if a string is a syntactically valid domain name or IP address.

    Args:
        host: Hostname or IP string.

    Returns:
        True if valid hostname or IP.
    """
    if not host or len(host) > 253:
        return False

    # Check if valid IP
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass

    # Check hostname regex
    return bool(HOSTNAME_REGEX.match(host))


def is_private_ip(ip_or_host: str) -> bool:
    """Check if an IP address or hostname represents a private/local network address.

    (localhost, 127.0.0.1, ::1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.)

    Args:
        ip_or_host: Hostname or IP string.

    Returns:
        True if the host is private/loopback/link-local/internal.
    """
    if not ip_or_host:
        return False

    host = ip_or_host.strip().lower()

    if host in {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}:
        return True

    if host.endswith(".local") or host.endswith(".internal") or host.endswith(".localhost"):
        return True

    try:
        ip = ipaddress.ip_address(host)
        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_unspecified
        )
    except ValueError:
        return False


def validate_port(port: int) -> bool:
    """Validate TCP port number range.

    Args:
        port: Integer port.

    Returns:
        True if port is in range 1-65535.
    """
    return isinstance(port, int) and 1 <= port <= 65535


def validate_url(url: str, allow_private: bool = True) -> Tuple[bool, Optional[str]]:
    """Validate a target URL for scheme, netloc, port, and security boundaries.

    Args:
        url: URL string to validate.
        allow_private: Whether private/localhost targets are permitted.

    Returns:
        Tuple of (is_valid, error_message). If valid, error_message is None.
    """
    if not url or not isinstance(url, str):
        return False, "URL cannot be empty."

    url = url.strip()

    if not (url.startswith("http://") or url.startswith("https://")):
        return False, f"Unsupported scheme. Only 'http://' and 'https://' are supported."

    try:
        parsed = urlparse(url)
    except Exception as e:
        return False, f"Malformed URL: {e}"

    if not parsed.scheme or parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, f"Invalid scheme '{parsed.scheme}'. Must be 'http' or 'https'."

    if not parsed.netloc:
        return False, "Missing network location (hostname/domain) in URL."

    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid or missing hostname in URL."

    if not is_valid_hostname(hostname):
        return False, f"Invalid hostname format: '{hostname}'."

    try:
        port = parsed.port
    except ValueError as e:
        return False, f"Invalid port: {e}"

    if port is not None and not validate_port(port):
        return False, f"Port {port} is out of valid range (1-65535)."

    if not allow_private and is_private_ip(hostname):
        return (
            False,
            f"Target '{hostname}' is a private/local address. Use '--allow-private' flag if testing in a local lab.",
        )

    return True, None
