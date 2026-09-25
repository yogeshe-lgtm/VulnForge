"""Target model definition and validation."""

from typing import List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field

from vulnforge.core.exceptions import TargetValidationError
from vulnforge.utils.normalization import normalize_url
from vulnforge.utils.validators import is_private_ip, validate_url


class Target(BaseModel):
    """Represents a validated and normalized scan target."""

    model_config = ConfigDict(frozen=True)

    raw_url: str = Field(..., description="Original user-supplied URL")
    scheme: str = Field(..., description="URL scheme (http or https)")
    hostname: str = Field(..., description="Target hostname or IP")
    port: int = Field(..., description="Target port number (e.g. 80, 443)")
    path: str = Field(default="/", description="URL path component")
    query: str = Field(default="", description="URL query string")
    normalized_url: str = Field(..., description="Canonical normalized URL")
    scope: List[str] = Field(default_factory=list, description="Associated allowed domain scopes")
    scan_profile: str = Field(default="safe", description="Scan profile (e.g., safe, standard)")
    is_private: bool = Field(default=False, description="Whether hostname is private/local")

    @classmethod
    def from_url(
        cls,
        url: str,
        scope: Optional[List[str]] = None,
        scan_profile: str = "safe",
        allow_private: bool = True,
    ) -> "Target":
        """Create a validated Target instance from a URL string.

        Args:
            url: Target URL string.
            scope: Optional list of in-scope domains/wildcards.
            scan_profile: Scan safety profile.
            allow_private: Whether private/loopback IPs are allowed.

        Returns:
            Validated Target instance.

        Raises:
            TargetValidationError: If URL is invalid or malformed.
        """
        if not url:
            raise TargetValidationError("Target URL cannot be empty.")

        is_valid, err = validate_url(url, allow_private=allow_private)
        if not is_valid:
            raise TargetValidationError(f"Invalid target URL: {err}")

        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()

        default_port = 443 if scheme == "https" else 80
        port = parsed.port if parsed.port is not None else default_port

        norm_url = normalize_url(url)
        norm_parsed = urlparse(norm_url)
        path = norm_parsed.path or "/"
        query = norm_parsed.query or ""

        # Default scope to target hostname and wildcard if none provided
        scope_list = list(scope) if scope else [hostname, f"*.{hostname}"]

        is_priv = is_private_ip(hostname)

        return cls(
            raw_url=url.strip(),
            scheme=scheme,
            hostname=hostname,
            port=port,
            path=path,
            query=query,
            normalized_url=norm_url,
            scope=scope_list,
            scan_profile=scan_profile,
            is_private=is_priv,
        )

    def base_url(self) -> str:
        """Return the base scheme://hostname:port root URL."""
        if (self.scheme == "http" and self.port == 80) or (
            self.scheme == "https" and self.port == 443
        ):
            return f"{self.scheme}://{self.hostname}"
        return f"{self.scheme}://{self.hostname}:{self.port}"
