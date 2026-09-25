"""HTTP response data model."""

from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class HttpResponse(BaseModel):
    """Represents a captured HTTP response returned by the VulnForge engine."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    status_code: int = Field(..., description="HTTP response status code")
    url: str = Field(..., description="Final response URL after any redirects")
    headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    body: str = Field(default="", description="Decoded text response body")
    raw_bytes: bytes = Field(default=b"", description="Raw response payload bytes")
    elapsed: float = Field(default=0.0, description="Response elapsed time in seconds")
    request_method: str = Field(..., description="Original request method")
    request_url: str = Field(..., description="Original request URL")
    request_headers: Dict[str, str] = Field(default_factory=dict, description="Sent request headers")
    history: List[str] = Field(
        default_factory=list, description="Chain of URLs traversed during redirects"
    )

    @property
    def is_success(self) -> bool:
        """Return True if status code is in 2xx range."""
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        """Return True if status code is in 3xx range."""
        return 300 <= self.status_code < 400

    @property
    def is_client_error(self) -> bool:
        """Return True if status code is in 4xx range."""
        return 400 <= self.status_code < 500

    @property
    def is_server_error(self) -> bool:
        """Return True if status code is in 5xx range."""
        return 500 <= self.status_code < 600

    @property
    def is_error(self) -> bool:
        """Return True if status code is 4xx or 5xx."""
        return self.status_code >= 400

    @property
    def content_type(self) -> str:
        """Return the Content-Type header value, if present."""
        for k, v in self.headers.items():
            if k.lower() == "content-type":
                return v
        return ""
