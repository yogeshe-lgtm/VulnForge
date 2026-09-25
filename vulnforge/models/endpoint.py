"""Endpoint data model for discovered routes and URLs."""

from datetime import datetime, timezone
from typing import List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from vulnforge.models.parameter import Parameter


class Endpoint(BaseModel):
    """Represents a discovered web application route or HTTP resource."""

    url: str = Field(..., description="Canonical endpoint URL")
    scheme: str = Field(..., description="HTTP scheme (http or https)")
    host: str = Field(..., description="Hostname of the endpoint")
    path: str = Field(default="/", description="Resource path")
    method: str = Field(default="GET", description="HTTP Method (GET, POST, etc.)")
    parameters: List[Parameter] = Field(
        default_factory=list, description="Associated parameters discovered on this endpoint"
    )
    content_type: Optional[str] = Field(default=None, description="Response Content-Type header")
    status_code: Optional[int] = Field(default=None, description="HTTP status code response")
    response_size: int = Field(default=0, description="Response body size in bytes")
    source: str = Field(
        default="HTML",
        description="Discovery source (HTML, FORM, JAVASCRIPT, SITEMAP, ROBOTS, REDIRECT, USER)",
    )
    discovered_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Discovery timestamp"
    )
    classifications: List[str] = Field(
        default_factory=list, description="Endpoint classification tags (e.g. API, AUTHENTICATION)"
    )
    risk_indicators: List[str] = Field(
        default_factory=list, description="Observed risk indicators"
    )
    priority_score: int = Field(
        default=50, ge=0, le=100, description="Calculated priority score (0-100)"
    )
    priority_level: str = Field(
        default="MEDIUM", description="Calculated priority level (CRITICAL, HIGH, MEDIUM, LOW)"
    )
    priority_reasons: List[str] = Field(
        default_factory=list, description="Explainable reasons for priority assignment"
    )
    technologies: List[str] = Field(
        default_factory=list, description="Associated detected technologies"
    )
    authentication_required: Optional[bool] = Field(
        default=None, description="Whether endpoint appears to require authentication"
    )
    discovered_from: Optional[str] = Field(
        default=None, description="Parent URL or asset from which this endpoint was discovered"
    )

    @classmethod
    def from_url(
        cls,
        url: str,
        method: str = "GET",
        source: str = "HTML",
        status_code: Optional[int] = None,
        content_type: Optional[str] = None,
        response_size: int = 0,
        parameters: Optional[List[Parameter]] = None,
        discovered_from: Optional[str] = None,
    ) -> "Endpoint":
        """Factory method to construct an Endpoint from a URL."""
        parsed = urlparse(url)
        scheme = parsed.scheme.lower() or "http"
        host = (parsed.hostname or "").lower()
        path = parsed.path or "/"

        params = list(parameters) if parameters else []
        if not parameters and parsed.query:
            from urllib.parse import parse_qsl
            from vulnforge.models.parameter import ParameterLocation
            for k, v in parse_qsl(parsed.query, keep_blank_values=True):
                params.append(
                    Parameter(
                        name=k,
                        location=ParameterLocation.QUERY,
                        sample_value=v,
                        endpoint_url=url,
                    )
                )

        return cls(
            url=url,
            scheme=scheme,
            host=host,
            path=path,
            method=method.upper(),
            parameters=params,
            content_type=content_type,
            status_code=status_code,
            response_size=response_size,
            source=source,
            discovered_from=discovered_from,
        )



    @property
    def is_api(self) -> bool:
        """Heuristic check whether endpoint looks like an API route."""
        lower_path = self.path.lower()
        if any(
            lower_path.startswith(prefix)
            for prefix in ("/api", "/v1", "/v2", "/v3", "/graphql", "/rest", "/oauth", "/auth")
        ):
            return True
        if self.content_type and "json" in self.content_type.lower():
            return True
        return False

    def add_parameter(self, param: Parameter) -> None:
        """Add a parameter if not already present."""
        existing_names = {p.identifier for p in self.parameters}
        if param.identifier not in existing_names:
            self.parameters.append(param)
