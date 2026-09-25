"""HTTP request data model."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class HttpRequest(BaseModel):
    """Represents an HTTP request issued by the VulnForge engine."""

    method: str = Field(..., description="HTTP Method (GET, POST, etc.)")
    url: str = Field(..., description="Target URL")
    headers: Dict[str, str] = Field(default_factory=dict, description="Request headers")
    params: Optional[Dict[str, Any]] = Field(default=None, description="Query string parameters")
    data: Optional[Any] = Field(default=None, description="Form or raw data body")
    json_data: Optional[Any] = Field(default=None, description="JSON body payload")
    cookies: Optional[Dict[str, str]] = Field(default=None, description="Request cookies")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of request initiation"
    )
    timeout: Optional[float] = Field(default=None, description="Optional per-request timeout")
