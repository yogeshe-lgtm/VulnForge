"""Out-of-Band Application Security Testing (OAST) models."""

import os
import secrets
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class OASTProviderType(str, Enum):
    """Supported OAST provider backend types."""

    SELF_HOSTED = "SELF_HOSTED"
    GENERIC_HTTP = "GENERIC_HTTP"
    BURP_COLLABORATOR = "BURP_COLLABORATOR"
    CUSTOM = "CUSTOM"


class CallbackToken(BaseModel):
    """Unique canary token generated for a specific scanner, endpoint, and parameter."""

    token_id: str = Field(..., description="Unique token string (e.g., VF-A9B8C7D6)")
    scanner_name: str = Field(..., description="Scanner that created this token")
    target_url: str = Field(..., description="Target URL where token was injected")
    parameter_name: Optional[str] = Field(default=None, description="Injected parameter name")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Generation timestamp")
    callback_url: str = Field(..., description="Full listening URL where callback is received")

    @classmethod
    def generate(cls, scanner_name: str, target_url: str, base_oast_domain: str, parameter_name: Optional[str] = None) -> "CallbackToken":
        """Generate a random unique token."""
        rand_hex = secrets.token_hex(4).upper()
        token_id = f"VF-{rand_hex}"
        callback_url = f"http://{token_id.lower()}.{base_oast_domain.lstrip('.')}"
        return cls(
            token_id=token_id,
            scanner_name=scanner_name,
            target_url=target_url,
            parameter_name=parameter_name,
            callback_url=callback_url,
        )


class CallbackEvent(BaseModel):
    """Telemetry captured when an out-of-band callback is received by the listener."""

    event_id: str = Field(default_factory=lambda: secrets.token_hex(6), description="Unique event ID")
    token_id: str = Field(..., description="Matching token ID")
    protocol: str = Field(default="HTTP", description="Protocol observed (HTTP, DNS, HTTPS)")
    client_ip: str = Field(default="127.0.0.1", description="Remote IP that made the callback")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Event timestamp")
    http_method: Optional[str] = Field(default=None, description="HTTP Method if HTTP callback")
    headers: Dict[str, str] = Field(default_factory=dict, description="Received headers")
    raw_query: Optional[str] = Field(default=None, description="Raw query string or DNS question")
