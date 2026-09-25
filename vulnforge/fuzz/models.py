"""Controlled Fuzzing data models."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class FuzzMode(str, Enum):
    """Fuzzing target mode."""

    DIRECTORY_DISCOVERY = "DIRECTORY_DISCOVERY"
    PARAMETER_DISCOVERY = "PARAMETER_DISCOVERY"
    HEADER_FUZZING = "HEADER_FUZZING"


class FuzzResult(BaseModel):
    """Result of an individual fuzzed probe request."""

    payload: str = Field(..., description="Injected payload or probed path")
    target_url: str = Field(..., description="Full URL probed")
    status_code: int = Field(..., description="HTTP response status code")
    response_size: int = Field(..., description="Response body size in bytes")
    elapsed_ms: float = Field(..., description="Response duration in milliseconds")
    content_type: str = Field(default="", description="Response content type")
    is_interesting: bool = Field(default=False, description="Whether status or response size was anomalous")
    note: str = Field(default="", description="Diagnostic observation note")


class FuzzSummary(BaseModel):
    """Consolidated summary of a controlled fuzzing campaign."""

    target_base_url: str = Field(..., description="Target base URL")
    fuzz_mode: FuzzMode = Field(..., description="Campaign mode")
    total_requests_sent: int = Field(default=0, description="Total requests performed")
    discovered_endpoints_count: int = Field(default=0, description="Interesting or newly discovered endpoints")
    status_distribution: Dict[int, int] = Field(default_factory=dict, description="Status code count distribution")
    results: List[FuzzResult] = Field(default_factory=list, description="List of interesting fuzz results")
