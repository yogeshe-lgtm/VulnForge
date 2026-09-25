"""Domain models for Attack Surface Intelligence and Classification."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from vulnforge.crawler.forms import DiscoveredForm
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter


class ParameterClassification(str, Enum):
    """Categorization of input parameters by security significance and data type."""

    IDENTIFIER = "IDENTIFIER"
    SEARCH = "SEARCH"
    URL_INPUT = "URL_INPUT"
    FILE_PATH = "FILE_PATH"
    FILE_NAME = "FILE_NAME"
    REDIRECT = "REDIRECT"
    AUTHENTICATION = "AUTHENTICATION"
    SESSION = "SESSION"
    STATE_CHANGE = "STATE_CHANGE"
    JSON_FIELD = "JSON_FIELD"
    NUMERIC = "NUMERIC"
    BOOLEAN = "BOOLEAN"
    PAGINATION = "PAGINATION"
    UNKNOWN = "UNKNOWN"


class EndpointClassification(str, Enum):
    """Categorization of endpoints by structural role, intent, and risk profile."""

    API = "API"
    AUTHENTICATION = "AUTHENTICATION"
    ADMIN_LIKE_PATH = "ADMIN_LIKE_PATH"
    SEARCH = "SEARCH"
    FILE_UPLOAD_CANDIDATE = "FILE_UPLOAD_CANDIDATE"
    REDIRECT_CANDIDATE = "REDIRECT_CANDIDATE"
    DYNAMIC_ROUTE = "DYNAMIC_ROUTE"
    STATIC_ASSET = "STATIC_ASSET"
    IDENTIFIER_ENDPOINT = "IDENTIFIER_ENDPOINT"
    STATE_CHANGING = "STATE_CHANGING"
    GENERAL_PAGE = "GENERAL_PAGE"


class PriorityLevel(str, Enum):
    """Priority tiers for security assessment and testing order."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ParameterClassificationResult(BaseModel):
    """Result of classifying a single parameter."""

    classification: ParameterClassification = Field(
        default=ParameterClassification.UNKNOWN, description="Primary parameter category"
    )
    confidence: int = Field(
        default=50, ge=0, le=100, description="Classification confidence percentage"
    )
    reasons: List[str] = Field(
        default_factory=list, description="Heuristic indicators and observable rationale"
    )


class EndpointPriority(BaseModel):
    """Calculated prioritization score and explainable reasons for an endpoint."""

    score: int = Field(default=50, ge=0, le=100, description="Calculated priority score (0-100)")
    priority_level: PriorityLevel = Field(
        default=PriorityLevel.MEDIUM, description="Categorical priority level"
    )
    reasons: List[str] = Field(
        default_factory=list, description="Human-readable explainable rationale"
    )
    indicators: List[str] = Field(
        default_factory=list, description="Technical indicators and matched traits"
    )


class AttackSurface(BaseModel):
    """Consolidated attack surface intelligence model."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    target_url: str = Field(..., description="Root target URL assessed")
    hosts: List[str] = Field(default_factory=list, description="Unique hostnames in attack surface")
    endpoints: List[Endpoint] = Field(default_factory=list, description="Discovered endpoints")
    parameters: List[Parameter] = Field(default_factory=list, description="Discovered parameters")
    forms: List[DiscoveredForm] = Field(default_factory=list, description="Extracted HTML forms")
    api_endpoints: List[Endpoint] = Field(default_factory=list, description="API route endpoints")
    javascript_assets: List[str] = Field(default_factory=list, description="Discovered script URLs")
    technologies: List[Any] = Field(
        default_factory=list, description="Identified server and framework technologies"
    )
    classifications: Dict[str, int] = Field(
        default_factory=dict, description="Aggregate counts per classification category"
    )
    high_priority_inputs_count: int = Field(
        default=0, description="Number of high-interest input parameters identified"
    )
    total_endpoints: int = Field(default=0, description="Total unique endpoints mapped")
    total_parameters: int = Field(default=0, description="Total unique parameters mapped")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of surface model creation",
    )

    def get_endpoints_by_priority(self, level: PriorityLevel) -> List[Endpoint]:
        """Filter endpoints by priority level."""
        return [ep for ep in self.endpoints if ep.priority_level.upper() == level.value]

    def get_endpoints_by_classification(self, classification: str) -> List[Endpoint]:
        """Filter endpoints matching a given classification."""
        return [ep for ep in self.endpoints if classification in ep.classifications]
