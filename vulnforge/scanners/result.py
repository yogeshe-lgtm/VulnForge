"""Data models for analysis observations, findings, and response comparisons."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import difflib
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field

from vulnforge.models.response import HttpResponse


class ObservationType(str, Enum):
    """Categorization for observed endpoint or response telemetry."""

    REFLECTION = "REFLECTION"
    REFLECTED_INPUT = "REFLECTION"
    UNENCODED_CONTEXT = "UNENCODED_CONTEXT"
    HEADER_CONFIGURATION = "HEADER_CONFIGURATION"
    HEADER_MISSING = "HEADER_CONFIGURATION"
    SECURITY_HEADER = "HEADER_CONFIGURATION"
    REDIRECT = "REDIRECT"
    HTTP_STATUS_CHANGE = "REDIRECT"
    ERROR_PATTERN = "ERROR_PATTERN"
    ERROR_LEAK = "ERROR_PATTERN"
    RESPONSE_DIFFERENCE = "RESPONSE_DIFFERENCE"
    PARAMETER_PATTERN = "PARAMETER_PATTERN"
    FORM_SIGNATURE = "PARAMETER_PATTERN"
    AUTHORIZATION_DIFFERENCE = "AUTHORIZATION_DIFFERENCE"
    UPLOAD_ENDPOINT = "UPLOAD_ENDPOINT"
    URL_INPUT = "URL_INPUT"
    DISCLOSURE = "DISCLOSURE"
    INFO_LEAK = "DISCLOSURE"
    METADATA = "METADATA"
    SCHEME_CONFIGURATION = "SCHEME_CONFIGURATION"
    GENERAL = "GENERAL"


class FindingSeverity(str, Enum):
    """Severity classification for audit findings."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingStatus(str, Enum):
    """Deterministic confirmation status for an assessment finding."""

    OBSERVED = "OBSERVED"
    POTENTIAL = "POTENTIAL"
    REQUIRES_MANUAL_VERIFICATION = "REQUIRES_MANUAL_VERIFICATION"
    CONFIRMED = "CONFIRMED"


class Observation(BaseModel):
    """Represents a factual telemetry data-point observed during endpoint inspection."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scanner: str = Field(..., description="Name of the reporting scanner")
    endpoint_url: str = Field(..., description="Target endpoint URL")
    parameter_name: Optional[str] = Field(default=None, description="Associated parameter name if any")
    observation_type: ObservationType = Field(
        default=ObservationType.GENERAL, description="Type of observed signal"
    )
    description: str = Field(..., description="Summary of observation")
    evidence: str = Field(default="", description="Factual supporting evidence")
    confidence: int = Field(default=50, ge=0, le=100, description="Confidence score 0-100%")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of observation"
    )

    @property
    def endpoint(self) -> str:
        """Alias for endpoint_url."""
        return self.endpoint_url

    @property
    def parameter(self) -> Optional[str]:
        """Alias for parameter_name."""
        return self.parameter_name

    @property
    def type(self) -> ObservationType:
        """Alias for observation_type."""
        return self.observation_type

    @property
    def deduplication_key(self) -> str:
        """Unique key for deduplicating identical observations."""
        return f"{self.scanner}::{self.endpoint_url}::{self.parameter_name or ''}::{self.observation_type.value}"


class Finding(BaseModel):
    """Structured security assessment finding."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    scanner: str = Field(..., description="Identifier of the scanner that generated the finding")
    category: str = Field(default="General", description="Vulnerability or assessment category")
    title: str = Field(..., description="Concise finding headline")
    severity: FindingSeverity = Field(default=FindingSeverity.INFO, description="Assessed impact severity")
    confidence: int = Field(default=50, ge=0, le=100, description="Confidence rating 0-100%")
    status: FindingStatus = Field(
        default=FindingStatus.POTENTIAL, description="Verification status"
    )
    endpoint_url: str = Field(..., description="Affected endpoint URL")
    parameter_name: Optional[str] = Field(default=None, description="Associated parameter name if any")
    description: str = Field(..., description="Detailed description of the observation or finding")
    evidence: str = Field(default="", description="Supporting evidence data")
    recommendation: str = Field(
        default="Conduct manual architectural review and follow secure coding best practices.",
        description="Remediation guidance",
    )
    references: List[str] = Field(default_factory=list, description="External references or OWASP links")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Discovery timestamp"
    )

    @property
    def endpoint(self) -> str:
        """Alias for endpoint_url."""
        return self.endpoint_url

    @property
    def parameter(self) -> Optional[str]:
        """Alias for parameter_name."""
        return self.parameter_name

    @property
    def deduplication_key(self) -> str:
        """Unique key for deduplicating findings."""
        return f"{self.scanner}::{self.category}::{self.endpoint_url}::{self.parameter_name or ''}::{self.title}"


@dataclass
class ResponseDifference:
    """Detailed structural and behavioral differences between two HTTP responses."""

    status_changed: bool
    status_baseline: int
    status_candidate: int
    size_changed: bool
    size_delta_bytes: int
    headers_changed: bool
    content_changed: bool
    similarity_ratio: float = 1.0  # 0.0 (completely different) to 1.0 (identical)
    redirect_changed: bool = False
    timing_delta_seconds: float = 0.0
    timing_changed: bool = False
    added_headers: Dict[str, str] = field(default_factory=dict)
    removed_headers: Dict[str, str] = field(default_factory=dict)



def compare_responses(
    baseline: HttpResponse,
    candidate: HttpResponse,
    similarity_threshold: float = 0.95,
) -> ResponseDifference:
    """Compare baseline and candidate HTTP responses to compute structural deltas.

    Args:
        baseline: Original baseline response.
        candidate: Subsequent or probe response.
        similarity_threshold: Threshold above which content is deemed substantially identical.

    Returns:
        ResponseDifference containing structural and content diff metrics.
    """
    status_changed = baseline.status_code != candidate.status_code
    baseline_bytes_len = len(baseline.raw_bytes) if baseline.raw_bytes else len(baseline.body.encode("utf-8", errors="replace"))
    candidate_bytes_len = len(candidate.raw_bytes) if candidate.raw_bytes else len(candidate.body.encode("utf-8", errors="replace"))
    size_delta = candidate_bytes_len - baseline_bytes_len
    size_changed = abs(size_delta) > 0


    # Header diffs
    b_hdrs = {k.lower(): v for k, v in baseline.headers.items()}
    c_hdrs = {k.lower(): v for k, v in candidate.headers.items()}

    added_headers = {k: v for k, v in c_hdrs.items() if k not in b_hdrs}
    removed_headers = {k: v for k, v in b_hdrs.items() if k not in c_hdrs}
    headers_changed = bool(added_headers or removed_headers)

    # Content similarity
    if baseline.body == candidate.body:
        similarity = 1.0
    elif not baseline.body or not candidate.body:
        similarity = 0.0
    else:
        matcher = difflib.SequenceMatcher(None, baseline.body[:20000], candidate.body[:20000])
        similarity = matcher.quick_ratio()

    content_changed = similarity < similarity_threshold
    redirect_changed = baseline.url != candidate.url or len(baseline.history) != len(candidate.history)
    timing_delta = candidate.elapsed - baseline.elapsed
    timing_changed = abs(timing_delta) > 1.0

    return ResponseDifference(
        status_changed=status_changed,
        status_baseline=baseline.status_code,
        status_candidate=candidate.status_code,
        size_changed=size_changed,
        size_delta_bytes=size_delta,
        headers_changed=headers_changed,
        added_headers=added_headers,
        removed_headers=removed_headers,
        content_changed=content_changed,
        similarity_ratio=similarity,
        redirect_changed=redirect_changed,
        timing_delta_seconds=timing_delta,
        timing_changed=timing_changed,
    )


# Alias for singular form
compare_response = compare_responses

