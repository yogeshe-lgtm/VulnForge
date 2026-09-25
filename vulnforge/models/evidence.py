"""Structured evidence models for security findings with automatic secret redaction."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, Field

from vulnforge.utils.redaction import redact_dict_secrets, redact_secrets


class EvidenceType(str, Enum):
    """Categorization of evidence supporting a security finding."""

    HTTP_REQUEST = "HTTP_REQUEST"
    HTTP_RESPONSE = "HTTP_RESPONSE"
    RESPONSE_DIFF = "RESPONSE_DIFF"
    REFLECTION = "REFLECTION"
    HEADER_MISCONFIG = "HEADER_MISCONFIG"
    ERROR_PATTERN = "ERROR_PATTERN"
    TIMING_DELTA = "TIMING_DELTA"
    DOM_FLOW = "DOM_FLOW"
    CANARY_TOKEN = "CANARY_TOKEN"
    METADATA = "METADATA"


class EvidenceItem(BaseModel):
    """Individual atomic piece of explainable evidence."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    evidence_type: EvidenceType = Field(default=EvidenceType.METADATA, description="Type of evidence")
    description: str = Field(..., description="Explainable description of the evidence")
    request_metadata: Optional[Dict[str, Any]] = Field(
        default=None, description="Request parameters, headers, method, and sanitized body"
    )
    response_metadata: Optional[Dict[str, Any]] = Field(
        default=None, description="Response status, headers, and sanitized snippet"
    )
    observed_behavior: Optional[str] = Field(default=None, description="Observed system or application reaction")
    reflection_location: Optional[str] = Field(default=None, description="Exact reflection context or DOM sink")
    scanner_reasoning: Optional[str] = Field(default=None, description="Diagnostic heuristic reasoning")
    confidence_factors: List[str] = Field(default_factory=list, description="Signals elevating or lowering confidence")
    raw_data: Optional[str] = Field(default=None, description="Raw sanitized payload or telemetry snippet")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), description="Timestamp of evidence acquisition"
    )

    def model_post_init(self, __context: Any) -> None:
        """Ensure all stored metadata and raw strings are automatically redacted."""
        if self.request_metadata:
            self.request_metadata = redact_dict_secrets(self.request_metadata)
        if self.response_metadata:
            self.response_metadata = redact_dict_secrets(self.response_metadata)
        if self.raw_data:
            self.raw_data = redact_secrets(self.raw_data)
        if self.observed_behavior:
            self.observed_behavior = redact_secrets(self.observed_behavior)


class EvidenceCollection(BaseModel):
    """Collection of structured evidence items associated with a finding."""

    items: List[EvidenceItem] = Field(default_factory=list, description="Ordered evidence items")

    def add(
        self,
        evidence_type: EvidenceType,
        description: str,
        request_metadata: Optional[Dict[str, Any]] = None,
        response_metadata: Optional[Dict[str, Any]] = None,
        observed_behavior: Optional[str] = None,
        reflection_location: Optional[str] = None,
        scanner_reasoning: Optional[str] = None,
        confidence_factors: Optional[List[str]] = None,
        raw_data: Optional[str] = None,
    ) -> EvidenceItem:
        """Construct and append a new sanitized evidence item."""
        item = EvidenceItem(
            evidence_type=evidence_type,
            description=description,
            request_metadata=request_metadata,
            response_metadata=response_metadata,
            observed_behavior=observed_behavior,
            reflection_location=reflection_location,
            scanner_reasoning=scanner_reasoning,
            confidence_factors=confidence_factors or [],
            raw_data=raw_data,
        )
        self.items.append(item)
        return item

    def to_summary_string(self) -> str:
        """Produce a formatted human-readable summary of all evidence items."""
        if not self.items:
            return ""
        parts = []
        for idx, item in enumerate(self.items, 1):
            parts.append(f"[{item.evidence_type.value}] {item.description}")
            if item.observed_behavior:
                parts.append(f"  Observed: {item.observed_behavior}")
            if item.reflection_location:
                parts.append(f"  Location: {item.reflection_location}")
            if item.scanner_reasoning:
                parts.append(f"  Reasoning: {item.scanner_reasoning}")
            if item.confidence_factors:
                parts.append(f"  Signals: {', '.join(item.confidence_factors)}")
        return "\n".join(parts)
