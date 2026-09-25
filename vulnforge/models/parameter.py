"""Parameter data model for discovered query, form, body, and path parameters."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class ParameterLocation(str, Enum):
    """Location of the parameter in the HTTP request."""

    QUERY = "query"
    FORM = "form"
    PATH = "path"
    JSON = "json"
    HEADER = "header"


class Parameter(BaseModel):
    """Represents an input parameter identified on an endpoint."""

    name: str = Field(..., description="Parameter name/key")
    location: ParameterLocation = Field(
        default=ParameterLocation.QUERY, description="Parameter location (query, form, etc.)"
    )
    param_type: str = Field(
        default="string", description="Parameter datatype or input type (e.g. text, password, number)"
    )
    sample_value: Optional[str] = Field(default=None, description="Default or sample value discovered")
    endpoint_url: str = Field(..., description="URL of the associated endpoint")
    source: str = Field(default="HTML", description="Origin of discovery (HTML, FORM, JAVASCRIPT, API)")
    classification: str = Field(
        default="UNKNOWN", description="Parameter classification category (e.g. IDENTIFIER, SEARCH)"
    )
    classification_confidence: int = Field(
        default=50, ge=0, le=100, description="Classification confidence percentage"
    )
    classification_reasons: List[str] = Field(
        default_factory=list, description="Reasons for parameter classification"
    )

    @property
    def identifier(self) -> str:
        """Unique parameter signature for deduplication."""
        return f"{self.endpoint_url}::{self.location.value}::{self.name}"

    @property
    def is_high_interest(self) -> bool:
        """Check if parameter represents a high-interest target for vulnerability testing."""
        high_categories = {
            "IDENTIFIER",
            "URL_INPUT",
            "REDIRECT",
            "FILE_PATH",
            "FILE_NAME",
            "AUTHENTICATION",
            "STATE_CHANGE",
            "SESSION",
        }
        return self.classification.upper() in high_categories

