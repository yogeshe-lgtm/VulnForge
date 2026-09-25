"""VulnForge Finding Correlation, Confidence Scoring, and Severity Module."""

from vulnforge.correlation.confidence import (
    ConfidenceEngine,
    ConfidenceLevel,
    ConfidenceReport,
    ConfidenceSignal,
)
from vulnforge.correlation.deduplicator import FindingDeduplicator
from vulnforge.correlation.engine import CorrelationEngine
from vulnforge.correlation.severity import (
    AuthRequirement,
    DataExposureLevel,
    SeverityContext,
    SeverityEngine,
)

__all__ = [
    "CorrelationEngine",
    "FindingDeduplicator",
    "ConfidenceEngine",
    "ConfidenceLevel",
    "ConfidenceReport",
    "ConfidenceSignal",
    "SeverityEngine",
    "SeverityContext",
    "AuthRequirement",
    "DataExposureLevel",
]
