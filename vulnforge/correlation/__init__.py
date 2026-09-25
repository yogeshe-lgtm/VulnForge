"""VulnForge Finding Correlation, Confidence Scoring, and Severity Module."""

from vulnforge.correlation.confidence import (
    ConfidenceEngine,
    ConfidenceLevel,
    ConfidenceReport,
    ConfidenceSignal,
)
from vulnforge.correlation.deduplicator import FindingDeduplicator
from vulnforge.correlation.engine import CorrelationEngine
from vulnforge.correlation.lifecycle import FindingLifecycleManager
from vulnforge.correlation.regression import (
    AttackSurfaceDelta,
    FindingRegressionItem,
    RegressionStatus,
    SecurityRegressionEngine,
    SecurityRegressionReport,
)
from vulnforge.correlation.severity import (
    AuthRequirement,
    DataExposureLevel,
    SeverityContext,
    SeverityEngine,
)

__all__ = [
    "CorrelationEngine",
    "FindingDeduplicator",
    "FindingLifecycleManager",
    "SecurityRegressionEngine",
    "SecurityRegressionReport",
    "RegressionStatus",
    "FindingRegressionItem",
    "AttackSurfaceDelta",
    "ConfidenceEngine",
    "ConfidenceLevel",
    "ConfidenceReport",
    "ConfidenceSignal",
    "SeverityEngine",
    "SeverityContext",
    "AuthRequirement",
    "DataExposureLevel",
]
