"""Abstract base class and contract for security analysis and inspection modules."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Dict, List, Optional

from vulnforge.models.endpoint import Endpoint
from vulnforge.scanners.context import AnalysisContext
from vulnforge.scanners.result import (
    Finding,
    FindingSeverity,
    FindingStatus,
    Observation,
    ObservationType,
)


class ScannerMode(str, Enum):
    """Operational mode of an analysis module."""

    PASSIVE = "PASSIVE"  # Inspects already gathered metadata without additional network queries
    ANALYSIS = "ANALYSIS"  # Non-destructive baseline and structural inspection
    CONTROLLED_TEST = "CONTROLLED_TEST"  # Safe controlled inspection within strict policy boundaries
    SAFE_ACTIVE = "CONTROLLED_TEST"  # Alias for controlled verification testing


class BaseScanner(ABC):
    """Abstract interface for all VulnForge security scanners and analysis plugins."""

    name: str = "base-scanner"
    description: str = "Base security analysis module"
    category: str = "General"
    mode: ScannerMode = ScannerMode.PASSIVE
    enabled: bool = True
    supported_methods: List[str] = ["GET", "POST"]

    async def initialize(self, context: AnalysisContext) -> None:
        """Lifecycle hook called before analyzing endpoints."""
        pass

    @abstractmethod
    async def analyze(
        self, context: AnalysisContext, endpoint: Endpoint
    ) -> List[Observation]:
        """Inspect a discovered endpoint and return factual telemetry observations.

        Args:
            context: AnalysisContext with shared HTTP engine, scope, and target state.
            endpoint: Discovered endpoint to analyze.

        Returns:
            List of Observation objects.
        """
        raise NotImplementedError

    async def finalize(self, context: AnalysisContext) -> List[Finding]:
        """Lifecycle hook called after all endpoints are analyzed to synthesize findings.

        Returns:
            List of Finding objects derived from collected observations.
        """
        return []

    def create_observation(
        self,
        endpoint_url: str,
        description: str,
        observation_type: ObservationType = ObservationType.GENERAL,
        parameter_name: Optional[str] = None,
        evidence: str = "",
        confidence: int = 50,
    ) -> Observation:
        """Helper to instantiate an Observation associated with this scanner."""
        return Observation(
            scanner=self.name,
            endpoint_url=endpoint_url,
            parameter_name=parameter_name,
            observation_type=observation_type,
            description=description,
            evidence=evidence,
            confidence=confidence,
        )

    def create_finding(
        self,
        title: str,
        endpoint_url: str,
        description: str,
        category: Optional[str] = None,
        severity: FindingSeverity = FindingSeverity.INFO,
        confidence: int = 50,
        status: FindingStatus = FindingStatus.POTENTIAL,
        parameter_name: Optional[str] = None,
        evidence: str = "",
        recommendation: str = "Conduct manual verification and adhere to secure architecture guidelines.",
        references: Optional[List[str]] = None,
    ) -> Finding:
        """Helper to instantiate a Finding associated with this scanner."""
        return Finding(
            scanner=self.name,
            category=category or self.category,
            title=title,
            severity=severity,
            confidence=confidence,
            status=status,
            endpoint_url=endpoint_url,
            parameter_name=parameter_name,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            references=references or [],
        )
