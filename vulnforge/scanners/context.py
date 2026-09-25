"""Execution context for scanners and analysis plugins."""

from typing import Any, Dict, List, Optional

from vulnforge.core.context import ScanContext
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter
from vulnforge.models.target import Target
from vulnforge.scanners.result import Finding, Observation


class AnalysisContext:
    """Encapsulates the runtime environment and collected artifacts for scanner execution."""

    def __init__(
        self,
        scan_context: Optional[ScanContext] = None,
        endpoints: Optional[List[Endpoint]] = None,
        parameters: Optional[List[Parameter]] = None,
        target: Optional[Target] = None,
        http: Optional[Any] = None,
    ):
        """Initialize AnalysisContext.

        Args:
            scan_context: Master scan session context.
            endpoints: List of discovered endpoints.
            parameters: List of discovered input parameters.
            target: Optional direct Target (used in standalone test fixtures).
            http: Optional direct HTTP engine (used in standalone test fixtures).
        """
        self.scan_context: Optional[ScanContext] = scan_context
        self._direct_target: Optional[Target] = target
        self._direct_http: Optional[Any] = http

        self.endpoints: List[Endpoint] = endpoints or []
        self.parameters: List[Parameter] = parameters or []

        self.observations: List[Observation] = []
        self.findings: List[Finding] = []
        self.custom_state: Dict[str, Any] = {}

    @property
    def http_engine(self):
        """Access the centralized HTTP engine with scope and rate controls."""
        if self._direct_http is not None:
            return self._direct_http
        return self.scan_context.http_engine if self.scan_context else None

    @property
    def http(self):
        """Alias to http_engine."""
        return self.http_engine

    @property
    def target(self) -> Optional[Target]:
        """Access the validated target."""
        if self._direct_target is not None:
            return self._direct_target
        return self.scan_context.target if self.scan_context else None

    def record_observation(self, observation: Observation) -> None:
        """Add an observation to the session."""
        self.observations.append(observation)

    def record_finding(self, finding: Finding) -> None:
        """Add a finding to the session."""
        self.findings.append(finding)
