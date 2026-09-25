"""Orchestrator pipeline executing registered security scanners over discovered endpoints."""

from typing import Dict, List, Optional, Tuple

from vulnforge.core.context import ScanContext
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter
from vulnforge.scanners.base import BaseScanner
from vulnforge.scanners.context import AnalysisContext
from vulnforge.scanners.registry import ScannerRegistry
from vulnforge.scanners.result import Finding, Observation


class ScannerEngine:
    """Orchestrates security analysis modules across the discovered attack surface."""

    def __init__(self, registry: Optional[ScannerRegistry] = None):
        """Initialize ScannerEngine."""
        self.registry = registry or ScannerRegistry

    async def run(
        self,
        scan_context: ScanContext,
        endpoints: List[Endpoint],
        parameters: Optional[List[Parameter]] = None,
        include_scanners: Optional[List[str]] = None,
        exclude_scanners: Optional[List[str]] = None,
    ) -> Tuple[List[Observation], List[Finding]]:
        """Execute selected scanners across all provided endpoints.

        Args:
            scan_context: Master scan session context.
            endpoints: Discovered endpoints to inspect.
            parameters: Discovered input parameters.
            include_scanners: Optional list of scanner names to include.
            exclude_scanners: Optional list of scanner names to exclude.

        Returns:
            Tuple of (deduplicated_observations, deduplicated_findings).
        """
        active_scanners = self.registry.filter(
            include=include_scanners, exclude=exclude_scanners
        )

        # Sort endpoints by priority score descending to assess higher-interest routes first
        sorted_endpoints = sorted(
            endpoints, key=lambda e: getattr(e, "priority_score", 50), reverse=True
        )

        analysis_context = AnalysisContext(
            scan_context=scan_context,
            endpoints=sorted_endpoints,
            parameters=parameters or [],
        )

        # 1. Initialize scanners
        for scanner in active_scanners:
            if scan_context.is_cancelled:
                break
            await scanner.initialize(analysis_context)

        # 2. Analyze endpoints in priority order
        for endpoint in sorted_endpoints:
            if scan_context.is_cancelled:
                break
            for scanner in active_scanners:
                if scan_context.is_cancelled:
                    break
                try:
                    observations = await scanner.analyze(analysis_context, endpoint)
                    for obs in observations:
                        analysis_context.record_observation(obs)
                except Exception:
                    # Individual scanner failure does not crash the entire scan pipeline
                    pass

        # 3. Finalize findings
        for scanner in active_scanners:
            if scan_context.is_cancelled:
                break
            try:
                findings = await scanner.finalize(analysis_context)
                for f in findings:
                    analysis_context.record_finding(f)
            except Exception:
                pass

        # 4. Deduplicate Observations
        dedup_observations: Dict[str, Observation] = {}
        for obs in analysis_context.observations:
            if obs.deduplication_key not in dedup_observations:
                dedup_observations[obs.deduplication_key] = obs

        # 5. Deduplicate Findings
        dedup_findings: Dict[str, Finding] = {}
        for finding in analysis_context.findings:
            if finding.deduplication_key not in dedup_findings:
                dedup_findings[finding.deduplication_key] = finding

        return list(dedup_observations.values()), list(dedup_findings.values())
