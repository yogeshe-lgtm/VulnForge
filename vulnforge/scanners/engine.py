"""Orchestrator pipeline executing registered security scanners over discovered endpoints."""

from typing import Dict, List, Optional, Set, Tuple

from vulnforge.core.context import ScanContext
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter
from vulnforge.scanners.base import BaseScanner
from vulnforge.scanners.context import AnalysisContext
from vulnforge.scanners.registry import ScannerRegistry
from vulnforge.scanners.result import (
    AssessmentCoverage,
    Finding,
    Observation,
    ScannerExecutionReport,
    ScannerStatus,
)


class ScannerEngine:
    """Orchestrates security analysis modules across the discovered attack surface."""

    def __init__(self, registry: Optional[ScannerRegistry] = None):
        """Initialize ScannerEngine."""
        self.registry = registry or ScannerRegistry
        self.scanner_reports: List[ScannerExecutionReport] = []
        self.coverage: Optional[AssessmentCoverage] = None

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
        all_registered = self.registry.list_all()
        active_scanners = self.registry.filter(
            include=include_scanners, exclude=exclude_scanners
        )
        active_names = {s.name.lower() for s in active_scanners}

        params_list = list(parameters or [])

        # Sort endpoints by priority score descending to assess higher-interest routes first
        sorted_endpoints = sorted(
            endpoints, key=lambda e: getattr(e, "priority_score", 50), reverse=True
        )

        analysis_context = AnalysisContext(
            scan_context=scan_context,
            endpoints=sorted_endpoints,
            parameters=params_list,
        )

        # Track per-scanner telemetry
        scanner_obs_count: Dict[str, int] = {s.name: 0 for s in all_registered}
        scanner_findings_count: Dict[str, int] = {s.name: 0 for s in all_registered}
        scanner_ep_tested: Dict[str, Set[str]] = {s.name: set() for s in all_registered}
        scanner_param_tested: Dict[str, Set[str]] = {s.name: set() for s in all_registered}
        scanner_errors: Dict[str, str] = {}

        # 1. Initialize scanners
        for scanner in active_scanners:
            if scan_context.is_cancelled:
                break
            try:
                await scanner.initialize(analysis_context)
            except Exception as e:
                scanner_errors[scanner.name] = f"Initialization error: {e}"

        # 2. Analyze endpoints in priority order
        for endpoint in sorted_endpoints:
            if scan_context.is_cancelled:
                break
            for scanner in active_scanners:
                if scan_context.is_cancelled:
                    break
                if scanner.name in scanner_errors:
                    continue
                try:
                    init_obs_len = len(analysis_context.observations)
                    observations = await scanner.analyze(analysis_context, endpoint)
                    scanner_ep_tested[scanner.name].add(endpoint.url)
                    for p in endpoint.parameters:
                        scanner_param_tested[scanner.name].add(p.identifier)
                    for obs in observations:
                        analysis_context.record_observation(obs)
                        scanner_obs_count[scanner.name] += 1
                except Exception as e:
                    scanner_errors[scanner.name] = f"Runtime error: {e}"

        # 3. Finalize findings
        for scanner in active_scanners:
            if scan_context.is_cancelled:
                break
            if scanner.name in scanner_errors:
                continue
            try:
                findings = await scanner.finalize(analysis_context)
                for f in findings:
                    analysis_context.record_finding(f)
                    scanner_findings_count[scanner.name] += 1
            except Exception as e:
                scanner_errors[scanner.name] = f"Finalization error: {e}"

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

        # 6. Build Detailed Scanner Reports & Coverage
        reports: List[ScannerExecutionReport] = []
        tested_endpoints_all: Set[str] = set()
        tested_params_all: Set[str] = set()

        for scanner in all_registered:
            name = scanner.name
            cat = scanner.category

            if name.lower() not in active_names:
                reports.append(
                    ScannerExecutionReport(
                        scanner_name=name,
                        category=cat,
                        status=ScannerStatus.SKIPPED,
                        reason="Excluded by scan profile or user module filter",
                        endpoints_tested=0,
                        parameters_tested=0,
                        observations_count=0,
                        findings_count=0,
                    )
                )
            elif name in scanner_errors:
                reports.append(
                    ScannerExecutionReport(
                        scanner_name=name,
                        category=cat,
                        status=ScannerStatus.FAILED,
                        reason=scanner_errors[name],
                        endpoints_tested=len(scanner_ep_tested[name]),
                        parameters_tested=len(scanner_param_tested[name]),
                        observations_count=scanner_obs_count[name],
                        findings_count=scanner_findings_count[name],
                    )
                )
            else:
                eps_count = len(scanner_ep_tested[name])
                params_count = len(scanner_param_tested[name])
                tested_endpoints_all.update(scanner_ep_tested[name])
                tested_params_all.update(scanner_param_tested[name])

                # Determine if scanner was effectively skipped due to target lack of compatible inputs
                if name in ("sqli", "xss", "open-redirect", "directory-traversal", "traversal") and not params_list and not any(ep.parameters for ep in sorted_endpoints):
                    status = ScannerStatus.SKIPPED
                    reason = "No input parameters or query arguments discovered for injection testing"
                elif name == "csrf" and not any(getattr(ep, "method", "") == "POST" for ep in sorted_endpoints):
                    status = ScannerStatus.SKIPPED
                    reason = "No state-changing POST endpoints or HTML forms identified"
                elif name == "file-upload" and not any("upload" in getattr(ep, "classifications", []) or "multipart" in str(getattr(ep, "content_type", "")).lower() for ep in sorted_endpoints):
                    status = ScannerStatus.SKIPPED
                    reason = "No multipart/form-data file upload endpoints discovered"
                elif name == "cors" and not any("API" in getattr(ep, "classifications", []) or getattr(ep, "is_api", False) for ep in sorted_endpoints):
                    status = ScannerStatus.SKIPPED
                    reason = "No API routes or CORS endpoints identified"
                elif name == "authorization" and not any(getattr(ep, "authentication_required", False) for ep in sorted_endpoints):
                    status = ScannerStatus.SKIPPED
                    reason = "No multi-role authentication endpoints or access-control routes identified"
                else:
                    status = ScannerStatus.COMPLETED
                    reason = f"Completed ({eps_count} endpoints inspected, {scanner_obs_count[name]} telemetry signals)"

                reports.append(
                    ScannerExecutionReport(
                        scanner_name=name,
                        category=cat,
                        status=status,
                        reason=reason,
                        endpoints_tested=eps_count,
                        parameters_tested=params_count,
                        observations_count=scanner_obs_count[name],
                        findings_count=scanner_findings_count[name],
                    )
                )

        self.scanner_reports = reports

        # Calculate Overall Coverage
        discovered_eps_count = len(sorted_endpoints)
        tested_eps_count = len(tested_endpoints_all)
        skipped_eps_count = max(0, discovered_eps_count - tested_eps_count)

        discovered_params_count = len(params_list)
        tested_params_count = len(tested_params_all)
        skipped_params_count = max(0, discovered_params_count - tested_params_count)

        executed_scanners_count = sum(1 for r in reports if r.status == ScannerStatus.COMPLETED)
        skipped_scanners_count = sum(1 for r in reports if r.status == ScannerStatus.SKIPPED)
        failed_scanners_count = sum(1 for r in reports if r.status == ScannerStatus.FAILED)

        untested_reasons: List[str] = []
        auth_eps = sum(1 for ep in sorted_endpoints if getattr(ep, "authentication_required", False))
        if auth_eps > 0:
            untested_reasons.append(f"{auth_eps} authentication-required endpoints (unauthenticated scan mode)")
        static_eps = sum(1 for ep in sorted_endpoints if "STATIC_ASSET" in getattr(ep, "classifications", []))
        if static_eps > 0:
            untested_reasons.append(f"{static_eps} static assets (CSS/fonts/images excluded from active testing)")
        if skipped_scanners_count > 0:
            untested_reasons.append(f"{skipped_scanners_count} scanner modules skipped due to missing target primitives or profile")

        self.coverage = AssessmentCoverage(
            endpoints_discovered=discovered_eps_count,
            endpoints_tested=tested_eps_count,
            endpoints_skipped=skipped_eps_count,
            parameters_discovered=discovered_params_count,
            parameters_tested=tested_params_count,
            parameters_skipped=skipped_params_count,
            scanners_available=len(all_registered),
            scanners_executed=executed_scanners_count,
            scanners_skipped=skipped_scanners_count,
            scanners_failed=failed_scanners_count,
            untested_reasons=untested_reasons,
        )

        return list(dedup_observations.values()), list(dedup_findings.values())

