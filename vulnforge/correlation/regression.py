"""Security Regression Engine - Scans comparison, regression detection, and attack surface deltas."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from vulnforge.scanners.result import Finding, FindingStatus


class RegressionStatus(str, Enum):
    """Categorical regression state of a security finding between scans."""

    NEW = "NEW"
    RESOLVED = "RESOLVED"
    UNCHANGED = "UNCHANGED"
    REGRESSED = "REGRESSED"
    REOPENED = "REOPENED"


class FindingRegressionItem(BaseModel):
    """Regression status and comparative delta for an individual finding."""

    fingerprint: str = Field(..., description="Deterministic finding fingerprint")
    status: RegressionStatus = Field(..., description="Comparative regression status")
    title: str = Field(..., description="Finding title")
    endpoint_url: str = Field(..., description="Affected endpoint")
    parameter_name: Optional[str] = Field(default=None, description="Affected parameter")
    severity: str = Field(..., description="Active finding severity")
    current_finding: Optional[Dict[str, Any]] = Field(default=None, description="Active finding data")
    baseline_finding: Optional[Dict[str, Any]] = Field(default=None, description="Historical baseline data")
    severity_change: Optional[str] = Field(default=None, description="Shift in severity level")
    confidence_delta: int = Field(default=0, description="Change in confidence percentage")
    explanation: str = Field(default="", description="Explainable reason for regression classification")


class AttackSurfaceDelta(BaseModel):
    """Comparative structural changes in attack surface between scans."""

    new_endpoints: List[str] = Field(default_factory=list, description="Newly discovered endpoints")
    removed_endpoints: List[str] = Field(default_factory=list, description="Endpoints no longer detected")
    new_parameters: List[str] = Field(default_factory=list, description="Newly mapped parameters")
    new_technologies: List[str] = Field(default_factory=list, description="Newly detected technologies")


class SecurityRegressionReport(BaseModel):
    """Consolidated security regression and attack surface comparison report."""

    baseline_scan_id: str = Field(..., description="Baseline historical scan ID")
    current_scan_id: str = Field(..., description="Candidate active scan ID")
    target_url: str = Field(default="", description="Assessed target URL")
    total_regressed: int = Field(default=0, description="Count of regressed or reopened findings")
    total_new: int = Field(default=0, description="Count of brand-new findings")
    total_resolved: int = Field(default=0, description="Count of successfully resolved findings")
    total_unchanged: int = Field(default=0, description="Count of recurring unchanged findings")
    total_reopened: int = Field(default=0, description="Count of reopened previously-resolved findings")
    finding_regressions: List[FindingRegressionItem] = Field(
        default_factory=list, description="Itemized finding regression states"
    )
    surface_delta: AttackSurfaceDelta = Field(
        default_factory=AttackSurfaceDelta, description="Attack surface topology delta"
    )
    has_blocking_regressions: bool = Field(
        default=False, description="Whether critical/high regressions were detected"
    )

    def summary(self) -> Dict[str, Any]:
        """Produce dictionary summary of regression metrics."""
        return {
            "baseline_scan_id": self.baseline_scan_id,
            "current_scan_id": self.current_scan_id,
            "target_url": self.target_url,
            "new": self.total_new,
            "resolved": self.total_resolved,
            "unchanged": self.total_unchanged,
            "regressed": self.total_regressed,
            "reopened": self.total_reopened,
            "blocking": self.has_blocking_regressions,
            "new_endpoints_count": len(self.surface_delta.new_endpoints),
        }


class SecurityRegressionEngine:
    """Analyzes and classifies security regressions and attack surface evolution between scans."""

    @staticmethod
    def compare_findings(
        baseline_findings: List[Finding],
        current_findings: List[Finding],
    ) -> List[FindingRegressionItem]:
        """Compare baseline and candidate findings by fingerprint to detect regressions."""
        base_map: Dict[str, Finding] = {f.fingerprint: f for f in baseline_findings}
        curr_map: Dict[str, Finding] = {f.fingerprint: f for f in current_findings}

        items: List[FindingRegressionItem] = []

        # 1. Process candidate findings
        for fp, curr in curr_map.items():
            curr_sev = curr.severity.value if hasattr(curr.severity, "value") else str(curr.severity)
            if fp in base_map:
                base = base_map[fp]
                base_sev = base.severity.value if hasattr(base.severity, "value") else str(base.severity)
                conf_diff = curr.confidence - base.confidence

                if base.status == FindingStatus.RESOLVED:
                    status = RegressionStatus.REOPENED
                    exp = "Previously resolved security flaw re-appeared in current scan (REGRESSION)"
                elif base_sev != curr_sev and curr_sev in ("CRITICAL", "HIGH"):
                    status = RegressionStatus.REGRESSED
                    exp = f"Severity escalated from {base_sev} to {curr_sev}"
                else:
                    status = RegressionStatus.UNCHANGED
                    exp = "Identical security finding persisted across scans"

                items.append(
                    FindingRegressionItem(
                        fingerprint=fp,
                        status=status,
                        title=curr.title,
                        endpoint_url=curr.endpoint_url,
                        parameter_name=curr.parameter_name,
                        severity=curr_sev,
                        current_finding=curr.model_dump(mode="json"),
                        baseline_finding=base.model_dump(mode="json"),
                        severity_change=f"{base_sev} -> {curr_sev}" if base_sev != curr_sev else None,
                        confidence_delta=conf_diff,
                        explanation=exp,
                    )
                )
            else:
                items.append(
                    FindingRegressionItem(
                        fingerprint=fp,
                        status=RegressionStatus.NEW,
                        title=curr.title,
                        endpoint_url=curr.endpoint_url,
                        parameter_name=curr.parameter_name,
                        severity=curr_sev,
                        current_finding=curr.model_dump(mode="json"),
                        baseline_finding=None,
                        confidence_delta=0,
                        explanation="Newly discovered security finding not present in baseline",
                    )
                )

        # 2. Process resolved findings (in baseline but missing from current)
        for fp, base in base_map.items():
            if fp not in curr_map:
                base_sev = base.severity.value if hasattr(base.severity, "value") else str(base.severity)
                items.append(
                    FindingRegressionItem(
                        fingerprint=fp,
                        status=RegressionStatus.RESOLVED,
                        title=base.title,
                        endpoint_url=base.endpoint_url,
                        parameter_name=base.parameter_name,
                        severity=base_sev,
                        current_finding=None,
                        baseline_finding=base.model_dump(mode="json"),
                        confidence_delta=0,
                        explanation="Security finding present in baseline was not detected in candidate scan (RESOLVED)",
                    )
                )

        return items

    def evaluate_regression(
        self,
        baseline_scan_id: str,
        current_scan_id: str,
        baseline_findings: List[Finding],
        current_findings: List[Finding],
        baseline_endpoints: Optional[List[str]] = None,
        current_endpoints: Optional[List[str]] = None,
        target_url: str = "",
    ) -> SecurityRegressionReport:
        """Generate comprehensive Security Regression Report."""
        reg_items = self.compare_findings(baseline_findings, current_findings)

        new_count = sum(1 for i in reg_items if i.status == RegressionStatus.NEW)
        resolved_count = sum(1 for i in reg_items if i.status == RegressionStatus.RESOLVED)
        unchanged_count = sum(1 for i in reg_items if i.status == RegressionStatus.UNCHANGED)
        reopened_count = sum(1 for i in reg_items if i.status == RegressionStatus.REOPENED)
        regressed_count = sum(1 for i in reg_items if i.status in (RegressionStatus.REGRESSED, RegressionStatus.REOPENED))

        # Check blocking regressions (Critical/High regressions or reopenings)
        blocking = any(
            i.status in (RegressionStatus.REGRESSED, RegressionStatus.REOPENED)
            and i.severity.upper() in ("CRITICAL", "HIGH")
            for i in reg_items
        )

        # Surface delta
        base_eps = set(baseline_endpoints or [])
        curr_eps = set(current_endpoints or [])
        delta = AttackSurfaceDelta(
            new_endpoints=sorted(list(curr_eps - base_eps)),
            removed_endpoints=sorted(list(base_eps - curr_eps)),
        )

        return SecurityRegressionReport(
            baseline_scan_id=baseline_scan_id,
            current_scan_id=current_scan_id,
            target_url=target_url,
            total_regressed=regressed_count,
            total_new=new_count,
            total_resolved=resolved_count,
            total_unchanged=unchanged_count,
            total_reopened=reopened_count,
            finding_regressions=reg_items,
            surface_delta=delta,
            has_blocking_regressions=blocking,
        )
