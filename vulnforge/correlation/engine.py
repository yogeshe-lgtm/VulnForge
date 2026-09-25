"""Multi-signal correlation engine synthesizing observations into high-confidence findings."""

from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

from vulnforge.correlation.confidence import ConfidenceEngine
from vulnforge.correlation.deduplicator import FindingDeduplicator
from vulnforge.correlation.severity import SeverityEngine
from vulnforge.scanners.result import (
    Finding,
    FindingSeverity,
    FindingStatus,
    Observation,
    ObservationType,
)
from vulnforge.utils.redaction import redact_secrets


class CorrelationEngine:
    """Correlates multi-source telemetry observations and candidate findings."""

    def __init__(self):
        """Initialize CorrelationEngine."""
        self.confidence_engine = ConfidenceEngine()
        self.severity_engine = SeverityEngine()
        self.deduplicator = FindingDeduplicator()

    def correlate(
        self,
        observations: List[Observation],
        candidate_findings: Optional[List[Finding]] = None,
    ) -> List[Finding]:
        """Correlate observations and candidate findings into consolidated security findings.

        Args:
            observations: List of raw telemetry observations.
            candidate_findings: Findings produced by individual scanners.

        Returns:
            Correlated, scored, and deduplicated list of Findings.
        """
        findings = list(candidate_findings) if candidate_findings else []

        # 1. Group observations by endpoint and parameter
        obs_groups: Dict[Tuple[str, Optional[str]], List[Observation]] = {}
        for obs in observations:
            parsed = urlparse(obs.endpoint_url)
            norm_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            key = (norm_url, obs.parameter_name)
            obs_groups.setdefault(key, []).append(obs)

        # 2. Synthesize correlated findings from multi-observation patterns
        for (norm_url, param), group_obs in obs_groups.items():
            obs_types = {o.observation_type for o in group_obs}

            # Check: REFLECTION + PARAMETER_PATTERN or ERROR_PATTERN
            if ObservationType.REFLECTION in obs_types and (
                ObservationType.PARAMETER_PATTERN in obs_types
                or ObservationType.URL_INPUT in obs_types
            ):
                conf_report = self.confidence_engine.evaluate(
                    base_score=60,
                    observations=group_obs,
                )
                severity = self.severity_engine.calculate_severity(
                    category="Input Validation",
                    endpoint_url=norm_url,
                    confidence_score=conf_report.score,
                )
                evidences = [redact_secrets(o.evidence) for o in group_obs if o.evidence]
                finding = Finding(
                    scanner="correlation-engine",
                    category="Input Validation",
                    title="Unsanitized Input Reflection Detected",
                    severity=severity,
                    confidence=conf_report.score,
                    status=self.confidence_engine.determine_finding_status(conf_report.score),
                    endpoint_url=norm_url,
                    parameter_name=param,
                    description=(
                        f"Parameter '{param or 'query'}' is reflected in the server response body without output sanitization."
                    ),
                    evidence="\n".join(evidences),
                    recommendation="Apply context-aware output encoding (HTML, JavaScript, attribute context) before reflection.",
                    references=[
                        "https://owasp.org/www-community/attacks/xss/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                    ],
                )
                findings.append(finding)

        # 3. Enhance and re-score candidate findings with correlation signals
        enhanced_findings: List[Finding] = []
        for finding in findings:
            # Find matching observations
            matching_obs = [
                o for o in observations
                if o.endpoint_url == finding.endpoint_url
                and (o.parameter_name == finding.parameter_name or not finding.parameter_name)
            ]

            conf_report = self.confidence_engine.evaluate(
                base_score=finding.confidence,
                observations=matching_obs,
            )

            contextual_sev = self.severity_engine.calculate_severity(
                category=finding.category,
                endpoint_url=finding.endpoint_url,
                confidence_score=conf_report.score,
            )

            status = self.confidence_engine.determine_finding_status(conf_report.score)

            updated = Finding(
                id=finding.id,
                scanner=finding.scanner,
                category=finding.category,
                title=finding.title,
                severity=contextual_sev,
                confidence=conf_report.score,
                status=status,
                endpoint_url=finding.endpoint_url,
                parameter_name=finding.parameter_name,
                description=finding.description,
                evidence=redact_secrets(finding.evidence),
                recommendation=finding.recommendation,
                references=finding.references,
                created_at=finding.created_at,
            )
            enhanced_findings.append(updated)

        # 4. Deduplicate and merge findings
        return self.deduplicator.merge(enhanced_findings)
