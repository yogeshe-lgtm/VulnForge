"""Cross-Site Request Forgery (CSRF) Form Security Scanner."""

from typing import List

from vulnforge.models.endpoint import Endpoint
from vulnforge.scanners.base import BaseScanner, ScannerMode
from vulnforge.scanners.context import AnalysisContext
from vulnforge.scanners.result import (
    Finding,
    FindingSeverity,
    FindingStatus,
    Observation,
    ObservationType,
)


class CSRFScanner(BaseScanner):
    """Detects state-changing HTML forms that lack anti-CSRF token protections."""

    name: str = "csrf"
    description: str = "Detects state-changing forms (POST/PUT/DELETE) lacking anti-CSRF tokens"
    category: str = "CSRF"
    mode: ScannerMode = ScannerMode.PASSIVE
    enabled: bool = True

    CSRF_TOKEN_NAMES = {
        "csrf", "csrftoken", "csrf_token", "_csrf", "_csrf_token",
        "authenticity_token", "_token", "anti_forgery_token", "nonce",
    }

    async def analyze(
        self, context: AnalysisContext, endpoint: Endpoint
    ) -> List[Observation]:
        """Inspect endpoint forms and method signatures for CSRF protections."""
        observations: List[Observation] = []

        # If endpoint has POST method or associated forms
        if endpoint.method.upper() in ("POST", "PUT", "DELETE"):
            param_names = {p.name.lower() for p in endpoint.parameters}
            has_csrf = any(csrf_name in param_names for csrf_name in self.CSRF_TOKEN_NAMES)

            if not has_csrf:
                obs = self.create_observation(
                    endpoint_url=endpoint.url,
                    description=f"State-changing endpoint ({endpoint.method}) lacks visible anti-CSRF token parameter",
                    observation_type=ObservationType.FORM_SIGNATURE,
                    evidence=f"Endpoint: {endpoint.method} {endpoint.url}, Parameters: {', '.join(p.name for p in endpoint.parameters) or 'None'}",
                    confidence=80,
                )
                observations.append(obs)

        return observations

    async def finalize(self, context: AnalysisContext) -> List[Finding]:
        """Synthesize CSRF findings."""
        findings: List[Finding] = []

        for obs in context.observations:
            if obs.scanner == self.name:
                findings.append(
                    self.create_finding(
                        title="Missing Anti-CSRF Token in State-Changing Form",
                        endpoint_url=obs.endpoint_url,
                        category="CSRF",
                        severity=FindingSeverity.MEDIUM,
                        confidence=obs.confidence,
                        status=FindingStatus.POTENTIAL,
                        description=f"The endpoint handles state-changing requests ({obs.description}) without verifying an anti-forgery CSRF token.",
                        evidence=obs.evidence,
                        recommendation="Implement unpredictable, cryptographically strong anti-CSRF tokens and set SameSite=Lax/Strict on session cookies.",
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                            "https://owasp.org/www-community/attacks/csrf",
                        ],
                    )
                )

        return findings
