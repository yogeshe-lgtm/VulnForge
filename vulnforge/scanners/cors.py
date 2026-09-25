"""Cross-Origin Resource Sharing (CORS) Misconfiguration Scanner."""

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


class CORSScanner(BaseScanner):
    """Audits Cross-Origin Resource Sharing policies for insecure origin reflection or credential exposure."""

    name: str = "cors"
    description: str = "Detects insecure CORS origin reflection and wildcard credential configurations"
    category: str = "CORS"
    mode: ScannerMode = ScannerMode.SAFE_ACTIVE
    enabled: bool = True

    CANARY_ORIGIN = "https://evil-attacker.example"

    async def analyze(
        self, context: AnalysisContext, endpoint: Endpoint
    ) -> List[Observation]:
        """Send a benign cross-origin probe header and evaluate CORS response headers."""
        observations: List[Observation] = []

        try:
            resp = await context.http.get(
                endpoint.url,
                headers={"Origin": self.CANARY_ORIGIN},
            )

            acao = resp.headers.get("access-control-allow-origin") or resp.headers.get("Access-Control-Allow-Origin")
            acac = resp.headers.get("access-control-allow-credentials") or resp.headers.get("Access-Control-Allow-Credentials")

            if acao:
                # 1. Arbitrary Origin Reflection
                if self.CANARY_ORIGIN in acao or acao == self.CANARY_ORIGIN:
                    is_creds = acac and acac.lower() == "true"
                    obs = self.create_observation(
                        endpoint_url=endpoint.url,
                        description=f"CORS policy reflects arbitrary Origin header{' with Allow-Credentials: true' if is_creds else ''}",
                        observation_type=ObservationType.SECURITY_HEADER,
                        evidence=f"Origin: {self.CANARY_ORIGIN} -> ACAO: {acao}, ACAC: {acac or 'false'}",
                        confidence=95 if is_creds else 85,
                    )
                    observations.append(obs)
                # 2. Wildcard with Credentials
                elif acao == "*" and acac and acac.lower() == "true":
                    obs = self.create_observation(
                        endpoint_url=endpoint.url,
                        description="CORS policy specifies wildcard '*' with Allow-Credentials: true",
                        observation_type=ObservationType.SECURITY_HEADER,
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        confidence=95,
                    )
                    observations.append(obs)
        except Exception:
            pass

        return observations

    async def finalize(self, context: AnalysisContext) -> List[Finding]:
        """Synthesize CORS findings."""
        findings: List[Finding] = []

        for obs in context.observations:
            if obs.scanner == self.name:
                with_creds = "Allow-Credentials: true" in obs.description or "ACAC: true" in obs.evidence
                severity = FindingSeverity.HIGH if with_creds else FindingSeverity.MEDIUM
                findings.append(
                    self.create_finding(
                        title="Insecure Cross-Origin Resource Sharing (CORS) Policy",
                        endpoint_url=obs.endpoint_url,
                        category="CORS",
                        severity=severity,
                        confidence=obs.confidence,
                        status=FindingStatus.CONFIRMED,
                        description="The server reflects untrusted arbitrary Origin headers, allowing malicious cross-origin websites to read private responses.",
                        evidence=obs.evidence,
                        recommendation="Implement an explicit whitelist of trusted origins and avoid echoing the request Origin header.",
                        references=[
                            "https://portswigger.net/web-security/cors",
                            "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                        ],
                    )
                )

        return findings
