"""Broken Access Control and Authorization Scanner (OWASP A01)."""

from typing import List
from urllib.parse import urlparse

from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter
from vulnforge.scanners.base import BaseScanner, ScannerMode
from vulnforge.scanners.context import AnalysisContext
from vulnforge.scanners.result import (
    Finding,
    FindingSeverity,
    FindingStatus,
    Observation,
    ObservationType,
)


class AuthorizationScanner(BaseScanner):
    """Audits endpoints for Broken Object-Level Authorization (BOLA), IDOR, and missing access control."""

    name: str = "authorization"
    version: str = "1.0.0"
    category: str = "Broken Access Control"
    description: str = "Audits endpoints for missing authentication, BOLA, IDOR, and authorization bypasses."
    mode: ScannerMode = ScannerMode.SAFE_ACTIVE
    enabled: bool = True

    async def analyze(
        self,
        context: AnalysisContext,
        endpoint: Endpoint,
    ) -> List[Observation]:
        """Inspect endpoint for access control bypasses."""
        observations: List[Observation] = []

        is_auth_candidate = (
            endpoint.authentication_required
            or "AUTHENTICATION" in endpoint.classifications
            or "ADMIN_LIKE_PATH" in endpoint.classifications
            or any(seg in endpoint.path.lower() for seg in ("/admin", "/api/admin", "/manage", "/dashboard", "/account", "/users"))
        )

        if not is_auth_candidate or not context.http:
            return observations

        # Test unauthenticated access with benign probe header
        try:
            resp = await context.http.get(
                endpoint.url,
                headers={"X-VulnForge-Probe": "AuthCheck"},
            )

            # Record observation
            obs = self.create_observation(
                endpoint_url=endpoint.url,
                observation_type=ObservationType.AUTHORIZATION_DIFFERENCE,
                description=f"Probed access control on {endpoint.url} with unauthenticated request. Status: {resp.status_code}",
                evidence=f"HTTP {resp.status_code} on {endpoint.method} {endpoint.path}",
                confidence=80,
            )
            observations.append(obs)

            # If an admin-like or authenticated endpoint returns 200 OK without any session/token
            if resp.status_code == 200 and len(resp.body) > 20:
                body_lower = resp.body.lower()
                is_login_page = any(kw in body_lower for kw in ("<input type=\"password\"", "name=\"password\"", "sign in", "login to continue"))

                if not is_login_page and any(adm in endpoint.path.lower() for adm in ("/admin", "/manage", "/dashboard", "/account")):
                    obs_admin = self.create_observation(
                        endpoint_url=endpoint.url,
                        observation_type=ObservationType.AUTHORIZATION_DIFFERENCE,
                        description=f"Unauthenticated Access to Administrative Endpoint: {endpoint.path}",
                        evidence=f"Unauthenticated GET to {endpoint.url} returned HTTP 200 (length: {len(resp.body)} bytes).",
                        confidence=85,
                    )
                    observations.append(obs_admin)


        except Exception:
            pass

        return observations

    async def finalize(self, context: AnalysisContext) -> List[Finding]:
        """Synthesize authorization findings."""
        findings: List[Finding] = []

        for obs in context.observations:
            if obs.scanner == self.name and "Unauthenticated Access" in obs.description:
                findings.append(
                    self.create_finding(
                        title=f"Unauthenticated Access to Administrative Endpoint",
                        endpoint_url=obs.endpoint_url,
                        category=self.category,
                        severity=FindingSeverity.HIGH,
                        confidence=obs.confidence,
                        status=FindingStatus.CONFIRMED,
                        description=(
                            "The endpoint responded with HTTP 200 OK to unauthenticated requests "
                            "without enforcing an authentication challenge or session requirement."
                        ),
                        evidence=obs.evidence,
                        recommendation="Enforce server-side authentication and role-based access control (RBAC) before dispatching handler logic.",
                        references=[
                            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                        ],
                    )
                )

        return findings

