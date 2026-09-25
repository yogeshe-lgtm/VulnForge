"""Multi-Role Authorization Engine - Comparative BOLA, IDOR, and privilege escalation analyzer."""

import difflib
from typing import Any, Dict, List, Optional

from vulnforge.auth.models import (
    AuthorizationCheckResult,
    AuthorizationViolationType,
    RoleProfile,
    SessionProfile,
)
from vulnforge.models.endpoint import Endpoint
from vulnforge.scanners.result import Finding, FindingSeverity, FindingStatus, Observation, ObservationType
from vulnforge.utils.redaction import redact_secrets


class MultiRoleAuthorizationEngine:
    """Conducts differential cross-identity testing to discover broken object and function-level authorization."""

    @staticmethod
    async def compare_role_access(
        http_engine: Any,
        endpoint_url: str,
        method: str,
        role_auth: RoleProfile,
        role_unauth: RoleProfile,
        expected_authorized: bool = True,
        violation_type: AuthorizationViolationType = AuthorizationViolationType.VERTICAL_PRIVILEGE_ESCALATION,
    ) -> AuthorizationCheckResult:
        """Execute request under authorized identity and unauthorized identity, comparing status codes and bodies."""
        # 1. Request with authorized role
        resp_auth = await http_engine.request(
            method=method,
            url=endpoint_url,
            headers=role_auth.get_effective_headers(),
            cookies=role_auth.get_effective_cookies(),
        )

        # 2. Request with unauthorized/lower-privilege role
        resp_unauth = await http_engine.request(
            method=method,
            url=endpoint_url,
            headers=role_unauth.get_effective_headers(),
            cookies=role_unauth.get_effective_cookies(),
        )

        auth_ok = 200 <= resp_auth.status_code < 300
        unauth_ok = 200 <= resp_unauth.status_code < 300

        # Calculate response similarity
        similarity = 0.0
        if resp_auth.body and resp_unauth.body:
            matcher = difflib.SequenceMatcher(None, resp_auth.body[:2000], resp_unauth.body[:2000])
            similarity = matcher.ratio()

        is_violation = False
        explanation = ""

        if expected_authorized and auth_ok:
            if unauth_ok and resp_unauth.status_code == resp_auth.status_code:
                # Unauthorized identity got 200 OK with substantial response body
                if len(resp_unauth.body) > 20 and similarity > 0.6:
                    is_violation = True
                    explanation = (
                        f"Unauthorized role '{role_unauth.name}' received HTTP {resp_unauth.status_code} "
                        f"(identical to authorized role '{role_auth.name}') with {similarity*100:.1f}% body match."
                    )
            elif unauth_ok and resp_unauth.status_code in (200, 201, 204):
                is_violation = True
                explanation = (
                    f"Unauthorized role '{role_unauth.name}' performed action successfully with HTTP {resp_unauth.status_code}."
                )

        return AuthorizationCheckResult(
            endpoint_url=endpoint_url,
            http_method=method,
            role_authorized=role_auth.name,
            role_unauthorized=role_unauth.name,
            status_code_authorized=resp_auth.status_code,
            status_code_unauthorized=resp_unauth.status_code,
            is_violation=is_violation,
            violation_type=violation_type if is_violation else None,
            explanation=explanation,
            response_similarity=similarity,
        )

    @classmethod
    def generate_findings(cls, results: List[AuthorizationCheckResult]) -> List[Finding]:
        """Convert authorization check violations into explainable security findings."""
        findings: List[Finding] = []

        for r in results:
            if not r.is_violation or not r.violation_type:
                continue

            sev = (
                FindingSeverity.CRITICAL
                if r.violation_type in (
                    AuthorizationViolationType.VERTICAL_PRIVILEGE_ESCALATION,
                    AuthorizationViolationType.BOLA,
                )
                else FindingSeverity.HIGH
            )

            title_map = {
                AuthorizationViolationType.VERTICAL_PRIVILEGE_ESCALATION: (
                    f"Vertical Privilege Escalation: '{r.role_unauthorized}' Accessed Protected Resource"
                ),
                AuthorizationViolationType.BOLA: (
                    f"Broken Object Level Authorization (BOLA/IDOR) on {r.endpoint_url}"
                ),
                AuthorizationViolationType.HORIZONTAL_PRIVILEGE_ESCALATION: (
                    f"Horizontal Authorization Bypass between '{r.role_authorized}' and '{r.role_unauthorized}'"
                ),
                AuthorizationViolationType.UNAUTHENTICATED_ACCESS: (
                    f"Unauthenticated Access to Protected Endpoint {r.endpoint_url}"
                ),
                AuthorizationViolationType.METHOD_AUTHORIZATION_BYPASS: (
                    f"HTTP Method Authorization Bypass on {r.endpoint_url}"
                ),
            }

            title = title_map.get(r.violation_type, f"Authorization Bypass on {r.endpoint_url}")

            findings.append(
                Finding(
                    scanner="authorization-engine",
                    category="Broken Access Control",
                    title=title,
                    severity=sev,
                    confidence=90,
                    status=FindingStatus.CONFIRMED,
                    endpoint_url=r.endpoint_url,
                    description=(
                        f"Access control check detected that identity '{r.role_unauthorized}' was able to access "
                        f"restricted resource '{r.endpoint_url}' ([{r.http_method}]). {r.explanation}"
                    ),
                    evidence=r.explanation,
                    recommendation=(
                        "Implement strict server-side authorization checks verifying user permissions, object ownership, "
                        "and role boundaries before returning data or processing state changes."
                    ),
                    references=[
                        "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Testing_Automation_Cheat_Sheet.html",
                    ],
                )
            )

        return findings
