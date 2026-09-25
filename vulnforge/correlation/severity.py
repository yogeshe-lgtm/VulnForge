"""Contextual severity calculation engine for security findings."""

from dataclasses import dataclass
from enum import Enum
from typing import List, Optional

from vulnforge.scanners.result import FindingSeverity


class AuthRequirement(str, Enum):
    """Authentication requirement needed to exploit the finding."""

    NONE = "None (Pre-auth / Public)"
    LOW_PRIVILEGED = "Low Privileged User"
    HIGH_PRIVILEGED = "Admin / High Privileged"


class DataExposureLevel(str, Enum):
    """Sensitivity level of data exposed or compromised."""

    NONE = "None"
    METADATA = "System Metadata / Architecture info"
    INTERNAL = "Internal Routes / Source fragments"
    PII = "Personal Identifiable Information (PII)"
    CREDENTIALS = "Passwords / Session Tokens / API Keys"


@dataclass
class SeverityContext:
    """Contextual factors modulating the raw impact of a security finding."""

    endpoint_url: str
    category: str
    auth_requirement: AuthRequirement = AuthRequirement.NONE
    data_exposure: DataExposureLevel = DataExposureLevel.NONE
    confidence_score: int = 50
    is_api_route: bool = False
    is_sensitive_path: bool = False


class SeverityEngine:
    """Computes realistic contextual severity considering environment and impact metrics."""

    CRITICAL_CATEGORIES = {
        "remote code execution", "rce", "sql injection", "sqli", "command injection",
        "authentication bypass", "deserialization",
    }
    HIGH_CATEGORIES = {
        "ssrf", "server-side request forgery", "xss", "cross-site scripting",
        "idor", "broken object level auth", "bola", "path traversal", "lfi",
        "file upload",
    }
    MEDIUM_CATEGORIES = {
        "cors", "csrf", "cross-site request forgery", "open redirect",
        "information disclosure", "security misconfiguration",
    }
    LOW_CATEGORIES = {
        "security headers", "transport security", "cache-control",
        "cookie security", "architecture",
    }

    SENSITIVE_PATHS = {
        "/admin", "/api/admin", "/auth", "/login", "/register", "/oauth",
        "/api/payment", "/checkout", "/user/profile", "/reset-password",
        "/internal", "/management", "/actuator",
    }

    @classmethod
    def calculate_severity(
        cls,
        category: str,
        endpoint_url: str,
        confidence_score: int = 50,
        auth_required: AuthRequirement = AuthRequirement.NONE,
        data_exposure: DataExposureLevel = DataExposureLevel.NONE,
        is_api: bool = False,
    ) -> FindingSeverity:
        """Calculate contextual severity combining category baseline with environment factors.

        Args:
            category: Vulnerability or audit category.
            endpoint_url: URL of the affected route.
            confidence_score: Confidence rating 0-100.
            auth_required: Level of authentication needed.
            data_exposure: Level of sensitive data exposure.
            is_api: Whether the route is an API endpoint.

        Returns:
            Calculated FindingSeverity (CRITICAL, HIGH, MEDIUM, LOW, INFO).
        """
        cat_lower = category.lower().strip()
        url_lower = endpoint_url.lower()

        # 1. Determine baseline numeric score (0-100)
        if any(c in cat_lower for c in cls.CRITICAL_CATEGORIES):
            base_score = 90
        elif any(c in cat_lower for c in cls.HIGH_CATEGORIES):
            base_score = 75
        elif any(c in cat_lower for c in cls.MEDIUM_CATEGORIES):
            base_score = 50
        elif any(c in cat_lower for c in cls.LOW_CATEGORIES):
            base_score = 25
        else:
            base_score = 30

        score = base_score

        # 2. Modulate based on sensitive route path
        is_sensitive = any(sp in url_lower for sp in cls.SENSITIVE_PATHS)
        if is_sensitive:
            score += 10

        # 3. Modulate based on Data Exposure
        if data_exposure == DataExposureLevel.CREDENTIALS:
            score += 20
        elif data_exposure == DataExposureLevel.PII:
            score += 15
        elif data_exposure == DataExposureLevel.INTERNAL:
            score += 5

        # 4. Modulate based on Authentication Requirement
        if auth_required == AuthRequirement.HIGH_PRIVILEGED:
            score -= 15
        elif auth_required == AuthRequirement.LOW_PRIVILEGED:
            score -= 5
        elif auth_required == AuthRequirement.NONE and is_sensitive:
            score += 5

        # 5. Modulate by confidence: low confidence dampens high severity claims
        if confidence_score < 40:
            score -= 20
        elif confidence_score < 60:
            score -= 10
        elif confidence_score >= 90:
            score += 5

        # Clamp and map to FindingSeverity enum
        final_score = max(0, min(100, score))

        if final_score >= 85:
            return FindingSeverity.CRITICAL
        elif final_score >= 65:
            return FindingSeverity.HIGH
        elif final_score >= 45:
            return FindingSeverity.MEDIUM
        elif final_score >= 20:
            return FindingSeverity.LOW
        return FindingSeverity.INFO
