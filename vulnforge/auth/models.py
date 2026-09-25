"""Authentication and Multi-Role Authorization domain models."""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from vulnforge.scanners.result import ResponseDifference
from vulnforge.utils.redaction import redact_dict_secrets, redact_secrets


class AuthMechanism(str, Enum):
    """Supported authentication mechanisms."""

    BEARER_TOKEN = "BEARER_TOKEN"
    COOKIE = "COOKIE"
    API_KEY = "API_KEY"
    BASIC_AUTH = "BASIC_AUTH"
    CUSTOM_HEADER = "CUSTOM_HEADER"
    ANONYMOUS = "ANONYMOUS"


class RoleProfile(BaseModel):
    """Security role profile defining authenticated identity headers and credentials."""

    name: str = Field(..., description="Role identifier (e.g., anonymous, user_a, user_b, admin)")
    role_type: str = Field(default="user", description="Categorical tier: anonymous, user, admin, custom")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers for this identity")
    cookies: Dict[str, str] = Field(default_factory=dict, description="Session cookies for this identity")
    tokens: Dict[str, str] = Field(default_factory=dict, description="Auth tokens or API keys")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Associated user attributes (e.g. user_id, org_id)")

    def get_effective_headers(self) -> Dict[str, str]:
        """Produce request headers for HTTP client."""
        hdrs = dict(self.headers)
        if "bearer" in self.tokens:
            hdrs["Authorization"] = f"Bearer {self.tokens['bearer']}"
        elif "api_key" in self.tokens:
            hdrs["X-API-Key"] = self.tokens["api_key"]
        return hdrs

    def get_effective_cookies(self) -> Dict[str, str]:
        """Produce request cookies for HTTP client."""
        return dict(self.cookies)

    def sanitized_dict(self) -> Dict[str, Any]:
        """Return role profile with all sensitive tokens and passwords redacted."""
        return {
            "name": self.name,
            "role_type": self.role_type,
            "headers": redact_dict_secrets(self.headers),
            "cookies": {k: "[REDACTED]" for k in self.cookies},
            "tokens": {k: "[REDACTED]" for k in self.tokens},
            "metadata": redact_dict_secrets(self.metadata),
        }



class SessionProfile(BaseModel):
    """Session configuration bundling test roles and authentication settings."""

    name: str = Field(default="default-session", description="Profile name")
    mechanism: AuthMechanism = Field(default=AuthMechanism.BEARER_TOKEN, description="Primary auth scheme")
    roles: List[RoleProfile] = Field(default_factory=list, description="Configured role identities")
    default_role: str = Field(default="user", description="Default role to use for scanning")

    def get_role(self, role_name: str) -> Optional[RoleProfile]:
        """Retrieve a role profile by name."""
        for r in self.roles:
            if r.name.lower() == role_name.lower():
                return r
        return None


class AuthorizationViolationType(str, Enum):
    """Classification of broken object and function-level access control vulnerabilities."""

    BOLA = "BOLA"                                    # Broken Object Level Authorization / IDOR
    VERTICAL_PRIVILEGE_ESCALATION = "VERTICAL_PRIVILEGE_ESCALATION" # User accessing Admin function
    HORIZONTAL_PRIVILEGE_ESCALATION = "HORIZONTAL_PRIVILEGE_ESCALATION" # User A accessing User B resource
    UNAUTHENTICATED_ACCESS = "UNAUTHENTICATED_ACCESS" # Anonymous access to protected endpoint
    METHOD_AUTHORIZATION_BYPASS = "METHOD_AUTHORIZATION_BYPASS" # Method tampering (e.g. GET allowed where POST requires auth)


class AuthorizationCheckResult(BaseModel):
    """Results from cross-role authorization comparative inspection."""

    endpoint_url: str = Field(..., description="Target endpoint")
    http_method: str = Field(..., description="HTTP Method tested")
    role_authorized: str = Field(..., description="Role expected to have access (e.g., Admin, User A)")
    role_unauthorized: str = Field(..., description="Role tested for unauthorized access (e.g., User, User B, Anonymous)")
    status_code_authorized: int = Field(..., description="HTTP status for authorized role")
    status_code_unauthorized: int = Field(..., description="HTTP status for unauthorized role")
    is_violation: bool = Field(default=False, description="Whether access control violation occurred")
    violation_type: Optional[AuthorizationViolationType] = Field(
        default=None, description="Specific access control flaw type"
    )
    explanation: str = Field(default="", description="Explainable rationale")
    response_similarity: float = Field(
        default=0.0, description="Similarity ratio between authorized and unauthorized responses"
    )
