"""Authentication and Multi-Role Authorization module for VulnForge."""

from vulnforge.auth.engine import MultiRoleAuthorizationEngine
from vulnforge.auth.models import (
    AuthMechanism,
    AuthorizationCheckResult,
    AuthorizationViolationType,
    RoleProfile,
    SessionProfile,
)

__all__ = [
    "AuthMechanism",
    "RoleProfile",
    "SessionProfile",
    "AuthorizationViolationType",
    "AuthorizationCheckResult",
    "MultiRoleAuthorizationEngine",
]
