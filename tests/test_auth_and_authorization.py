"""Tests for authentication models, multi-role authorization engine, and authorization scanner."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from vulnforge.auth.models import (
    AuthMechanism,
    RoleProfile,
    SessionProfile,
    AuthorizationViolationType,
)
from vulnforge.auth.engine import MultiRoleAuthorizationEngine
from vulnforge.scanners.result import FindingSeverity
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter
from vulnforge.models.target import Target
from vulnforge.scanners.authorization import AuthorizationScanner
from vulnforge.scanners.context import ScannerContext
from vulnforge.models.response import HttpResponse


def test_session_profile_headers_and_redaction():
    role = RoleProfile(
        name="admin",
        role_type="admin",
        tokens={"bearer": "secret-token-12345678"},
        cookies={"sessionid": "secret-cookie-value-999"},
        headers={"X-Custom-Auth": "custom-auth-val"},
    )
    session = SessionProfile(
        name="admin_session",
        mechanism=AuthMechanism.BEARER_TOKEN,
        roles=[role],
        default_role="admin",
    )

    headers = role.get_effective_headers()
    assert headers["Authorization"] == "Bearer secret-token-12345678"
    assert headers["X-Custom-Auth"] == "custom-auth-val"

    redacted = role.sanitized_dict()
    assert "secret-token" not in str(redacted["tokens"])
    assert "secret-cookie" not in str(redacted["cookies"])
    assert redacted["tokens"]["bearer"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_multi_role_authorization_engine():
    role_admin = RoleProfile(name="admin", role_type="admin", tokens={"bearer": "adm-tok-123"})
    role_user = RoleProfile(name="user", role_type="user", tokens={"bearer": "usr-tok-456"})

    endpoint_url = "https://example.com/api/admin/users"

    mock_http = MagicMock()

    async def mock_request(method, url, headers=None, cookies=None, **kwargs):
        headers = headers or {}
        auth_hdr = headers.get("Authorization", "")
        if "adm-tok" in auth_hdr:
            return HttpResponse(
                url=url,
                request_url=url,
                request_method=method,
                status_code=200,
                headers={"content-type": "application/json"},
                body='{"users": ["alice", "bob"]}',
                elapsed=0.05,
            )
        elif "usr-tok" in auth_hdr:
            # Flawed API: returns 200 OK with admin data to regular user (BOLA/BFLA)
            return HttpResponse(
                url=url,
                request_url=url,
                request_method=method,
                status_code=200,
                headers={"content-type": "application/json"},
                body='{"users": ["alice", "bob"]}',
                elapsed=0.045,
            )
        else:
            return HttpResponse(
                url=url,
                request_url=url,
                request_method=method,
                status_code=401,
                headers={"content-type": "application/json"},
                body='{"error": "Unauthorized"}',
                elapsed=0.03,
            )

    mock_http.request = AsyncMock(side_effect=mock_request)

    result = await MultiRoleAuthorizationEngine.compare_role_access(
        http_engine=mock_http,
        endpoint_url=endpoint_url,
        method="GET",
        role_auth=role_admin,
        role_unauth=role_user,
        violation_type=AuthorizationViolationType.VERTICAL_PRIVILEGE_ESCALATION,
    )

    assert result.is_violation is True
    assert result.violation_type == AuthorizationViolationType.VERTICAL_PRIVILEGE_ESCALATION

    findings = MultiRoleAuthorizationEngine.generate_findings([result])
    assert len(findings) == 1
    assert "Vertical Privilege Escalation" in findings[0].title
    assert findings[0].severity == FindingSeverity.CRITICAL


@pytest.mark.asyncio
async def test_authorization_scanner_unauthenticated_admin_detection():
    scanner = AuthorizationScanner()
    target = Target.from_url("https://example.com")
    endpoint = Endpoint.from_url(
        "https://example.com/admin/dashboard",
        method="GET",
    )
    endpoint.authentication_required = True
    endpoint.classifications = ["AUTHENTICATION", "ADMIN_LIKE_PATH"]

    mock_http = MagicMock()
    mock_http.get = AsyncMock(return_value=HttpResponse(
        url=endpoint.url,
        request_url=endpoint.url,
        request_method="GET",
        status_code=200,
        headers={"content-type": "text/html"},
        body="<html><body><h1>Administrative Dashboard</h1><p>Welcome to root settings</p></body></html>",
        elapsed=0.05,
    ))

    context = ScannerContext(target=target, http=mock_http)
    observations = await scanner.analyze(context, endpoint)
    for obs in observations:
        context.add_observation(obs)
    findings = await scanner.finalize(context)

    assert len(findings) == 1
    assert "Unauthenticated Access" in findings[0].title
    assert findings[0].severity == FindingSeverity.HIGH
    assert findings[0].confidence == 85


