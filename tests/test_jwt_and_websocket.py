"""Unit and integration tests for JWT and WebSocket protocol analyzers."""

import base64
import json
import pytest
from unittest.mock import AsyncMock, MagicMock

from vulnforge.models.response import HttpResponse
from vulnforge.protocols.jwt import JWTAnalyzer, JWTAnalysisResult
from vulnforge.protocols.websocket import WebSocketAnalyzer, WebSocketAnalysisResult
from vulnforge.scanners.result import FindingSeverity


def _make_jwt(header: dict, payload: dict, signature: str = "dGVzdHNpZw") -> str:
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h_b64}.{p_b64}.{signature}"


def test_jwt_none_algorithm_detection():
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "user123", "role": "admin"}
    token = _make_jwt(header, payload, signature="")

    result = JWTAnalyzer.analyze_token(token)
    assert result.is_valid_structure is True
    assert result.is_none_algorithm is True
    assert result.algorithm == "none"
    assert len(result.findings) >= 1
    assert any("Insecure JWT Algorithm: 'none'" in f.title for f in result.findings)
    assert any(f.severity == FindingSeverity.CRITICAL for f in result.findings)


def test_jwt_sensitive_claim_and_missing_exp_detection():
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user": "alice", "password": "SuperSecretPassword123!", "api_key": "key-xyz"}
    token = _make_jwt(header, payload)

    result = JWTAnalyzer.analyze_token(token)
    assert result.is_valid_structure is True
    assert result.is_none_algorithm is False
    assert "password" in result.sensitive_claims_exposed
    assert "api_key" in result.sensitive_claims_exposed
    # Secrets should be redacted in returned claims dict
    assert result.claims["password"] == "[REDACTED]"
    assert any("Sensitive Data Exposed" in f.title for f in result.findings)
    assert any("Missing Expiration" in f.title for f in result.findings)


def test_jwt_discovery_in_text():
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"user": "bob"}
    token = _make_jwt(header, payload)

    text_blob = f"Here is the token stored in localStorage: {token} and some other text."
    results = JWTAnalyzer.extract_and_analyze_tokens_from_text(text_blob)
    assert len(results) == 1
    assert results[0].algorithm == "HS256"


@pytest.mark.asyncio
async def test_websocket_cswsh_and_unencrypted_detection():
    mock_http = MagicMock()

    # Handshake response allowing arbitrary origin
    async def mock_get(url, headers=None, **kwargs):
        headers = headers or {}
        origin = headers.get("Origin")
        if origin == "https://untrusted-attacker.example":
            # Vulnerable server accepts cross-origin handshake
            return HttpResponse(
                url=url,
                request_url=url,
                request_method="GET",
                status_code=101,
                headers={
                    "Upgrade": "websocket",
                    "Connection": "Upgrade",
                    "Sec-WebSocket-Accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
                },
                body="",
                elapsed=0.04,
            )
        return HttpResponse(
            url=url,
            request_url=url,
            request_method="GET",
            status_code=101,
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
            },
            body="",
            elapsed=0.04,
        )

    mock_http.get = AsyncMock(side_effect=mock_get)

    result = await WebSocketAnalyzer.analyze_endpoint(
        http_client=mock_http,
        target_url="ws://example.com/socket",
    )

    assert result.is_upgrade_supported is True
    assert result.allows_arbitrary_origin is True
    assert result.is_unencrypted is True
    assert len(result.findings) >= 2

    finding_titles = [f.title for f in result.findings]
    assert any("Cross-Site WebSocket Hijacking" in t for t in finding_titles)
    assert any("Unencrypted WebSocket Connection" in t for t in finding_titles)
