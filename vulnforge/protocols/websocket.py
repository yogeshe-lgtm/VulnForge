"""WebSocket Security Analyzer (CSWSH, Origin Validation, Transport Security)."""

import base64
import hashlib
import os
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from pydantic import BaseModel, Field

from vulnforge.scanners.result import Finding, FindingSeverity, FindingStatus


class WebSocketAnalysisResult(BaseModel):
    """Telemetry and security assessment for a WebSocket endpoint."""

    endpoint_url: str = Field(..., description="Target WebSocket or upgrade URL")
    is_upgrade_supported: bool = Field(default=False, description="Whether endpoint responded to WebSocket upgrade")
    status_code: int = Field(default=0, description="HTTP response status code on handshake")
    allows_arbitrary_origin: bool = Field(default=False, description="Whether arbitrary Origin was accepted (potential CSWSH)")
    requires_authentication: bool = Field(default=False, description="Whether handshake requires authentication")
    is_unencrypted: bool = Field(default=False, description="Whether endpoint uses unencrypted ws:// or http://")
    subprotocols_supported: List[str] = Field(default_factory=list, description="Supported Sec-WebSocket-Protocol values")
    response_headers: Dict[str, str] = Field(default_factory=dict, description="Captured handshake response headers")
    findings: List[Finding] = Field(default_factory=list, description="Identified security findings")


class WebSocketAnalyzer:
    """Performs controlled, non-destructive security analysis on WebSocket handshake endpoints."""

    CANARY_ORIGIN = "https://untrusted-attacker.example"

    @staticmethod
    def _generate_websocket_key() -> str:
        """Generate a random 16-byte base64-encoded Sec-WebSocket-Key."""
        return base64.b64encode(os.urandom(16)).decode("ascii")

    @classmethod
    async def analyze_endpoint(
        cls,
        http_client: Any,
        target_url: str,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> WebSocketAnalysisResult:
        """Evaluate WebSocket handshake security, origin validation, and encryption."""
        parsed = urlparse(target_url)
        is_unencrypted = parsed.scheme in ("ws", "http")

        # Normalize to http/https for the upgrade handshake request
        scheme = "https" if parsed.scheme in ("wss", "https") else "http"
        http_url = f"{scheme}://{parsed.netloc}{parsed.path or '/'}"
        if parsed.query:
            http_url += f"?{parsed.query}"

        ws_key = cls._generate_websocket_key()

        handshake_headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": ws_key,
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Protocol": "chat, json, stream",
        }
        if auth_headers:
            handshake_headers.update(auth_headers)

        findings: List[Finding] = []
        is_upgrade_supported = False
        allows_arbitrary_origin = False
        requires_auth = False
        status_code = 0
        resp_headers: Dict[str, str] = {}
        subprotocols: List[str] = []

        # 1. Check baseline unauthenticated handshake
        try:
            resp = await http_client.get(http_url, headers=handshake_headers)
            status_code = resp.status_code
            resp_headers = resp.headers

            # 101 Switching Protocols indicates handshake accepted
            if status_code == 101:
                is_upgrade_supported = True
                subproto = resp.headers.get("sec-websocket-protocol", "")
                if subproto:
                    subprotocols = [s.strip() for s in subproto.split(",")]
            elif status_code in (401, 403):
                requires_auth = True

        except Exception:
            pass

        # 2. Check Transport Security
        if is_unencrypted:
            findings.append(
                Finding(
                    scanner="websocket-analyzer",
                    category="Cryptographic Failures",
                    title="Unencrypted WebSocket Connection (ws://)",
                    severity=FindingSeverity.MEDIUM,
                    confidence=95,
                    status=FindingStatus.CONFIRMED,
                    endpoint_url=target_url,
                    description="The WebSocket endpoint uses unencrypted 'ws://' or 'http://' transport, allowing plaintext interception and eavesdropping.",
                    evidence=f"Target URL scheme: {parsed.scheme}",
                    recommendation="Enforce TLS encryption for all WebSocket connections using 'wss://'.",
                    references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
                )
            )

        # 3. Check Cross-Site WebSocket Hijacking (CSWSH) via untrusted Origin probe
        try:
            probe_headers = dict(handshake_headers)
            probe_headers["Origin"] = cls.CANARY_ORIGIN

            resp_cswsh = await http_client.get(http_url, headers=probe_headers)
            if resp_cswsh.status_code == 101:
                allows_arbitrary_origin = True
                findings.append(
                    Finding(
                        scanner="websocket-analyzer",
                        category="Broken Access Control",
                        title="Potential Cross-Site WebSocket Hijacking (CSWSH) - Missing Origin Validation",
                        severity=FindingSeverity.HIGH,
                        confidence=90,
                        status=FindingStatus.CONFIRMED,
                        endpoint_url=target_url,
                        description=(
                            f"The WebSocket handshake accepted an arbitrary cross-origin Origin header ({cls.CANARY_ORIGIN}) "
                            "with HTTP 101 Switching Protocols. A malicious third-party webpage could initiate unauthorized "
                            "WebSocket connections on behalf of logged-in users."
                        ),
                        evidence=f"Handshake with Origin: {cls.CANARY_ORIGIN} returned HTTP 101 Switching Protocols.",
                        recommendation="Implement strict server-side validation of the 'Origin' request header during the WebSocket handshake.",
                        references=[
                            "https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking",
                            "https://owasp.org/www-community/vulnerabilities/Cross-Site_WebSocket_Hijacking",
                        ],
                    )
                )
        except Exception:
            pass

        return WebSocketAnalysisResult(
            endpoint_url=target_url,
            is_upgrade_supported=is_upgrade_supported,
            status_code=status_code,
            allows_arbitrary_origin=allows_arbitrary_origin,
            requires_authentication=requires_auth,
            is_unencrypted=is_unencrypted,
            subprotocols_supported=subprotocols,
            response_headers=resp_headers,
            findings=findings,
        )
