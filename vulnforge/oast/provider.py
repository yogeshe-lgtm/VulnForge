"""OAST Provider implementations and correlation manager."""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import httpx

from vulnforge.oast.models import CallbackEvent, CallbackToken, OASTProviderType
from vulnforge.scanners.result import Finding, FindingSeverity, FindingStatus


class OASTProvider(ABC):
    """Abstract interface for Out-of-Band Application Security Testing (OAST) callback services."""

    def __init__(self, base_domain: str = "oast.vulnforge.local"):
        self.base_domain = base_domain
        self.registered_tokens: Dict[str, CallbackToken] = {}
        self.captured_events: List[CallbackEvent] = []

    def create_canary(
        self,
        scanner_name: str,
        target_url: str,
        parameter_name: Optional[str] = None,
    ) -> CallbackToken:
        """Generate a unique tracking token for blind vulnerability verification."""
        token = CallbackToken.generate(
            scanner_name=scanner_name,
            target_url=target_url,
            base_oast_domain=self.base_domain,
            parameter_name=parameter_name,
        )
        self.registered_tokens[token.token_id] = token
        return token

    @abstractmethod
    async def poll_events(self) -> List[CallbackEvent]:
        """Poll the callback listener for newly received events."""
        raise NotImplementedError

    def record_local_event(self, event: CallbackEvent) -> None:
        """Register a received callback event in the provider memory."""
        self.captured_events.append(event)

    def correlate(self) -> List[Finding]:
        """Correlate captured events against registered tokens to synthesize confirmed blind findings."""
        findings: List[Finding] = []
        for event in self.captured_events:
            token = self.registered_tokens.get(event.token_id)
            if not token:
                continue

            findings.append(
                Finding(
                    scanner=token.scanner_name,
                    category="Out-of-Band Vulnerability",
                    title=f"Out-of-Band (OAST) Callback Received via {event.protocol} on {token.target_url}",
                    severity=FindingSeverity.CRITICAL,
                    confidence=100,
                    status=FindingStatus.CONFIRMED,
                    endpoint_url=token.target_url,
                    parameter_name=token.parameter_name,
                    description=(
                        f"A verified out-of-band {event.protocol} callback was received from client IP {event.client_ip} "
                        f"for canary token '{token.token_id}'. This confirms blind command execution, SSRF, or XXE injection."
                    ),
                    evidence=f"Protocol: {event.protocol}, Remote IP: {event.client_ip}, Time: {event.timestamp.isoformat()}",
                    recommendation="Investigate and remediate blind injection vector on the affected endpoint/parameter immediately.",
                    references=[
                        "https://owasp.org/Top10/A03_2021-Injection/",
                        "https://portswigger.net/burp/application-security-testing/oast",
                    ],
                )
            )

        return findings


class SelfHostedOASTProvider(OASTProvider):
    """In-memory and local mock OAST provider for testing and private deployments."""

    def __init__(self, base_domain: str = "oast.vulnforge.local"):
        super().__init__(base_domain=base_domain)

    async def poll_events(self) -> List[CallbackEvent]:
        """Return captured events."""
        return list(self.captured_events)


class GenericHTTPCallbackProvider(OASTProvider):
    """Integrates with an external generic HTTP webhook / callback API server."""

    def __init__(self, api_url: str, api_key: Optional[str] = None, base_domain: str = "oast.example.com"):
        super().__init__(base_domain=base_domain)
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key

    async def poll_events(self) -> List[CallbackEvent]:
        """Fetch remote events from webhook server."""
        headers = {}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        events: List[CallbackEvent] = []
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{self.api_url}/events", headers=headers)
                if resp.status_code == 200:
                    raw_data = resp.json()
                    for item in raw_data:
                        evt = CallbackEvent(
                            token_id=item.get("token_id", ""),
                            protocol=item.get("protocol", "HTTP"),
                            client_ip=item.get("client_ip", "127.0.0.1"),
                            http_method=item.get("method"),
                            headers=item.get("headers", {}),
                        )
                        events.append(evt)
                        self.record_local_event(evt)
        except Exception:
            pass

        return events
