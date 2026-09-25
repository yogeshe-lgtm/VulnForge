"""Unit tests for Phase 3A Scanner Framework and Finding Pipeline."""

import pytest
from datetime import datetime, timezone
from typing import List

from vulnforge.core.config import VulnForgeConfig
from vulnforge.core.context import ScanContext
from vulnforge.core.rate_limiter import RateLimiter
from vulnforge.core.scope import ScopeEngine
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter, ParameterLocation
from vulnforge.models.response import HttpResponse
from vulnforge.models.target import Target
from vulnforge.scanners.base import BaseScanner, ScannerMode
from vulnforge.scanners.context import AnalysisContext
from vulnforge.scanners.endpoint_inspector import EndpointInspectorScanner
from vulnforge.scanners.engine import ScannerEngine
from vulnforge.scanners.exceptions import ScannerRegistrationError
from vulnforge.scanners.registry import ScannerRegistry
from vulnforge.scanners.result import (
    Finding,
    FindingSeverity,
    FindingStatus,
    Observation,
    ObservationType,
    ResponseDifference,
    compare_response,
    compare_responses,
)
from vulnforge.storage.database import DatabaseManager


class DummyTestScanner(BaseScanner):
    """Mock scanner for testing registration and lifecycle hooks."""

    name: str = "dummy-test-scanner"
    description: str = "Test module for scanner framework unit testing"
    category: str = "Test"
    mode: ScannerMode = ScannerMode.ANALYSIS
    enabled: bool = True

    async def analyze(
        self, context: AnalysisContext, endpoint: Endpoint
    ) -> List[Observation]:
        obs = self.create_observation(
            endpoint_url=endpoint.url,
            description=f"Mock observation on {endpoint.url}",
            observation_type=ObservationType.REFLECTION,
            evidence="Mock evidence",
            confidence=80,
        )
        return [obs]

    async def finalize(self, context: AnalysisContext) -> List[Finding]:
        finding = self.create_finding(
            title="Mock Finding Title",
            endpoint_url=context.target.normalized_url,
            description="Mock finding description",
            severity=FindingSeverity.LOW,
            confidence=85,
            status=FindingStatus.POTENTIAL,
        )
        return [finding]


def create_mock_scan_context(url: str = "https://example.local") -> ScanContext:
    """Helper to generate a mock ScanContext."""
    target = Target.from_url(url, allow_private=True)
    config = VulnForgeConfig()
    scope = ScopeEngine(allowed_domains=target.scope)
    rate_limiter = RateLimiter(rate=10.0, concurrency=2)
    return ScanContext(
        target=target,
        config=config,
        scope=scope,
        rate_limiter=rate_limiter,
    )


class TestScannerRegistration:
    """Tests for ScannerRegistry registration and lifecycle."""

    def setup_method(self):
        """Reset registry before each test."""
        ScannerRegistry.clear()

    def test_register_and_list_scanner(self):
        """Test registering a scanner instance and retrieving it."""
        scanner = DummyTestScanner()
        ScannerRegistry.register(scanner)

        registered = ScannerRegistry.list()
        assert len(registered) == 1
        assert registered[0].name == "dummy-test-scanner"
        assert ScannerRegistry.get("dummy-test-scanner") is scanner

    def test_register_by_class(self):
        """Test registering a scanner class directly."""
        ScannerRegistry.register(DummyTestScanner)
        registered = ScannerRegistry.list_all()
        assert len(registered) == 1
        assert registered[0].name == "dummy-test-scanner"

    def test_register_invalid_object(self):
        """Test registering non-BaseScanner raises error."""
        with pytest.raises(ScannerRegistrationError):
            ScannerRegistry.register(object())

    def test_unregister_scanner(self):
        """Test unregistering a scanner by name."""
        ScannerRegistry.register(DummyTestScanner())
        assert ScannerRegistry.unregister("dummy-test-scanner") is True
        assert ScannerRegistry.unregister("dummy-test-scanner") is False
        assert len(ScannerRegistry.list()) == 0

    def test_filter_scanners_include_and_exclude(self):
        """Test include and exclude filtering on ScannerRegistry."""
        ScannerRegistry.register(DummyTestScanner())
        ScannerRegistry.register(EndpointInspectorScanner())

        all_scanners = ScannerRegistry.list()
        assert len(all_scanners) == 2

        # Include filter
        included = ScannerRegistry.filter(include=["endpoint-inspector"])
        assert len(included) == 1
        assert included[0].name == "endpoint-inspector"

        # Exclude filter
        excluded = ScannerRegistry.filter(exclude=["dummy-test-scanner"])
        assert len(excluded) == 1
        assert excluded[0].name == "endpoint-inspector"


class TestModelsAndResponseComparison:
    """Tests for Observation, Finding, and ResponseDifference."""

    def test_observation_creation_and_aliases(self):
        """Test Observation model creation, property aliases, and deduplication key."""
        obs = Observation(
            scanner="test-scanner",
            endpoint_url="https://example.local/api/users",
            parameter_name="id",
            observation_type=ObservationType.PARAMETER_PATTERN,
            description="Identifier parameter detected",
            evidence="id=123",
            confidence=90,
        )

        assert obs.endpoint == "https://example.local/api/users"
        assert obs.parameter == "id"
        assert obs.type == ObservationType.PARAMETER_PATTERN
        assert obs.confidence == 90
        assert "test-scanner" in obs.deduplication_key
        assert "id" in obs.deduplication_key

    def test_finding_creation_and_aliases(self):
        """Test Finding model creation, property aliases, and defaults."""
        finding = Finding(
            scanner="test-scanner",
            category="Injection",
            title="Potential Injection Pattern",
            severity=FindingSeverity.MEDIUM,
            confidence=70,
            status=FindingStatus.POTENTIAL,
            endpoint_url="https://example.local/search",
            parameter_name="q",
            description="Query parameter reflected",
            evidence="q=test",
        )

        assert finding.endpoint == "https://example.local/search"
        assert finding.parameter == "q"
        assert finding.severity == FindingSeverity.MEDIUM
        assert finding.status == FindingStatus.POTENTIAL
        assert "Potential Injection Pattern" in finding.deduplication_key

    def test_compare_responses_identical(self):
        """Test compare_responses when responses are identical."""
        resp1 = HttpResponse(
            status_code=200,
            headers={"Content-Type": "text/html", "Server": "nginx"},
            body="<html><body>Hello World</body></html>",
            url="https://example.local/",
            request_url="https://example.local/",
            elapsed=0.05,
            request_method="GET",
        )
        resp2 = HttpResponse(
            status_code=200,
            headers={"Content-Type": "text/html", "Server": "nginx"},
            body="<html><body>Hello World</body></html>",
            url="https://example.local/",
            request_url="https://example.local/",
            elapsed=0.06,
            request_method="GET",
        )

        diff = compare_responses(resp1, resp2)
        assert diff.status_changed is False
        assert diff.size_changed is False
        assert diff.headers_changed is False
        assert diff.content_changed is False
        assert diff.similarity_ratio == 1.0
        assert diff.redirect_changed is False

    def test_compare_responses_different_status_and_body(self):
        """Test compare_responses when status, size, and body change."""
        baseline = HttpResponse(
            status_code=200,
            headers={"Content-Type": "text/html"},
            body="<html><body>Profile Page of User 1</body></html>",
            url="https://example.local/user?id=1",
            request_url="https://example.local/user?id=1",
            elapsed=0.10,
            request_method="GET",
        )
        candidate = HttpResponse(
            status_code=403,
            headers={"Content-Type": "application/json", "X-Error": "Forbidden"},
            body='{"error": "Unauthorized Access Denied"}',
            url="https://example.local/user?id=2",
            request_url="https://example.local/user?id=2",
            elapsed=1.50,
            request_method="GET",
        )

        diff = compare_response(baseline, candidate)
        assert diff.status_changed is True
        assert diff.status_baseline == 200
        assert diff.status_candidate == 403
        assert diff.size_changed is True
        assert diff.headers_changed is True
        assert "x-error" in diff.added_headers
        assert diff.content_changed is True
        assert diff.similarity_ratio < 0.5
        assert diff.timing_changed is True


class TestEndpointInspectorScanner:
    """Tests for demonstration EndpointInspectorScanner."""

    @pytest.mark.asyncio
    async def test_endpoint_inspector_observations(self):
        """Test inspector reports scheme, query parameter, and semantic signatures."""
        scanner = EndpointInspectorScanner()
        # example.com is a public domain, so Target.from_url sets is_private=False
        target = Target.from_url("http://example.com", allow_private=False)
        config = VulnForgeConfig()
        scope = ScopeEngine(allowed_domains=target.scope)
        rate_limiter = RateLimiter(rate=10.0, concurrency=2)
        context_scan = ScanContext(
            target=target,
            config=config,
            scope=scope,
            rate_limiter=rate_limiter,
        )

        endpoint = Endpoint.from_url(
            "http://example.com/download.php?file=report.pdf&user_id=42&redirect=https://google.com",
            method="GET",
            source="crawl",
        )

        analysis_ctx = AnalysisContext(scan_context=context_scan, endpoints=[endpoint])
        observations = await scanner.analyze(analysis_ctx, endpoint)

        obs_types = [o.observation_type for o in observations]
        assert ObservationType.SCHEME_CONFIGURATION in obs_types
        assert ObservationType.PARAMETER_PATTERN in obs_types
        assert ObservationType.URL_INPUT in obs_types

        # Verify observations descriptions
        obs_descs = " ".join(o.description for o in observations)
        assert "unencrypted HTTP" in obs_descs
        assert "file/resource path" in obs_descs
        assert "object/user identifier" in obs_descs
        assert "URL or redirection" in obs_descs

        # Verify finalize generates informational finding for HTTP transport on public target
        for o in observations:
            analysis_ctx.record_observation(o)
        findings = await scanner.finalize(analysis_ctx)
        assert len(findings) == 1
        assert findings[0].title == "Unencrypted HTTP Transport In Use"
        assert findings[0].status == FindingStatus.OBSERVED


class TestScannerEngineAndDeduplication:
    """Tests for ScannerEngine pipeline orchestration and deduplication."""

    @pytest.mark.asyncio
    async def test_scanner_engine_pipeline(self):
        """Test ScannerEngine executes active scanners and deduplicates observations."""
        ScannerRegistry.clear()
        ScannerRegistry.register(DummyTestScanner())

        scan_context = create_mock_scan_context("https://lab.local")
        ep1 = Endpoint.from_url("https://lab.local/api/items", method="GET")
        ep2 = Endpoint.from_url("https://lab.local/api/items", method="GET")

        engine = ScannerEngine()
        observations, findings = await engine.run(
            scan_context=scan_context,
            endpoints=[ep1, ep2],
        )

        # ep1 and ep2 generate identical observations -> deduplication reduces to 1
        assert len(observations) == 1
        assert observations[0].scanner == "dummy-test-scanner"
        assert len(findings) == 1
        assert findings[0].title == "Mock Finding Title"



class TestDatabasePersistence:
    """Tests for SQLite persistence of observations and findings."""

    def test_save_and_retrieve_observations_and_findings(self):
        """Test database operations for observations and findings."""
        db = DatabaseManager(":memory:")
        scan_ctx = create_mock_scan_context("https://lab.local")
        db.save_scan(scan_ctx, status="completed")

        obs1 = Observation(
            scanner="test-scanner",
            endpoint_url="https://lab.local/api/test",
            parameter_name="token",
            observation_type=ObservationType.DISCLOSURE,
            description="Sensitive token parameter",
            evidence="token=abc",
            confidence=90,
        )
        obs2 = Observation(
            scanner="test-scanner",
            endpoint_url="https://lab.local/api/test",
            parameter_name="debug",
            observation_type=ObservationType.PARAMETER_PATTERN,
            description="Debug flag present",
            evidence="debug=1",
            confidence=85,
        )

        finding = Finding(
            scanner="test-scanner",
            category="Disclosure",
            title="Token Disclosure",
            severity=FindingSeverity.LOW,
            confidence=90,
            status=FindingStatus.REQUIRES_MANUAL_VERIFICATION,
            endpoint_url="https://lab.local/api/test",
            parameter_name="token",
            description="Token disclosure in URL",
            evidence="token=abc",
            recommendation="Pass token in authorization header.",
        )

        # Save to database
        db.save_observations(scan_ctx.scan_id, [obs1, obs2])
        db.save_findings(scan_ctx.scan_id, [finding])

        # Retrieve
        stored_obs = db.get_observations(scan_ctx.scan_id)
        assert len(stored_obs) == 2
        assert stored_obs[0]["scanner"] == "test-scanner"
        assert stored_obs[0]["observation_type"] in ("DISCLOSURE", "PARAMETER_PATTERN")

        stored_findings = db.get_findings(scan_ctx.scan_id)
        assert len(stored_findings) == 1
        assert stored_findings[0]["title"] == "Token Disclosure"
        assert stored_findings[0]["severity"] == "LOW"
        assert stored_findings[0]["status"] == "REQUIRES_MANUAL_VERIFICATION"
