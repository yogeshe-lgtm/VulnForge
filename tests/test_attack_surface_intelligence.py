"""Comprehensive unit tests for VulnForge Attack Surface Intelligence."""

import pytest

from vulnforge.core.config import VulnForgeConfig
from vulnforge.core.context import ScanContext
from vulnforge.core.scope import ScopeEngine
from vulnforge.intelligence import (
    AttackSurface,
    AttackSurfaceBuilder,
    EndpointClassification,
    EndpointClassifier,
    EndpointPriority,
    EndpointPrioritizer,
    ParameterClassification,
    ParameterClassifier,
    PriorityLevel,
)
from vulnforge.crawler.forms import DiscoveredForm, FormField
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter, ParameterLocation
from vulnforge.models.target import Target
from vulnforge.storage.database import DatabaseManager


class TestParameterClassification:
    """Test suite for ParameterClassifier heuristics and type recognition."""

    def test_classify_identifier_by_name(self):
        param = Parameter(name="user_id", endpoint_url="https://app.local/user")
        res = ParameterClassifier.classify(param)
        assert res.classification == ParameterClassification.IDENTIFIER
        assert res.confidence >= 85
        assert len(res.reasons) > 0

    def test_classify_identifier_by_uuid_value(self):
        param = Parameter(
            name="ref",
            sample_value="123e4567-e89b-12d3-a456-426614174000",
            endpoint_url="https://app.local/item",
        )
        res = ParameterClassifier.classify(param)
        assert res.classification == ParameterClassification.IDENTIFIER
        assert res.confidence >= 90

    def test_classify_authentication_parameters(self):
        auth_names = ["token", "access_token", "api_key", "password", "jwt", "secret"]
        for name in auth_names:
            param = Parameter(name=name, endpoint_url="https://app.local/auth")
            res = ParameterClassifier.classify(param)
            assert res.classification == ParameterClassification.AUTHENTICATION

    def test_classify_session_parameters(self):
        param = Parameter(name="jsessionid", endpoint_url="https://app.local/dashboard")
        res = ParameterClassifier.classify(param)
        assert res.classification == ParameterClassification.SESSION

    def test_classify_redirect_parameters(self):
        param = Parameter(name="return_to", endpoint_url="https://app.local/login")
        res = ParameterClassifier.classify(param)
        assert res.classification == ParameterClassification.REDIRECT

    def test_classify_url_input_by_name_and_value(self):
        param1 = Parameter(name="webhook", endpoint_url="https://app.local/settings")
        res1 = ParameterClassifier.classify(param1)
        assert res1.classification == ParameterClassification.URL_INPUT

        param2 = Parameter(name="feed", sample_value="https://partner.com/rss", endpoint_url="https://app.local/rss")
        res2 = ParameterClassifier.classify(param2)
        assert res2.classification == ParameterClassification.URL_INPUT

    def test_classify_file_name_and_path(self):
        param_file = Parameter(name="attachment", sample_value="invoice.pdf", endpoint_url="https://app.local/download")
        res_file = ParameterClassifier.classify(param_file)
        assert res_file.classification == ParameterClassification.FILE_NAME

        param_path = Parameter(name="folder_path", sample_value="/var/www/data", endpoint_url="https://app.local/files")
        res_path = ParameterClassifier.classify(param_path)
        assert res_path.classification == ParameterClassification.FILE_PATH

    def test_classify_search_query(self):
        for q in ["q", "query", "search", "keyword"]:
            param = Parameter(name=q, endpoint_url="https://app.local/search")
            res = ParameterClassifier.classify(param)
            assert res.classification == ParameterClassification.SEARCH

    def test_classify_pagination(self):
        for p in ["page", "limit", "offset", "per_page"]:
            param = Parameter(name=p, endpoint_url="https://app.local/items")
            res = ParameterClassifier.classify(param)
            assert res.classification == ParameterClassification.PAGINATION

    def test_classify_state_change(self):
        param = Parameter(name="action", sample_value="delete", endpoint_url="https://app.local/admin")
        res = ParameterClassifier.classify(param)
        assert res.classification == ParameterClassification.STATE_CHANGE

    def test_classify_json_payload_field(self):
        param = Parameter(name="username", location=ParameterLocation.JSON, endpoint_url="https://app.local/api/users")
        res = ParameterClassifier.classify(param)
        assert res.classification == ParameterClassification.JSON_FIELD

    def test_classify_unknown_parameter(self):
        param = Parameter(name="custom_random_param", endpoint_url="https://app.local/view")
        res = ParameterClassifier.classify(param)
        assert res.classification == ParameterClassification.UNKNOWN
        assert res.confidence <= 50


class TestEndpointClassification:
    """Test suite for EndpointClassifier structural and functional recognition."""

    def test_classify_api_and_identifier(self):
        ep = Endpoint.from_url("https://app.local/api/v1/users/42", method="GET")
        classes = EndpointClassifier.classify(ep)
        class_values = {c.value for c in classes}
        assert EndpointClassification.API.value in class_values
        assert EndpointClassification.IDENTIFIER_ENDPOINT.value in class_values

    def test_classify_search_endpoint(self):
        ep = Endpoint.from_url("https://app.local/search?q=security+audit", method="GET")
        classes = EndpointClassifier.classify(ep)
        class_values = {c.value for c in classes}
        assert EndpointClassification.SEARCH.value in class_values
        assert EndpointClassification.DYNAMIC_ROUTE.value in class_values

    def test_classify_authentication_endpoint(self):
        ep = Endpoint.from_url("https://app.local/auth/login", method="POST")
        classes = EndpointClassifier.classify(ep)
        class_values = {c.value for c in classes}
        assert EndpointClassification.AUTHENTICATION.value in class_values
        assert EndpointClassification.STATE_CHANGING.value in class_values

    def test_classify_admin_interface(self):
        ep = Endpoint.from_url("https://app.local/admin/dashboard", method="GET")
        classes = EndpointClassifier.classify(ep)
        class_values = {c.value for c in classes}
        assert EndpointClassification.ADMIN_LIKE_PATH.value in class_values

    def test_classify_file_upload_endpoint(self):
        ep = Endpoint.from_url(
            "https://app.local/upload/avatar",
            method="POST",
            content_type="multipart/form-data",
        )
        classes = EndpointClassifier.classify(ep)
        class_values = {c.value for c in classes}
        assert EndpointClassification.FILE_UPLOAD_CANDIDATE.value in class_values

    def test_classify_redirect_endpoint(self):
        ep = Endpoint.from_url("https://app.local/redirect?url=https://out.local", method="GET")
        classes = EndpointClassifier.classify(ep)
        class_values = {c.value for c in classes}
        assert EndpointClassification.REDIRECT_CANDIDATE.value in class_values

    def test_classify_static_assets(self):
        static_urls = [
            "https://app.local/static/style.css",
            "https://app.local/assets/bundle.min.js",
            "https://app.local/images/logo.svg",
            "https://app.local/favicon.ico",
        ]
        for url in static_urls:
            ep = Endpoint.from_url(url, method="GET")
            classes = EndpointClassifier.classify(ep)
            assert len(classes) == 1
            assert classes[0] == EndpointClassification.STATIC_ASSET


class TestEndpointPrioritization:
    """Test suite for explainable endpoint priority scoring."""

    def test_static_asset_low_priority(self):
        ep = Endpoint.from_url("https://app.local/static/logo.png", method="GET")
        priority = EndpointPrioritizer.prioritize(ep)
        assert priority.score <= 20
        assert priority.priority_level == PriorityLevel.LOW
        assert any("static" in r.lower() for r in priority.reasons)

    def test_authentication_post_high_priority(self):
        ep = Endpoint.from_url("https://app.local/auth/login", method="POST")
        priority = EndpointPrioritizer.prioritize(ep)
        assert priority.score >= 60
        assert priority.priority_level in (PriorityLevel.HIGH, PriorityLevel.CRITICAL)
        assert any("authentication" in r.lower() for r in priority.reasons)
        assert any("state-changing" in r.lower() for r in priority.reasons)

    def test_admin_api_critical_priority(self):
        ep = Endpoint.from_url("https://app.local/api/admin/users/123", method="DELETE")
        priority = EndpointPrioritizer.prioritize(ep)
        assert priority.score >= 80
        assert priority.priority_level == PriorityLevel.CRITICAL
        assert len(priority.reasons) >= 3


class TestAttackSurfaceBuilder:
    """Test suite for complete AttackSurface aggregation and scanner recommendations."""

    def test_attack_surface_construction(self):
        endpoints = [
            Endpoint.from_url("https://app.local/api/users/1", method="GET"),
            Endpoint.from_url("https://app.local/search?q=audit", method="GET"),
            Endpoint.from_url("https://app.local/static/app.js", method="GET"),
        ]
        params = [
            Parameter(name="q", endpoint_url="https://app.local/search"),
            Parameter(name="id", endpoint_url="https://app.local/api/users/1"),
        ]
        techs = [{"name": "Django", "category": "Framework", "confidence": 90, "evidence": "csrftoken"}]

        surface = AttackSurfaceBuilder.build(
            target_url="https://app.local",
            endpoints=endpoints,
            parameters=params,
            technologies=techs,
        )

        assert surface.total_endpoints == 3
        assert surface.total_parameters == 2
        assert len(surface.hosts) == 1
        assert surface.hosts[0] == "app.local"
        assert surface.high_priority_inputs_count >= 1
        assert len(surface.api_endpoints) >= 1

        # Check endpoints are sorted by priority score descending
        scores = [ep.priority_score for ep in surface.endpoints]
        assert scores == sorted(scores, reverse=True)

    def test_attack_surface_construction_with_forms(self):
        endpoints = [Endpoint.from_url("https://app.local/login", method="POST")]
        form = DiscoveredForm(
            action="https://app.local/login",
            method="POST",
            enctype="application/x-www-form-urlencoded",
            fields=[
                FormField(name="username", field_type="text"),
                FormField(name="password", field_type="password"),
            ],
            source_url="https://app.local/login.php",
        )
        surface = AttackSurfaceBuilder.build(
            target_url="https://app.local",
            endpoints=endpoints,
            forms=[form],
        )
        assert len(surface.forms) == 1
        assert surface.forms[0].action == "https://app.local/login"

    def test_scanner_recommendations(self):
        api_ep = Endpoint.from_url("https://app.local/api/v1/resource", method="GET")
        api_ep.classifications = [EndpointClassification.API.value]
        recs = AttackSurfaceBuilder.get_scanner_recommendations(api_ep)
        assert "cors" in recs
        assert "security-headers" in recs

        static_ep = Endpoint.from_url("https://app.local/static/style.css", method="GET")
        static_ep.classifications = [EndpointClassification.STATIC_ASSET.value]
        static_recs = AttackSurfaceBuilder.get_scanner_recommendations(static_ep)
        assert static_recs == ["security-headers"]


class TestDatabaseStorageIntelligence:
    """Test SQLite persistence of intelligence classifications and priority metadata."""

    def test_save_and_retrieve_endpoints_with_intelligence(self):
        db = DatabaseManager(":memory:")
        cfg = VulnForgeConfig()
        target = Target.from_url("https://app.local")
        scope = ScopeEngine([target.hostname])
        context = ScanContext(target=target, config=cfg, scope=scope)
        db.save_scan(context)

        ep = Endpoint.from_url("https://app.local/api/items/123", method="GET")
        ep.classifications = ["API", "IDENTIFIER_ENDPOINT"]
        ep.priority_score = 75
        ep.priority_level = "HIGH"
        ep.priority_reasons = ["API route processing structured data", "Contains resource identifier"]
        param = Parameter(
            name="id",
            endpoint_url=ep.url,
            classification="IDENTIFIER",
            classification_confidence=95,
        )
        ep.parameters.append(param)

        db.save_endpoints(context.scan_id, [ep])

        retrieved = db.get_endpoints(context.scan_id)
        assert len(retrieved) == 1
        r_ep = retrieved[0]
        assert r_ep["priority_score"] == 75
        assert r_ep["priority_level"] == "HIGH"
        assert "API" in r_ep["classifications"]
        assert len(r_ep["parameters"]) == 1
        assert r_ep["parameters"][0]["classification"] == "IDENTIFIER"
        assert r_ep["parameters"][0]["confidence"] == 95
