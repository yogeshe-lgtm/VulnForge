"""Comprehensive unit and integration tests for API Security and GraphQL Assessment (Phases 8 & 9)."""

import pytest
from typer.testing import CliRunner

from vulnforge.api.graphql import GraphQLAnalyzer
from vulnforge.api.models import (
    APIAnalysisResult,
    APISpec,
    APIType,
    GraphQLAnalysisResult,
)
from vulnforge.api.openapi import OpenAPIParser, OpenAPIScanner
from vulnforge.cli.main import app
from vulnforge.models.endpoint import Endpoint


@pytest.fixture
def sample_openapi_dict() -> dict:
    """Sample OpenAPI 3.0 specification dictionary."""
    return {
        "openapi": "3.0.0",
        "info": {"title": "E-Commerce API", "version": "2.1.0"},
        "servers": [{"url": "https://api.example.com/v2"}],
        "components": {
            "securitySchemes": {
                "BearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                }
            }
        },
        "paths": {
            "/users": {
                "get": {
                    "operationId": "listUsers",
                    "summary": "List all users",
                    "parameters": [
                        {"name": "page", "in": "query", "schema": {"type": "integer"}, "required": False},
                        {"name": "limit", "in": "query", "schema": {"type": "integer"}, "required": False},
                    ],
                    "security": [{"BearerAuth": []}],
                    "responses": {"200": {"description": "User list"}},
                },
                "post": {
                    "operationId": "createUser",
                    "summary": "Create user",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {"type": "object", "properties": {"username": {"type": "string"}}}
                            }
                        },
                    },
                    "security": [{"BearerAuth": []}],
                    "responses": {"201": {"description": "Created"}},
                },
            },
            "/admin/cleanup": {
                "delete": {
                    "operationId": "cleanupData",
                    "summary": "Purge system data",
                    # No security scheme -> dangerous unauthenticated DELETE
                    "responses": {"200": {"description": "Cleaned"}},
                }
            },
        },
    }


def test_openapi_parser(sample_openapi_dict: dict):
    """Verify OpenAPI 3.0 parser extracts routes, parameters, and security definitions."""
    spec = OpenAPIParser.parse(sample_openapi_dict, base_url="https://api.example.com")

    assert spec.title == "E-Commerce API"
    assert spec.version == "2.1.0"
    assert len(spec.routes) == 3
    assert "BearerAuth" in spec.security_schemes

    routes_by_path = {f"{r.method} {r.path}": r for r in spec.routes}
    assert "GET /users" in routes_by_path
    assert "POST /users" in routes_by_path
    assert "DELETE /admin/cleanup" in routes_by_path

    get_users = routes_by_path["GET /users"]
    assert len(get_users.parameters) == 2
    assert get_users.security_schemes == ["BearerAuth"]

    endpoints = OpenAPIScanner.spec_to_endpoints(spec, "https://api.example.com")
    assert len(endpoints) == 3
    assert any(ep.method == "GET" and "/users" in ep.path for ep in endpoints)


def test_api_security_analysis(sample_openapi_dict: dict):
    """Verify detection of shadow/undocumented routes and unauthenticated dangerous methods."""
    spec = OpenAPIParser.parse(sample_openapi_dict, base_url="https://api.example.com")

    discovered_endpoints = [
        Endpoint.from_url("https://api.example.com/v2/users", method="GET"),
        Endpoint.from_url("https://api.example.com/v2/hidden_debug_endpoint", method="GET"),
    ]
    discovered_endpoints[1].classifications = ["API"]

    analysis = OpenAPIScanner.analyze_api_security(
        spec=spec,
        discovered_endpoints=discovered_endpoints,
        target_url="https://api.example.com",
    )

    assert analysis.documented_endpoints_count == 3
    assert len(analysis.undocumented_endpoints) == 1
    assert "hidden_debug_endpoint" in analysis.undocumented_endpoints[0]

    # Dangerous unauthenticated DELETE
    assert len(analysis.potentially_dangerous_methods) >= 1
    assert any("DELETE" in m and "/admin/cleanup" in m for m in analysis.potentially_dangerous_methods)


@pytest.mark.asyncio
async def test_graphql_analyzer(mocker):
    """Verify GraphQL schema introspection parsing and finding generation."""
    introspection_response_body = {
        "data": {
            "__schema": {
                "queryType": {"name": "Query"},
                "mutationType": {"name": "Mutation"},
                "subscriptionType": None,
                "types": [
                    {
                        "name": "Query",
                        "kind": "OBJECT",
                        "fields": [
                            {"name": "getUser", "type": {"name": "User"}},
                            {"name": "systemSecretKey", "type": {"name": "String"}},
                        ],
                    },
                    {
                        "name": "Mutation",
                        "kind": "OBJECT",
                        "fields": [
                            {"name": "updatePassword", "type": {"name": "Boolean"}},
                        ],
                    },
                    {
                        "name": "User",
                        "kind": "OBJECT",
                        "fields": [
                            {"name": "id", "type": {"name": "ID"}},
                            {"name": "api_token", "type": {"name": "String"}},
                        ],
                    },
                ],
            }
        }
    }

    mock_resp = mocker.MagicMock()
    mock_resp.status_code = 200
    mock_resp.is_success = True
    mock_resp.body = str(introspection_response_body).replace("'", '"').replace("None", "null")

    mock_engine = mocker.MagicMock()
    mock_engine.post = mocker.AsyncMock(return_value=mock_resp)

    analysis = await GraphQLAnalyzer.analyze_graphql(mock_engine, "https://example.com/graphql")

    assert analysis.introspection_enabled is True
    assert analysis.query_type_name == "Query"
    assert analysis.mutation_type_name == "Mutation"
    assert analysis.queries_count == 2
    assert analysis.mutations_count == 1
    assert len(analysis.sensitive_fields) >= 2  # systemSecretKey, updatePassword, api_token

    findings = GraphQLAnalyzer.generate_findings(analysis)
    assert len(findings) >= 2
    titles = [f.title for f in findings]
    assert any("Introspection Query Enabled" in t for t in titles)
    assert any("Sensitive GraphQL Fields" in t for t in titles)


def test_cli_api_and_graphql_commands(mocker):
    """Verify CLI `vulnforge api` and `vulnforge graphql` commands."""
    runner = CliRunner()

    mocker.patch("vulnforge.cli.main.execute_api", new_callable=mocker.AsyncMock, return_value=0)
    mocker.patch("vulnforge.cli.main.execute_graphql", new_callable=mocker.AsyncMock, return_value=0)

    res_api = runner.invoke(app, ["api", "https://example.com", "--quiet"])
    assert res_api.exit_code == 0

    res_gql = runner.invoke(app, ["graphql", "https://example.com", "--quiet"])
    assert res_gql.exit_code == 0
