"""Comprehensive unit and integration tests for Attack Surface Graph (Phase 2)."""

import pytest
from typer.testing import CliRunner

from vulnforge.cli.main import app
from vulnforge.intelligence.graph import (
    AttackSurfaceGraph,
    EdgeType,
    GraphEdge,
    GraphNode,
    NodeType,
)
from vulnforge.intelligence.models import AttackSurface
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter
from vulnforge.scanners import Finding, FindingSeverity


@pytest.fixture
def sample_surface() -> AttackSurface:
    """Create a realistic AttackSurface model for graph generation."""
    ep1 = Endpoint.from_url(
        "https://api.example.com/v1/users",
        method="GET",
        source="crawl",
        status_code=200,
        content_type="application/json",
    )
    ep1.classifications = ["API", "AUTHENTICATION"]
    ep1.authentication_required = True
    ep1.priority_score = 85
    ep1.priority_level = "HIGH"

    ep2 = Endpoint.from_url(
        "https://example.com/search",
        method="GET",
        source="crawl",
        status_code=200,
    )
    ep2.classifications = ["SEARCH"]
    ep2.priority_score = 45
    ep2.priority_level = "MEDIUM"

    ep3 = Endpoint.from_url(
        "https://example.com/admin/delete",
        method="POST",
        source="javascript",
        discovered_from="https://example.com/assets/app.js",
    )
    ep3.classifications = ["ADMIN_LIKE_PATH", "STATE_CHANGING"]
    ep3.priority_score = 90
    ep3.priority_level = "CRITICAL"
    ep3.authentication_required = True

    p1 = Parameter(
        name="user_id",
        location="query",
        endpoint_url=ep1.url,
        classification="IDENTIFIER",
        is_high_interest=True,
    )
    p2 = Parameter(
        name="q",
        location="query",
        endpoint_url=ep2.url,
        classification="SEARCH",
    )

    return AttackSurface(
        target_url="https://example.com",
        hosts=["example.com", "api.example.com"],
        endpoints=[ep1, ep2, ep3],
        parameters=[p1, p2],
        javascript_assets=["https://example.com/assets/app.js"],
        technologies=[
            {"name": "Nginx", "category": "web_server", "version": "1.24.0", "confidence": 100},
            {"name": "FastAPI", "category": "framework", "version": "0.100.0", "confidence": 90},
        ],
        total_endpoints=3,
        total_parameters=2,
    )


def test_graph_node_and_edge_creation():
    """Verify manual creation of nodes, edges, and graph queries."""
    graph = AttackSurfaceGraph(target_url="https://example.com")
    n1 = GraphNode(id="target:1", label="https://example.com", node_type=NodeType.TARGET)
    n2 = GraphNode(id="host:example.com", label="example.com", node_type=NodeType.HOST)
    graph.add_node(n1)
    graph.add_node(n2)
    edge = graph.add_edge("target:1", "host:example.com", EdgeType.HOSTS)

    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1
    assert edge.edge_type == EdgeType.HOSTS
    assert graph.nodes["target:1"].node_type == NodeType.TARGET


def test_graph_from_attack_surface(sample_surface: AttackSurface):
    """Verify building complete graph from attack surface with findings."""
    finding = Finding(
        id="VF-XSS-001",
        scanner="xss",
        category="xss",
        title="Reflected XSS in search",
        severity=FindingSeverity.HIGH,
        confidence=85,
        description="Reflected XSS parameter reflection observed without output encoding",
        recommendation="Properly HTML encode user input in responses",
        endpoint_url="https://example.com/search",
        parameter_name="q",
    )

    graph = AttackSurfaceGraph.from_attack_surface(sample_surface, findings=[finding])

    assert len(graph.nodes) > 5
    assert len(graph.edges) > 5

    # Check node types
    targets = graph.get_nodes_by_type(NodeType.TARGET)
    assert len(targets) == 1
    assert targets[0].label == "https://example.com"

    hosts = graph.get_nodes_by_type(NodeType.HOST)
    assert len(hosts) >= 2

    # Check endpoints and API routes
    endpoints = graph.get_endpoints()
    assert len(endpoints) == 3

    api_routes = graph.get_api_routes()
    assert any("users" in n.label for n in api_routes)

    # Check high value endpoints
    high_value = graph.get_high_value_endpoints()
    assert len(high_value) >= 2  # ep1 (85 HIGH) and ep3 (90 CRITICAL)

    # Check authenticated endpoints
    auth_eps = graph.get_authenticated_endpoints()
    assert len(auth_eps) >= 2

    # Check JS linked endpoints
    js_linked = graph.get_js_linked_endpoints()
    assert len(js_linked) == 1
    assert "admin/delete" in js_linked[0].metadata.get("url", "")

    # Check parameters for endpoint
    params_search = graph.get_parameters_for_endpoint("https://example.com/search")
    assert len(params_search) == 1
    assert params_search[0].metadata.get("name") == "q"

    # Check findings attached to endpoint
    findings_search = graph.get_findings_for_endpoint("https://example.com/search")
    assert len(findings_search) == 1
    assert "Reflected XSS" in findings_search[0].metadata.get("title", "")


def test_graph_summary_and_tree(sample_surface: AttackSurface):
    """Verify graph summary stats and ASCII tree rendering."""
    graph = AttackSurfaceGraph.from_attack_surface(sample_surface)
    summary = graph.summary()

    assert summary["target_url"] == "https://example.com"
    assert summary["total_nodes"] > 0
    assert summary["total_edges"] > 0
    assert summary["high_value_endpoints"] >= 2
    assert summary["api_routes"] >= 1

    tree = graph.render_ascii_tree()
    assert "Target: https://example.com" in tree
    assert "Host:" in tree
    assert "Param:" in tree


def test_cli_graph_command(mocker):
    """Verify CLI `vulnforge graph` command execution."""
    runner = CliRunner()

    mocker.patch("vulnforge.cli.main.execute_graph", new_callable=mocker.AsyncMock, return_value=0)

    result = runner.invoke(app, ["graph", "https://example.com", "--depth", "1", "--quiet"])
    assert result.exit_code == 0

