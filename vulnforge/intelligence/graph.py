"""Attack Surface Graph - Relational and topological representation of the discovered attack surface."""

from __future__ import annotations

from collections import defaultdict
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from vulnforge.intelligence.models import AttackSurface
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter

if TYPE_CHECKING:
    from vulnforge.scanners.result import Finding


class NodeType(str, Enum):
    """Categorization of entities within the Attack Surface Graph."""

    TARGET = "TARGET"
    HOST = "HOST"
    ENDPOINT = "ENDPOINT"
    PARAMETER = "PARAMETER"
    FORM = "FORM"
    API_ROUTE = "API_ROUTE"
    JAVASCRIPT = "JAVASCRIPT"
    TECHNOLOGY = "TECHNOLOGY"
    AUTH_BOUNDARY = "AUTH_BOUNDARY"
    FINDING = "FINDING"


class EdgeType(str, Enum):
    """Semantic relationship connecting nodes in the Attack Surface Graph."""

    HOSTS = "HOSTS"
    CONTAINS_ENDPOINT = "CONTAINS_ENDPOINT"
    ACCEPTS_PARAMETER = "ACCEPTS_PARAMETER"
    CONTAINS_FORM = "CONTAINS_FORM"
    EXPOSES_API = "EXPOSES_API"
    INCLUDES_SCRIPT = "INCLUDES_SCRIPT"
    DISCOVERED_FROM = "DISCOVERED_FROM"
    USES_TECH = "USES_TECH"
    HAS_FINDING = "HAS_FINDING"
    PROTECTED_BY = "PROTECTED_BY"


class GraphNode(BaseModel):
    """A node entity in the Attack Surface Graph."""

    id: str = Field(..., description="Unique node identifier (e.g., 'ep:https://target/api/users')")
    label: str = Field(..., description="Human-readable display label")
    node_type: NodeType = Field(..., description="Entity classification")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary attributes and signals")


class GraphEdge(BaseModel):
    """A directed edge connecting two entities in the Attack Surface Graph."""

    source_id: str = Field(..., description="ID of source node")
    target_id: str = Field(..., description="ID of target node")
    edge_type: EdgeType = Field(..., description="Relationship type")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Edge properties")


class AttackSurfaceGraph(BaseModel):
    """Directed graph representing the topological and semantic attack surface."""

    target_url: str = Field(..., description="Root target URL assessed")
    nodes: Dict[str, GraphNode] = Field(default_factory=dict, description="Node inventory keyed by ID")
    edges: List[GraphEdge] = Field(default_factory=list, description="List of directed relationship edges")

    def add_node(self, node: GraphNode) -> GraphNode:
        """Add or update a node in the graph."""
        self.nodes[node.id] = node
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: EdgeType,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GraphEdge:
        """Add a directed edge between two existing nodes."""
        edge = GraphEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            metadata=metadata or {},
        )
        self.edges.append(edge)
        return edge

    @classmethod
    def from_attack_surface(
        cls,
        surface: AttackSurface,
        findings: Optional[List[Finding]] = None,
    ) -> "AttackSurfaceGraph":
        """Build an attack surface graph directly from an AttackSurface model and optional findings."""
        graph = cls(target_url=surface.target_url)

        # 1. Target Root Node
        target_id = f"target:{surface.target_url}"
        graph.add_node(
            GraphNode(
                id=target_id,
                label=surface.target_url,
                node_type=NodeType.TARGET,
                metadata={"total_endpoints": surface.total_endpoints, "total_parameters": surface.total_parameters},
            )
        )

        # 2. Host Nodes
        hosts_seen: Set[str] = set()
        parsed_target = urlparse(surface.target_url)
        target_host = parsed_target.netloc or "localhost"

        for h in surface.hosts or [target_host]:
            if not h:
                continue
            host_id = f"host:{h}"
            if host_id not in graph.nodes:
                graph.add_node(
                    GraphNode(
                        id=host_id,
                        label=h,
                        node_type=NodeType.HOST,
                        metadata={"hostname": h},
                    )
                )
                graph.add_edge(target_id, host_id, EdgeType.HOSTS)
                hosts_seen.add(h)

        # 3. Technology Nodes (attached to Hosts)
        for tech in surface.technologies:
            tech_name = tech.get("name", "Unknown")
            tech_id = f"tech:{tech_name.lower()}"
            if tech_id not in graph.nodes:
                graph.add_node(
                    GraphNode(
                        id=tech_id,
                        label=f"{tech_name} ({tech.get('version', 'unknown') or 'unknown'})",
                        node_type=NodeType.TECHNOLOGY,
                        metadata=tech,
                    )
                )
            for h in hosts_seen:
                graph.add_edge(f"host:{h}", tech_id, EdgeType.USES_TECH)

        # 4. Endpoints & API Routes
        endpoint_id_map: Dict[str, str] = {}
        for ep in surface.endpoints:
            parsed = urlparse(ep.url)
            ep_host = parsed.netloc or target_host
            host_id = f"host:{ep_host}"
            if host_id not in graph.nodes:
                graph.add_node(
                    GraphNode(id=host_id, label=ep_host, node_type=NodeType.HOST, metadata={"hostname": ep_host})
                )
                graph.add_edge(target_id, host_id, EdgeType.HOSTS)
                hosts_seen.add(ep_host)

            is_api = ep.is_api or "API" in ep.classifications
            node_type = NodeType.API_ROUTE if is_api else NodeType.ENDPOINT
            ep_id = f"ep:{ep.method}:{ep.url}"
            endpoint_id_map[ep.url] = ep_id

            graph.add_node(
                GraphNode(
                    id=ep_id,
                    label=f"[{ep.method}] {parsed.path or '/'}",
                    node_type=node_type,
                    metadata={
                        "url": ep.url,
                        "method": ep.method,
                        "priority_score": ep.priority_score,
                        "priority_level": ep.priority_level,
                        "priority_reasons": ep.priority_reasons,
                        "classifications": ep.classifications,
                        "source": ep.source,
                        "is_api": is_api,
                        "requires_auth": bool(ep.authentication_required or "AUTHENTICATION" in ep.classifications),
                    },
                )
            )

            rel = EdgeType.EXPOSES_API if is_api else EdgeType.CONTAINS_ENDPOINT
            graph.add_edge(host_id, ep_id, rel)

            # Link Auth Boundary if applicable
            if ep.authentication_required or "AUTHENTICATION" in ep.classifications:
                auth_id = f"auth:{ep_host}"
                if auth_id not in graph.nodes:
                    graph.add_node(
                        GraphNode(
                            id=auth_id,
                            label=f"Auth Boundary ({ep_host})",
                            node_type=NodeType.AUTH_BOUNDARY,
                            metadata={"host": ep_host},
                        )
                    )
                    graph.add_edge(host_id, auth_id, EdgeType.PROTECTED_BY)
                graph.add_edge(ep_id, auth_id, EdgeType.PROTECTED_BY)

        # 5. Parameters (attached to Endpoints)
        for param in surface.parameters:
            param_id = f"param:{param.name}:{param.location}:{param.endpoint_url}"
            graph.add_node(
                GraphNode(
                    id=param_id,
                    label=f"{param.name} ({param.location})",
                    node_type=NodeType.PARAMETER,
                    metadata={
                        "name": param.name,
                        "location": param.location,
                        "classification": param.classification,
                        "classification_reasons": param.classification_reasons,
                        "is_high_interest": param.is_high_interest,
                    },
                )
            )
            ep_id = endpoint_id_map.get(param.endpoint_url) or f"ep:GET:{param.endpoint_url}"
            if ep_id in graph.nodes:
                graph.add_edge(ep_id, param_id, EdgeType.ACCEPTS_PARAMETER)

        # 6. JavaScript Assets
        for js_url in surface.javascript_assets:
            js_id = f"js:{js_url}"
            parsed_js = urlparse(js_url)
            js_host = parsed_js.netloc or target_host
            host_id = f"host:{js_host}"
            if js_id not in graph.nodes:
                graph.add_node(
                    GraphNode(
                        id=js_id,
                        label=parsed_js.path.split("/")[-1] or js_url,
                        node_type=NodeType.JAVASCRIPT,
                        metadata={"url": js_url},
                    )
                )
            if host_id in graph.nodes:
                graph.add_edge(host_id, js_id, EdgeType.INCLUDES_SCRIPT)

        # 7. Discovered From Relationships (Endpoints discovered from JS/robots/sitemap)
        for ep in surface.endpoints:
            ep_id = endpoint_id_map.get(ep.url)
            if not ep_id:
                continue
            if ep.source == "javascript" and ep.discovered_from:
                js_id = f"js:{ep.discovered_from}"
                if js_id in graph.nodes:
                    graph.add_edge(js_id, ep_id, EdgeType.DISCOVERED_FROM)

        # 8. Security Findings
        if findings:
            for f in findings:
                f_id = f"finding:{f.id}"
                graph.add_node(
                    GraphNode(
                        id=f_id,
                        label=f"[{f.severity.value.upper() if hasattr(f.severity, 'value') else str(f.severity).upper()}] {f.title}",
                        node_type=NodeType.FINDING,
                        metadata={
                            "title": f.title,
                            "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                            "confidence": f.confidence,
                            "scanner": f.scanner,
                            "endpoint_url": f.endpoint_url,
                            "parameter_name": f.parameter_name,
                        },
                    )
                )
                ep_id = endpoint_id_map.get(f.endpoint_url)
                if ep_id and ep_id in graph.nodes:
                    graph.add_edge(ep_id, f_id, EdgeType.HAS_FINDING)
                elif f.endpoint_url:
                    # Generic link to target
                    graph.add_edge(target_id, f_id, EdgeType.HAS_FINDING)

        return graph

    # Query Helper Methods
    def get_nodes_by_type(self, node_type: NodeType) -> List[GraphNode]:
        """Return all nodes of a specific entity type."""
        return [n for n in self.nodes.values() if n.node_type == node_type]

    def get_endpoints(self) -> List[GraphNode]:
        """Return all endpoint and API route nodes."""
        return [n for n in self.nodes.values() if n.node_type in (NodeType.ENDPOINT, NodeType.API_ROUTE)]

    def get_parameters_for_endpoint(self, endpoint_url: str) -> List[GraphNode]:
        """Return all parameter nodes attached to an endpoint."""
        param_nodes: List[GraphNode] = []
        for edge in self.edges:
            if edge.edge_type == EdgeType.ACCEPTS_PARAMETER:
                src_node = self.nodes.get(edge.source_id)
                if src_node and (src_node.metadata.get("url") == endpoint_url or src_node.id == endpoint_url):
                    tgt_node = self.nodes.get(edge.target_id)
                    if tgt_node:
                        param_nodes.append(tgt_node)
        return param_nodes

    def get_high_value_endpoints(self) -> List[GraphNode]:
        """Return endpoints with priority level HIGH or CRITICAL (or priority_score >= 70)."""
        res = []
        for ep in self.get_endpoints():
            score = ep.metadata.get("priority_score", 0)
            level = (ep.metadata.get("priority_level") or "").upper()
            if score >= 70 or level in ("HIGH", "CRITICAL"):
                res.append(ep)
        return res

    def get_api_routes(self) -> List[GraphNode]:
        """Return all API route nodes."""
        return [n for n in self.nodes.values() if n.node_type == NodeType.API_ROUTE or n.metadata.get("is_api")]

    def get_authenticated_endpoints(self) -> List[GraphNode]:
        """Return all endpoints marked as requiring authentication."""
        return [n for n in self.get_endpoints() if n.metadata.get("requires_auth")]

    def get_js_linked_endpoints(self) -> List[GraphNode]:
        """Return endpoints that were discovered from JavaScript assets."""
        linked_ids = {edge.target_id for edge in self.edges if edge.edge_type == EdgeType.DISCOVERED_FROM}
        return [self.nodes[nid] for nid in linked_ids if nid in self.nodes]

    def get_findings_for_endpoint(self, endpoint_url: str) -> List[GraphNode]:
        """Return all finding nodes associated with a given endpoint."""
        finding_nodes: List[GraphNode] = []
        for edge in self.edges:
            if edge.edge_type == EdgeType.HAS_FINDING:
                src = self.nodes.get(edge.source_id)
                if src and (src.metadata.get("url") == endpoint_url or src.id == endpoint_url):
                    tgt = self.nodes.get(edge.target_id)
                    if tgt:
                        finding_nodes.append(tgt)
        return finding_nodes

    def summary(self) -> Dict[str, Any]:
        """Return aggregate structural counts of the graph."""
        counts = defaultdict(int)
        for n in self.nodes.values():
            counts[n.node_type.value] += 1
        return {
            "target_url": self.target_url,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "node_counts": dict(counts),
            "high_value_endpoints": len(self.get_high_value_endpoints()),
            "api_routes": len(self.get_api_routes()),
            "authenticated_endpoints": len(self.get_authenticated_endpoints()),
            "js_linked_endpoints": len(self.get_js_linked_endpoints()),
        }

    def render_ascii_tree(self) -> str:
        """Render a clean text-based hierarchical tree representation of the attack surface graph."""
        lines = [f"Target: {self.target_url}"]
        hosts = self.get_nodes_by_type(NodeType.HOST)

        for h_idx, host in enumerate(hosts):
            is_last_host = h_idx == len(hosts) - 1
            h_prefix = "└── " if is_last_host else "├── "
            lines.append(f"{h_prefix}Host: {host.label}")

            # Endpoints under host
            host_endpoints = [
                self.nodes[edge.target_id]
                for edge in self.edges
                if edge.source_id == host.id and edge.edge_type in (EdgeType.CONTAINS_ENDPOINT, EdgeType.EXPOSES_API)
                and edge.target_id in self.nodes
            ]

            child_indent = "    " if is_last_host else "│   "

            for ep_idx, ep in enumerate(host_endpoints):
                is_last_ep = ep_idx == len(host_endpoints) - 1
                ep_prefix = "└── " if is_last_ep else "├── "
                ep_tag = "[API] " if ep.node_type == NodeType.API_ROUTE else ""
                priority = ep.metadata.get("priority_level", "MED")
                lines.append(f"{child_indent}{ep_prefix}{ep_tag}{ep.label} [dim]({priority})[/dim]")

                # Parameters under endpoint
                params = [
                    self.nodes[edge.target_id]
                    for edge in self.edges
                    if edge.source_id == ep.id and edge.edge_type == EdgeType.ACCEPTS_PARAMETER
                    and edge.target_id in self.nodes
                ]
                param_indent = child_indent + ("    " if is_last_ep else "│   ")
                for p_idx, param in enumerate(params):
                    is_last_p = p_idx == len(params) - 1
                    p_prefix = "└── " if is_last_p else "├── "
                    p_cls = param.metadata.get("classification", "UNKNOWN")
                    lines.append(f"{param_indent}{p_prefix}Param: {param.label} [cyan]({p_cls})[/cyan]")

            # Scripts under host
            scripts = [
                self.nodes[edge.target_id]
                for edge in self.edges
                if edge.source_id == host.id and edge.edge_type == EdgeType.INCLUDES_SCRIPT
                and edge.target_id in self.nodes
            ]
            if scripts:
                lines.append(f"{child_indent}├── Scripts ({len(scripts)} assets)")
                for s_idx, s in enumerate(scripts[:5]):
                    lines.append(f"{child_indent}│   ├── {s.label}")
                if len(scripts) > 5:
                    lines.append(f"{child_indent}│   └── ... and {len(scripts) - 5} more")

        return "\n".join(lines)
