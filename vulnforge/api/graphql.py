"""GraphQL endpoint detection, safe schema introspection, and security analysis."""

import json
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

from vulnforge.api.models import (
    GraphQLAnalysisResult,
    GraphQLField,
    GraphQLType,
)
from vulnforge.scanners.result import Finding, FindingSeverity, FindingStatus, Observation, ObservationType


GRAPHQL_PROBE_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/api/v1/graphql",
    "/query",
    "/api/query",
    "/graph",
    "/api/graph",
    "/graphql/v1",
    "/graphql.json",
]

SAFE_INTROSPECTION_QUERY = """
query SafeIntrospection {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      description
      fields(includeDeprecated: true) {
        name
        isDeprecated
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
        args {
          name
          type {
            name
            kind
          }
        }
      }
    }
  }
}
"""

SENSITIVE_KEYWORDS = {
    "password", "secret", "token", "apikey", "api_key", "credential",
    "private_key", "ssn", "auth", "session", "access_token", "admin_secret",
}


class GraphQLAnalyzer:
    """Detects GraphQL endpoints and conducts non-destructive introspection and configuration analysis."""

    @staticmethod
    async def detect_graphql_endpoint(http_engine: Any, base_url: str) -> Optional[str]:
        """Probe potential GraphQL endpoint URLs with lightweight diagnostic query."""
        parsed = urlparse(base_url)
        root_origin = f"{parsed.scheme}://{parsed.netloc}"

        probe_payload = {"query": "{ __typename }"}
        for path in GRAPHQL_PROBE_PATHS:
            target_url = urljoin(root_origin, path)
            try:
                resp = await http_engine.post(
                    target_url,
                    json=probe_payload,
                    headers={"Content-Type": "application/json"},
                )
                if resp.status_code in (200, 400) and resp.body:
                    try:
                        data = json.loads(resp.body)
                        if "data" in data and "__typename" in data.get("data", {}) or "errors" in data:
                            return target_url
                    except Exception:
                        pass
            except Exception:
                continue

        return None

    @staticmethod
    async def analyze_graphql(http_engine: Any, endpoint_url: str) -> GraphQLAnalysisResult:
        """Run safe schema introspection and security checks against confirmed GraphQL endpoint."""
        result = GraphQLAnalysisResult(endpoint_url=endpoint_url)

        # 1. Test Introspection
        try:
            resp = await http_engine.post(
                endpoint_url,
                json={"query": SAFE_INTROSPECTION_QUERY},
                headers={"Content-Type": "application/json"},
            )
            if resp.is_success and resp.body:
                try:
                    res_json = json.loads(resp.body)
                    schema = res_json.get("data", {}).get("__schema")
                    if schema:
                        result.introspection_enabled = True
                        result.query_type_name = (schema.get("queryType") or {}).get("name")
                        result.mutation_type_name = (schema.get("mutationType") or {}).get("name")
                        result.subscription_type_name = (schema.get("subscriptionType") or {}).get("name")

                        types_raw = schema.get("types", [])
                        types_list: List[GraphQLType] = []
                        sensitive_found: List[str] = []

                        for t in types_raw:
                            t_name = t.get("name", "")
                            # Skip internal GraphQL types
                            if t_name.startswith("__"):
                                continue

                            fields_list: List[GraphQLField] = []
                            for f in (t.get("fields") or []):
                                f_name = f.get("name", "")
                                f_type_info = f.get("type", {})
                                type_name = f_type_info.get("name") or (f_type_info.get("ofType") or {}).get("name", "Unknown")

                                # Check sensitive field keywords
                                if any(kw in f_name.lower() for kw in SENSITIVE_KEYWORDS):
                                    sensitive_found.append(f"{t_name}.{f_name} ({type_name})")

                                fields_list.append(
                                    GraphQLField(
                                        name=f_name,
                                        field_type=str(type_name),
                                        is_deprecated=bool(f.get("isDeprecated", False)),
                                    )
                                )

                            types_list.append(
                                GraphQLType(
                                    name=t_name,
                                    kind=t.get("kind", "OBJECT"),
                                    description=t.get("description"),
                                    fields=fields_list,
                                )
                            )

                            if t_name == result.query_type_name:
                                result.queries_count = len(fields_list)
                            elif t_name == result.mutation_type_name:
                                result.mutations_count = len(fields_list)

                        result.types = types_list
                        result.sensitive_fields = sorted(list(set(sensitive_found)))
                except Exception:
                    pass
        except Exception:
            pass

        # 2. Test Field Suggestions ("Did you mean ...?")
        try:
            test_query = {"query": "query { __invalidFieldProbe12345 }"}
            resp_sugg = await http_engine.post(
                endpoint_url,
                json=test_query,
                headers={"Content-Type": "application/json"},
            )
            if resp_sugg.body and "Did you mean" in resp_sugg.body:
                result.suggestions_enabled = True
        except Exception:
            pass

        return result

    @staticmethod
    def generate_findings(analysis: GraphQLAnalysisResult) -> List[Finding]:
        """Convert GraphQL analysis results into security findings."""
        findings: List[Finding] = []

        if analysis.introspection_enabled:
            findings.append(
                Finding(
                    scanner="graphql-analyzer",
                    category="Information Disclosure",
                    title="GraphQL Introspection Query Enabled in Production",
                    severity=FindingSeverity.MEDIUM,
                    confidence=95,
                    status=FindingStatus.CONFIRMED,
                    endpoint_url=analysis.endpoint_url,
                    description=(
                        f"GraphQL schema introspection is enabled on {analysis.endpoint_url}, exposing all "
                        f"{len(analysis.types)} types, {analysis.queries_count} queries, and "
                        f"{analysis.mutations_count} mutations to unauthenticated consumers."
                    ),
                    evidence=f"Introspection query succeeded. Schema defines {len(analysis.types)} types.",
                    recommendation="Disable GraphQL introspection in production environments or restrict access behind authentication.",
                    references=[
                        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                        "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL",
                    ],
                )
            )

        if analysis.sensitive_fields:
            findings.append(
                Finding(
                    scanner="graphql-analyzer",
                    category="Information Disclosure",
                    title="Potentially Sensitive GraphQL Fields Discovered",
                    severity=FindingSeverity.LOW,
                    confidence=75,
                    status=FindingStatus.POTENTIAL,
                    endpoint_url=analysis.endpoint_url,
                    description=(
                        f"Schema introspection revealed fields containing sensitive keywords: "
                        f"{', '.join(analysis.sensitive_fields[:5])}"
                    ),
                    evidence=f"Sensitive fields found: {', '.join(analysis.sensitive_fields)}",
                    recommendation="Verify field-level authorization and object-level permissions on sensitive schema fields.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                )
            )

        if analysis.suggestions_enabled:
            findings.append(
                Finding(
                    scanner="graphql-analyzer",
                    category="Information Disclosure",
                    title="GraphQL Field Suggestions Enabled",
                    severity=FindingSeverity.INFO,
                    confidence=90,
                    status=FindingStatus.CONFIRMED,
                    endpoint_url=analysis.endpoint_url,
                    description=(
                        "The GraphQL engine returns schema suggestions ('Did you mean ...?') when querying "
                        "non-existent fields, allowing field enumeration even if introspection is disabled."
                    ),
                    evidence="Server responded with field suggestions upon receiving invalid field query.",
                    recommendation="Disable field suggestions in production GraphQL configuration.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"],
                )
            )

        return findings
