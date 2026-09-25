"""OpenAPI and Swagger specification parser, auto-discovery, and security analyzer."""

import json
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from vulnforge.api.models import (
    APIAnalysisResult,
    APIParameter,
    APIRequestBody,
    APIResponse,
    APIRoute,
    APISecurityScheme,
    APISpec,
    APIType,
)
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter, ParameterLocation


OPENAPI_PROBE_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/api/openapi.json",
    "/api/swagger.json",
    "/api/v1/openapi.json",
    "/api/v2/openapi.json",
    "/swagger/v1/swagger.json",
    "/docs",
    "/api/docs",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/redoc",
]


class OpenAPIParser:
    """Parses OpenAPI 3.x and Swagger 2.0 JSON/YAML specifications into structured API models."""

    @staticmethod
    def parse(spec_dict: Dict[str, Any], base_url: str = "") -> APISpec:
        """Parse raw dictionary spec into an APISpec model."""
        info = spec_dict.get("info", {})
        title = info.get("title", "API Specification")
        version = info.get("version", "1.0.0")

        spec_ver = spec_dict.get("openapi") or spec_dict.get("swagger") or "3.0.0"

        # Determine servers / base_url
        effective_base = base_url
        if "servers" in spec_dict and isinstance(spec_dict["servers"], list) and spec_dict["servers"]:
            server_url = spec_dict["servers"][0].get("url", "")
            if server_url.startswith("http"):
                effective_base = server_url
            elif effective_base:
                effective_base = urljoin(effective_base, server_url)
        elif "host" in spec_dict:
            scheme = spec_dict.get("schemes", ["http"])[0]
            base_path = spec_dict.get("basePath", "")
            effective_base = f"{scheme}://{spec_dict['host']}{base_path}"

        # Security schemes
        security_schemes: Dict[str, APISecurityScheme] = {}
        if "components" in spec_dict and "securitySchemes" in spec_dict["components"]:
            for name, sc in spec_dict["components"]["securitySchemes"].items():
                security_schemes[name] = APISecurityScheme(
                    name=name,
                    scheme_type=sc.get("type", "http"),
                    location=sc.get("in"),
                    param_name=sc.get("name"),
                    description=sc.get("description"),
                )
        elif "securityDefinitions" in spec_dict:
            for name, sc in spec_dict["securityDefinitions"].items():
                security_schemes[name] = APISecurityScheme(
                    name=name,
                    scheme_type=sc.get("type", "apiKey"),
                    location=sc.get("in"),
                    param_name=sc.get("name"),
                    description=sc.get("description"),
                )

        # Routes and Operations
        routes: List[APIRoute] = []
        paths_obj = spec_dict.get("paths", {})
        http_methods = {"get", "post", "put", "delete", "patch", "options", "head"}

        for path_str, path_item in paths_obj.items():
            if not isinstance(path_item, dict):
                continue

            # Path-level parameters
            path_level_params = path_item.get("parameters", [])

            for method_name, op_item in path_item.items():
                if method_name.lower() not in http_methods or not isinstance(op_item, dict):
                    continue

                # Merge parameters
                raw_params = list(path_level_params) + op_item.get("parameters", [])
                api_params: List[APIParameter] = []
                for p in raw_params:
                    if not isinstance(p, dict):
                        continue
                    schema = p.get("schema", {})
                    p_type = schema.get("type") or p.get("type", "string")
                    api_params.append(
                        APIParameter(
                            name=p.get("name", "unknown"),
                            location=p.get("in", "query"),
                            param_type=p_type,
                            required=bool(p.get("required", False)),
                            description=p.get("description"),
                            default_value=str(schema.get("default", "")) if schema.get("default") else None,
                            enum_values=[str(v) for v in schema.get("enum", [])] if schema.get("enum") else [],
                        )
                    )

                # Request body (OpenAPI 3.x)
                req_body = None
                if "requestBody" in op_item and isinstance(op_item["requestBody"], dict):
                    rb = op_item["requestBody"]
                    content = rb.get("content", {})
                    c_type = "application/json" if "application/json" in content else (list(content.keys())[0] if content else "application/json")
                    schema_def = content.get(c_type, {}).get("schema", {})
                    req_body = APIRequestBody(
                        content_type=c_type,
                        schema_definition=schema_def,
                        required=bool(rb.get("required", False)),
                    )

                # Responses
                responses: List[APIResponse] = []
                for code_str, resp_item in op_item.get("responses", {}).items():
                    if isinstance(resp_item, dict):
                        resp_content = resp_item.get("content", {})
                        r_type = list(resp_content.keys())[0] if resp_content else "application/json"
                        r_schema = resp_content.get(r_type, {}).get("schema", {}) if resp_content else {}
                        responses.append(
                            APIResponse(
                                status_code=str(code_str),
                                description=resp_item.get("description", ""),
                                content_type=r_type,
                                schema_definition=r_schema,
                            )
                        )

                # Security on operation
                op_sec = op_item.get("security", spec_dict.get("security", []))
                sec_names = []
                for sec_item in op_sec:
                    if isinstance(sec_item, dict):
                        sec_names.extend(sec_item.keys())

                routes.append(
                    APIRoute(
                        path=path_str,
                        method=method_name.upper(),
                        operation_id=op_item.get("operationId"),
                        summary=op_item.get("summary"),
                        description=op_item.get("description"),
                        parameters=api_params,
                        request_body=req_body,
                        responses=responses,
                        security_schemes=sec_names,
                        tags=op_item.get("tags", []),
                        is_deprecated=bool(op_item.get("deprecated", False)),
                    )
                )

        return APISpec(
            title=title,
            version=version,
            spec_version=spec_ver,
            base_url=effective_base,
            routes=routes,
            security_schemes=security_schemes,
            raw_spec=spec_dict,
        )


class OpenAPIScanner:
    """Detects OpenAPI documents and analyzes API attack surface and security posture."""

    @staticmethod
    async def auto_detect_spec(http_engine: Any, base_url: str) -> Optional[Tuple[str, APISpec]]:
        """Probe common OpenAPI and Swagger discovery endpoints to locate schema definitions."""
        parsed_base = urlparse(base_url)
        root_origin = f"{parsed_base.scheme}://{parsed_base.netloc}"

        for path in OPENAPI_PROBE_PATHS:
            target_url = urljoin(root_origin, path)
            try:
                resp = await http_engine.get(target_url)
                if resp.is_success and resp.body:
                    try:
                        spec_json = json.loads(resp.body)
                        if isinstance(spec_json, dict) and ("openapi" in spec_json or "swagger" in spec_json or "paths" in spec_json):
                            parsed = OpenAPIParser.parse(spec_json, base_url=root_origin)
                            return target_url, parsed
                    except Exception:
                        continue
            except Exception:
                continue

        return None

    @staticmethod
    def analyze_api_security(
        spec: APISpec,
        discovered_endpoints: List[Endpoint],
        target_url: str,
    ) -> APIAnalysisResult:
        """Analyze API spec against discovered crawl surface to detect undocumented routes and insecure configurations."""
        doc_routes_set: Set[Tuple[str, str]] = set()
        base_prefix = urlparse(spec.base_url).path.rstrip("/") if spec.base_url else ""
        for r in spec.routes:
            doc_routes_set.add((r.path.rstrip("/"), r.method.upper()))
            if base_prefix:
                prefixed_path = f"{base_prefix}/{r.path.lstrip('/')}".rstrip("/")
                doc_routes_set.add((prefixed_path, r.method.upper()))

        disc_routes_set: Set[Tuple[str, str]] = set()
        undocumented_eps: List[str] = []
        for ep in discovered_endpoints:
            parsed = urlparse(ep.url)
            ep_path = parsed.path.rstrip("/")
            disc_routes_set.add((ep_path, ep.method.upper()))

            # Check if discovered route is not in spec
            matched = False
            for doc_path, doc_method in doc_routes_set:
                # Handle path parameters like /users/{id} vs /users/123
                if doc_method == ep.method.upper():
                    if doc_path == ep_path:
                        matched = True
                        break
                    doc_parts = doc_path.split("/")
                    ep_parts = ep_path.split("/")
                    if len(doc_parts) == len(ep_parts):
                        if all(dp.startswith("{") and dp.endswith("}") or dp == ep for dp, ep in zip(doc_parts, ep_parts)):
                            matched = True
                            break
            if not matched and (ep.is_api or "API" in ep.classifications):
                undocumented_eps.append(f"[{ep.method}] {parsed.path}")

        # Dangerous methods and unauthenticated routes
        dangerous_methods: List[str] = []
        unauth_routes: List[str] = []

        for r in spec.routes:
            if not r.security_schemes:
                unauth_routes.append(f"[{r.method}] {r.path}")
                if r.method in ("DELETE", "PUT", "PATCH"):
                    dangerous_methods.append(f"[{r.method}] {r.path} (No Security Requirement)")

        return APIAnalysisResult(
            target_url=target_url,
            api_type=APIType.OPENAPI_V3 if spec.spec_version.startswith("3") else APIType.SWAGGER_V2,
            spec=spec,
            documented_endpoints_count=len(spec.routes),
            discovered_endpoints_count=len(discovered_endpoints),
            undocumented_endpoints=sorted(undocumented_eps),
            potentially_dangerous_methods=sorted(dangerous_methods),
            unauthenticated_routes=sorted(unauth_routes),
        )

    @staticmethod
    def spec_to_endpoints(spec: APISpec, target_url: str) -> List[Endpoint]:
        """Convert parsed OpenAPI routes into VulnForge Endpoint models."""
        parsed_target = urlparse(target_url)
        root_origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
        endpoints: List[Endpoint] = []

        for r in spec.routes:
            full_url = urljoin(root_origin, r.path)
            # Create endpoint
            ep = Endpoint.from_url(
                url=full_url,
                method=r.method,
                source="OPENAPI",
            )
            ep.classifications = ["API"]
            if not r.security_schemes:
                ep.classifications.append("UNAUTHENTICATED_API")
            else:
                ep.authentication_required = True
                ep.classifications.append("AUTHENTICATION")

            # Attach parameters
            for p in r.parameters:
                loc = (
                    ParameterLocation.QUERY if p.location == "query"
                    else ParameterLocation.PATH if p.location == "path"
                    else ParameterLocation.HEADER if p.location == "header"
                    else ParameterLocation.FORM
                )
                ep.add_parameter(
                    Parameter(
                        name=p.name,
                        location=loc,
                        param_type=p.param_type,
                        endpoint_url=full_url,
                        source="OPENAPI",
                        sample_value=p.default_value,
                    )
                )

            endpoints.append(ep)

        return endpoints
