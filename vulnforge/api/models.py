"""API and GraphQL security analysis domain models."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class APIType(str, Enum):
    """Classification of API architectural style."""

    REST = "REST"
    OPENAPI_V3 = "OPENAPI_V3"
    SWAGGER_V2 = "SWAGGER_V2"
    GRAPHQL = "GRAPHQL"
    JSON_RPC = "JSON_RPC"
    UNKNOWN = "UNKNOWN"


class APISecurityScheme(BaseModel):
    """Authentication and authorization scheme defined in API specification."""

    name: str = Field(..., description="Security scheme name (e.g., BearerAuth, ApiKeyAuth)")
    scheme_type: str = Field(..., description="Type: http, apiKey, oauth2, openIdConnect")
    location: Optional[str] = Field(default=None, description="Location: header, query, cookie")
    param_name: Optional[str] = Field(default=None, description="Header or parameter name")
    description: Optional[str] = Field(default=None, description="Scheme description")


class APIParameter(BaseModel):
    """Structured parameter extracted from API specification or schema."""

    name: str = Field(..., description="Parameter name")
    location: str = Field(..., description="query, path, header, cookie, body")
    param_type: str = Field(default="string", description="JSON schema data type")
    required: bool = Field(default=False, description="Whether parameter is mandatory")
    description: Optional[str] = Field(default=None, description="Parameter description")
    default_value: Optional[str] = Field(default=None, description="Default parameter value")
    enum_values: List[str] = Field(default_factory=list, description="Allowed enumeration values")


class APIRequestBody(BaseModel):
    """Specification of request payload schema."""

    content_type: str = Field(default="application/json", description="Body MIME type")
    schema_definition: Dict[str, Any] = Field(default_factory=dict, description="Parsed JSON schema")
    required: bool = Field(default=False, description="Whether body is required")


class APIResponse(BaseModel):
    """Specification of response status and payload schema."""

    status_code: str = Field(..., description="HTTP status code or 'default'")
    description: str = Field(default="", description="Response description")
    content_type: Optional[str] = Field(default="application/json", description="Response MIME type")
    schema_definition: Dict[str, Any] = Field(default_factory=dict, description="Response payload schema")


class APIRoute(BaseModel):
    """Single API endpoint path, method, and schema definition."""

    path: str = Field(..., description="API route path template (e.g., /api/v1/users/{id})")
    method: str = Field(..., description="HTTP Method (GET, POST, PUT, DELETE, PATCH, OPTIONS)")
    operation_id: Optional[str] = Field(default=None, description="Unique operation identifier")
    summary: Optional[str] = Field(default=None, description="Short summary of operation")
    description: Optional[str] = Field(default=None, description="Detailed operation description")
    parameters: List[APIParameter] = Field(default_factory=list, description="Declared parameters")
    request_body: Optional[APIRequestBody] = Field(default=None, description="Request body specification")
    responses: List[APIResponse] = Field(default_factory=list, description="Documented response codes")
    security_schemes: List[str] = Field(default_factory=list, description="Required security schemes")
    tags: List[str] = Field(default_factory=list, description="Categorical tags")
    is_deprecated: bool = Field(default=False, description="Whether route is marked deprecated")


class APISpec(BaseModel):
    """Parsed OpenAPI / Swagger specification."""

    title: str = Field(default="API Specification", description="API Title")
    version: str = Field(default="1.0.0", description="API Version")
    spec_version: str = Field(default="3.0.0", description="OpenAPI / Swagger spec version")
    base_url: str = Field(default="", description="API Base URL / Server URL")
    routes: List[APIRoute] = Field(default_factory=list, description="Documented API routes")
    security_schemes: Dict[str, APISecurityScheme] = Field(
        default_factory=dict, description="Configured security schemes"
    )
    raw_spec: Dict[str, Any] = Field(default_factory=dict, description="Raw dictionary spec")


class APIAnalysisResult(BaseModel):
    """Comprehensive findings and attack surface delta from API security analysis."""

    target_url: str = Field(..., description="Target base URL")
    api_type: APIType = Field(default=APIType.REST, description="Detected API architecture")
    spec: Optional[APISpec] = Field(default=None, description="Parsed API specification if discovered")
    documented_endpoints_count: int = Field(default=0, description="Total routes documented in spec")
    discovered_endpoints_count: int = Field(default=0, description="Total routes observed during crawl")
    undocumented_endpoints: List[str] = Field(
        default_factory=list, description="Routes found during crawl but missing from API documentation"
    )
    undocumented_parameters: List[str] = Field(
        default_factory=list, description="Parameters observed during crawl but missing from spec"
    )
    potentially_dangerous_methods: List[str] = Field(
        default_factory=list, description="Endpoints exposing DELETE, PUT, or PATCH without documented auth"
    )
    unauthenticated_routes: List[str] = Field(
        default_factory=list, description="Routes marked with no authentication requirements"
    )


class GraphQLField(BaseModel):
    """Field definition in a GraphQL Type."""

    name: str = Field(..., description="Field name")
    field_type: str = Field(..., description="Field type (e.g. String!, [User], Int)")
    is_deprecated: bool = Field(default=False, description="Whether field is deprecated")
    arguments: List[Dict[str, str]] = Field(default_factory=list, description="Field arguments and types")


class GraphQLType(BaseModel):
    """GraphQL Schema Type definition."""

    name: str = Field(..., description="Type name")
    kind: str = Field(..., description="OBJECT, INTERFACE, UNION, ENUM, INPUT_OBJECT, SCALAR")
    description: Optional[str] = Field(default=None, description="Type documentation")
    fields: List[GraphQLField] = Field(default_factory=list, description="Field definitions")


class GraphQLAnalysisResult(BaseModel):
    """Results of GraphQL security assessment and introspection audit."""

    endpoint_url: str = Field(..., description="Discovered GraphQL endpoint URL")
    introspection_enabled: bool = Field(
        default=False, description="Whether schema introspection query succeeded"
    )
    query_type_name: Optional[str] = Field(default=None, description="Root Query type name")
    mutation_type_name: Optional[str] = Field(default=None, description="Root Mutation type name")
    subscription_type_name: Optional[str] = Field(default=None, description="Root Subscription type name")
    types: List[GraphQLType] = Field(default_factory=list, description="Extracted schema types")
    queries_count: int = Field(default=0, description="Number of query fields exposed")
    mutations_count: int = Field(default=0, description="Number of mutation fields exposed")
    sensitive_fields: List[str] = Field(
        default_factory=list, description="Fields exposing sensitive keywords (password, token, secret, ssn, role)"
    )
    suggestions_enabled: bool = Field(
        default=False, description="Whether field name suggestions ('Did you mean ...?') are enabled"
    )
