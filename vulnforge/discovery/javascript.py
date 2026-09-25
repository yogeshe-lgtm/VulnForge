"""Static JavaScript analysis and client-side endpoint discovery."""

from dataclasses import dataclass, field
import re
from typing import List, Set
from urllib.parse import urljoin, urlparse

from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter, ParameterLocation
from vulnforge.utils.normalization import normalize_url

# Regex patterns to statically identify API routes and paths inside JS code
PATH_PATTERNS = [
    # Explicit API, auth, graphql, admin routes inside quotes
    re.compile(r"""["'`](\/(?:api|v[0-9]+|graphql|auth|admin|users?|account|profile|search|login|logout|cart|orders?|items?|upload|download|static|data)[a-zA-Z0-9_./?=&%-]*)["'`]"""),
    # Generic relative paths with extension or query
    re.compile(r"""["'`](\/[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_.-]+)*(?:\?[a-zA-Z0-9_=&%-]+)?)["'`]"""),
]

# Client-side AJAX & Fetch patterns
AJAX_PATTERNS = [
    # fetch("...") or fetch(`...`)
    re.compile(r"""fetch\s*\(\s*["'`]([a-zA-Z0-9_./?:=&%-]+)["'`]"""),
    # axios.get("..."), axios.post("..."), etc.
    re.compile(r"""axios(?:\.(?:get|post|put|delete|patch|head))?\s*\(\s*["'`]([a-zA-Z0-9_./?:=&%-]+)["'`]"""),
    # $.ajax({url: "..."}) or $.get("..."), $.post("...")
    re.compile(r"""\$\s*\.\s*(?:get|post|getJSON|ajax)\s*\(\s*["'`]?([a-zA-Z0-9_./?:=&%-]+)["'`]?"""),
    re.compile(r"""url\s*:\s*["'`]([a-zA-Z0-9_./?:=&%-]+)["'`]"""),
    # xhr.open("GET", "...")
    re.compile(r"""\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["'`]([a-zA-Z0-9_./?:=&%-]+)["'`]"""),
]

# Blacklist of non-endpoint strings or file extensions that match path regex by accident
IGNORED_SUBSTRINGS = {
    "text/html", "text/javascript", "application/json", "text/css", "utf-8",
    "use strict", "undefined", "object", "function", "number", "boolean",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".css",
}


@dataclass
class JsDiscoveryResult:
    """Findings extracted from JavaScript source files."""

    script_url: str
    discovered_endpoints: List[Endpoint] = field(default_factory=list)
    discovered_parameters: List[Parameter] = field(default_factory=list)
    raw_paths: Set[str] = field(default_factory=set)


def extract_endpoints_from_js(
    js_content: str,
    script_url: str,
    base_target_url: str,
) -> JsDiscoveryResult:
    """Statically analyze JavaScript content to identify API routes, fetch targets, and parameters.

    Args:
        js_content: JavaScript code string.
        script_url: Source URL of the JavaScript file.
        base_target_url: Root application URL to resolve relative endpoints.

    Returns:
        JsDiscoveryResult containing discovered routes and parameters.
    """
    result = JsDiscoveryResult(script_url=script_url)
    if not js_content or not isinstance(js_content, str):
        return result

    raw_candidates: Set[str] = set()

    # 1. Match Path Patterns
    for pattern in PATH_PATTERNS:
        for match in pattern.findall(js_content):
            match_str = match.strip()
            if match_str and len(match_str) > 1 and not any(ign in match_str.lower() for ign in IGNORED_SUBSTRINGS):
                raw_candidates.add(match_str)

    # 2. Match AJAX/Fetch Patterns
    for pattern in AJAX_PATTERNS:
        for match in pattern.findall(js_content):
            match_str = match.strip()
            if match_str and len(match_str) > 1 and not any(ign in match_str.lower() for ign in IGNORED_SUBSTRINGS):
                raw_candidates.add(match_str)

    result.raw_paths = raw_candidates

    # Convert candidates to Endpoints & Parameters
    seen_endpoints: Set[str] = set()

    for candidate in raw_candidates:
        # If absolute URL with http/https
        if candidate.startswith("http://") or candidate.startswith("https://"):
            full_url = normalize_url(candidate)
        elif candidate.startswith("/"):
            full_url = normalize_url(urljoin(base_target_url, candidate))
        else:
            full_url = normalize_url(urljoin(base_target_url, "/" + candidate))

        if not full_url or full_url in seen_endpoints:
            continue

        seen_endpoints.add(full_url)

        # Parse query params if any
        parsed = urlparse(full_url)
        params: List[Parameter] = []
        if parsed.query:
            base_route = full_url.split("?")[0]
            from urllib.parse import parse_qsl
            for k, v in parse_qsl(parsed.query, keep_blank_values=True):
                param = Parameter(
                    name=k,
                    location=ParameterLocation.QUERY,
                    param_type="string",
                    sample_value=v,
                    endpoint_url=base_route,
                    source="JAVASCRIPT",
                )
                params.append(param)
                result.discovered_parameters.append(param)

        endpoint = Endpoint.from_url(
            url=full_url,
            method="GET",
            source="JAVASCRIPT",
            parameters=params,
        )
        result.discovered_endpoints.append(endpoint)

    return result
