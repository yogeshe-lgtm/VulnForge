"""Endpoint classification engine for Attack Surface Intelligence."""

import re
from typing import List, Optional, Set
from urllib.parse import urlparse

from vulnforge.intelligence.models import (
    EndpointClassification,
    ParameterClassification,
)
from vulnforge.intelligence.parameters import ParameterClassifier
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter


STATIC_EXTENSIONS: Set[str] = {
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff",
    ".woff2", ".ttf", ".eot", ".mp4", ".webm", ".map", ".webp", ".avif",
    ".zip", ".gz", ".tar", ".wasm", ".bin",
}

AUTH_PATH_KEYWORDS: Set[str] = {
    "login", "signin", "auth", "oauth", "logout", "signout", "register",
    "signup", "password", "reset-password", "forgot", "mfa", "2fa", "sso",
    "saml", "token", "session", "credential",
}

ADMIN_PATH_KEYWORDS: Set[str] = {
    "admin", "dashboard", "manage", "management", "panel", "control", "portal",
    "internal", "moderator", "sysadmin", "console", "root", "settings",
}

SEARCH_PATH_KEYWORDS: Set[str] = {
    "search", "find", "query", "lookup", "filter", "explore",
}

UPLOAD_PATH_KEYWORDS: Set[str] = {
    "upload", "attachment", "import", "media", "avatar", "file-upload", "dropzone",
}

REDIRECT_PATH_KEYWORDS: Set[str] = {
    "redirect", "goto", "out", "forward", "relay", "r", "jump", "link",
}

PATH_ID_REGEX = re.compile(
    r"/(?:[0-9]{1,10}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})(?:/|$)"
)
PATH_VARIABLE_REGEX = re.compile(r"/\{[\w-]+\}(?:/|$)")


class EndpointClassifier:
    """Classifies endpoints into functional, structural, and risk-oriented categories."""

    @classmethod
    def classify(
        cls,
        endpoint: Endpoint,
        parameters: Optional[List[Parameter]] = None,
    ) -> List[EndpointClassification]:
        """Classify endpoint based on URL structure, path semantics, HTTP method, and parameters.

        Args:
            endpoint: Endpoint instance to classify.
            parameters: Associated parameters for this endpoint (defaults to endpoint.parameters).

        Returns:
            List of matched EndpointClassification enum values.
        """
        params = parameters if parameters is not None else endpoint.parameters
        parsed = urlparse(endpoint.url)
        path = parsed.path.lower() or "/"
        method = endpoint.method.upper()
        content_type = (endpoint.content_type or "").lower()

        classifications: Set[EndpointClassification] = set()

        # 1. Check for Static Asset
        is_static = False
        if any(path.endswith(ext) for ext in STATIC_EXTENSIONS):
            is_static = True
        elif any(ct in content_type for ct in ("image/", "text/css", "font/", "audio/", "video/")):
            is_static = True

        if is_static:
            classifications.add(EndpointClassification.STATIC_ASSET)
            return list(classifications)

        # 2. Check for API Endpoint
        if endpoint.is_api:
            classifications.add(EndpointClassification.API)
        elif any(
            path.startswith(prefix)
            for prefix in ("/api", "/v1", "/v2", "/v3", "/graphql", "/rest", "/oauth", "/auth")
        ):
            classifications.add(EndpointClassification.API)
        elif "application/json" in content_type or "application/xml" in content_type:
            classifications.add(EndpointClassification.API)

        # 3. Check for Authentication Endpoint
        path_segments = [s.strip() for s in path.split("/") if s.strip()]
        if any(k in path_segments or any(k in seg for k in AUTH_PATH_KEYWORDS) for seg in path_segments for k in AUTH_PATH_KEYWORDS):
            classifications.add(EndpointClassification.AUTHENTICATION)

        # 4. Check for Admin-like Path
        if any(k in path_segments for k in ADMIN_PATH_KEYWORDS):
            classifications.add(EndpointClassification.ADMIN_LIKE_PATH)

        # 5. Check for Search
        if any(k in path_segments for k in SEARCH_PATH_KEYWORDS):
            classifications.add(EndpointClassification.SEARCH)

        # 6. Check for File Upload Candidate
        if any(k in path_segments for k in UPLOAD_PATH_KEYWORDS):
            classifications.add(EndpointClassification.FILE_UPLOAD_CANDIDATE)
        elif "multipart/form-data" in content_type and method in ("POST", "PUT"):
            classifications.add(EndpointClassification.FILE_UPLOAD_CANDIDATE)

        # 7. Check for Redirect Candidate
        if any(k in path_segments for k in REDIRECT_PATH_KEYWORDS):
            classifications.add(EndpointClassification.REDIRECT_CANDIDATE)

        # 8. Check for Identifier in Path
        if PATH_ID_REGEX.search(path) or PATH_VARIABLE_REGEX.search(path):
            classifications.add(EndpointClassification.IDENTIFIER_ENDPOINT)

        # 9. Check for State Changing HTTP Method
        if method in ("POST", "PUT", "DELETE", "PATCH"):
            classifications.add(EndpointClassification.STATE_CHANGING)

        # 10. Check Parameters for Classification Cross-Inference
        if params:
            classifications.add(EndpointClassification.DYNAMIC_ROUTE)
            for p in params:
                p_cls = p.classification
                if p_cls == "UNKNOWN":
                    res = ParameterClassifier.classify(p, endpoint)
                    p_cls = res.classification.value
                    p.classification = p_cls
                    p.classification_confidence = res.confidence

                if p_cls == ParameterClassification.IDENTIFIER.value:
                    classifications.add(EndpointClassification.IDENTIFIER_ENDPOINT)
                elif p_cls == ParameterClassification.SEARCH.value:
                    classifications.add(EndpointClassification.SEARCH)
                elif p_cls in (ParameterClassification.REDIRECT.value, ParameterClassification.URL_INPUT.value):
                    classifications.add(EndpointClassification.REDIRECT_CANDIDATE)
                elif p_cls in (ParameterClassification.FILE_NAME.value, ParameterClassification.FILE_PATH.value):
                    classifications.add(EndpointClassification.FILE_UPLOAD_CANDIDATE)
                elif p_cls in (ParameterClassification.AUTHENTICATION.value, ParameterClassification.SESSION.value):
                    classifications.add(EndpointClassification.AUTHENTICATION)

        # 11. Default fallback
        if not classifications:
            classifications.add(EndpointClassification.GENERAL_PAGE)

        return sorted(list(classifications), key=lambda c: c.value)
