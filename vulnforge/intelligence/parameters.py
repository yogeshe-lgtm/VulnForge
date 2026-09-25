"""Parameter classification engine for Attack Surface Intelligence."""

import re
from typing import Optional, Set
from urllib.parse import urlparse

from vulnforge.intelligence.models import (
    ParameterClassification,
    ParameterClassificationResult,
)
from vulnforge.models.endpoint import Endpoint
from vulnforge.models.parameter import Parameter, ParameterLocation


# Keyword sets for parameter classification
IDENTIFIER_KEYWORDS: Set[str] = {
    "id", "user_id", "userid", "account_id", "uid", "item_id", "uuid", "guid",
    "doc_id", "profile_id", "order_id", "customer_id", "entity_id", "post_id",
    "article_id", "comment_id", "num", "record_id", "member_id", "device_id",
    "client_id", "session_user_id", "org_id", "role_id", "product_id",
}

AUTHENTICATION_KEYWORDS: Set[str] = {
    "token", "auth", "access_token", "api_key", "apikey", "secret", "password",
    "passwd", "pwd", "key", "jwt", "bearer", "private_key", "cert", "credential",
    "auth_token", "pass", "pin", "otp", "signature", "auth_code", "client_secret",
}

SESSION_KEYWORDS: Set[str] = {
    "session", "sid", "sessid", "session_id", "sessionid", "jsessionid",
    "phpsessid", "aspnet_sessionid", "csrf_token", "xsrf_token", "_csrf", "_xsrf",
}

REDIRECT_KEYWORDS: Set[str] = {
    "redirect", "redirect_to", "redirect_url", "return", "return_to", "return_url",
    "next", "goto", "out", "rurl", "forward", "dest", "destination", "target_url",
    "continue", "callback", "oauth_callback", "successto", "relay",
}

URL_INPUT_KEYWORDS: Set[str] = {
    "url", "uri", "link", "href", "domain", "host", "endpoint", "src", "source",
    "target", "webhook", "proxy", "feed", "site", "fetch", "preview_url", "remote_url",
}

FILE_PATH_KEYWORDS: Set[str] = {
    "path", "dir", "folder", "directory", "filepath", "pathname", "base_path",
    "root_dir", "location", "folder_path",
}

FILE_NAME_KEYWORDS: Set[str] = {
    "file", "filename", "doc", "document", "attachment", "report", "image",
    "upload", "log", "template", "sheet", "pdf", "csv", "avatar", "photo", "media",
}

SEARCH_KEYWORDS: Set[str] = {
    "q", "query", "search", "keyword", "term", "find", "filter", "search_term",
    "s", "lookup", "k", "text", "search_query",
}

PAGINATION_KEYWORDS: Set[str] = {
    "page", "p", "limit", "offset", "count", "start", "per_page", "size",
    "pagesize", "max_results", "rows", "skip", "take",
}

STATE_CHANGE_KEYWORDS: Set[str] = {
    "action", "act", "do", "operation", "op", "cmd", "delete", "remove", "update",
    "create", "submit", "save", "edit", "modify", "toggle", "status_change",
}

# Value patterns
UUID_REGEX = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
FILE_EXT_REGEX = re.compile(
    r"^[\w,\s-]+\.(pdf|docx?|xlsx?|txt|csv|png|jpe?g|gif|svg|xml|json|html?|php|jsp|asp|sh|bat)$",
    re.IGNORECASE,
)
NUMERIC_REGEX = re.compile(r"^-?\d+(\.\d+)?$")
URL_PREFIX_REGEX = re.compile(r"^(https?://|//|ftp://)", re.IGNORECASE)
PATH_SLASH_REGEX = re.compile(r"[/\\].+[/\\].+")


class ParameterClassifier:
    """Classifies input parameters based on name semantics, location, and sample value characteristics."""

    @classmethod
    def classify(
        cls,
        param: Parameter,
        endpoint_context: Optional[Endpoint] = None,
    ) -> ParameterClassificationResult:
        """Classify a parameter and determine confidence score with explainable reasons.

        Args:
            param: Parameter instance to analyze.
            endpoint_context: Optional parent Endpoint providing contextual clues.

        Returns:
            ParameterClassificationResult with category, confidence, and reasons.
        """
        name_lower = param.name.lower().strip()
        val = str(param.sample_value).strip() if param.sample_value is not None else ""
        reasons = []

        # 1. Location-specific classification (JSON Body)
        if param.location == ParameterLocation.JSON:
            reasons.append("Parameter discovered within JSON request payload")

        # 2. Check Redirect Keywords
        if name_lower in REDIRECT_KEYWORDS or any(
            name_lower.startswith(k + "_") or name_lower.endswith("_" + k) for k in REDIRECT_KEYWORDS
        ):
            reasons.append(f"Parameter name '{param.name}' matches URL redirection conventions")
            return ParameterClassificationResult(
                classification=ParameterClassification.REDIRECT,
                confidence=90,
                reasons=reasons,
            )

        # 3. Check Authentication Keywords
        if name_lower in AUTHENTICATION_KEYWORDS or any(
            name_lower.startswith(k + "_") or name_lower.endswith("_" + k) for k in AUTHENTICATION_KEYWORDS
        ):
            reasons.append(f"Parameter name '{param.name}' matches authentication/credential conventions")
            return ParameterClassificationResult(
                classification=ParameterClassification.AUTHENTICATION,
                confidence=95,
                reasons=reasons,
            )

        # 4. Check Session Keywords
        if name_lower in SESSION_KEYWORDS:
            reasons.append(f"Parameter name '{param.name}' matches session tracking conventions")
            return ParameterClassificationResult(
                classification=ParameterClassification.SESSION,
                confidence=90,
                reasons=reasons,
            )

        # 5. Check URL Input (by keyword or value shape)
        if name_lower in URL_INPUT_KEYWORDS or any(
            name_lower.endswith("_" + k) for k in URL_INPUT_KEYWORDS
        ):
            reasons.append(f"Parameter name '{param.name}' indicates target URL input")
            return ParameterClassificationResult(
                classification=ParameterClassification.URL_INPUT,
                confidence=85,
                reasons=reasons,
            )

        if val and URL_PREFIX_REGEX.match(val):
            reasons.append(f"Sample value '{val[:30]}' matches absolute URL format")
            return ParameterClassificationResult(
                classification=ParameterClassification.URL_INPUT,
                confidence=90,
                reasons=reasons,
            )

        # 6. Check File Path Keywords & Value Shape
        if name_lower in FILE_PATH_KEYWORDS or any(
            name_lower.endswith("_" + k) for k in FILE_PATH_KEYWORDS
        ):
            reasons.append(f"Parameter name '{param.name}' matches filesystem path conventions")
            return ParameterClassificationResult(
                classification=ParameterClassification.FILE_PATH,
                confidence=85,
                reasons=reasons,
            )

        if val and PATH_SLASH_REGEX.search(val):
            reasons.append(f"Sample value contains multi-level path separators: {val[:30]}")
            return ParameterClassificationResult(
                classification=ParameterClassification.FILE_PATH,
                confidence=80,
                reasons=reasons,
            )

        # 7. Check File Name Keywords & Value Shape
        if name_lower in FILE_NAME_KEYWORDS or any(
            name_lower.endswith("_" + k) for k in FILE_NAME_KEYWORDS
        ):
            reasons.append(f"Parameter name '{param.name}' matches filename or document attachment conventions")
            return ParameterClassificationResult(
                classification=ParameterClassification.FILE_NAME,
                confidence=85,
                reasons=reasons,
            )

        if val and FILE_EXT_REGEX.match(val):
            reasons.append(f"Sample value '{val}' has recognized file extension format")
            return ParameterClassificationResult(
                classification=ParameterClassification.FILE_NAME,
                confidence=85,
                reasons=reasons,
            )

        # 8. Check Identifier Keywords & UUID Shape
        if (
            name_lower in IDENTIFIER_KEYWORDS
            or name_lower.endswith("_id")
            or (name_lower.startswith("id_") and len(name_lower) > 3)
            or (name_lower.endswith("id") and len(name_lower) > 2 and name_lower not in ("grid", "void", "fluid", "solid", "valid", "hybrid"))
        ):
            reasons.append(f"Parameter name '{param.name}' indicates resource or entity identifier")
            return ParameterClassificationResult(
                classification=ParameterClassification.IDENTIFIER,
                confidence=90,
                reasons=reasons,
            )

        if val and UUID_REGEX.match(val):
            reasons.append(f"Sample value matches standard UUID pattern: {val}")
            return ParameterClassificationResult(
                classification=ParameterClassification.IDENTIFIER,
                confidence=95,
                reasons=reasons,
            )

        # 9. Check Search Keywords
        if name_lower in SEARCH_KEYWORDS:
            reasons.append(f"Parameter name '{param.name}' matches search/query input conventions")
            return ParameterClassificationResult(
                classification=ParameterClassification.SEARCH,
                confidence=85,
                reasons=reasons,
            )

        # 10. Check Pagination Keywords
        if name_lower in PAGINATION_KEYWORDS:
            reasons.append(f"Parameter name '{param.name}' matches pagination/cursor parameter conventions")
            return ParameterClassificationResult(
                classification=ParameterClassification.PAGINATION,
                confidence=85,
                reasons=reasons,
            )

        # 11. Check State Change Keywords
        if name_lower in STATE_CHANGE_KEYWORDS:
            reasons.append(f"Parameter name '{param.name}' indicates state-altering action/command parameter")
            return ParameterClassificationResult(
                classification=ParameterClassification.STATE_CHANGE,
                confidence=80,
                reasons=reasons,
            )

        # 12. Check Boolean flags
        if val.lower() in ("true", "false", "yes", "no") or name_lower.startswith(("is_", "has_", "enable_", "allow_")):
            reasons.append(f"Parameter '{param.name}' exhibits boolean toggle semantics")
            return ParameterClassificationResult(
                classification=ParameterClassification.BOOLEAN,
                confidence=80,
                reasons=reasons,
            )

        # 13. Check Numeric Value
        if val and NUMERIC_REGEX.match(val):
            reasons.append(f"Sample value is numeric format: {val}")
            return ParameterClassificationResult(
                classification=ParameterClassification.NUMERIC,
                confidence=70,
                reasons=reasons,
            )

        # 14. Check JSON Field
        if param.location == ParameterLocation.JSON:
            return ParameterClassificationResult(
                classification=ParameterClassification.JSON_FIELD,
                confidence=75,
                reasons=["Extracted from JSON structured payload"],
            )

        # Default: UNKNOWN
        return ParameterClassificationResult(
            classification=ParameterClassification.UNKNOWN,
            confidence=30,
            reasons=["No distinct category patterns or formatting conventions matched"],
        )
