"""Secret and sensitive data redaction utility."""

import re
from typing import Any, Dict, List, Union

REDACTION_PATTERNS = [
    # Authorization header / Bearer token / Basic Auth
    (re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)\s+)[A-Za-z0-9\-_.~+/=]+"), r"\1[REDACTED]"),
    # JWT tokens
    (re.compile(r"eyJ[A-Za-z0-9\-_=]+\.eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_.+/=]+"), "[REDACTED_JWT]"),
    # Generic API Keys / Tokens
    (re.compile(r"(?i)(api[_-]?key|token|access[_-]?token|secret|password|passwd|auth[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9\-_.~+/=]{6,})['\"]?"), r"\1=[REDACTED]"),
    # Cookies
    (re.compile(r"(?i)(cookie\s*:\s*.*?(?:sessionid|session|token|auth|jwt)=)[^;\s]+"), r"\1[REDACTED]"),
    # Private keys
    (re.compile(r"-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----[\s\S]*?-----END\s+[A-Z\s]+PRIVATE\s+KEY-----"), "[REDACTED_PRIVATE_KEY]"),
    # AWS Access / Secret keys
    (re.compile(r"(?i)(AKIA[0-9A-Z]{16})"), "[REDACTED_AWS_KEY]"),
    (re.compile(r"(?i)(aws_secret_access_key\s*=\s*)[A-Za-z0-9/+=]{40}"), r"\1[REDACTED]"),
]


def redact_secrets(text: Union[str, Any]) -> str:
    """Redact passwords, tokens, API keys, and sensitive authorization headers from text.

    Args:
        text: Arbitrary string or object to sanitize.

    Returns:
        Sanitized string with sensitive secrets masked.
    """
    if not isinstance(text, str):
        text = str(text) if text is not None else ""

    sanitized = text
    for pattern, replacement in REDACTION_PATTERNS:
        sanitized = pattern.sub(replacement, sanitized)

    return sanitized


def redact_dict_secrets(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively redact secrets in dictionaries and string values."""
    sanitized: Dict[str, Any] = {}
    sensitive_keys = {
        "password", "passwd", "secret", "token", "access_token",
        "authorization", "api_key", "apikey", "session", "cookie", "set-cookie",
    }

    for k, v in data.items():
        if k.lower() in sensitive_keys and isinstance(v, str):
            sanitized[k] = "[REDACTED]"
        elif isinstance(v, dict):
            sanitized[k] = redact_dict_secrets(v)
        elif isinstance(v, list):
            sanitized[k] = [
                redact_dict_secrets(item) if isinstance(item, dict)
                else redact_secrets(item) if isinstance(item, str)
                else item
                for item in v
            ]
        elif isinstance(v, str):
            sanitized[k] = redact_secrets(v)
        else:
            sanitized[k] = v

    return sanitized
