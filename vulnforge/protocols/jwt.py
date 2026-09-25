"""JWT (JSON Web Token) Security and Configuration Analyzer."""

import base64
import json
import re
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from vulnforge.scanners.result import Finding, FindingSeverity, FindingStatus
from vulnforge.utils.redaction import mask_token, redact_dict_secrets


JWT_REGEX = re.compile(r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*")

SENSITIVE_CLAIM_KEYWORDS = {
    "password", "passwd", "secret", "private_key", "ssn", "credit_card",
    "cvv", "api_key", "access_token", "refresh_token", "pin", "salt",
}


class JWTAnalysisResult(BaseModel):
    """Detailed structural and security analysis of a JSON Web Token."""

    raw_token_masked: str = Field(..., description="Masked token representation")
    algorithm: str = Field(default="UNKNOWN", description="Signing algorithm specified in header")
    key_id: Optional[str] = Field(default=None, description="Key identifier (kid)")
    header: Dict[str, Any] = Field(default_factory=dict, description="Decoded JOSE header")
    claims: Dict[str, Any] = Field(default_factory=dict, description="Decoded JWT claims payload")
    is_valid_structure: bool = Field(default=True, description="Whether token matches RFC 7519 3-segment structure")
    is_none_algorithm: bool = Field(default=False, description="Whether algorithm is set to 'none'")
    is_expired: Optional[bool] = Field(default=None, description="Expiration status")
    issued_at: Optional[str] = Field(default=None, description="Token issue timestamp")
    expires_at: Optional[str] = Field(default=None, description="Token expiration timestamp")
    sensitive_claims_exposed: List[str] = Field(default_factory=list, description="Sensitive claims found in unencrypted payload")
    weaknesses: List[str] = Field(default_factory=list, description="Identified security weaknesses or anomalies")
    findings: List[Finding] = Field(default_factory=list, description="Synthesized security findings")


class JWTAnalyzer:
    """Analyzer for inspecting JWT tokens, identifying insecure algorithms and sensitive claim leakage."""

    @staticmethod
    def _base64url_decode(segment: str) -> bytes:
        """Safely decode a base64url-encoded segment with proper padding."""
        rem = len(segment) % 4
        if rem > 0:
            segment += "=" * (4 - rem)
        return base64.urlsafe_b64decode(segment.encode("ascii"))

    @classmethod
    def analyze_token(cls, raw_token: str, origin_endpoint: str = "Client/Token Analysis") -> JWTAnalysisResult:
        """Parse and evaluate security properties of a JSON Web Token."""
        token_str = raw_token.strip()
        # Remove Bearer prefix if present
        if token_str.lower().startswith("bearer "):
            token_str = token_str[7:].strip()

        masked = mask_token(token_str)
        parts = token_str.split(".")

        if len(parts) != 3:
            return JWTAnalysisResult(
                raw_token_masked=masked,
                is_valid_structure=False,
                weaknesses=["Malformed JWT: Token does not contain exactly 3 dot-separated segments."],
            )

        header_b64, payload_b64, signature_b64 = parts

        # 1. Decode Header
        try:
            header_json = cls._base64url_decode(header_b64).decode("utf-8", errors="replace")
            header = json.loads(header_json)
        except Exception as e:
            header = {}

        # 2. Decode Payload
        try:
            payload_json = cls._base64url_decode(payload_b64).decode("utf-8", errors="replace")
            claims = json.loads(payload_json)
        except Exception as e:
            claims = {}

        algorithm = str(header.get("alg", "UNKNOWN")).strip()
        key_id = header.get("kid")

        weaknesses: List[str] = []
        findings: List[Finding] = []
        is_none_algorithm = False

        # Check 'none' algorithm
        if algorithm.lower() == "none":
            is_none_algorithm = True
            weaknesses.append("Insecure Algorithm: 'none' algorithm detected (unsigned token).")
            findings.append(
                Finding(
                    scanner="jwt-analyzer",
                    category="Cryptographic Weakness",
                    title="Insecure JWT Algorithm: 'none' In Use",
                    severity=FindingSeverity.CRITICAL,
                    confidence=95,
                    status=FindingStatus.CONFIRMED,
                    endpoint_url=origin_endpoint,
                    description=(
                        "The token uses the 'none' algorithm which disables cryptographic signature validation, "
                        "allowing arbitrary token forgery and authentication bypass if accepted by the server."
                    ),
                    evidence=f"Header: {json.dumps(header)}",
                    recommendation="Reject any tokens with 'alg: none'. Enforce strong asymmetric (e.g. RS256, ES256) or HMAC algorithms.",
                    references=["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"],
                )
            )

        # Check missing or no signature
        if not signature_b64 and not is_none_algorithm:
            weaknesses.append("Empty Signature: Token payload is unsigned.")
            findings.append(
                Finding(
                    scanner="jwt-analyzer",
                    category="Cryptographic Weakness",
                    title="Unsigned JWT Token",
                    severity=FindingSeverity.HIGH,
                    confidence=90,
                    status=FindingStatus.CONFIRMED,
                    endpoint_url=origin_endpoint,
                    description="The JWT contains an empty signature segment, indicating unverified integrity.",
                    evidence="Signature segment is empty.",
                    recommendation="Ensure all tokens are cryptographically signed with a secure private key or secret.",
                )
            )

        # Check expiration (exp) claim
        is_expired: Optional[bool] = None
        expires_at_str: Optional[str] = None
        issued_at_str: Optional[str] = None

        now = int(time.time())

        if "exp" in claims and isinstance(claims["exp"], (int, float)):
            exp_ts = int(claims["exp"])
            is_expired = exp_ts < now
            expires_at_str = datetime.fromtimestamp(exp_ts, tz=timezone.utc).isoformat()
            if is_expired:
                weaknesses.append(f"Expired Token: Expired at {expires_at_str}.")
        else:
            weaknesses.append("Missing Expiration: Token does not contain an 'exp' claim (indefinitely valid).")
            findings.append(
                Finding(
                    scanner="jwt-analyzer",
                    category="Session Management",
                    title="JWT Missing Expiration (exp) Claim",
                    severity=FindingSeverity.MEDIUM,
                    confidence=85,
                    status=FindingStatus.POTENTIAL,
                    endpoint_url=origin_endpoint,
                    description="The JWT token lacks an expiration timestamp ('exp' claim), making it valid indefinitely if intercepted.",
                    evidence=f"Claims keys present: {list(claims.keys())}",
                    recommendation="Include a short-lived 'exp' claim in all issued JWTs.",
                )
            )

        if "iat" in claims and isinstance(claims["iat"], (int, float)):
            issued_at_str = datetime.fromtimestamp(int(claims["iat"]), tz=timezone.utc).isoformat()

        # Check key ID (kid) injection / directory traversal indicators
        if key_id and isinstance(key_id, str):
            if any(p in key_id for p in ("../", "..\\", "/dev/null", "'", ";", "--")):
                weaknesses.append(f"Suspicious Key ID: 'kid' value contains suspicious traversal or injection sequences: {key_id}")
                findings.append(
                    Finding(
                        scanner="jwt-analyzer",
                        category="Injection",
                        title="Suspicious 'kid' Parameter in JWT Header",
                        severity=FindingSeverity.HIGH,
                        confidence=80,
                        status=FindingStatus.POTENTIAL,
                        endpoint_url=origin_endpoint,
                        description=f"The JWT header 'kid' parameter contains suspicious sequence '{key_id}' indicative of directory traversal or injection attacks.",
                        evidence=f"Header: {json.dumps(header)}",
                        recommendation="Sanitize and strictly whitelist 'kid' values against an allowed set of key IDs.",
                    )
                )

        # Check sensitive claim exposure
        sensitive_claims: List[str] = []
        for claim_key in claims:
            if any(kw in claim_key.lower() for kw in SENSITIVE_CLAIM_KEYWORDS):
                sensitive_claims.append(claim_key)

        if sensitive_claims:
            weaknesses.append(f"Sensitive Data Exposure: Unencrypted payload contains sensitive fields: {sensitive_claims}")
            findings.append(
                Finding(
                    scanner="jwt-analyzer",
                    category="Information Disclosure",
                    title=f"Sensitive Data Exposed in JWT Claims ({', '.join(sensitive_claims)})",
                    severity=FindingSeverity.MEDIUM,
                    confidence=85,
                    status=FindingStatus.CONFIRMED,
                    endpoint_url=origin_endpoint,
                    description=(
                        f"JWT payload is Base64URL-encoded (not encrypted) and exposes sensitive fields ({sensitive_claims}). "
                        "Anyone with access to the token can read these values."
                    ),
                    evidence=f"Sensitive claim names: {sensitive_claims}",
                    recommendation="Never store secrets, passwords, or sensitive PII in unencrypted JWT claims.",
                )
            )

        return JWTAnalysisResult(
            raw_token_masked=masked,
            algorithm=algorithm,
            key_id=key_id,
            header=header,
            claims=redact_dict_secrets(claims),
            is_valid_structure=True,
            is_none_algorithm=is_none_algorithm,
            is_expired=is_expired,
            issued_at=issued_at_str,
            expires_at=expires_at_str,
            sensitive_claims_exposed=sensitive_claims,
            weaknesses=weaknesses,
            findings=findings,
        )

    @classmethod
    def extract_and_analyze_tokens_from_text(cls, text: str, endpoint: str = "Discovered Content") -> List[JWTAnalysisResult]:
        """Discover JWT tokens in arbitrary text / response bodies and perform analysis."""
        matches = JWT_REGEX.findall(text)
        results: List[JWTAnalysisResult] = []
        seen = set()

        for match in matches:
            if match not in seen:
                seen.add(match)
                results.append(cls.analyze_token(match, origin_endpoint=endpoint))

        return results
