"""Passive technology fingerprinting and framework detection."""

from dataclasses import dataclass, field
import re
from typing import Dict, List, Optional, Set

from vulnforge.models.response import HttpResponse


@dataclass
class TechnologyDetection:
    """Represents a passively detected technology signature."""

    name: str
    category: str  # Web Server, Framework, Language, CDN/WAF, CMS, JS Library
    confidence: int  # 1-100%
    evidence: str
    version: Optional[str] = None


class TechnologyFingerprinter:
    """Passively identifies server-side, framework, and client-side web technologies."""

    def __init__(self):
        self._detections: Dict[str, TechnologyDetection] = {}

    def _add_detection(
        self,
        name: str,
        category: str,
        confidence: int,
        evidence: str,
        version: Optional[str] = None,
    ) -> None:
        """Add or merge detection with highest confidence."""
        if name in self._detections:
            existing = self._detections[name]
            # If new detection has higher confidence or provides version
            if confidence > existing.confidence:
                self._detections[name] = TechnologyDetection(
                    name=name,
                    category=category,
                    confidence=confidence,
                    evidence=f"{existing.evidence}; {evidence}",
                    version=version or existing.version,
                )
            elif version and not existing.version:
                existing.version = version
                existing.evidence += f"; {evidence}"
        else:
            self._detections[name] = TechnologyDetection(
                name=name,
                category=category,
                confidence=min(100, max(1, confidence)),
                evidence=evidence,
                version=version,
            )

    def analyze_response(
        self,
        response: HttpResponse,
        meta_tags: Optional[Dict[str, str]] = None,
        scripts: Optional[List[str]] = None,
    ) -> List[TechnologyDetection]:
        """Analyze HTTP headers, cookies, HTML DOM, meta tags, and script URLs.

        Args:
            response: Captured HTTP response.
            meta_tags: Extracted HTML meta tags dictionary.
            scripts: List of discovered script URLs.

        Returns:
            List of detected technologies on this response.
        """
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        body = response.body or ""
        body_lower = body.lower()

        # ----------------------------------------------------
        # 1. HTTP HEADERS ANALYSIS
        # ----------------------------------------------------
        # Server header
        server = headers_lower.get("server", "")
        if server:
            if "nginx" in server.lower():
                ver_match = re.search(r"nginx/([\d.]+)", server, re.IGNORECASE)
                self._add_detection(
                    "Nginx", "Web Server", 95, f"Server header: '{server}'", ver_match.group(1) if ver_match else None
                )
            elif "apache" in server.lower():
                ver_match = re.search(r"apache/([\d.]+)", server, re.IGNORECASE)
                self._add_detection(
                    "Apache HTTP Server", "Web Server", 95, f"Server header: '{server}'", ver_match.group(1) if ver_match else None
                )
            elif "cloudflare" in server.lower():
                self._add_detection("Cloudflare", "CDN/WAF", 95, f"Server header: '{server}'")
            elif "caddy" in server.lower():
                self._add_detection("Caddy", "Web Server", 90, f"Server header: '{server}'")
            elif "microsoft-iis" in server.lower():
                ver_match = re.search(r"Microsoft-IIS/([\d.]+)", server, re.IGNORECASE)
                self._add_detection(
                    "Microsoft IIS", "Web Server", 95, f"Server header: '{server}'", ver_match.group(1) if ver_match else None
                )

        # X-Powered-By
        x_powered_by = headers_lower.get("x-powered-by", "")
        if x_powered_by:
            if "php" in x_powered_by.lower():
                ver_match = re.search(r"PHP/([\d.]+)", x_powered_by, re.IGNORECASE)
                self._add_detection(
                    "PHP", "Programming Language", 95, f"X-Powered-By: '{x_powered_by}'", ver_match.group(1) if ver_match else None
                )
            elif "express" in x_powered_by.lower():
                self._add_detection("Express.js", "Web Framework", 95, f"X-Powered-By: '{x_powered_by}'")
                self._add_detection("Node.js", "Runtime", 85, "Express.js runtime inference")
            elif "asp.net" in x_powered_by.lower():
                self._add_detection("ASP.NET", "Web Framework", 95, f"X-Powered-By: '{x_powered_by}'")
            elif "next.js" in x_powered_by.lower():
                self._add_detection("Next.js", "Web Framework", 95, f"X-Powered-By: '{x_powered_by}'")

        # Other technology-specific headers
        if "x-nextjs-cache" in headers_lower or "x-nextjs-page" in headers_lower:
            self._add_detection("Next.js", "Web Framework", 95, "X-NextJS custom header presence")
        if "cf-ray" in headers_lower:
            self._add_detection("Cloudflare", "CDN/WAF", 95, f"CF-Ray header: {headers_lower['cf-ray']}")

        # ----------------------------------------------------
        # 2. COOKIES ANALYSIS
        # ----------------------------------------------------
        set_cookie = headers_lower.get("set-cookie", "")
        if "phpsessid" in set_cookie.lower():
            self._add_detection("PHP", "Programming Language", 85, "PHPSESSID session cookie")
        if "laravel_session" in set_cookie.lower() or "laravel_token" in set_cookie.lower():
            self._add_detection("Laravel", "Web Framework", 90, "laravel_session cookie")
            self._add_detection("PHP", "Programming Language", 85, "Laravel framework indicator")
        if "csrftoken" in set_cookie.lower() or "django" in set_cookie.lower():
            self._add_detection("Django", "Web Framework", 75, "Django csrftoken/session cookie")
            self._add_detection("Python", "Programming Language", 70, "Django framework indicator")
        if "connect.sid" in set_cookie.lower():
            self._add_detection("Express.js", "Web Framework", 85, "connect.sid session cookie")
            self._add_detection("Node.js", "Runtime", 80, "Express.js cookie indicator")
        if "jsessionid" in set_cookie.lower():
            self._add_detection("Java / Servlet", "Runtime", 85, "JSESSIONID cookie")
        if "asp.net_sessionid" in set_cookie.lower() or ".aspnetcore" in set_cookie.lower():
            self._add_detection("ASP.NET", "Web Framework", 90, "ASP.NET session cookie")

        # ----------------------------------------------------
        # 3. META TAGS ANALYSIS
        # ----------------------------------------------------
        if meta_tags:
            generator = meta_tags.get("generator", "")
            if generator:
                if "wordpress" in generator.lower():
                    ver_match = re.search(r"wordpress\s*([\d.]+)", generator, re.IGNORECASE)
                    self._add_detection(
                        "WordPress", "CMS", 98, f"Meta generator: '{generator}'", ver_match.group(1) if ver_match else None
                    )
                    self._add_detection("PHP", "Programming Language", 90, "WordPress CMS indicator")
                elif "drupal" in generator.lower():
                    ver_match = re.search(r"drupal\s*([\d.]+)", generator, re.IGNORECASE)
                    self._add_detection(
                        "Drupal", "CMS", 98, f"Meta generator: '{generator}'", ver_match.group(1) if ver_match else None
                    )
                elif "joomla" in generator.lower():
                    self._add_detection("Joomla", "CMS", 98, f"Meta generator: '{generator}'")

        # ----------------------------------------------------
        # 4. HTML DOM & BODY SIGNATURES
        # ----------------------------------------------------
        if body_lower:
            # WordPress
            if "/wp-content/" in body_lower or "/wp-includes/" in body_lower:
                self._add_detection("WordPress", "CMS", 85, "/wp-content/ asset path in HTML")
                self._add_detection("PHP", "Programming Language", 80, "WordPress asset indicator")

            # React
            if "data-reactroot" in body_lower or "data-reactid" in body_lower or "__react" in body_lower:
                self._add_detection("React", "JavaScript Library", 90, "data-reactroot / React DOM marker")

            # Next.js
            if "__next_data__" in body_lower or "/_next/static/" in body_lower or 'id="__next"' in body_lower or 'id=__next' in body_lower:
                self._add_detection("Next.js", "Web Framework", 95, "__NEXT_DATA__ / __next DOM marker in HTML")
                self._add_detection("React", "JavaScript Library", 90, "Next.js dependency")

            # Vue.js
            if "data-v-" in body_lower or "vue.js" in body_lower:
                self._add_detection("Vue.js", "JavaScript Library", 80, "Vue scoped CSS attribute (data-v-*)")

            # Angular
            if "ng-version=" in body_lower or "ng-app=" in body_lower or "_nghost" in body_lower:
                ver_match = re.search(r'ng-version=["\']([\d.]+)["\']', body, re.IGNORECASE)
                self._add_detection(
                    "Angular", "Web Framework", 95, "ng-version / Angular marker", ver_match.group(1) if ver_match else None
                )

            # Laravel Blade
            if "laravel" in body_lower and ("csrf-token" in body_lower or "blade" in body_lower):
                self._add_detection("Laravel", "Web Framework", 75, "Laravel CSRF / Blade meta signature")

            # Flask / Jinja2
            if "werkzeug" in server.lower() or "flask" in body_lower:
                self._add_detection("Flask", "Web Framework", 75, "Flask / Werkzeug runtime indicator")
                self._add_detection("Python", "Programming Language", 75, "Flask framework indicator")

            # Bootstrap
            if "bootstrap.min.css" in body_lower or "bootstrap.bundle" in body_lower:
                self._add_detection("Bootstrap", "CSS Framework", 85, "Bootstrap stylesheet / bundle reference")

            # Tailwind CSS
            if "tailwind" in body_lower:
                self._add_detection("Tailwind CSS", "CSS Framework", 70, "Tailwind CSS reference")

        # ----------------------------------------------------
        # 5. SCRIPTS ANALYSIS
        # ----------------------------------------------------
        if scripts:
            for s_url in scripts:
                s_lower = s_url.lower()
                if "jquery" in s_lower:
                    ver_match = re.search(r"jquery[.-]([\d.]+)", s_lower)
                    self._add_detection(
                        "jQuery", "JavaScript Library", 90, f"Script URL: '{s_url}'", ver_match.group(1) if ver_match else None
                    )
                elif "react" in s_lower:
                    self._add_detection("React", "JavaScript Library", 80, f"Script URL: '{s_url}'")
                elif "vue" in s_lower:
                    self._add_detection("Vue.js", "JavaScript Library", 80, f"Script URL: '{s_url}'")
                elif "axios" in s_lower:
                    self._add_detection("Axios", "JavaScript Library", 85, f"Script URL: '{s_url}'")
                elif "lodash" in s_lower or "underscore" in s_lower:
                    self._add_detection("Lodash/Underscore", "JavaScript Library", 80, f"Script URL: '{s_url}'")

        return list(self._detections.values())

    def get_detected(self) -> List[TechnologyDetection]:
        """Return all unique detected technologies sorted by confidence descending."""
        return sorted(self._detections.values(), key=lambda t: t.confidence, reverse=True)
