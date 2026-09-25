"""Burp Suite and OWASP ZAP Proxy Integration (HAR Archive Import and Export)."""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from vulnforge import __version__
from vulnforge.models.endpoint import Endpoint
from vulnforge.scanners.result import Finding


class ProxyAdapter:
    """Provides bidirectional interoperability between VulnForge and interception proxies (Burp/ZAP)."""

    @staticmethod
    def import_har_endpoints(har_content: str) -> List[Endpoint]:
        """Parse an HTTP Archive (HAR) file and extract discovered endpoints and parameters."""
        data = json.loads(har_content)
        log = data.get("log", {})
        entries = log.get("entries", [])
        endpoints: List[Endpoint] = []
        seen_keys = set()

        for entry in entries:
            req = entry.get("request", {})
            url = req.get("url", "")
            method = req.get("method", "GET").upper()
            status = entry.get("response", {}).get("status", 200)

            if not url:
                continue

            dedup_key = f"{method}:{url}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            try:
                ep = Endpoint.from_url(url=url, method=method, source="proxy_har")
                ep.status_code = status
                endpoints.append(ep)
            except Exception:
                pass

        return endpoints

    @staticmethod
    def export_har(
        endpoints: List[Endpoint],
        creator_name: str = "VulnForge",
    ) -> Dict[str, Any]:
        """Export discovered endpoints into standard HAR 1.2 format for import into Burp / ZAP."""
        entries: List[Dict[str, Any]] = []

        for ep in endpoints:
            entry = {
                "startedDateTime": datetime.now(timezone.utc).isoformat(),
                "time": 50,
                "request": {
                    "method": ep.method,
                    "url": ep.url,
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [],
                    "queryString": [{"name": p.name, "value": getattr(p, "sample_value", "") or ""} for p in ep.parameters],
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "response": {
                    "status": ep.status_code or 200,
                    "statusText": "OK",
                    "httpVersion": "HTTP/1.1",
                    "cookies": [],
                    "headers": [],
                    "content": {"size": 0, "mimeType": "text/html"},
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": -1,
                },
                "cache": {},
                "timings": {"send": 10, "wait": 30, "receive": 10},
            }
            entries.append(entry)

        return {
            "log": {
                "version": "1.2",
                "creator": {"name": creator_name, "version": __version__},
                "entries": entries,
            }
        }
