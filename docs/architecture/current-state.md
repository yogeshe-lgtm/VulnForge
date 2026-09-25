# VulnForge — Architecture Audit & Current State Map

**Date**: September 2026  
**Status**: Verified Working (111/111 unit & integration tests passing)  
**Version**: 0.1.0  

---

## 1. Executive Summary

VulnForge is an asynchronous, modular web security assessment CLI tool designed for authorized penetration testing, bug-bounty asset mapping, and security verification. It is built on Python 3.12+, Typer, Rich, HTTPX, Pydantic, and SQLite.

---

## 2. Component Inventory & Responsibility Map

| Module / Package | Primary Responsibility | Key Files | Key Classes / Functions | Status & Notes |
| :--- | :--- | :--- | :--- | :--- |
| **CLI Presentation** | Terminal UI, progress spinners, banners, formatted tables, command routing. | `vulnforge/cli/main.py`<br>`vulnforge/cli/commands.py`<br>`vulnforge/cli/banners.py`<br>`vulnforge/cli/themes.py` | `app` (Typer), `execute_scan()`, `execute_surface()`, `execute_crawl()`, `execute_recon()`, `render_banner()` | **Complete & Verified.** Supports 10 commands (`scan`, `surface`, `recon`, `crawl`, `scanners`, `history`, `show`, `diff`, `config`, `version`). |
| **Core HTTP Engine & Scope** | Async HTTP client, token-bucket rate limiting, concurrency bounding, strict scope enforcement. | `vulnforge/core/engine.py`<br>`vulnforge/core/scope.py`<br>`vulnforge/core/rate_limiter.py`<br>`vulnforge/core/context.py`<br>`vulnforge/core/config.py` | `HttpEngine`, `ScopeEngine`, `RateLimiter`, `ScanContext`, `VulnForgeConfig` | **Complete & Hardened.** Enforces exact domain, wildcard subdomains (`*.domain.com`), and excluded paths across redirects. |
| **Discovery & Crawler** | Async breadth-first crawler, HTML link extraction, form parsing, robots.txt & sitemaps, JS regex extraction, technology fingerprinting. | `vulnforge/crawler/crawler.py`<br>`vulnforge/crawler/forms.py`<br>`vulnforge/crawler/sitemap.py`<br>`vulnforge/discovery/javascript.py`<br>`vulnforge/discovery/technologies.py` | `WebCrawler`, `parse_robots_txt()`, `parse_sitemap_xml()`, `extract_endpoints_from_js()`, `TechnologyFingerprinter` | **Complete.** Extracts endpoints, parameters, and technologies with confidence metrics. |
| **Attack Surface Intelligence** | Heuristic parameter & endpoint classification, explainable 0–100 risk prioritization, AttackSurface model aggregation. | `vulnforge/intelligence/models.py`<br>`vulnforge/intelligence/parameters.py`<br>`vulnforge/intelligence/endpoints.py`<br>`vulnforge/intelligence/prioritizer.py`<br>`vulnforge/intelligence/surface.py` | `ParameterClassifier`, `EndpointClassifier`, `EndpointPrioritizer`, `AttackSurfaceBuilder`, `AttackSurface` | **Complete.** Classifies 14 parameter categories and 11 endpoint roles with explainable priority tiers. |
| **Scanner Engine & Registry** | Modular vulnerability scanner plugin framework, safe canary probing, telemetry observations. | `vulnforge/scanners/base.py`<br>`vulnforge/scanners/registry.py`<br>`vulnforge/scanners/engine.py`<br>`vulnforge/scanners/result.py`<br>10 Scanner modules (`xss`, `sqli`, `cors`, etc.) | `BaseScanner`, `ScannerRegistry`, `ScannerEngine`, `Observation`, `Finding`, `XSSScanner`, `SQLiScanner`, etc. | **Complete.** Safe, non-destructive scanners executing in priority order. |
| **Correlation, Confidence & Severity** | Multi-signal observation correlation, finding deduplication, signal-based confidence scoring, contextual severity calculation. | `vulnforge/correlation/engine.py`<br>`vulnforge/correlation/deduplicator.py`<br>`vulnforge/correlation/confidence.py`<br>`vulnforge/correlation/severity.py` | `CorrelationEngine`, `FindingDeduplicator`, `ConfidenceEngine`, `SeverityEngine` | **Complete.** Multi-signal confidence bands (0–39, 40–69, 70–89, 90–100) and severity modulation. |
| **Storage & Persistence** | Local SQLite storage for scans, targets, statistics, HTTP logs, discovered endpoints, parameters, observations, and findings. | `vulnforge/storage/database.py` | `DatabaseManager` | **Complete & Migrated.** Thread-safe SQLite manager with foreign key cascades and automatic schema migration. |
| **Reporting** | Standalone zero-dependency HTML dashboard, structured JSON, and GitHub-flavored Markdown reports. | `vulnforge/reporting/html_report.py`<br>`vulnforge/reporting/json_report.py`<br>`vulnforge/reporting/markdown_report.py` | `generate_html_report()`, `generate_json_report()`, `generate_markdown_report()` | **Complete.** Formatted with executive summary, findings, evidence, tech stack, and remediation guidance. |
| **Utilities & Hardening** | URL normalization, domain validation, sensitive credential & secret scrubbing. | `vulnforge/utils/normalization.py`<br>`vulnforge/utils/validators.py`<br>`vulnforge/utils/redaction.py` | `normalize_url()`, `redact_secrets()`, `redact_dict_secrets()`, `validate_url()` | **Complete.** Protects against secret leakage in logs, reports, and database records. |

---

## 3. Existing CLI Command Map

```text
vulnforge
├── scan <url>         # Full end-to-end security assessment scan
├── surface <url>      # Attack Surface Intelligence & classification summary
├── recon <url>        # Passive reconnaissance (robots.txt, sitemaps, tech)
├── crawl <url>        # Web crawling, form extraction, JS endpoint parsing
├── scanners           # List registered security scanner modules
├── history            # View past scan sessions and finding metrics
├── show [scan_id]     # Detailed findings, evidence, and remediation inspector
├── diff <id1> <id2>   # Compare scan sessions (NEW/RESOLVED/UNCHANGED)
├── config             # Configuration management (show, init, path)
└── version            # Version and licensing notice
```

---

## 4. Current Test Suite Status

* **Total Tests**: 111 passing in 2.48s
* **Test Modules**:
  * `tests/test_attack_surface_intelligence.py` (25 tests)
  * `tests/test_config.py` (2 tests)
  * `tests/test_correlation_and_reporting.py` (14 tests)
  * `tests/test_crawler.py` (2 tests)
  * `tests/test_database.py` (3 tests)
  * `tests/test_forms.py` (3 tests)
  * `tests/test_http.py` (5 tests)
  * `tests/test_javascript_discovery.py` (2 tests)
  * `tests/test_normalization.py` (6 tests)
  * `tests/test_phase5_hardening.py` (18 tests)
  * `tests/test_rate_limiter.py` (2 tests)
  * `tests/test_scanners.py` (12 tests)
  * `tests/test_scope.py` (6 tests)
  * `tests/test_sitemap.py` (2 tests)
  * `tests/test_technologies.py` (3 tests)
  * `tests/test_validators.py` (6 tests)

---

## 5. Upgrade Gaps & Next Development Stages

To evolve VulnForge into a complete security assessment platform (Phases 1–37), the following capabilities will be sequentially implemented:

1. **Attack Surface Graph (Phase 2)**: Graph model relating Target &rarr; Hosts &rarr; Endpoints &rarr; Parameters &rarr; Technologies &rarr; APIs &rarr; Findings. (`vulnforge graph`)
2. **Finding Lifecycle & State Transitions (Phase 5)**: `OBSERVED`, `POTENTIAL`, `PROBABLE`, `CONFIRMED`, `FALSE_POSITIVE`, `RESOLVED`, `REOPENED`.
3. **Structured Evidence Engine (Phase 6)**: `Evidence`, `EvidenceType`, `EvidenceCollection` with redacted request/response context.
4. **Security Regression Engine (Phase 7)**: `vulnforge regression <baseline> <current>` tracking regressions and resolution verification.
5. **API & OpenAPI/Swagger Security Engine (Phase 8)**: Dedicated schema parser (`swagger.json`/`openapi.yaml`), undocumented endpoint detection, and `vulnforge api <target>`.
6. **GraphQL Security Analysis (Phase 9)**: Introspection analysis, query complexity, mutation audits (`vulnforge graphql <target>`).
7. **Authenticated Testing & Multi-Role Authorization (Phases 10 & 11)**: Role profiles (`anonymous`, `user`, `admin`), BOLA/IDOR matrix validation.
8. **JWT & Token Analysis (Phase 14)**: Structure, algorithm, expiration, claim exposure (`vulnforge token <target>`).
9. **WebSocket Analysis (Phase 15)**: Handshake, origin, message schemas (`vulnforge websocket <target>`).
10. **Controlled OAST/Callback Engine (Phase 16)**: Pluggable out-of-band canary token generator for blind verification.
11. **Controlled Fuzzing & Wordlists (Phase 17)**: Rate-limited wordlist fuzzing (`vulnforge fuzz <target>`).
12. **CI/CD Integration & SARIF 2.x Output (Phases 19 & 20)**: `vulnforge ci <target>` with configurable exit code thresholds and standard SARIF export.
