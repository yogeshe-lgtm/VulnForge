"""SQLite Database storage manager for VulnForge."""

import json
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional

from vulnforge.core.config import DEFAULT_DB_FILE
from vulnforge.core.context import ScanContext, ScanStatistics
from vulnforge.core.exceptions import DatabaseError


class DatabaseManager:
    """Manages SQLite storage for scans, targets, statistics, and HTTP history."""

    def __init__(self, db_path: Optional[str] = None):
        """Initialize DatabaseManager.

        Args:
            db_path: Path to the SQLite database file. Defaults to ~/.config/vulnforge/vulnforge.db.
        """
        if db_path is None:
            expanded = Path(DEFAULT_DB_FILE).expanduser().resolve()
            expanded.parent.mkdir(parents=True, exist_ok=True)
            self.db_path = str(expanded)
            self._mem_conn = None
        elif db_path == ":memory:":
            self.db_path = ":memory:"
            self._mem_conn = sqlite3.connect(":memory:")
            self._mem_conn.row_factory = sqlite3.Row
            self._mem_conn.execute("PRAGMA foreign_keys = ON")
        else:
            expanded = Path(db_path).expanduser().resolve()
            expanded.parent.mkdir(parents=True, exist_ok=True)
            self.db_path = str(expanded)
            self._mem_conn = None

        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Create or return a database connection with row factory enabled."""
        if self._mem_conn is not None:
            return self._mem_conn
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            return conn
        except Exception as e:
            raise DatabaseError(f"Failed to connect to SQLite database at '{self.db_path}': {e}")

    def init_db(self) -> None:
        """Create database tables if they do not already exist."""
        schema_sql = """
        -- Core Scan Records
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target_url TEXT NOT NULL,
            profile TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            finished_at TIMESTAMP,
            duration_seconds REAL DEFAULT 0.0,
            config_json TEXT
        );

        -- Target Metadata
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            raw_url TEXT NOT NULL,
            scheme TEXT NOT NULL,
            hostname TEXT NOT NULL,
            port INTEGER NOT NULL,
            normalized_url TEXT NOT NULL,
            scope_rules TEXT,
            is_private INTEGER DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        );

        -- Scan Statistics
        CREATE TABLE IF NOT EXISTS scan_statistics (
            scan_id TEXT PRIMARY KEY,
            requests_sent INTEGER DEFAULT 0,
            requests_successful INTEGER DEFAULT 0,
            requests_failed INTEGER DEFAULT 0,
            requests_blocked INTEGER DEFAULT 0,
            http_errors INTEGER DEFAULT 0,
            timeouts INTEGER DEFAULT 0,
            redirects INTEGER DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        );

        -- HTTP Request Logs
        CREATE TABLE IF NOT EXISTS http_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            status_code INTEGER,
            elapsed_ms REAL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_blocked INTEGER DEFAULT 0,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        );

        -- Extensibility Schema for Future Phases (Phase 2+)
        CREATE TABLE IF NOT EXISTS endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            status_code INTEGER,
            content_type TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS parameters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            endpoint_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            location TEXT NOT NULL,
            sample_value TEXT,
            FOREIGN KEY (endpoint_id) REFERENCES endpoints (id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS observations (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            scanner TEXT NOT NULL,
            endpoint_url TEXT NOT NULL,
            parameter_name TEXT,
            observation_type TEXT NOT NULL,
            description TEXT NOT NULL,
            evidence TEXT,
            confidence INTEGER DEFAULT 50,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            scan_id TEXT NOT NULL,
            scanner TEXT NOT NULL,
            category TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence INTEGER DEFAULT 50,
            status TEXT NOT NULL,
            endpoint_url TEXT NOT NULL,
            parameter_name TEXT,
            description TEXT,
            evidence TEXT,
            recommendation TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
        );
        """
        with self._get_connection() as conn:
            conn.executescript(schema_sql)
            # Schema migrations for existing databases
            # 1. Findings table
            cursor = conn.execute("PRAGMA table_info(findings)")
            findings_rows = cursor.fetchall()
            findings_types = {row["name"].lower(): row["type"].upper() for row in findings_rows}
            existing_findings_cols = set(findings_types.keys())
            
            if findings_types.get("id") == "INTEGER":
                conn.execute("DROP TABLE IF EXISTS findings")
                conn.execute("""
                    CREATE TABLE findings (
                        id TEXT PRIMARY KEY,
                        scan_id TEXT NOT NULL,
                        scanner TEXT NOT NULL,
                        category TEXT NOT NULL,
                        title TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        confidence INTEGER DEFAULT 50,
                        status TEXT NOT NULL,
                        endpoint_url TEXT NOT NULL,
                        parameter_name TEXT,
                        description TEXT,
                        evidence TEXT,
                        recommendation TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
                    )
                """)
            else:
                for col_name, col_def in [
                    ("title", "TEXT DEFAULT 'Finding'"),
                    ("severity", "TEXT DEFAULT 'INFO'"),
                    ("endpoint_url", "TEXT DEFAULT ''"),
                    ("description", "TEXT"),
                    ("evidence", "TEXT"),
                    ("scanner", "TEXT DEFAULT 'scanner'"),
                    ("category", "TEXT DEFAULT 'General'"),
                    ("parameter_name", "TEXT"),
                    ("confidence", "INTEGER DEFAULT 50"),
                    ("status", "TEXT DEFAULT 'POTENTIAL'"),
                    ("recommendation", "TEXT"),
                ]:
                    if col_name not in existing_findings_cols:
                        conn.execute(f"ALTER TABLE findings ADD COLUMN {col_name} {col_def}")

            # 2. Observations table
            cursor = conn.execute("PRAGMA table_info(observations)")
            obs_rows = cursor.fetchall()
            obs_types = {row["name"].lower(): row["type"].upper() for row in obs_rows}
            if obs_types.get("id") == "INTEGER":
                conn.execute("DROP TABLE IF EXISTS observations")
                conn.execute("""
                    CREATE TABLE observations (
                        id TEXT PRIMARY KEY,
                        scan_id TEXT NOT NULL,
                        scanner TEXT NOT NULL,
                        endpoint_url TEXT NOT NULL,
                        parameter_name TEXT,
                        observation_type TEXT NOT NULL,
                        description TEXT NOT NULL,
                        evidence TEXT,
                        confidence INTEGER DEFAULT 50,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
                    )
                """)

            # 3. Endpoints table migrations
            cursor = conn.execute("PRAGMA table_info(endpoints)")
            endpoint_cols = {row["name"].lower() for row in cursor.fetchall()}
            if "classifications" not in endpoint_cols:
                conn.execute("ALTER TABLE endpoints ADD COLUMN classifications TEXT DEFAULT '[]'")
            if "priority_score" not in endpoint_cols:
                conn.execute("ALTER TABLE endpoints ADD COLUMN priority_score INTEGER DEFAULT 50")
            if "priority_level" not in endpoint_cols:
                conn.execute("ALTER TABLE endpoints ADD COLUMN priority_level TEXT DEFAULT 'MEDIUM'")
            if "priority_reasons" not in endpoint_cols:
                conn.execute("ALTER TABLE endpoints ADD COLUMN priority_reasons TEXT DEFAULT '[]'")

            # 4. Parameters table migrations
            cursor = conn.execute("PRAGMA table_info(parameters)")
            param_cols = {row["name"].lower() for row in cursor.fetchall()}
            if "classification" not in param_cols:
                conn.execute("ALTER TABLE parameters ADD COLUMN classification TEXT DEFAULT 'UNKNOWN'")
            if "confidence" not in param_cols:
                conn.execute("ALTER TABLE parameters ADD COLUMN confidence INTEGER DEFAULT 50")

    def save_scan(self, context: ScanContext, status: str = "running") -> None:
        """Insert a new scan and target record into the database."""
        with self._get_connection() as conn:
            config_json = json.dumps(context.config.to_dict())
            scope_json = json.dumps(context.target.scope)

            conn.execute(
                """
                INSERT OR REPLACE INTO scans (id, target_url, profile, status, config_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    context.scan_id,
                    context.target.raw_url,
                    context.target.scan_profile,
                    status,
                    config_json,
                ),
            )

            conn.execute(
                """
                INSERT INTO targets (scan_id, raw_url, scheme, hostname, port, normalized_url, scope_rules, is_private)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    context.scan_id,
                    context.target.raw_url,
                    context.target.scheme,
                    context.target.hostname,
                    context.target.port,
                    context.target.normalized_url,
                    scope_json,
                    1 if context.target.is_private else 0,
                ),
            )

            # Insert initial stats
            conn.execute(
                """
                INSERT OR REPLACE INTO scan_statistics (
                    scan_id, requests_sent, requests_successful, requests_failed,
                    requests_blocked, http_errors, timeouts, redirects
                )
                VALUES (?, 0, 0, 0, 0, 0, 0, 0)
                """,
                (context.scan_id,),
            )

    def update_scan_status(
        self,
        scan_id: str,
        status: str,
        stats: Optional[ScanStatistics] = None,
    ) -> None:
        """Update scan completion status, duration, and statistics."""
        with self._get_connection() as conn:
            duration = stats.duration_seconds if stats else 0.0
            conn.execute(
                """
                UPDATE scans
                SET status = ?, finished_at = CURRENT_TIMESTAMP, duration_seconds = ?
                WHERE id = ?
                """,
                (status, duration, scan_id),
            )

            if stats:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO scan_statistics (
                        scan_id, requests_sent, requests_successful, requests_failed,
                        requests_blocked, http_errors, timeouts, redirects
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        stats.requests_sent,
                        stats.requests_successful,
                        stats.requests_failed,
                        stats.requests_blocked,
                        stats.http_errors,
                        stats.timeouts,
                        stats.redirects,
                    ),
                )

    def log_http_request(
        self,
        scan_id: str,
        method: str,
        url: str,
        status_code: Optional[int] = None,
        elapsed_ms: float = 0.0,
        is_blocked: bool = False,
    ) -> None:
        """Record an individual HTTP request log."""
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO http_logs (scan_id, method, url, status_code, elapsed_ms, is_blocked)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (scan_id, method.upper(), url, status_code, elapsed_ms, 1 if is_blocked else 0),
            )

    def list_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List recent scans with statistics and findings count."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT
                    s.id, s.target_url, s.profile, s.status, s.created_at, s.finished_at, s.duration_seconds,
                    st.requests_sent, st.requests_successful, st.requests_failed, st.requests_blocked,
                    COUNT(f.id) AS findings_count,
                    COALESCE(SUM(CASE WHEN UPPER(f.severity) = 'CRITICAL' THEN 1 ELSE 0 END), 0) AS critical_count,
                    COALESCE(SUM(CASE WHEN UPPER(f.severity) = 'HIGH' THEN 1 ELSE 0 END), 0) AS high_count,
                    COALESCE(SUM(CASE WHEN UPPER(f.severity) = 'MEDIUM' THEN 1 ELSE 0 END), 0) AS medium_count,
                    COALESCE(SUM(CASE WHEN UPPER(f.severity) = 'LOW' THEN 1 ELSE 0 END), 0) AS low_count,
                    COALESCE(SUM(CASE WHEN UPPER(f.severity) = 'INFO' THEN 1 ELSE 0 END), 0) AS info_count
                FROM scans s
                LEFT JOIN scan_statistics st ON s.id = st.scan_id
                LEFT JOIN findings f ON s.id = f.scan_id
                GROUP BY s.id
                ORDER BY s.created_at DESC
                LIMIT ?
                """,
                (limit,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve full details of a specific scan by ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT
                    s.id, s.target_url, s.profile, s.status, s.created_at, s.finished_at, s.duration_seconds, s.config_json,
                    st.requests_sent, st.requests_successful, st.requests_failed, st.requests_blocked, st.http_errors, st.timeouts, st.redirects
                FROM scans s
                LEFT JOIN scan_statistics st ON s.id = st.scan_id
                WHERE s.id = ?
                """,
                (scan_id,),
            )
            row = cursor.fetchone()
            return dict(row) if row else None

    def get_latest_scan(self) -> Optional[Dict[str, Any]]:
        """Retrieve the most recently recorded scan session."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT
                    s.id, s.target_url, s.profile, s.status, s.created_at, s.finished_at, s.duration_seconds, s.config_json,
                    st.requests_sent, st.requests_successful, st.requests_failed, st.requests_blocked, st.http_errors, st.timeouts, st.redirects
                FROM scans s
                LEFT JOIN scan_statistics st ON s.id = st.scan_id
                ORDER BY s.created_at DESC
                LIMIT 1
                """
            )
            row = cursor.fetchone()
            return dict(row) if row else None


    def save_endpoints(self, scan_id: str, endpoints: List[Any]) -> None:
        """Persist discovered endpoints and associated parameters into database."""
        with self._get_connection() as conn:
            for ep in endpoints:
                classifications_json = json.dumps(getattr(ep, "classifications", []))
                priority_reasons_json = json.dumps(getattr(ep, "priority_reasons", []))
                cursor = conn.execute(
                    """
                    INSERT INTO endpoints (
                        scan_id, method, path, status_code, content_type,
                        classifications, priority_score, priority_level, priority_reasons
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        ep.method,
                        ep.url,
                        ep.status_code,
                        ep.content_type,
                        classifications_json,
                        getattr(ep, "priority_score", 50),
                        getattr(ep, "priority_level", "MEDIUM"),
                        priority_reasons_json,
                    ),
                )
                endpoint_id = cursor.lastrowid

                # Save associated parameters
                for param in ep.parameters:
                    conn.execute(
                        """
                        INSERT INTO parameters (
                            endpoint_id, name, location, sample_value, classification, confidence
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (
                            endpoint_id,
                            param.name,
                            param.location.value if hasattr(param.location, "value") else str(param.location),
                            param.sample_value,
                            getattr(param, "classification", "UNKNOWN"),
                            getattr(param, "classification_confidence", 50),
                        ),
                    )

    def get_endpoints(self, scan_id: str) -> List[Dict[str, Any]]:
        """Retrieve all endpoints and parameters recorded for a scan session."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, scan_id, method, path, status_code, content_type,
                       classifications, priority_score, priority_level, priority_reasons, created_at
                FROM endpoints
                WHERE scan_id = ?
                """,
                (scan_id,),
            )
            endpoints = []
            for row in cursor.fetchall():
                ep_dict = dict(row)
                try:
                    ep_dict["classifications"] = json.loads(ep_dict.get("classifications") or "[]")
                except Exception:
                    ep_dict["classifications"] = []
                try:
                    ep_dict["priority_reasons"] = json.loads(ep_dict.get("priority_reasons") or "[]")
                except Exception:
                    ep_dict["priority_reasons"] = []
                endpoints.append(ep_dict)

            for ep in endpoints:
                p_cursor = conn.execute(
                    """
                    SELECT name, location, sample_value, classification, confidence
                    FROM parameters
                    WHERE endpoint_id = ?
                    """,
                    (ep["id"],),
                )
                ep["parameters"] = [dict(p) for p in p_cursor.fetchall()]
            return endpoints

    def save_observations(self, scan_id: str, observations: List[Any]) -> None:
        """Persist telemetry observations into database."""
        with self._get_connection() as conn:
            for obs in observations:
                obs_type = obs.observation_type.value if hasattr(obs.observation_type, "value") else str(obs.observation_type)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO observations (
                        id, scan_id, scanner, endpoint_url, parameter_name,
                        observation_type, description, evidence, confidence
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        obs.id,
                        scan_id,
                        obs.scanner,
                        obs.endpoint_url,
                        obs.parameter_name,
                        obs_type,
                        obs.description,
                        obs.evidence,
                        obs.confidence,
                    ),
                )

    def save_findings(self, scan_id: str, findings: List[Any]) -> None:
        """Persist security assessment findings into database."""
        with self._get_connection() as conn:
            for f in findings:
                severity = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
                status = f.status.value if hasattr(f.status, "value") else str(f.status)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO findings (
                        id, scan_id, scanner, category, title, severity,
                        confidence, status, endpoint_url, parameter_name,
                        description, evidence, recommendation
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f.id,
                        scan_id,
                        f.scanner,
                        f.category,
                        f.title,
                        severity,
                        f.confidence,
                        status,
                        f.endpoint_url,
                        f.parameter_name,
                        f.description,
                        f.evidence,
                        f.recommendation,
                    ),
                )

    def get_observations(self, scan_id: str) -> List[Dict[str, Any]]:
        """Retrieve all observations recorded for a scan session."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, scan_id, scanner, endpoint_url, parameter_name,
                       observation_type, description, evidence, confidence, created_at
                FROM observations
                WHERE scan_id = ?
                ORDER BY created_at ASC
                """,
                (scan_id,),
            )
            return [dict(row) for row in cursor.fetchall()]

    def get_findings(self, scan_id: str) -> List[Dict[str, Any]]:
        """Retrieve all findings recorded for a scan session."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                SELECT id, scan_id, scanner, category, title, severity,
                       confidence, status, endpoint_url, parameter_name,
                       description, evidence, recommendation, created_at
                FROM findings
                WHERE scan_id = ?
                ORDER BY created_at ASC
                """,
                (scan_id,),
            )
            return [dict(row) for row in cursor.fetchall()]
