"""Configuration management for VulnForge with hierarchical loading and profile support."""

import os
from pathlib import Path
import tomllib
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field
import tomli_w

from vulnforge.core.exceptions import ConfigurationError

DEFAULT_CONFIG_DIR = Path.home() / ".config" / "vulnforge"
DEFAULT_CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.toml"
DEFAULT_DB_FILE = DEFAULT_CONFIG_DIR / "vulnforge.db"

PROJECT_CONFIG_FILENAMES = ["vulnforge.toml", ".vulnforge.toml"]

# Configuration Profiles
PROFILE_PRESETS: Dict[str, Dict[str, Any]] = {
    "passive": {
        "default_rate": 10.0,
        "default_threads": 5,
        "default_timeout": 8.0,
        "crawl_depth": 2,
        "follow_redirects": True,
        "enabled_scanners": ["security-headers", "information-disclosure", "endpoint-inspector"],
    },
    "safe": {
        "default_rate": 5.0,
        "default_threads": 4,
        "default_timeout": 10.0,
        "crawl_depth": 3,
        "follow_redirects": True,
        "enabled_scanners": None,  # All safe/non-destructive verification scanners
    },
    "balanced": {
        "default_rate": 15.0,
        "default_threads": 8,
        "default_timeout": 12.0,
        "crawl_depth": 4,
        "follow_redirects": True,
        "enabled_scanners": None,  # All scanners with deeper crawl
    },
    "custom": {
        # Custom profile adopts user/project config settings directly
    },
}


class VulnForgeConfig(BaseModel):
    """User and project configuration model."""

    default_timeout: float = Field(default=10.0, description="Default HTTP request timeout in seconds")
    default_rate: float = Field(default=5.0, description="Default rate limit (requests per second)")
    default_threads: int = Field(default=5, description="Default concurrency / worker threads")
    default_user_agent: str = Field(
        default="VulnForge/0.1.0 (Web Security Assessment Engine; Authorized Testing)",
        description="Default HTTP User-Agent header",
    )
    default_profile: str = Field(default="safe", description="Default scan profile (passive, safe, balanced, custom)")
    crawl_depth: int = Field(default=3, description="Default crawling depth")
    follow_redirects: bool = Field(default=True, description="Whether to follow in-scope redirects")
    verify_tls: bool = Field(default=True, description="Verify TLS certificates")
    output_directory: str = Field(default="./reports", description="Default directory for reports")
    database_path: str = Field(
        default=str(DEFAULT_DB_FILE), description="Path to SQLite database file"
    )
    enabled_scanners: Optional[List[str]] = Field(
        default=None, description="List of enabled scanner modules (None for all)"
    )
    excluded_scanners: Optional[List[str]] = Field(
        default=None, description="List of excluded scanner modules"
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary excluding None values for TOML serialization."""
        return {k: v for k, v in self.model_dump().items() if v is not None}


def get_user_config_path() -> Path:
    """Return user-level configuration file path."""
    custom_path = os.getenv("VULNFORGE_CONFIG")
    if custom_path:
        return Path(custom_path)
    return DEFAULT_CONFIG_FILE


def get_project_config_path(start_dir: Optional[Path] = None) -> Optional[Path]:
    """Search for a project-level configuration file in the current or parent directories."""
    current = (start_dir or Path.cwd()).resolve()
    for directory in [current, *current.parents]:
        for fname in PROJECT_CONFIG_FILENAMES:
            candidate = directory / fname
            if candidate.is_file():
                return candidate
    return None


def get_default_config_path() -> Path:
    """Return default configuration file path (alias to user config path)."""
    return get_user_config_path()


def ensure_config_dir(config_path: Optional[Path] = None) -> Path:
    """Ensure directory containing the config file exists."""
    path = config_path or get_default_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    return path.parent


def load_config(
    config_path: Optional[Path] = None,
    profile_name: Optional[str] = None,
) -> VulnForgeConfig:
    """Load configuration using hierarchical resolution:

    Priority:
    1. Project config (./vulnforge.toml)
    2. User config (~/.config/vulnforge/config.toml)
    3. Profile presets (passive, safe, balanced, custom)
    4. Defaults
    """
    merged_data: Dict[str, Any] = {}

    # 1. Load User Config if present
    user_path = config_path or get_user_config_path()
    if user_path.is_file():
        try:
            with open(user_path, "rb") as f:
                user_data = tomllib.load(f)
                merged_data.update(user_data)
        except Exception as e:
            raise ConfigurationError(f"Failed to load user configuration from '{user_path}': {e}")

    # 2. Load Project Config if present (overrides user config)
    project_path = get_project_config_path()
    if project_path and project_path.is_file() and project_path.resolve() != user_path.resolve():
        try:
            with open(project_path, "rb") as f:
                proj_data = tomllib.load(f)
                merged_data.update(proj_data)
        except Exception as e:
            raise ConfigurationError(f"Failed to load project configuration from '{project_path}': {e}")

    # 3. Apply profile adjustments if a profile is selected
    active_profile = profile_name or merged_data.get("default_profile", "safe")
    if active_profile in PROFILE_PRESETS and active_profile != "custom":
        preset = PROFILE_PRESETS[active_profile]
        for k, v in preset.items():
            if k not in merged_data or profile_name:
                merged_data[k] = v

    return VulnForgeConfig(**merged_data)


def save_config(config: VulnForgeConfig, config_path: Optional[Path] = None) -> Path:
    """Save configuration to TOML file."""
    path = config_path or get_default_config_path()
    try:
        ensure_config_dir(path)
        with open(path, "wb") as f:
            tomli_w.dump(config.to_dict(), f)
        return path
    except Exception as e:
        raise ConfigurationError(f"Failed to save configuration to '{path}': {e}")
