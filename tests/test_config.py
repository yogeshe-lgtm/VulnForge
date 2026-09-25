"""Tests for Configuration management."""

from pathlib import Path
import pytest
from vulnforge.core.config import VulnForgeConfig, load_config, save_config


def test_default_config():
    """Verify default configuration attributes."""
    cfg = VulnForgeConfig()
    assert cfg.default_timeout == 10.0
    assert cfg.default_rate == 5.0
    assert cfg.default_threads == 5
    assert cfg.default_profile == "safe"
    assert "VulnForge" in cfg.default_user_agent


def test_save_and_load_config(tmp_path: Path):
    """Verify saving configuration to TOML and reloading it."""
    cfg_file = tmp_path / "test_config.toml"
    cfg = VulnForgeConfig(
        default_timeout=15.0,
        default_rate=8.5,
        default_threads=10,
        default_profile="aggressive",
    )

    save_config(cfg, config_path=cfg_file)
    assert cfg_file.exists()

    loaded = load_config(config_path=cfg_file)
    assert loaded.default_timeout == 15.0
    assert loaded.default_rate == 8.5
    assert loaded.default_threads == 10
    assert loaded.default_profile == "aggressive"
