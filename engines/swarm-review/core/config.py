"""Config loader for profiles, budgets, and MCP settings."""

from __future__ import annotations

from pathlib import Path

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None


def _load_yaml(path: str, default: dict) -> dict:
    if not yaml:
        return default
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
            return data
    except Exception:
        return default


def load_profiles(path: str) -> dict:
    default = {
        "profiles": {
            "passive": {"active_tests": False, "max_pages": 10},
            "cautious": {"active_tests": True, "max_pages": 20},
            "active": {"active_tests": True, "max_pages": 50},
        }
    }
    return _load_yaml(path, default)


def load_budget(path: str) -> dict:
    default = {"requests": {"max_per_minute": 120, "max_per_run": 1000}, "evidence_level": "standard"}
    return _load_yaml(path, default)


def load_mcp(path: str) -> dict:
    default = {
        "enabled": True,
        "endpoints": {
            "recon": "",
            "crawl": "",
            "enrichment": "",
            "code": "",
        },
    }
    return _load_yaml(path, default)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]
