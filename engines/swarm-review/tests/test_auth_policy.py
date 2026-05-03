"""Tests for core/auth_policy.py — authorization gate enforcement."""

import os
import sys
import textwrap
import pytest
from pathlib import Path

# Ensure repo root is importable
REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from core.auth_policy import (
    load_policy,
    validate_policy_schema,
    require_auth_policy,
    log_authz_event,
    default_policy_path,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write(tmp_path, content: str, name: str = "policy.yml") -> str:
    p = tmp_path / name
    p.write_text(textwrap.dedent(content))
    return str(p)


VALID_POLICY = """
    version: "1"
    allow:
      targets:
        - example.com
      actions:
        - recon
        - crawl
"""


# ---------------------------------------------------------------------------
# Test: missing policy file → exits nonzero
# ---------------------------------------------------------------------------

def test_missing_policy_exits(tmp_path):
    missing = str(tmp_path / "nonexistent_policy.yml")
    with pytest.raises(SystemExit) as exc_info:
        load_policy(missing)
    assert exc_info.value.code != 0


# ---------------------------------------------------------------------------
# Test: invalid YAML → exits nonzero
# ---------------------------------------------------------------------------

def test_invalid_yaml_exits(tmp_path):
    path = _write(tmp_path, "version: [\nbroken yaml:::{{")
    with pytest.raises(SystemExit) as exc_info:
        load_policy(path)
    assert exc_info.value.code != 0


# ---------------------------------------------------------------------------
# Test: invalid schema (missing allow block) → exits nonzero
# ---------------------------------------------------------------------------

def test_invalid_schema_exits(tmp_path):
    path = _write(tmp_path, "version: '1'\n# missing allow block\n")
    with pytest.raises(SystemExit) as exc_info:
        load_policy(path)
    assert exc_info.value.code != 0


def test_empty_targets_exits(tmp_path):
    content = """
        version: "1"
        allow:
          targets: []
          actions:
            - recon
    """
    path = _write(tmp_path, content)
    with pytest.raises(SystemExit) as exc_info:
        load_policy(path)
    assert exc_info.value.code != 0


def test_empty_actions_exits(tmp_path):
    content = """
        version: "1"
        allow:
          targets:
            - example.com
          actions: []
    """
    path = _write(tmp_path, content)
    with pytest.raises(SystemExit) as exc_info:
        load_policy(path)
    assert exc_info.value.code != 0


# ---------------------------------------------------------------------------
# Test: valid policy → proceeds and logs AUTHZ_ENFORCED
# ---------------------------------------------------------------------------

def test_valid_policy_proceeds_and_logs(tmp_path, capsys):
    path = _write(tmp_path, VALID_POLICY)
    policy = require_auth_policy(path, run_id="test-run-001")

    # Returned policy must be a dict with expected keys
    assert isinstance(policy, dict)
    assert "version" in policy
    assert "allow" in policy

    # AUTHZ_ENFORCED event must appear on stdout
    captured = capsys.readouterr()
    assert "AUTHZ_ENFORCED" in captured.out
    assert "test-run-001" in captured.out
    assert "policy_sha256=" in captured.out


# ---------------------------------------------------------------------------
# Test: validate_policy_schema unit tests
# ---------------------------------------------------------------------------

def test_schema_valid_minimal():
    data = {"version": "1", "allow": {"targets": ["x.com"], "actions": ["recon"]}}
    assert validate_policy_schema(data) == []


def test_schema_missing_version():
    data = {"allow": {"targets": ["x.com"], "actions": ["recon"]}}
    errors = validate_policy_schema(data)
    assert any("version" in e for e in errors)


def test_schema_allow_not_dict():
    data = {"version": "1", "allow": ["targets"]}
    errors = validate_policy_schema(data)
    assert any("allow" in e for e in errors)


def test_schema_deny_optional():
    data = {
        "version": "1",
        "allow": {"targets": ["x.com"], "actions": ["recon"]},
        "deny": {"actions": ["exploit"]},
    }
    assert validate_policy_schema(data) == []


def test_schema_deny_must_be_dict():
    data = {
        "version": "1",
        "allow": {"targets": ["x.com"], "actions": ["recon"]},
        "deny": "all",
    }
    errors = validate_policy_schema(data)
    assert any("deny" in e for e in errors)


# ---------------------------------------------------------------------------
# Test: default policy path exists (optional integration check)
# ---------------------------------------------------------------------------

def test_default_policy_path_returns_string():
    path = default_policy_path()
    assert isinstance(path, str)
    assert path.endswith("policy.yml")


def test_default_policy_is_valid_if_present():
    """If the repo ships policy.yml, it must pass schema validation."""
    path = default_policy_path()
    if not os.path.exists(path):
        pytest.skip("policy.yml not present — skipping integration check")
    # Should not raise or exit
    policy = load_policy(path)
    assert isinstance(policy, dict)
