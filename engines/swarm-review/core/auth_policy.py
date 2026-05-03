"""Authorization policy enforcement for bug bounty swarm.

Fail-closed: if policy is missing, invalid, or schema-broken the swarm
refuses to run and exits nonzero.  Every successful load writes an
AUTHZ_ENFORCED audit event to stdout (and optionally a log file).
"""

from __future__ import annotations

import hashlib
import os
import sys
import uuid
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# YAML loader (PyYAML required; pyyaml is already in requirements.txt)
# ---------------------------------------------------------------------------

def _load_yaml(path: str) -> dict:
    """Load YAML from *path* and return a dict.  Raises on any failure."""
    try:
        import yaml  # type: ignore
    except ImportError:
        _die(f"PyYAML not installed.  Run: pip install pyyaml")

    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        _die(f"Auth policy file not found: {path}")
    except Exception as e:
        _die(f"YAML parse error in {path}: {e}")

    if not isinstance(data, dict):
        _die(f"Auth policy must be a YAML mapping, got {type(data).__name__}: {path}")

    return data


# ---------------------------------------------------------------------------
# Schema validation
# ---------------------------------------------------------------------------

_REQUIRED_ALLOW_KEYS = {"targets", "actions"}


def validate_policy_schema(data: dict) -> list[str]:
    """Validate the policy dict against the required schema.

    Returns a (possibly empty) list of error strings.
    Callers should treat any non-empty list as fatal.

    Required structure::

        version: "1"          # str
        allow:
          targets: [...]      # list[str | dict], non-empty
          actions: [...]      # list[str], non-empty
        deny:                 # optional mapping
          ...
    """
    errors: list[str] = []

    # version
    if "version" not in data:
        errors.append("Missing required key: version")
    elif not isinstance(data["version"], (str, int, float)):
        errors.append(f"'version' must be a string, got {type(data['version']).__name__}")

    # allow block
    if "allow" not in data:
        errors.append("Missing required key: allow")
    else:
        allow = data["allow"]
        if not isinstance(allow, dict):
            errors.append(f"'allow' must be a mapping, got {type(allow).__name__}")
        else:
            for key in _REQUIRED_ALLOW_KEYS:
                if key not in allow:
                    errors.append(f"Missing required key under allow: {key}")
                elif not isinstance(allow[key], list):
                    errors.append(f"allow.{key} must be a list, got {type(allow[key]).__name__}")
                elif len(allow[key]) == 0:
                    errors.append(f"allow.{key} must not be empty")

    # deny block (optional)
    if "deny" in data and data["deny"] is not None:
        if not isinstance(data["deny"], dict):
            errors.append(f"'deny' must be a mapping if present, got {type(data['deny']).__name__}")

    return errors


# ---------------------------------------------------------------------------
# Hash helper
# ---------------------------------------------------------------------------

def _policy_sha256(path: str) -> str:
    """Return the SHA-256 hex digest of the raw policy file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def log_authz_event(run_id: str, policy_path: str, policy_sha256: str) -> None:
    """Write AUTHZ_ENFORCED event line to stdout (and LOG_FILE if set)."""
    line = (
        f"AUTHZ_ENFORCED run_id={run_id} "
        f"policy_sha256={policy_sha256} "
        f"policy_path={policy_path}"
    )
    print(line, flush=True)

    log_file = os.environ.get("SWARM_AUTH_LOG")
    if log_file:
        try:
            with open(log_file, "a") as f:
                import datetime
                ts = datetime.datetime.utcnow().isoformat()
                f.write(f"{ts} {line}\n")
        except Exception as e:
            print(f"[auth_policy] WARNING: could not write to SWARM_AUTH_LOG: {e}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def load_policy(path: str) -> dict:
    """Load, parse, and return the validated auth policy dict.

    Calls sys.exit(1) on any failure (fail-closed).
    """
    resolved = str(Path(path).resolve())
    data = _load_yaml(resolved)
    errors = validate_policy_schema(data)
    if errors:
        _die(
            f"Auth policy schema invalid ({resolved}):\n"
            + "\n".join(f"  - {e}" for e in errors)
        )
    return data


def require_auth_policy(
    path: str,
    run_id: str | None = None,
    *,
    warn_deny_all: bool = True,
) -> dict:
    """Load and enforce the auth policy.  Returns validated policy dict.

    * Fails closed on missing/invalid policy.
    * Emits AUTHZ_ENFORCED audit event on success.
    * Optionally warns if policy effectively denies all targets.
    """
    policy = load_policy(path)
    sha = _policy_sha256(path)
    run_id = run_id or str(uuid.uuid4())
    log_authz_event(run_id, path, sha)

    if warn_deny_all:
        targets = (policy.get("allow") or {}).get("targets", [])
        if not targets:
            print(
                "[auth_policy] WARNING: allow.targets is empty — effectively deny-all.",
                file=sys.stderr,
            )

    return policy


def default_policy_path() -> str:
    """Return the default policy.yml path (repo root)."""
    return str(Path(__file__).resolve().parents[1] / "policy.yml")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _die(msg: str) -> None:
    print(f"[auth_policy] FATAL: {msg}", file=sys.stderr)
    sys.exit(1)
