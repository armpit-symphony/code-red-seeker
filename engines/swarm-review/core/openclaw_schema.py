"""OpenClaw schema validation helper."""

from __future__ import annotations

import json
from pathlib import Path


def load_schema(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)


def validate(summary: dict, schema: dict) -> list[str]:
    errors = []
    for field, ftype in schema.get("fields", {}).items():
        if field not in summary:
            errors.append(f"missing:{field}")
            continue
        if ftype == "string" and not isinstance(summary[field], str):
            errors.append(f"type:{field}")
        if ftype == "array" and not isinstance(summary[field], list):
            errors.append(f"type:{field}")
        if ftype == "object" and not isinstance(summary[field], dict):
            errors.append(f"type:{field}")
    return errors


def repair(summary: dict, schema: dict) -> dict:
    fixed = dict(summary)
    for field, ftype in schema.get("fields", {}).items():
        if field not in fixed:
            fixed[field] = _default_for(ftype)
            continue
        if ftype == "string" and not isinstance(fixed[field], str):
            fixed[field] = str(fixed[field])
        if ftype == "array" and not isinstance(fixed[field], list):
            fixed[field] = []
        if ftype == "object" and not isinstance(fixed[field], dict):
            fixed[field] = {}
    return fixed


def _default_for(ftype: str):
    if ftype == "string":
        return ""
    if ftype == "array":
        return []
    if ftype == "object":
        return {}
    return None
