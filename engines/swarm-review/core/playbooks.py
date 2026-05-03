"""Playbook loader and helpers."""

from __future__ import annotations

from pathlib import Path

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None


def load_playbook(name: str, root: str) -> dict:
    if not yaml:
        return {}
    path = Path(root) / f"{name}.yaml"
    try:
        with open(path, "r") as f:
            return yaml.safe_load(f) or {}
    except Exception:
        return {}


def load_all_playbooks(root: str) -> dict:
    if not yaml:
        return {}
    pb_root = Path(root)
    playbooks = {}
    for p in pb_root.glob("*.yaml"):
        try:
            with open(p, "r") as f:
                playbooks[p.stem.lower()] = yaml.safe_load(f) or {}
        except Exception:
            continue
    return playbooks
