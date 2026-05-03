"""Target focus mode enforcement."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except Exception:  # pragma: no cover
    yaml = None


def load_focus(path: str) -> dict:
    default = {
        "enabled": False,
        "target": "",
        "days": 56,
        "mode": "single",
        "rotate_targets": [],
        "rotate_start": "",
    }
    if not yaml:
        return default
    try:
        with open(path, "r") as f:
            data = yaml.safe_load(f) or {}
            return {**default, **data}
    except Exception:
        return default


def require_focus_target(focus: dict, target: str) -> None:
    if not focus.get("enabled"):
        return
    focus_target = resolve_focus_target(focus)
    if not focus_target:
        raise ValueError("Focus mode enabled but no target set in configs/focus.yaml")
    if target.strip().lower() != focus_target:
        raise ValueError(f"Focus mode enabled. Only target '{focus_target}' is allowed.")


def resolve_focus_target(focus: dict) -> str:
    if not focus.get("enabled"):
        return ""
    mode = (focus.get("mode") or "single").strip().lower()
    if mode == "rotate":
        targets = [t.strip().lower() for t in focus.get("rotate_targets", []) if t.strip()]
        if not targets:
            return (focus.get("target") or "").strip().lower()
        days = int(focus.get("days") or 56)
        start = (focus.get("rotate_start") or "").strip()
        if not start:
            return targets[0]
        try:
            start_dt = datetime.fromisoformat(start.replace("Z", "+00:00"))
        except Exception:
            return targets[0]
        now = datetime.now(timezone.utc)
        delta_days = max(0, (now - start_dt).days)
        idx = (delta_days // max(days, 1)) % len(targets)
        return targets[idx]
    return (focus.get("target") or "").strip().lower()
