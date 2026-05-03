#!/usr/bin/env python3
"""Cron-friendly runner that uses focus target settings."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from core.focus import load_focus, resolve_focus_target
from core.config import repo_root


def main() -> int:
    focus = load_focus(str(repo_root() / "configs" / "focus.yaml"))
    target = resolve_focus_target(focus)
    if not target:
        print("No focus target configured.")
        return 1

    cmd = [
        "python3",
        str(repo_root() / "swarm_orchestrator.py"),
        target,
        "--profile",
        "cautious",
        "--run-vuln",
        "--authorized",
        "--openclaw",
        "--schema-repair",
        "--summary-json",
        str(repo_root() / "output" / "openclaw_summary.json"),
        "--artifact-dir",
        str(repo_root() / "output" / "artifacts"),
    ]
    env = os.environ.copy()
    return subprocess.call(cmd, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
