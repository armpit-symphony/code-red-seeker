#!/usr/bin/env python3
"""Code Red Seeker developer entrypoint.

This wrapper gives the merged R&D repo one root command while the older
engines are being refactored into a shared package.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SWARM_CLI = ROOT / "engines" / "swarm-review" / "swarm_review_cli.py"
PATH_FLAGS = {"--repo", "--diff", "--out", "--summary-json", "--artifact-dir", "--auth", "--scope"}


def run_swarm(args: list[str]) -> int:
    if not SWARM_CLI.exists():
        print(f"Missing SwarmReview engine CLI: {SWARM_CLI}", file=sys.stderr)
        return 2
    return subprocess.call([sys.executable, str(SWARM_CLI), *normalize_path_args(args)], cwd=str(SWARM_CLI.parent))


def normalize_path_args(args: list[str]) -> list[str]:
    normalized: list[str] = []
    pending_path = False
    for arg in args:
        if pending_path:
            normalized.append(resolve_root_path(arg))
            pending_path = False
            continue
        normalized.append(arg)
        if arg in PATH_FLAGS:
            pending_path = True
    return normalized


def resolve_root_path(value: str) -> str:
    path = Path(value).expanduser()
    if path.is_absolute():
        return str(path)
    return str((ROOT / path).resolve())


def platform_info() -> int:
    print("Code Red Seeker platform lives in ./platform")
    print("Backend:  ./platform/backend")
    print("Frontend: ./platform/frontend")
    print("Docker:   ./platform/docker-compose.yml")
    print("")
    print("Next integration step: wire platform scanner jobs to engines/swarm-review.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="code-red-seeker",
        description="Unified R&D entrypoint for Code Red Seeker.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    review = sub.add_parser("review", help="Run code review against a repo, diff, or PR.")

    scan = sub.add_parser("scan", help="Run governed web/security scan workflow.")

    doctor = sub.add_parser("doctor", help="Run scanner preflight checks.")

    sub.add_parser("platform", help="Show platform location and next steps.")
    return parser


def main() -> int:
    args, engine_args = build_parser().parse_known_args()
    if args.command == "review":
        return run_swarm(["review", *engine_args])
    if args.command == "scan":
        return run_swarm(["scan", *engine_args])
    if args.command == "doctor":
        return run_swarm(["doctor", *engine_args])
    if args.command == "platform":
        return platform_info()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
