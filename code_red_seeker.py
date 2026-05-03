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


def run_swarm(args: list[str]) -> int:
    if not SWARM_CLI.exists():
        print(f"Missing SwarmReview engine CLI: {SWARM_CLI}", file=sys.stderr)
        return 2
    return subprocess.call([sys.executable, str(SWARM_CLI), *args], cwd=str(SWARM_CLI.parent))


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
    review.add_argument("args", nargs=argparse.REMAINDER, help="Arguments passed to SwarmReview review.")

    scan = sub.add_parser("scan", help="Run governed web/security scan workflow.")
    scan.add_argument("args", nargs=argparse.REMAINDER, help="Arguments passed to SwarmReview scan.")

    doctor = sub.add_parser("doctor", help="Run scanner preflight checks.")
    doctor.add_argument("args", nargs=argparse.REMAINDER, help="Arguments passed to SwarmReview doctor.")

    sub.add_parser("platform", help="Show platform location and next steps.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "review":
        return run_swarm(["review", *args.args])
    if args.command == "scan":
        return run_swarm(["scan", *args.args])
    if args.command == "doctor":
        return run_swarm(["doctor", *args.args])
    if args.command == "platform":
        return platform_info()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
