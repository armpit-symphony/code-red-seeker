#!/usr/bin/env python3
"""Set focus target rotation schedule."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone

import yaml


def main() -> int:
    parser = argparse.ArgumentParser(description="Configure focus rotation")
    parser.add_argument("--targets", required=True, help="Comma-separated targets")
    parser.add_argument("--days", type=int, default=56, help="Days per target")
    parser.add_argument("--enable", action="store_true", help="Enable focus mode")
    parser.add_argument("--config", default="configs/focus.yaml")
    args = parser.parse_args()

    targets = [t.strip() for t in args.targets.split(",") if t.strip()]
    if not targets:
        print("No targets provided.")
        return 1

    data = {
        "enabled": bool(args.enable),
        "target": targets[0],
        "days": args.days,
        "mode": "rotate",
        "rotate_targets": targets,
        "rotate_start": datetime.now(timezone.utc).isoformat(),
    }
    with open(args.config, "w") as f:
        yaml.safe_dump(data, f, sort_keys=False)
    print(args.config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
