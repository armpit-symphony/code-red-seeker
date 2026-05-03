#!/usr/bin/env python3
"""Package evidence artifacts into a zip file."""

from __future__ import annotations

import argparse
import os
import zipfile
from datetime import datetime


def package(output_dir: str) -> str | None:
    evidence_dir = os.path.join(output_dir, "evidence")
    if not os.path.isdir(evidence_dir):
        return None
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    zip_path = os.path.join(output_dir, f"evidence_bundle_{stamp}.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(evidence_dir):
            for name in files:
                full = os.path.join(root, name)
                rel = os.path.relpath(full, output_dir)
                zf.write(full, rel)
    return zip_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Package evidence into a zip bundle")
    parser.add_argument("--output-dir", default="output", help="Output directory root")
    args = parser.parse_args()

    zip_path = package(args.output_dir)
    if not zip_path:
        print("No evidence directory found.")
        return 1
    print(zip_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
