"""Lightweight validation harness to spot false positives."""

from __future__ import annotations

import json
from pathlib import Path


def load_findings(report_path: str) -> list[dict]:
    with open(report_path, "r") as f:
        data = json.load(f)
    return data.get("triaged_findings", [])


def score_false_positives(findings: list[dict]) -> dict:
    """Return a simple score based on missing evidence fields."""
    score = {"total": len(findings), "missing_evidence": 0}
    for f in findings:
        pb = f.get("playbook", {})
        if pb and not pb.get("evidence"):
            score["missing_evidence"] += 1
    return score


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Validate scan report for basic quality checks")
    parser.add_argument("report", help="Path to vuln_scan_*.json")
    args = parser.parse_args()

    findings = load_findings(args.report)
    score = score_false_positives(findings)
    print(json.dumps(score, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
