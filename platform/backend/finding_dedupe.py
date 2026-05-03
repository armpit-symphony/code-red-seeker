from __future__ import annotations

import hashlib
import json
from typing import Any


def finding_fingerprint(finding: dict[str, Any]) -> str:
    """Return a stable per-run fingerprint for duplicate finding suppression."""
    payload = {
        "run": finding.get("audit_run_id", ""),
        "title": _clean(finding.get("title", "")),
        "severity": _clean(finding.get("severity", "")),
        "surfaces": sorted(_clean(surface) for surface in finding.get("affected_surfaces", []) if _clean(surface)),
        "source": _clean(finding.get("source_name", "")),
        "rule": _clean(finding.get("source_rule_id", "")),
        "evidence": _clean(finding.get("evidence", ""))[:500],
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def attach_fingerprints(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    for finding in findings:
        finding["fingerprint"] = finding.get("fingerprint") or finding_fingerprint(finding)
    return findings


async def filter_duplicate_findings(database, run_id: str, findings: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    attach_fingerprints(findings)
    fingerprints = [finding["fingerprint"] for finding in findings]
    if not fingerprints:
        return [], 0

    existing = set()
    async for item in database.findings.find(
        {"audit_run_id": run_id, "fingerprint": {"$in": fingerprints}},
        {"fingerprint": 1, "_id": 0},
    ):
        if item.get("fingerprint"):
            existing.add(item["fingerprint"])

    unique: list[dict[str, Any]] = []
    seen = set(existing)
    duplicate_count = 0
    for finding in findings:
        fingerprint = finding["fingerprint"]
        if fingerprint in seen:
            duplicate_count += 1
            continue
        seen.add(fingerprint)
        unique.append(finding)

    return unique, duplicate_count


def _clean(value: Any) -> str:
    return str(value or "").strip().lower()
