from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
SWARM_ENGINE_DIR = REPO_ROOT / "engines" / "swarm-review"
SWARM_CLI = SWARM_ENGINE_DIR / "swarm_review_cli.py"
SCANNER_ARTIFACT_ROOT = REPO_ROOT / "artifacts" / "scanner-runs"


class ScannerJobError(RuntimeError):
    """Raised when a scanner job cannot be executed or parsed."""


def resolve_scan_target(run_record: dict[str, Any], explicit_target_path: str = "") -> Path:
    raw_target = explicit_target_path.strip() or str(run_record.get("target_locator", "")).strip()
    if not raw_target:
        raise ScannerJobError("Run target locator is empty.")

    target = Path(raw_target).expanduser()
    if not target.is_absolute():
        target = (REPO_ROOT / target).resolve()
    else:
        target = target.resolve()

    if not target.exists():
        raise ScannerJobError(f"Code review target does not exist: {target}")
    return target


def scanner_output_dir(run_id: str) -> Path:
    out_dir = SCANNER_ARTIFACT_ROOT / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir


async def run_code_review_scan(run_record: dict[str, Any], profile: str, target_path: str = "") -> dict[str, Any]:
    if not SWARM_CLI.exists():
        raise ScannerJobError(f"SwarmReview CLI not found: {SWARM_CLI}")

    target = resolve_scan_target(run_record, target_path)
    out_dir = scanner_output_dir(run_record["id"])
    before = {path.resolve() for path in out_dir.glob("*") if path.is_file()}

    command = [
        sys.executable,
        str(SWARM_CLI),
        "review",
        "--repo",
        str(target),
        "--profile",
        profile,
        "--out",
        str(out_dir),
    ]
    proc = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(SWARM_ENGINE_DIR),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    stdout_text = stdout.decode("utf-8", errors="replace")
    stderr_text = stderr.decode("utf-8", errors="replace")

    after = {path.resolve() for path in out_dir.glob("*") if path.is_file()}
    new_files = sorted(after - before, key=lambda path: path.name)

    if proc.returncode != 0:
        raise ScannerJobError(
            "SwarmReview code review failed with exit "
            f"{proc.returncode}.\nSTDOUT:\n{stdout_text[-4000:]}\nSTDERR:\n{stderr_text[-4000:]}"
        )

    findings_payload = _load_latest_findings(out_dir)
    report_path = _latest_file(out_dir, "report_review_*.md")

    return {
        "engine": "swarm-review",
        "profile": profile,
        "target": str(target),
        "out_dir": str(out_dir),
        "stdout": stdout_text,
        "stderr": stderr_text,
        "findings_payload": findings_payload,
        "findings": findings_payload.get("findings", []),
        "total_findings": findings_payload.get("total_findings", len(findings_payload.get("findings", []))),
        "findings_file": str(_latest_file(out_dir, "findings_review_*.json") or ""),
        "report_file": str(report_path or ""),
        "new_files": [str(path) for path in new_files],
        "report_markdown": _read_text(report_path, max_chars=40000) if report_path else "",
    }


def _latest_file(directory: Path, pattern: str) -> Path | None:
    matches = sorted(directory.glob(pattern), key=lambda path: path.stat().st_mtime, reverse=True)
    return matches[0] if matches else None


def _load_latest_findings(directory: Path) -> dict[str, Any]:
    findings_path = _latest_file(directory, "findings_review_*.json")
    if not findings_path:
        raise ScannerJobError(f"SwarmReview did not produce a findings JSON file in {directory}")
    try:
        return json.loads(findings_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ScannerJobError(f"Invalid findings JSON from {findings_path}: {exc}") from exc


def _read_text(path: Path, max_chars: int) -> str:
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) > max_chars:
        return f"{text[:max_chars]}\n\n[truncated after {max_chars} characters]"
    return text
