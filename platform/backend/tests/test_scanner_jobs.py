import asyncio
import json
import sys
from pathlib import Path


BACKEND_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND_DIR))

import scanner_jobs  # noqa: E402


def test_resolve_scan_target_accepts_relative_repo_path(tmp_path, monkeypatch):
    repo_root = tmp_path / "repo-root"
    target = repo_root / "sample-repo"
    target.mkdir(parents=True)
    monkeypatch.setattr(scanner_jobs, "REPO_ROOT", repo_root)

    resolved = scanner_jobs.resolve_scan_target({"target_locator": "sample-repo", "id": "run-1"})

    assert resolved == target.resolve()


def test_resolve_scan_target_rejects_missing_target(tmp_path, monkeypatch):
    monkeypatch.setattr(scanner_jobs, "REPO_ROOT", tmp_path)

    try:
        scanner_jobs.resolve_scan_target({"target_locator": "missing", "id": "run-1"})
    except scanner_jobs.ScannerJobError as exc:
        assert "does not exist" in str(exc)
    else:
        raise AssertionError("Expected ScannerJobError")


def test_run_code_review_scan_collects_swarm_outputs(tmp_path, monkeypatch):
    target = tmp_path / "target-repo"
    target.mkdir()
    artifact_root = tmp_path / "artifacts"

    monkeypatch.setattr(scanner_jobs, "SCANNER_ARTIFACT_ROOT", artifact_root)

    class FakeProcess:
        returncode = 0

        async def communicate(self):
            return b'{"run_id":"fake"}', b""

    async def fake_create_subprocess_exec(*command, **kwargs):
        out_dir = Path(command[command.index("--out") + 1])
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "findings_review_20260503.json").write_text(
            json.dumps(
                {
                    "total_findings": 1,
                    "findings": [
                        {
                            "tool": "custom-patterns",
                            "title": "shell command call",
                            "severity": "HIGH",
                            "confidence": "MEDIUM",
                            "file": "app.py",
                            "line": 12,
                            "description": "command injection risk",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        (out_dir / "report_review_20260503.md").write_text("# Report\n", encoding="utf-8")
        return FakeProcess()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    result = asyncio.run(
        scanner_jobs.run_code_review_scan(
            {"id": "run-1", "target_locator": str(target)},
            "review-cautious",
        )
    )

    assert result["engine"] == "swarm-review"
    assert result["total_findings"] == 1
    assert result["findings"][0]["title"] == "shell command call"
    assert result["report_markdown"] == "# Report\n"
