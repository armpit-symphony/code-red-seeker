"""Write a schema validation report."""

from __future__ import annotations

import json
from pathlib import Path


def write_report(output_dir: str, errors: list[str]) -> str:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    path = Path(output_dir) / "openclaw_schema_report.json"
    payload = {"errors": errors, "status": "ok" if not errors else "failed"}
    with open(path, "w") as f:
        json.dump(payload, f, indent=2)
    return str(path)
