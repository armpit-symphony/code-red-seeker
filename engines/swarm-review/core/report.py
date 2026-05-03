"""Report writer: JSON, Markdown, HTML."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path


def _ensure_dir(path: str) -> None:
    Path(path).mkdir(parents=True, exist_ok=True)


def write_json(output_dir: str, name: str, data: dict) -> str:
    _ensure_dir(output_dir)
    path = Path(output_dir) / f"{name}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    return str(path)


def write_markdown(output_dir: str, name: str, md: str) -> str:
    _ensure_dir(output_dir)
    path = Path(output_dir) / f"{name}.md"
    with open(path, "w") as f:
        f.write(md)
    return str(path)


def write_html(output_dir: str, name: str, title: str, body: str) -> str:
    _ensure_dir(output_dir)
    path = Path(output_dir) / f"{name}.html"
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{title}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; color: #111; }}
    h1 {{ margin-bottom: 8px; }}
    h2 {{ margin-top: 24px; }}
    code {{ background: #f6f6f6; padding: 2px 4px; }}
    table {{ border-collapse: collapse; width: 100%; margin-top: 12px; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
    th {{ background: #f2f2f2; }}
  </style>
</head>
<body>
{body}
</body>
</html>
"""
    with open(path, "w") as f:
        f.write(html)
    return str(path)
