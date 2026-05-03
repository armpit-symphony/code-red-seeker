"""Evidence store for requests and responses."""

from __future__ import annotations

import json
import time
from pathlib import Path


class EvidenceStore:
    def __init__(self, output_dir: str, level: str = "standard"):
        self.base = Path(output_dir) / "evidence"
        self.base.mkdir(parents=True, exist_ok=True)
        self.level = level

    def save_http(self, url: str, method: str, request: dict, response: dict) -> str:
        stamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in url)[:80]
        name = f"http_{stamp}_{safe}.json"
        path = self.base / name
        response = self._apply_level(response)
        payload = {
            "url": url,
            "method": method,
            "request": request,
            "response": response,
            "timestamp": stamp,
        }
        with open(path, "w") as f:
            json.dump(payload, f, indent=2)
        return str(path)

    def _apply_level(self, response: dict) -> dict:
        if self.level == "lite":
            return {k: response.get(k) for k in ("status", "headers")}
        if self.level == "full":
            body = response.get("body", "")
            if isinstance(body, str):
                response["body"] = body[:10000]
            return response
        body = response.get("body", "")
        if isinstance(body, str):
            response["body"] = body[:2000]
        return response
