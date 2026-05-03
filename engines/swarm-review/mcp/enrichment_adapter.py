"""MCP Enrichment Adapter (fallbacks to local if unavailable)."""

from __future__ import annotations

import requests


class EnrichmentMCPAdapter:
    def __init__(self, endpoint: str):
        self.endpoint = (endpoint or "").strip()

    def available(self) -> bool:
        return bool(self.endpoint)

    def health(self) -> bool:
        if not self.available():
            return False
        try:
            resp = requests.post(self.endpoint, json={"action": "health"}, timeout=5)
            return resp.ok
        except Exception:
            return False

    def run(self, target: str) -> dict | None:
        if not self.available():
            return None
        try:
            resp = requests.post(
                self.endpoint,
                json={"action": "enrich", "target": target},
                timeout=20,
            )
            if resp.ok:
                return resp.json()
        except Exception:
            return None
        return None
