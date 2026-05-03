"""MCP Crawl Adapter (fallbacks to local if unavailable)."""

from __future__ import annotations

import requests


class CrawlMCPAdapter:
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

    def run(self, target: str, max_pages: int = 20) -> dict | None:
        if not self.available():
            return None
        try:
            resp = requests.post(
                self.endpoint,
                json={"action": "crawl", "target": target, "max_pages": max_pages},
                timeout=30,
            )
            if resp.ok:
                return resp.json()
        except Exception:
            return None
        return None
