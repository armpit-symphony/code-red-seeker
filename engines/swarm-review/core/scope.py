"""Scope enforcement and authorization gating."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse


def _normalize_host(target: str) -> str:
    if "://" in target:
        parsed = urlparse(target)
        host = parsed.hostname or ""
    else:
        host = target
    return host.strip().lower().rstrip(".")


def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"[0-9]{1,3}(?:\\.[0-9]{1,3}){3}", host))


@dataclass
class ScopeConfig:
    domains: list[str]
    ips: list[str]
    notes: str

    @classmethod
    def load(cls, path: str) -> "ScopeConfig":
        default = {"domains": [], "ips": [], "notes": ""}
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            data = default
        except Exception:
            data = default
        return cls(
            domains=[d.lower().rstrip(".") for d in data.get("domains", [])],
            ips=data.get("ips", []),
            notes=data.get("notes", ""),
        )

    def in_scope(self, target: str) -> bool:
        host = _normalize_host(target)
        if not host:
            return False
        if _is_ip(host):
            return host in self.ips
        for d in self.domains:
            if host == d or host.endswith("." + d):
                return True
        return False


def require_in_scope(scope: ScopeConfig, target: str) -> None:
    if not scope.in_scope(target):
        raise ValueError(
            f"Target '{target}' is out of scope. Update configs/scope.json before running."
        )


def require_authorized(authorized: bool) -> None:
    if not authorized:
        raise PermissionError(
            "Active testing requires --authorized. Set it only when you have explicit permission."
        )


def default_scope_path() -> str:
    repo_root = Path(__file__).resolve().parents[1]
    return str(repo_root / "configs" / "scope.json")
