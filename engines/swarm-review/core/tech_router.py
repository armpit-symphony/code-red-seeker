"""Route playbooks based on detected technologies."""

from __future__ import annotations


TECH_TO_PLAYBOOKS = {
    "next.js": ["auth", "ssrf", "idor", "xss"],
    "react": ["xss", "auth"],
    "angular": ["xss", "auth"],
    "vue": ["xss", "auth"],
    "django": ["sqli", "auth", "idor"],
    "flask": ["sqli", "auth", "idor"],
    "express": ["auth", "ssrf", "idor"],
    "laravel": ["sqli", "auth", "idor"],
    "wordpress": ["auth", "idor", "xss"],
}


def route_playbooks(tech_list: list[str]) -> list[str]:
    selected = []
    for t in tech_list:
        key = t.lower()
        for tech_key, pbs in TECH_TO_PLAYBOOKS.items():
            if tech_key in key:
                for pb in pbs:
                    if pb not in selected:
                        selected.append(pb)
    if not selected:
        selected = ["xss", "sqli", "auth", "idor"]
    return selected
