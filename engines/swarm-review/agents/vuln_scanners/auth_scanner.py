#!/usr/bin/env python3
"""
Auth Scanner Agent
Detects authentication-related vulnerabilities
"""

import os
import sys
import json
import requests
import re
from urllib.parse import urljoin
from datetime import datetime
from pathlib import Path
from core.evidence.store import EvidenceStore
from core.rate_limit import from_env as budget_from_env

OUTPUT_DIR = os.getenv("SWARM_OUTPUT_DIR") or str(Path(__file__).resolve().parents[2] / "output")

class AuthScanner:
    def __init__(self, target):
        self.target = target
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "BugBountyBot/1.0"})
    
    def scan(self):
        """Run auth scan"""
        print(f"   🎯 Auth Scanner: {self.target}")
        self._evidence = EvidenceStore(OUTPUT_DIR, level=os.getenv("EVIDENCE_LEVEL", "standard"))
        self._budget = budget_from_env()
        
        # Check for login pages
        self.check_login_page()
        
        # Check for password reset
        self.check_password_reset()
        
        # Check for weak auth
        self.check_weak_auth()
        
        # Check for session issues
        self.check_session()
        
        self.save_results()
        return self.findings
    
    def check_login_page(self):
        """Check login page for issues"""
        login_indicators = ["/login", "/signin", "/auth", "/admin"]
        
        for indicator in login_indicators:
            url = urljoin(self.target, indicator)
            try:
                baseline = self._baseline(url)
                self._budget.wait_for_budget()
                resp = self.session.get(url, timeout=10)
                self._evidence.save_http(url, "GET", {}, {"status": resp.status_code, "body": resp.text[:2000]})
                if resp.status_code == 200:
                    # Check for security issues
                    issues = []
                    
                    # No HTTPS in form action
                    form_action = re.search(r'action=["\']([^"\']+)["\']', resp.text)
                    if form_action:
                        action = form_action.group(1)
                        if action.startswith("http://"):
                            issues.append("form_submits_http")
                    
                    # Weak password policy
                    if "password" in resp.text.lower():
                        if not re.search(r'minlength|min-length', resp.text, re.I):
                            issues.append("no_min_password_length")
                    
                    if issues and self._differs(baseline, resp):
                        finding = {
                            "type": "Auth",
                            "issue": "login_page_issues",
                            "url": url,
                            "details": issues,
                            "severity": "MEDIUM",
                            "timestamp": datetime.utcnow().isoformat()
                        }
                        self.findings.append(finding)
                        print(f"      ⚠️ Auth issues: {url}")
                        
            except Exception:
                pass
    
    def check_password_reset(self):
        """Check password reset flow"""
        reset_indicators = ["/reset", "/forgot", "/password-reset", "/lost-password"]
        
        for indicator in reset_indicators:
            url = urljoin(self.target, indicator)
            try:
                baseline = self._baseline(url)
                self._budget.wait_for_budget()
                resp = self.session.get(url, timeout=10)
                self._evidence.save_http(url, "GET", {}, {"status": resp.status_code, "body": resp.text[:2000]})
                if resp.status_code == 200:
                    issues = []
                    
                    # Token in URL (predictable)
                    if "?" in url and "token" in url.lower():
                        issues.append("token_in_url")
                    
                    # Email enumeration possible
                    if "not found" in resp.text.lower() or "invalid" in resp.text.lower():
                        issues.append("possible_user_enum")
                    
                    if issues and self._differs(baseline, resp):
                        finding = {
                            "type": "Auth",
                            "issue": "password_reset_issues",
                            "url": url,
                            "details": issues,
                            "severity": "MEDIUM",
                            "timestamp": datetime.utcnow().isoformat()
                        }
                        self.findings.append(finding)
                        print(f"      ⚠️ Password reset issues: {url}")
                        
            except Exception:
                pass
    
    def check_weak_auth(self):
        """Check for weak authentication"""
        try:
            baseline = self._baseline(self.target)
            self._budget.wait_for_budget()
            resp = self.session.get(self.target, timeout=10)
            self._evidence.save_http(self.target, "GET", {}, {"status": resp.status_code, "headers": dict(resp.headers)})
            
            # Check for basic auth header
            www_auth = resp.headers.get("WWW-Authenticate")
            if www_auth and self._differs(baseline, resp):
                finding = {
                    "type": "Auth",
                    "issue": "basic_auth_enabled",
                    "header": www_auth,
                    "severity": "LOW",
                    "timestamp": datetime.utcnow().isoformat()
                }
                self.findings.append(finding)
            
            # Check for missing security headers
            security_headers = {
                "Strict-Transport-Security": "HSTS_missing",
                "X-Frame-Options": "clickjacking_protection_missing",
                "X-Content-Type-Options": "nosniff_missing",
                "Content-Security-Policy": "csp_missing"
            }
            
            missing = []
            for header, issue in security_headers.items():
                if header not in resp.headers:
                    missing.append(issue)
            
            if missing and self._differs(baseline, resp):
                finding = {
                    "type": "Auth",
                    "issue": "missing_security_headers",
                    "missing": missing,
                    "severity": "LOW",
                    "timestamp": datetime.utcnow().isoformat()
                }
                self.findings.append(finding)
                
        except Exception:
            pass

    def _baseline(self, url):
        try:
            self._budget.wait_for_budget()
            return self.session.get(url, timeout=10)
        except Exception:
            return None

    def _differs(self, baseline, resp) -> bool:
        if not baseline:
            return True
        if baseline.status_code != resp.status_code:
            return True
        try:
            return abs(len(baseline.text) - len(resp.text)) > 50
        except Exception:
            return True
    
    def check_session(self):
        """Check session handling"""
        # Create two sessions
        s1 = requests.Session()
        s2 = requests.Session()
        
        try:
            # Try to get a session
            resp1 = s1.get(self.target, timeout=10)
            cookie1 = s1.cookies.get_dict()
            
            resp2 = s2.get(self.target, timeout=10)
            cookie2 = s2.cookies.get_dict()
            
            # Check if cookies are predictable
            if cookie1 and cookie2:
                if cookie1 == cookie2:
                    finding = {
                        "type": "Auth",
                        "issue": "static_session_cookie",
                        "severity": "HIGH",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    self.findings.append(finding)
                    print(f"      ⚠️ Static session cookie")
                    
        except Exception:
            pass
    
    def save_results(self):
        """Save findings"""
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", self.target).strip("_")
        filename = f"{OUTPUT_DIR}/auth_{safe_target}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, "w") as f:
            json.dump({
                "target": self.target,
                "findings": self.findings,
                "count": len(self.findings)
            }, f, indent=2)
        
        print(f"      💾 Auth findings: {len(self.findings)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python auth_scanner.py <target_url>")
        sys.exit(1)
    
    scanner = AuthScanner(sys.argv[1])
    scanner.scan()
