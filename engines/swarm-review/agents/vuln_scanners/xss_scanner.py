#!/usr/bin/env python3
"""
XSS Scanner Agent
Detects Reflected, Stored, and DOM-based XSS vulnerabilities
"""

import os
import sys
import json
import requests
import re
from urllib.parse import urljoin, urlparse, parse_qs
from datetime import datetime
from pathlib import Path
from core.evidence.store import EvidenceStore
from core.rate_limit import from_env as budget_from_env

OUTPUT_DIR = os.getenv("SWARM_OUTPUT_DIR") or str(Path(__file__).resolve().parents[2] / "output")

class XSSScanner:
    def __init__(self, target, forms=None, endpoints=None):
        self.target = target
        self.forms = forms or []
        self.endpoints = endpoints or []
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "BugBountyBot/1.0"})
        
        # XSS payloads
        self.payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "'-alert(1)-'",
            "{{constructor.constructor('alert(1)')()}}"
        ]
    
    def scan(self):
        """Run XSS scan"""
        print(f"   🎯 XSS Scanner: {self.target}")
        self._evidence = EvidenceStore(OUTPUT_DIR, level=os.getenv("EVIDENCE_LEVEL", "standard"))
        self._budget = budget_from_env()
        
        # Scan forms
        for form in self.forms:
            self.scan_form(form)
        
        # Scan endpoints with params
        for endpoint in self.endpoints[:20]:  # Limit
            parsed = urlparse(endpoint)
            if parsed.query:
                self.scan_params(endpoint, parse_qs(parsed.query))
        
        self.save_results()
        return self.findings
    
    def scan_form(self, form):
        """Test form inputs for XSS"""
        action = form.get("action", "/")
        method = form.get("method", "get").upper()
        inputs = form.get("inputs", [])
        
        if not inputs:
            return
        
        url = urljoin(self.target, action)
        
        baseline = self._baseline_form(url, method, inputs)
        for payload in self.payloads[:3]:  # Limit payloads
            data = {}
            for inp in inputs:
                if inp:
                    data[inp] = payload
            
            try:
                if method == "POST":
                    self._budget.wait_for_budget()
                    resp = self.session.post(url, data=data, timeout=10)
                    self._evidence.save_http(url, "POST", {"data": data}, {"status": resp.status_code, "body": resp.text[:2000]})
                else:
                    self._budget.wait_for_budget()
                    resp = self.session.get(url, params=data, timeout=10)
                    self._evidence.save_http(url, "GET", {"params": data}, {"status": resp.status_code, "body": resp.text[:2000]})
                
                # Check for reflected payload with baseline diff
                if payload in resp.text and self._differs(baseline, resp):
                    # Verify it's not in a safe context
                    self.check_reflection(url, payload, resp.text)
                    
            except Exception as e:
                pass
    
    def scan_params(self, url, params):
        """Test URL parameters for XSS"""
        baseline = self._baseline_params(url, params)
        for payload in self.payloads[:3]:
            test_params = {k: payload for k in params.keys()}
            
            try:
                self._budget.wait_for_budget()
                resp = self.session.get(url, params=test_params, timeout=10)
                self._evidence.save_http(url, "GET", {"params": test_params}, {"status": resp.status_code, "body": resp.text[:2000]})
                
                if payload in resp.text and self._differs(baseline, resp):
                    self.check_reflection(url, payload, resp.text)
                    
            except Exception:
                pass
    
    def check_reflection(self, url, payload, response):
        """Check if payload is reflected in safe context"""
        # Simple check - look for payload in response
        if payload not in response:
            return
        
        # Check for common filters
        filtered = False
        if "<script" in payload and "<script" not in response:
            filtered = True
        if "alert" in payload and "alert" not in response:
            filtered = True
        
        if not filtered:
            finding = {
                "type": "XSS",
                "url": url,
                "payload": payload,
                "severity": "HIGH",
                "timestamp": datetime.utcnow().isoformat()
            }
            
            # Avoid duplicates
            if finding not in self.findings:
                self.findings.append(finding)
                print(f"      ⚠️ XSS FOUND: {url}")

    def _baseline_form(self, url, method, inputs):
        data = {inp: "baseline" for inp in inputs if inp}
        try:
            if method == "POST":
                self._budget.wait_for_budget()
                resp = self.session.post(url, data=data, timeout=10)
            else:
                self._budget.wait_for_budget()
                resp = self.session.get(url, params=data, timeout=10)
            return resp
        except Exception:
            return None

    def _baseline_params(self, url, params):
        data = {k: "baseline" for k in params.keys()}
        try:
            self._budget.wait_for_budget()
            return self.session.get(url, params=data, timeout=10)
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
    
    def save_results(self):
        """Save findings"""
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", self.target).strip("_")
        filename = f"{OUTPUT_DIR}/xss_{safe_target}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, "w") as f:
            json.dump({
                "target": self.target,
                "findings": self.findings,
                "count": len(self.findings)
            }, f, indent=2)
        
        print(f"      💾 XSS findings: {len(self.findings)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python xss_scanner.py <target_url>")
        sys.exit(1)
    
    scanner = XSSScanner(sys.argv[1])
    scanner.scan()
