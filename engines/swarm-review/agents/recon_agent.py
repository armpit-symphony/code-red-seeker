#!/usr/bin/env python3
"""
Recon Agent - Domain and IP reconnaissance
Auto-detects API availability and uses best available method
"""

import os
import sys
import json
import subprocess
import socket
import requests
import re
from datetime import datetime
from pathlib import Path
from core.rate_limit import from_env as budget_from_env
from core.http_utils import response_differs

# Config
OUTPUT_DIR = os.getenv("SWARM_OUTPUT_DIR") or str(Path(__file__).resolve().parents[1] / "output")
SHODAN_KEY = os.environ.get("SHODAN_API_KEY", "")
CENSYS_API_KEY = os.environ.get("CENSYS_API_KEY", "")
CENSYS_SECRET = os.environ.get("CENSYS_API_SECRET", "")

class ReconAgent:
    def __init__(self, target):
        self.target = target
        self.results = {
            "target": target,
            "timestamp": datetime.utcnow().isoformat(),
            "dns": {},
            "whois": {},
            "ports": [],
            "subdomains": [],
            "ssl_certs": [],
            "shodan": None,
            "censys": None
        }
    
    def run(self):
        """Run full recon based on available APIs"""
        print(f"🎯 Starting recon on: {self.target}")
        self._budget = budget_from_env()
        
        # Always run basic recon
        self.resolve_dns()
        self.get_whois()
        
        # API-based recon (if keys available)
        if SHODAN_KEY:
            self.shodan_lookup()
        else:
            print("⚪ configured Shodan not - skipping")
        
        if CENSYS_API_KEY:
            self.censys_lookup()
        else:
            print("⚪ Censys not configured - skipping")
        
        # Always run free subdomain enumeration
        self.enumerate_subdomains()
        
        self.save_results()
        return self.results
    
    def resolve_dns(self):
        """Resolve DNS records"""
        print("   🔎 DNS lookup...")
        try:
            ip = socket.gethostbyname(self.target)
            self.results["dns"]["a"] = [ip]
            print(f"      ✅ A record: {ip}")
        except Exception as e:
            print(f"      ❌ DNS failed: {e}")
    
    def get_whois(self):
        """Get WHOIS info"""
        print("   📜 WHOIS lookup...")
        try:
            # Use whois command
            result = subprocess.run(
                ["whois", self.target],
                capture_output=True,
                text=True,
                timeout=10
            )
            self.results["whois"]["raw"] = result.stdout[:2000]  # Limit size
            print("      ✅ WHOIS complete")
        except Exception as e:
            print(f"      ⚠️ WHOIS failed: {e}")
    
    def shodan_lookup(self):
        """Shodan API lookup"""
        print("   🔍 Shodan lookup...")
        try:
            url = f"https://api.shodan.io/dns/domain/{self.target}"
            params = {"key": SHODAN_KEY}
            self._budget.wait_for_budget()
            baseline = requests.get(url, params=params, timeout=10)
            self._budget.wait_for_budget()
            resp = requests.get(url, params=params, timeout=10)
            if resp.ok:
                if not response_differs(baseline, resp):
                    return
                data = resp.json()
                self.results["shodan"] = data
                subdomains = data.get("subdomains", [])
                self.results["subdomains"].extend(subdomains)
                print(f"      ✅ Found {len(subdomains)} subdomains")
            else:
                print(f"      ⚠️ Shodan error: {resp.status_code}")
        except Exception as e:
            print(f"      ❌ Shodan failed: {e}")
    
    def censys_lookup(self):
        """Censys API lookup"""
        print("   🔎 Censys lookup...")
        try:
            # Basic cert search
            url = f"https://search.censys.io/api/v1/search/certificates"
            params = {
                "q": f"names: {self.target}",
                "page": 1,
                "per_page": 10
            }
            auth = (CENSYS_API_KEY, CENSYS_SECRET)
            self._budget.wait_for_budget()
            baseline = requests.get(url, params=params, auth=auth, timeout=10)
            self._budget.wait_for_budget()
            resp = requests.get(url, params=params, auth=auth, timeout=10)
            if resp.ok:
                if not response_differs(baseline, resp):
                    return
                data = resp.json()
                self.results["censys"] = data
                print(f"      ✅ Cert search complete")
            else:
                print(f"      ⚠️ Censys error: {resp.status_code}")
        except Exception as e:
            print(f"      ❌ Censys failed: {e}")
    
    def enumerate_subdomains(self):
        """Free subdomain enumeration"""
        print("   🌐 Subdomain enumeration (free)...")
        
        # CRT.sh (free)
        try:
            url = f"https://crt.sh/?q={self.target}&output=json"
            self._budget.wait_for_budget()
            baseline = requests.get(url, timeout=15)
            self._budget.wait_for_budget()
            resp = requests.get(url, timeout=15)
            if resp.ok:
                if not response_differs(baseline, resp):
                    return
                data = resp.json()
                subs = set()
                for cert in data[:50]:  # Limit
                    name = cert.get("name_value", "")
                    if "*" not in name:
                        subs.add(name)
                self.results["subdomains"].extend(list(subs))
                print(f"      ✅ Found {len(subs)} subdomains from crt.sh")
        except Exception as e:
            print(f"      ⚠️ CRT.sh failed: {e}")
    
    def save_results(self):
        """Save results to file"""
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", self.target).strip("_")
        filename = f"{OUTPUT_DIR}/recon_{safe_target}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)
        
        print(f"   💾 Saved: {filename}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python recon_agent.py <target_domain>")
        sys.exit(1)
    
    target = sys.argv[1]
    agent = ReconAgent(target)
    results = agent.run()
    
    print(f"\n✅ Recon complete for {target}")
    print(f"   Subdomains found: {len(results.get('subdomains', []))}")
