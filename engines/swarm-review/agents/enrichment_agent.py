#!/usr/bin/env python3
"""
Enrichment Agent - CVE lookup, vulnerability enrichment
Free tier: cve.circl.lu (no API key)
Paid tier: VirusTotal (if key available)
"""

import os
import sys
import json
import requests
import re
from datetime import datetime
from pathlib import Path
from core.rate_limit import from_env as budget_from_env

# Config
OUTPUT_DIR = os.getenv("SWARM_OUTPUT_DIR") or str(Path(__file__).resolve().parents[1] / "output")
VIRUSTOTAL_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")

class EnrichmentAgent:
    def __init__(self):
        self.results = {
            "timestamp": datetime.utcnow().isoformat(),
            "cve_lookups": [],
            "virustotal": [],
            "tech_detection": []
        }
        self._budget = budget_from_env()
        
        os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    def lookup_cve(self, cve_id):
        """Lookup CVE details from circl.lu (free)"""
        print(f"   🔍 CVE lookup: {cve_id}")
        
        try:
            url = f"https://cve.circl.lu/api/cve/{cve_id}"
            self._budget.wait_for_budget()
            resp = requests.get(url, timeout=10)
            
            if resp.ok:
                data = resp.json()
                result = {
                    "cve_id": cve_id,
                    "cvss": data.get("cvss", "N/A"),
                    "summary": data.get("summary", "")[:500],
                    "references": data.get("references", [])[:5],
                    "attack_vector": data.get("attack_vector", ""),
                    "cwe": data.get("cwe", "")
                }
                self.results["cve_lookups"].append(result)
                print(f"      ✅ CVSS: {result['cvss']}")
                return result
            else:
                print(f"      ⚠️ Not found: {cve_id}")
                
        except Exception as e:
            print(f"      ❌ Error: {cve_id}: {e}")
        
        return None
    
    def lookup_ip_virustotal(self, ip):
        """VirusTotal IP lookup (if API key available)"""
        if not VIRUSTOTAL_KEY:
            print(f"   ⚪ VirusTotal not configured - skipping IP lookup")
            return None
        
        print(f"   🔍 VirusTotal lookup: {ip}")
        
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            headers = {"x-apikey": VIRUSTOTAL_KEY}
            self._budget.wait_for_budget()
            resp = requests.get(url, headers=headers, timeout=10)
            
            if resp.ok:
                data = resp.json()
                result = {
                    "ip": ip,
                    "malicious": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
                    "suspicious": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("suspicious", 0),
                    "country": data.get("data", {}).get("attributes", {}).get("country", ""),
                    "as_owner": data.get("data", {}).get("attributes", {}).get("as_owner", "")
                }
                self.results["virustotal"].append(result)
                print(f"      ✅ Malicious: {result['malicious']}, Suspicious: {result['suspicious']}")
                return result
                
        except Exception as e:
            print(f"      ❌ VT error: {e}")
        
        return None
    
    def lookup_domain_virustotal(self, domain):
        """VirusTotal domain lookup"""
        if not VIRUSTOTAL_KEY:
            print(f"   ⚪ VirusTotal not configured - skipping domain lookup")
            return None
        
        print(f"   🔍 VirusTotal domain: {domain}")
        
        try:
            url = f"https://www.virustotal.com/api/v3/domains/{domain}"
            headers = {"x-apikey": VIRUSTOTAL_KEY}
            self._budget.wait_for_budget()
            resp = requests.get(url, headers=headers, timeout=10)
            
            if resp.ok:
                data = resp.json()
                result = {
                    "domain": domain,
                    "malicious": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious", 0),
                    "categories": data.get("data", {}).get("attributes", {}).get("categories", {})
                }
                self.results["virustotal"].append(result)
                print(f"      ✅ Malicious: {result['malicious']}")
                return result
                
        except Exception as e:
            print(f"      ❌ VT error: {e}")
        
        return None
    
    def detect_tech(self, url):
        """Detect technologies from response headers/body"""
        print(f"   🔍 Tech detection: {url}")
        
        try:
            self._budget.wait_for_budget()
            resp = requests.get(url, timeout=10)
            headers = resp.headers
            
            tech = []
            
            # Server header
            if "server" in headers:
                tech.append(f"Server: {headers['server']}")
            
            # X-Powered-By
            if "x-powered-by" in headers:
                tech.append(f"Powered-By: {headers['x-powered-by']}")
            
            # Check for specific frameworks in body
            content = resp.text.lower()
            frameworks = [
                ("react", "React"),
                ("next.js", "Next.js"),
                ("angular", "Angular"),
                ("vue", "Vue.js"),
                ("django", "Django"),
                ("flask", "Flask"),
                ("express", "Express"),
                ("laravel", "Laravel"),
                ("wordpress", "WordPress")
            ]
            
            for pattern, name in frameworks:
                if pattern in content:
                    tech.append(name)
            
            if tech:
                self.results["tech_detection"].append({
                    "url": url,
                    "tech": list(set(tech))
                })
                print(f"      ✅ Found: {', '.join(tech[:3])}")
                
        except Exception as e:
            print(f"      ❌ Error: {e}")
    
    def save_results(self):
        """Save results"""
        filename = f"{OUTPUT_DIR}/enrichment_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        with open(filename, "w") as f:
            json.dump(self.results, f, indent=2)
        
        print(f"   💾 Saved: {filename}")
        
        return filename

if __name__ == "__main__":
    agent = EnrichmentAgent()
    
    # Example usage
    if len(sys.argv) > 1:
        if sys.argv[1] == "cve":
            agent.lookup_cve(sys.argv[2] if len(sys.argv) > 2 else "CVE-2024-1234")
        elif sys.argv[1] == "ip":
            agent.lookup_ip_virustotal(sys.argv[2] if len(sys.argv) > 2 else "8.8.8.8")
        elif sys.argv[1] == "domain":
            agent.lookup_domain_virustotal(sys.argv[2] if len(sys.argv) > 2 else "example.com")
        elif sys.argv[1] == "tech":
            agent.detect_tech(sys.argv[2] if len(sys.argv) > 2 else "https://example.com")
    
    agent.save_results()
    print("✅ Enrichment agent complete")
