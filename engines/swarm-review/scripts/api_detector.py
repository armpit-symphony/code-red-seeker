#!/usr/bin/env python3
"""
API Tier Detector
Checks available API keys and determines which tier to use (free/paid)
"""

import os
import sys
from pathlib import Path

# API availability
APIS = {
    "shodan": {
        "env": "SHODAN_API_KEY",
        "free_fallback": "native_recon",
        "paid_name": "Shodan MCP"
    },
    "censys": {
        "env": "CENSYS_API_KEY", 
        "free_fallback": "crt.sh + certspotter",
        "paid_name": "Censys MCP"
    },
    "virustotal": {
        "env": "VIRUSTOTAL_API_KEY",
        "free_fallback": "cve.circl.lu",
        "paid_name": "VirusTotal MCP"
    },
    "github": {
        "env": "GITHUB_TOKEN",
        "free_fallback": "public_api",
        "paid_name": "GitHub MCP"
    },
    "mcp_recon": {
        "env": "MCP_RECON_PATH",
        "free_fallback": "built-in",
        "paid_name": "mcp-recon"
    }
}

def check_api(name):
    """Check if API key is available"""
    config = APIS[name]
    key = os.environ.get(config["env"], "").strip()
    
    if key:
        return {
            "name": name,
            "tier": "paid",
            "display": config["paid_name"],
            "available": True
        }
    else:
        return {
            "name": name,
            "tier": "free",
            "display": config["free_fallback"],
            "available": False
        }

def detect_available():
    """Detect all available APIs and their tiers"""
    results = {}
    
    for api_name in APIS:
        results[api_name] = check_api(api_name)
    
    return results

def get_capabilities():
    """Get combined capabilities based on available APIs"""
    apis = detect_available()
    
    capabilities = {
        "recon": [],
        "enrichment": [],
        "code_intel": [],
        "screenshots": []
    }
    
    # Recon capabilities
    if apis["shodan"]["available"]:
        capabilities["recon"].append("shodan")
    capabilities["recon"].append("native_dns")
    capabilities["recon"].append("whois")
    
    if apis["censys"]["available"]:
        capabilities["recon"].append("censys")
    capabilities["recon"].append("cert_lookup")
    
    # Enrichment
    if apis["virustotal"]["available"]:
        capabilities["enrichment"].append("virustotal")
    capabilities["enrichment"].append("cve_search")
    
    # Code intel
    if apis["github"]["available"]:
        capabilities["code_intel"].append("github_api")
    capabilities["code_intel"].append("public_github")
    
    # Screenshots
    capabilities["screenshots"].append("puppeteer")  # Always available
    
    return capabilities

def print_status():
    """Print API status in human-readable format"""
    apis = detect_available()
    caps = get_capabilities()
    
    print("=" * 50)
    print("BUG BOUNTY SWARM - API STATUS")
    print("=" * 50)
    print()
    
    print("📡 RECON:")
    for api in ["shodan", "censys"]:
        info = apis[api]
        status = "✅" if info["available"] else "⚪"
        print(f"   {status} {info['name']}: {info['display']}")
    
    print()
    print("🔍 ENRICHMENT:")
    info = apis["virustotal"]
    status = "✅" if info["available"] else "⚪"
    print(f"   {status} {info['name']}: {info['display']}")
    
    print()
    print("💻 CODE INTEL:")
    info = apis["github"]
    status = "✅" if info["available"] else "⚪"
    print(f"   {status} {info['name']}: {info['display']}")
    
    print()
    print("📸 SCREENSHOTS: puppeteer (built-in)")
    
    print()
    print("-" * 50)
    print("CAPABILITIES ENABLED:")
    for category, tools in caps.items():
        print(f"   {category}: {', '.join(tools)}")
    
    print("=" * 50)

if __name__ == "__main__":
    print_status()
