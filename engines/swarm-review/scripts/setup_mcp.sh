#!/bin/bash
# MCP Server Setup - Install and configure MCP servers for bug bounty
# Free by default, with placeholders for paid APIs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_DIR="$SCRIPT_DIR/mcp"

echo "=========================================="
echo "MCP SERVER SETUP - BUG BOUNTY SWARM"
echo "=========================================="

# Check for Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js not found. Install from https://nodejs.org/"
    exit 1
fi

# Check for Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found."
    exit 1
fi

echo ""
echo "📦 Installing MCP servers..."

# Install MCP servers (npm global)
npm install -g @modelcontextprotocol/server-filesystem 2>/dev/null || true
npm install -g @modelcontextprotocol/server-github 2>/dev/null || true
npm install -g puppeteer 2>/dev/null || true

echo ""
echo "=========================================="
echo "API CONFIGURATION"
echo "=========================================="
echo ""
echo "To enable paid APIs, set these environment variables:"
echo ""
echo "  export SHODAN_API_KEY=your_key"
echo "  export CENSYS_API_KEY=your_key"
echo "  export CENSYS_API_SECRET=your_secret"
echo "  export VIRUSTOTAL_API_KEY=your_key"
echo "  export GITHUB_TOKEN=your_token"
echo ""
echo "Current status:"
python3 "$SCRIPT_DIR/scripts/api_detector.py"

echo ""
echo "=========================================="
echo "TESTING AGENTS"
echo "=========================================="

# Test API detector
echo ""
echo "🔍 Testing API detector..."
python3 "$SCRIPT_DIR/scripts/api_detector.py"

# Test basic imports
echo ""
echo "🐍 Testing Python agents..."
python3 -c "import requests, bs4; print('✅ Dependencies OK')" || echo "❌ Missing dependencies"

echo ""
echo "=========================================="
echo "SETUP COMPLETE"
echo "=========================================="
echo ""
echo "Usage:"
echo "  python3 swarm_orchestrator.py <target>"
echo ""
echo "Example:"
echo "  python3 swarm_orchestrator.py example.com"
echo ""
